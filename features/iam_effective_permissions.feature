Feature: IAM effective permissions
  In order to answer why a user can do something
  As an administrator
  I want to see the effective permissions of a user with the roles and scopes behind them

  Scenario: The effective permissions list each key and wildcard with its roles, scopes, shortest expiry and policy version over REST and GraphQL
    Given a caller authenticated as the bootstrapped administrator
    And an assignable role "Billing reader" that grants "rest:billing:GET /invoices/{}, gql:billing:*"
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "global"}, "expiresAt": "2099-01-01T00:00:00Z"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "project", "projectId": "0190f2a8-7b3c-7d4e-8f10-1234567890cd"}, "expiresAt": "2098-01-01T00:00:00Z"}
      """
    Then the response status code should be 201
    When GET request is sent to "/api/users/0190f2a8-7b3c-7d4e-8f10-1234567890ab/role-permissions"
    Then the response status code should be 200
    And the JSON pointer "/userId" should equal "0190f2a8-7b3c-7d4e-8f10-1234567890ab"
    And the JSON pointer "/policyVersion" should be present
    And the JSON pointer "/permissions/0/key" should equal "rest:billing:GET /invoices/{}"
    And the JSON pointer "/permissions/0/kind" should equal "rest"
    And the JSON pointer "/permissions/0/service" should equal "billing"
    And the JSON pointer "/permissions/0/wildcard" should be present
    And the JSON pointer "/permissions/0/roles/0/id" should equal the seeded role
    And the JSON pointer "/permissions/0/roles/0/name" should equal "Billing reader"
    And the JSON pointer "/permissions/0/scopes/0" should equal "all"
    And the JSON pointer "/permissions/0/expiresAt" should equal "2098-01-01T00:00:00.000000Z"
    And the JSON pointer "/permissions/1/key" should equal "gql:billing:*"
    And the JSON pointer "/permissions/1/scopes/0" should equal "all"
    And the JSON pointer "/permissions/2" should be absent
    When the GraphQL operation is sent:
      """
      { userRolePermissions(userId: "0190f2a8-7b3c-7d4e-8f10-1234567890ab") { userId policyVersion permissions { key kind service wildcard scopes expiresAt roles { id name } } } }
      """
    Then the response status code should be 200
    And the GraphQL response should have no errors
    And the JSON pointer "/data/userRolePermissions/userId" should equal "0190f2a8-7b3c-7d4e-8f10-1234567890ab"
    And the JSON pointer "/data/userRolePermissions/policyVersion" should be present
    And the JSON pointer "/data/userRolePermissions/permissions/0/key" should equal "rest:billing:GET /invoices/{}"
    And the JSON pointer "/data/userRolePermissions/permissions/0/roles/0/id" should equal the seeded role
    And the JSON pointer "/data/userRolePermissions/permissions/0/roles/0/name" should equal "Billing reader"
    And the JSON pointer "/data/userRolePermissions/permissions/0/scopes/0" should equal "all"
    And the JSON pointer "/data/userRolePermissions/permissions/0/expiresAt" should equal "2098-01-01T00:00:00.000000Z"
    And the JSON pointer "/data/userRolePermissions/permissions/1/key" should equal "gql:billing:*"

  Scenario: A project assignment lists its project and the filters narrow the answer
    Given a caller authenticated as the bootstrapped administrator
    And an assignable role "Billing reader" that grants "rest:billing:GET /invoices/{}, rest:shipping:GET /parcels"
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "project", "projectId": "0190f2a8-7b3c-7d4e-8f10-1234567890cd"}}
      """
    Then the response status code should be 201
    When GET request is sent to "/api/users/0190f2a8-7b3c-7d4e-8f10-1234567890ab/role-permissions?service=shipping"
    Then the response status code should be 200
    And the JSON pointer "/permissions/0/key" should equal "rest:shipping:GET /parcels"
    And the JSON pointer "/permissions/0/scopes/0" should equal "0190f2a8-7b3c-7d4e-8f10-1234567890cd"
    And the JSON pointer "/permissions/0/expiresAt" should be absent
    And the JSON pointer "/permissions/1" should be absent
    When GET request is sent to "/api/users/0190f2a8-7b3c-7d4e-8f10-1234567890ab/role-permissions?projectId=0190f2a8-7b3c-7d4e-8f10-1234567890ce"
    Then the response status code should be 200
    And the JSON pointer "/permissions/0" should be absent
    When the GraphQL operation is sent:
      """
      { userRolePermissions(userId: "0190f2a8-7b3c-7d4e-8f10-1234567890ab", projectId: "0190f2a8-7b3c-7d4e-8f10-1234567890cd", service: "billing") { permissions { key scopes } } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/userRolePermissions/permissions/0/key" should equal "rest:billing:GET /invoices/{}"
    And the JSON pointer "/data/userRolePermissions/permissions/1" should be absent

  Scenario: A user without assignments holds nothing
    Given a caller authenticated as the bootstrapped administrator
    When GET request is sent to "/api/users/0190f2a8-7b3c-7d4e-8f10-1234567890ab/role-permissions"
    Then the response status code should be 200
    And the JSON pointer "/policyVersion" should be present
    And the JSON pointer "/permissions/0" should be absent

  Scenario: The read model holds the keys that the decision API allows
    Given a caller authenticated as the bootstrapped administrator
    And an assignable role "Invoice reader" that grants "rest:billing:GET /invoices/{}"
    And a subject token of a user in session "e2e-effective-1"
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "billing", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Billing\",\"version\":\"1\"},\"paths\":{\"/invoices/{invoiceId}\":{\"get\":{}},\"/refunds\":{\"post\":{}}}}"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/openapi-specs/{id}/permissions" with body:
      """
      {}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/access-validations" with body:
      """
      {"credential": "{token}", "service": "billing", "rest": {"method": "GET", "path": "/invoices/42"}, "requestId": "req-held"}
      """
    Then the response status code should be 200
    And the JSON pointer "/decision" should equal "allow"
    When POST request is sent to "/api/access-validations" with body:
      """
      {"credential": "{token}", "service": "billing", "rest": {"method": "POST", "path": "/refunds"}, "requestId": "req-missing"}
      """
    Then the response status code should be 200
    And the JSON pointer "/decision" should equal "deny"
    When GET request is sent to "/api/users/0190f2a8-7b3c-7d4e-8f10-1234567890ab/role-permissions?service=billing"
    Then the response status code should be 200
    And the JSON pointer "/permissions/0/key" should equal "rest:billing:GET /invoices/{}"
    And the JSON pointer "/permissions/1" should be absent

  Scenario: A subject without the key of the operation is refused over REST and GraphQL and the refusals are audited
    Given a caller authenticated with a valid service token that holds no IAM key
    When GET request is sent to "/api/users/0190f2a8-7b3c-7d4e-8f10-1234567890ab/role-permissions"
    Then the response status code should be 403
    And the response header "content-type" should contain "application/problem+json"
    And the audit log should hold 1 forbidden "user_role_permission.list" record within one second
    When the GraphQL operation is sent:
      """
      { userRolePermissions(userId: "0190f2a8-7b3c-7d4e-8f10-1234567890ab") { policyVersion } }
      """
    Then the response status code should be 200
    And the GraphQL error code should be "FORBIDDEN"

  Scenario Outline: An invalid identifier or filter is a validation failure over REST
    Given a caller authenticated as the bootstrapped administrator
    When GET request is sent to "<path>"
    Then the response status code should be 422
    And the JSON pointer "/violations/0/propertyPath" should equal "<property>"

    Examples:
      | path                                                                                                  | property  |
      | /api/users/not-a-uuid/role-permissions                                                                | userId    |
      | /api/users/0190f2a8-7b3c-7d4e-8f10-1234567890ab/role-permissions?projectId=nope                       | projectId |
      | /api/users/0190f2a8-7b3c-7d4e-8f10-1234567890ab/role-permissions?service=Not%20A%20Service             | service   |
