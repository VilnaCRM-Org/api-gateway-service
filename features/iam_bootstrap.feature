Feature: The first IAM administrator
  In order to keep IAM administrable without a backdoor in the API
  As an operator
  I want the platform to refuse every change that would leave it without an active administrator

  Scenario: The last administrator assignment cannot be revoked over REST and the refusal is audited
    Given a caller authenticated as the bootstrapped administrator
    And the first administrator is bootstrapped
    When DELETE request is sent to "/api/user-roles/{id}"
    Then the response status code should be 409
    And the response header "content-type" should contain "application/problem+json"
    And the JSON pointer "/type" should equal "/problems/last-administrator"
    And the JSON pointer "/status" should equal the number 409
    And the role "iam-platform-admin" should have 1 active global assignment
    And the audit log should hold 1 rejected "user_role.revoke" record with the reason "last_administrator"
    And the audit log should hold 0 committed "user_role.revoke" records

  Scenario: The last administrator assignment cannot be given an expiry over REST and the refusal is audited
    Given a caller authenticated as the bootstrapped administrator
    And the first administrator is bootstrapped
    When PATCH request is sent to "/api/user-roles/{id}" with body:
      """
      {"expiresAt": "2099-01-01T00:00:00Z"}
      """
    Then the response status code should be 409
    And the JSON pointer "/type" should equal "/problems/last-administrator"
    And the role "iam-platform-admin" should have 1 active global assignment
    And the audit log should hold 1 rejected "user_role.update" record with the reason "last_administrator"
    And the audit log should hold 0 committed "user_role.update" records

  Scenario: The last administrator assignment cannot be revoked over GraphQL and the refusal is audited
    Given a caller authenticated as the bootstrapped administrator
    And the first administrator is bootstrapped
    When the GraphQL operation is sent:
      """
      mutation { revokeUserRole(input: {id: "{id}", expectedVersion: 1}) { id version } }
      """
    Then the GraphQL error code should be "LAST_ADMINISTRATOR"
    And the role "iam-platform-admin" should have 1 active global assignment
    And the audit log should hold 1 rejected "user_role.revoke" record with the reason "last_administrator"

  Scenario: The last administrator assignment cannot be given an expiry over GraphQL
    Given a caller authenticated as the bootstrapped administrator
    And the first administrator is bootstrapped
    When the GraphQL operation is sent:
      """
      mutation { updateUserRole(input: {id: "{id}", expectedVersion: 1, expiresAt: "2099-01-01T00:00:00Z"}) { id version } }
      """
    Then the GraphQL error code should be "LAST_ADMINISTRATOR"
    And the role "iam-platform-admin" should have 1 active global assignment
    And the audit log should hold 1 rejected "user_role.update" record with the reason "last_administrator"

  Scenario: The bootstrapped system role cannot be renamed or deleted over either interface
    Given a caller authenticated as the bootstrapped administrator
    And the first administrator is bootstrapped
    And the If-Match header '"2"'
    When DELETE request is sent to "/api/roles/{role}"
    Then the response status code should be 403
    When PATCH request is sent to "/api/roles/{role}" with body:
      """
      {"name": "renamed"}
      """
    Then the response status code should be 403
    When the GraphQL operation is sent:
      """
      mutation { deleteRole(input: {id: "{role}", expectedVersion: 2}) { id } }
      """
    Then the GraphQL error code should be "FORBIDDEN"
    When the GraphQL operation is sent:
      """
      mutation { updateRole(input: {id: "{role}", expectedVersion: 2, name: "renamed"}) { id } }
      """
    Then the GraphQL error code should be "FORBIDDEN"
