Feature: IAM role assignments
  In order to give people exactly the access their job needs
  As an administrator
  I want to assign roles to users and services, globally or per project, and see the assignments

  Scenario: Assigning a role to a user at global scope over REST commits the assignment, its event, its audit record and a policy version
    Given a caller authenticated with a valid service token
    And an assignable role "Billing administrator"
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 201
    And the response header "location" should contain "/api/user-roles/"
    And the response header "etag" should contain '"1"'
    And the response header "iam-policy-version" should contain "1"
    And the JSON pointer "/id" should be present
    And the JSON pointer "/subject/kind" should equal "user"
    And the JSON pointer "/subject/id" should equal "0190f2a8-7b3c-7d4e-8f10-1234567890ab"
    And the JSON pointer "/roleName" should equal "Billing administrator"
    And the JSON pointer "/scope/kind" should equal "global"
    And the JSON pointer "/scope/projectId" should be absent
    And the JSON pointer "/expiresAt" should be absent
    And the JSON pointer "/version" should equal the number 1
    And the JSON pointer "/createdAt" should be present
    And the JSON pointer "/updatedAt" should be present
    And the IAM policy version should be 1
    And the outbox should hold 1 "iam.user_role.assigned" event
    And the "iam.user_role.assigned" event should carry "userId" in its payload
    And the "iam.user_role.assigned" event should carry "subject" in its payload
    And the outbox should hold 0 "iam.privileged_role.assigned" events
    And the audit log should hold 1 committed "user_role.assign" record

  Scenario: Assigning a role to a user at project scope with an expiry over GraphQL returns the same data
    Given a caller authenticated with a valid service token
    And an assignable role "Billing administrator"
    When the GraphQL operation is sent:
      """
      mutation { assignUserRole(input: {subject: {kind: "user", id: "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, roleId: "{role}", scope: {kind: "project", projectId: "0190f2a8-7b3c-7d4e-8f10-1234567890cd"}, expiresAt: "2099-01-01T00:00:00Z"}) { id subject { kind id } roleId roleName scope { kind projectId } expiresAt version createdAt updatedAt } }
      """
    Then the response status code should be 200
    And the GraphQL response should have no errors
    And the JSON pointer "/data/assignUserRole/id" should be present
    And the JSON pointer "/data/assignUserRole/subject/kind" should equal "user"
    And the JSON pointer "/data/assignUserRole/roleName" should equal "Billing administrator"
    And the JSON pointer "/data/assignUserRole/scope/kind" should equal "project"
    And the JSON pointer "/data/assignUserRole/scope/projectId" should equal "0190f2a8-7b3c-7d4e-8f10-1234567890cd"
    And the JSON pointer "/data/assignUserRole/expiresAt" should equal "2099-01-01T00:00:00.000000Z"
    And the JSON pointer "/data/assignUserRole/version" should equal the number 1
    And the JSON pointer "/data/assignUserRole/createdAt" should be present
    And the IAM policy version should be 1
    And the outbox should hold 1 "iam.user_role.assigned" event
    And the audit log should hold 1 committed "user_role.assign" record

  Scenario: Assigning a role to a project over REST keeps the project scope and the expiry
    Given a caller authenticated with a valid service token
    And an assignable role "Billing administrator"
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "project", "projectId": "0190f2a8-7b3c-7d4e-8f10-1234567890cd"}, "expiresAt": "2099-01-01T00:00:00Z"}
      """
    Then the response status code should be 201
    And the JSON pointer "/scope/kind" should equal "project"
    And the JSON pointer "/scope/projectId" should equal "0190f2a8-7b3c-7d4e-8f10-1234567890cd"
    And the JSON pointer "/expiresAt" should equal "2099-01-01T00:00:00.000000Z"

  Scenario: Assigning a role to a service subject over REST stores and lists it with the subject kind service
    Given a caller authenticated with a valid service token
    And an assignable role "Billing administrator"
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "service", "id": "billing-worker"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 201
    And the JSON pointer "/subject/kind" should equal "service"
    And the JSON pointer "/subject/id" should equal "billing-worker"
    And the store should hold 1 assignment of subject kind "service"
    And the "iam.user_role.assigned" event should carry "billing-worker" in its payload
    When GET request is sent to "/api/user-roles?subjectKind=service"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON pointer "/items/0/subject/kind" should equal "service"
    And the JSON pointer "/items/0/subject/id" should equal "billing-worker"

  Scenario: Assigning a role to a service subject over GraphQL stores and lists it with the subject kind service
    Given a caller authenticated with a valid service token
    And an assignable role "Billing administrator"
    When the GraphQL operation is sent:
      """
      mutation { assignUserRole(input: {subject: {kind: "service", id: "billing-worker"}, roleId: "{role}", scope: {kind: "global"}}) { id subject { kind id } } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/assignUserRole/subject/kind" should equal "service"
    And the store should hold 1 assignment of subject kind "service"
    When the GraphQL operation is sent:
      """
      { userRoles(filter: {subjectKind: "service"}) { items { subject { kind id } } nextCursor } }
      """
    Then the GraphQL response should have no errors
    And the JSON array at "/data/userRoles/items" should have 1 items
    And the JSON pointer "/data/userRoles/items/0/subject/kind" should equal "service"
    And the JSON pointer "/data/userRoles/items/0/subject/id" should equal "billing-worker"

  Scenario: Assigning a role that grants a wildcard or a reserved key also commits the privileged alert
    Given a caller authenticated with a valid service token
    And an assignable role "Operator" that grants "iam:audit:read, rest:billing:*, rest:billing:GET /invoices"
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 201
    And the outbox should hold 1 "iam.user_role.assigned" event
    And the outbox should hold 1 "iam.privileged_role.assigned" event
    And the "iam.privileged_role.assigned" event should carry "iam:audit:read" in its payload
    And the "iam.privileged_role.assigned" event should carry "rest:billing:*" in its payload
    And the audit log should hold 1 committed "user_role.assign" record

  Scenario: Assigning a role that grants only ordinary keys commits no privileged alert
    Given a caller authenticated with a valid service token
    And an assignable role "Invoice reader" that grants "rest:billing:GET /invoices"
    When the GraphQL operation is sent:
      """
      mutation { assignUserRole(input: {subject: {kind: "user", id: "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, roleId: "{role}", scope: {kind: "global"}}) { id } }
      """
    Then the GraphQL response should have no errors
    And the outbox should hold 1 "iam.user_role.assigned" event
    And the outbox should hold 0 "iam.privileged_role.assigned" events

  Scenario: A duplicate assignment is a conflict over REST and GraphQL
    Given a caller authenticated with a valid service token
    And an assignable role "Billing administrator"
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 409
    When the GraphQL operation is sent:
      """
      mutation { assignUserRole(input: {subject: {kind: "user", id: "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, roleId: "{role}", scope: {kind: "global"}}) { id } }
      """
    Then the GraphQL error code should be "CONFLICT"
    And the store should hold 1 assignment of subject kind "user"
    And the IAM policy version should be 1
    And the outbox should hold 1 "iam.user_role.assigned" event
    And the audit log should hold 1 committed "user_role.assign" record

  Scenario: The same role may be assigned at another scope or to another subject
    Given a caller authenticated with a valid service token
    And an assignable role "Billing administrator"
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    And POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "project", "projectId": "0190f2a8-7b3c-7d4e-8f10-1234567890cd"}}
      """
    And POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ef"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 201
    And the store should hold 3 assignments of subject kind "user"
    And the IAM policy version should be 3

  Scenario: A past expiry is a validation failure over REST and GraphQL
    Given a caller authenticated with a valid service token
    And an assignable role "Billing administrator"
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "global"}, "expiresAt": "2020-01-01T00:00:00Z"}
      """
    Then the response status code should be 422
    And the response body should contain "/problems/validation-failed"
    And the response body should contain "expiresAt"
    When the GraphQL operation is sent:
      """
      mutation { assignUserRole(input: {subject: {kind: "user", id: "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, roleId: "{role}", scope: {kind: "global"}, expiresAt: "2020-01-01T00:00:00Z"}) { id } }
      """
    Then the GraphQL error code should be "VALIDATION_FAILED"
    And the response body should contain "expiresAt"
    And the store should hold 0 assignments of subject kind "user"
    And the IAM policy version should be 0
    And the outbox should hold 0 "iam.user_role.assigned" events
    And the audit log should hold 0 committed "user_role.assign" records

  Scenario: An unknown role is a validation failure on roleId over REST and GraphQL
    Given a caller authenticated with a valid service token
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "00000000-0000-7000-8000-000000000000", "scope": {"kind": "global"}}
      """
    Then the response status code should be 422
    And the response body should contain "/problems/validation-failed"
    And the response body should contain "roleId"
    When the GraphQL operation is sent:
      """
      mutation { assignUserRole(input: {subject: {kind: "user", id: "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, roleId: "00000000-0000-7000-8000-000000000000", scope: {kind: "global"}}) { id } }
      """
    Then the GraphQL error code should be "VALIDATION_FAILED"
    And the response body should contain "roleId"
    And the store should hold 0 assignments of subject kind "user"
    And the outbox should hold 0 "iam.user_role.assigned" events

  Scenario: Invalid subjects, scopes and identifiers are validation failures that name their property
    Given a caller authenticated with a valid service token
    And an assignable role "Billing administrator"
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "robot", "id": "x"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 422
    And the response body should contain "subject.kind"
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "not-a-uuid"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 422
    And the response body should contain "subject.id"
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "service", "id": "Billing Worker"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 422
    And the response body should contain "subject.id"
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "project"}}
      """
    Then the response status code should be 422
    And the response body should contain "scope.projectId"
    When the GraphQL operation is sent:
      """
      mutation { assignUserRole(input: {subject: {kind: "robot", id: "x"}, roleId: "{role}", scope: {kind: "global"}}) { id } }
      """
    Then the GraphQL error code should be "VALIDATION_FAILED"
    And the response body should contain "subject.kind"
    And the store should hold 0 assignments of subject kind "user"

  Scenario: Repeating an assignment with the same idempotency key returns the original result
    Given a caller authenticated with a valid service token
    And an assignable role "Billing administrator"
    And the idempotency key "assign-billing-rest"
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    And POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 201
    And the last two responses should have the same body
    And the store should hold 1 assignment of subject kind "user"
    And the IAM policy version should be 1
    And the outbox should hold 1 "iam.user_role.assigned" event
    And the audit log should hold 1 committed "user_role.assign" record

  Scenario: Reading an assignment by id over REST and GraphQL
    Given a caller authenticated with a valid service token
    And an assignable role "Billing administrator"
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "project", "projectId": "0190f2a8-7b3c-7d4e-8f10-1234567890cd"}, "expiresAt": "2099-01-01T00:00:00Z"}
      """
    And GET request is sent to "/api/user-roles/{id}"
    Then the response status code should be 200
    And the response header "etag" should contain '"1"'
    And the JSON pointer "/subject/kind" should equal "user"
    And the JSON pointer "/roleName" should equal "Billing administrator"
    And the JSON pointer "/scope/kind" should equal "project"
    And the JSON pointer "/scope/projectId" should equal "0190f2a8-7b3c-7d4e-8f10-1234567890cd"
    And the JSON pointer "/expiresAt" should equal "2099-01-01T00:00:00.000000Z"
    And the JSON pointer "/version" should equal the number 1
    And the JSON pointer "/createdAt" should be present
    And the JSON pointer "/updatedAt" should be present
    When the GraphQL operation is sent:
      """
      { userRole(id: "{id}") { id roleName scope { kind projectId } expiresAt version createdAt updatedAt } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/userRole/roleName" should equal "Billing administrator"
    And the JSON pointer "/data/userRole/scope/kind" should equal "project"
    And the JSON pointer "/data/userRole/expiresAt" should equal "2099-01-01T00:00:00.000000Z"
    And the JSON pointer "/data/userRole/version" should equal the number 1

  Scenario: An unknown assignment is 404 over REST and null over GraphQL
    Given a caller authenticated with a valid service token
    When GET request is sent to "/api/user-roles/00000000-0000-7000-8000-000000000000"
    Then the response status code should be 404
    When GET request is sent to "/api/user-roles/not-a-uuid"
    Then the response status code should be 422
    When the GraphQL operation is sent:
      """
      { userRole(id: "00000000-0000-7000-8000-000000000000") { id } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/userRole" should be null

  Scenario: Assignments are listed with cursor pagination over REST
    Given a caller authenticated with a valid service token
    And an assignable role "Billing administrator"
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-000000000001"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    And POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-000000000002"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    And POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-000000000003"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    And GET request is sent to "/api/user-roles?limit=2"
    Then the response status code should be 200
    And the JSON array at "/items" should have 2 items
    And the JSON pointer "/items/0/subject/id" should equal "0190f2a8-7b3c-7d4e-8f10-000000000001"
    And the JSON pointer "/items/1/subject/id" should equal "0190f2a8-7b3c-7d4e-8f10-000000000002"
    And the JSON pointer "/items/0/roleName" should equal "Billing administrator"
    And the JSON pointer "/items/0/scope/kind" should equal "global"
    And the JSON pointer "/items/0/version" should equal the number 1
    And the JSON pointer "/items/0/createdAt" should be present
    And the JSON pointer "/nextCursor" should be present
    When the cursor at "/nextCursor" is remembered
    And GET request is sent to "/api/user-roles?limit=2&after={cursor}"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON pointer "/items/0/subject/id" should equal "0190f2a8-7b3c-7d4e-8f10-000000000003"
    And the JSON pointer "/nextCursor" should be absent

  Scenario: Assignments are filtered by subject, role and project over REST
    Given a caller authenticated with a valid service token
    And an assignable role "Billing administrator"
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-000000000001"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    And POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-000000000002"}, "roleId": "{role}", "scope": {"kind": "project", "projectId": "0190f2a8-7b3c-7d4e-8f10-1234567890cd"}}
      """
    And POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "service", "id": "billing-worker"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    And GET request is sent to "/api/user-roles?subjectKind=user"
    Then the JSON array at "/items" should have 2 items
    When GET request is sent to "/api/user-roles?subjectId=0190f2a8-7b3c-7d4e-8f10-000000000002"
    Then the JSON array at "/items" should have 1 items
    And the JSON pointer "/items/0/scope/kind" should equal "project"
    When GET request is sent to "/api/user-roles?projectId=0190f2a8-7b3c-7d4e-8f10-1234567890cd"
    Then the JSON array at "/items" should have 1 items
    When GET request is sent to "/api/user-roles?roleId={role}"
    Then the JSON array at "/items" should have 3 items
    When GET request is sent to "/api/user-roles?roleId=00000000-0000-7000-8000-000000000000"
    Then the JSON array at "/items" should have 0 items
    When GET request is sent to "/api/user-roles?includeExpired=true"
    Then the JSON array at "/items" should have 3 items

  Scenario: Assignments are listed with cursor pagination and filters over GraphQL
    Given a caller authenticated with a valid service token
    And an assignable role "Billing administrator"
    When the GraphQL operation is sent:
      """
      mutation { assignUserRole(input: {subject: {kind: "user", id: "0190f2a8-7b3c-7d4e-8f10-000000000001"}, roleId: "{role}", scope: {kind: "global"}}) { id } }
      """
    And the GraphQL operation is sent:
      """
      mutation { assignUserRole(input: {subject: {kind: "user", id: "0190f2a8-7b3c-7d4e-8f10-000000000002"}, roleId: "{role}", scope: {kind: "global"}}) { id } }
      """
    And the GraphQL operation is sent:
      """
      mutation { assignUserRole(input: {subject: {kind: "service", id: "billing-worker"}, roleId: "{role}", scope: {kind: "global"}}) { id } }
      """
    And the GraphQL operation is sent:
      """
      { userRoles(first: 2) { items { id roleName scope { kind } version createdAt updatedAt } nextCursor } }
      """
    Then the GraphQL response should have no errors
    And the JSON array at "/data/userRoles/items" should have 2 items
    And the JSON pointer "/data/userRoles/items/0/roleName" should equal "Billing administrator"
    And the JSON pointer "/data/userRoles/items/0/version" should equal the number 1
    And the JSON pointer "/data/userRoles/nextCursor" should be present
    When the cursor at "/data/userRoles/nextCursor" is remembered
    And the GraphQL operation is sent:
      """
      { userRoles(first: 2, after: "{cursor}") { items { subject { kind } } nextCursor } }
      """
    Then the JSON array at "/data/userRoles/items" should have 1 items
    And the JSON pointer "/data/userRoles/items/0/subject/kind" should equal "service"
    And the JSON pointer "/data/userRoles/nextCursor" should be null
    When the GraphQL operation is sent:
      """
      { userRoles(first: 10, filter: {subjectKind: "user", roleId: "{role}", includeExpired: true}) { items { subject { id } } nextCursor } }
      """
    Then the JSON array at "/data/userRoles/items" should have 2 items

  Scenario: Invalid list parameters are validation failures over REST and GraphQL
    Given a caller authenticated with a valid service token
    When GET request is sent to "/api/user-roles?limit=0"
    Then the response status code should be 422
    When GET request is sent to "/api/user-roles?subjectKind=robot"
    Then the response status code should be 422
    When the GraphQL operation is sent:
      """
      { userRoles(filter: {roleId: "x"}) { items { id } } }
      """
    Then the GraphQL error code should be "VALIDATION_FAILED"

  Scenario: Setting, shortening and clearing an expiry over REST commits each update, its event, its audit record and a policy version
    Given a caller authenticated with a valid service token
    And an assignable role "Billing administrator"
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 201
    Given the If-Match header is the ETag of the last response
    When PATCH request is sent to "/api/user-roles/{id}" with body:
      """
      {"expiresAt": "2099-01-01T00:00:00Z"}
      """
    Then the response status code should be 200
    And the response header "etag" should contain '"2"'
    And the response header "iam-policy-version" should contain "2"
    And the JSON pointer "/expiresAt" should equal "2099-01-01T00:00:00.000000Z"
    And the JSON pointer "/version" should equal the number 2
    Given the If-Match header is the ETag of the last response
    When PATCH request is sent to "/api/user-roles/{id}" with body:
      """
      {"expiresAt": "2098-01-01T00:00:00Z"}
      """
    Then the response status code should be 200
    And the JSON pointer "/expiresAt" should equal "2098-01-01T00:00:00.000000Z"
    And the JSON pointer "/version" should equal the number 3
    Given the If-Match header is the ETag of the last response
    When PATCH request is sent to "/api/user-roles/{id}" with body:
      """
      {"expiresAt": null}
      """
    Then the response status code should be 200
    And the JSON pointer "/expiresAt" should be absent
    And the JSON pointer "/version" should equal the number 4
    And the IAM policy version should be 4
    And the outbox should hold 3 "iam.user_role.updated" events
    And the audit log should hold 3 committed "user_role.update" records
    When GET request is sent to "/api/user-roles/{id}"
    Then the response status code should be 200
    And the JSON pointer "/version" should equal the number 4

  Scenario: Changing an expiry over GraphQL returns the new expiry and version
    Given a caller authenticated with a valid service token
    And an assignable role "Billing administrator"
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "global"}, "expiresAt": "2099-01-01T00:00:00Z"}
      """
    Then the response status code should be 201
    When the GraphQL operation is sent:
      """
      mutation { updateUserRole(input: {id: "{id}", expectedVersion: 1, expiresAt: "2098-06-01T00:00:00Z"}) { id expiresAt version } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/updateUserRole/expiresAt" should equal "2098-06-01T00:00:00.000000Z"
    And the JSON pointer "/data/updateUserRole/version" should equal the number 2
    When the GraphQL operation is sent:
      """
      mutation { updateUserRole(input: {id: "{id}", expectedVersion: 2, expiresAt: null}) { id expiresAt version } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/updateUserRole/expiresAt" should be null
    And the JSON pointer "/data/updateUserRole/version" should equal the number 3
    And the IAM policy version should be 3
    And the outbox should hold 2 "iam.user_role.updated" events
    And the audit log should hold 2 committed "user_role.update" records

  Scenario: An expiry that is not in the future is a validation failure on update over REST and GraphQL
    Given a caller authenticated with a valid service token
    And an assignable role "Billing administrator"
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 201
    Given the If-Match header is the ETag of the last response
    When PATCH request is sent to "/api/user-roles/{id}" with body:
      """
      {"expiresAt": "2000-01-01T00:00:00Z"}
      """
    Then the response status code should be 422
    When the GraphQL operation is sent:
      """
      mutation { updateUserRole(input: {id: "{id}", expectedVersion: 1, expiresAt: "2000-01-01T00:00:00Z"}) { id } }
      """
    Then the GraphQL error code should be "VALIDATION_FAILED"
    And the outbox should hold 0 "iam.user_role.updated" events
    And the IAM policy version should be 1

  Scenario: An update without a version or with a stale version is refused over REST and GraphQL
    Given a caller authenticated with a valid service token
    And an assignable role "Billing administrator"
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 201
    When PATCH request is sent to "/api/user-roles/{id}" with body:
      """
      {"expiresAt": "2099-01-01T00:00:00Z"}
      """
    Then the response status code should be 428
    When the GraphQL operation is sent:
      """
      mutation { updateUserRole(input: {id: "{id}", expiresAt: "2099-01-01T00:00:00Z"}) { id } }
      """
    Then the GraphQL error code should be "PRECONDITION_REQUIRED"
    Given the If-Match header '"7"'
    When PATCH request is sent to "/api/user-roles/{id}" with body:
      """
      {"expiresAt": "2099-01-01T00:00:00Z"}
      """
    Then the response status code should be 412
    When the GraphQL operation is sent:
      """
      mutation { updateUserRole(input: {id: "{id}", expectedVersion: 7, expiresAt: "2099-01-01T00:00:00Z"}) { id } }
      """
    Then the GraphQL error code should be "PRECONDITION_FAILED"
    And the outbox should hold 0 "iam.user_role.updated" events

  Scenario: Revoking an assignment over REST removes it from the listings and commits its event, its audit record and a policy version
    Given a caller authenticated with a valid service token
    And an assignable role "Billing administrator"
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 201
    Given the If-Match header is the ETag of the last response
    When DELETE request is sent to "/api/user-roles/{id}"
    Then the response status code should be 204
    And the response header "iam-policy-version" should contain "2"
    And the IAM policy version should be 2
    And the store should hold 0 assignments of subject kind "user"
    And the outbox should hold 1 "iam.user_role.revoked" event
    And the "iam.user_role.revoked" event should carry "Billing administrator" in its payload
    And the audit log should hold 1 committed "user_role.revoke" record
    When GET request is sent to "/api/user-roles/{id}"
    Then the response status code should be 404
    When GET request is sent to "/api/user-roles?includeExpired=true"
    Then the response status code should be 200
    And the JSON array at "/items" should have 0 items

  Scenario: Revoking an assignment over GraphQL removes it from the listings and commits its event, its audit record and a policy version
    Given a caller authenticated with a valid service token
    And an assignable role "Billing administrator"
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 201
    When the GraphQL operation is sent:
      """
      mutation { revokeUserRole(input: {id: "{id}", expectedVersion: 1}) { id version policyVersion } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/revokeUserRole/id" should be present
    And the JSON pointer "/data/revokeUserRole/version" should equal the number 2
    And the JSON pointer "/data/revokeUserRole/policyVersion" should equal the number 2
    And the IAM policy version should be 2
    And the store should hold 0 assignments of subject kind "user"
    And the outbox should hold 1 "iam.user_role.revoked" event
    And the audit log should hold 1 committed "user_role.revoke" record
    When the GraphQL operation is sent:
      """
      query { userRole(id: "{id}") { id } }
      """
    Then the JSON pointer "/data/userRole" should be null
    When the GraphQL operation is sent:
      """
      { userRoles(filter: {includeExpired: true}) { items { id } } }
      """
    Then the JSON array at "/data/userRoles/items" should have 0 items

  Scenario: A revocation without a version, with a stale version or of an assignment that is already revoked is refused
    Given a caller authenticated with a valid service token
    And an assignable role "Billing administrator"
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 201
    When DELETE request is sent to "/api/user-roles/{id}"
    Then the response status code should be 428
    When the GraphQL operation is sent:
      """
      mutation { revokeUserRole(input: {id: "{id}"}) { id } }
      """
    Then the GraphQL error code should be "PRECONDITION_REQUIRED"
    Given the If-Match header '"7"'
    When DELETE request is sent to "/api/user-roles/{id}"
    Then the response status code should be 412
    When the GraphQL operation is sent:
      """
      mutation { revokeUserRole(input: {id: "{id}", expectedVersion: 7}) { id } }
      """
    Then the GraphQL error code should be "PRECONDITION_FAILED"
    And the outbox should hold 0 "iam.user_role.revoked" events
    And the IAM policy version should be 1
    Given the If-Match header '"1"'
    When DELETE request is sent to "/api/user-roles/{id}"
    Then the response status code should be 204
    When DELETE request is sent to "/api/user-roles/{id}"
    Then the response status code should be 404
    When the GraphQL operation is sent:
      """
      mutation { revokeUserRole(input: {id: "{id}", expectedVersion: 1}) { id } }
      """
    Then the GraphQL error code should be "NOT_FOUND"
    And the outbox should hold 1 "iam.user_role.revoked" event

  Scenario: Repeating a revocation with the same idempotency key returns the original result
    Given a caller authenticated with a valid service token
    And an assignable role "Billing administrator"
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 201
    Given the If-Match header '"1"'
    And the idempotency key "revoke-billing"
    When DELETE request is sent to "/api/user-roles/{id}"
    Then the response status code should be 204
    When DELETE request is sent to "/api/user-roles/{id}"
    Then the response status code should be 204
    And the response header "iam-policy-version" should contain "2"
    And the outbox should hold 1 "iam.user_role.revoked" event
    And the audit log should hold 1 committed "user_role.revoke" record
    And the IAM policy version should be 2

  Scenario: Updating and revoking an assignment need a valid bearer token
    When PATCH request is sent to "/api/user-roles/0190f2a8-7b3c-7d4e-8f10-1234567890ab" with body:
      """
      {"expiresAt": null}
      """
    Then the response status code should be 401
    When DELETE request is sent to "/api/user-roles/0190f2a8-7b3c-7d4e-8f10-1234567890ab"
    Then the response status code should be 401
    When the GraphQL operation is sent:
      """
      mutation { revokeUserRole(input: {id: "0190f2a8-7b3c-7d4e-8f10-1234567890ab", expectedVersion: 1}) { id } }
      """
    Then the GraphQL error code should be "UNAUTHENTICATED"

  Scenario: Assignment operations need a valid bearer token
    When GET request is sent to "/api/user-roles"
    Then the response status code should be 401
    And the response should challenge with the Bearer scheme
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "00000000-0000-7000-8000-000000000000", "scope": {"kind": "global"}}
      """
    Then the response status code should be 401
    When the GraphQL operation is sent:
      """
      { userRoles { items { id } } }
      """
    Then the GraphQL error code should be "UNAUTHENTICATED"
