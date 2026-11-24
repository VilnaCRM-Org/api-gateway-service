Feature: IAM roles
  In order to build my organisation's role model
  As an administrator
  I want to create, read and update roles over REST or GraphQL

  Scenario: Creating a role over REST commits the role, its event and its audit record
    Given a caller authenticated as the bootstrapped administrator
    When POST request is sent to "/api/roles" with body:
      """
      {"name": "Billing administrator", "description": "Manages invoices."}
      """
    Then the response status code should be 201
    And the response header "location" should contain "/api/roles/"
    And the response header "etag" should contain '"1"'
    And the JSON pointer "/id" should be present
    And the JSON pointer "/name" should equal "Billing administrator"
    And the JSON pointer "/description" should equal "Manages invoices."
    And the JSON pointer "/kind" should equal "custom"
    And the JSON pointer "/grantCount" should equal the number 0
    And the JSON pointer "/version" should equal the number 1
    And the outbox should hold 1 "iam.role.created" event
    And the audit log should hold 1 committed "role.create" record

  Scenario: Creating a role over GraphQL returns the same data
    Given a caller authenticated as the bootstrapped administrator
    When the GraphQL operation is sent:
      """
      mutation { createRole(input: {name: "Billing administrator", description: "Manages invoices."}) { id name description kind grantCount version createdAt updatedAt } }
      """
    Then the response status code should be 200
    And the GraphQL response should have no errors
    And the JSON pointer "/data/createRole/id" should be present
    And the JSON pointer "/data/createRole/name" should equal "Billing administrator"
    And the JSON pointer "/data/createRole/description" should equal "Manages invoices."
    And the JSON pointer "/data/createRole/kind" should equal "custom"
    And the JSON pointer "/data/createRole/grantCount" should equal the number 0
    And the JSON pointer "/data/createRole/version" should equal the number 1
    And the JSON pointer "/data/createRole/createdAt" should be present
    And the outbox should hold 1 "iam.role.created" event
    And the audit log should hold 1 committed "role.create" record

  Scenario: Waiting for the propagated mode is refused before Story 13.4 over REST and GraphQL
    Given a caller authenticated as the bootstrapped administrator
    And the Prefer header "wait=propagated"
    When POST request is sent to "/api/roles" with body:
      """
      {"name": "Billing administrator"}
      """
    Then the response status code should be 422
    And the response body should contain "/problems/validation-failed"
    And the response body should contain "The write mode `propagated` is not supported yet"
    When the GraphQL operation is sent:
      """
      mutation { createRole(input: {name: "Billing administrator", consistency: "PROPAGATED"}) { id } }
      """
    Then the GraphQL error code should be "VALIDATION_FAILED"
    And the response body should contain "The write mode `propagated` is not supported yet"
    And the outbox should hold 0 "iam.role.created" events

  Scenario: A duplicate name is a conflict over REST and GraphQL
    Given a caller authenticated as the bootstrapped administrator
    And a role exists with name "Billing administrator"
    When POST request is sent to "/api/roles" with body:
      """
      {"name": "billing ADMINISTRATOR"}
      """
    Then the response status code should be 409
    When the GraphQL operation is sent:
      """
      mutation { createRole(input: {name: "Billing Administrator"}) { id } }
      """
    Then the GraphQL error code should be "CONFLICT"
    And the role "Billing administrator" should be stored once
    And the outbox should hold 1 "iam.role.created" event
    And the audit log should hold 1 committed "role.create" record

  Scenario: An invalid name is a validation failure with the same violations over REST and GraphQL
    Given a caller authenticated as the bootstrapped administrator
    When POST request is sent to "/api/roles" with body:
      """
      {"name": ""}
      """
    Then the response status code should be 422
    And the response body should contain "/problems/validation-failed"
    And the response body should contain "This value must contain between 1 and 100 characters."
    When the GraphQL operation is sent:
      """
      mutation { createRole(input: {name: ""}) { id } }
      """
    Then the GraphQL error code should be "VALIDATION_FAILED"
    And the response body should contain "This value must contain between 1 and 100 characters."
    And the outbox should hold 0 "iam.role.created" events

  Scenario: Repeating a REST creation with the same idempotency key returns the original result
    Given a caller authenticated as the bootstrapped administrator
    And the idempotency key "create-billing-rest"
    When POST request is sent to "/api/roles" with body:
      """
      {"name": "Billing administrator"}
      """
    And POST request is sent to "/api/roles" with body:
      """
      {"name": "Billing administrator"}
      """
    Then the response status code should be 201
    And the last two responses should have the same body
    And the role "Billing administrator" should be stored once
    And the outbox should hold 1 "iam.role.created" event
    And the audit log should hold 1 committed "role.create" record

  Scenario: Repeating a GraphQL creation with the same idempotency key returns the original result
    Given a caller authenticated as the bootstrapped administrator
    When the GraphQL operation is sent:
      """
      mutation { createRole(input: {name: "Billing administrator", idempotencyKey: "create-billing-graphql"}) { id name version } }
      """
    And the GraphQL operation is sent:
      """
      mutation { createRole(input: {name: "Billing administrator", idempotencyKey: "create-billing-graphql"}) { id name version } }
      """
    Then the GraphQL response should have no errors
    And the last two responses should have the same body
    And the role "Billing administrator" should be stored once
    And the outbox should hold 1 "iam.role.created" event
    And the audit log should hold 1 committed "role.create" record

  Scenario: Reusing an idempotency key for another request is refused
    Given a caller authenticated as the bootstrapped administrator
    And the idempotency key "create-billing-reused"
    When POST request is sent to "/api/roles" with body:
      """
      {"name": "Billing administrator"}
      """
    And POST request is sent to "/api/roles" with body:
      """
      {"name": "Support agent"}
      """
    Then the response status code should be 422
    And the response body should contain "The idempotency key was already used for a different request."
    And the role "Support agent" should be stored 0 times

  Scenario: Reading a role by id over REST and GraphQL
    Given a caller authenticated as the bootstrapped administrator
    And a role exists with name "Billing administrator"
    When GET request is sent to "/api/roles/{id}"
    Then the response status code should be 200
    And the response header "etag" should contain '"1"'
    And the JSON pointer "/name" should equal "Billing administrator"
    And the JSON pointer "/kind" should equal "custom"
    And the JSON pointer "/grantCount" should equal the number 0
    And the JSON pointer "/version" should equal the number 1
    And the JSON pointer "/createdAt" should be present
    And the JSON pointer "/updatedAt" should be present
    When the GraphQL operation is sent:
      """
      { role(id: "{id}") { id name description kind grantCount version createdAt updatedAt } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/role/name" should equal "Billing administrator"
    And the JSON pointer "/data/role/kind" should equal "custom"
    And the JSON pointer "/data/role/grantCount" should equal the number 0
    And the JSON pointer "/data/role/version" should equal the number 1

  Scenario: An unknown role is 404 over REST and null over GraphQL
    Given a caller authenticated as the bootstrapped administrator
    When GET request is sent to "/api/roles/00000000-0000-7000-8000-000000000000"
    Then the response status code should be 404
    When the GraphQL operation is sent:
      """
      { role(id: "00000000-0000-7000-8000-000000000000") { id } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/role" should be null

  Scenario: Roles are listed with cursor pagination over REST
    Given a caller authenticated as the bootstrapped administrator
    And a role exists with name "Alpha role"
    And a role exists with name "Beta role"
    And a role exists with name "Gamma role"
    When GET request is sent to "/api/roles?limit=2"
    Then the response status code should be 200
    And the JSON array at "/items" should have 2 items
    And the JSON pointer "/items/0/name" should equal "Alpha role"
    And the JSON pointer "/items/1/name" should equal "Beta role"
    And the JSON pointer "/nextCursor" should be present
    When the cursor at "/nextCursor" is remembered
    And GET request is sent to "/api/roles?limit=2&after={cursor}"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON pointer "/items/0/name" should equal "Gamma role"
    And the JSON pointer "/nextCursor" should be absent

  Scenario: Roles are filtered by name prefix and kind over REST
    Given a caller authenticated as the bootstrapped administrator
    And a role exists with name "Alpha role"
    And a role exists with name "Beta role"
    When GET request is sent to "/api/roles?namePrefix=ALP"
    Then the JSON array at "/items" should have 1 items
    And the JSON pointer "/items/0/name" should equal "Alpha role"
    And the JSON pointer "/items/0/grantCount" should equal the number 0
    When GET request is sent to "/api/roles?kind=custom"
    Then the JSON array at "/items" should have 2 items
    When GET request is sent to "/api/roles?kind=system"
    Then the JSON array at "/items" should have 0 items

  Scenario: Roles are listed with cursor pagination and filters over GraphQL
    Given a caller authenticated as the bootstrapped administrator
    And a role exists with name "Alpha role"
    And a role exists with name "Beta role"
    And a role exists with name "Gamma role"
    When the GraphQL operation is sent:
      """
      { roles(first: 2) { items { id name kind grantCount version createdAt updatedAt } nextCursor } }
      """
    Then the GraphQL response should have no errors
    And the JSON array at "/data/roles/items" should have 2 items
    And the JSON pointer "/data/roles/items/0/name" should equal "Alpha role"
    And the JSON pointer "/data/roles/nextCursor" should be present
    When the cursor at "/data/roles/nextCursor" is remembered
    And the GraphQL operation is sent:
      """
      { roles(first: 2, after: "{cursor}") { items { name } nextCursor } }
      """
    Then the JSON array at "/data/roles/items" should have 1 items
    And the JSON pointer "/data/roles/items/0/name" should equal "Gamma role"
    And the JSON pointer "/data/roles/nextCursor" should be null
    When the GraphQL operation is sent:
      """
      { roles(first: 10, filter: {namePrefix: "beta", kind: "custom"}) { items { name } nextCursor } }
      """
    Then the JSON array at "/data/roles/items" should have 1 items
    And the JSON pointer "/data/roles/items/0/name" should equal "Beta role"

  Scenario: Role operations need a valid bearer token
    When GET request is sent to "/api/roles"
    Then the response status code should be 401
    And the response should challenge with the Bearer scheme
    When POST request is sent to "/api/roles" with body:
      """
      {"name": "Billing administrator"}
      """
    Then the response status code should be 401
    When the GraphQL operation is sent:
      """
      { roles { items { id } } }
      """
    Then the GraphQL error code should be "UNAUTHENTICATED"

  Scenario: Renaming a role over REST with its current ETag commits the update, its event and its audit record
    Given a caller authenticated as the bootstrapped administrator
    And a role exists with name "Billing administrator"
    And the If-Match header is the ETag of the last response
    When PATCH request is sent to "/api/roles/{id}" with body:
      """
      {"name": "Accounting administrator", "description": null}
      """
    Then the response status code should be 200
    And the response header "etag" should contain '"2"'
    And the JSON pointer "/name" should equal "Accounting administrator"
    And the JSON pointer "/description" should be null
    And the JSON pointer "/version" should equal the number 2
    And the role "Billing administrator" should be stored 0 times
    And the outbox should hold 1 "iam.role.updated" event
    And the audit log should hold 1 committed "role.update" record

  Scenario: Renaming a role over GraphQL with its current version commits the update, its event and its audit record
    Given a caller authenticated as the bootstrapped administrator
    And a role exists with name "Billing administrator"
    When the GraphQL operation is sent:
      """
      mutation { updateRole(input: {id: "{id}", expectedVersion: 1, name: "Accounting administrator"}) { id name description version } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/updateRole/name" should equal "Accounting administrator"
    And the JSON pointer "/data/updateRole/version" should equal the number 2
    And the role "Billing administrator" should be stored 0 times
    And the outbox should hold 1 "iam.role.updated" event
    And the audit log should hold 1 committed "role.update" record

  Scenario: An update without a version is refused over REST and GraphQL
    Given a caller authenticated as the bootstrapped administrator
    And a role exists with name "Billing administrator"
    When PATCH request is sent to "/api/roles/{id}" with body:
      """
      {"name": "Accounting administrator"}
      """
    Then the response status code should be 428
    When the GraphQL operation is sent:
      """
      mutation { updateRole(input: {id: "{id}", name: "Accounting administrator"}) { id } }
      """
    Then the GraphQL error code should be "PRECONDITION_REQUIRED"
    And the role "Billing administrator" should be stored once
    And the outbox should hold 0 "iam.role.updated" events

  Scenario: An update with a stale version is refused over REST and GraphQL
    Given a caller authenticated as the bootstrapped administrator
    And a role exists with name "Billing administrator"
    And the If-Match header '"7"'
    When PATCH request is sent to "/api/roles/{id}" with body:
      """
      {"name": "Accounting administrator"}
      """
    Then the response status code should be 412
    When the GraphQL operation is sent:
      """
      mutation { updateRole(input: {id: "{id}", expectedVersion: 7, name: "Accounting administrator"}) { id } }
      """
    Then the GraphQL error code should be "PRECONDITION_FAILED"
    And the role "Billing administrator" should be stored once
    And the outbox should hold 0 "iam.role.updated" events

  Scenario: A system role cannot be updated over REST or GraphQL
    Given a caller authenticated as the bootstrapped administrator
    And a system role exists with name "Platform administrator"
    And the If-Match header '"1"'
    When PATCH request is sent to "/api/roles/{id}" with body:
      """
      {"name": "Renamed administrator"}
      """
    Then the response status code should be 403
    When the GraphQL operation is sent:
      """
      mutation { updateRole(input: {id: "{id}", expectedVersion: 1, name: "Renamed administrator"}) { id } }
      """
    Then the GraphQL error code should be "FORBIDDEN"
    When GET request is sent to "/api/roles/{id}"
    Then the JSON pointer "/name" should equal "Platform administrator"
    And the JSON pointer "/version" should equal the number 1
    And the outbox should hold 0 "iam.role.updated" events

  Scenario: Deleting a role over REST revokes its assignments and commits the events, the audit records and one policy version
    Given a caller authenticated as the bootstrapped administrator
    And an assignable role "Billing administrator"
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ac"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "service", "id": "billing-worker"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 201
    Given the If-Match header '"1"'
    When DELETE request is sent to "/api/roles/{role}"
    Then the response status code should be 200
    And the response header "etag" should contain '"2"'
    And the response header "iam-policy-version" should contain "6"
    And the JSON pointer "/id" should equal the seeded role
    And the JSON pointer "/revokedAssignments" should equal the number 3
    And the IAM policy version should be 6
    And the store should hold 0 assignments of subject kind "user"
    And the store should hold 0 assignments of subject kind "service"
    And the outbox should hold 1 "iam.role.deleted" event
    And the outbox should hold 3 "iam.user_role.revoked" events
    And the "iam.role.deleted" event should carry "Billing administrator" in its payload
    And the audit log should hold 1 committed "role.delete" record
    And the audit log should hold 3 committed "user_role.revoke" records
    When GET request is sent to "/api/roles/{role}"
    Then the response status code should be 404
    When GET request is sent to "/api/roles"
    Then the response status code should be 200
    And the JSON array at "/items" should have 0 items
    When GET request is sent to "/api/user-roles?includeExpired=true"
    Then the response status code should be 200
    And the JSON array at "/items" should have 0 items

  Scenario: Deleting a role over GraphQL revokes its assignments and reports their number
    Given a caller authenticated as the bootstrapped administrator
    And an assignable role "Billing administrator"
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ac"}, "roleId": "{role}", "scope": {"kind": "project", "projectId": "0190f2a8-7b3c-7d4e-8f10-1234567890cd"}}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "service", "id": "billing-worker"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 201
    When the GraphQL operation is sent:
      """
      mutation { deleteRole(input: {id: "{role}", expectedVersion: 1}) { id version policyVersion revokedAssignments } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/deleteRole/id" should equal the seeded role
    And the JSON pointer "/data/deleteRole/version" should equal the number 2
    And the JSON pointer "/data/deleteRole/policyVersion" should equal the number 6
    And the JSON pointer "/data/deleteRole/revokedAssignments" should equal the number 3
    And the IAM policy version should be 6
    And the store should hold 0 assignments of subject kind "user"
    And the store should hold 0 assignments of subject kind "service"
    And the outbox should hold 1 "iam.role.deleted" event
    And the outbox should hold 3 "iam.user_role.revoked" events
    And the audit log should hold 1 committed "role.delete" record
    And the audit log should hold 3 committed "user_role.revoke" records
    When the GraphQL operation is sent:
      """
      query { role(id: "{role}") { id } }
      """
    Then the JSON pointer "/data/role" should be null
    When the GraphQL operation is sent:
      """
      { userRoles(filter: {includeExpired: true}) { items { id } } }
      """
    Then the JSON array at "/data/userRoles/items" should have 0 items

  Scenario: A deletion whose statement fails changes nothing and leaves no event or audit record
    Given a caller authenticated as the bootstrapped administrator
    And an assignable role "Billing administrator"
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ac"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 201
    Given every update of an assignment fails in the store
    And the If-Match header '"1"'
    When DELETE request is sent to "/api/roles/{role}"
    Then the response status code should be 500
    When the GraphQL operation is sent:
      """
      mutation { deleteRole(input: {id: "{role}", expectedVersion: 1}) { id } }
      """
    Then the GraphQL error code should be "INTERNAL_SERVER_ERROR"
    And the IAM policy version should be 4
    And the store should hold 2 assignments of subject kind "user"
    And the outbox should hold 0 "iam.role.deleted" events
    And the outbox should hold 0 "iam.user_role.revoked" events
    And the audit log should hold 0 committed "role.delete" records
    And the audit log should hold 0 committed "user_role.revoke" records
    When GET request is sent to "/api/roles/{role}"
    Then the response status code should be 200
    And the JSON pointer "/version" should equal the number 1

  Scenario: A system role cannot be deleted and a stale or missing version is refused
    Given a caller authenticated as the bootstrapped administrator
    And a system role exists with name "iam-platform-admin"
    And the If-Match header '"1"'
    When DELETE request is sent to "/api/roles/{id}"
    Then the response status code should be 403
    When the GraphQL operation is sent:
      """
      mutation { deleteRole(input: {id: "{id}", expectedVersion: 1}) { id } }
      """
    Then the GraphQL error code should be "FORBIDDEN"
    Given an assignable role "Billing administrator"
    And the If-Match header '"7"'
    When DELETE request is sent to "/api/roles/{role}"
    Then the response status code should be 412
    When the GraphQL operation is sent:
      """
      mutation { deleteRole(input: {id: "{role}", expectedVersion: 7}) { id } }
      """
    Then the GraphQL error code should be "PRECONDITION_FAILED"
    When the GraphQL operation is sent:
      """
      mutation { deleteRole(input: {id: "{role}"}) { id } }
      """
    Then the GraphQL error code should be "PRECONDITION_REQUIRED"
    And the outbox should hold 0 "iam.role.deleted" events
    And the IAM policy version should be 2

  Scenario: A deletion without a version is refused over REST and a deleted role is not found again
    Given a caller authenticated as the bootstrapped administrator
    And an assignable role "Billing administrator"
    When DELETE request is sent to "/api/roles/{role}"
    Then the response status code should be 428
    Given the If-Match header '"1"'
    When DELETE request is sent to "/api/roles/{role}"
    Then the response status code should be 200
    And the JSON pointer "/revokedAssignments" should equal the number 0
    When DELETE request is sent to "/api/roles/{role}"
    Then the response status code should be 404
    And the outbox should hold 1 "iam.role.deleted" event
    And the IAM policy version should be 3

  Scenario: Repeating a deletion with the same idempotency key returns the original result and changes nothing a second time
    Given a caller authenticated as the bootstrapped administrator
    And an assignable role "Billing administrator"
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ac"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 201
    Given the If-Match header '"1"'
    And the idempotency key "delete-billing"
    When DELETE request is sent to "/api/roles/{role}"
    Then the response status code should be 200
    And the JSON pointer "/revokedAssignments" should equal the number 2
    When DELETE request is sent to "/api/roles/{role}"
    Then the response status code should be 200
    And the JSON pointer "/revokedAssignments" should equal the number 2
    And the response header "iam-policy-version" should contain "5"
    And the last two responses should have the same body
    And the outbox should hold 1 "iam.role.deleted" event
    And the outbox should hold 2 "iam.user_role.revoked" events
    And the audit log should hold 1 committed "role.delete" record
    And the IAM policy version should be 5

  Scenario: Repeating a GraphQL deletion with the same idempotency key returns the original result
    Given a caller authenticated as the bootstrapped administrator
    And an assignable role "Billing administrator"
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 201
    When the GraphQL operation is sent:
      """
      mutation { deleteRole(input: {id: "{role}", expectedVersion: 1, idempotencyKey: "delete-billing-gql"}) { id version policyVersion revokedAssignments } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/deleteRole/revokedAssignments" should equal the number 1
    When the GraphQL operation is sent:
      """
      mutation { deleteRole(input: {id: "{role}", expectedVersion: 1, idempotencyKey: "delete-billing-gql"}) { id version policyVersion revokedAssignments } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/deleteRole/revokedAssignments" should equal the number 1
    And the JSON pointer "/data/deleteRole/policyVersion" should equal the number 4
    And the outbox should hold 1 "iam.role.deleted" event
    And the outbox should hold 1 "iam.user_role.revoked" event
    And the IAM policy version should be 4

  Scenario: Deleting a role needs a valid bearer token
    When DELETE request is sent to "/api/roles/0190f2a8-7b3c-7d4e-8f10-1234567890ab"
    Then the response status code should be 401
    When the GraphQL operation is sent:
      """
      mutation { deleteRole(input: {id: "0190f2a8-7b3c-7d4e-8f10-1234567890ab", expectedVersion: 1}) { id } }
      """
    Then the GraphQL error code should be "UNAUTHENTICATED"

  Scenario: Replacing the grants of a role over REST commits the grants, the event, the audit record and a policy version
    Given a caller authenticated as the bootstrapped administrator
    And an assignable role "Billing administrator"
    And the If-Match header '"1"'
    When POST request is sent to "/api/graphql-specs" with body:
      """
      {"service": "billing", "sdl": "type Query {\n  invoices: [String!]!\n}\n"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/graphql-specs/{id}/permissions" with body:
      """
      {}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "orders", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Orders\",\"version\":\"1\"},\"paths\":{\"/orders\":{\"get\":{}}}}"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/openapi-specs/{id}/permissions" with body:
      """
      {}
      """
    Then the response status code should be 201
    When PUT request is sent to "/api/roles/{role}/permissions" with body:
      """
      {"keys": ["rest:orders:GET /orders", "gql:billing:Query.invoices", "gql:billing:*", "gql:billing:*"]}
      """
    Then the response status code should be 200
    And the response header "etag" should contain '"2"'
    And the response header "iam-policy-version" should be present
    And the JSON pointer "/roleId" should equal the seeded role
    And the JSON pointer "/version" should equal the number 2
    And the JSON array at "/permissions" should have 3 items
    And the JSON pointer "/permissions/0/key" should equal "gql:billing:*"
    And the JSON pointer "/permissions/1/key" should equal "gql:billing:Query.invoices"
    And the JSON pointer "/permissions/1/kind" should equal "gql"
    And the JSON pointer "/permissions/1/service" should equal "billing"
    And the JSON pointer "/permissions/2/key" should equal "rest:orders:GET /orders"
    And the JSON pointer "/permissions/2/kind" should equal "rest"
    And the JSON pointer "/permissions/2/service" should equal "orders"
    And the response body should contain '"wildcard":true'
    And the response body should contain '"active":true'
    And the outbox should hold 1 "iam.role_permissions.changed" event
    And the "iam.role_permissions.changed" event should carry "rest:orders:GET /orders" in its payload
    And the audit log should hold 1 committed "role.permissions.set" record

  Scenario: The grants of a role are read over REST with the ETag of the role
    Given a caller authenticated as the bootstrapped administrator
    And an assignable role "Billing administrator" that grants "gql:billing:Query.invoices, rest:orders:GET /orders"
    When GET request is sent to "/api/roles/{role}/permissions"
    Then the response status code should be 200
    And the response header "etag" should contain '"1"'
    And the JSON pointer "/roleId" should equal the seeded role
    And the JSON pointer "/version" should equal the number 1
    And the JSON array at "/permissions" should have 2 items
    And the JSON pointer "/permissions/0/key" should equal "gql:billing:Query.invoices"
    And the JSON pointer "/permissions/1/key" should equal "rest:orders:GET /orders"
    And the response body should contain '"active":true,"wildcard":false'
    When GET request is sent to "/api/roles/00000000-0000-7000-8000-000000000000/permissions"
    Then the response status code should be 404

  Scenario: Replacing the grants of a role over GraphQL returns the same data and the new grants through the role
    Given a caller authenticated as the bootstrapped administrator
    And an assignable role "Billing administrator" that grants "gql:billing:Query.invoices, rest:orders:GET /orders"
    When POST request is sent to "/api/graphql-specs" with body:
      """
      {"service": "billing", "sdl": "type Query {\n  invoices: [String!]!\n}\n"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/graphql-specs/{id}/permissions" with body:
      """
      {}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "orders", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Orders\",\"version\":\"1\"},\"paths\":{\"/orders\":{\"get\":{}}}}"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/openapi-specs/{id}/permissions" with body:
      """
      {}
      """
    Then the response status code should be 201
    When the GraphQL operation is sent:
      """
      mutation { setRolePermissions(input: {id: "{role}", expectedVersion: 1, keys: ["gql:billing:Query.invoices", "rest:orders:*"]}) { id version grantCount permissions { key kind service active wildcard } } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/setRolePermissions/version" should equal the number 2
    And the JSON pointer "/data/setRolePermissions/grantCount" should equal the number 2
    And the JSON array at "/data/setRolePermissions/permissions" should have 2 items
    And the JSON pointer "/data/setRolePermissions/permissions/0/key" should equal "gql:billing:Query.invoices"
    And the JSON pointer "/data/setRolePermissions/permissions/1/key" should equal "rest:orders:*"
    And the JSON pointer "/data/setRolePermissions/permissions/1/kind" should equal "rest"
    And the outbox should hold 1 "iam.role_permissions.changed" event
    And the "iam.role_permissions.changed" event should carry "rest:orders:GET /orders" in its payload
    And the audit log should hold 1 committed "role.permissions.set" record
    When the GraphQL operation is sent:
      """
      { role(id: "{role}") { id version permissions { key active wildcard } } }
      """
    Then the GraphQL response should have no errors
    And the JSON array at "/data/role/permissions" should have 2 items
    And the JSON pointer "/data/role/permissions/1/key" should equal "rest:orders:*"

  Scenario: A wildcard grant of an existing service is audited as covering future elements
    Given a caller authenticated as the bootstrapped administrator
    And an assignable role "Billing administrator"
    And the If-Match header '"1"'
    When POST request is sent to "/api/graphql-specs" with body:
      """
      {"service": "billing", "sdl": "type Query {\n  invoices: [String!]!\n}\n"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/graphql-specs/{id}/permissions" with body:
      """
      {}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "orders", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Orders\",\"version\":\"1\"},\"paths\":{\"/orders\":{\"get\":{}}}}"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/openapi-specs/{id}/permissions" with body:
      """
      {}
      """
    Then the response status code should be 201
    When PUT request is sent to "/api/roles/{role}/permissions" with body:
      """
      {"keys": ["rest:orders:GET *"]}
      """
    Then the response status code should be 200
    And the audit log should hold 1 committed "role.permissions.set" record whose summary holds "coversFutureElements=true"
    And the audit log should hold 1 committed "role.permissions.set" record whose summary holds "rest:orders:GET *"

  Scenario: Unknown keys are one violation each over REST and GraphQL and change nothing
    Given a caller authenticated as the bootstrapped administrator
    And an assignable role "Billing administrator"
    And the If-Match header '"1"'
    When POST request is sent to "/api/graphql-specs" with body:
      """
      {"service": "billing", "sdl": "type Query {\n  invoices: [String!]!\n}\n"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/graphql-specs/{id}/permissions" with body:
      """
      {}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "orders", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Orders\",\"version\":\"1\"},\"paths\":{\"/orders\":{\"get\":{}}}}"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/openapi-specs/{id}/permissions" with body:
      """
      {}
      """
    Then the response status code should be 201
    When PUT request is sent to "/api/roles/{role}/permissions" with body:
      """
      {"keys": ["gql:billing:Query.invoices", "gql:billing:Query.missing", "rest:orders:GET /missing", "rest:nowhere:*"]}
      """
    Then the response status code should be 422
    And the response body should contain "keys[1]"
    And the response body should contain "keys[2]"
    And the response body should contain "keys[3]"
    When the GraphQL operation is sent:
      """
      mutation { setRolePermissions(input: {id: "{role}", expectedVersion: 1, keys: ["gql:billing:Query.missing"]}) { id } }
      """
    Then the GraphQL error code should be "VALIDATION_FAILED"
    And the outbox should hold 0 "iam.role_permissions.changed" events
    And the audit log should hold 0 committed "role.permissions.set" records

  Scenario: More than 5000 keys are refused over REST
    Given a caller authenticated as the bootstrapped administrator
    And an assignable role "Billing administrator"
    And the If-Match header '"1"'
    When 5001 generated keys replace the grants of the seeded role over REST
    Then the response status code should be 422
    And the response body should contain "keys"
    And the outbox should hold 0 "iam.role_permissions.changed" events

  Scenario: A missing or stale version refuses the replacement over REST and GraphQL
    Given a caller authenticated as the bootstrapped administrator
    And an assignable role "Billing administrator"
    When PUT request is sent to "/api/roles/{role}/permissions" with body:
      """
      {"keys": []}
      """
    Then the response status code should be 428
    When the GraphQL operation is sent:
      """
      mutation { setRolePermissions(input: {id: "{role}", keys: []}) { id } }
      """
    Then the GraphQL error code should be "PRECONDITION_REQUIRED"
    When the GraphQL operation is sent:
      """
      mutation { setRolePermissions(input: {id: "{role}", expectedVersion: 7, keys: []}) { id } }
      """
    Then the GraphQL error code should be "PRECONDITION_FAILED"
    And the outbox should hold 0 "iam.role_permissions.changed" events

  Scenario: Replacing the grants of an unknown role is 404 and needs a valid bearer token
    Given a caller authenticated as the bootstrapped administrator
    And the If-Match header '"1"'
    When PUT request is sent to "/api/roles/00000000-0000-7000-8000-000000000000/permissions" with body:
      """
      {"keys": []}
      """
    Then the response status code should be 404

  Scenario: The grants of a role need a valid bearer token
    When GET request is sent to "/api/roles/0190f2a8-7b3c-7d4e-8f10-1234567890ab/permissions"
    Then the response status code should be 401
    When PUT request is sent to "/api/roles/0190f2a8-7b3c-7d4e-8f10-1234567890ab/permissions" with body:
      """
      {"keys": []}
      """
    Then the response status code should be 401
    When the GraphQL operation is sent:
      """
      mutation { setRolePermissions(input: {id: "0190f2a8-7b3c-7d4e-8f10-1234567890ab", expectedVersion: 1, keys: []}) { id } }
      """
    Then the GraphQL error code should be "UNAUTHENTICATED"
