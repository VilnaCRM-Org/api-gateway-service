Feature: IAM roles
  In order to build my organisation's role model
  As an administrator
  I want to create, read and update roles over REST or GraphQL

  Scenario: Creating a role over REST commits the role, its event and its audit record
    Given a caller authenticated with a valid service token
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
    Given a caller authenticated with a valid service token
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

  Scenario: A duplicate name is a conflict over REST and GraphQL
    Given a caller authenticated with a valid service token
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
    Given a caller authenticated with a valid service token
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
    Given a caller authenticated with a valid service token
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
    Given a caller authenticated with a valid service token
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
    Given a caller authenticated with a valid service token
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
    Given a caller authenticated with a valid service token
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
    Given a caller authenticated with a valid service token
    When GET request is sent to "/api/roles/00000000-0000-7000-8000-000000000000"
    Then the response status code should be 404
    When the GraphQL operation is sent:
      """
      { role(id: "00000000-0000-7000-8000-000000000000") { id } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/role" should be null

  Scenario: Roles are listed with cursor pagination over REST
    Given a caller authenticated with a valid service token
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
    Given a caller authenticated with a valid service token
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
    Given a caller authenticated with a valid service token
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
    Given a caller authenticated with a valid service token
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
    Given a caller authenticated with a valid service token
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
    Given a caller authenticated with a valid service token
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
    Given a caller authenticated with a valid service token
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
    Given a caller authenticated with a valid service token
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
