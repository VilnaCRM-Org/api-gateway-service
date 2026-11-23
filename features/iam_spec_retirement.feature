Feature: IAM specification retirement
  In order to remove operations that no longer exist from what can be granted
  As an administrator
  I want to retire specification versions and confirm the grants that this orphans over REST or GraphQL

  Scenario: Retiring a GraphQL version that would orphan grants needs confirmOrphans over REST and GraphQL, and confirming orphans them
    Given a caller authenticated with a valid service token
    And an assignable role "Payer"
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
    When PUT request is sent to "/api/roles/{role}/permissions" with body:
      """
      {"keys": ["gql:billing:Query.invoices"]}
      """
    Then the response status code should be 200
    When POST request is sent to "/api/graphql-specs/{id}/retirement" with body:
      """
      {}
      """
    Then the response status code should be 409
    And the response body should contain "/problems/orphan-confirmation-required"
    And the response body should contain "gql:billing:Query.invoices"
    And the seeded role should hold 1 active grant
    And the outbox should hold 0 "iam.graphql_spec.retired" events
    And the IAM policy version should be 4
    When the GraphQL operation is sent:
      """
      mutation { retireGraphqlSpec(input: {id: "{id}"}) { id } }
      """
    Then the GraphQL error code should be "ORPHAN_CONFIRMATION_REQUIRED"
    When POST request is sent to "/api/graphql-specs/{id}/retirement" with body:
      """
      {"confirmOrphans": true}
      """
    Then the response status code should be 200
    And the response header "iam-policy-version" should contain "5"
    And the JSON pointer "/service" should equal "billing"
    And the JSON pointer "/status" should equal "retired"
    And the JSON pointer "/policyVersion" should equal the number 5
    And the seeded role should hold 1 orphaned grant
    And the seeded role should hold 0 active grants
    And the catalogue of the service "billing" should hold 0 active GraphQL permissions
    And the IAM policy version should be 5
    And the outbox should hold 1 "iam.graphql_spec.retired" event
    And the outbox should hold 1 "iam.permissions.orphaned" event
    And the "iam.permissions.orphaned" event should carry "gql:billing:Query.invoices" in its payload
    And the audit log should hold 1 committed "graphql_spec.retire" record
    When GET request is sent to "/api/graphql-specs/{id}"
    Then the response status code should be 200
    And the JSON pointer "/status" should equal "retired"
    When GET request is sent to "/api/roles/{role}/permissions"
    Then the response status code should be 200
    And the response body should contain '"active":false'

  Scenario: Retiring a GraphQL version over GraphQL needs confirmOrphans and then orphans the grants
    Given a caller authenticated with a valid service token
    And an assignable role "Payer"
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
    When PUT request is sent to "/api/roles/{role}/permissions" with body:
      """
      {"keys": ["gql:billing:Query.invoices"]}
      """
    Then the response status code should be 200
    When the GraphQL operation is sent:
      """
      mutation { retireGraphqlSpec(input: {id: "{id}"}) { id } }
      """
    Then the GraphQL error code should be "ORPHAN_CONFIRMATION_REQUIRED"
    And the response body should contain "gql:billing:Query.invoices"
    When POST request is sent to "/api/graphql-specs/{id}/retirement" with body:
      """
      {}
      """
    Then the response status code should be 409
    When the GraphQL operation is sent:
      """
      mutation { retireGraphqlSpec(input: {id: "{id}", confirmOrphans: true}) { id service status policyVersion } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/retireGraphqlSpec/service" should equal "billing"
    And the JSON pointer "/data/retireGraphqlSpec/status" should equal "retired"
    And the JSON pointer "/data/retireGraphqlSpec/policyVersion" should equal the number 5
    And the seeded role should hold 1 orphaned grant
    And the outbox should hold 1 "iam.graphql_spec.retired" event
    And the outbox should hold 1 "iam.permissions.orphaned" event
    And the audit log should hold 1 committed "graphql_spec.retire" record

  Scenario: Retiring an OpenAPI version that would orphan grants needs confirmOrphans over REST and GraphQL, and confirming orphans them
    Given a caller authenticated with a valid service token
    And an assignable role "Payer"
    And the If-Match header '"1"'
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "billing", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Billing\",\"version\":\"1\"},\"paths\":{\"/invoices\":{\"get\":{}}}}"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/openapi-specs/{id}/permissions" with body:
      """
      {}
      """
    Then the response status code should be 201
    When PUT request is sent to "/api/roles/{role}/permissions" with body:
      """
      {"keys": ["rest:billing:GET /invoices"]}
      """
    Then the response status code should be 200
    When POST request is sent to "/api/openapi-specs/{id}/retirement" with body:
      """
      {}
      """
    Then the response status code should be 409
    And the response body should contain "/problems/orphan-confirmation-required"
    And the response body should contain "rest:billing:GET /invoices"
    And the seeded role should hold 1 active grant
    And the outbox should hold 0 "iam.openapi_spec.retired" events
    When the GraphQL operation is sent:
      """
      mutation { retireOpenapiSpec(input: {id: "{id}"}) { id } }
      """
    Then the GraphQL error code should be "ORPHAN_CONFIRMATION_REQUIRED"
    When POST request is sent to "/api/openapi-specs/{id}/retirement" with body:
      """
      {"confirmOrphans": true}
      """
    Then the response status code should be 200
    And the response header "iam-policy-version" should contain "5"
    And the JSON pointer "/service" should equal "billing"
    And the JSON pointer "/status" should equal "retired"
    And the JSON pointer "/policyVersion" should equal the number 5
    And the seeded role should hold 1 orphaned grant
    And the seeded role should hold 0 active grants
    And the catalogue of the service "billing" should hold 0 active REST permissions
    And the outbox should hold 1 "iam.openapi_spec.retired" event
    And the outbox should hold 1 "iam.permissions.orphaned" event
    And the audit log should hold 1 committed "openapi_spec.retire" record
    When GET request is sent to "/api/openapi-specs/{id}"
    Then the response status code should be 200
    And the JSON pointer "/status" should equal "retired"

  Scenario: Retiring an OpenAPI version over GraphQL needs confirmOrphans and then orphans the grants
    Given a caller authenticated with a valid service token
    And an assignable role "Payer"
    And the If-Match header '"1"'
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "billing", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Billing\",\"version\":\"1\"},\"paths\":{\"/invoices\":{\"get\":{}}}}"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/openapi-specs/{id}/permissions" with body:
      """
      {}
      """
    Then the response status code should be 201
    When PUT request is sent to "/api/roles/{role}/permissions" with body:
      """
      {"keys": ["rest:billing:GET /invoices"]}
      """
    Then the response status code should be 200
    When the GraphQL operation is sent:
      """
      mutation { retireOpenapiSpec(input: {id: "{id}"}) { id } }
      """
    Then the GraphQL error code should be "ORPHAN_CONFIRMATION_REQUIRED"
    When the GraphQL operation is sent:
      """
      mutation { retireOpenapiSpec(input: {id: "{id}", confirmOrphans: true}) { id service status policyVersion } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/retireOpenapiSpec/status" should equal "retired"
    And the JSON pointer "/data/retireOpenapiSpec/policyVersion" should equal the number 5
    And the seeded role should hold 1 orphaned grant
    And the outbox should hold 1 "iam.openapi_spec.retired" event
    And the outbox should hold 1 "iam.permissions.orphaned" event

  Scenario: A version without grants retires without confirmation and its keys leave the catalogue
    Given a caller authenticated with a valid service token
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
    And the catalogue of the service "billing" should hold 2 active GraphQL permissions
    When POST request is sent to "/api/graphql-specs/{id}/retirement" with body:
      """
      {}
      """
    Then the response status code should be 200
    And the JSON pointer "/status" should equal "retired"
    And the catalogue of the service "billing" should hold 0 active GraphQL permissions
    And the outbox should hold 1 "iam.graphql_spec.retired" event
    And the outbox should hold 0 "iam.permissions.orphaned" events
    When POST request is sent to "/api/graphql-specs/{id}/retirement" with body:
      """
      {}
      """
    Then the response status code should be 409
    And the outbox should hold 1 "iam.graphql_spec.retired" event

  Scenario: Repeating a REST retirement with the same idempotency key returns the original result and no second event
    Given a caller authenticated with a valid service token
    And an assignable role "Payer"
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
    When PUT request is sent to "/api/roles/{role}/permissions" with body:
      """
      {"keys": ["gql:billing:Query.invoices"]}
      """
    Then the response status code should be 200
    Given the idempotency key "retire-billing-rest"
    When POST request is sent to "/api/graphql-specs/{id}/retirement" with body:
      """
      {"confirmOrphans": true}
      """
    When POST request is sent to "/api/graphql-specs/{id}/retirement" with body:
      """
      {"confirmOrphans": true}
      """
    Then the response status code should be 200
    And the last two responses should have the same body
    And the IAM policy version should be 5
    And the outbox should hold 1 "iam.graphql_spec.retired" event
    And the outbox should hold 1 "iam.permissions.orphaned" event
    And the audit log should hold 1 committed "graphql_spec.retire" record

  Scenario: Repeating a GraphQL retirement with the same idempotency key returns the original result and no second event
    Given a caller authenticated with a valid service token
    And an assignable role "Payer"
    And the If-Match header '"1"'
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "billing", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Billing\",\"version\":\"1\"},\"paths\":{\"/invoices\":{\"get\":{}}}}"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/openapi-specs/{id}/permissions" with body:
      """
      {}
      """
    Then the response status code should be 201
    When PUT request is sent to "/api/roles/{role}/permissions" with body:
      """
      {"keys": ["rest:billing:GET /invoices"]}
      """
    Then the response status code should be 200
    When the GraphQL operation is sent:
      """
      mutation { retireOpenapiSpec(input: {id: "{id}", confirmOrphans: true, idempotencyKey: "retire-billing-graphql"}) { id status policyVersion } }
      """
    When the GraphQL operation is sent:
      """
      mutation { retireOpenapiSpec(input: {id: "{id}", confirmOrphans: true, idempotencyKey: "retire-billing-graphql"}) { id status policyVersion } }
      """
    Then the GraphQL response should have no errors
    And the last two responses should have the same body
    And the JSON pointer "/data/retireOpenapiSpec/policyVersion" should equal the number 5
    And the IAM policy version should be 5
    And the outbox should hold 1 "iam.openapi_spec.retired" event
    And the audit log should hold 1 committed "openapi_spec.retire" record

  Scenario: An orphaned grant stays inactive when a later GraphQL version contains its key
    Given a caller authenticated with a valid service token
    And an assignable role "Payer"
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
    When PUT request is sent to "/api/roles/{role}/permissions" with body:
      """
      {"keys": ["gql:billing:Query.invoices"]}
      """
    Then the response status code should be 200
    When POST request is sent to "/api/graphql-specs/{id}/retirement" with body:
      """
      {"confirmOrphans": true}
      """
    Then the response status code should be 200
    When POST request is sent to "/api/graphql-specs" with body:
      """
      {"service": "billing", "sdl": "type Query {\n  invoices: [String!]!\n  orders: [String!]!\n}\n"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/graphql-specs/{id}/permissions" with body:
      """
      {}
      """
    Then the response status code should be 201
    And the catalogue of the service "billing" should hold 3 active GraphQL permissions
    And the seeded role should hold 1 orphaned grant
    And the seeded role should hold 0 active grants
    And the outbox should hold 1 "iam.permissions.orphaned" event
    When GET request is sent to "/api/roles/{role}/permissions"
    Then the response status code should be 200
    And the response body should contain "gql:billing:Query.invoices"
    And the response body should contain '"active":false'

  Scenario: An orphaned grant stays inactive when a later OpenAPI version contains its key
    Given a caller authenticated with a valid service token
    And an assignable role "Payer"
    And the If-Match header '"1"'
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "billing", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Billing\",\"version\":\"1\"},\"paths\":{\"/invoices\":{\"get\":{}}}}"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/openapi-specs/{id}/permissions" with body:
      """
      {}
      """
    Then the response status code should be 201
    When PUT request is sent to "/api/roles/{role}/permissions" with body:
      """
      {"keys": ["rest:billing:GET /invoices"]}
      """
    Then the response status code should be 200
    When POST request is sent to "/api/openapi-specs/{id}/retirement" with body:
      """
      {"confirmOrphans": true}
      """
    Then the response status code should be 200
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "billing", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Billing\",\"version\":\"1\"},\"paths\":{\"/invoices\":{\"get\":{}},\"/orders\":{\"get\":{}}}}"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/openapi-specs/{id}/permissions" with body:
      """
      {}
      """
    Then the response status code should be 201
    And the catalogue of the service "billing" should hold 2 active REST permissions
    And the seeded role should hold 1 orphaned grant
    And the seeded role should hold 0 active grants
    When GET request is sent to "/api/roles/{role}/permissions"
    Then the response status code should be 200
    And the response body should contain "rest:billing:GET /invoices"
    And the response body should contain '"active":false'

  Scenario: A rename in a GraphQL activation moves the grants that were created through the API and is audited
    Given a caller authenticated with a valid service token
    And an assignable role "Payer"
    And the If-Match header '"1"'
    When POST request is sent to "/api/graphql-specs" with body:
      """
      {"service": "billing", "sdl": "type Query {\n  bills: [String!]!\n}\n"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/graphql-specs/{id}/permissions" with body:
      """
      {}
      """
    Then the response status code should be 201
    When PUT request is sent to "/api/roles/{role}/permissions" with body:
      """
      {"keys": ["gql:billing:Query.bills"]}
      """
    Then the response status code should be 200
    When POST request is sent to "/api/graphql-specs/{id}/retirement" with body:
      """
      {"confirmOrphans": true}
      """
    Then the response status code should be 200
    When POST request is sent to "/api/graphql-specs" with body:
      """
      {"service": "billing", "sdl": "type Query {\n  invoices: [String!]!\n}\n"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/graphql-specs/{id}/permissions" with body:
      """
      {"renames": [{"from": "gql:billing:Query.bills", "to": "gql:billing:Query.invoices"}]}
      """
    Then the response status code should be 201
    And the IAM policy version should be 6
    And the "iam.graphql_permissions.created" event should carry '"from":"gql:billing:Query.bills"' in its payload
    And the audit log should hold 1 committed "graphql_spec.activate" record whose summary holds "renamed=1"
    When GET request is sent to "/api/roles/{role}/permissions"
    Then the response status code should be 200
    And the JSON array at "/permissions" should have 1 items
    And the JSON pointer "/permissions/0/key" should equal "gql:billing:Query.invoices"

  Scenario: A rename in an OpenAPI activation moves the grants that were created through the API and is audited
    Given a caller authenticated with a valid service token
    And an assignable role "Payer"
    And the If-Match header '"1"'
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "billing", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Billing\",\"version\":\"1\"},\"paths\":{\"/bills\":{\"get\":{}}}}"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/openapi-specs/{id}/permissions" with body:
      """
      {}
      """
    Then the response status code should be 201
    When PUT request is sent to "/api/roles/{role}/permissions" with body:
      """
      {"keys": ["rest:billing:GET /bills"]}
      """
    Then the response status code should be 200
    When POST request is sent to "/api/openapi-specs/{id}/retirement" with body:
      """
      {"confirmOrphans": true}
      """
    Then the response status code should be 200
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "billing", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Billing\",\"version\":\"1\"},\"paths\":{\"/invoices\":{\"get\":{}}}}"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/openapi-specs/{id}/permissions" with body:
      """
      {"renames": [{"from": "rest:billing:GET /bills", "to": "rest:billing:GET /invoices"}]}
      """
    Then the response status code should be 201
    And the IAM policy version should be 6
    And the "iam.rest_permissions.created" event should carry '"from":"rest:billing:GET /bills"' in its payload
    And the audit log should hold 1 committed "openapi_spec.activate" record whose summary holds "renamed=1"
    When GET request is sent to "/api/roles/{role}/permissions"
    Then the response status code should be 200
    And the JSON array at "/permissions" should have 1 items
    And the JSON pointer "/permissions/0/key" should equal "rest:billing:GET /invoices"

  Scenario: An unknown version, a draft, an invalid identifier and a missing token are refused
    Given a caller authenticated with a valid service token
    When POST request is sent to "/api/graphql-specs/0190f2a8-7b3c-7d4e-8f10-1234567890ad/retirement" with body:
      """
      {}
      """
    Then the response status code should be 404
    When POST request is sent to "/api/openapi-specs/0190f2a8-7b3c-7d4e-8f10-1234567890ad/retirement" with body:
      """
      {}
      """
    Then the response status code should be 404
    When POST request is sent to "/api/graphql-specs/not-a-uuid/retirement" with body:
      """
      {}
      """
    Then the response status code should be 422
    When the GraphQL operation is sent:
      """
      mutation { retireOpenapiSpec(input: {id: "0190f2a8-7b3c-7d4e-8f10-1234567890ad"}) { id } }
      """
    Then the GraphQL error code should be "NOT_FOUND"
    When the GraphQL operation is sent:
      """
      mutation { retireGraphqlSpec(input: {id: "not-a-uuid"}) { id } }
      """
    Then the GraphQL error code should be "VALIDATION_FAILED"
    When POST request is sent to "/api/graphql-specs" with body:
      """
      {"service": "billing", "sdl": "type Query {\n  invoices: [String!]!\n}\n"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/graphql-specs/{id}/retirement" with body:
      """
      {}
      """
    Then the response status code should be 409
    When the GraphQL operation is sent:
      """
      mutation { retireGraphqlSpec(input: {id: "{id}"}) { id } }
      """
    Then the GraphQL error code should be "CONFLICT"
    And the outbox should hold 0 "iam.graphql_spec.retired" events
    And the outbox should hold 0 "iam.openapi_spec.retired" events

  Scenario: The retirement needs a valid token
    When POST request is sent to "/api/graphql-specs/0190f2a8-7b3c-7d4e-8f10-1234567890ad/retirement" with body:
      """
      {}
      """
    Then the response status code should be 401
    When POST request is sent to "/api/openapi-specs/0190f2a8-7b3c-7d4e-8f10-1234567890ad/retirement" with body:
      """
      {}
      """
    Then the response status code should be 401
    When the GraphQL operation is sent:
      """
      mutation { retireGraphqlSpec(input: {id: "0190f2a8-7b3c-7d4e-8f10-1234567890ad"}) { id } }
      """
    Then the GraphQL error code should be "UNAUTHENTICATED"
    When the GraphQL operation is sent:
      """
      mutation { retireOpenapiSpec(input: {id: "0190f2a8-7b3c-7d4e-8f10-1234567890ad"}) { id } }
      """
    Then the GraphQL error code should be "UNAUTHENTICATED"
