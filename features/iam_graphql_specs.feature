Feature: IAM GraphQL specifications
  In order to turn the fields of a service into permission candidates without manual work
  As the delivery pipeline of a service
  I want to upload the GraphQL SDL of the service and see what it changes

  Scenario: Uploading a new SDL over REST creates a draft and commits its event and audit record
    Given a caller authenticated with a valid service token
    When POST request is sent to "/api/graphql-specs" with body:
      """
      {"service": "billing", "sdl": "type Query {\n  invoices: [String!]!\n}\n\ntype Mutation {\n  pay(id: ID!): String! @iamSensitive\n}\n"}
      """
    Then the response status code should be 201
    And the response header "location" should contain "/api/graphql-specs/"
    And the JSON pointer "/id" should be present
    And the JSON pointer "/service" should equal "billing"
    And the JSON pointer "/status" should equal "draft"
    And the JSON pointer "/contentHash" should be present
    And the JSON pointer "/coordinateCount" should equal the number 2
    And the JSON array at "/diff/added" should have 2 items
    And the JSON array at "/diff/removed" should have 0 items
    And the service "billing" should have 1 GraphQL specification version
    And the outbox should hold 1 "iam.graphql_spec.loaded" event
    And the audit log should hold 1 committed "graphql_spec.load" record

  Scenario: Uploading a new SDL over GraphQL returns the same data
    Given a caller authenticated with a valid service token
    When the GraphQL operation is sent:
      """
      mutation { loadGraphqlSpec(input: {service: "billing", sdl: "type Query { invoices: [String!]! }"}) { id service status contentHash coordinateCount diff { added removed } } }
      """
    Then the response status code should be 200
    And the GraphQL response should have no errors
    And the JSON pointer "/data/loadGraphqlSpec/id" should be present
    And the JSON pointer "/data/loadGraphqlSpec/service" should equal "billing"
    And the JSON pointer "/data/loadGraphqlSpec/status" should equal "draft"
    And the JSON pointer "/data/loadGraphqlSpec/coordinateCount" should equal the number 1
    And the JSON array at "/data/loadGraphqlSpec/diff/added" should have 1 items
    And the outbox should hold 1 "iam.graphql_spec.loaded" event
    And the audit log should hold 1 committed "graphql_spec.load" record

  Scenario: Uploading identical content again returns the existing version and changes nothing
    Given a caller authenticated with a valid service token
    When POST request is sent to "/api/graphql-specs" with body:
      """
      {"service": "billing", "sdl": "type Query { invoices: [String!]! }"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/graphql-specs" with body:
      """
      {"service": "billing", "sdl": "type Query { invoices: [String!]! }"}
      """
    Then the response status code should be 200
    And the last two responses should be the created version and then the same version found
    And the service "billing" should have 1 GraphQL specification version
    And the outbox should hold 1 "iam.graphql_spec.loaded" event
    And the audit log should hold 1 committed "graphql_spec.load" record

  Scenario: An SDL that does not parse is a validation failure with its position over REST and GraphQL
    Given a caller authenticated with a valid service token
    When POST request is sent to "/api/graphql-specs" with body:
      """
      {"service": "billing", "sdl": "type Query {"}
      """
    Then the response status code should be 422
    And the response body should contain "/problems/validation-failed"
    And the response body should contain '"propertyPath":"sdl"'
    And the response body should contain "line"
    When the GraphQL operation is sent:
      """
      mutation { loadGraphqlSpec(input: {service: "billing", sdl: "type Query {"}) { id } }
      """
    Then the GraphQL error code should be "VALIDATION_FAILED"
    And the service "billing" should have 0 GraphQL specification versions
    And the outbox should hold 0 "iam.graphql_spec.loaded" events

  Scenario: An invalid service name is a validation failure over REST and GraphQL
    Given a caller authenticated with a valid service token
    When POST request is sent to "/api/graphql-specs" with body:
      """
      {"service": "Not A Service", "sdl": "type Query { invoices: [String!]! }"}
      """
    Then the response status code should be 422
    And the response body should contain '"propertyPath":"service"'
    When the GraphQL operation is sent:
      """
      mutation { loadGraphqlSpec(input: {service: "Not A Service", sdl: "type Query { a: Int }"}) { id } }
      """
    Then the GraphQL error code should be "VALIDATION_FAILED"
    And the outbox should hold 0 "iam.graphql_spec.loaded" events

  Scenario: The reserved service iam is refused to every actor but the startup registration
    Given a caller authenticated with a valid service token
    When POST request is sent to "/api/graphql-specs" with body:
      """
      {"service": "iam", "sdl": "type Query { a: Int }"}
      """
    Then the response status code should be 403
    When the GraphQL operation is sent:
      """
      mutation { loadGraphqlSpec(input: {service: "iam", sdl: "type Query { a: Int }"}) { id } }
      """
    Then the GraphQL error code should be "FORBIDDEN"
    And the service "iam" should have 0 GraphQL specification versions
    And the outbox should hold 0 "iam.graphql_spec.loaded" events

  Scenario: A caller without a token is refused
    When POST request is sent to "/api/graphql-specs" with body:
      """
      {"service": "billing", "sdl": "type Query { a: Int }"}
      """
    Then the response status code should be 401
    And the service "billing" should have 0 GraphQL specification versions

  Scenario: A body over 6 MiB on a specification route and over the template limit on another IAM route are refused
    Given a caller authenticated with a valid service token
    When POST request is sent to "/api/graphql-specs" with a JSON body of 6500000 bytes
    Then the response status code should be 413
    When POST request is sent to "/api/roles" with a JSON body of 70000 bytes
    Then the response status code should be 413
    And the service "billing" should have 0 GraphQL specification versions

  Scenario: Versions of several services are listed with filters over REST and GraphQL
    Given a caller authenticated with a valid service token
    When POST request is sent to "/api/graphql-specs" with body:
      """
      {"service": "billing", "sdl": "type Query {\n  invoices: [String!]!\n}\n\ntype Mutation {\n  pay(id: ID!): String!\n}\n"}
      """
    Then the response status code should be 201
    Given the remembered GraphQL specification is active
    When POST request is sent to "/api/graphql-specs" with body:
      """
      {"service": "shipping", "sdl": "type Query {\n  parcels: [String!]!\n}\n"}
      """
    Then the response status code should be 201
    When GET request is sent to "/api/graphql-specs"
    Then the response status code should be 200
    And the JSON array at "/items" should have 2 items
    And the JSON pointer "/nextCursor" should be absent
    When GET request is sent to "/api/graphql-specs?service=billing"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON pointer "/items/0/id" should be present
    And the JSON pointer "/items/0/service" should equal "billing"
    And the JSON pointer "/items/0/contentHash" should be present
    And the JSON pointer "/items/0/status" should equal "active"
    And the JSON pointer "/items/0/uploadedBy" should be present
    And the JSON pointer "/items/0/createdAt" should be present
    And the JSON pointer "/items/0/activatedAt" should be present
    And the JSON pointer "/items/0/coordinateCount" should equal the number 2
    And the JSON pointer "/items/0/sdl" should be absent
    When GET request is sent to "/api/graphql-specs?status=draft&includeSdl=true"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON pointer "/items/0/service" should equal "shipping"
    And the JSON pointer "/items/0/sdl" should be present
    When GET request is sent to "/api/graphql-specs?limit=1"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON pointer "/nextCursor" should be present
    When GET request is sent to "/api/graphql-specs/{id}"
    Then the response status code should be 200
    And the JSON pointer "/service" should equal "shipping"
    And the JSON pointer "/coordinateCount" should equal the number 1
    And the JSON pointer "/sdl" should be absent
    When GET request is sent to "/api/graphql-specs/{id}?includeSdl=true"
    Then the response status code should be 200
    And the JSON pointer "/sdl" should be present
    When the GraphQL operation is sent:
      """
      { graphqlSpecs(filter: {service: "billing"}) { items { id service status coordinateCount sdl } nextCursor } }
      """
    Then the GraphQL response should have no errors
    And the JSON array at "/data/graphqlSpecs/items" should have 1 items
    And the JSON pointer "/data/graphqlSpecs/items/0/service" should equal "billing"
    And the JSON pointer "/data/graphqlSpecs/items/0/status" should equal "active"
    And the JSON pointer "/data/graphqlSpecs/items/0/coordinateCount" should equal the number 2
    And the JSON pointer "/data/graphqlSpecs/items/0/sdl" should be present
    And the JSON pointer "/data/graphqlSpecs/nextCursor" should be null
    When the GraphQL operation is sent:
      """
      { graphqlSpecs(first: 1, filter: {status: "draft"}) { items { service sdl } } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/graphqlSpecs/items/0/service" should equal "shipping"
    And the JSON pointer "/data/graphqlSpecs/items/0/sdl" should be present
    When the GraphQL operation is sent:
      """
      { graphqlSpec(id: "{id}") { id service status coordinateCount sdl } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/graphqlSpec/service" should equal "shipping"
    And the JSON pointer "/data/graphqlSpec/coordinateCount" should equal the number 1
    And the JSON pointer "/data/graphqlSpec/sdl" should be present

  Scenario: The diff of a draft that removes a granted coordinate lists the affected role over REST and GraphQL
    Given a caller authenticated with a valid service token
    And an assignable role "Payer" that grants "gql:billing:Mutation.pay"
    When POST request is sent to "/api/graphql-specs" with body:
      """
      {"service": "billing", "sdl": "type Query {\n  invoices: [String!]!\n}\n\ntype Mutation {\n  pay(id: ID!): String!\n}\n"}
      """
    Then the response status code should be 201
    Given the remembered GraphQL specification is active
    When POST request is sent to "/api/graphql-specs" with body:
      """
      {"service": "billing", "sdl": "type Query {\n  invoices: [String!]!\n}\n"}
      """
    Then the response status code should be 201
    When GET request is sent to "/api/graphql-specs/{id}/diff"
    Then the response status code should be 200
    And the JSON array at "/added" should have 0 items
    And the JSON array at "/removed" should have 1 items
    And the JSON pointer "/removed/0" should equal "Mutation.pay"
    And the JSON array at "/removedGrants" should have 1 items
    And the JSON pointer "/removedGrants/0/coordinate" should equal "Mutation.pay"
    And the JSON array at "/removedGrants/0/roles" should have 1 items
    And the JSON pointer "/removedGrants/0/roles/0" should be the seeded role
    When the GraphQL operation is sent:
      """
      { graphqlSpec(id: "{id}") { id diff { removed removedGrants { coordinate roles } } } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/graphqlSpec/diff/removed/0" should equal "Mutation.pay"
    And the JSON pointer "/data/graphqlSpec/diff/removedGrants/0/coordinate" should equal "Mutation.pay"
    And the JSON pointer "/data/graphqlSpec/diff/removedGrants/0/roles/0" should be the seeded role

  Scenario: The diff lists the wildcard grants that gain the coordinates a draft adds
    Given a caller authenticated with a valid service token
    And an assignable role "Reader" that grants "gql:billing:Query.*"
    When POST request is sent to "/api/graphql-specs" with body:
      """
      {"service": "billing", "sdl": "type Query {\n  invoices: [String!]!\n}\n"}
      """
    Then the response status code should be 201
    Given the remembered GraphQL specification is active
    When POST request is sent to "/api/graphql-specs" with body:
      """
      {"service": "billing", "sdl": "type Query {\n  invoices: [String!]!\n  orders: [String!]!\n}\n"}
      """
    Then the response status code should be 201
    When GET request is sent to "/api/graphql-specs/{id}/diff"
    Then the response status code should be 200
    And the JSON pointer "/added/0" should equal "Query.orders"
    And the JSON array at "/removedGrants" should have 0 items
    And the JSON array at "/wildcardGains" should have 1 items
    And the JSON pointer "/wildcardGains/0/role" should be the seeded role
    And the JSON pointer "/wildcardGains/0/pattern" should equal "gql:billing:Query.*"
    And the JSON pointer "/wildcardGains/0/coordinates/0" should equal "Query.orders"
    When the GraphQL operation is sent:
      """
      { graphqlSpec(id: "{id}") { diff { added wildcardGains { role pattern coordinates } } } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/graphqlSpec/diff/added/0" should equal "Query.orders"
    And the JSON pointer "/data/graphqlSpec/diff/wildcardGains/0/pattern" should equal "gql:billing:Query.*"

  Scenario: A draft that drops @iamSensitive from an active field is listed as a flag downgrade over REST and GraphQL
    Given a caller authenticated with a valid service token
    When POST request is sent to "/api/graphql-specs" with body:
      """
      {"service": "billing", "sdl": "type Query {\n  invoices: [String!]!\n}\n\ntype Mutation {\n  pay(id: ID!): String! @iamSensitive\n}\n"}
      """
    Then the response status code should be 201
    Given the remembered GraphQL specification is active
    When POST request is sent to "/api/graphql-specs" with body:
      """
      {"service": "billing", "sdl": "type Query {\n  invoices: [String!]!\n}\n\ntype Mutation {\n  pay(id: ID!): String!\n}\n"}
      """
    Then the response status code should be 201
    When GET request is sent to "/api/graphql-specs/{id}/diff"
    Then the response status code should be 200
    And the JSON array at "/flagDowngrades" should have 1 items
    And the JSON pointer "/flagDowngrades/0/coordinate" should equal "Mutation.pay"
    And the response body should contain '"before":{"sensitive":true,"auditAlways":false}'
    And the response body should contain '"after":{"sensitive":false,"auditAlways":false}'
    When the GraphQL operation is sent:
      """
      { graphqlSpec(id: "{id}") { diff { flagDowngrades { coordinate before { sensitive auditAlways } after { sensitive auditAlways } } } } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/graphqlSpec/diff/flagDowngrades/0/coordinate" should equal "Mutation.pay"
    And the response body should contain '"before":{"sensitive":true,"auditAlways":false}'

  Scenario: An unknown version is a 404 over REST and null over GraphQL
    Given a caller authenticated with a valid service token
    When GET request is sent to "/api/graphql-specs/0190f2a8-7b3c-7d4e-8f10-1234567890ad"
    Then the response status code should be 404
    When GET request is sent to "/api/graphql-specs/0190f2a8-7b3c-7d4e-8f10-1234567890ad/diff"
    Then the response status code should be 404
    When GET request is sent to "/api/graphql-specs/not-a-uuid"
    Then the response status code should be 422
    When the GraphQL operation is sent:
      """
      { graphqlSpec(id: "0190f2a8-7b3c-7d4e-8f10-1234567890ad") { id } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/graphqlSpec" should be null

  Scenario: The reads need a valid token
    When GET request is sent to "/api/graphql-specs"
    Then the response status code should be 401
    When GET request is sent to "/api/graphql-specs/0190f2a8-7b3c-7d4e-8f10-1234567890ad"
    Then the response status code should be 401
    When GET request is sent to "/api/graphql-specs/0190f2a8-7b3c-7d4e-8f10-1234567890ad/diff"
    Then the response status code should be 401
