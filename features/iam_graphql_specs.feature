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
