Feature: IAM's own upstream and routes
  In order to reach the management API through the gateway from the first deployment
  As an operator
  I want the first-administrator bootstrap to seed the upstream and the routes of IAM as system entries

  Scenario: A seeded IAM route cannot be changed or deleted over REST or GraphQL and every refusal is audited
    Given a caller authenticated as the bootstrapped administrator
    And the first administrator is bootstrapped with the IAM host "iam.example.test"
    And the seeded IAM route "/api/graphql" is remembered
    When PATCH request is sent to "/api/routes/{id}" with body:
      """
      {"requestTimeoutMs": 5000}
      """
    Then the response status code should be 409
    And the response body should contain "/problems/system-entry"
    When DELETE request is sent to "/api/routes/{id}"
    Then the response status code should be 409
    And the response body should contain "/problems/system-entry"
    When the GraphQL operation is sent:
      """
      mutation { updateRoute(input: {id: "{id}", expectedVersion: 1, requestTimeoutMs: 5000}) { id } }
      """
    Then the GraphQL error code should be "CONFLICT"
    When the GraphQL operation is sent:
      """
      mutation { deleteRoute(input: {id: "{id}", expectedVersion: 1}) { id } }
      """
    Then the GraphQL error code should be "CONFLICT"
    And the audit log should hold 1 system-entry "route.update" record in a second
    And the audit log should hold 1 system-entry "route.delete" record in a second
    And the routes of the host "iam.example.test" should number 4
    And the outbox should hold 0 "iam.route.updated" events
    And the outbox should hold 0 "iam.route.deleted" events

  Scenario: The bootstrapped administrator lists the seeded IAM routes over REST and GraphQL
    Given a caller authenticated as the bootstrapped administrator
    And the first administrator is bootstrapped with the IAM host "iam.example.test"
    When GET request is sent to "/api/routes?host=iam.example.test&service=iam"
    Then the response status code should be 200
    And the JSON pointer "/items/3/pathPattern" should be present
    And the response body should contain "/api/graphql"
    And the response body should contain "/api/openapi-specs"
    And the response body should contain "/api/graphql-specs"
    And the response body should contain "/api/{rest:*}"
    When the GraphQL operation is sent:
      """
      query { routes(filter: {host: "iam.example.test"}) { items { pathPattern graphql system bodyLimitBytes } } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/routes/items/3/pathPattern" should be present
    And the response body should contain "/api/graphql-specs"
    And the response body should contain "6291456"
    And the routes of the host "iam.example.test" should number 4
    And the outbox should hold 4 "iam.route.created" events
    And the outbox should hold 1 "iam.upstream.created" event
