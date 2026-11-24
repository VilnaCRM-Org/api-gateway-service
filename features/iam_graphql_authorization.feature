Feature: IAM GraphQL authorization
  In order to enforce one authorization rule over both interfaces
  As the owner of IAM
  I want every IAM GraphQL field to require its key and every refused attempt to be recorded

  Scenario: A caller without the catalogue key is refused over GraphQL and the refusal is audited
    Given a caller authenticated with a valid service token that holds no IAM key
    When the GraphQL operation is sent:
      """
      { roles(first: 10) { items { id name } } }
      """
    Then the response status code should be 200
    And the GraphQL error code should be "FORBIDDEN"
    And the audit log should hold 1 forbidden "role.list" record within one second

  Scenario: A mutation without the catalogue key changes nothing and is audited
    Given a caller authenticated with a valid service token that holds no IAM key
    When the GraphQL operation is sent:
      """
      mutation { createRole(input: {name: "Billing administrator"}) { id } }
      """
    Then the GraphQL error code should be "FORBIDDEN"
    And the audit log should hold 1 forbidden "role.create" record within one second
    And the audit log should hold 0 committed "role.create" records
    And the outbox should hold 0 "iam.role.created" events

  Scenario: Validating access over GraphQL needs the reserved validate key
    Given a caller authenticated with a valid service token that holds no IAM key
    When the GraphQL operation is sent:
      """
      { validateAccess(input: {credential: "unused", service: "iam", permissions: ["iam:validate:*"], requestId: "req-1"}) { decision } }
      """
    Then the GraphQL error code should be "FORBIDDEN"
    And the audit log should hold 1 forbidden "access.validate" record within one second

  Scenario: An IAM field next to an example field does not escape the check
    Given a caller authenticated with a valid service token that holds no IAM key
    When the GraphQL operation is sent:
      """
      { exampleApiResources(itemsPerPage: 1) { id } roles(first: 1) { items { id } } }
      """
    Then the GraphQL error code should be "FORBIDDEN"
    And the audit log should hold 1 forbidden "role.list" record within one second

  Scenario: An IAM field without a token is unauthenticated and nothing is audited
    When the GraphQL operation is sent:
      """
      { roles(first: 10) { items { id } } }
      """
    Then the response status code should be 200
    And the GraphQL error code should be "UNAUTHENTICATED"
    And the audit log should hold no rejected record after the writer ran

  Scenario: A document of example fields without a token behaves as in the template
    When the GraphQL operation is sent:
      """
      { exampleApiResources(itemsPerPage: 1) { id } }
      """
    Then the response status code should be 200
    And the GraphQL response should have no errors

  Scenario: The bootstrapped administrator calls IAM over REST and GraphQL
    Given a caller authenticated as the bootstrapped administrator
    When GET request is sent to "/api/roles"
    Then the response status code should be 200
    When the GraphQL operation is sent:
      """
      { roles(first: 10) { items { id name } } }
      """
    Then the response status code should be 200
    And the GraphQL response should have no errors
    When the GraphQL operation is sent:
      """
      mutation { createRole(input: {name: "Billing administrator"}) { id name } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/createRole/id" should be present
