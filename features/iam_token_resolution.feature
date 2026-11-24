Feature: IAM token resolution
  In order to identify a caller without parsing tokens myself
  As a microservice
  I want to resolve a User service token into its subject over REST or GraphQL

  Scenario: A valid user token resolves to the same subject over REST and GraphQL
    Given a caller authenticated as the bootstrapped administrator
    And a subject token of a user in session "e2e-session-1"
    When POST request is sent to "/api/token-resolutions" with body:
      """
      {"credential": "{token}"}
      """
    And the GraphQL operation is sent:
      """
      { resolveToken(input: {credential: "{token}"}) { resolved reason subjectId subjectKind sessionId roles expiresAt } }
      """
    Then the response status code should be 200
    And the GraphQL response should have no errors
    And the REST and GraphQL token resolutions should be the same
    And both token resolutions should be resolved for a "user" subject in session "e2e-session-1"
    And no response should contain the subject token

  Scenario: An expired token is refused with its reason over REST and GraphQL
    Given a caller authenticated as the bootstrapped administrator
    And an expired subject token of a user in session "e2e-session-2"
    When POST request is sent to "/api/token-resolutions" with body:
      """
      {"credential": "{token}"}
      """
    And the GraphQL operation is sent:
      """
      { resolveToken(input: {credential: "{token}"}) { resolved reason subjectId subjectKind sessionId roles expiresAt } }
      """
    Then the REST and GraphQL token resolutions should be the same
    And both token resolutions should be unresolved with reason "token_expired"
    And no response should contain the subject token

  Scenario: A token signed by an unknown key is invalid over REST and GraphQL
    Given a caller authenticated as the bootstrapped administrator
    And a subject token signed by an unknown key
    When POST request is sent to "/api/token-resolutions" with body:
      """
      {"credential": "{token}"}
      """
    And the GraphQL operation is sent:
      """
      { resolveToken(input: {credential: "{token}"}) { resolved reason subjectId subjectKind sessionId roles expiresAt } }
      """
    Then the REST and GraphQL token resolutions should be the same
    And both token resolutions should be unresolved with reason "token_invalid"
    And no response should contain the subject token

  Scenario: An empty credential is missing over REST and GraphQL
    Given a caller authenticated as the bootstrapped administrator
    And an empty subject token
    When POST request is sent to "/api/token-resolutions" with body:
      """
      {"credential": "{token}"}
      """
    And the GraphQL operation is sent:
      """
      { resolveToken(input: {credential: "{token}"}) { resolved reason subjectId subjectKind sessionId roles expiresAt } }
      """
    Then the REST and GraphQL token resolutions should be the same
    And both token resolutions should be unresolved with reason "token_missing"

  Scenario: A token of a revoked session is refused over REST and GraphQL
    Given a caller authenticated as the bootstrapped administrator
    And a subject token of a user in session "e2e-session-3"
    And the session "e2e-session-3" is revoked
    When POST request is sent to "/api/token-resolutions" with body:
      """
      {"credential": "{token}"}
      """
    And the GraphQL operation is sent:
      """
      { resolveToken(input: {credential: "{token}"}) { resolved reason subjectId subjectKind sessionId roles expiresAt } }
      """
    Then the REST and GraphQL token resolutions should be the same
    And both token resolutions should be unresolved with reason "token_revoked"
    And no response should contain the subject token

  Scenario: A request without a bearer token is unauthenticated over REST
    Given a subject token of a user in session "e2e-session-4"
    When POST request is sent to "/api/token-resolutions" with body:
      """
      {"credential": "{token}"}
      """
    Then the response status code should be 401
    And the response should challenge with the Bearer scheme
    And the response header "content-type" should contain "application/problem+json"
    And no response should contain the subject token

  Scenario: A request without a bearer token is unauthenticated over GraphQL
    Given a subject token of a user in session "e2e-session-5"
    When the GraphQL operation is sent:
      """
      { resolveToken(input: {credential: "{token}"}) { resolved reason } }
      """
    Then the response status code should be 200
    And the GraphQL error code should be "UNAUTHENTICATED"
    And no response should contain the subject token

  Scenario: A rejected bearer token is unauthenticated over REST
    Given a caller presenting a token signed by an unknown key
    And a subject token of a user in session "e2e-session-6"
    When POST request is sent to "/api/token-resolutions" with body:
      """
      {"credential": "{token}"}
      """
    Then the response status code should be 401
    And the response should challenge with the Bearer scheme

  Scenario: A rejected bearer token is unauthenticated over GraphQL
    Given a caller presenting a token signed by an unknown key
    And a subject token of a user in session "e2e-session-7"
    When the GraphQL operation is sent:
      """
      { resolveToken(input: {credential: "{token}"}) { resolved reason } }
      """
    Then the response status code should be 200
    And the GraphQL error code should be "UNAUTHENTICATED"

  Scenario: The token-resolution operation is documented with its security requirement
    When GET request is sent to "/api/docs/openapi.json"
    Then the response status code should be 200
    And the response body should contain "api_token_resolutions_post"
    And the response body should contain "bearerAuth"
    And the response body should contain "application/problem+json"
