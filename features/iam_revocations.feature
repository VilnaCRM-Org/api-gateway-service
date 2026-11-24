Feature: IAM revocations
  In order to refuse a compromised session or key on every gateway pod
  As a security officer
  I want to revoke sessions of a user or set a global token cut-off over REST or GraphQL

  Scenario: Revoking one session over REST commits its state record and event and refuses its token
    Given a caller authenticated as the bootstrapped administrator
    And a subject token of a user in session "e2e-revoked-1"
    When POST request is sent to "/api/session-revocations" with body:
      """
      {"userId": "0190f2a8-7b3c-7d4e-8f10-1234567890ab", "sessionIds": ["e2e-revoked-1"]}
      """
    Then the response status code should be 201
    And the JSON pointer "/policyVersion" should be present
    And the JSON pointer "/id" should be present
    And the outbox should hold 1 "iam.session.revoked" event
    And the audit log should hold 1 committed "session.revoke" record
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

  Scenario: A token of another session of the same user is still accepted
    Given a caller authenticated as the bootstrapped administrator
    And a subject token of a user in session "e2e-kept-1"
    When POST request is sent to "/api/session-revocations" with body:
      """
      {"userId": "0190f2a8-7b3c-7d4e-8f10-1234567890ab", "sessionIds": ["e2e-revoked-2"]}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/token-resolutions" with body:
      """
      {"credential": "{token}"}
      """
    Then the response status code should be 200
    And the JSON boolean at "/resolved" should be true

  Scenario: Revoking one session over GraphQL returns the policy version and refuses its token
    Given a caller authenticated as the bootstrapped administrator
    And a subject token of a user in session "e2e-revoked-3"
    When the GraphQL operation is sent:
      """
      mutation { revokeSessions(input: {userId: "0190f2a8-7b3c-7d4e-8f10-1234567890ab", sessionIds: ["e2e-revoked-3"]}) { id policyVersion } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/revokeSessions/policyVersion" should be present
    And the outbox should hold 1 "iam.session.revoked" event
    And the audit log should hold 1 committed "session.revoke" record

  Scenario: An empty session list sets the cut-off of the user
    Given a caller authenticated as the bootstrapped administrator
    When POST request is sent to "/api/session-revocations" with body:
      """
      {"userId": "0190f2a8-7b3c-7d4e-8f10-1234567890ab", "sessionIds": []}
      """
    Then the response status code should be 201
    And the outbox should hold 1 "iam.user_tokens.cut_off" event
    And the audit log should hold 1 committed "user_tokens.cut_off" record

  Scenario: Setting the global cut-off over REST commits its event and audit record and ends the caller's token
    Given a caller authenticated as the bootstrapped administrator
    When POST request is sent to "/api/global-token-cutoffs" with body:
      """
      {}
      """
    Then the response status code should be 201
    And the JSON pointer "/policyVersion" should be present
    And the outbox should hold 1 "iam.global_tokens.cut_off" event
    And the audit log should hold 1 committed "global_tokens.cut_off" record
    When the GraphQL operation is sent:
      """
      mutation { setGlobalTokenCutoff(input: {}) { id policyVersion } }
      """
    Then the GraphQL error code should be "UNAUTHENTICATED"
    And the outbox should hold 1 "iam.global_tokens.cut_off" event

  Scenario: Setting the global cut-off over GraphQL commits its event and audit record
    Given a caller authenticated as the bootstrapped administrator
    When the GraphQL operation is sent:
      """
      mutation { setGlobalTokenCutoff(input: {}) { id policyVersion } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/setGlobalTokenCutoff/policyVersion" should be present
    And the outbox should hold 1 "iam.global_tokens.cut_off" event
    And the audit log should hold 1 committed "global_tokens.cut_off" record

  Scenario: A caller without the reserved keys is refused over REST and over GraphQL
    Given a caller authenticated with a valid service token that holds no IAM key
    When POST request is sent to "/api/session-revocations" with body:
      """
      {"userId": "0190f2a8-7b3c-7d4e-8f10-1234567890ab", "sessionIds": ["e2e-revoked-4"]}
      """
    Then the response status code should be 403
    When POST request is sent to "/api/global-token-cutoffs" with body:
      """
      {}
      """
    Then the response status code should be 403
    When the GraphQL operation is sent:
      """
      mutation { revokeSessions(input: {userId: "0190f2a8-7b3c-7d4e-8f10-1234567890ab", sessionIds: ["e2e-revoked-4"]}) { id } }
      """
    Then the GraphQL error code should be "FORBIDDEN"
    When the GraphQL operation is sent:
      """
      mutation { setGlobalTokenCutoff(input: {}) { id } }
      """
    Then the GraphQL error code should be "FORBIDDEN"
    And the outbox should hold 0 "iam.session.revoked" event
    And the outbox should hold 0 "iam.global_tokens.cut_off" event

  Scenario: A revocation repeated with the same idempotency key commits one record
    Given a caller authenticated as the bootstrapped administrator
    And the idempotency key "revoke-1"
    When POST request is sent to "/api/session-revocations" with body:
      """
      {"userId": "0190f2a8-7b3c-7d4e-8f10-1234567890ab", "sessionIds": ["e2e-revoked-5"]}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/session-revocations" with body:
      """
      {"userId": "0190f2a8-7b3c-7d4e-8f10-1234567890ab", "sessionIds": ["e2e-revoked-5"]}
      """
    Then the response status code should be 201
    And the outbox should hold 1 "iam.session.revoked" event
    And the audit log should hold 1 committed "session.revoke" record

  Scenario: A revocation with an invalid user is refused
    Given a caller authenticated as the bootstrapped administrator
    When POST request is sent to "/api/session-revocations" with body:
      """
      {"userId": "not-a-uuid"}
      """
    Then the response status code should be 422
    And the outbox should hold 0 "iam.session.revoked" event
