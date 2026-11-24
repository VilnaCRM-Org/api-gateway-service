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

  Scenario: An auditor lists the revocations newest first over REST with every filter and cursor pages
    Given a caller authenticated as the bootstrapped administrator
    And the revocation "0190f2a8-7b3c-7d4e-8f20-000000000001" of the session "e2e-read-1" from "operator" recorded 30 minutes ago
    And the revocation "0190f2a8-7b3c-7d4e-8f20-000000000002" of the session "e2e-read-2" from "user-service" recorded 10 minutes ago
    When GET request is sent to "/api/session-revocations"
    Then the response status code should be 200
    And the JSON array at "/items" should have 2 items
    And the JSON pointer "/items/0/id" should equal "0190f2a8-7b3c-7d4e-8f20-000000000002"
    And the JSON pointer "/items/0/sessionId" should equal "e2e-read-2"
    And the JSON pointer "/items/0/userId" should equal "0190f2a8-7b3c-7d4e-8f10-1234567890ab"
    And the JSON pointer "/items/0/source" should equal "user-service"
    And the JSON pointer "/items/0/actor" should equal "system:user-service"
    And the JSON pointer "/items/0/revokedAt" should be present
    And the JSON pointer "/items/1/id" should equal "0190f2a8-7b3c-7d4e-8f20-000000000001"
    And the JSON pointer "/items/1/source" should equal "operator"
    And the JSON pointer "/items/1/actor" should equal "user:0190f2a8-7b3c-7d4e-8f10-00000000ad02"
    And the JSON pointer "/nextCursor" should be absent
    When GET request is sent to "/api/session-revocations?source=operator"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON pointer "/items/0/id" should equal "0190f2a8-7b3c-7d4e-8f20-000000000001"
    When GET request is sent to "/api/session-revocations?userId=0190f2a8-7b3c-7d4e-8f10-1234567890ab"
    Then the response status code should be 200
    And the JSON array at "/items" should have 2 items
    When GET request is sent to "/api/session-revocations?userId=0190f2a8-7b3c-7d4e-8f10-000000000000"
    Then the response status code should be 200
    And the JSON array at "/items" should have 0 items
    When GET request is sent to "/api/session-revocations?from=2020-01-01T00:00:00Z&until=2099-01-01T00:00:00Z"
    Then the response status code should be 200
    And the JSON array at "/items" should have 2 items
    When GET request is sent to "/api/session-revocations?until=2020-01-01T00:00:00Z"
    Then the response status code should be 200
    And the JSON array at "/items" should have 0 items
    When GET request is sent to "/api/session-revocations?limit=1"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON pointer "/items/0/id" should equal "0190f2a8-7b3c-7d4e-8f20-000000000002"
    And the JSON pointer "/nextCursor" should equal "0190f2a8-7b3c-7d4e-8f20-000000000002"
    When GET request is sent to "/api/session-revocations?limit=1&after=0190f2a8-7b3c-7d4e-8f20-000000000002"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON pointer "/items/0/id" should equal "0190f2a8-7b3c-7d4e-8f20-000000000001"
    And the JSON pointer "/nextCursor" should be absent

  Scenario: An auditor lists the revocations newest first over GraphQL with every filter and cursor pages
    Given a caller authenticated as the bootstrapped administrator
    And the revocation "0190f2a8-7b3c-7d4e-8f20-000000000001" of the session "e2e-read-1" from "operator" recorded 30 minutes ago
    And the revocation "0190f2a8-7b3c-7d4e-8f20-000000000002" of the session "e2e-read-2" from "user-service" recorded 10 minutes ago
    When the GraphQL operation is sent:
      """
      { sessionRevocations { items { id sessionId userId source actor revokedAt } nextCursor } }
      """
    Then the GraphQL response should have no errors
    And the JSON array at "/data/sessionRevocations/items" should have 2 items
    And the JSON pointer "/data/sessionRevocations/items/0/id" should equal "0190f2a8-7b3c-7d4e-8f20-000000000002"
    And the JSON pointer "/data/sessionRevocations/items/0/source" should equal "user-service"
    And the JSON pointer "/data/sessionRevocations/items/0/actor" should equal "system:user-service"
    And the JSON pointer "/data/sessionRevocations/items/1/source" should equal "operator"
    And the JSON pointer "/data/sessionRevocations/items/1/actor" should equal "user:0190f2a8-7b3c-7d4e-8f10-00000000ad02"
    And the JSON pointer "/data/sessionRevocations/nextCursor" should be null
    When the GraphQL operation is sent:
      """
      { sessionRevocations(filter: {source: "operator", userId: "0190f2a8-7b3c-7d4e-8f10-1234567890ab", from: "2020-01-01T00:00:00Z", until: "2099-01-01T00:00:00Z"}) { items { id } } }
      """
    Then the GraphQL response should have no errors
    And the JSON array at "/data/sessionRevocations/items" should have 1 items
    And the JSON pointer "/data/sessionRevocations/items/0/id" should equal "0190f2a8-7b3c-7d4e-8f20-000000000001"
    When the GraphQL operation is sent:
      """
      { sessionRevocations(first: 1) { items { id } nextCursor } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/sessionRevocations/items/0/id" should equal "0190f2a8-7b3c-7d4e-8f20-000000000002"
    And the JSON pointer "/data/sessionRevocations/nextCursor" should equal "0190f2a8-7b3c-7d4e-8f20-000000000002"
    When the GraphQL operation is sent:
      """
      { sessionRevocations(first: 1, after: "0190f2a8-7b3c-7d4e-8f20-000000000002") { items { id } nextCursor } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/sessionRevocations/items/0/id" should equal "0190f2a8-7b3c-7d4e-8f20-000000000001"
    And the JSON pointer "/data/sessionRevocations/nextCursor" should be null

  Scenario: An auditor reads one revocation over REST and over GraphQL and an unknown id is not found
    Given a caller authenticated as the bootstrapped administrator
    And the revocation "0190f2a8-7b3c-7d4e-8f20-000000000001" of the session "e2e-read-1" from "operator" recorded 30 minutes ago
    When GET request is sent to "/api/session-revocations/0190f2a8-7b3c-7d4e-8f20-000000000001"
    Then the response status code should be 200
    And the JSON pointer "/sessionId" should equal "e2e-read-1"
    And the JSON pointer "/source" should equal "operator"
    And the JSON pointer "/actor" should equal "user:0190f2a8-7b3c-7d4e-8f10-00000000ad02"
    When the GraphQL operation is sent:
      """
      { sessionRevocation(id: "0190f2a8-7b3c-7d4e-8f20-000000000001") { id sessionId userId source actor revokedAt } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/sessionRevocation/sessionId" should equal "e2e-read-1"
    And the JSON pointer "/data/sessionRevocation/source" should equal "operator"
    When GET request is sent to "/api/session-revocations/0190f2a8-7b3c-7d4e-8f20-0000000000ff"
    Then the response status code should be 404
    When the GraphQL operation is sent:
      """
      { sessionRevocation(id: "0190f2a8-7b3c-7d4e-8f20-0000000000ff") { id } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/sessionRevocation" should be null
    When GET request is sent to "/api/session-revocations/not-a-uuid"
    Then the response status code should be 422

  Scenario: An auditor reads the cut-off of a user and the global cut-off with their source and actor
    Given a caller authenticated as the bootstrapped administrator
    And a token cut-off of the user from "user-service"
    And a global token cut-off set by the bootstrapped administrator
    When GET request is sent to "/api/users/0190f2a8-7b3c-7d4e-8f10-1234567890ab/token-cutoff"
    Then the response status code should be 200
    And the JSON pointer "/userId" should equal "0190f2a8-7b3c-7d4e-8f10-1234567890ab"
    And the JSON pointer "/source" should equal "user-service"
    And the JSON pointer "/actor" should equal "system:user-service"
    And the JSON pointer "/tokensValidAfter" should be present
    When GET request is sent to "/api/global-token-cutoffs/current"
    Then the response status code should be 200
    And the JSON pointer "/source" should equal "operator"
    And the JSON pointer "/actor" should equal "user:0190f2a8-7b3c-7d4e-8f10-00000000ad02"
    And the JSON pointer "/tokensValidAfter" should be present
    When the GraphQL operation is sent:
      """
      { userTokenCutoff(userId: "0190f2a8-7b3c-7d4e-8f10-1234567890ab") { userId tokensValidAfter source actor updatedAt } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/userTokenCutoff/source" should equal "user-service"
    And the JSON pointer "/data/userTokenCutoff/actor" should equal "system:user-service"
    When the GraphQL operation is sent:
      """
      { globalTokenCutoff { tokensValidAfter source actor setAt } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/globalTokenCutoff/source" should equal "operator"
    And the JSON pointer "/data/globalTokenCutoff/actor" should equal "user:0190f2a8-7b3c-7d4e-8f10-00000000ad02"

  Scenario: The cut-off that an operator set shows the operator as its actor
    Given a caller authenticated as the bootstrapped administrator
    When POST request is sent to "/api/session-revocations" with body:
      """
      {"userId": "0190f2a8-7b3c-7d4e-8f10-1234567890ab", "sessionIds": []}
      """
    Then the response status code should be 201
    When GET request is sent to "/api/users/0190f2a8-7b3c-7d4e-8f10-1234567890ab/token-cutoff"
    Then the response status code should be 200
    And the JSON pointer "/source" should equal "operator"
    And the JSON pointer "/actor" should equal "user:0190f2a8-7b3c-7d4e-8f10-00000000ad02"

  Scenario: A user without a cut-off and a global cut-off that was never set are not found
    Given a caller authenticated as the bootstrapped administrator
    When GET request is sent to "/api/users/0190f2a8-7b3c-7d4e-8f10-1234567890ab/token-cutoff"
    Then the response status code should be 404
    When GET request is sent to "/api/global-token-cutoffs/current"
    Then the response status code should be 404
    When the GraphQL operation is sent:
      """
      { userTokenCutoff(userId: "0190f2a8-7b3c-7d4e-8f10-1234567890ab") { source } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/userTokenCutoff" should be null
    When the GraphQL operation is sent:
      """
      { globalTokenCutoff { source } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/globalTokenCutoff" should be null
    When GET request is sent to "/api/users/not-a-uuid/token-cutoff"
    Then the response status code should be 422

  Scenario: A caller without iam:audit:read is refused every revocation read over REST and over GraphQL
    Given a caller authenticated with a valid service token that holds no IAM key
    When GET request is sent to "/api/session-revocations"
    Then the response status code should be 403
    When GET request is sent to "/api/session-revocations/0190f2a8-7b3c-7d4e-8f20-000000000001"
    Then the response status code should be 403
    When GET request is sent to "/api/users/0190f2a8-7b3c-7d4e-8f10-1234567890ab/token-cutoff"
    Then the response status code should be 403
    When GET request is sent to "/api/global-token-cutoffs/current"
    Then the response status code should be 403
    When the GraphQL operation is sent:
      """
      { sessionRevocations { items { id } } }
      """
    Then the GraphQL error code should be "FORBIDDEN"
    When the GraphQL operation is sent:
      """
      { sessionRevocation(id: "0190f2a8-7b3c-7d4e-8f20-000000000001") { id } }
      """
    Then the GraphQL error code should be "FORBIDDEN"
    When the GraphQL operation is sent:
      """
      { userTokenCutoff(userId: "0190f2a8-7b3c-7d4e-8f10-1234567890ab") { source } }
      """
    Then the GraphQL error code should be "FORBIDDEN"
    When the GraphQL operation is sent:
      """
      { globalTokenCutoff { source } }
      """
    Then the GraphQL error code should be "FORBIDDEN"
