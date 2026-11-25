Feature: IAM access decision log
  In order to investigate incidents
  As a security officer
  I want to search access decisions by time, subject, decision, reason, upstream, route and status over REST and GraphQL

  Scenario: A holder of iam:audit:read searches the decisions in Loki over REST and the search is audited
    Given a caller authenticated as the bootstrapped administrator
    And the compose Loki holds 3 decisions of the subject "alice" denied with status 403
    When the access decisions of the subject "alice" are searched over REST with "decision=deny&status=403&reason=permission_missing&upstream=user-service&subjectKind=user"
    Then the response status code should be 200
    And the JSON array at "/items" should have 3 items
    And the JSON pointer "/items/0/decision" should equal "deny"
    And the JSON pointer "/items/0/reason" should equal "permission_missing"
    And the JSON pointer "/items/0/upstream" should equal "user-service"
    And the JSON pointer "/items/0/subjectKind" should equal "user"
    And the JSON pointer "/items/0/routeTemplate" should equal "/api/users/{id}"
    And the JSON pointer "/items/0/status" should equal the number 403
    And the JSON pointer "/items/0/id" should be present
    And the JSON pointer "/nextCursor" should be absent
    When GET request is sent to "/api/security-audit-events?action=access_log.list"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON pointer "/items/0/targetType" should equal "access_decision"

  Scenario: A filter that no decision meets returns an empty page
    Given a caller authenticated as the bootstrapped administrator
    And the compose Loki holds 2 decisions of the subject "bob" denied with status 403
    When the access decisions of the subject "bob" are searched over REST with "status=404"
    Then the response status code should be 200
    And the JSON array at "/items" should have 0 items

  Scenario: A page holds the newest decisions first and its cursor leads to the older ones
    Given a caller authenticated as the bootstrapped administrator
    And the compose Loki holds 5 decisions of the subject "carol" denied with status 403
    When the access decisions of the subject "carol" are searched over REST with "limit=2"
    Then the response status code should be 200
    And the JSON array at "/items" should have 2 items
    And the JSON pointer "/nextCursor" should be present
    When the cursor at "/nextCursor" is remembered
    When the access decisions of the subject "carol" are searched over REST with "limit=10&after={cursor}"
    Then the response status code should be 200
    And the JSON array at "/items" should have 3 items
    And the JSON pointer "/nextCursor" should be absent

  Scenario: A holder of iam:audit:read searches the decisions in Loki over GraphQL
    Given a caller authenticated as the bootstrapped administrator
    And the compose Loki holds 3 decisions of the subject "dave" denied with status 403
    When the access decisions of the subject "dave" are searched over GraphQL with the filter 'decision: "deny", status: 403, reason: "permission_missing"'
    Then the response status code should be 200
    And the GraphQL response should have no errors
    And the JSON array at "/data/accessDecisions/items" should have 3 items
    And the JSON pointer "/data/accessDecisions/items/0/decision" should equal "deny"
    And the JSON pointer "/data/accessDecisions/items/0/subjectId" should be present
    And the JSON pointer "/data/accessDecisions/nextCursor" should be null
    When GET request is sent to "/api/security-audit-events?action=access_log.list"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items

  Scenario: A decision is read by its id over both interfaces and an absent id is a 404 and null
    Given a caller authenticated as the bootstrapped administrator
    And the compose Loki holds 1 decisions of the subject "erin" denied with status 403
    When the access decisions of the subject "erin" are searched over REST with "limit=1"
    Then the response status code should be 200
    When the first decision of the last search is read by id over REST
    Then the response status code should be 200
    And the JSON pointer "/subjectId" should be present
    And the JSON pointer "/reason" should equal "permission_missing"
    When the access decisions of the subject "erin" are searched over GraphQL with the filter ""
    And the first decision of the last search is read by id over GraphQL
    Then the response status code should be 200
    And the GraphQL response should have no errors
    And the JSON pointer "/data/accessDecision/decision" should equal "deny"
    When GET request is sent to "/api/access-decisions/01a1c6b5-cb86-7134-868a-7608036facfe"
    Then the response status code should be 404
    When the GraphQL operation is sent:
      """
      { accessDecision(id: "01a1c6b5-cb86-7134-868a-7608036facfe") { id } }
      """
    Then the response status code should be 200
    And the GraphQL response should have no errors
    And the JSON pointer "/data/accessDecision" should be null

  Scenario: A missing or too long range is refused over both interfaces
    Given a caller authenticated as the bootstrapped administrator
    When the access decisions are searched over REST without a time range
    Then the response status code should be 422
    When the access decisions are searched over REST from "2026-01-01T00:00:00Z" until "2026-01-03T00:00:00Z"
    Then the response status code should be 422
    When the access decisions are searched over GraphQL without a time range
    Then the response status code should be 200
    And the GraphQL error code should be "VALIDATION_FAILED"

  Scenario: A caller without iam:audit:read is refused over REST and GraphQL
    Given a caller authenticated with a valid service token that holds no IAM key
    When GET request is sent to "/api/access-decisions?from=2026-11-25T08:00:00Z&until=2026-11-25T09:00:00Z"
    Then the response status code should be 403
    And the response header "content-type" should contain "application/problem+json"
    When GET request is sent to "/api/access-decisions/01a1c6b5-cb86-7134-868a-7608036facfe"
    Then the response status code should be 403
    When the access decisions are searched over GraphQL without a time range
    Then the response status code should be 200
    And the GraphQL error code should be "FORBIDDEN"

  Scenario: A request without a token is unauthenticated over both interfaces
    When GET request is sent to "/api/access-decisions?from=2026-11-25T08:00:00Z&until=2026-11-25T09:00:00Z"
    Then the response status code should be 401
    When the access decisions are searched over GraphQL without a time range
    Then the response status code should be 200
    And the GraphQL error code should be "UNAUTHENTICATED"
