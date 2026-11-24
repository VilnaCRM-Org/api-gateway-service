Feature: IAM security audit log
  In order to review who changed what
  As a security officer
  I want to search the security audit log by time, actor, action, target and outcome over REST and GraphQL

  Scenario: An administrator reads the committed and the rejected records over REST
    Given a caller authenticated as the bootstrapped administrator
    And a role exists with name "Billing administrator"
    And the If-Match header is the ETag of the last response
    When PATCH request is sent to "/api/roles/{id}" with body:
      """
      {"name": "Accounting administrator"}
      """
    Then the response status code should be 200
    Given the first administrator is bootstrapped
    When DELETE request is sent to "/api/user-roles/{id}"
    Then the response status code should be 409
    When GET request is sent to "/api/security-audit-events?action=role.update"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON pointer "/items/0/outcome" should equal "committed"
    And the JSON pointer "/items/0/actor" should equal "user:0190f2a8-7b3c-7d4e-8f10-00000000ad02"
    And the JSON pointer "/items/0/action" should equal "role.update"
    And the JSON pointer "/items/0/targetType" should equal "role"
    And the JSON pointer "/items/0/targetId" should be present
    And the JSON pointer "/items/0/before" should be present
    And the JSON pointer "/items/0/after" should be present
    # A rename does not change any access decision, so the record carries no policy version.
    And the JSON pointer "/items/0/policyVersion" should be absent
    And the JSON pointer "/items/0/seq" should be present
    And the JSON pointer "/items/0/hash" should be present
    And the JSON pointer "/nextCursor" should be absent
    When GET request is sent to "/api/security-audit-events?outcome=rejected&action=user_role.revoke"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON pointer "/items/0/outcome" should equal "rejected"
    And the JSON pointer "/items/0/reason" should equal "last_administrator"
    And the JSON pointer "/items/0/actor" should equal "user:0190f2a8-7b3c-7d4e-8f10-00000000ad02"
    When GET request is sent to "/api/security-audit-events?actor=user:0190f2a8-7b3c-7d4e-8f10-00000000ad02&targetType=role&from=2020-01-01T00:00:00Z&until=2099-01-01T00:00:00Z"
    Then the response status code should be 200
    And the JSON pointer "/items/0/targetType" should equal "role"
    When GET request is sent to "/api/security-audit-events?until=2020-01-01T00:00:00Z"
    Then the response status code should be 200
    And the JSON array at "/items" should have 0 items

  Scenario: An administrator reads the committed and the rejected records over GraphQL
    Given a caller authenticated as the bootstrapped administrator
    And a role exists with name "Billing administrator"
    And the If-Match header is the ETag of the last response
    When PATCH request is sent to "/api/roles/{id}" with body:
      """
      {"name": "Accounting administrator"}
      """
    Then the response status code should be 200
    Given the first administrator is bootstrapped
    When DELETE request is sent to "/api/user-roles/{id}"
    Then the response status code should be 409
    When the GraphQL operation is sent:
      """
      { securityAuditEvents(filter: {action: "role.update"}) { items { id seq actor action targetType targetId before after outcome policyVersion hash } nextCursor } }
      """
    Then the response status code should be 200
    And the GraphQL response should have no errors
    And the JSON array at "/data/securityAuditEvents/items" should have 1 items
    And the JSON pointer "/data/securityAuditEvents/items/0/outcome" should equal "committed"
    And the JSON pointer "/data/securityAuditEvents/items/0/actor" should equal "user:0190f2a8-7b3c-7d4e-8f10-00000000ad02"
    And the JSON pointer "/data/securityAuditEvents/items/0/before" should be present
    And the JSON pointer "/data/securityAuditEvents/items/0/after" should be present
    And the JSON pointer "/data/securityAuditEvents/items/0/policyVersion" should be null
    And the JSON pointer "/data/securityAuditEvents/nextCursor" should be null
    When the GraphQL operation is sent:
      """
      { securityAuditEvents(filter: {outcome: "rejected", action: "user_role.revoke"}) { items { outcome reason actor } } }
      """
    Then the GraphQL response should have no errors
    And the JSON array at "/data/securityAuditEvents/items" should have 1 items
    And the JSON pointer "/data/securityAuditEvents/items/0/outcome" should equal "rejected"
    And the JSON pointer "/data/securityAuditEvents/items/0/reason" should equal "last_administrator"

  Scenario: A record is read by its identifier over both interfaces and an unknown one is not found
    Given a caller authenticated as the bootstrapped administrator
    And a role exists with name "Billing administrator"
    When GET request is sent to "/api/security-audit-events?action=role.create&limit=1"
    Then the response status code should be 200
    And the JSON pointer "/items/0/id" should be present
    When the cursor at "/items/0/id" is remembered
    And GET request is sent to "/api/security-audit-events/{cursor}"
    Then the response status code should be 200
    And the JSON pointer "/id" should be present
    And the JSON pointer "/action" should equal "role.create"
    And the JSON pointer "/outcome" should equal "committed"
    When the GraphQL operation is sent:
      """
      { securityAuditEvent(id: "{cursor}") { id action outcome } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/securityAuditEvent/action" should equal "role.create"
    When GET request is sent to "/api/security-audit-events/0190f2a8-7b3c-7d4e-8f10-000000000000"
    Then the response status code should be 404
    When the GraphQL operation is sent:
      """
      { securityAuditEvent(id: "0190f2a8-7b3c-7d4e-8f10-000000000000") { id } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/securityAuditEvent" should be null

  Scenario: Pages run from the newest record to the oldest and follow their cursors
    Given a caller authenticated as the bootstrapped administrator
    And a role exists with name "Billing administrator"
    And a role exists with name "Accounting administrator"
    When GET request is sent to "/api/security-audit-events?limit=1&action=role.create"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON pointer "/nextCursor" should be present
    When the cursor at "/nextCursor" is remembered
    And GET request is sent to "/api/security-audit-events?limit=1&action=role.create&after={cursor}"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON pointer "/items/0/action" should equal "role.create"

  Scenario: Every successful query is itself audited
    Given a caller authenticated as the bootstrapped administrator
    When GET request is sent to "/api/security-audit-events?action=security_audit.list"
    Then the response status code should be 200
    And the JSON array at "/items" should have 0 items
    When GET request is sent to "/api/security-audit-events?action=security_audit.list"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON pointer "/items/0/actor" should equal "user:0190f2a8-7b3c-7d4e-8f10-00000000ad02"
    And the JSON pointer "/items/0/targetType" should equal "security_audit_event"
    And the JSON pointer "/items/0/targetId" should equal "query"
    And the JSON pointer "/items/0/outcome" should equal "committed"
    When the GraphQL operation is sent:
      """
      { securityAuditEvents(filter: {action: "security_audit.list"}) { items { action } } }
      """
    Then the GraphQL response should have no errors
    And the JSON array at "/data/securityAuditEvents/items" should have 2 items
    When GET request is sent to "/api/security-audit-events?action=security_audit.list&limit=1"
    And the cursor at "/items/0/id" is remembered
    And GET request is sent to "/api/security-audit-events/{cursor}"
    Then the response status code should be 200
    When GET request is sent to "/api/security-audit-events?action=security_audit.read"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON pointer "/items/0/targetType" should equal "security_audit_event"

  Scenario: A caller without iam:audit:read is refused over REST and GraphQL and the refusals are audited
    Given a caller authenticated with a valid service token that holds no IAM key
    When GET request is sent to "/api/security-audit-events"
    Then the response status code should be 403
    And the response header "content-type" should contain "application/problem+json"
    When GET request is sent to "/api/security-audit-events/0190f2a8-7b3c-7d4e-8f10-000000000000"
    Then the response status code should be 403
    And the audit log should hold 1 forbidden "security_audit.list" record within one second
    And the audit log should hold 1 forbidden "security_audit.read" record within one second
    When the GraphQL operation is sent:
      """
      { securityAuditEvents { items { id } } }
      """
    Then the response status code should be 200
    And the GraphQL error code should be "FORBIDDEN"
    When the GraphQL operation is sent:
      """
      { securityAuditEvent(id: "0190f2a8-7b3c-7d4e-8f10-000000000000") { id } }
      """
    Then the GraphQL error code should be "FORBIDDEN"

  Scenario: A request without a token is unauthenticated over both interfaces
    When GET request is sent to "/api/security-audit-events"
    Then the response status code should be 401
    When the GraphQL operation is sent:
      """
      { securityAuditEvents { items { id } } }
      """
    Then the GraphQL error code should be "UNAUTHENTICATED"

  Scenario Outline: An invalid identifier or filter is a validation failure over REST
    Given a caller authenticated as the bootstrapped administrator
    When GET request is sent to "<path>"
    Then the response status code should be 422
    And the JSON pointer "/violations/0/propertyPath" should equal "<property>"

    Examples:
      | path                                                 | property   |
      | /api/security-audit-events/not-a-uuid                | id         |
      | /api/security-audit-events?limit=0                   | limit      |
      | /api/security-audit-events?limit=101                 | limit      |
      | /api/security-audit-events?after=nope                | after      |
      | /api/security-audit-events?from=yesterday            | from       |
      | /api/security-audit-events?until=tomorrow            | until      |
      | /api/security-audit-events?actor=someone             | actor      |
      | /api/security-audit-events?action=Role               | action     |
      | /api/security-audit-events?outcome=maybe             | outcome    |
      | /api/security-audit-events?targetId=r-1              | targetType |

  Scenario Outline: An invalid argument is a validation failure over GraphQL
    Given a caller authenticated as the bootstrapped administrator
    When the GraphQL operation is sent:
      """
      <query>
      """
    Then the GraphQL error code should be "VALIDATION_FAILED"

    Examples:
      | query                                                              |
      | { securityAuditEvents(first: 0) { items { id } } }                 |
      | { securityAuditEvents(after: "nope") { items { id } } }            |
      | { securityAuditEvents(filter: {outcome: "maybe"}) { items { id } } } |
      | { securityAuditEvent(id: "not-a-uuid") { id } }                    |
