Feature: IAM operations
  In order to repair the state topic after an incident
  As an operator
  I want to republish the complete current policy as a new log epoch with a reason

  Scenario: Resyncing over REST returns the bulk operation and republishes every entity under the new log epoch
    Given a caller authenticated as the bootstrapped administrator
    And an assignable role "Billing administrator"
    When POST request is sent to "/api/policy-resyncs" with body:
      """
      {"reason": "The state topic lost records after a broker failure."}
      """
    Then the response status code should be 202
    And the response header "location" should contain "/api/bulk-operations/"
    And the JSON pointer "/kind" should equal "resync"
    And the JSON pointer "/totalRecords" should be present
    And the JSON pointer "/appliedRecords" should be present
    And the JSON pointer "/requester" should be present
    When the bulk operation runner has finished every bulk operation
    Then the policy log epoch should be 1
    And every stored role should have a state row under the log epoch 1
    And the state rows of the log epoch 1 should lie above every earlier version
    And the newest head digest should equal the digest of the policy epoch
    And the outbox should hold 1 "iam.policy.resynced" event
    And the outbox should hold 1 "iam.bulk_operation.completed" event
    And the audit log should hold 1 committed "policy.resync" record
    When GET request is sent to "/api/bulk-operations"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON pointer "/items/0/kind" should equal "resync"
    And the JSON pointer "/items/0/status" should equal "completed"
    And the JSON pointer "/items/0/firstVersion" should be present

  Scenario: Resyncing over GraphQL returns the bulk operation and republishes every entity under the new log epoch
    Given a caller authenticated as the bootstrapped administrator
    And an assignable role "Billing administrator"
    When the GraphQL operation is sent:
      """
      mutation { resyncPolicy(input: {reason: "The state topic lost records after a broker failure."}) { id kind totalRecords appliedRecords } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/resyncPolicy/id" should be present
    And the JSON pointer "/data/resyncPolicy/kind" should equal "resync"
    When the bulk operation runner has finished every bulk operation
    Then the policy log epoch should be 1
    And every stored role should have a state row under the log epoch 1
    And the newest head digest should equal the digest of the policy epoch
    And the outbox should hold 1 "iam.policy.resynced" event
    And the audit log should hold 1 committed "policy.resync" record

  Scenario: A resync without a reason is refused over REST and over GraphQL
    Given a caller authenticated as the bootstrapped administrator
    When POST request is sent to "/api/policy-resyncs" with body:
      """
      {}
      """
    Then the response status code should be 422
    When POST request is sent to "/api/policy-resyncs" with body:
      """
      {"reason": "   "}
      """
    Then the response status code should be 422
    When the GraphQL operation is sent:
      """
      mutation { resyncPolicy(input: {reason: ""}) { id } }
      """
    Then the GraphQL error code should be "VALIDATION_FAILED"
    And the policy log epoch should be 0
    And the outbox should hold 0 "iam.policy.resynced" event

  Scenario: A caller without iam:policy:resync is refused over REST and over GraphQL
    Given a caller authenticated with a valid service token that holds no IAM key
    When POST request is sent to "/api/policy-resyncs" with body:
      """
      {"reason": "The state topic lost records after a broker failure."}
      """
    Then the response status code should be 403
    When the GraphQL operation is sent:
      """
      mutation { resyncPolicy(input: {reason: "The state topic lost records after a broker failure."}) { id } }
      """
    Then the GraphQL error code should be "FORBIDDEN"
    And the policy log epoch should be 0
    And the outbox should hold 0 "iam.policy.resynced" event

  Scenario: A resync repeated with the same idempotency key starts no second resync
    Given a caller authenticated as the bootstrapped administrator
    And an assignable role "Billing administrator"
    And the idempotency key "resync-1"
    When POST request is sent to "/api/policy-resyncs" with body:
      """
      {"reason": "The state topic lost records after a broker failure."}
      """
    Then the response status code should be 202
    When POST request is sent to "/api/policy-resyncs" with body:
      """
      {"reason": "The state topic lost records after a broker failure."}
      """
    Then the response status code should be 202
    When the bulk operation runner has finished every bulk operation
    Then the policy log epoch should be 1
    And the outbox should hold 1 "iam.policy.resynced" event
    When GET request is sent to "/api/bulk-operations"
    Then the JSON array at "/items" should have 1 items

  Scenario: The same idempotency key with another reason is refused
    Given a caller authenticated as the bootstrapped administrator
    And the idempotency key "resync-1"
    When POST request is sent to "/api/policy-resyncs" with body:
      """
      {"reason": "The state topic lost records after a broker failure."}
      """
    Then the response status code should be 202
    When POST request is sent to "/api/policy-resyncs" with body:
      """
      {"reason": "Another reason."}
      """
    Then the response status code should be 422

  Scenario: The operator cache flush does not exist
    Given a caller authenticated as the bootstrapped administrator
    When POST request is sent to "/api/authorization-cache/flushes" with body:
      """
      {}
      """
    Then the response status code should be 404
