Feature: IAM bulk operations
  In order to change a large part of the policy without a change that is more permissive than intended
  As an operator
  I want large changes split into ordered chunks that I can follow

  Scenario: Deleting a role with 2500 assignments over REST returns the bulk operation and commits it in chunks
    Given a caller authenticated as the bootstrapped administrator
    And an assignable role "Billing administrator"
    And the seeded role has 2500 assignments
    And the If-Match header '"1"'
    When DELETE request is sent to "/api/roles/{role}"
    Then the response status code should be 202
    And the response header "location" should contain "/api/bulk-operations/"
    And the JSON pointer "/id" should equal the seeded role
    And the JSON pointer "/revokedAssignments" should equal the number 2500
    When the bulk operation runner has finished every bulk operation
    Then the store should hold 0 assignments of subject kind "user"
    And the outbox should hold 2500 "iam.user_role.revoked" events
    And the outbox should hold 1 "iam.role.deleted" event
    And the outbox should hold 1 "iam.bulk_operation.completed" event
    And no version should revoke more than 1000 assignments
    And the assignments should be revoked in 3 versions
    When GET request is sent to "/api/roles/{role}"
    Then the response status code should be 404
    When GET request is sent to "/api/bulk-operations"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON pointer "/items/0/kind" should equal "role_deletion"
    And the JSON pointer "/items/0/status" should equal "completed"
    And the JSON pointer "/items/0/totalRecords" should equal the number 2501
    And the JSON pointer "/items/0/appliedRecords" should equal the number 2501
    And the JSON pointer "/items/0/firstVersion" should be present
    And the JSON pointer "/items/0/lastVersion" should be present
    And the JSON pointer "/items/0/requester" should be present

  Scenario: Deleting a role with 2500 assignments over GraphQL returns the bulk operation id
    Given a caller authenticated as the bootstrapped administrator
    And an assignable role "Billing administrator"
    And the seeded role has 2500 assignments
    When the GraphQL operation is sent:
      """
      mutation { deleteRole(input: {id: "{role}", expectedVersion: 1}) { id version policyVersion revokedAssignments bulkOperationId } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/deleteRole/id" should equal the seeded role
    And the JSON pointer "/data/deleteRole/bulkOperationId" should be present
    And the JSON pointer "/data/deleteRole/policyVersion" should be null
    And the JSON pointer "/data/deleteRole/revokedAssignments" should equal the number 2500
    When the bulk operation runner has finished every bulk operation
    Then the store should hold 0 assignments of subject kind "user"
    And the outbox should hold 1 "iam.bulk_operation.completed" event
    When the GraphQL operation is sent:
      """
      { bulkOperations { items { kind status totalRecords appliedRecords requester } } }
      """
    Then the GraphQL response should have no errors
    And the JSON array at "/data/bulkOperations/items" should have 1 items
    And the JSON pointer "/data/bulkOperations/items/0/kind" should equal "role_deletion"
    And the JSON pointer "/data/bulkOperations/items/0/status" should equal "completed"

  Scenario: An unknown bulk operation is 404 over REST and null over GraphQL
    Given a caller authenticated as the bootstrapped administrator
    When GET request is sent to "/api/bulk-operations/00000000-0000-0000-0000-0000000000ff"
    Then the response status code should be 404
    When the GraphQL operation is sent:
      """
      { bulkOperation(id: "00000000-0000-0000-0000-0000000000ff") { id } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/bulkOperation" should be null

  Scenario: A role whose deletion fits one chunk is still deleted in one change
    Given a caller authenticated as the bootstrapped administrator
    And an assignable role "Billing administrator"
    And the seeded role has 3 assignments
    And the If-Match header '"1"'
    When DELETE request is sent to "/api/roles/{role}"
    Then the response status code should be 200
    And the JSON pointer "/revokedAssignments" should equal the number 3
    When GET request is sent to "/api/bulk-operations"
    Then the JSON array at "/items" should have 0 items
