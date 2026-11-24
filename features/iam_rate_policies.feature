Feature: IAM rate policies
  In order to attach global quotas to routes
  As an administrator
  I want to create, read, update and delete rate policies over REST or GraphQL

  Scenario: Creating a rate policy over REST commits its state record, its event and its audit record together
    Given a caller authenticated as the bootstrapped administrator
    When POST request is sent to "/api/rate-policies" with body:
      """
      {"name": "per-subject-route", "key": "subject_route", "limit": 100, "periodMs": 60000, "burst": 20, "fallback": "divided"}
      """
    Then the response status code should be 201
    And the response header "location" should contain "/api/rate-policies/"
    And the response header "etag" should contain '"1"'
    And the response header "iam-policy-version" should be present
    And the JSON pointer "/id" should be present
    And the JSON pointer "/name" should equal "per-subject-route"
    And the JSON pointer "/key" should equal "subject_route"
    And the JSON pointer "/limit" should equal the number 100
    And the JSON pointer "/periodMs" should equal the number 60000
    And the JSON pointer "/burst" should equal the number 20
    And the JSON pointer "/fallback" should equal "divided"
    And the JSON pointer "/version" should equal the number 1
    And the state record of the rate policy should hold its configuration
    And the outbox should hold 1 "iam.rate_policy.created" event
    And the audit log should hold 1 committed "rate_policy.create" record

  Scenario: Creating a rate policy over GraphQL returns the same data
    Given a caller authenticated as the bootstrapped administrator
    When the GraphQL operation is sent:
      """
      mutation { createRatePolicy(input: {name: "per-subject-route", key: "subject_route", limit: 100, periodMs: 60000, burst: 20, fallback: "divided"}) { id name key limit periodMs burst fallback version createdAt updatedAt } }
      """
    Then the response status code should be 200
    And the GraphQL response should have no errors
    And the JSON pointer "/data/createRatePolicy/id" should be present
    And the JSON pointer "/data/createRatePolicy/name" should equal "per-subject-route"
    And the JSON pointer "/data/createRatePolicy/key" should equal "subject_route"
    And the JSON pointer "/data/createRatePolicy/limit" should equal the number 100
    And the JSON pointer "/data/createRatePolicy/periodMs" should equal the number 60000
    And the JSON pointer "/data/createRatePolicy/burst" should equal the number 20
    And the JSON pointer "/data/createRatePolicy/fallback" should equal "divided"
    And the JSON pointer "/data/createRatePolicy/version" should equal the number 1
    And the JSON pointer "/data/createRatePolicy/createdAt" should be present
    And the outbox should hold 1 "iam.rate_policy.created" event
    And the audit log should hold 1 committed "rate_policy.create" record

  Scenario: Invalid fields are a validation failure over REST and GraphQL
    Given a caller authenticated as the bootstrapped administrator
    When POST request is sent to "/api/rate-policies" with body:
      """
      {"name": "", "key": "subject_route", "limit": 0, "periodMs": 1500, "burst": -1, "fallback": "divided"}
      """
    Then the response status code should be 422
    And the response body should contain "/problems/validation-failed"
    And the response body should contain "periodMs"
    When POST request is sent to "/api/rate-policies" with body:
      """
      {"name": "per-ip", "key": "everyone", "limit": 10, "periodMs": 1000, "burst": 0, "fallback": "divided"}
      """
    Then the response status code should be 422
    When the GraphQL operation is sent:
      """
      mutation { createRatePolicy(input: {name: "", key: "ip", limit: 0, periodMs: 1500, burst: -1, fallback: "divided"}) { id } }
      """
    Then the GraphQL error code should be "VALIDATION_FAILED"
    And the response body should contain "periodMs"
    And the outbox should hold 0 "iam.rate_policy.created" events
    And the audit log should hold 0 committed "rate_policy.create" records

  Scenario: A duplicate name is a conflict over REST and GraphQL
    Given a caller authenticated as the bootstrapped administrator
    And a rate policy exists with name "per-subject-route"
    When POST request is sent to "/api/rate-policies" with body:
      """
      {"name": "per-subject-route", "key": "ip", "limit": 10, "periodMs": 1000, "burst": 0, "fallback": "full"}
      """
    Then the response status code should be 409
    When the GraphQL operation is sent:
      """
      mutation { createRatePolicy(input: {name: "per-subject-route", key: "ip", limit: 10, periodMs: 1000, burst: 0, fallback: "full"}) { id } }
      """
    Then the GraphQL error code should be "CONFLICT"
    And the rate policy "per-subject-route" should be stored once
    And the outbox should hold 1 "iam.rate_policy.created" event
    And the audit log should hold 1 committed "rate_policy.create" record

  Scenario: Reading a rate policy by id over REST and GraphQL, and an unknown id
    Given a caller authenticated as the bootstrapped administrator
    And a rate policy exists with name "per-subject-route"
    When GET request is sent to "/api/rate-policies/{id}"
    Then the response status code should be 200
    And the response header "etag" should contain '"1"'
    And the JSON pointer "/name" should equal "per-subject-route"
    And the JSON pointer "/key" should equal "subject_route"
    And the JSON pointer "/limit" should equal the number 100
    And the JSON pointer "/periodMs" should equal the number 60000
    And the JSON pointer "/burst" should equal the number 20
    And the JSON pointer "/fallback" should equal "divided"
    And the JSON pointer "/version" should equal the number 1
    And the JSON pointer "/createdAt" should be present
    And the JSON pointer "/updatedAt" should be present
    When the GraphQL operation is sent:
      """
      { ratePolicy(id: "{id}") { id name key limit periodMs burst fallback version createdAt updatedAt } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/ratePolicy/name" should equal "per-subject-route"
    And the JSON pointer "/data/ratePolicy/key" should equal "subject_route"
    And the JSON pointer "/data/ratePolicy/limit" should equal the number 100
    And the JSON pointer "/data/ratePolicy/periodMs" should equal the number 60000
    And the JSON pointer "/data/ratePolicy/burst" should equal the number 20
    And the JSON pointer "/data/ratePolicy/fallback" should equal "divided"
    And the JSON pointer "/data/ratePolicy/version" should equal the number 1
    When GET request is sent to "/api/rate-policies/00000000-0000-7000-8000-000000000000"
    Then the response status code should be 404
    When the GraphQL operation is sent:
      """
      { ratePolicy(id: "00000000-0000-7000-8000-000000000000") { id } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/ratePolicy" should be null

  Scenario: Rate policies are listed over REST and GraphQL
    Given a caller authenticated as the bootstrapped administrator
    And a rate policy exists with name "per-subject-route"
    And a rate policy exists with name "per-ip"
    When GET request is sent to "/api/rate-policies"
    Then the response status code should be 200
    And the JSON array at "/items" should have 2 items
    And the JSON pointer "/items/0/periodMs" should equal the number 60000
    When GET request is sent to "/api/rate-policies?limit=1"
    Then the JSON array at "/items" should have 1 items
    And the JSON pointer "/nextCursor" should be present
    When the GraphQL operation is sent:
      """
      { ratePolicies(first: 10) { items { id name key limit periodMs burst fallback version } nextCursor } }
      """
    Then the GraphQL response should have no errors
    And the JSON array at "/data/ratePolicies/items" should have 2 items
    And the JSON pointer "/data/ratePolicies/nextCursor" should be null

  Scenario: A rate policy is updated with its current version over REST and GraphQL
    Given a caller authenticated as the bootstrapped administrator
    And a rate policy exists with name "per-subject-route"
    And the If-Match header is the ETag of the last response
    When PATCH request is sent to "/api/rate-policies/{id}" with body:
      """
      {"limit": 200, "fallback": "full"}
      """
    Then the response status code should be 200
    And the response header "etag" should contain '"2"'
    And the response header "iam-policy-version" should be present
    And the JSON pointer "/limit" should equal the number 200
    And the JSON pointer "/fallback" should equal "full"
    And the JSON pointer "/name" should equal "per-subject-route"
    And the JSON pointer "/burst" should equal the number 20
    And the JSON pointer "/version" should equal the number 2
    And the outbox should hold 1 "iam.rate_policy.updated" event
    And the audit log should hold 1 committed "rate_policy.update" record
    When the GraphQL operation is sent:
      """
      mutation { updateRatePolicy(input: {id: "{id}", expectedVersion: 2, periodMs: 30000}) { id periodMs limit version } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/updateRatePolicy/periodMs" should equal the number 30000
    And the JSON pointer "/data/updateRatePolicy/limit" should equal the number 200
    And the JSON pointer "/data/updateRatePolicy/version" should equal the number 3
    And the outbox should hold 2 "iam.rate_policy.updated" events

  Scenario: An update without a version or with a stale one is refused over REST and GraphQL
    Given a caller authenticated as the bootstrapped administrator
    And a rate policy exists with name "per-subject-route"
    When PATCH request is sent to "/api/rate-policies/{id}" with body:
      """
      {"limit": 200}
      """
    Then the response status code should be 428
    When the GraphQL operation is sent:
      """
      mutation { updateRatePolicy(input: {id: "{id}", limit: 200}) { id } }
      """
    Then the GraphQL error code should be "PRECONDITION_REQUIRED"
    Given the If-Match header '"7"'
    When PATCH request is sent to "/api/rate-policies/{id}" with body:
      """
      {"limit": 200}
      """
    Then the response status code should be 412
    When the GraphQL operation is sent:
      """
      mutation { updateRatePolicy(input: {id: "{id}", expectedVersion: 7, limit: 200}) { id } }
      """
    Then the GraphQL error code should be "PRECONDITION_FAILED"
    And the outbox should hold 0 "iam.rate_policy.updated" events

  Scenario: A rate policy that a route references cannot be deleted over REST or GraphQL
    Given a caller authenticated as the bootstrapped administrator
    And a rate policy exists with name "per-subject-route"
    And a route applies the rate policy
    And the If-Match header '"1"'
    When DELETE request is sent to "/api/rate-policies/{id}"
    Then the response status code should be 409
    When the GraphQL operation is sent:
      """
      mutation { deleteRatePolicy(input: {id: "{id}", expectedVersion: 1}) { id } }
      """
    Then the GraphQL error code should be "CONFLICT"
    And the rate policy "per-subject-route" should be stored once
    And the outbox should hold 0 "iam.rate_policy.deleted" events
    And the audit log should hold 0 committed "rate_policy.delete" records

  Scenario: An unreferenced rate policy is deleted over REST with a tombstone state record and its event
    Given a caller authenticated as the bootstrapped administrator
    And a rate policy exists with name "per-subject-route"
    And the If-Match header is the ETag of the last response
    When DELETE request is sent to "/api/rate-policies/{id}"
    Then the response status code should be 200
    And the response header "etag" should contain '"2"'
    And the response header "iam-policy-version" should be present
    And the JSON pointer "/version" should equal the number 2
    And the state record of the rate policy should be a tombstone
    And the rate policy "per-subject-route" should be stored 0 times
    And the outbox should hold 1 "iam.rate_policy.deleted" event
    And the audit log should hold 1 committed "rate_policy.delete" record
    When GET request is sent to "/api/rate-policies/{id}"
    Then the response status code should be 404

  Scenario: An unreferenced rate policy is deleted over GraphQL with a tombstone state record and its event
    Given a caller authenticated as the bootstrapped administrator
    And a rate policy exists with name "per-subject-route"
    When the GraphQL operation is sent:
      """
      mutation { deleteRatePolicy(input: {id: "{id}", expectedVersion: 1}) { id version policyVersion } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/deleteRatePolicy/version" should equal the number 2
    And the JSON pointer "/data/deleteRatePolicy/policyVersion" should be present
    And the state record of the rate policy should be a tombstone
    And the outbox should hold 1 "iam.rate_policy.deleted" event
    And the audit log should hold 1 committed "rate_policy.delete" record
    When the GraphQL operation is sent:
      """
      { ratePolicy(id: "{id}") { id } }
      """
    Then the JSON pointer "/data/ratePolicy" should be null

  Scenario: A request without a valid token is refused over REST and GraphQL
    When POST request is sent to "/api/rate-policies" with body:
      """
      {"name": "per-subject-route", "key": "subject_route", "limit": 100, "periodMs": 60000, "burst": 20, "fallback": "divided"}
      """
    Then the response status code should be 401
    When the GraphQL operation is sent:
      """
      { ratePolicies { items { id } } }
      """
    Then the GraphQL error code should be "UNAUTHENTICATED"
