Feature: IAM upstreams
  In order to register the services the gateway proxies to
  As an administrator
  I want to create, read, update and delete upstreams over REST or GraphQL

  Scenario: Creating an upstream over REST commits its state record, its event and its audit record together
    Given a caller authenticated as the bootstrapped administrator
    When POST request is sent to "/api/upstreams" with body:
      """
      {"name": "core", "namespace": "platform", "service": "core-service", "catalogService": "core", "port": 8080, "protocol": "h2c"}
      """
    Then the response status code should be 201
    And the response header "location" should contain "/api/upstreams/"
    And the response header "etag" should contain '"1"'
    And the response header "iam-policy-version" should be present
    And the JSON pointer "/id" should be present
    And the JSON pointer "/name" should equal "core"
    And the JSON pointer "/namespace" should equal "platform"
    And the JSON pointer "/service" should equal "core-service"
    And the JSON pointer "/catalogService" should equal "core"
    And the JSON boolean at "/forwardCredentials" should be false
    And the JSON pointer "/port" should equal the number 8080
    And the JSON pointer "/protocol" should equal "h2c"
    And the JSON pointer "/connectTimeoutMs" should equal the number 250
    And the JSON pointer "/version" should equal the number 1
    And the state record of the upstream "core" should hold its configuration
    And the outbox should hold 1 "iam.upstream.created" event
    And the audit log should hold 1 committed "upstream.create" record

  Scenario: Creating an upstream over GraphQL returns the same data
    Given a caller authenticated as the bootstrapped administrator
    When the GraphQL operation is sent:
      """
      mutation { createUpstream(input: {name: "core", namespace: "platform", service: "core-service", catalogService: "core", port: 8080, protocol: "h2c"}) { id name namespace service catalogService forwardCredentials port protocol connectTimeoutMs responseTimeoutMs concurrencyLimit retryBudgetPercent outlierConsecutiveErrors system version createdAt updatedAt propagation { status } } }
      """
    Then the response status code should be 200
    And the GraphQL response should have no errors
    And the JSON pointer "/data/createUpstream/id" should be present
    And the JSON pointer "/data/createUpstream/name" should equal "core"
    And the JSON pointer "/data/createUpstream/namespace" should equal "platform"
    And the JSON pointer "/data/createUpstream/service" should equal "core-service"
    And the JSON pointer "/data/createUpstream/catalogService" should equal "core"
    And the JSON pointer "/data/createUpstream/port" should equal the number 8080
    And the JSON pointer "/data/createUpstream/protocol" should equal "h2c"
    And the JSON pointer "/data/createUpstream/connectTimeoutMs" should equal the number 250
    And the JSON pointer "/data/createUpstream/version" should equal the number 1
    And the JSON pointer "/data/createUpstream/createdAt" should be present
    And the state record of the upstream "core" should hold its configuration
    And the outbox should hold 1 "iam.upstream.created" event
    And the audit log should hold 1 committed "upstream.create" record

  Scenario: Invalid fields are a validation failure over REST and GraphQL
    Given a caller authenticated as the bootstrapped administrator
    When POST request is sent to "/api/upstreams" with body:
      """
      {"name": "Core Upstream", "namespace": "platform", "service": "core-service", "catalogService": "core", "port": 70000, "protocol": "h2c"}
      """
    Then the response status code should be 422
    And the response body should contain "/problems/validation-failed"
    And the response body should contain "name"
    And the response body should contain "port"
    When the GraphQL operation is sent:
      """
      mutation { createUpstream(input: {name: "core", namespace: "platform", service: "core-service", catalogService: "core", port: 0, protocol: "h2c"}) { id } }
      """
    Then the GraphQL error code should be "VALIDATION_FAILED"
    And the response body should contain "port"
    And the outbox should hold 0 "iam.upstream.created" events

  Scenario: A duplicate name is a conflict over REST and GraphQL
    Given a caller authenticated as the bootstrapped administrator
    And an upstream exists with name "core"
    When POST request is sent to "/api/upstreams" with body:
      """
      {"name": "core", "namespace": "platform", "service": "core-service", "catalogService": "core", "port": 8080, "protocol": "h2c"}
      """
    Then the response status code should be 409
    When the GraphQL operation is sent:
      """
      mutation { createUpstream(input: {name: "core", namespace: "platform", service: "core-service", catalogService: "core", port: 8080, protocol: "h2c"}) { id } }
      """
    Then the GraphQL error code should be "CONFLICT"
    And the upstream "core" should be stored once
    And the outbox should hold 1 "iam.upstream.created" event

  Scenario: Updating an upstream with the current version succeeds over REST
    Given a caller authenticated as the bootstrapped administrator
    And an upstream exists with name "core"
    And the If-Match header is the ETag of the last response
    When PATCH request is sent to "/api/upstreams/{id}" with body:
      """
      {"port": 9090, "protocol": "http1", "forwardCredentials": true}
      """
    Then the response status code should be 200
    And the response header "etag" should contain '"2"'
    And the response header "iam-policy-version" should be present
    And the JSON pointer "/port" should equal the number 9090
    And the JSON pointer "/protocol" should equal "http1"
    And the JSON boolean at "/forwardCredentials" should be true
    And the JSON pointer "/namespace" should equal "platform"
    And the JSON pointer "/version" should equal the number 2
    And the outbox should hold 1 "iam.upstream.updated" event
    And the audit log should hold 1 committed "upstream.update" record

  Scenario: Updating an upstream with a stale version is refused with 412 and with no version with 428
    Given a caller authenticated as the bootstrapped administrator
    And an upstream exists with name "core"
    And the If-Match header '"7"'
    When PATCH request is sent to "/api/upstreams/{id}" with body:
      """
      {"port": 9090}
      """
    Then the response status code should be 412
    When the GraphQL operation is sent:
      """
      mutation { updateUpstream(input: {id: "{id}", expectedVersion: 7, port: 9090}) { id } }
      """
    Then the GraphQL error code should be "PRECONDITION_FAILED"
    When the GraphQL operation is sent:
      """
      mutation { updateUpstream(input: {id: "{id}", port: 9090}) { id } }
      """
    Then the GraphQL error code should be "PRECONDITION_REQUIRED"
    And the outbox should hold 0 "iam.upstream.updated" events

  Scenario: Updating an upstream without If-Match is refused with 428
    Given a caller authenticated as the bootstrapped administrator
    And an upstream exists with name "core"
    When PATCH request is sent to "/api/upstreams/{id}" with body:
      """
      {"port": 9090}
      """
    Then the response status code should be 428
    And the outbox should hold 0 "iam.upstream.updated" events

  Scenario: Updating an upstream over GraphQL returns the same data
    Given a caller authenticated as the bootstrapped administrator
    And an upstream exists with name "core"
    When the GraphQL operation is sent:
      """
      mutation { updateUpstream(input: {id: "{id}", expectedVersion: 1, port: 9090, protocol: "http1"}) { id port protocol version } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/updateUpstream/port" should equal the number 9090
    And the JSON pointer "/data/updateUpstream/protocol" should equal "http1"
    And the JSON pointer "/data/updateUpstream/version" should equal the number 2
    And the outbox should hold 1 "iam.upstream.updated" event

  Scenario: An update that changes the name is a validation failure over REST and GraphQL
    Given a caller authenticated as the bootstrapped administrator
    And an upstream exists with name "core"
    And the If-Match header is the ETag of the last response
    When PATCH request is sent to "/api/upstreams/{id}" with body:
      """
      {"name": "renamed"}
      """
    Then the response status code should be 422
    And the response body should contain "The name of an upstream cannot be changed."
    When the GraphQL operation is sent:
      """
      mutation { updateUpstream(input: {id: "{id}", expectedVersion: 1, name: "renamed"}) { id } }
      """
    Then the GraphQL error code should be "VALIDATION_FAILED"
    And the outbox should hold 0 "iam.upstream.updated" events

  Scenario: An upstream that a route references is not deleted
    Given a caller authenticated as the bootstrapped administrator
    And an upstream exists with name "core"
    And a route references the upstream "core"
    And the If-Match header '"1"'
    When DELETE request is sent to "/api/upstreams/{id}"
    Then the response status code should be 409
    And the response body should contain "/problems/referenced-by-route"
    When the GraphQL operation is sent:
      """
      mutation { deleteUpstream(input: {id: "{id}", expectedVersion: 1}) { id } }
      """
    Then the GraphQL error code should be "CONFLICT"
    And the outbox should hold 0 "iam.upstream.deleted" events

  Scenario: An unreferenced upstream is deleted over REST with a tombstone state record
    Given a caller authenticated as the bootstrapped administrator
    And an upstream exists with name "core"
    And the If-Match header is the ETag of the last response
    When DELETE request is sent to "/api/upstreams/{id}"
    Then the response status code should be 204
    And the response header "etag" should contain '"2"'
    And the response header "iam-policy-version" should be present
    And the state record of the upstream "core" should be a tombstone
    And the outbox should hold 1 "iam.upstream.deleted" event
    And the audit log should hold 1 committed "upstream.delete" record
    When GET request is sent to "/api/upstreams/{id}"
    Then the response status code should be 404

  Scenario: An unreferenced upstream is deleted over GraphQL with a tombstone state record
    Given a caller authenticated as the bootstrapped administrator
    And an upstream exists with name "core"
    When the GraphQL operation is sent:
      """
      mutation { deleteUpstream(input: {id: "{id}", expectedVersion: 1}) { id version policyVersion } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/deleteUpstream/version" should equal the number 2
    And the JSON pointer "/data/deleteUpstream/policyVersion" should be present
    And the state record of the upstream "core" should be a tombstone
    And the outbox should hold 1 "iam.upstream.deleted" event
    And the audit log should hold 1 committed "upstream.delete" record

  Scenario: Upstreams are read by id and listed with cursor pagination over REST
    Given a caller authenticated as the bootstrapped administrator
    And an upstream exists with name "alpha"
    And an upstream exists with name "beta"
    When GET request is sent to "/api/upstreams/{id}"
    Then the response status code should be 200
    And the response header "etag" should contain '"1"'
    And the JSON pointer "/name" should equal "beta"
    And the JSON pointer "/namespace" should equal "platform"
    And the JSON pointer "/service" should equal "core-service"
    And the JSON pointer "/catalogService" should equal "core"
    And the JSON boolean at "/forwardCredentials" should be false
    And the JSON pointer "/port" should equal the number 8080
    And the JSON pointer "/protocol" should equal "h2c"
    And the JSON pointer "/connectTimeoutMs" should equal the number 250
    And the JSON pointer "/responseTimeoutMs" should equal the number 10000
    And the JSON pointer "/concurrencyLimit" should equal the number 256
    And the JSON pointer "/retryBudgetPercent" should equal the number 10
    And the JSON pointer "/outlierConsecutiveErrors" should equal the number 5
    And the JSON pointer "/version" should equal the number 1
    And the JSON pointer "/createdAt" should be present
    And the JSON pointer "/updatedAt" should be present
    When GET request is sent to "/api/upstreams?limit=1"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON pointer "/nextCursor" should be present
    When the cursor at "/nextCursor" is remembered
    And GET request is sent to "/api/upstreams?limit=1&after={cursor}"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON pointer "/nextCursor" should be absent

  Scenario: Upstreams are read by id and listed with cursor pagination over GraphQL
    Given a caller authenticated as the bootstrapped administrator
    And an upstream exists with name "alpha"
    When the GraphQL operation is sent:
      """
      query { upstream(id: "{id}") { id name catalogService port protocol version } upstreams(first: 10) { items { id name } nextCursor } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/upstream/name" should equal "alpha"
    And the JSON pointer "/data/upstream/version" should equal the number 1
    And the JSON array at "/data/upstreams/items" should have 1 items
    And the JSON pointer "/data/upstreams/nextCursor" should be null

  Scenario: An unknown upstream is 404 over REST and null over GraphQL
    Given a caller authenticated as the bootstrapped administrator
    When GET request is sent to "/api/upstreams/0190f2a8-7b3c-7d4e-8f10-1234567890ab"
    Then the response status code should be 404
    When the GraphQL operation is sent:
      """
      query { upstream(id: "0190f2a8-7b3c-7d4e-8f10-1234567890ab") { id } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/upstream" should be null

  Scenario: A caller without the catalogue key of an operation is refused and audited over REST and GraphQL
    Given a caller authenticated with a valid service token that holds no IAM key
    When POST request is sent to "/api/upstreams" with body:
      """
      {"name": "core", "namespace": "platform", "service": "core-service", "catalogService": "core", "port": 8080, "protocol": "h2c"}
      """
    Then the response status code should be 403
    When GET request is sent to "/api/upstreams"
    Then the response status code should be 403
    When the GraphQL operation is sent:
      """
      query { upstreams { items { id } } }
      """
    Then the GraphQL error code should be "FORBIDDEN"
    And the audit log should hold 1 forbidden "upstream.create" record within one second
    And the audit log should hold 1 forbidden "upstream.list" record within one second
    And the outbox should hold 0 "iam.upstream.created" events

  Scenario: Repeating a REST creation with the same idempotency key returns the original result
    Given a caller authenticated as the bootstrapped administrator
    And the idempotency key "create-core-rest"
    When POST request is sent to "/api/upstreams" with body:
      """
      {"name": "core", "namespace": "platform", "service": "core-service", "catalogService": "core", "port": 8080, "protocol": "h2c"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/upstreams" with body:
      """
      {"name": "core", "namespace": "platform", "service": "core-service", "catalogService": "core", "port": 8080, "protocol": "h2c"}
      """
    Then the response status code should be 201
    And the last two responses should have the same body
    And the upstream "core" should be stored once
    And the outbox should hold 1 "iam.upstream.created" event
    And the audit log should hold 1 committed "upstream.create" record

  Scenario: Repeating a GraphQL creation with the same idempotency key returns the original result
    Given a caller authenticated as the bootstrapped administrator
    When the GraphQL operation is sent:
      """
      mutation { createUpstream(input: {name: "core", namespace: "platform", service: "core-service", catalogService: "core", port: 8080, protocol: "h2c", idempotencyKey: "create-core-gql"}) { id name version } }
      """
    Then the GraphQL response should have no errors
    When the GraphQL operation is sent:
      """
      mutation { createUpstream(input: {name: "core", namespace: "platform", service: "core-service", catalogService: "core", port: 8080, protocol: "h2c", idempotencyKey: "create-core-gql"}) { id name version } }
      """
    Then the GraphQL response should have no errors
    And the last two responses should have the same body
    And the upstream "core" should be stored once
    And the outbox should hold 1 "iam.upstream.created" event
    And the audit log should hold 1 committed "upstream.create" record

  Scenario: A principal holding the route key of one service writes only the upstreams of that service
    Given a caller authenticated as an administrator that holds iam:route:core only
    When POST request is sent to "/api/upstreams" with body:
      """
      {"name": "core", "namespace": "platform", "service": "core-service", "catalogService": "core", "port": 8080, "protocol": "h2c"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/upstreams" with body:
      """
      {"name": "payment", "namespace": "platform", "service": "payment-service", "catalogService": "payment", "port": 8080, "protocol": "h2c"}
      """
    Then the response status code should be 403
    When the GraphQL operation is sent:
      """
      mutation { createUpstream(input: {name: "payment", namespace: "platform", service: "payment-service", catalogService: "payment", port: 8080, protocol: "h2c"}) { id } }
      """
    Then the GraphQL error code should be "FORBIDDEN"
    And the upstream "payment" should be stored 0 times
    And the outbox should hold 1 "iam.upstream.created" event
    And the audit log should hold 2 route-scope-denied "upstream.create" records

  Scenario: Any write on a system upstream is a conflict and is audited over REST and GraphQL
    Given a caller authenticated as an administrator that holds iam:route:core only
    And a system upstream exists with name "iam-control"
    And the If-Match header '"1"'
    When PATCH request is sent to "/api/upstreams/{id}" with body:
      """
      {"port": 9090}
      """
    Then the response status code should be 409
    And the response body should contain "/problems/system-entry"
    When DELETE request is sent to "/api/upstreams/{id}"
    Then the response status code should be 409
    When the GraphQL operation is sent:
      """
      mutation { updateUpstream(input: {id: "{id}", expectedVersion: 1, port: 9090}) { id } }
      """
    Then the GraphQL error code should be "CONFLICT"
    And the audit log should hold 1 system-entry "upstream.update" record within one second
    And the audit log should hold 1 system-entry "upstream.delete" record within one second
    And the outbox should hold 0 "iam.upstream.updated" events
    And the outbox should hold 0 "iam.upstream.deleted" events
