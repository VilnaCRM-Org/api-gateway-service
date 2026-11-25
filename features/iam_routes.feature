Feature: IAM routes
  In order to decide which host, methods and paths reach which upstream
  As an administrator
  I want to create, read, update and delete routes over REST or GraphQL

  Scenario: Creating a route over REST commits its state record, its event and its audit record together
    Given a caller authenticated as the bootstrapped administrator
    And an upstream exists with name "core" of the catalogue service "core"
    When POST request is sent to "/api/routes" with body:
      """
      {"host": "app.example.test", "methods": ["GET"], "pathPattern": "/api/orders/{order}", "service": "core", "upstreamId": "{id}"}
      """
    Then the response status code should be 201
    And the response header "location" should contain "/api/routes/"
    And the response header "etag" should contain '"1"'
    And the response header "iam-policy-version" should be present
    And the JSON pointer "/id" should be present
    And the JSON pointer "/host" should equal "app.example.test"
    And the JSON pointer "/pathPattern" should equal "/api/orders/{order}"
    And the JSON pointer "/service" should equal "core"
    And the JSON boolean at "/anonymous" should be false
    And the JSON pointer "/enforcement" should equal "enforce"
    And the JSON pointer "/version" should equal the number 1
    And the state record of the remembered route should hold its configuration
    And the outbox should hold 1 "iam.route.created" event
    And the audit log should hold 1 committed "route.create" record

  Scenario: Creating a route over GraphQL returns the same data
    Given a caller authenticated as the bootstrapped administrator
    And an upstream exists with name "core" of the catalogue service "core"
    When the GraphQL operation is sent for the upstream "core":
      """
      mutation { createRoute(input: {host: "app.example.test", methods: ["GET"], pathPattern: "/api/orders/{order}", service: "core", upstreamId: "UPSTREAM"}) { id host methods pathPattern service upstreamId graphql streaming anonymous enforcement bodyLimitBytes requestTimeoutMs idleTimeoutMs retryPolicy ratePolicyIds system version createdAt updatedAt propagation { status } } }
      """
    Then the response status code should be 200
    And the GraphQL response should have no errors
    And the JSON pointer "/data/createRoute/id" should be present
    And the JSON pointer "/data/createRoute/host" should equal "app.example.test"
    And the JSON pointer "/data/createRoute/pathPattern" should equal "/api/orders/{order}"
    And the JSON pointer "/data/createRoute/enforcement" should equal "enforce"
    And the JSON pointer "/data/createRoute/version" should equal the number 1
    And the state record of the remembered route should hold its configuration
    And the outbox should hold 1 "iam.route.created" event
    And the audit log should hold 1 committed "route.create" record

  Scenario: A route that overlaps another route of its host is a conflict, another method is accepted
    Given a caller authenticated as the bootstrapped administrator
    And an upstream exists with name "core" of the catalogue service "core"
    And a route exists on host "app.example.test" with pattern "/api/orders/{order}" and methods "GET" for the upstream "core"
    When POST request is sent to "/api/routes" for the upstream "core" with body:
      """
      {"host": "app.example.test", "methods": ["GET", "PATCH"], "pathPattern": "/api/orders/{order}", "service": "core", "upstreamId": "UPSTREAM"}
      """
    Then the response status code should be 409
    When the GraphQL operation is sent for the upstream "core":
      """
      mutation { createRoute(input: {host: "app.example.test", methods: ["GET", "PATCH"], pathPattern: "/api/orders/{order}", service: "core", upstreamId: "UPSTREAM"}) { id } }
      """
    Then the GraphQL error code should be "CONFLICT"
    When POST request is sent to "/api/routes" for the upstream "core" with body:
      """
      {"host": "app.example.test", "methods": ["DELETE"], "pathPattern": "/api/orders/{order}", "service": "core", "upstreamId": "UPSTREAM"}
      """
    Then the response status code should be 201
    And the routes of the host "app.example.test" should number 2
    And the outbox should hold 2 "iam.route.created" events

  Scenario: A pattern that the gateway could not build next to a stored one is a route table conflict and writes nothing
    Given a caller authenticated as the bootstrapped administrator
    And an upstream exists with name "core" of the catalogue service "core"
    And a route exists on host "app.example.test" with pattern "/users/{user}" and methods "GET" for the upstream "core"
    When POST request is sent to "/api/routes" for the upstream "core" with body:
      """
      {"host": "app.example.test", "methods": ["GET"], "pathPattern": "/users/{name}", "service": "core", "upstreamId": "UPSTREAM"}
      """
    Then the response status code should be 409
    And the response body should contain "/problems/route-table-conflict"
    When the GraphQL operation is sent for the upstream "core":
      """
      mutation { createRoute(input: {host: "app.example.test", methods: ["GET"], pathPattern: "/users/{name}", service: "core", upstreamId: "UPSTREAM"}) { id } }
      """
    Then the GraphQL error code should be "CONFLICT"
    And the routes of the host "app.example.test" should number 1
    And the outbox should hold 1 "iam.route.created" event

  Scenario: Only a holder of iam:route:anonymous makes a route anonymous or changes the enforcement over REST and GraphQL
    Given a caller authenticated as an administrator that holds iam:route:core only
    And an upstream exists with name "core" of the catalogue service "core"
    When POST request is sent to "/api/routes" for the upstream "core" with body:
      """
      {"host": "app.example.test", "methods": ["GET"], "pathPattern": "/public", "service": "core", "upstreamId": "UPSTREAM", "anonymous": true}
      """
    Then the response status code should be 403
    When the GraphQL operation is sent for the upstream "core":
      """
      mutation { createRoute(input: {host: "app.example.test", methods: ["GET"], pathPattern: "/audited", service: "core", upstreamId: "UPSTREAM", enforcement: "audit"}) { id } }
      """
    Then the GraphQL error code should be "FORBIDDEN"
    And the routes of the host "app.example.test" should number 0
    And the audit log should hold 2 rejected "route.create" records with the reason "anonymous_route_forbidden"
    And the outbox should hold 0 "iam.route.created" events

  Scenario: A principal without iam:route:anonymous cannot switch a route to audit mode over REST or GraphQL
    Given a caller authenticated as an administrator that holds iam:route:core only
    And an upstream exists with name "core" of the catalogue service "core"
    And a route exists on host "app.example.test" with pattern "/api/orders/{order}" and methods "GET" for the upstream "core"
    And the If-Match header '"1"'
    When PATCH request is sent to "/api/routes/{id}" with body:
      """
      {"enforcement": "audit"}
      """
    Then the response status code should be 403
    When the GraphQL operation is sent:
      """
      mutation { updateRoute(input: {id: "{id}", expectedVersion: 1, enforcement: "audit"}) { id } }
      """
    Then the GraphQL error code should be "FORBIDDEN"
    And the audit log should hold 2 rejected "route.update" records with the reason "anonymous_route_forbidden"
    And the outbox should hold 0 "iam.route.updated" events

  Scenario: The administrator makes a route anonymous and the audit record names the flag change
    Given a caller authenticated as the bootstrapped administrator
    And an upstream exists with name "core" of the catalogue service "core"
    When POST request is sent to "/api/routes" for the upstream "core" with body:
      """
      {"host": "app.example.test", "methods": ["GET"], "pathPattern": "/public", "service": "core", "upstreamId": "UPSTREAM", "anonymous": true}
      """
    Then the response status code should be 201
    And the JSON boolean at "/anonymous" should be true
    And the audit log should hold 1 committed "route.create" record that name "anonymous=true"
    Given the If-Match header is the ETag of the last response
    When PATCH request is sent to "/api/routes/{id}" with body:
      """
      {"anonymous": false}
      """
    Then the response status code should be 200
    And the JSON boolean at "/anonymous" should be false
    And the audit log should hold 1 committed "route.update" record that name "anonymous=false"

  Scenario: An unknown upstream, an unknown rate policy and an invalid pattern are validation failures
    Given a caller authenticated as the bootstrapped administrator
    And an upstream exists with name "core" of the catalogue service "core"
    When POST request is sent to "/api/routes" with body:
      """
      {"host": "app.example.test", "methods": ["GET"], "pathPattern": "/api/orders", "service": "core", "upstreamId": "0190f2a8-7b3c-7d4e-8f10-1234567890ff"}
      """
    Then the response status code should be 422
    And the response body should contain "upstreamId"
    When POST request is sent to "/api/routes" for the upstream "core" with body:
      """
      {"host": "app.example.test", "methods": ["GET"], "pathPattern": "/api/orders", "service": "core", "upstreamId": "UPSTREAM", "ratePolicyIds": ["0190f2a8-7b3c-7d4e-8f10-1234567890fe"]}
      """
    Then the response status code should be 422
    And the response body should contain "ratePolicyIds"
    When the GraphQL operation is sent for the upstream "core":
      """
      mutation { createRoute(input: {host: "app.example.test", methods: ["GET"], pathPattern: "orders", service: "core", upstreamId: "UPSTREAM"}) { id } }
      """
    Then the GraphQL error code should be "VALIDATION_FAILED"
    And the response body should contain "pathPattern"
    And the routes of the host "app.example.test" should number 0

  Scenario: Updating a route with a stale and with no version is refused over REST and GraphQL
    Given a caller authenticated as the bootstrapped administrator
    And an upstream exists with name "core" of the catalogue service "core"
    And a route exists on host "app.example.test" with pattern "/api/orders/{order}" and methods "GET" for the upstream "core"
    And the If-Match header '"7"'
    When PATCH request is sent to "/api/routes/{id}" with body:
      """
      {"requestTimeoutMs": 5000}
      """
    Then the response status code should be 412
    When the GraphQL operation is sent:
      """
      mutation { updateRoute(input: {id: "{id}", expectedVersion: 7, requestTimeoutMs: 5000}) { id } }
      """
    Then the GraphQL error code should be "PRECONDITION_FAILED"
    When the GraphQL operation is sent:
      """
      mutation { updateRoute(input: {id: "{id}", requestTimeoutMs: 5000}) { id } }
      """
    Then the GraphQL error code should be "PRECONDITION_REQUIRED"
    And the outbox should hold 0 "iam.route.updated" events

  Scenario: Updating or deleting a route without If-Match is refused with 428
    Given a caller authenticated as the bootstrapped administrator
    And an upstream exists with name "core" of the catalogue service "core"
    And a route exists on host "app.example.test" with pattern "/api/orders/{order}" and methods "GET" for the upstream "core"
    When PATCH request is sent to "/api/routes/{id}" with body:
      """
      {"requestTimeoutMs": 5000}
      """
    Then the response status code should be 428
    When DELETE request is sent to "/api/routes/{id}"
    Then the response status code should be 428
    And the outbox should hold 0 "iam.route.updated" events
    And the outbox should hold 0 "iam.route.deleted" events

  Scenario: Updating a route with its current version changes the named members
    Given a caller authenticated as the bootstrapped administrator
    And an upstream exists with name "core" of the catalogue service "core"
    And a route exists on host "app.example.test" with pattern "/api/orders/{order}" and methods "GET" for the upstream "core"
    And the If-Match header '"1"'
    When PATCH request is sent to "/api/routes/{id}" with body:
      """
      {"requestTimeoutMs": 5000, "methods": ["GET", "PATCH"]}
      """
    Then the response status code should be 200
    And the response header "etag" should contain '"2"'
    And the JSON pointer "/requestTimeoutMs" should equal the number 5000
    And the JSON pointer "/idleTimeoutMs" should equal the number 60000
    And the JSON pointer "/version" should equal the number 2
    And the outbox should hold 1 "iam.route.updated" event
    And the audit log should hold 1 committed "route.update" record

  Scenario: Deleting a route writes a tombstone state record and the deleted event
    Given a caller authenticated as the bootstrapped administrator
    And an upstream exists with name "core" of the catalogue service "core"
    And a route exists on host "app.example.test" with pattern "/api/orders/{order}" and methods "GET" for the upstream "core"
    And the If-Match header '"1"'
    When DELETE request is sent to "/api/routes/{id}"
    Then the response status code should be 204
    And the routes of the host "app.example.test" should number 0
    And the state record of the remembered route should be a tombstone
    And the outbox should hold 1 "iam.route.deleted" event
    And the audit log should hold 1 committed "route.delete" record
    When GET request is sent to "/api/routes/{id}"
    Then the response status code should be 404

  Scenario: Routes are read by id and listed with the filters over both interfaces
    Given a caller authenticated as the bootstrapped administrator
    And an upstream exists with name "core" of the catalogue service "core"
    And an upstream exists with name "payment" of the catalogue service "payment"
    And a route exists on host "app.example.test" with pattern "/api/orders/{order}" and methods "GET" for the upstream "core"
    When GET request is sent to "/api/routes/{id}"
    Then the response status code should be 200
    And the response header "etag" should contain '"1"'
    And the JSON pointer "/host" should equal "app.example.test"
    When GET request is sent to "/api/routes?host=app.example.test&service=core"
    Then the response status code should be 200
    And the JSON pointer "/items/0/pathPattern" should equal "/api/orders/{order}"
    When GET request is sent to "/api/routes?service=payment"
    Then the response status code should be 200
    And the response body should contain '"items":[]'
    When the GraphQL operation is sent:
      """
      query { route(id: "{id}") { id host version } routes(filter: {host: "app.example.test"}) { items { id } nextCursor } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/route/host" should equal "app.example.test"
    And the JSON pointer "/data/routes/items/0/id" should be present

  Scenario: An unknown id is 404 over REST and null over GraphQL
    Given a caller authenticated as the bootstrapped administrator
    When GET request is sent to "/api/routes/0190f2a8-7b3c-7d4e-8f10-1234567890ab"
    Then the response status code should be 404
    When the GraphQL operation is sent:
      """
      query { route(id: "0190f2a8-7b3c-7d4e-8f10-1234567890ab") { id } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/route" should be null

  Scenario: A route created with a cors policy returns the policy unchanged and an origin that is not exact is refused
    Given a caller authenticated as the bootstrapped administrator
    And an upstream exists with name "core" of the catalogue service "core"
    When POST request is sent to "/api/routes" for the upstream "core" with body:
      """
      {"host": "app.example.test", "methods": ["GET"], "pathPattern": "/api/orders", "service": "core", "upstreamId": "UPSTREAM", "cors": {"origins": ["https://app.example.test"], "methods": ["GET"], "headers": ["content-type"], "allowCredentials": true, "maxAgeSeconds": 600}}
      """
    Then the response status code should be 201
    And the JSON pointer "/cors/origins/0" should equal "https://app.example.test"
    And the JSON boolean at "/cors/allowCredentials" should be true
    And the JSON pointer "/cors/maxAgeSeconds" should equal the number 600
    When POST request is sent to "/api/routes" for the upstream "core" with body:
      """
      {"host": "app.example.test", "methods": ["GET"], "pathPattern": "/api/other", "service": "core", "upstreamId": "UPSTREAM", "cors": {"origins": ["https://*.example.test"]}}
      """
    Then the response status code should be 422
    And the response body should contain "cors.origins"

  Scenario: A principal holding one route key writes only the routes of that service and never a system route
    Given a caller authenticated as the bootstrapped administrator
    And an upstream exists with name "payment" of the catalogue service "payment"
    And a system upstream exists with name "iam-control"
    And a system route exists on host "iam.example.test" with pattern "/api/iam" for the system upstream "iam-control"
    And the If-Match header '"1"'
    And a caller authenticated as an administrator that holds iam:route:core only
    When POST request is sent to "/api/routes" for the upstream "payment" with body:
      """
      {"host": "payment.example.test", "methods": ["GET"], "pathPattern": "/api/payments", "service": "core", "upstreamId": "UPSTREAM"}
      """
    Then the response status code should be 422
    When POST request is sent to "/api/routes" for the upstream "payment" with body:
      """
      {"host": "payment.example.test", "methods": ["GET"], "pathPattern": "/api/iam", "service": "iam", "upstreamId": "UPSTREAM"}
      """
    Then the response status code should be 403
    When PATCH request is sent to "/api/routes/{id}" with body:
      """
      {"requestTimeoutMs": 5000}
      """
    Then the response status code should be 409
    And the response body should contain "/problems/system-entry"
    And the audit log should hold 1 route-scope-denied "route.create" record within one second
    And the audit log should hold 1 system-entry "route.update" record in a second
    And the routes of the host "payment.example.test" should number 0
