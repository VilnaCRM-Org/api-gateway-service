Feature: IAM route configurations
  In order to keep the routes of a host in version control and apply them without drift
  As an administrator
  I want to replace the full route set of a host in one operation, with a dry run first, over REST or GraphQL

  Scenario: Applying a set over REST deletes, updates and creates routes in one version
    Given a caller authenticated as the bootstrapped administrator
    And an upstream exists with name "core" of the catalogue service "core"
    And a route exists on host "app.example.test" with pattern "/a" and methods "GET" for the upstream "core"
    And a route exists on host "app.example.test" with pattern "/b" and methods "GET" for the upstream "core"
    When GET request is sent to "/api/route-configurations/app.example.test"
    Then the response status code should be 200
    And the response header "etag" should be present
    And the JSON pointer "/routes/0/pathPattern" should equal "/a"
    And the JSON pointer "/routes/1/pathPattern" should equal "/b"
    Given the If-Match header is the ETag of the last response
    When PUT request is sent to "/api/route-configurations/app.example.test" for the upstream "core" with body:
      """
      {"routes": [
        {"methods": ["GET"], "pathPattern": "/b", "service": "core", "upstreamId": "UPSTREAM", "requestTimeoutMs": 5000},
        {"methods": ["GET"], "pathPattern": "/c", "service": "core", "upstreamId": "UPSTREAM"}
      ]}
      """
    Then the response status code should be 200
    And the response header "etag" should be present
    And the response header "iam-policy-version" should be present
    And the JSON boolean at "/dryRun" should be false
    And the JSON boolean at "/revocation" should be true
    And the JSON pointer "/added/0/pathPattern" should equal "/c"
    And the JSON pointer "/changed/0/pathPattern" should equal "/b"
    And the JSON pointer "/removed/0/pathPattern" should equal "/a"
    And the routes of the host "app.example.test" should number 2
    And the outbox should hold 1 "iam.route_configuration.applied" event
    And the outbox should hold 1 "iam.route.deleted" event
    And the outbox should hold 1 "iam.route.updated" event
    And the outbox should hold 3 "iam.route.created" events
    And the audit log should hold 1 committed "route_configuration.apply" record
    And the policy version of the application should hold 4 events
    And the newest state records of the routes should hold 2 configurations and 1 tombstones

  Scenario: Applying a set over GraphQL gives the same result
    Given a caller authenticated as the bootstrapped administrator
    And an upstream exists with name "core" of the catalogue service "core"
    And a route exists on host "app.example.test" with pattern "/a" and methods "GET" for the upstream "core"
    And a route exists on host "app.example.test" with pattern "/b" and methods "GET" for the upstream "core"
    When the GraphQL operation is sent for the upstream "core" against the stored set of the host "app.example.test":
      """
      mutation { applyRouteConfiguration(input: {host: "app.example.test", expectedVersion: VERSION, routes: [{methods: ["GET"], pathPattern: "/b", service: "core", upstreamId: "UPSTREAM", requestTimeoutMs: 5000}, {methods: ["GET"], pathPattern: "/c", service: "core", upstreamId: "UPSTREAM"}]}) { dryRun version routeCount revocation added { pathPattern } changed { pathPattern changedFields } removed { pathPattern } propagation { status } } }
      """
    Then the response status code should be 200
    And the GraphQL response should have no errors
    And the JSON boolean at "/data/applyRouteConfiguration/dryRun" should be false
    And the JSON pointer "/data/applyRouteConfiguration/added/0/pathPattern" should equal "/c"
    And the JSON pointer "/data/applyRouteConfiguration/changed/0/pathPattern" should equal "/b"
    And the JSON pointer "/data/applyRouteConfiguration/changed/0/changedFields/0" should equal "timeouts"
    And the JSON pointer "/data/applyRouteConfiguration/removed/0/pathPattern" should equal "/a"
    And the routes of the host "app.example.test" should number 2
    And the outbox should hold 1 "iam.route_configuration.applied" event
    And the audit log should hold 1 committed "route_configuration.apply" record
    And the policy version of the application should hold 4 events
    And the newest state records of the routes should hold 2 configurations and 1 tombstones

  Scenario: A dry run lists the diff over REST and GraphQL and writes nothing
    Given a caller authenticated as the bootstrapped administrator
    And an upstream exists with name "core" of the catalogue service "core"
    And a route exists on host "app.example.test" with pattern "/a" and methods "GET" for the upstream "core"
    And a route exists on host "app.example.test" with pattern "/b" and methods "GET" for the upstream "core"
    When GET request is sent to "/api/route-configurations/app.example.test"
    Given the If-Match header is the ETag of the last response
    When PUT request is sent to "/api/route-configurations/app.example.test?dryRun=true" for the upstream "core" with body:
      """
      {"routes": [
        {"methods": ["GET"], "pathPattern": "/b", "service": "core", "upstreamId": "UPSTREAM", "requestTimeoutMs": 5000},
        {"methods": ["GET"], "pathPattern": "/c", "service": "core", "upstreamId": "UPSTREAM"}
      ]}
      """
    Then the response status code should be 200
    And the JSON boolean at "/dryRun" should be true
    And the JSON pointer "/added/0/pathPattern" should equal "/c"
    And the JSON pointer "/changed/0/pathPattern" should equal "/b"
    And the JSON pointer "/removed/0/pathPattern" should equal "/a"
    When the GraphQL operation is sent for the upstream "core" against the stored set of the host "app.example.test":
      """
      mutation { applyRouteConfiguration(input: {host: "app.example.test", expectedVersion: VERSION, dryRun: true, routes: [{methods: ["GET"], pathPattern: "/b", service: "core", upstreamId: "UPSTREAM", requestTimeoutMs: 5000}, {methods: ["GET"], pathPattern: "/c", service: "core", upstreamId: "UPSTREAM"}]}) { dryRun added { pathPattern } changed { pathPattern } removed { pathPattern } policyVersion } }
      """
    Then the GraphQL response should have no errors
    And the JSON boolean at "/data/applyRouteConfiguration/dryRun" should be true
    And the JSON pointer "/data/applyRouteConfiguration/added/0/pathPattern" should equal "/c"
    And the JSON pointer "/data/applyRouteConfiguration/removed/0/pathPattern" should equal "/a"
    And the routes of the host "app.example.test" should number 2
    And the outbox should hold 0 "iam.route_configuration.applied" events
    And the outbox should hold 0 "iam.route.deleted" events
    And the outbox should hold 0 "iam.route.updated" events
    And the outbox should hold 2 "iam.route.created" events
    And the audit log should hold 0 committed "route_configuration.apply" records

  Scenario: A set with routes that the gateway could not build is a route table conflict and changes nothing
    Given a caller authenticated as the bootstrapped administrator
    And an upstream exists with name "core" of the catalogue service "core"
    And a route exists on host "app.example.test" with pattern "/a" and methods "GET" for the upstream "core"
    And a route exists on host "app.example.test" with pattern "/b" and methods "GET" for the upstream "core"
    When GET request is sent to "/api/route-configurations/app.example.test"
    Given the If-Match header is the ETag of the last response
    When PUT request is sent to "/api/route-configurations/app.example.test" for the upstream "core" with body:
      """
      {"routes": [
        {"methods": ["GET"], "pathPattern": "/users/{id}", "service": "core", "upstreamId": "UPSTREAM"},
        {"methods": ["GET"], "pathPattern": "/users/{name}", "service": "core", "upstreamId": "UPSTREAM"}
      ]}
      """
    Then the response status code should be 409
    And the response body should contain "/problems/route-table-conflict"
    When the GraphQL operation is sent for the upstream "core" against the stored set of the host "app.example.test":
      """
      mutation { applyRouteConfiguration(input: {host: "app.example.test", expectedVersion: VERSION, routes: [{methods: ["GET"], pathPattern: "/users/{id}", service: "core", upstreamId: "UPSTREAM"}, {methods: ["GET"], pathPattern: "/users/{name}", service: "core", upstreamId: "UPSTREAM"}]}) { version } }
      """
    Then the GraphQL error code should be "CONFLICT"
    And the routes of the host "app.example.test" should number 2
    And the outbox should hold 0 "iam.route_configuration.applied" events

  Scenario: A set of 1000 routes is committed as one policy version and a set of 1001 is refused
    Given a caller authenticated as the bootstrapped administrator
    And an upstream exists with name "core" of the catalogue service "core"
    When GET request is sent to "/api/route-configurations/app.example.test"
    Given the If-Match header is the ETag of the last response
    When 1001 generated routes are put to "/api/route-configurations/app.example.test" for the upstream "core"
    Then the response status code should be 422
    And the response body should contain "routes"
    When 1001 generated routes are applied over GraphQL to the host "app.example.test" for the upstream "core"
    Then the GraphQL error code should be "VALIDATION_FAILED"
    And the routes of the host "app.example.test" should number 0
    When 1000 generated routes are put to "/api/route-configurations/app.example.test" for the upstream "core"
    Then the response status code should be 200
    And the JSON pointer "/routeCount" should equal the number 1000
    And the routes of the host "app.example.test" should number 1000
    And the outbox should hold 1 "iam.route_configuration.applied" event
    And the policy version of the application should hold 1001 events
    When GET request is sent to "/api/route-configurations/app.example.test"
    Then the response status code should be 200
    And the JSON pointer "/routes/999/pathPattern" should be present
    And the JSON pointer "/routes/1000" should be absent

  Scenario: A stale or a missing version is refused over REST and GraphQL
    Given a caller authenticated as the bootstrapped administrator
    And an upstream exists with name "core" of the catalogue service "core"
    And a route exists on host "app.example.test" with pattern "/a" and methods "GET" for the upstream "core"
    And the If-Match header '"7"'
    When PUT request is sent to "/api/route-configurations/app.example.test" for the upstream "core" with body:
      """
      {"routes": [{"methods": ["GET"], "pathPattern": "/c", "service": "core", "upstreamId": "UPSTREAM"}]}
      """
    Then the response status code should be 412
    When the GraphQL operation is sent for the upstream "core":
      """
      mutation { applyRouteConfiguration(input: {host: "app.example.test", expectedVersion: 7, routes: [{methods: ["GET"], pathPattern: "/c", service: "core", upstreamId: "UPSTREAM"}]}) { version } }
      """
    Then the GraphQL error code should be "PRECONDITION_FAILED"
    When the GraphQL operation is sent for the upstream "core":
      """
      mutation { applyRouteConfiguration(input: {host: "app.example.test", routes: [{methods: ["GET"], pathPattern: "/c", service: "core", upstreamId: "UPSTREAM"}]}) { version } }
      """
    Then the GraphQL error code should be "PRECONDITION_REQUIRED"
    And the routes of the host "app.example.test" should number 1
    And the outbox should hold 0 "iam.route_configuration.applied" events

  Scenario: Only a holder of iam:route:anonymous applies a set with an anonymous route
    Given a caller authenticated as an administrator that holds iam:route:core only
    And an upstream exists with name "core" of the catalogue service "core"
    When GET request is sent to "/api/route-configurations/app.example.test"
    Given the If-Match header is the ETag of the last response
    When PUT request is sent to "/api/route-configurations/app.example.test" for the upstream "core" with body:
      """
      {"routes": [{"methods": ["GET"], "pathPattern": "/public", "service": "core", "upstreamId": "UPSTREAM", "anonymous": true}]}
      """
    Then the response status code should be 403
    When the GraphQL operation is sent for the upstream "core" against the stored set of the host "app.example.test":
      """
      mutation { applyRouteConfiguration(input: {host: "app.example.test", expectedVersion: VERSION, routes: [{methods: ["GET"], pathPattern: "/public", service: "core", upstreamId: "UPSTREAM", anonymous: true}]}) { version } }
      """
    Then the GraphQL error code should be "FORBIDDEN"
    And the routes of the host "app.example.test" should number 0
    And the outbox should hold 0 "iam.route_configuration.applied" events

  Scenario: A set that omits a system route is refused as a system entry and audited
    Given a caller authenticated as the bootstrapped administrator
    And an upstream exists with name "core" of the catalogue service "core"
    And a system upstream exists with name "system-core"
    And a system route exists on host "app.example.test" with pattern "/system" for the system upstream "system-core"
    When GET request is sent to "/api/route-configurations/app.example.test"
    Given the If-Match header is the ETag of the last response
    When PUT request is sent to "/api/route-configurations/app.example.test" for the upstream "core" with body:
      """
      {"routes": []}
      """
    Then the response status code should be 409
    And the response body should contain "/problems/system-entry"
    And the audit log should hold 1 system-entry "route_configuration.apply" record in a second
    And the routes of the host "app.example.test" should number 1
