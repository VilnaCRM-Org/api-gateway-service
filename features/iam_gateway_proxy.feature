Feature: Gateway request forwarding
  In order to protect a service without changing what it returns
  As a customer of a VilnaCRM service
  I want my authorized request forwarded to the upstream of the route and its response relayed unchanged

  Scenario: The response of the upstream is relayed unchanged to a subject holding the key of the route
    Given a gateway route "GET /api/users/{id}" of the host "api.example.test" for the service "users" guarded by the key "rest:users:GET /api/users/{}"
    And the gateway subject "customer" holds the key "rest:users:GET /api/users/{}"
    When the gateway subject "customer" sends GET request to "/api/users/42" through the gateway
    Then the response status code should be 201
    And the response header "x-upstream" should contain "yes"
    And the response body should contain "upstream got 0 bytes"
    And the fake upstream should have received 1 request

  Scenario: A subject without the IAM key is refused by the gateway and the administrator reaches iam-control
    Given a gateway route "GET /api/roles" of the host "iam.example.test" for the service "iam" guarded by the key "rest:iam:GET /api/roles"
    And the gateway subject "service" holds no key
    And the gateway subject "administrator" holds the key "rest:iam:GET /api/roles"
    When the gateway subject "service" sends GET request to "/api/roles" through the gateway
    Then the response status code should be 403
    And the fake upstream should have received 0 requests
    When the gateway subject "administrator" sends GET request to "/api/roles" through the gateway
    Then the response status code should be 201
    And the fake upstream should have received 1 request
