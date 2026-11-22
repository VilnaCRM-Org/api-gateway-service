Feature: IAM context
  In order to add authorization behaviour to a running service
  As the IAM team
  I want the service to start with the IAM context wired

  Scenario: The service starts with the IAM context wired
    When GET request is sent to "/api/health"
    Then the response status code should be 204
    And the IAM policy epoch should be the seeded one

  Scenario: The health check still reports the cache
    Given the cache is not working
    When GET request is sent to "/api/health"
    Then the response status code should be 500
    And the response body should contain "Cache is not working"
    And the IAM policy epoch should be the seeded one

  Scenario: The health check still reports the database
    Given the database is not available
    When GET request is sent to "/api/health"
    Then the response status code should be 500
    And the response body should contain "Database is not available"
    And the IAM policy epoch should be the seeded one

  Scenario: The health check still reports the message broker
    Given the message broker is not available
    When GET request is sent to "/api/health"
    Then the response status code should be 500
    And the response body should contain "Message broker is not available"
    And the IAM policy epoch should be the seeded one
