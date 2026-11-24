Feature: IAM REST authorization
  In order to let administrators do only what their roles allow
  As the owner of IAM
  I want every IAM REST operation to require its key and every refused attempt to be recorded

  Scenario: A caller without the catalogue key is refused over REST and the refusal is audited
    Given a caller authenticated with a valid service token that holds no IAM key
    When POST request is sent to "/api/roles" with body:
      """
      {"name": "Billing administrator", "description": "Manages invoices."}
      """
    Then the response status code should be 403
    And the response header "content-type" should contain "application/problem+json"
    And the JSON pointer "/status" should equal the number 403
    And the audit log should hold 1 forbidden "role.create" record within one second
    And the audit log should hold 0 committed "role.create" records
    And the outbox should hold 0 "iam.role.created" events

  Scenario: Reading roles without the catalogue key is refused over REST
    Given a caller authenticated with a valid service token that holds no IAM key
    When GET request is sent to "/api/roles"
    Then the response status code should be 403
    And the audit log should hold 1 forbidden "role.list" record within one second

  Scenario: Validating access needs the reserved validate key and no catalogue key
    Given a caller authenticated with a valid service token that holds no IAM key
    When POST request is sent to "/api/access-validations" with body:
      """
      {"credential": "unused", "service": "iam", "requestId": "req-1", "permissions": ["iam:validate:*"]}
      """
    Then the response status code should be 403
    And the audit log should hold 1 forbidden "access.validate" record within one second

  Scenario: Repeated refusals of one caller leave one record within the summary window
    Given a caller authenticated with a valid service token that holds no IAM key
    When POST request is sent to "/api/roles" with body:
      """
      {"name": "Billing administrator"}
      """
    And POST request is sent to "/api/roles" with body:
      """
      {"name": "Billing administrator"}
      """
    Then the response status code should be 403
    And the audit log should hold 1 forbidden "role.create" record within one second

  Scenario: A request without a valid token is refused with 401 and nothing is audited
    Given a caller presenting a token signed by an unknown key
    When GET request is sent to "/api/roles"
    Then the response status code should be 401
    And the audit log should hold no rejected record after the writer ran
