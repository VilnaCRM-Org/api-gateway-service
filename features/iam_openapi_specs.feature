Feature: IAM OpenAPI specifications
  In order to turn the REST operations of a service into permission candidates without manual work
  As the delivery pipeline of a service
  I want to upload the OpenAPI document of the service and see what it changes

  Scenario: Uploading a new document over REST creates a draft and commits its event and audit record
    Given a caller authenticated with a valid service token
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "billing", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Billing\",\"version\":\"1\"},\"paths\":{\"/invoices\":{\"get\":{\"operationId\":\"listInvoices\"}},\"/invoices/{invoiceId}\":{\"post\":{\"operationId\":\"payInvoice\",\"x-iam-sensitive\":true}}}}"}
      """
    Then the response status code should be 201
    And the response header "location" should contain "/api/openapi-specs/"
    And the JSON pointer "/id" should be present
    And the JSON pointer "/service" should equal "billing"
    And the JSON pointer "/status" should equal "draft"
    And the JSON pointer "/contentHash" should be present
    And the JSON pointer "/operationCount" should equal the number 2
    And the JSON array at "/diff/added" should have 2 items
    And the JSON array at "/diff/removed" should have 0 items
    And the service "billing" should have 1 OpenAPI specification version
    And the outbox should hold 1 "iam.openapi_spec.loaded" event
    And the audit log should hold 1 committed "openapi_spec.load" record

  Scenario: Uploading a new document over GraphQL returns the same data
    Given a caller authenticated with a valid service token
    When the GraphQL operation is sent:
      """
      mutation { loadOpenapiSpec(input: {service: "billing", document: "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Billing\",\"version\":\"1\"},\"paths\":{\"/invoices\":{\"get\":{}}}}"}) { id service status contentHash operationCount diff { added removed } } }
      """
    Then the response status code should be 200
    And the GraphQL response should have no errors
    And the JSON pointer "/data/loadOpenapiSpec/id" should be present
    And the JSON pointer "/data/loadOpenapiSpec/service" should equal "billing"
    And the JSON pointer "/data/loadOpenapiSpec/status" should equal "draft"
    And the JSON pointer "/data/loadOpenapiSpec/operationCount" should equal the number 1
    And the JSON array at "/data/loadOpenapiSpec/diff/added" should have 1 items
    And the outbox should hold 1 "iam.openapi_spec.loaded" event
    And the audit log should hold 1 committed "openapi_spec.load" record

  Scenario: Uploading identical content again returns the existing version and changes nothing
    Given a caller authenticated with a valid service token
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "billing", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Billing\",\"version\":\"1\"},\"paths\":{\"/invoices\":{\"get\":{}}}}"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "billing", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Billing\",\"version\":\"1\"},\"paths\":{\"/invoices\":{\"get\":{}}}}"}
      """
    Then the response status code should be 200
    And the last two responses should be the created version and then the same version found
    And the service "billing" should have 1 OpenAPI specification version
    And the outbox should hold 1 "iam.openapi_spec.loaded" event
    And the audit log should hold 1 committed "openapi_spec.load" record

  Scenario: A document with an external reference is a validation failure with its JSON pointer over REST and GraphQL
    Given a caller authenticated with a valid service token
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "billing", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"a\",\"version\":\"1\"},\"paths\":{\"/a\":{\"get\":{\"responses\":{\"200\":{\"$ref\":\"https://example.com/a.json\"}}}}}}"}
      """
    Then the response status code should be 422
    And the response body should contain "/problems/validation-failed"
    And the response body should contain '"propertyPath":"document"'
    And the response body should contain "pointer /paths/"
    When the GraphQL operation is sent:
      """
      mutation { loadOpenapiSpec(input: {service: "billing", document: "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"a\",\"version\":\"1\"},\"paths\":{\"/a\":{\"get\":{\"responses\":{\"200\":{\"$ref\":\"https://example.com/a.json\"}}}}}}"}) { id } }
      """
    Then the GraphQL error code should be "VALIDATION_FAILED"
    And the service "billing" should have 0 OpenAPI specification versions
    And the outbox should hold 0 "iam.openapi_spec.loaded" events

  Scenario: Two operations with the same normalised key are a validation failure over REST and GraphQL
    Given a caller authenticated with a valid service token
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "billing", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"a\",\"version\":\"1\"},\"paths\":{\"/a/{x}\":{\"get\":{}},\"/a/{y}\":{\"get\":{}}}}"}
      """
    Then the response status code should be 422
    And the response body should contain '"propertyPath":"document"'
    And the response body should contain "more than once"
    When the GraphQL operation is sent:
      """
      mutation { loadOpenapiSpec(input: {service: "billing", document: "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"a\",\"version\":\"1\"},\"paths\":{\"/a/{x}\":{\"get\":{}},\"/a/{y}\":{\"get\":{}}}}"}) { id } }
      """
    Then the GraphQL error code should be "VALIDATION_FAILED"
    And the service "billing" should have 0 OpenAPI specification versions
    And the outbox should hold 0 "iam.openapi_spec.loaded" events

  Scenario: An invalid service name is a validation failure over REST and GraphQL
    Given a caller authenticated with a valid service token
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "Not A Service", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"a\",\"version\":\"1\"},\"paths\":{}}"}
      """
    Then the response status code should be 422
    And the response body should contain '"propertyPath":"service"'
    When the GraphQL operation is sent:
      """
      mutation { loadOpenapiSpec(input: {service: "Not A Service", document: "{}"}) { id } }
      """
    Then the GraphQL error code should be "VALIDATION_FAILED"
    And the outbox should hold 0 "iam.openapi_spec.loaded" events

  Scenario: The reserved service iam is refused to every actor but the startup registration
    Given a caller authenticated with a valid service token
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "iam", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"a\",\"version\":\"1\"},\"paths\":{}}"}
      """
    Then the response status code should be 403
    When the GraphQL operation is sent:
      """
      mutation { loadOpenapiSpec(input: {service: "iam", document: "{}"}) { id } }
      """
    Then the GraphQL error code should be "FORBIDDEN"
    And the service "iam" should have 0 OpenAPI specification versions
    And the outbox should hold 0 "iam.openapi_spec.loaded" events

  Scenario: A caller without a token is refused
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "billing", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"a\",\"version\":\"1\"},\"paths\":{}}"}
      """
    Then the response status code should be 401
    And the service "billing" should have 0 OpenAPI specification versions

  Scenario: A body over 6 MiB on a specification route is refused
    Given a caller authenticated with a valid service token
    When POST request is sent to "/api/openapi-specs" with a JSON body of 6500000 bytes
    Then the response status code should be 413
    And the service "billing" should have 0 OpenAPI specification versions
