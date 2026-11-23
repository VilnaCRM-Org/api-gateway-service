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

  Scenario: Versions of several services are listed with filters over REST and GraphQL
    Given a caller authenticated with a valid service token
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "billing", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Billing\",\"version\":\"1\"},\"paths\":{\"/invoices\":{\"get\":{\"operationId\":\"listInvoices\"}},\"/invoices/{invoiceId}/pay\":{\"post\":{\"operationId\":\"payInvoice\"}}}}"}
      """
    Then the response status code should be 201
    Given the remembered OpenAPI specification is active
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "shipping", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Billing\",\"version\":\"1\"},\"paths\":{\"/parcels\":{\"get\":{}}}}"}
      """
    Then the response status code should be 201
    When GET request is sent to "/api/openapi-specs"
    Then the response status code should be 200
    And the JSON array at "/items" should have 2 items
    And the JSON pointer "/nextCursor" should be absent
    When GET request is sent to "/api/openapi-specs?service=billing"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON pointer "/items/0/id" should be present
    And the JSON pointer "/items/0/service" should equal "billing"
    And the JSON pointer "/items/0/contentHash" should be present
    And the JSON pointer "/items/0/status" should equal "active"
    And the JSON pointer "/items/0/uploadedBy" should be present
    And the JSON pointer "/items/0/createdAt" should be present
    And the JSON pointer "/items/0/activatedAt" should be present
    And the JSON pointer "/items/0/operationCount" should equal the number 2
    And the JSON pointer "/items/0/document" should be absent
    When GET request is sent to "/api/openapi-specs?status=draft&includeDocument=true"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON pointer "/items/0/service" should equal "shipping"
    And the JSON pointer "/items/0/document" should be present
    When GET request is sent to "/api/openapi-specs?limit=1"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON pointer "/nextCursor" should be present
    When GET request is sent to "/api/openapi-specs/{id}"
    Then the response status code should be 200
    And the JSON pointer "/service" should equal "shipping"
    And the JSON pointer "/operationCount" should equal the number 1
    And the JSON pointer "/document" should be absent
    When GET request is sent to "/api/openapi-specs/{id}?includeDocument=true"
    Then the response status code should be 200
    And the JSON pointer "/document" should be present
    When the GraphQL operation is sent:
      """
      { openapiSpecs(first: 3, filter: {service: "billing"}) { items { id service status operationCount document } nextCursor } }
      """
    Then the GraphQL response should have no errors
    And the JSON array at "/data/openapiSpecs/items" should have 1 items
    And the JSON pointer "/data/openapiSpecs/items/0/service" should equal "billing"
    And the JSON pointer "/data/openapiSpecs/items/0/status" should equal "active"
    And the JSON pointer "/data/openapiSpecs/items/0/operationCount" should equal the number 2
    And the JSON pointer "/data/openapiSpecs/items/0/document" should be present
    And the JSON pointer "/data/openapiSpecs/nextCursor" should be null
    When the GraphQL operation is sent:
      """
      { openapiSpecs(first: 1, filter: {status: "draft"}) { items { service document } } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/openapiSpecs/items/0/service" should equal "shipping"
    And the JSON pointer "/data/openapiSpecs/items/0/document" should be present
    When the GraphQL operation is sent:
      """
      { openapiSpec(id: "{id}") { id service status operationCount document } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/openapiSpec/service" should equal "shipping"
    And the JSON pointer "/data/openapiSpec/operationCount" should equal the number 1
    And the JSON pointer "/data/openapiSpec/document" should be present

  Scenario: The diff of a draft that removes a granted operation lists the affected role over REST and GraphQL
    Given a caller authenticated with a valid service token
    And an assignable role "Payer" that grants "rest:billing:POST /invoices/{}/pay"
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "billing", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Billing\",\"version\":\"1\"},\"paths\":{\"/invoices\":{\"get\":{\"operationId\":\"listInvoices\"}},\"/invoices/{invoiceId}/pay\":{\"post\":{\"operationId\":\"payInvoice\"}}}}"}
      """
    Then the response status code should be 201
    Given the remembered OpenAPI specification is active
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "billing", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Billing\",\"version\":\"1\"},\"paths\":{\"/invoices\":{\"get\":{\"operationId\":\"listInvoices\"}}}}"}
      """
    Then the response status code should be 201
    When GET request is sent to "/api/openapi-specs/{id}/diff"
    Then the response status code should be 200
    And the JSON array at "/added" should have 0 items
    And the JSON array at "/removed" should have 1 items
    And the JSON pointer "/removed/0" should equal "POST /invoices/{}/pay"
    And the JSON array at "/removedGrants" should have 1 items
    And the JSON pointer "/removedGrants/0/operation" should equal "POST /invoices/{}/pay"
    And the JSON array at "/removedGrants/0/roles" should have 1 items
    And the JSON pointer "/removedGrants/0/roles/0" should be the seeded role
    When the GraphQL operation is sent:
      """
      { openapiSpec(id: "{id}") { id diff { removed removedGrants { operation roles } } } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/openapiSpec/diff/removed/0" should equal "POST /invoices/{}/pay"
    And the JSON pointer "/data/openapiSpec/diff/removedGrants/0/operation" should equal "POST /invoices/{}/pay"
    And the JSON pointer "/data/openapiSpec/diff/removedGrants/0/roles/0" should be the seeded role

  Scenario: The diff lists the wildcard grants that gain the operations a draft adds
    Given a caller authenticated with a valid service token
    And an assignable role "Reader" that grants "rest:billing:GET *"
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "billing", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Billing\",\"version\":\"1\"},\"paths\":{\"/invoices\":{\"get\":{\"operationId\":\"listInvoices\"}}}}"}
      """
    Then the response status code should be 201
    Given the remembered OpenAPI specification is active
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "billing", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Billing\",\"version\":\"1\"},\"paths\":{\"/invoices\":{\"get\":{\"operationId\":\"listInvoices\"}},\"/orders\":{\"get\":{\"operationId\":\"listOrders\"}}}}"}
      """
    Then the response status code should be 201
    When GET request is sent to "/api/openapi-specs/{id}/diff"
    Then the response status code should be 200
    And the JSON pointer "/added/0" should equal "GET /orders"
    And the JSON array at "/removedGrants" should have 0 items
    And the JSON array at "/wildcardGains" should have 1 items
    And the JSON pointer "/wildcardGains/0/role" should be the seeded role
    And the JSON pointer "/wildcardGains/0/pattern" should equal "rest:billing:GET *"
    And the JSON pointer "/wildcardGains/0/operations/0" should equal "GET /orders"
    When the GraphQL operation is sent:
      """
      { openapiSpec(id: "{id}") { diff { added wildcardGains { role pattern operations } } } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/openapiSpec/diff/added/0" should equal "GET /orders"
    And the JSON pointer "/data/openapiSpec/diff/wildcardGains/0/pattern" should equal "rest:billing:GET *"

  Scenario: A draft that drops x-iam-sensitive from an active operation is listed as a flag downgrade over REST and GraphQL
    Given a caller authenticated with a valid service token
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "billing", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Billing\",\"version\":\"1\"},\"paths\":{\"/invoices\":{\"get\":{\"operationId\":\"listInvoices\"}},\"/invoices/{invoiceId}/pay\":{\"post\":{\"operationId\":\"payInvoice\",\"x-iam-sensitive\":true}}}}"}
      """
    Then the response status code should be 201
    Given the remembered OpenAPI specification is active
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "billing", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Billing\",\"version\":\"1\"},\"paths\":{\"/invoices\":{\"get\":{\"operationId\":\"listInvoices\"}},\"/invoices/{invoiceId}/pay\":{\"post\":{\"operationId\":\"payInvoice\"}}}}"}
      """
    Then the response status code should be 201
    When GET request is sent to "/api/openapi-specs/{id}/diff"
    Then the response status code should be 200
    And the JSON array at "/flagDowngrades" should have 1 items
    And the JSON pointer "/flagDowngrades/0/operation" should equal "POST /invoices/{}/pay"
    And the response body should contain '"before":{"sensitive":true,"auditAlways":false}'
    And the response body should contain '"after":{"sensitive":false,"auditAlways":false}'
    When the GraphQL operation is sent:
      """
      { openapiSpec(id: "{id}") { diff { flagDowngrades { operation before { sensitive auditAlways } after { sensitive auditAlways } } } } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/openapiSpec/diff/flagDowngrades/0/operation" should equal "POST /invoices/{}/pay"
    And the response body should contain '"before":{"sensitive":true,"auditAlways":false}'

  Scenario: An unknown version is a 404 over REST and null over GraphQL
    Given a caller authenticated with a valid service token
    When GET request is sent to "/api/openapi-specs/0190f2a8-7b3c-7d4e-8f10-1234567890ad"
    Then the response status code should be 404
    When GET request is sent to "/api/openapi-specs/0190f2a8-7b3c-7d4e-8f10-1234567890ad/diff"
    Then the response status code should be 404
    When GET request is sent to "/api/openapi-specs/not-a-uuid"
    Then the response status code should be 422
    When the GraphQL operation is sent:
      """
      { openapiSpec(id: "0190f2a8-7b3c-7d4e-8f10-1234567890ad") { id } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/openapiSpec" should be null

  Scenario: The reads need a valid token
    When GET request is sent to "/api/openapi-specs"
    Then the response status code should be 401
    When GET request is sent to "/api/openapi-specs/0190f2a8-7b3c-7d4e-8f10-1234567890ad"
    Then the response status code should be 401
    When GET request is sent to "/api/openapi-specs/0190f2a8-7b3c-7d4e-8f10-1234567890ad/diff"
    Then the response status code should be 401
