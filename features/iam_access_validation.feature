Feature: IAM access validation
  In order to enforce access centrally where the route check of the gateway is not enough
  As a microservice
  I want to ask IAM whether a subject may perform a REST operation, run a GraphQL document or hold permission keys

  Scenario Outline: A check is decided the same way over REST and GraphQL
    Given a caller authenticated with a valid service token
    And an assignable role "Invoice reader" that grants "rest:billing:GET /invoices/{}"
    And a subject token of a user in session "e2e-validate-1"
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "billing", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Billing\",\"version\":\"1\"},\"paths\":{\"/invoices/{invoiceId}\":{\"get\":{}},\"/refunds\":{\"post\":{}}}}"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/openapi-specs/{id}/permissions" with body:
      """
      {}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/access-validations" with body:
      """
      {"credential": "{token}", "service": "<service>", "rest": {"method": "<method>", "path": "<path>"}, "requestId": "req-<name>"}
      """
    And the GraphQL operation is sent:
      """
      { validateAccess(input: {credential: "{token}", service: "<service>", rest: {method: "<method>", path: "<path>"}, requestId: "req-<name>"}) { decision reason denied scopes { all projects } subject { id kind } decisionId policyVersion requestId } }
      """
    Then the response status code should be 200
    And the GraphQL response should have no errors
    And the REST and GraphQL access validations should be the same
    And both access validations should echo the request id "req-<name>"
    And both access validations should <outcome>
    And no response should contain the subject token

    Examples:
      | name       | service  | method | path              | outcome                                                  |
      | allowed    | billing  | GET    | /invoices/42      | be an allow for every project                            |
      | missing    | billing  | POST   | /refunds          | be a deny with reason "permission_missing"               |
      | unknown    | billing  | GET    | /unknown          | be a deny with reason "unknown_operation"                |
      | malformed  | billing  | GET    | /invoices/../42   | be a deny with reason "malformed_operation"              |
      | service    | shipping | GET    | /parcels          | be a deny with reason "unknown_service"                  |

  Scenario Outline: A refused token is a deny with its reason over REST and GraphQL
    Given a caller authenticated with a valid service token
    And <subject token>
    When POST request is sent to "/api/access-validations" with body:
      """
      {"credential": "{token}", "service": "billing", "permissions": ["rest:billing:GET /invoices"], "requestId": "req-token"}
      """
    And the GraphQL operation is sent:
      """
      { validateAccess(input: {credential: "{token}", service: "billing", permissions: ["rest:billing:GET /invoices"], requestId: "req-token"}) { decision reason denied scopes { all projects } subject { id kind } decisionId policyVersion requestId } }
      """
    Then the response status code should be 200
    And the GraphQL response should have no errors
    And the REST and GraphQL access validations should be the same
    And both access validations should be a deny with reason "<reason>"

    Examples:
      | subject token                                                  | reason        |
      | an expired subject token of a user in session "e2e-validate-2" | token_expired |
      | a subject token signed by an unknown key                       | token_invalid |
      | an empty subject token                                         | token_missing |

  Scenario: A token of a revoked session is a deny with token_revoked over REST and GraphQL
    Given a caller authenticated with a valid service token
    And a subject token of a user in session "e2e-validate-3"
    And the session "e2e-validate-3" is revoked
    When POST request is sent to "/api/access-validations" with body:
      """
      {"credential": "{token}", "service": "billing", "permissions": ["rest:billing:GET /invoices"], "requestId": "req-revoked"}
      """
    And the GraphQL operation is sent:
      """
      { validateAccess(input: {credential: "{token}", service: "billing", permissions: ["rest:billing:GET /invoices"], requestId: "req-revoked"}) { decision reason denied scopes { all projects } subject { id kind } decisionId policyVersion requestId } }
      """
    Then the response status code should be 200
    And the REST and GraphQL access validations should be the same
    And both access validations should be a deny with reason "token_revoked"
    And no response should contain the subject token

  Scenario: Permission keys are decided by project scope over REST and GraphQL
    Given a caller authenticated with a valid service token
    And an assignable role "Invoice reader" that grants "rest:billing:GET /invoices"
    And a subject token of a user in session "e2e-validate-4"
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "billing", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Billing\",\"version\":\"1\"},\"paths\":{\"/invoices\":{\"get\":{}}}}"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/openapi-specs/{id}/permissions" with body:
      """
      {}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "project", "projectId": "0190f2a8-7b3c-7d4e-8f10-1234567890cd"}}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/access-validations" with body:
      """
      {"credential": "{token}", "service": "billing", "permissions": ["rest:billing:GET /invoices"], "projectId": "0190f2a8-7b3c-7d4e-8f10-1234567890cd", "requestId": "req-in"}
      """
    And the GraphQL operation is sent:
      """
      { validateAccess(input: {credential: "{token}", service: "billing", permissions: ["rest:billing:GET /invoices"], projectId: "0190f2a8-7b3c-7d4e-8f10-1234567890cd", requestId: "req-in"}) { decision reason denied scopes { all projects } subject { id kind } decisionId policyVersion requestId } }
      """
    Then the REST and GraphQL access validations should be the same
    And both access validations should be an allow in the projects "0190f2a8-7b3c-7d4e-8f10-1234567890cd"
    When POST request is sent to "/api/access-validations" with body:
      """
      {"credential": "{token}", "service": "billing", "permissions": ["rest:billing:GET /invoices"], "requestId": "req-all-projects"}
      """
    And the GraphQL operation is sent:
      """
      { validateAccess(input: {credential: "{token}", service: "billing", permissions: ["rest:billing:GET /invoices"], requestId: "req-all-projects"}) { decision reason denied scopes { all projects } subject { id kind } decisionId policyVersion requestId } }
      """
    Then the REST and GraphQL access validations should be the same
    And both access validations should be an allow in the projects "0190f2a8-7b3c-7d4e-8f10-1234567890cd"
    When POST request is sent to "/api/access-validations" with body:
      """
      {"credential": "{token}", "service": "billing", "permissions": ["rest:billing:GET /invoices"], "projectId": "0190f2a8-7b3c-7d4e-8f10-1234567890ce", "requestId": "req-other"}
      """
    And the GraphQL operation is sent:
      """
      { validateAccess(input: {credential: "{token}", service: "billing", permissions: ["rest:billing:GET /invoices"], projectId: "0190f2a8-7b3c-7d4e-8f10-1234567890ce", requestId: "req-other"}) { decision reason denied scopes { all projects } subject { id kind } decisionId policyVersion requestId } }
      """
    Then the REST and GraphQL access validations should be the same
    And both access validations should be a deny with reason "scope_missing"
    And both access validations should deny "rest:billing:GET /invoices"

  Scenario: An unknown key and a key of another service are denied as unknown operations over REST and GraphQL
    Given a caller authenticated with a valid service token
    And a subject token of a user in session "e2e-validate-5"
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "billing", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Billing\",\"version\":\"1\"},\"paths\":{\"/invoices\":{\"get\":{}}}}"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/openapi-specs/{id}/permissions" with body:
      """
      {}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/access-validations" with body:
      """
      {"credential": "{token}", "service": "billing", "permissions": ["rest:billing:GET /nothing"], "requestId": "req-key"}
      """
    And the GraphQL operation is sent:
      """
      { validateAccess(input: {credential: "{token}", service: "billing", permissions: ["rest:billing:GET /nothing"], requestId: "req-key"}) { decision reason denied scopes { all projects } subject { id kind } decisionId policyVersion requestId } }
      """
    Then the REST and GraphQL access validations should be the same
    And both access validations should be a deny with reason "unknown_operation"
    And both access validations should deny "rest:billing:GET /nothing"

  Scenario: A revoked assignment is denied at once over REST and GraphQL
    Given a caller authenticated with a valid service token
    And an assignable role "Invoice reader" that grants "rest:billing:GET /invoices"
    And a subject token of a user in session "e2e-validate-6"
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "billing", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Billing\",\"version\":\"1\"},\"paths\":{\"/invoices\":{\"get\":{}}}}"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/openapi-specs/{id}/permissions" with body:
      """
      {}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/access-validations" with body:
      """
      {"credential": "{token}", "service": "billing", "rest": {"method": "GET", "path": "/invoices"}, "requestId": "req-before"}
      """
    Then the JSON pointer "/decision" should equal "allow"
    Given the If-Match header '"1"'
    When DELETE request is sent to "/api/user-roles/{id}"
    Then the response status code should be 204
    When POST request is sent to "/api/access-validations" with body:
      """
      {"credential": "{token}", "service": "billing", "rest": {"method": "GET", "path": "/invoices"}, "requestId": "req-after"}
      """
    And the GraphQL operation is sent:
      """
      { validateAccess(input: {credential: "{token}", service: "billing", rest: {method: "GET", path: "/invoices"}, requestId: "req-after"}) { decision reason denied scopes { all projects } subject { id kind } decisionId policyVersion requestId } }
      """
    Then the REST and GraphQL access validations should be the same
    And both access validations should be a deny with reason "permission_missing"

  Scenario: A deleted role is denied at once over REST and GraphQL
    Given a caller authenticated with a valid service token
    And an assignable role "Invoice reader" that grants "rest:billing:GET /invoices"
    And a subject token of a user in session "e2e-validate-7"
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "billing", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Billing\",\"version\":\"1\"},\"paths\":{\"/invoices\":{\"get\":{}}}}"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/openapi-specs/{id}/permissions" with body:
      """
      {}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 201
    Given the If-Match header '"1"'
    When DELETE request is sent to "/api/roles/{role}"
    Then the response status code should be 200
    When POST request is sent to "/api/access-validations" with body:
      """
      {"credential": "{token}", "service": "billing", "rest": {"method": "GET", "path": "/invoices"}, "requestId": "req-deleted"}
      """
    And the GraphQL operation is sent:
      """
      { validateAccess(input: {credential: "{token}", service: "billing", rest: {method: "GET", path: "/invoices"}, requestId: "req-deleted"}) { decision reason denied scopes { all projects } subject { id kind } decisionId policyVersion requestId } }
      """
    Then the REST and GraphQL access validations should be the same
    And both access validations should be a deny with reason "permission_missing"

  Scenario: A request with no target form or two target forms is refused over REST and GraphQL
    Given a caller authenticated with a valid service token
    And a subject token of a user in session "e2e-validate-8"
    When POST request is sent to "/api/access-validations" with body:
      """
      {"credential": "{token}", "service": "billing", "requestId": "req-none"}
      """
    Then the response status code should be 422
    And the response header "content-type" should contain "application/problem+json"
    When the GraphQL operation is sent:
      """
      { validateAccess(input: {credential: "{token}", service: "billing", requestId: "req-none"}) { decision } }
      """
    Then the GraphQL error code should be "VALIDATION_FAILED"
    When POST request is sent to "/api/access-validations" with body:
      """
      {"credential": "{token}", "service": "billing", "rest": {"method": "GET", "path": "/invoices"}, "permissions": ["rest:billing:GET /invoices"], "requestId": "req-two"}
      """
    Then the response status code should be 422
    When the GraphQL operation is sent:
      """
      { validateAccess(input: {credential: "{token}", service: "billing", rest: {method: "GET", path: "/invoices"}, permissions: ["rest:billing:GET /invoices"], requestId: "req-two"}) { decision } }
      """
    Then the GraphQL error code should be "VALIDATION_FAILED"
    And no response should contain the subject token

  Scenario: More than 100 permission keys are refused over REST and GraphQL
    Given a caller authenticated with a valid service token
    And a subject token of a user in session "e2e-validate-9"
    When a check of 101 permission keys is sent over REST and GraphQL
    Then the response status code should be 200
    And the REST status of the check should be 422
    And the GraphQL error code should be "VALIDATION_FAILED"
    When a check of 100 permission keys is sent over REST and GraphQL
    Then the REST status of the check should be 200
    And the GraphQL response should have no errors

  Scenario: A minimum policy version above the current one is refused over REST and GraphQL
    Given a caller authenticated with a valid service token
    And a subject token of a user in session "e2e-validate-10"
    When POST request is sent to "/api/access-validations" with body:
      """
      {"credential": "{token}", "service": "billing", "permissions": ["rest:billing:GET /invoices"], "minPolicyVersion": 999999, "requestId": "req-version"}
      """
    Then the response status code should be 422
    And the response body should contain "minPolicyVersion"
    When the GraphQL operation is sent:
      """
      { validateAccess(input: {credential: "{token}", service: "billing", permissions: ["rest:billing:GET /invoices"], minPolicyVersion: 999999, requestId: "req-version"}) { decision } }
      """
    Then the GraphQL error code should be "VALIDATION_FAILED"
    And no response should contain the subject token

  Scenario: A request without a bearer token is unauthenticated over REST and GraphQL
    Given a subject token of a user in session "e2e-validate-11"
    When POST request is sent to "/api/access-validations" with body:
      """
      {"credential": "{token}", "service": "billing", "permissions": ["rest:billing:GET /invoices"], "requestId": "req-anonymous"}
      """
    Then the response status code should be 401
    And the response should challenge with the Bearer scheme
    When the GraphQL operation is sent:
      """
      { validateAccess(input: {credential: "{token}", service: "billing", permissions: ["rest:billing:GET /invoices"], requestId: "req-anonymous"}) { decision } }
      """
    Then the GraphQL error code should be "UNAUTHENTICATED"
    And no response should contain the subject token

  Scenario: A document is denied as a whole when one coordinate is missing, listing every denied coordinate, over REST and GraphQL
    Given a caller authenticated with a valid service token
    And an assignable role "Invoice reader" that grants "gql:billing:Query.invoice"
    And a subject token of a user in session "e2e-validate-12"
    When POST request is sent to "/api/graphql-specs" with body:
      """
      {"service": "billing", "sdl": "type Query {\n  invoice: Invoice\n}\n\ntype Invoice {\n  id: ID!\n  total: Int!\n}\n"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/graphql-specs/{id}/permissions" with body:
      """
      {}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/access-validations" with body:
      """
      {"credential": "{token}", "service": "billing", "graphql": {"document": "{ invoice { id total } }"}, "requestId": "req-partial"}
      """
    And the GraphQL operation is sent:
      """
      { validateAccess(input: {credential: "{token}", service: "billing", graphql: {document: "{ invoice { id total } }"}, requestId: "req-partial"}) { decision reason denied scopes { all projects } subject { id kind } decisionId policyVersion requestId } }
      """
    Then the response status code should be 200
    And the GraphQL response should have no errors
    And the REST and GraphQL access validations should be the same
    And both access validations should be a deny with reason "permission_missing"
    And both access validations should deny the keys "gql:billing:Invoice.id, gql:billing:Invoice.total"
    And no response should contain the subject token

  Scenario: A document is allowed when the subject holds every coordinate it selects over REST and GraphQL
    Given a caller authenticated with a valid service token
    And an assignable role "Invoice reader" that grants "gql:billing:Query.invoice, gql:billing:Invoice.id, gql:billing:Invoice.total"
    And a subject token of a user in session "e2e-validate-13"
    When POST request is sent to "/api/graphql-specs" with body:
      """
      {"service": "billing", "sdl": "type Query {\n  invoice: Invoice\n}\n\ntype Invoice {\n  id: ID!\n  total: Int!\n}\n"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/graphql-specs/{id}/permissions" with body:
      """
      {}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/access-validations" with body:
      """
      {"credential": "{token}", "service": "billing", "graphql": {"document": "{ invoice { id total } }"}, "requestId": "req-whole"}
      """
    And the GraphQL operation is sent:
      """
      { validateAccess(input: {credential: "{token}", service: "billing", graphql: {document: "{ invoice { id total } }"}, requestId: "req-whole"}) { decision reason denied scopes { all projects } subject { id kind } decisionId policyVersion requestId } }
      """
    Then the response status code should be 200
    And the GraphQL response should have no errors
    And the REST and GraphQL access validations should be the same
    And both access validations should be an allow for every project
    And no response should contain the subject token

  Scenario: A document over a limit is a deny with limits_exceeded over REST and GraphQL
    Given a caller authenticated with a valid service token
    And a subject token of a user in session "e2e-validate-14"
    When POST request is sent to "/api/graphql-specs" with body:
      """
      {"service": "billing", "sdl": "type Query {\n  invoice: Invoice\n}\n\ntype Invoice {\n  id: ID!\n  total: Int!\n}\n"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/graphql-specs/{id}/permissions" with body:
      """
      {}
      """
    Then the response status code should be 201
    When a check of a GraphQL document of 51 aliases is sent over REST and GraphQL
    Then the response status code should be 200
    And the GraphQL response should have no errors
    And the REST and GraphQL access validations should be the same
    And both access validations should be a deny with reason "limits_exceeded"
    When a check of a GraphQL document of 50 aliases is sent over REST and GraphQL
    Then the REST and GraphQL access validations should be the same
    And both access validations should be a deny with reason "permission_missing"

  Scenario: A newly activated GraphQL version is evaluated at once over REST and GraphQL
    Given a caller authenticated with a valid service token
    And a subject token of a user in session "e2e-validate-15"
    When POST request is sent to "/api/graphql-specs" with body:
      """
      {"service": "billing", "sdl": "type Query {\n  invoice: Invoice\n}\n\ntype Invoice {\n  id: ID!\n  total: Int!\n}\n"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/graphql-specs/{id}/permissions" with body:
      """
      {}
      """
    Then the response status code should be 201
    # The role is seeded once the first version is active: activating a version that lacks a key
    # a role already grants would orphan that grant.
    Given an assignable role "Invoice reader" that grants "gql:billing:Query.invoice, gql:billing:Invoice.id, gql:billing:Invoice.refunded"
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/access-validations" with body:
      """
      {"credential": "{token}", "service": "billing", "graphql": {"document": "{ invoice { id refunded } }"}, "requestId": "req-before-version"}
      """
    And the GraphQL operation is sent:
      """
      { validateAccess(input: {credential: "{token}", service: "billing", graphql: {document: "{ invoice { id refunded } }"}, requestId: "req-before-version"}) { decision reason denied scopes { all projects } subject { id kind } decisionId policyVersion requestId } }
      """
    Then the REST and GraphQL access validations should be the same
    And both access validations should be a deny with reason "unknown_operation"
    When POST request is sent to "/api/graphql-specs" with body:
      """
      {"service": "billing", "sdl": "type Query {\n  invoice: Invoice\n}\n\ntype Invoice {\n  id: ID!\n  total: Int!\n  refunded: Boolean!\n}\n"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/graphql-specs/{id}/permissions" with body:
      """
      {}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/access-validations" with body:
      """
      {"credential": "{token}", "service": "billing", "graphql": {"document": "{ invoice { id refunded } }"}, "requestId": "req-after-version"}
      """
    And the GraphQL operation is sent:
      """
      { validateAccess(input: {credential: "{token}", service: "billing", graphql: {document: "{ invoice { id refunded } }"}, requestId: "req-after-version"}) { decision reason denied scopes { all projects } subject { id kind } decisionId policyVersion requestId } }
      """
    Then the REST and GraphQL access validations should be the same
    And both access validations should be an allow for every project

  Scenario: A batch of mixed checks is decided in request order over REST and GraphQL
    Given a caller authenticated with a valid service token
    And an assignable role "Invoice reader" that grants "rest:billing:GET /invoices/{}"
    And a subject token of a user in session "e2e-validate-16"
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "billing", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Billing\",\"version\":\"1\"},\"paths\":{\"/invoices/{invoiceId}\":{\"get\":{}},\"/refunds\":{\"post\":{}}}}"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/openapi-specs/{id}/permissions" with body:
      """
      {}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 201
    When a batch of mixed checks is sent over REST and GraphQL
    Then the REST status of the check should be 200
    And the GraphQL response should have no errors
    And both batches should have 7 results
    And the REST and GraphQL batch results should be the same and have the reasons "allowed, permission_missing, unknown_operation, malformed_operation, malformed_operation, token_invalid, unknown_service"
    And no response should contain the subject token

  Scenario Outline: A batch of no check or of too many is refused over REST and GraphQL
    Given a caller authenticated with a valid service token
    And a subject token of a user in session "e2e-validate-17"
    When a batch of <count> checks is sent over REST and GraphQL
    Then the REST status of the check should be 422
    And the GraphQL batch should fail with the code "VALIDATION_FAILED"

    Examples:
      | count |
      | 0     |
      | 101   |

  Scenario: A batch of one hundred checks over two credentials is decided in request order
    Given a caller authenticated with a valid service token
    And an assignable role "Invoice reader" that grants "rest:billing:GET /invoices/{}"
    And a subject token of a user in session "e2e-validate-18"
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "billing", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Billing\",\"version\":\"1\"},\"paths\":{\"/invoices/{invoiceId}\":{\"get\":{}}}}"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/openapi-specs/{id}/permissions" with body:
      """
      {}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 201
    When a batch of 100 checks that alternate between the subject token and an invalid one is sent over REST and GraphQL
    Then the REST status of the check should be 200
    And both batches should have 100 results
    And the REST and GraphQL batch results should be the same and alternate "allowed" and "token_invalid"

  Scenario: The access-validation operation is documented with its security requirement
    When GET request is sent to "/api/docs/openapi.json"
    Then the response status code should be 200
    And the response body should contain "api_access_validations_post"
    And the response body should contain "api_access_validations_batch_post"
    And the response body should contain "bearerAuth"
