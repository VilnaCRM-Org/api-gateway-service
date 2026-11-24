Feature: IAM permission catalogue
  In order to find the keys to grant and see who holds them
  As an administrator
  I want to browse the GraphQL and the REST permission catalogue over REST or GraphQL

  Scenario: An activated catalogue is listed with its keys, flags, versions and granting roles over REST and GraphQL
    Given a caller authenticated as the bootstrapped administrator
    And an assignable role "Payer" that grants "gql:billing:Mutation.pay"
    When POST request is sent to "/api/graphql-specs" with body:
      """
      {"service": "billing", "sdl": "type Query {\n  invoices: [String!]!\n}\n\ntype Mutation {\n  pay(id: ID!): String! @iamSensitive\n}\n"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/graphql-specs/{id}/permissions" with body:
      """
      {}
      """
    Then the response status code should be 201
    When GET request is sent to "/api/graphql-permissions?service=billing"
    Then the response status code should be 200
    And the JSON array at "/items" should have 3 items
    And the JSON pointer "/nextCursor" should be absent
    And the response body should contain "gql:billing:__introspection"
    And the response body should contain "gql:billing:Query.invoices"
    When GET request is sent to "/api/graphql-permissions?service=billing&type=Mutation"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON pointer "/items/0/id" should be present
    And the JSON pointer "/items/0/key" should equal "gql:billing:Mutation.pay"
    And the JSON pointer "/items/0/service" should equal "billing"
    And the JSON pointer "/items/0/type" should equal "Mutation"
    And the JSON pointer "/items/0/field" should equal "pay"
    And the response body should contain '"flags":{"sensitive":true,"auditAlways":false}'
    And the response body should contain '"active":true'
    And the response body should contain '"versions":["{id}"]'
    And the JSON array at "/items/0/roles" should have 1 items
    And the JSON pointer "/items/0/roles/0" should equal the seeded role
    When the GraphQL operation is sent:
      """
      { graphqlPermissions(filter: {service: "billing", type: "Mutation"}) { items { id key service type field flags { sensitive auditAlways } active versions roles } nextCursor } }
      """
    Then the response status code should be 200
    And the GraphQL response should have no errors
    And the JSON array at "/data/graphqlPermissions/items" should have 1 items
    And the JSON pointer "/data/graphqlPermissions/items/0/key" should equal "gql:billing:Mutation.pay"
    And the JSON pointer "/data/graphqlPermissions/items/0/service" should equal "billing"
    And the JSON pointer "/data/graphqlPermissions/items/0/type" should equal "Mutation"
    And the JSON pointer "/data/graphqlPermissions/items/0/field" should equal "pay"
    And the JSON pointer "/data/graphqlPermissions/items/0/roles/0" should equal the seeded role
    And the JSON pointer "/data/graphqlPermissions/nextCursor" should be null
    And the response body should contain '"versions":["{id}"]'

  Scenario: The list is filtered by service, type, active state, the sensitive flag and the key prefix over REST and GraphQL
    Given a caller authenticated as the bootstrapped administrator
    And the catalogue holds the inactive sensitive key "gql:shipping:Query.legacy"
    When POST request is sent to "/api/graphql-specs" with body:
      """
      {"service": "billing", "sdl": "type Query {\n  invoices: [String!]!\n}\n\ntype Mutation {\n  pay(id: ID!): String! @iamSensitive\n}\n"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/graphql-specs/{id}/permissions" with body:
      """
      {}
      """
    Then the response status code should be 201
    When GET request is sent to "/api/graphql-permissions?service=billing"
    Then the response status code should be 200
    And the JSON array at "/items" should have 3 items
    When GET request is sent to "/api/graphql-permissions?service=shipping"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON pointer "/items/0/key" should equal "gql:shipping:Query.legacy"
    And the response body should contain '"active":false'
    And the response body should contain '"versions":[]'
    And the response body should contain '"roles":[]'
    When GET request is sent to "/api/graphql-permissions?active=false"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON pointer "/items/0/key" should equal "gql:shipping:Query.legacy"
    When GET request is sent to "/api/graphql-permissions?service=billing&active=true&sensitive=true"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON pointer "/items/0/key" should equal "gql:billing:Mutation.pay"
    When GET request is sent to "/api/graphql-permissions?sensitive=false&service=billing"
    Then the response status code should be 200
    And the JSON array at "/items" should have 2 items
    When GET request is sent to "/api/graphql-permissions?keyPrefix=gql:billing:Query."
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON pointer "/items/0/key" should equal "gql:billing:Query.invoices"
    When GET request is sent to "/api/graphql-permissions?service=billing&type=Query&active=true&sensitive=false&keyPrefix=gql:billing:Query."
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    When GET request is sent to "/api/graphql-permissions?limit=1"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON pointer "/nextCursor" should be present
    When the GraphQL operation is sent:
      """
      { graphqlPermissions(filter: {active: false}) { items { key active } } }
      """
    Then the GraphQL response should have no errors
    And the JSON array at "/data/graphqlPermissions/items" should have 1 items
    And the JSON pointer "/data/graphqlPermissions/items/0/key" should equal "gql:shipping:Query.legacy"
    When the GraphQL operation is sent:
      """
      { graphqlPermissions(filter: {service: "billing", sensitive: true, keyPrefix: "gql:billing:Mutation."}) { items { key } } }
      """
    Then the GraphQL response should have no errors
    And the JSON array at "/data/graphqlPermissions/items" should have 1 items
    And the JSON pointer "/data/graphqlPermissions/items/0/key" should equal "gql:billing:Mutation.pay"
    When the GraphQL operation is sent:
      """
      { graphqlPermissions(first: 1) { items { key } nextCursor } }
      """
    Then the GraphQL response should have no errors
    And the JSON array at "/data/graphqlPermissions/items" should have 1 items
    And the JSON pointer "/data/graphqlPermissions/nextCursor" should be present

  Scenario: Two active versions are both listed on the entries they share
    Given a caller authenticated as the bootstrapped administrator
    When POST request is sent to "/api/graphql-specs" with body:
      """
      {"service": "billing", "sdl": "type Query {\n  invoices: [String!]!\n}\n"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/graphql-specs/{id}/permissions" with body:
      """
      {}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/graphql-specs" with body:
      """
      {"service": "billing", "sdl": "type Query {\n  invoices: [String!]!\n  orders: [String!]!\n}\n"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/graphql-specs/{id}/permissions" with body:
      """
      {}
      """
    Then the response status code should be 201
    When GET request is sent to "/api/graphql-permissions?keyPrefix=gql:billing:Query.invoices"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON array at "/items/0/versions" should have 2 items
    When GET request is sent to "/api/graphql-permissions?keyPrefix=gql:billing:Query.orders"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON array at "/items/0/versions" should have 1 items
    And the response body should contain '"versions":["{id}"]'
    When GET request is sent to "/api/graphql-permissions?keyPrefix=gql:billing:__introspection"
    Then the response status code should be 200
    And the JSON array at "/items/0/versions" should have 2 items

  Scenario: One permission is read by its identifier over REST and GraphQL
    Given a caller authenticated as the bootstrapped administrator
    When POST request is sent to "/api/graphql-specs" with body:
      """
      {"service": "billing", "sdl": "type Query {\n  invoices: [String!]!\n}\n"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/graphql-specs/{id}/permissions" with body:
      """
      {}
      """
    Then the response status code should be 201
    When GET request is sent to "/api/graphql-permissions?service=billing&limit=1"
    Then the response status code should be 200
    And the JSON pointer "/nextCursor" should be present
    When the cursor at "/nextCursor" is remembered
    And GET request is sent to "/api/graphql-permissions/{cursor}"
    Then the response status code should be 200
    And the JSON pointer "/id" should be present
    And the JSON pointer "/key" should be present
    And the JSON pointer "/service" should equal "billing"
    And the response body should contain '"active":true'
    And the response body should contain '"versions":["{id}"]'
    When the GraphQL operation is sent:
      """
      { graphqlPermission(id: "{cursor}") { id key service type field flags { sensitive auditAlways } active versions roles } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/graphqlPermission/id" should be present
    And the JSON pointer "/data/graphqlPermission/service" should equal "billing"
    And the response body should contain '"versions":["{id}"]'

  Scenario: An unknown permission is a 404 over REST and null over GraphQL
    Given a caller authenticated as the bootstrapped administrator
    When GET request is sent to "/api/graphql-permissions/0190f2a8-7b3c-7d4e-8f12-1234567890ad"
    Then the response status code should be 404
    When GET request is sent to "/api/graphql-permissions/not-a-uuid"
    Then the response status code should be 422
    When the GraphQL operation is sent:
      """
      { graphqlPermission(id: "0190f2a8-7b3c-7d4e-8f12-1234567890ad") { id } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/graphqlPermission" should be null

  Scenario: An invalid filter is a validation failure over REST and GraphQL
    Given a caller authenticated as the bootstrapped administrator
    When GET request is sent to "/api/graphql-permissions?limit=0"
    Then the response status code should be 422
    When GET request is sent to "/api/graphql-permissions?after=nope"
    Then the response status code should be 422
    When GET request is sent to "/api/graphql-permissions?type=1Bad"
    Then the response status code should be 422
    When the GraphQL operation is sent:
      """
      { graphqlPermissions(first: 0) { items { id } } }
      """
    Then the GraphQL error code should be "VALIDATION_FAILED"

  Scenario: The reads need a valid token
    When GET request is sent to "/api/graphql-permissions"
    Then the response status code should be 401
    When GET request is sent to "/api/graphql-permissions/0190f2a8-7b3c-7d4e-8f12-1234567890ad"
    Then the response status code should be 401

  Scenario: An activated REST catalogue is listed with its keys, flags, versions and granting roles over REST and GraphQL
    Given a caller authenticated as the bootstrapped administrator
    And an assignable role "Payer" that grants "rest:billing:POST /invoices/{}/pay"
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "billing", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Billing\",\"version\":\"1\"},\"paths\":{\"/invoices\":{\"get\":{}},\"/invoices/{invoiceId}/pay\":{\"post\":{\"x-iam-sensitive\":true}}}}"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/openapi-specs/{id}/permissions" with body:
      """
      {}
      """
    Then the response status code should be 201
    When GET request is sent to "/api/rest-permissions?service=billing"
    Then the response status code should be 200
    And the JSON array at "/items" should have 2 items
    And the JSON pointer "/nextCursor" should be absent
    And the response body should contain "rest:billing:GET /invoices"
    When GET request is sent to "/api/rest-permissions?service=billing&method=POST"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON pointer "/items/0/id" should be present
    And the JSON pointer "/items/0/key" should equal "rest:billing:POST /invoices/{}/pay"
    And the JSON pointer "/items/0/service" should equal "billing"
    And the JSON pointer "/items/0/method" should equal "POST"
    And the JSON pointer "/items/0/template" should equal "/invoices/{}/pay"
    And the response body should contain '"flags":{"sensitive":true,"auditAlways":false}'
    And the response body should contain '"active":true'
    And the response body should contain '"versions":["{id}"]'
    And the JSON array at "/items/0/roles" should have 1 items
    And the JSON pointer "/items/0/roles/0" should equal the seeded role
    When the GraphQL operation is sent:
      """
      { restPermissions(filter: {service: "billing", method: "POST"}) { items { id key service method template flags { sensitive auditAlways } active versions roles } nextCursor } }
      """
    Then the response status code should be 200
    And the GraphQL response should have no errors
    And the JSON array at "/data/restPermissions/items" should have 1 items
    And the JSON pointer "/data/restPermissions/items/0/key" should equal "rest:billing:POST /invoices/{}/pay"
    And the JSON pointer "/data/restPermissions/items/0/service" should equal "billing"
    And the JSON pointer "/data/restPermissions/items/0/method" should equal "POST"
    And the JSON pointer "/data/restPermissions/items/0/template" should equal "/invoices/{}/pay"
    And the JSON pointer "/data/restPermissions/items/0/roles/0" should equal the seeded role
    And the JSON pointer "/data/restPermissions/nextCursor" should be null
    And the response body should contain '"versions":["{id}"]'

  Scenario: The REST list is filtered by service, method, active state, the sensitive flag and the template prefix over REST and GraphQL
    Given a caller authenticated as the bootstrapped administrator
    And the catalogue holds the inactive sensitive REST key "rest:shipping:GET /legacy"
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "billing", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Billing\",\"version\":\"1\"},\"paths\":{\"/invoices\":{\"get\":{}},\"/invoices/{invoiceId}/pay\":{\"post\":{\"x-iam-sensitive\":true}}}}"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/openapi-specs/{id}/permissions" with body:
      """
      {}
      """
    Then the response status code should be 201
    When GET request is sent to "/api/rest-permissions?service=billing"
    Then the response status code should be 200
    And the JSON array at "/items" should have 2 items
    When GET request is sent to "/api/rest-permissions?service=shipping"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON pointer "/items/0/key" should equal "rest:shipping:GET /legacy"
    And the response body should contain '"active":false'
    And the response body should contain '"versions":[]'
    And the response body should contain '"roles":[]'
    When GET request is sent to "/api/rest-permissions?active=false"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON pointer "/items/0/key" should equal "rest:shipping:GET /legacy"
    When GET request is sent to "/api/rest-permissions?service=billing&active=true&sensitive=true"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON pointer "/items/0/key" should equal "rest:billing:POST /invoices/{}/pay"
    When GET request is sent to "/api/rest-permissions?service=billing&method=GET"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    When GET request is sent to "/api/rest-permissions?templatePrefix=/invoices"
    Then the response status code should be 200
    And the JSON array at "/items" should have 2 items
    When GET request is sent to "/api/rest-permissions?service=billing&method=GET&active=true&sensitive=false&templatePrefix=/invoices"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON pointer "/items/0/key" should equal "rest:billing:GET /invoices"
    When GET request is sent to "/api/rest-permissions?limit=1"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON pointer "/nextCursor" should be present
    When the GraphQL operation is sent:
      """
      { restPermissions(filter: {active: false}) { items { key active } } }
      """
    Then the GraphQL response should have no errors
    And the JSON array at "/data/restPermissions/items" should have 1 items
    And the JSON pointer "/data/restPermissions/items/0/key" should equal "rest:shipping:GET /legacy"
    When the GraphQL operation is sent:
      """
      { restPermissions(filter: {service: "billing", sensitive: true, templatePrefix: "/invoices"}) { items { key } } }
      """
    Then the GraphQL response should have no errors
    And the JSON array at "/data/restPermissions/items" should have 1 items
    And the JSON pointer "/data/restPermissions/items/0/key" should equal "rest:billing:POST /invoices/{}/pay"
    When the GraphQL operation is sent:
      """
      { restPermissions(first: 1) { items { key } nextCursor } }
      """
    Then the GraphQL response should have no errors
    And the JSON array at "/data/restPermissions/items" should have 1 items
    And the JSON pointer "/data/restPermissions/nextCursor" should be present

  Scenario: Two active versions are both listed on the REST entries they share
    Given a caller authenticated as the bootstrapped administrator
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
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "billing", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Billing\",\"version\":\"1\"},\"paths\":{\"/invoices\":{\"get\":{}},\"/orders\":{\"get\":{}}}}"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/openapi-specs/{id}/permissions" with body:
      """
      {}
      """
    Then the response status code should be 201
    When GET request is sent to "/api/rest-permissions?templatePrefix=/invoices"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON array at "/items/0/versions" should have 2 items
    When GET request is sent to "/api/rest-permissions?templatePrefix=/orders"
    Then the response status code should be 200
    And the JSON array at "/items" should have 1 items
    And the JSON array at "/items/0/versions" should have 1 items
    And the response body should contain '"versions":["{id}"]'

  Scenario: One REST permission is read by its identifier over REST and GraphQL
    Given a caller authenticated as the bootstrapped administrator
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
    When GET request is sent to "/api/rest-permissions?service=billing&limit=1"
    Then the response status code should be 200
    And the JSON pointer "/items/0/id" should be present
    When the cursor at "/items/0/id" is remembered
    And GET request is sent to "/api/rest-permissions/{cursor}"
    Then the response status code should be 200
    And the JSON pointer "/id" should be present
    And the JSON pointer "/key" should equal "rest:billing:GET /invoices"
    And the JSON pointer "/service" should equal "billing"
    And the response body should contain '"active":true'
    And the response body should contain '"versions":["{id}"]'
    When the GraphQL operation is sent:
      """
      { restPermission(id: "{cursor}") { id key service method template flags { sensitive auditAlways } active versions roles } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/restPermission/id" should be present
    And the JSON pointer "/data/restPermission/service" should equal "billing"
    And the JSON pointer "/data/restPermission/method" should equal "GET"
    And the response body should contain '"versions":["{id}"]'

  Scenario: An unknown REST permission is a 404 over REST and null over GraphQL
    Given a caller authenticated as the bootstrapped administrator
    When GET request is sent to "/api/rest-permissions/0190f2a8-7b3c-7d4e-8f12-1234567890ad"
    Then the response status code should be 404
    When GET request is sent to "/api/rest-permissions/not-a-uuid"
    Then the response status code should be 422
    When the GraphQL operation is sent:
      """
      { restPermission(id: "0190f2a8-7b3c-7d4e-8f12-1234567890ad") { id } }
      """
    Then the GraphQL response should have no errors
    And the JSON pointer "/data/restPermission" should be null

  Scenario: An invalid REST filter is a validation failure over REST and GraphQL
    Given a caller authenticated as the bootstrapped administrator
    When GET request is sent to "/api/rest-permissions?limit=0"
    Then the response status code should be 422
    When GET request is sent to "/api/rest-permissions?after=nope"
    Then the response status code should be 422
    When GET request is sent to "/api/rest-permissions?method=get"
    Then the response status code should be 422
    When the GraphQL operation is sent:
      """
      { restPermissions(first: 0) { items { id } } }
      """
    Then the GraphQL error code should be "VALIDATION_FAILED"

  Scenario: The REST permission reads need a valid token
    When GET request is sent to "/api/rest-permissions"
    Then the response status code should be 401
    When GET request is sent to "/api/rest-permissions/0190f2a8-7b3c-7d4e-8f12-1234567890ad"
    Then the response status code should be 401
