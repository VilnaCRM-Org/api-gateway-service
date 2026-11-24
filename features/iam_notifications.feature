Feature: IAM change events and notification events on the events topic
  In order to alert users and security staff without polling IAM
  As Notification service and other consumers of IAM events
  I want every IAM change event, with the documented fields, on the topic iam.events.v1

  Scenario: An assignment, a revocation and a role deletion publish their events keyed by the aggregate id
    Given a caller authenticated as the bootstrapped administrator
    And an assignable role "Billing administrator"
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "service", "id": "billing-worker"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 201
    Given the If-Match header '"1"'
    When DELETE request is sent to "/api/user-roles/{id}"
    Then the response status code should be 204
    When DELETE request is sent to "/api/roles/{role}"
    Then the response status code should be 200
    And the events topic of the scenario should hold 2 "iam.user_role.assigned" events
    And the events topic of the scenario should hold 2 "iam.user_role.revoked" events
    And the events topic of the scenario should hold 1 "iam.role.deleted" event
    And every "iam.user_role.assigned" event on the events topic should be keyed by its aggregate id
    And every "iam.user_role.revoked" event on the events topic should be keyed by its aggregate id
    And every envelope on the events topic should be at most 64 KiB

  Scenario: An assignment to a user publishes the subject, the user, the role, its name, the scope and the actor
    Given a caller authenticated as the bootstrapped administrator
    And an assignable role "Billing administrator"
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 201
    And the events topic of the scenario should hold 1 "iam.user_role.assigned" event
    And the "iam.user_role.assigned" event on the events topic should have "/data/subject/kind" equal to "user"
    And the "iam.user_role.assigned" event on the events topic should have "/data/subject/id" equal to "0190f2a8-7b3c-7d4e-8f10-1234567890ab"
    And the "iam.user_role.assigned" event on the events topic should have "/data/userId" equal to "0190f2a8-7b3c-7d4e-8f10-1234567890ab"
    And the "iam.user_role.assigned" event on the events topic should have "/data/roleId" equal to "{role}"
    And the "iam.user_role.assigned" event on the events topic should have "/data/roleName" equal to "Billing administrator"
    And the "iam.user_role.assigned" event on the events topic should have "/data/scope" equal to "global"
    And the "iam.user_role.assigned" event on the events topic should have "/data/actor" present
    And the "iam.user_role.assigned" event on the events topic should have "/data/policyVersion" present
    And the events topic of the scenario should hold 0 "iam.privileged_role.assigned" events

  Scenario: A revocation publishes the subject, the user, the role, its name, the scope and the actor
    Given a caller authenticated as the bootstrapped administrator
    And an assignable role "Billing administrator"
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "project", "projectId": "0190f2a8-7b3c-7d4e-8f10-1234567890cd"}}
      """
    Then the response status code should be 201
    Given the If-Match header is the ETag of the last response
    When DELETE request is sent to "/api/user-roles/{id}"
    Then the response status code should be 204
    And the events topic of the scenario should hold 1 "iam.user_role.revoked" event
    And the "iam.user_role.revoked" event on the events topic should have "/data/subject/kind" equal to "user"
    And the "iam.user_role.revoked" event on the events topic should have "/data/userId" equal to "0190f2a8-7b3c-7d4e-8f10-1234567890ab"
    And the "iam.user_role.revoked" event on the events topic should have "/data/roleId" equal to "{role}"
    And the "iam.user_role.revoked" event on the events topic should have "/data/roleName" equal to "Billing administrator"
    And the "iam.user_role.revoked" event on the events topic should have "/data/scope" equal to "project:0190f2a8-7b3c-7d4e-8f10-1234567890cd"
    And the "iam.user_role.revoked" event on the events topic should have "/data/actor" present
    And the "iam.user_role.revoked" event on the events topic should have "/data/cause" present

  Scenario: A scenario reads only the events of its own database
    Given a caller authenticated as the bootstrapped administrator
    And an assignable role "Billing administrator"
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 201
    And the events topic of the scenario should hold 1 "iam.user_role.assigned" event
    And the "iam.user_role.assigned" event on the events topic should have "/data/userRoleId" equal to "{id}"
    And the "iam.user_role.assigned" event on the events topic should have "/data/roleId" equal to "{role}"

  Scenario: Assigning a role that grants a wildcard publishes the privileged alert with its keys
    Given a caller authenticated as the bootstrapped administrator
    And an assignable role "Operator" that grants "iam:audit:read, rest:billing:*, rest:billing:GET /invoices"
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 201
    And the events topic of the scenario should hold 1 "iam.user_role.assigned" event
    And the events topic of the scenario should hold 1 "iam.privileged_role.assigned" event
    And the "iam.privileged_role.assigned" event on the events topic should have "/data/privilegedKeys" listing "rest:billing:*"
    And the "iam.privileged_role.assigned" event on the events topic should have "/data/privilegedKeys" listing "iam:audit:read"
    And the "iam.privileged_role.assigned" event on the events topic should have "/data/roleId" equal to "{role}"
    And the "iam.privileged_role.assigned" event on the events topic should have "/data/roleName" equal to "Operator"
    And the "iam.privileged_role.assigned" event on the events topic should have "/data/userId" equal to "0190f2a8-7b3c-7d4e-8f10-1234567890ab"
    And every "iam.privileged_role.assigned" event on the events topic should be keyed by its aggregate id

  Scenario: An activation that orphans grants publishes the orphaned keys and the affected roles
    Given a caller authenticated as the bootstrapped administrator
    And an assignable role "Payer" that grants "rest:billing:POST /invoices/{}/pay"
    When POST request is sent to "/api/openapi-specs" with body:
      """
      {"service": "billing", "document": "{\"openapi\":\"3.1.0\",\"info\":{\"title\":\"Billing\",\"version\":\"1\"},\"paths\":{\"/invoices\":{\"get\":{}}}}"}
      """
    Then the response status code should be 201
    When POST request is sent to "/api/openapi-specs/{id}/permissions" with body:
      """
      {"confirmOrphans": true}
      """
    Then the response status code should be 201
    And the events topic of the scenario should hold 1 "iam.permissions.orphaned" event
    And the "iam.permissions.orphaned" event on the events topic should have "/data/service" equal to "billing"
    And the "iam.permissions.orphaned" event on the events topic should have "/data/specId" present
    And the "iam.permissions.orphaned" event on the events topic should have "/data/orphanedKeys" listing "rest:billing:POST /invoices/{}/pay"
    And the "iam.permissions.orphaned" event on the events topic should have "/data/affectedRoleIds" listing "{role}"
    And every "iam.permissions.orphaned" event on the events topic should be keyed by its aggregate id

  Scenario: A retirement that orphans grants publishes the orphaned keys and the affected roles
    Given a caller authenticated as the bootstrapped administrator
    And an assignable role "Payer"
    And the If-Match header '"1"'
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
    When PUT request is sent to "/api/roles/{role}/permissions" with body:
      """
      {"keys": ["gql:billing:Query.invoices"]}
      """
    Then the response status code should be 200
    When POST request is sent to "/api/graphql-specs/{id}/retirement" with body:
      """
      {"confirmOrphans": true}
      """
    Then the response status code should be 200
    And the events topic of the scenario should hold 1 "iam.permissions.orphaned" event
    And the "iam.permissions.orphaned" event on the events topic should have "/data/service" equal to "billing"
    And the "iam.permissions.orphaned" event on the events topic should have "/data/specId" present
    And the "iam.permissions.orphaned" event on the events topic should have "/data/orphanedKeys" listing "gql:billing:Query.invoices"
    And the "iam.permissions.orphaned" event on the events topic should have "/data/affectedRoleIds" listing "{role}"

  Scenario: IAM produces only to the state topic and the events topic and never flushes an authorization cache
    Given a caller authenticated as the bootstrapped administrator
    And an assignable role "Billing administrator"
    When POST request is sent to "/api/user-roles" with body:
      """
      {"subject": {"kind": "user", "id": "0190f2a8-7b3c-7d4e-8f10-1234567890ab"}, "roleId": "{role}", "scope": {"kind": "global"}}
      """
    Then the response status code should be 201
    And IAM should have produced only to the state topic and the events topic of the scenario
    And the events topic of the scenario should hold 0 "iam.authorization_cache.flushed" events
