use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_graphql::Request;
use iam_application::http::IamState;
use iam_application::{Principal, ResolveSubjectTokenQuery, TokenResolution};
use iam_domain::{AccessToken, AccessTokenParts, SessionId, SubjectId, TokenId, TokenIdentity};
use shared_domain::{CommandBus, QueryBus, Uuid};
use test_support::bus::{FakeCommandBus, FakeQueryBus};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::request_digester::FakeRequestDigester;

use super::*;

const EXPECTED_SDL: &str = r#""The GraphQL document that a check names."
input AccessGraphQlTargetInput {
  "The document as the caller received it; IAM resolves every field it selects against the active GraphQL versions of the service. A document over a limit is decided as a deny with `limits_exceeded`."
  document: String!
  "The operation to check; optional when the document holds exactly one operation."
  operationName: String
}

"The REST request that a check names."
input AccessRestTargetInput {
  "The HTTP method, in upper case: `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE` or `OPTIONS`."
  method: String!
  "The path of the request as received; IAM normalises it and matches it against the operation templates of the active `OpenAPI` versions of the service."
  path: String!
}

"The projects in which an allow holds."
type AccessScopes {
  "Whether a global assignment holds every required key, so that the allow holds in every project."
  all: Boolean!
  "The projects that hold every required key when `all` is false; empty for a deny and for `all`."
  projects: [String!]!
}

"The subject that a decision was made for."
type AccessSubject {
  "The user id, or the service name of a service principal."
  id: String!
  "`user` or `service`."
  kind: String!
}

"The decision of an access check."
type AccessValidation {
  "`allow` or `deny`."
  decision: String!
  "The identifier of this decision."
  decisionId: ID!
  "The keys or coordinates that are denied; empty for an allow."
  denied: [String!]!
  "The policy version that the decision reflects; null when no policy was read."
  policyVersion: Int
  "`allowed`, `token_missing`, `token_invalid`, `token_expired`, `token_revoked`, `unknown_service`, `unknown_operation`, `malformed_operation`, `permission_missing`, `scope_missing`, `limits_exceeded` or `unavailable`."
  reason: String!
  "The request id of the caller, as sent."
  requestId: String!
  "The projects in which an allow holds; empty for a deny."
  scopes: AccessScopes!
  "The subject of the token; null when no token resolved."
  subject: AccessSubject
}

"Input of the route-configuration mutation."
input ApplyRouteConfigurationInput {
  "What the write waits for: `PUBLISHED` (the default) returns once Kafka acknowledged the policy version; `PROPAGATED` is refused with `VALIDATION_FAILED` until the gateway pods report their versions."
  consistency: String
  "Returns the diff and writes nothing; default `false`."
  dryRun: Boolean
  "The version of the set that the caller read (`routeConfiguration.version`); required, and the application is refused when it is not the current one."
  expectedVersion: Int
  "The lower-case DNS name of the host whose routes the set replaces."
  host: String!
  "The routes the host has afterwards, at most `ROUTE_CONFIGURATION_MAX_ROUTES` (1,000 by default); a stored route that the set does not declare is deleted."
  routes: [RouteDeclarationInput!]!
}

"The result of the route-configuration mutation."
type ApplyRouteConfigurationPayload {
  "The routes the set creates."
  added: [RouteConfigurationChange!]!
  "The routes the set updates."
  changed: [RouteConfigurationChange!]!
  "Whether the request was a dry run, which wrote nothing."
  dryRun: Boolean!
  "The host."
  host: String!
  "The policy version that the application produced; null for a dry run and for a set that changes nothing."
  policyVersion: Int
  "What the application learned about the publication of its policy version; null for a dry run and for a set that changes nothing."
  propagation: Propagation
  "The routes the set deletes."
  removed: [RouteConfigurationChange!]!
  "Whether the diff deletes a route, clears `anonymous` or moves `enforcement` from `audit` to `enforce`, which makes the application revocation-class."
  revocation: Boolean!
  "The number of routes the host has, or would have after a dry run."
  routeCount: Int!
  "The number of declared routes that equal a stored route."
  unchanged: Int!
  "The version of the set of the host: the version after an applied set, the stored version after a dry run or a set that changes nothing."
  version: Int!
}

"Input of the assignment mutation."
input AssignUserRoleInput {
  "What the write waits for: `PUBLISHED` (the default) returns once Kafka acknowledged the policy version; `PROPAGATED` is refused with `VALIDATION_FAILED` until the gateway pods report their versions."
  consistency: String
  "When the assignment expires, as an RFC 3339 UTC time in the future; null for an assignment that never expires."
  expiresAt: String
  "Makes the assignment safe to repeat for 24 hours: 1 to 255 visible ASCII characters."
  idempotencyKey: String
  "The role to assign; it must exist."
  roleId: String!
  "Where the role applies."
  scope: AssignmentScopeInput!
  "Who receives the role."
  subject: AssignmentSubjectInput!
}

"Where an assignment applies."
type AssignmentScope {
  "`global` or `project`."
  kind: String!
  "The project of a project scope; null for a global scope."
  projectId: String
}

"Where an assignment applies, as an input."
input AssignmentScopeInput {
  "`global` for every project, `project` for the project named by `projectId`."
  kind: String!
  "The project of a project scope; null for a global scope."
  projectId: String
}

"Who holds an assignment."
type AssignmentSubject {
  "The UUID of a user, or the service name of a service principal."
  id: String!
  "`user` or `service`."
  kind: String!
}

"Who receives a role, as an input."
input AssignmentSubjectInput {
  "The UUID of a user, or the service name of a service principal such as `billing-worker`."
  id: String!
  "`user` for a user of the User service, `service` for a service principal."
  kind: String!
}

"A bulk operation: a large change that the runner commits in chunks."
type BulkOperation {
  "How many records the committed chunks applied."
  appliedRecords: Int!
  "When the operation was recorded, as an RFC 3339 UTC time."
  createdAt: String!
  "Why the operation failed; null otherwise."
  error: String
  "The policy version of the first committed chunk; null before the first chunk."
  firstVersion: Int
  "The identifier."
  id: ID!
  "What the operation changes: `role_deletion`, `catalogue`, `resync` or `other`."
  kind: String!
  "The policy version of the last committed chunk; null before the first chunk."
  lastVersion: Int
  "The propagation of a revocation-class bulk operation; null until the chunks of such an operation are fenced by the pods' acknowledgements."
  propagation: BulkOperationPropagation
  "Who asked for the change."
  requester: String!
  "Where it stands: `pending`, `running`, `completed` or `failed`."
  status: String!
  "How many records the whole change touches."
  totalRecords: Int!
  "When the operation last changed, as an RFC 3339 UTC time."
  updatedAt: String!
}

"One page of bulk operations."
type BulkOperationPage {
  "The operations of the page, oldest first."
  items: [BulkOperation!]!
  "The `after` value of the next page; null on the last page."
  nextCursor: String
}

"""
How far the gateway pods have acknowledged the policy versions of a revocation-class bulk
operation.
"""
type BulkOperationPropagation {
  "How many gateway pods acknowledged the version."
  podsAcknowledged: Int!
  "How many gateway pods did not acknowledge it in time."
  podsTimedOut: Int!
  "The policy version the status is about."
  policyVersion: Int!
  "`pending`, `acknowledged` or `timed_out`."
  status: String!
}

"The two flags of a coordinate."
type CoordinateFlags {
  "Whether every use of the coordinate is audited (`@iamAuditAlways`)."
  auditAlways: Boolean!
  "Whether a wildcard grant never covers the coordinate (`@iamSensitive`)."
  sensitive: Boolean!
}

"Input of the create mutation."
input CreateExampleApiResourceInput {
  "Description."
  description: String!
  "Name."
  name: String!
}

"Input of the mutation that activates a GraphQL specification version."
input CreateGraphqlPermissionsInput {
  "Accepts that keys lose the sensitive or the always-audit flag; without it, an activation that would remove a flag fails with `FLAG_DOWNGRADE_CONFIRMATION_REQUIRED`."
  confirmFlagDowngrade: Boolean! = false
  "Accepts that grants of keys that leave the catalogue become inactive; without it, an activation that would orphan grants fails with `ORPHAN_CONFIRMATION_REQUIRED`."
  confirmOrphans: Boolean! = false
  "The version to activate."
  id: ID!
  "Makes the activation safe to repeat for 24 hours: 1 to 255 visible ASCII characters."
  idempotencyKey: String
  "The coordinates that the version renames; the grants of each old key move to its new key before anything is orphaned."
  renames: [KeyRenameInput!]! = []
}

"Input of the rate-policy creation mutation."
input CreateRatePolicyInput {
  "The number of requests allowed above the limit in a burst, from 0 to 4,294,967,295."
  burst: Int!
  "What the write waits for: `PUBLISHED` (the default) returns once Kafka acknowledged the policy version; `PROPAGATED` is refused with `VALIDATION_FAILED` until the gateway pods report their versions."
  consistency: String
  "What the limit becomes without the shared counter: `divided` or `full`."
  fallback: String!
  "Makes the creation safe to repeat for 24 hours: 1 to 255 visible ASCII characters."
  idempotencyKey: String
  "What requests are counted by: `ip`, `subject`, `subject_route` or `route`."
  key: String!
  "The number of requests allowed per period, from 1 to 4,294,967,295."
  limit: Int!
  "The name: 1 to 100 characters, unique among the rate policies that are not deleted."
  name: String!
  "The period in milliseconds: a multiple of 1,000, from 1,000 to 4,294,967,295,000."
  periodMs: Int!
}

"Input of the mutation that activates an `OpenAPI` specification version."
input CreateRestPermissionsInput {
  "Accepts that keys lose the sensitive or the always-audit flag; without it, an activation that would remove a flag fails with `FLAG_DOWNGRADE_CONFIRMATION_REQUIRED`."
  confirmFlagDowngrade: Boolean! = false
  "Accepts that grants of keys that leave the catalogue become inactive; without it, an activation that would orphan grants fails with `ORPHAN_CONFIRMATION_REQUIRED`."
  confirmOrphans: Boolean! = false
  "The version to activate."
  id: ID!
  "Makes the activation safe to repeat for 24 hours: 1 to 255 visible ASCII characters."
  idempotencyKey: String
  "The operations that the version renames; the grants of each old key move to its new key before anything is orphaned."
  renames: [KeyRenameInput!]! = []
}

"Input of the role-creation mutation."
input CreateRoleInput {
  "What the write waits for: `PUBLISHED` (the default) returns once Kafka acknowledged the policy version; `PROPAGATED` is refused with `VALIDATION_FAILED` until the gateway pods report their versions."
  consistency: String
  "What the role is for, at most 1,000 characters."
  description: String
  "Makes the creation safe to repeat for 24 hours: 1 to 255 visible ASCII characters."
  idempotencyKey: String
  "The name of the role: 1 to 100 characters, unique without regard to case among the roles that are not deleted."
  name: String!
}

"Input of the route-creation mutation."
input CreateRouteInput {
  "Whether the route is served without authentication; needs `iam:route:anonymous`; default `false`."
  anonymous: Boolean
  "The largest request body in bytes; default 1,048,576."
  bodyLimitBytes: Int
  "What the write waits for: `PUBLISHED` (the default) returns once Kafka acknowledged the policy version; `PROPAGATED` is refused with `VALIDATION_FAILED` until the gateway pods report their versions."
  consistency: String
  "The CORS policy of the route."
  cors: RouteCorsPolicyInput
  "The enforcement mode: `enforce` (the default) or `audit`, which needs `iam:route:anonymous`."
  enforcement: String
  "Whether the route serves GraphQL; default `false`."
  graphql: Boolean
  "The lower-case DNS name of the host the route serves."
  host: String!
  "Makes the creation safe to repeat for 24 hours: 1 to 255 visible ASCII characters."
  idempotencyKey: String
  "The idle timeout in milliseconds; default 60,000."
  idleTimeoutMs: Int
  "The methods the route serves, such as `GET`."
  methods: [String!]!
  "The path pattern, with `{name}` and `{name:*}` segments."
  pathPattern: String!
  "The rate policies of the route, in the order they apply, at most 10."
  ratePolicyIds: [ID!]
  "The request timeout in milliseconds; default 30,000."
  requestTimeoutMs: Int
  "Which failed requests are retried: `none` (the default) or `idempotent`."
  retryPolicy: String
  "The catalogue service whose keys authorize the route; it must equal the catalogue service of the upstream."
  service: String!
  "Whether the route streams its response; default `false`."
  streaming: Boolean
  "The upstream the route forwards to."
  upstreamId: ID!
}

"Input of the upstream-creation mutation."
input CreateUpstreamInput {
  "The catalogue service whose keys authorize the routes of this upstream."
  catalogService: String!
  "The largest number of concurrent requests to the upstream; default 256."
  concurrencyLimit: Int
  "The connect timeout in milliseconds; default 250."
  connectTimeoutMs: Int
  "What the write waits for: `PUBLISHED` (the default) returns once Kafka acknowledged the policy version; `PROPAGATED` is refused with `VALIDATION_FAILED` until the gateway pods report their versions."
  consistency: String
  "Whether the credentials of the caller are forwarded to the upstream; default `false`."
  forwardCredentials: Boolean
  "Makes the creation safe to repeat for 24 hours: 1 to 255 visible ASCII characters."
  idempotencyKey: String
  "The name of the upstream: a service name such as `core`, 1 to 63 characters, unique among the upstreams that are not deleted."
  name: String!
  "The Kubernetes namespace of the Service."
  namespace: String!
  "The number of consecutive failures after which an endpoint is ejected; default 5."
  outlierConsecutiveErrors: Int
  "The port of the Service, from 1 to 65,535."
  port: Int!
  "The protocol the gateway speaks to the upstream: `http1` or `h2c`."
  protocol: String!
  "The response timeout in milliseconds; default 10,000."
  responseTimeoutMs: Int
  "The retry budget in percent of the requests, from 0 to 100; default 10."
  retryBudgetPercent: Int
  "The Kubernetes Service that the gateway proxies to."
  service: String!
}

"Input of the rate-policy deletion mutation."
input DeleteRatePolicyInput {
  "What the write waits for: `PUBLISHED` (the default) returns once Kafka acknowledged the policy version; `PROPAGATED` is refused with `VALIDATION_FAILED` until the gateway pods report their versions."
  consistency: String
  "The version the caller read; required, and the deletion is refused when it is not the current one."
  expectedVersion: Int
  "The rate policy to delete."
  id: ID!
  "Makes the deletion safe to repeat for 24 hours: 1 to 255 visible ASCII characters."
  idempotencyKey: String
}

"The result of a rate-policy deletion."
type DeleteRatePolicyPayload {
  "The identifier of the deleted rate policy."
  id: ID!
  "The policy version that the deletion produced."
  policyVersion: Int
  "What the deletion learned about the publication of its policy version."
  propagation: Propagation
  "The final version of the rate policy."
  version: Int!
}

"Input of the role-deletion mutation."
input DeleteRoleInput {
  "What the write waits for: `PUBLISHED` (the default) returns once Kafka acknowledged the policy version; `PROPAGATED` is refused with `VALIDATION_FAILED` until the gateway pods report their versions."
  consistency: String
  "The version the caller read; required, and the deletion is refused when it is not the current one."
  expectedVersion: Int
  "The role to delete."
  id: ID!
  "Makes the deletion safe to repeat for 24 hours: 1 to 255 visible ASCII characters."
  idempotencyKey: String
}

"The result of a role deletion."
type DeleteRolePayload {
  "The bulk operation that deletes a role with more assignments than `BULK_CHUNK_ENTITIES` in chunks, or null when the deletion committed in one change; for a bulk operation `version` is the version the role holds until the last chunk deletes it, `revokedAssignments` is the number of assignments it will revoke and `policyVersion` is null."
  bulkOperationId: ID
  "The identifier of the deleted role."
  id: ID!
  "The policy version that the deletion produced."
  policyVersion: Int
  "What the deletion learned about the publication of its policy version."
  propagation: Propagation
  "The number of assignments that the deletion revoked."
  revokedAssignments: Int!
  "The final version of the role."
  version: Int!
}

"Input of the route-deletion mutation."
input DeleteRouteInput {
  "What the write waits for: `PUBLISHED` (the default) returns once Kafka acknowledged the policy version; `PROPAGATED` is refused with `VALIDATION_FAILED` until the gateway pods report their versions."
  consistency: String
  "The version the caller read; required, and the deletion is refused when it is not the current one."
  expectedVersion: Int
  "The route to delete."
  id: ID!
  "Makes the deletion safe to repeat for 24 hours: 1 to 255 visible ASCII characters."
  idempotencyKey: String
}

"The result of a route deletion."
type DeleteRoutePayload {
  "The identifier of the deleted route."
  id: ID!
  "The policy version that the deletion produced."
  policyVersion: Int
  "What the deletion learned about the publication of its policy version."
  propagation: Propagation
  "The final version of the route."
  version: Int!
}

"Input of the upstream-deletion mutation."
input DeleteUpstreamInput {
  "What the write waits for: `PUBLISHED` (the default) returns once Kafka acknowledged the policy version; `PROPAGATED` is refused with `VALIDATION_FAILED` until the gateway pods report their versions."
  consistency: String
  "The version the caller read; required, and the deletion is refused when it is not the current one."
  expectedVersion: Int
  "The upstream to delete."
  id: ID!
  "Makes the deletion safe to repeat for 24 hours: 1 to 255 visible ASCII characters."
  idempotencyKey: String
}

"The result of an upstream deletion."
type DeleteUpstreamPayload {
  "The identifier of the deleted upstream."
  id: ID!
  "The policy version that the deletion produced."
  policyVersion: Int
  "What the deletion learned about the publication of its policy version."
  propagation: Propagation
  "The final version of the upstream."
  version: Int!
}

"One key or wildcard that a user holds."
type EffectivePermission {
  "The shortest expiry among the contributing assignments that expire, as an RFC 3339 UTC time; null when none of them expires."
  expiresAt: String
  "The permission key or the wildcard pattern."
  key: String!
  "The form of the key: `rest` or `gql`, or `reserved` for a reserved `iam:` key."
  kind: String!
  "The roles of the active assignments that grant it, in identifier order."
  roles: [GrantingRole!]!
  "Where it is held: the single value `all` when a global assignment grants it, else the project ids."
  scopes: [String!]!
  "The service of the key."
  service: String!
  "Whether the entry is a wildcard pattern; a wildcard never covers a sensitive key."
  wildcard: Boolean!
}

"Template example resource."
type ExampleApiResource {
  "Description."
  description: String!
  "Identifier."
  id: ID!
  "Name."
  name: String!
}

"A coordinate that would lose a flag."
type FlagDowngrade {
  "Its flags in the new version."
  after: CoordinateFlags!
  "Its flags in the active versions."
  before: CoordinateFlags!
  "The coordinate, `Type.field`."
  coordinate: String!
}

"The cut-off of every token."
type GlobalTokenCutoff {
  "The actor that set the cut-off: `user:<uuid>`, `service:<name>` or `system:<component>`."
  actor: String!
  "When the cut-off was set, as an RFC 3339 UTC time."
  setAt: String!
  "Who caused the cut-off; the global cut-off is always set by an operator."
  source: String!
  "Tokens issued at or before this RFC 3339 UTC time are refused."
  tokensValidAfter: String!
}

"A role that grants an effective permission."
type GrantingRole {
  "The identifier of the role."
  id: ID!
  "The name of the role; null when the role is no longer stored."
  name: String
}

"A GraphQL catalogue entry."
type GraphqlPermission {
  "Whether some active version holds the key."
  active: Boolean!
  "The field of the key; `__introspection` for the introspection key."
  field: String!
  "The flags of the entry: the most restrictive ones across the active versions."
  flags: CoordinateFlags!
  "The identifier of the entry."
  id: ID!
  "The permission key, `gql:{service}:{Type}.{field}` or `gql:{service}:__introspection`."
  key: String!
  "The identifiers of the roles that grant the key by its exact key; wildcard grants are not listed."
  roles: [String!]!
  "The service of the key."
  service: String!
  "The GraphQL type of the key; `__introspection` for the introspection key."
  type: String!
  "The identifiers of the active versions that contain the key."
  versions: [String!]!
}

"Filters of the permission list."
input GraphqlPermissionFilter {
  "Only active (`true`) or only inactive (`false`) permissions."
  active: Boolean
  "Only permissions whose key starts with this text."
  keyPrefix: String
  "Only permissions that are sensitive (`true`) or not (`false`)."
  sensitive: Boolean
  "Only permissions of this service."
  service: String
  "Only permissions of this GraphQL type."
  type: String
}

"One page of GraphQL catalogue entries."
type GraphqlPermissionPage {
  "The entries of the page."
  items: [GraphqlPermission!]!
  "The `after` value of the next page; null on the last page."
  nextCursor: String
}

"The result of an activation."
type GraphqlPermissionsActivation {
  "The keys that the activation added to the catalogue, in key order; empty for a version that was active already."
  createdKeys: [String!]!
  "The identifier of the activated version."
  id: ID!
  "The policy version that the activation produced; for a version that was active already, the current policy version."
  policyVersion: Int!
  "The service the schema belongs to."
  service: String!
  "`active`."
  status: String!
}

"A GraphQL specification version with its diff."
type GraphqlSpec {
  "When the version became active."
  activatedAt: String
  "The SHA-256 hash of the SDL, in lower-case hexadecimal."
  contentHash: String!
  "The number of field coordinates of the schema."
  coordinateCount: Int!
  "When the version was loaded, as an RFC 3339 UTC time."
  createdAt: String!
  "What the version changes against the union of the active versions of its service."
  diff: GraphqlSpecDiff!
  "The identifier of the version."
  id: ID!
  "When the version was retired."
  retiredAt: String
  "The SDL document, read only when the query selects it."
  sdl: String
  "The service the schema belongs to."
  service: String!
  "`draft`, `active` or `retired`."
  status: String!
  "Who loaded the version, as `user:<id>`, `service:<name>` or `system:<component>`."
  uploadedBy: String!
}

"What a version changes against the union of the active versions of its service."
type GraphqlSpecDiff {
  "The coordinates the version adds."
  added: [String!]!
  "The coordinates that would lose a flag."
  flagDowngrades: [FlagDowngrade!]!
  "The coordinates the version removes."
  removed: [String!]!
  "The removed coordinates that roles grant by their exact key."
  removedGrants: [RemovedGrant!]!
  "The wildcard grants that would cover added coordinates."
  wildcardGains: [WildcardGain!]!
}

"Filters of the version list."
input GraphqlSpecFilter {
  "Only versions of this service."
  service: String
  "Only versions in this status: `draft`, `active` or `retired`."
  status: String
}

"One page of GraphQL specification versions."
type GraphqlSpecPage {
  "The versions of the page."
  items: [GraphqlSpec!]!
  "The `after` value of the next page; null on the last page."
  nextCursor: String
}

"A coordinate that a version renames: the grants of the old key move to the new key."
input KeyRenameInput {
  "The old key, which the version no longer holds, such as `gql:billing:Query.bills`."
  from: String!
  "The new key, which the version holds, such as `gql:billing:Query.invoices`."
  to: String!
}

"Input of the mutation that loads a GraphQL specification."
input LoadGraphqlSpecInput {
  "The SDL document, at most 5 MiB."
  sdl: String!
  "The name of the service the schema belongs to: lower-case letters, digits and hyphens, at most 63 characters; `iam` is reserved for IAM's own schema."
  service: String!
}

"Input of the mutation that loads an `OpenAPI` specification."
input LoadOpenapiSpecInput {
  "The `OpenAPI` 3.0.x or 3.1.x document as JSON text, at most 5 MiB."
  document: String!
  "The name of the service the document belongs to: lower-case letters, digits and hyphens, at most 63 characters; `iam` is reserved for IAM's own document."
  service: String!
}

"Mutation root."
type Mutation {
  "Replaces the full route set of one host atomically when `expectedVersion` is the version that `routeConfiguration` returned: routes of the set that the host lacks are created, routes whose methods and path pattern match a stored route are updated, and stored routes that the set omits are deleted, all in one transaction under one policy version, with their `route/<id>` state records, `iam.route.*` events, `iam.route_configuration.applied` and an audit record. The whole set is validated first: one violation, conflict or route the caller may not write rejects it (`VALIDATION_FAILED`, `CONFLICT`, `FORBIDDEN`), and the candidate route table of the host must build. A set larger than `ROUTE_CONFIGURATION_MAX_ROUTES` routes is refused with `VALIDATION_FAILED`. With `dryRun` the mutation runs every check and returns the diff without writing anything. A set whose diff deletes a route, clears `anonymous` or moves `enforcement` from `audit` to `enforce` is revocation-class. The caller needs `iam:route:{service}` or `iam:route:*` for every service the set touches, and `iam:route:anonymous` to create an anonymous or audit-only route or change either flag."
  applyRouteConfiguration(input: ApplyRouteConfigurationInput!): ApplyRouteConfigurationPayload!
  "Assigns an existing role to a user or a service principal at global or project scope, takes the next policy version and records `iam.user_role.assigned`, and `iam.privileged_role.assigned` as well when the role grants a wildcard or a reserved key."
  assignUserRole(input: AssignUserRoleInput!): UserRole!
  "Creates an example API resource."
  createExampleApiResource(input: CreateExampleApiResourceInput!): ExampleApiResource!
  "Activates a draft GraphQL specification version and makes its fields grantable permissions: the catalogue of the service becomes the union of its active versions, the next policy version is taken and `iam.graphql_permissions.created` is recorded. An activation that would remove the sensitive or always-audit flag from a key fails with `FLAG_DOWNGRADE_CONFIRMATION_REQUIRED` unless `confirmFlagDowngrade` is true, and one that would orphan grants fails with `ORPHAN_CONFIRMATION_REQUIRED` unless `confirmOrphans` is true. A version that is active already is a no-op."
  createGraphqlPermissions(input: CreateGraphqlPermissionsInput!): GraphqlPermissionsActivation!
  "Creates a rate policy at version 1, takes the next policy version and records `iam.rate_policy.created`. The period `periodMs` is a multiple of 1,000."
  createRatePolicy(input: CreateRatePolicyInput!): RatePolicy!
  "Activates a draft `OpenAPI` specification version and makes its operations grantable permissions: the catalogue of the service becomes the union of its active versions, the next policy version is taken and `iam.rest_permissions.created` is recorded. An activation that would remove the sensitive or always-audit flag from a key fails with `FLAG_DOWNGRADE_CONFIRMATION_REQUIRED` unless `confirmFlagDowngrade` is true, and one that would orphan grants fails with `ORPHAN_CONFIRMATION_REQUIRED` unless `confirmOrphans` is true. A version that is active already is a no-op."
  createRestPermissions(input: CreateRestPermissionsInput!): RestPermissionsActivation!
  "Creates a custom role without grants at version 1 and records `iam.role.created`."
  createRole(input: CreateRoleInput!): Role!
  "Registers a route of one host, a set of methods and a path pattern that the gateway forwards to an upstream, at version 1, writes its `route/<id>` state record, takes the next policy version and records `iam.route.created`. The caller needs `iam:route:{service}` or `iam:route:*`, and `iam:route:anonymous` to make the route anonymous or audit-only. The route `service` must equal the `catalogService` of its upstream. A route that overlaps another route of its host, or whose candidate route table the gateway could not build, is refused with `CONFLICT`, and so is a route of the `iam` service. A repeated `idempotencyKey` with the same input within 24 hours returns the original result."
  createRoute(input: CreateRouteInput!): Route!
  "Registers an upstream at version 1, writes its `upstream/<name>` state record, takes the next policy version and records `iam.upstream.created`. The caller needs `iam:route:{catalogService}` or `iam:route:*`; an upstream of the `iam` service is refused with `CONFLICT`. A repeated `idempotencyKey` with the same input within 24 hours returns the original result."
  createUpstream(input: CreateUpstreamInput!): Upstream!
  "Deletes a rate policy when `expectedVersion` is the current version and no route references it: the rate policy leaves the listings at once, the next policy version is committed, and `iam.rate_policy.deleted` and an audit record are written. A rate policy that a route references fails with `CONFLICT`."
  deleteRatePolicy(input: DeleteRatePolicyInput!): DeleteRatePolicyPayload!
  "Deletes a custom role when `expectedVersion` is the current version and revokes every assignment of it in the same transaction: the role and its assignments leave the active listings at once, the next policy version is committed, and `iam.role.deleted`, one `iam.user_role.revoked` per revoked assignment and the audit records are written. The payload reports the number of revoked assignments."
  deleteRole(input: DeleteRoleInput!): DeleteRolePayload!
  "Deletes a route when `expectedVersion` is the current version: its state record becomes a tombstone, the next policy version is committed, and `iam.route.deleted` and an audit record are written in the same transaction. A system route and one of the `iam` service are refused with `CONFLICT`."
  deleteRoute(input: DeleteRouteInput!): DeleteRoutePayload!
  "Deletes an upstream when `expectedVersion` is the current version and no route references it: its state record becomes a tombstone, the next policy version is committed, and `iam.upstream.deleted` and an audit record are written in the same transaction. An upstream that a route references is refused with `CONFLICT`, and so are a system upstream and one of the `iam` service."
  deleteUpstream(input: DeleteUpstreamInput!): DeleteUpstreamPayload!
  "Loads the SDL of a service as a draft version and returns it with its diff against the active versions; an SDL that the service already holds returns its version and changes nothing. The service `iam` is reserved."
  loadGraphqlSpec(input: LoadGraphqlSpecInput!): GraphqlSpec!
  "Loads the `OpenAPI` document of a service as a draft version and returns it with its diff against the active versions; a document that the service already holds returns its version and changes nothing. The service `iam` is reserved."
  loadOpenapiSpec(input: LoadOpenapiSpecInput!): OpenApiSpec!
  "Resyncs the policy state: republishes the complete current policy as a new log epoch, with versions continuing above the highest version of the state topic, as a bulk operation of kind `resync`, and records `iam.policy.resynced`. `reason` is required. Needs `iam:policy:resync`. Returns the bulk operation; follow it with `bulkOperation(id)` until it is `completed`. A repeated `idempotencyKey` with the same input within 24 hours returns the original operation."
  resyncPolicy(input: ResyncPolicyInput!): BulkOperation!
  "Retires an active GraphQL specification version: its fields leave the catalogue of the service unless another active version holds them, the next policy version is taken and `iam.graphql_spec.retired` is recorded. A retirement that would orphan grants fails with `ORPHAN_CONFIRMATION_REQUIRED` unless `confirmOrphans` is true; with the confirmation the grants become inactive and `iam.permissions.orphaned` is recorded."
  retireGraphqlSpec(input: RetireGraphqlSpecInput!): SpecRetirement!
  "Retires an active `OpenAPI` specification version: its operations leave the catalogue of the service unless another active version holds them, the next policy version is taken and `iam.openapi_spec.retired` is recorded. A retirement that would orphan grants fails with `ORPHAN_CONFIRMATION_REQUIRED` unless `confirmOrphans` is true; with the confirmation the grants become inactive and `iam.permissions.orphaned` is recorded."
  retireOpenapiSpec(input: RetireOpenapiSpecInput!): SpecRetirement!
  "Revokes sessions of a user: each listed session gets a revocation record and its state record, the next policy version is committed, and `iam.session.revoked` and an audit record are written in the same transaction. An empty or missing `sessionIds` sets the cut-off of every token of the user to the commit time plus 2 seconds instead and records `iam.user_tokens.cut_off`. Needs `iam:revoke:sessions`. A repeated `idempotencyKey` with the same input within 24 hours returns the original result."
  revokeSessions(input: RevokeSessionsInput!): RevocationPayload!
  "Revokes an assignment when `expectedVersion` is the current version: it leaves the active listings at once, the next policy version is committed, and `iam.user_role.revoked` and an audit record are written in the same transaction."
  revokeUserRole(input: RevokeUserRoleInput!): RevokeUserRolePayload!
  "Sets the global token cut-off: every token issued before the commit time plus 2 seconds is refused, the next policy version is committed, and `iam.global_tokens.cut_off` and an audit record are written in the same transaction. A cut-off never moves back. Needs `iam:revoke:global`. A repeated `idempotencyKey` within 24 hours returns the original result."
  setGlobalTokenCutoff(input: SetGlobalTokenCutoffInput!): RevocationPayload!
  "Replaces the whole grant set of a role when `expectedVersion` is the current version: every key must be in an active catalogue or be one of the four wildcard forms of a service that has a catalogue, and at most 5,000 keys are accepted; unknown keys fail with `VALIDATION_FAILED` and one violation per key. The change increases the version, updates the grant count, takes the next policy version and records `iam.role_permissions.changed` with the added and removed keys; an added wildcard is audited with `coversFutureElements=true`."
  setRolePermissions(input: SetRolePermissionsInput!): Role!
  "Changes the fields of a rate policy that the input names when `expectedVersion` is the current version, increases the version, takes the next policy version and records `iam.rate_policy.updated`."
  updateRatePolicy(input: UpdateRatePolicyInput!): RatePolicy!
  "Renames a custom role or changes its description when `expectedVersion` is the current version, increases the version and records `iam.role.updated`."
  updateRole(input: UpdateRoleInput!): Role!
  "Changes the members named in the input when `expectedVersion` is the current version, increases the version, takes the next policy version and records `iam.route.updated`. The caller needs `iam:route:{service}` or `iam:route:*` for the service before and after the change, and `iam:route:anonymous` to change `anonymous` or `enforcement`; a system route and one of the `iam` service are refused with `CONFLICT`. A null `cors` removes the CORS policy."
  updateRoute(input: UpdateRouteInput!): Route!
  "Changes the settings named in the input when `expectedVersion` is the current version, increases the version, takes the next policy version and records `iam.upstream.updated`. The name cannot change. The caller needs `iam:route:{catalogService}` or `iam:route:*` for the service before and after the change; a system upstream and one of the `iam` service are refused with `CONFLICT`."
  updateUpstream(input: UpdateUpstreamInput!): Upstream!
  "Sets, extends, shortens or clears the expiry of an assignment when `expectedVersion` is the current version, increases the version, takes the next policy version and records `iam.user_role.updated`. `expiresAt` is required: a time in the future, or null to clear the expiry."
  updateUserRole(input: UpdateUserRoleInput!): UserRole!
}

"An `OpenAPI` specification version."
type OpenApiSpec {
  "When the version became active."
  activatedAt: String
  "The SHA-256 hash of the document, in lower-case hexadecimal."
  contentHash: String!
  "When the version was loaded, as an RFC 3339 UTC time."
  createdAt: String!
  "What the version changes against the union of the active versions of its service."
  diff: OpenApiSpecDiff!
  "The `OpenAPI` document as JSON text, read only when the query selects it."
  document: String
  "The identifier of the version."
  id: ID!
  "The number of operations of the document."
  operationCount: Int!
  "When the version was retired."
  retiredAt: String
  "The service the document belongs to."
  service: String!
  "`draft`, `active` or `retired`."
  status: String!
  "Who loaded the version, as `user:<id>`, `service:<name>` or `system:<component>`."
  uploadedBy: String!
}

"What a version changes against the union of the active versions of its service."
type OpenApiSpecDiff {
  "The operations the version adds."
  added: [String!]!
  "The operations that would lose a flag."
  flagDowngrades: [OperationFlagDowngrade!]!
  "The operations the version removes."
  removed: [String!]!
  "The removed operations that roles grant by their exact key."
  removedGrants: [RemovedOperationGrant!]!
  "The wildcard grants that would cover added operations."
  wildcardGains: [OperationWildcardGain!]!
}

"Filters of the version list."
input OpenapiSpecFilter {
  "Only versions of this service."
  service: String
  "Only versions in this status: `draft`, `active` or `retired`."
  status: String
}

"One page of `OpenAPI` specification versions."
type OpenapiSpecPage {
  "The versions of the page."
  items: [OpenApiSpec!]!
  "The `after` value of the next page; null on the last page."
  nextCursor: String
}

"An operation that would lose a flag."
type OperationFlagDowngrade {
  "Its flags in the new version."
  after: OperationFlags!
  "Its flags in the active versions."
  before: OperationFlags!
  "The operation, `{METHOD} {template}`."
  operation: String!
}

"The two flags of an operation."
type OperationFlags {
  "Whether every use of the operation is audited (`x-iam-audit: always`)."
  auditAlways: Boolean!
  "Whether a wildcard grant never covers the operation (`x-iam-sensitive`)."
  sensitive: Boolean!
}

"A wildcard grant that would cover added operations."
type OperationWildcardGain {
  "The added operations the pattern would cover."
  operations: [String!]!
  "The wildcard pattern, such as `rest:billing:GET *`."
  pattern: String!
  "The identifier of the role that holds the grant."
  role: String!
}

"What a write learned about the publication of its policy version."
type Propagation {
  "The number of gateway pods that applied the version; null until Story 13.4."
  podsAcknowledged: Int
  "The number of gateway pods that did not apply the version in time; null until Story 13.4."
  podsTimedOut: Int
  "The policy version that the change produced."
  policyVersion: Int
  "How far the change got: `PUBLISHED` when Kafka acknowledged the policy version, or `COMMITTED_PENDING` when the change is committed and Kafka did not acknowledge the version within the wait."
  status: String!
}

"Query root."
type Query {
  "Retrieves a bulk operation by id; null when it is unknown."
  bulkOperation(id: ID!): BulkOperation
  "Retrieves one page of bulk operations, oldest first."
  bulkOperations(
    "The nextCursor of the previous page."
    after: String,
    "Page size, from 1 to 100."
    first: Int = 30
  ): BulkOperationPage!
  "Retrieves an example API resource by id."
  exampleApiResource(id: ID!): ExampleApiResource
  "Retrieves one page of example API resources, newest first."
  exampleApiResources(
    "Number of items per page, from 1 to 100."
    itemsPerPage: Int! = 30,
    "Page number, from 1."
    page: Int! = 1
  ): [ExampleApiResource!]!
  "Retrieves the global token cut-off with its source and actor; null when it was never set. Needs `iam:audit:read`."
  globalTokenCutoff: GlobalTokenCutoff
  "Retrieves a GraphQL permission by id with the active versions that contain its key and the roles that grant it by its exact key; null when it is unknown."
  graphqlPermission(id: ID!): GraphqlPermission
  "Retrieves one page of GraphQL permissions in a stable order, filtered by service, type, active state, the sensitive flag and key prefix."
  graphqlPermissions(
    "The nextCursor of the previous page."
    after: String,
    "Only permissions that match the filter."
    filter: GraphqlPermissionFilter,
    "Page size, from 1 to 100."
    first: Int = 30
  ): GraphqlPermissionPage!
  "Retrieves a GraphQL specification version by id; null when it is unknown. The fields `sdl` and `diff` are read only when the query selects them."
  graphqlSpec(id: ID!): GraphqlSpec
  "Retrieves one page of GraphQL specification versions in a stable order, filtered by service and status."
  graphqlSpecs(
    "The nextCursor of the previous page."
    after: String,
    "Only versions that match the filter."
    filter: GraphqlSpecFilter,
    "Page size, from 1 to 100."
    first: Int = 30
  ): GraphqlSpecPage!
  "Retrieves an `OpenAPI` specification version by id; null when it is unknown. The fields `document` and `diff` are read only when the query selects them."
  openapiSpec(id: ID!): OpenApiSpec
  "Retrieves one page of `OpenAPI` specification versions in a stable order, filtered by service and status."
  openapiSpecs(
    "The nextCursor of the previous page."
    after: String,
    "Only versions that match the filter."
    filter: OpenapiSpecFilter,
    "Page size, from 1 to 100."
    first: Int = 30
  ): OpenapiSpecPage!
  "Retrieves one page of rate policies in a stable order."
  ratePolicies(
    "The nextCursor of the previous page."
    after: String,
    "Page size, from 1 to 100."
    first: Int = 30
  ): RatePolicyPage!
  "Retrieves a rate policy by id; null when it is unknown or deleted."
  ratePolicy(id: ID!): RatePolicy
  "Resolves a User service token into its subject, or says why it is refused."
  resolveToken(input: ResolveTokenInput!): TokenResolution!
  "Retrieves a REST permission by id with the active versions that contain its key and the roles that grant it by its exact key; null when it is unknown."
  restPermission(id: ID!): RestPermission
  "Retrieves one page of REST permissions in a stable order, filtered by service, method, active state, the sensitive flag and path template prefix."
  restPermissions(
    "The nextCursor of the previous page."
    after: String,
    "Only permissions that match the filter."
    filter: RestPermissionFilter,
    "Page size, from 1 to 100."
    first: Int = 30
  ): RestPermissionPage!
  "Retrieves a role by id; null when it is unknown or deleted."
  role(id: ID!): Role
  "Retrieves one page of roles in a stable order, filtered by name prefix and kind."
  roles(
    "The nextCursor of the previous page."
    after: String,
    "Only roles that match the filter."
    filter: RoleFilter,
    "Page size, from 1 to 100."
    first: Int = 30
  ): RolePage!
  "Retrieves a route by id; null when it is unknown or deleted."
  route(id: ID!): Route
  "Retrieves the route configuration of a host: every route of the host that is not deleted, in the form that `applyRouteConfiguration` accepts, and the version of the set; a host without routes has an empty set."
  routeConfiguration(host: String!): RouteConfiguration!
  "Retrieves one page of the routes that are not deleted, in a stable order; the filter keeps the routes that match every field given."
  routes(
    "The nextCursor of the previous page."
    after: String,
    "Keeps the routes of this host, upstream and catalogue service."
    filter: RouteFilterInput,
    "Page size, from 1 to 100."
    first: Int = 30
  ): RoutePage!
  "Retrieves a security audit record by id and records the read in the audit log; null when it is unknown. Needs `iam:audit:read`."
  securityAuditEvent(id: ID!): SecurityAuditEvent
  "Retrieves one page of the security audit records, newest first, and records the search in the audit log; the filter keeps the records that match every field given. Needs `iam:audit:read`."
  securityAuditEvents(
    "The nextCursor of the previous page."
    after: String,
    "Keeps the records in a time range, of an actor, an action, a target and an outcome."
    filter: SecurityAuditEventFilterInput,
    "Page size, from 1 to 100."
    first: Int = 30
  ): SecurityAuditEventPage!
  "Retrieves a session revocation by id with its source and actor; null when it is unknown. Needs `iam:audit:read`."
  sessionRevocation(id: ID!): SessionRevocation
  "Retrieves one page of the session revocations, newest first; the filter keeps the revocations that match every field given. Needs `iam:audit:read`."
  sessionRevocations(
    "The nextCursor of the previous page."
    after: String,
    "Keeps the revocations of a user, of a source and in a time range."
    filter: SessionRevocationFilterInput,
    "Page size, from 1 to 100."
    first: Int = 30
  ): SessionRevocationPage!
  "Retrieves an upstream by id; null when it is unknown or deleted."
  upstream(id: ID!): Upstream
  "Retrieves one page of the upstreams that are not deleted, in a stable order."
  upstreams(
    "The nextCursor of the previous page."
    after: String,
    "Page size, from 1 to 100."
    first: Int = 30
  ): UpstreamPage!
  "Retrieves a role assignment by id; null when it is unknown or revoked."
  userRole(id: ID!): UserRole
  "Retrieves the effective permissions of a user: every key and wildcard that its active assignments hold, each with the roles that grant it, its scopes (`all` or project ids), the shortest expiry among the contributing assignments that expire and the policy version the answer was composed at. `projectId` keeps the global assignments and those of the project; `service` keeps the keys and wildcards of the service. A user without assignments has an empty list."
  userRolePermissions(
    "Only assignments that apply in this project: the global ones and those of the project."
    projectId: String,
    "Only keys and wildcards of this service."
    service: String,
    "The user whose permissions are read."
    userId: ID!
  ): UserRolePermissions!
  "Retrieves one page of role assignments that are not revoked, in a stable order, filtered by subject, role, project and expiry."
  userRoles(
    "The nextCursor of the previous page."
    after: String,
    "Only assignments that match the filter."
    filter: UserRoleFilter,
    "Page size, from 1 to 100."
    first: Int = 30
  ): UserRolePage!
  "Retrieves the token cut-off of a user with its source and actor; null when the user has none. Needs `iam:audit:read`."
  userTokenCutoff(userId: ID!): UserTokenCutoff
  "Decides whether a subject may perform a REST operation or hold permission keys; a valid request always gets a decision."
  validateAccess(input: ValidateAccessInput!): AccessValidation!
  "Decides 1 to 100 checks of the shape of `validateAccess` and returns one decision per input, in the order of the inputs, each with its own `decisionId`; an input that cannot be read is a `deny` with the reason `malformed_operation` and does not fail the others. A batch of no input or of more than 100 fails with `VALIDATION_FAILED`."
  validateAccessBatch(inputs: [ValidateAccessInput!]!): [AccessValidation!]!
}

"A rate policy."
type RatePolicy {
  "The number of requests allowed above the limit in a burst."
  burst: Int!
  "When the rate policy was created, as an RFC 3339 UTC time."
  createdAt: String!
  "What the limit becomes without the shared counter: `divided` or `full`."
  fallback: String!
  "The identifier of the rate policy."
  id: ID!
  "What requests are counted by: `ip`, `subject`, `subject_route` or `route`."
  key: String!
  "The number of requests allowed per period."
  limit: Int!
  "The name of the rate policy."
  name: String!
  "The period in milliseconds."
  periodMs: Int!
  "What the write that returned the rate policy learned about the publication of its policy version; null for a read."
  propagation: Propagation
  "When the rate policy was last changed, as an RFC 3339 UTC time."
  updatedAt: String!
  "The version of the rate policy."
  version: Int!
}

"One page of rate policies."
type RatePolicyPage {
  "The rate policies of the page."
  items: [RatePolicy!]!
  "The `after` value of the next page; null on the last page."
  nextCursor: String
}

"A removed coordinate that roles grant by its exact key."
type RemovedGrant {
  "The removed coordinate, `Type.field`."
  coordinate: String!
  "The identifiers of the roles that grant it."
  roles: [String!]!
}

"A removed operation that roles grant by its exact key."
type RemovedOperationGrant {
  "The removed operation, `{METHOD} {template}`."
  operation: String!
  "The identifiers of the roles that grant it."
  roles: [String!]!
}

"Input of the token-resolution query."
input ResolveTokenInput {
  "The User service token to resolve; an empty one resolves as `token_missing`."
  credential: String!
}

"A REST catalogue entry."
type RestPermission {
  "Whether some active version holds the key."
  active: Boolean!
  "The flags of the entry: the most restrictive ones across the active versions."
  flags: OperationFlags!
  "The identifier of the entry."
  id: ID!
  "The permission key, `rest:{service}:{METHOD} {template}`."
  key: String!
  "The HTTP method of the key."
  method: String!
  "The identifiers of the roles that grant the key by its exact key; wildcard grants are not listed."
  roles: [String!]!
  "The service of the key."
  service: String!
  "The normalised path template of the key; parameters are written `{}`."
  template: String!
  "The identifiers of the active versions that contain the key."
  versions: [String!]!
}

"Filters of the REST permission list."
input RestPermissionFilter {
  "Only active (`true`) or only inactive (`false`) permissions."
  active: Boolean
  "Only permissions of this HTTP method, in upper case."
  method: String
  "Only permissions that are sensitive (`true`) or not (`false`)."
  sensitive: Boolean
  "Only permissions of this service."
  service: String
  "Only permissions whose normalised path template starts with this text."
  templatePrefix: String
}

"One page of REST catalogue entries."
type RestPermissionPage {
  "The entries of the page."
  items: [RestPermission!]!
  "The `after` value of the next page; null on the last page."
  nextCursor: String
}

"The result of an activation."
type RestPermissionsActivation {
  "The keys that the activation added to the catalogue, in key order; empty for a version that was active already."
  createdKeys: [String!]!
  "The identifier of the activated version."
  id: ID!
  "The policy version that the activation produced; for a version that was active already, the current policy version."
  policyVersion: Int!
  "The service the document belongs to."
  service: String!
  "`active`."
  status: String!
}

"Input of the policy resync mutation."
input ResyncPolicyInput {
  "Makes the resync safe to repeat for 24 hours: 1 to 255 visible ASCII characters."
  idempotencyKey: String
  "Why the policy is resynced: one line of 1 to 500 characters, kept in the audit record and in `iam.policy.resynced`; a missing or blank reason fails with `VALIDATION_FAILED`."
  reason: String! = ""
}

"Input of the mutation that retires a GraphQL specification version."
input RetireGraphqlSpecInput {
  "Accepts that grants of keys that leave the catalogue become inactive; without it, a retirement that would orphan grants fails with `ORPHAN_CONFIRMATION_REQUIRED`."
  confirmOrphans: Boolean! = false
  "The version to retire."
  id: ID!
  "Makes the retirement safe to repeat for 24 hours: 1 to 255 visible ASCII characters."
  idempotencyKey: String
}

"Input of the mutation that retires an `OpenAPI` specification version."
input RetireOpenapiSpecInput {
  "Accepts that grants of keys that leave the catalogue become inactive; without it, a retirement that would orphan grants fails with `ORPHAN_CONFIRMATION_REQUIRED`."
  confirmOrphans: Boolean! = false
  "The version to retire."
  id: ID!
  "Makes the retirement safe to repeat for 24 hours: 1 to 255 visible ASCII characters."
  idempotencyKey: String
}

"The result of a revocation write."
type RevocationPayload {
  "What the audit record of the change targets: the first revoked session's revocation, the user of a cut-off, or `current` for the global cut-off."
  id: ID!
  "The policy version that the change produced."
  policyVersion: Int
  "What the change learned about the publication of its policy version."
  propagation: Propagation
}

"Input of the session revocation mutation."
input RevokeSessionsInput {
  "What the write waits for: `PUBLISHED` (the default) returns once Kafka acknowledged the policy version; `PROPAGATED` is refused with `VALIDATION_FAILED` until the gateway pods report their versions."
  consistency: String
  "Makes the revocation safe to repeat for 24 hours: 1 to 255 visible ASCII characters."
  idempotencyKey: String
  "The sessions to revoke, at most 100, each 1 to 255 visible ASCII characters; an empty or missing list sets the cut-off of every token of the user instead."
  sessionIds: [String!]! = []
  "The user whose sessions or tokens are revoked."
  userId: ID!
}

"Input of the assignment-revocation mutation."
input RevokeUserRoleInput {
  "What the write waits for: `PUBLISHED` (the default) returns once Kafka acknowledged the policy version; `PROPAGATED` is refused with `VALIDATION_FAILED` until the gateway pods report their versions."
  consistency: String
  "The version the caller read; required, and the revocation is refused when it is not the current one."
  expectedVersion: Int
  "The assignment to revoke."
  id: ID!
  "Makes the revocation safe to repeat for 24 hours: 1 to 255 visible ASCII characters."
  idempotencyKey: String
}

"The result of a revocation."
type RevokeUserRolePayload {
  "The identifier of the revoked assignment."
  id: ID!
  "The policy version that the revocation produced."
  policyVersion: Int
  "What the revocation learned about the publication of its policy version."
  propagation: Propagation
  "The final version of the assignment."
  version: Int!
}

"A role."
type Role {
  "When the role was created, as an RFC 3339 UTC time."
  createdAt: String!
  "What the role is for."
  description: String
  "The number of permission grants of the role."
  grantCount: Int!
  "The identifier of the role."
  id: ID!
  "`system` for a role that IAM manages, `custom` for one that an administrator manages."
  kind: String!
  "The name of the role."
  name: String!
  "The grants of the role in key order, each with its key, kind, service, active flag and wildcard flag."
  permissions: [RolePermission!]!
  "What the write that returned the role learned about the publication of its policy version; null for a read and for a change that does not affect decisions."
  propagation: Propagation
  "When the role was last changed, as an RFC 3339 UTC time."
  updatedAt: String!
  "The version of the role."
  version: Int!
}

"Filters of the role list."
input RoleFilter {
  "Only roles of this kind: `system` or `custom`."
  kind: String
  "Only roles whose name starts with this text, without regard to case."
  namePrefix: String
}

"One page of roles."
type RolePage {
  "The roles of the page."
  items: [Role!]!
  "The `after` value of the next page; null on the last page."
  nextCursor: String
}

"One grant of a role."
type RolePermission {
  "Whether the grant takes part in decisions; a grant to a key that left the catalogue is inactive."
  active: Boolean!
  "The permission key or the wildcard pattern."
  key: String!
  "The form of the key: `rest` or `gql`, or `reserved` for a reserved `iam:` key."
  kind: String!
  "The service of the key."
  service: String!
  "Whether the grant is a wildcard pattern."
  wildcard: Boolean!
}

"A route of the gateway configuration."
type Route {
  "Whether the route is served without authentication."
  anonymous: Boolean!
  "The largest request body in bytes."
  bodyLimitBytes: Int!
  "The CORS policy of the route; null when it has none."
  cors: RouteCorsPolicy
  "When the route was created, as an RFC 3339 UTC time."
  createdAt: String!
  "The enforcement mode: `enforce` or `audit`."
  enforcement: String!
  "Whether the route serves GraphQL."
  graphql: Boolean!
  "The host the route serves."
  host: String!
  "The identifier of the route."
  id: ID!
  "The idle timeout in milliseconds."
  idleTimeoutMs: Int!
  "The methods the route serves."
  methods: [String!]!
  "The path pattern."
  pathPattern: String!
  "What the write that returned the route learned about the publication of its policy version; null for a read."
  propagation: Propagation
  "The rate policies of the route, in the order they apply."
  ratePolicyIds: [ID!]!
  "The request timeout in milliseconds."
  requestTimeoutMs: Int!
  "Which failed requests are retried: `none` or `idempotent`."
  retryPolicy: String!
  "The catalogue service whose keys authorize the route."
  service: String!
  "Whether the route streams its response."
  streaming: Boolean!
  "Whether IAM manages the route itself; the API refuses every change of a system route."
  system: Boolean!
  "When the route was last changed, as an RFC 3339 UTC time."
  updatedAt: String!
  "The upstream the route forwards to."
  upstreamId: ID!
  "The version of the route."
  version: Int!
}

"The route set of a host and its version."
type RouteConfiguration {
  "The host."
  host: String!
  "The routes of the host, in the form that the application accepts."
  routes: [RouteDeclaration!]!
  "The version of the set, to pass as `expectedVersion` of the next application."
  version: Int!
}

"A route that a set adds, changes or removes."
type RouteConfigurationChange {
  "The names of the properties that change; empty unless the route is changed."
  changedFields: [String!]!
  "The methods of the route."
  methods: [String!]!
  "The path pattern of the route."
  pathPattern: String!
}

"The CORS policy of a route."
type RouteCorsPolicy {
  "Whether credentials are allowed."
  allowCredentials: Boolean!
  "The allowed request headers."
  headers: [String!]!
  "How long a preflight answer may be cached, in seconds."
  maxAgeSeconds: Int!
  "The allowed methods."
  methods: [String!]!
  "The allowed origins."
  origins: [String!]!
}

"Input of the CORS policy of a route."
input RouteCorsPolicyInput {
  "Whether credentials are allowed; default `false`."
  allowCredentials: Boolean
  "The allowed request headers."
  headers: [String!]
  "How long a preflight answer may be cached, in seconds, at most 86,400; default 600."
  maxAgeSeconds: Int
  "The allowed methods, such as `GET`."
  methods: [String!]
  "The allowed origins, each an exact `https` (or `http`) origin."
  origins: [String!]!
}

"One route of a set, in the form that the application accepts."
type RouteDeclaration {
  "Whether the route is served without authentication."
  anonymous: Boolean!
  "The largest request body in bytes."
  bodyLimitBytes: Int!
  "The CORS policy of the route; null when it has none."
  cors: RouteCorsPolicy
  "The enforcement mode: `enforce` or `audit`."
  enforcement: String!
  "Whether the route serves GraphQL."
  graphql: Boolean!
  "The idle timeout in milliseconds."
  idleTimeoutMs: Int!
  "The methods the route serves."
  methods: [String!]!
  "The path pattern."
  pathPattern: String!
  "The rate policies of the route, in the order they apply."
  ratePolicyIds: [ID!]!
  "The request timeout in milliseconds."
  requestTimeoutMs: Int!
  "Which failed requests are retried: `none` or `idempotent`."
  retryPolicy: String!
  "The catalogue service whose keys authorize the route."
  service: String!
  "Whether the route streams its response."
  streaming: Boolean!
  "The upstream the route forwards to."
  upstreamId: ID!
}

"Input of one route of a declared set."
input RouteDeclarationInput {
  "Whether the route is served without authentication; needs `iam:route:anonymous`; default `false`."
  anonymous: Boolean
  "The largest request body in bytes; default 1,048,576."
  bodyLimitBytes: Int
  "The CORS policy of the route."
  cors: RouteCorsPolicyInput
  "The enforcement mode: `enforce` (the default) or `audit`, which needs `iam:route:anonymous`."
  enforcement: String
  "Whether the route serves GraphQL; default `false`."
  graphql: Boolean
  "The idle timeout in milliseconds; default 60,000."
  idleTimeoutMs: Int
  "The methods the route serves, such as `GET`."
  methods: [String!]!
  "The path pattern, with `{name}` and `{name:*}` segments."
  pathPattern: String!
  "The rate policies of the route, in the order they apply, at most 10."
  ratePolicyIds: [ID!]
  "The request timeout in milliseconds; default 30,000."
  requestTimeoutMs: Int
  "Which failed requests are retried: `none` (the default) or `idempotent`."
  retryPolicy: String
  "The catalogue service whose keys authorize the route; it must equal the catalogue service of the upstream."
  service: String!
  "Whether the route streams its response; default `false`."
  streaming: Boolean
  "The upstream the route forwards to."
  upstreamId: ID!
}

"The filters of the route list: a route must match every one that is given."
input RouteFilterInput {
  "Only the routes of this host."
  host: String
  "Only the routes of this catalogue service."
  service: String
  "Only the routes that forward to this upstream."
  upstream: ID
}

"One page of routes."
type RoutePage {
  "The routes of the page."
  items: [Route!]!
  "The `after` value of the next page; null on the last page."
  nextCursor: String
}

"One security audit record with its place in the hash chain."
type SecurityAuditEvent {
  "What was done, such as `role.create`."
  action: String!
  "Who performed the action: `user:<uuid>`, `service:<name>` or `system:<component>`."
  actor: String!
  "The state after the change, as a summary of identifiers, names and keys."
  after: String
  "The state before the change, as a summary of identifiers, names and keys."
  before: String
  "The service that called on behalf of the actor, when it differs from the actor."
  callerService: String
  "The hash of this record: `SHA-256(prevHash || canonical form)`, 64 lower-case hexadecimal digits."
  hash: String!
  "The identifier of the record."
  id: ID!
  "When the action happened, as an RFC 3339 UTC time."
  occurredAt: String!
  "Whether the change took effect: `committed` or `rejected`."
  outcome: String!
  "The policy version that resulted from the change."
  policyVersion: Int
  "The hash of the previous record, 64 lower-case hexadecimal digits; all zeros for the first."
  prevHash: String!
  "Why an attempt was refused, such as `forbidden`."
  reason: String
  "The request id of the caller."
  requestId: String
  "Where it applies: `global` or `project:<uuid>`."
  scope: String
  "The gap-free sequence number of the record in the chain, starting at 1."
  seq: Int!
  "The identifier of what it was done to."
  targetId: String!
  "The type of what it was done to, such as `role`."
  targetType: String!
}

"The filters of the security audit search: a record must meet every one that is given."
input SecurityAuditEventFilterInput {
  "Only the records of this action, such as `role.create`."
  action: String
  "Only the records of this actor: `user:<uuid>`, `service:<name>` or `system:<component>`."
  actor: String
  "Only the records from this RFC 3339 UTC time on."
  from: String
  "Only the records of this outcome: `committed` or `rejected`."
  outcome: String
  "Only the records about this target; needs `targetType`."
  targetId: String
  "Only the records about targets of this type, such as `role`."
  targetType: String
  "Only the records before this RFC 3339 UTC time."
  until: String
}

"One page of security audit records."
type SecurityAuditEventPage {
  "The records of the page, newest first."
  items: [SecurityAuditEvent!]!
  "The `after` value of the next, older page; null on the last page."
  nextCursor: String
}

"One revoked session with the source and the actor of its revocation."
type SessionRevocation {
  "The actor that recorded the revocation: `user:<uuid>`, `service:<name>` or `system:<component>`."
  actor: String!
  "The identifier of the revocation."
  id: ID!
  "When the revocation was recorded, as an RFC 3339 UTC time."
  revokedAt: String!
  "The revoked session."
  sessionId: String!
  "Who caused the revocation: `user-service` or `operator`."
  source: String!
  "The user the session belongs to."
  userId: ID!
}

"The filters of the session revocation list: a revocation must meet every one that is given."
input SessionRevocationFilterInput {
  "Only the revocations from this RFC 3339 UTC time on."
  from: String
  "Only the revocations that this source caused: `user-service` or `operator`."
  source: String
  "Only the revocations before this RFC 3339 UTC time."
  until: String
  "Only the revocations of the sessions of this user."
  userId: ID
}

"One page of session revocations."
type SessionRevocationPage {
  "The revocations of the page, newest first."
  items: [SessionRevocation!]!
  "The `after` value of the next, older page; null on the last page."
  nextCursor: String
}

"Input of the global token cut-off mutation."
input SetGlobalTokenCutoffInput {
  "What the write waits for: `PUBLISHED` (the default) returns once Kafka acknowledged the policy version; `PROPAGATED` is refused with `VALIDATION_FAILED` until the gateway pods report their versions."
  consistency: String
  "Makes the write safe to repeat for 24 hours: 1 to 255 visible ASCII characters."
  idempotencyKey: String
}

"Input of the mutation that replaces the grants of a role."
input SetRolePermissionsInput {
  "What the write waits for: `PUBLISHED` (the default) returns once Kafka acknowledged the policy version; `PROPAGATED` is refused with `VALIDATION_FAILED` until the gateway pods report their versions."
  consistency: String
  "The version the caller read; required, and the replacement is refused when it is not the current one."
  expectedVersion: Int
  "The role to change."
  id: ID!
  "Makes the replacement safe to repeat for 24 hours: 1 to 255 visible ASCII characters."
  idempotencyKey: String
  "The new grant set: keys of an active catalogue and the four wildcard forms of a service that has a catalogue; at most 5,000. A key that repeats counts once and an empty list removes every grant."
  keys: [String!]!
}

"The result of a retirement."
type SpecRetirement {
  "The identifier of the retired version."
  id: ID!
  "The policy version that the retirement produced."
  policyVersion: Int!
  "The service the specification belongs to."
  service: String!
  "`retired`."
  status: String!
}

"The resolution of a credential: the subject and its token claims, or the reason it is refused."
type TokenResolution {
  "When the token expires, in seconds since 1970-01-01T00:00:00Z."
  expiresAt: Int
  "Why the credential is refused: `token_missing`, `token_invalid`, `token_expired` or `token_revoked`."
  reason: String
  "Whether the credential is valid and unrevoked."
  resolved: Boolean!
  "The roles claim of the token as issued."
  roles: [String!]
  "The User service session of the token, when it names one."
  sessionId: String
  "The user id, or the service name of a service principal."
  subjectId: String
  "`user` or `service`."
  subjectKind: String
}

"Input of the rate-policy update mutation."
input UpdateRatePolicyInput {
  "The new burst; an absent field keeps it."
  burst: Int
  "What the write waits for: `PUBLISHED` (the default) returns once Kafka acknowledged the policy version; `PROPAGATED` is refused with `VALIDATION_FAILED` until the gateway pods report their versions."
  consistency: String
  "The version the caller read; required, and the update is refused when it is not the current one."
  expectedVersion: Int
  "The new fallback; an absent field keeps it."
  fallback: String
  "The rate policy to change."
  id: ID!
  "Makes the update safe to repeat for 24 hours: 1 to 255 visible ASCII characters."
  idempotencyKey: String
  "The new key kind; an absent field keeps it."
  key: String
  "The new limit; an absent field keeps it."
  limit: Int
  "The new name; an absent field keeps it."
  name: String
  "The new period in milliseconds; an absent field keeps it."
  periodMs: Int
}

"Input of the role-update mutation."
input UpdateRoleInput {
  "What the write waits for: `PUBLISHED` (the default) returns once Kafka acknowledged the policy version; `PROPAGATED` is refused with `VALIDATION_FAILED` until the gateway pods report their versions."
  consistency: String
  "The new description, at most 1,000 characters; null removes it and an absent field keeps it."
  description: String
  "The version the caller read; required, and the update is refused when it is not the current one."
  expectedVersion: Int
  "The role to change."
  id: ID!
  "Makes the update safe to repeat for 24 hours: 1 to 255 visible ASCII characters."
  idempotencyKey: String
  "The new name of the role: 1 to 100 characters, unique without regard to case among the roles that are not deleted."
  name: String
}

"""
Input of the route-update mutation; an absent or null setting keeps its stored value, except
`cors`, where null removes the policy.
"""
input UpdateRouteInput {
  "Whether the route is served without authentication; changing it needs `iam:route:anonymous`."
  anonymous: Boolean
  "The largest request body in bytes."
  bodyLimitBytes: Int
  "What the write waits for: `PUBLISHED` (the default) returns once Kafka acknowledged the policy version; `PROPAGATED` is refused with `VALIDATION_FAILED` until the gateway pods report their versions."
  consistency: String
  "The CORS policy of the route; null removes it."
  cors: RouteCorsPolicyInput
  "The enforcement mode: `enforce` or `audit`; changing it needs `iam:route:anonymous`."
  enforcement: String
  "The version the caller read; required, and the update is refused when it is not the current one."
  expectedVersion: Int
  "Whether the route serves GraphQL."
  graphql: Boolean
  "The lower-case DNS name of the host the route serves."
  host: String
  "The route to change."
  id: ID!
  "Makes the update safe to repeat for 24 hours: 1 to 255 visible ASCII characters."
  idempotencyKey: String
  "The idle timeout in milliseconds."
  idleTimeoutMs: Int
  "The methods the route serves, such as `GET`."
  methods: [String!]
  "The path pattern."
  pathPattern: String
  "The rate policies of the route, in the order they apply, at most 10."
  ratePolicyIds: [ID!]
  "The request timeout in milliseconds."
  requestTimeoutMs: Int
  "Which failed requests are retried: `none` or `idempotent`."
  retryPolicy: String
  "The catalogue service whose keys authorize the route."
  service: String
  "Whether the route streams its response."
  streaming: Boolean
  "The upstream the route forwards to."
  upstreamId: ID
}

"Input of the upstream-update mutation; an absent or null setting keeps its stored value."
input UpdateUpstreamInput {
  "The catalogue service whose keys authorize the routes of this upstream."
  catalogService: String
  "The largest number of concurrent requests to the upstream."
  concurrencyLimit: Int
  "The connect timeout in milliseconds."
  connectTimeoutMs: Int
  "What the write waits for: `PUBLISHED` (the default) returns once Kafka acknowledged the policy version; `PROPAGATED` is refused with `VALIDATION_FAILED` until the gateway pods report their versions."
  consistency: String
  "The version the caller read; required, and the update is refused when it is not the current one."
  expectedVersion: Int
  "Whether the credentials of the caller are forwarded to the upstream."
  forwardCredentials: Boolean
  "The upstream to change."
  id: ID!
  "Makes the update safe to repeat for 24 hours: 1 to 255 visible ASCII characters."
  idempotencyKey: String
  "The name of the upstream; it must equal the stored name, because the name cannot change."
  name: String
  "The Kubernetes namespace of the Service."
  namespace: String
  "The number of consecutive failures after which an endpoint is ejected."
  outlierConsecutiveErrors: Int
  "The port of the Service, from 1 to 65,535."
  port: Int
  "The protocol the gateway speaks to the upstream: `http1` or `h2c`."
  protocol: String
  "The response timeout in milliseconds."
  responseTimeoutMs: Int
  "The retry budget in percent of the requests, from 0 to 100."
  retryBudgetPercent: Int
  "The Kubernetes Service that the gateway proxies to."
  service: String
}

"Input of the assignment-update mutation."
input UpdateUserRoleInput {
  "What the write waits for: `PUBLISHED` (the default) returns once Kafka acknowledged the policy version; `PROPAGATED` is refused with `VALIDATION_FAILED` until the gateway pods report their versions."
  consistency: String
  "The version the caller read; required, and the update is refused when it is not the current one."
  expectedVersion: Int
  "The new expiry, as an RFC 3339 UTC time in the future; null clears the expiry. The field is required."
  expiresAt: String
  "The assignment to change."
  id: ID!
  "Makes the update safe to repeat for 24 hours: 1 to 255 visible ASCII characters."
  idempotencyKey: String
}

"An upstream of the gateway configuration."
type Upstream {
  "The catalogue service whose keys authorize the routes of this upstream."
  catalogService: String!
  "The largest number of concurrent requests to the upstream."
  concurrencyLimit: Int!
  "The connect timeout in milliseconds."
  connectTimeoutMs: Int!
  "When the upstream was created, as an RFC 3339 UTC time."
  createdAt: String!
  "Whether the credentials of the caller are forwarded to the upstream."
  forwardCredentials: Boolean!
  "The identifier of the upstream."
  id: ID!
  "The name of the upstream."
  name: String!
  "The Kubernetes namespace of the Service."
  namespace: String!
  "The number of consecutive failures after which an endpoint is ejected."
  outlierConsecutiveErrors: Int!
  "The port of the Service."
  port: Int!
  "What the write that returned the upstream learned about the publication of its policy version; null for a read."
  propagation: Propagation
  "The protocol the gateway speaks to the upstream: `http1` or `h2c`."
  protocol: String!
  "The response timeout in milliseconds."
  responseTimeoutMs: Int!
  "The retry budget in percent of the requests."
  retryBudgetPercent: Int!
  "The Kubernetes Service that the gateway proxies to."
  service: String!
  "Whether IAM manages the upstream itself; the API refuses every change of a system upstream."
  system: Boolean!
  "When the upstream was last changed, as an RFC 3339 UTC time."
  updatedAt: String!
  "The version of the upstream."
  version: Int!
}

"One page of upstreams."
type UpstreamPage {
  "The upstreams of the page."
  items: [Upstream!]!
  "The `after` value of the next page; null on the last page."
  nextCursor: String
}

"A role assignment."
type UserRole {
  "When the assignment was created, as an RFC 3339 UTC time."
  createdAt: String!
  "When the assignment expires, as an RFC 3339 UTC time; null when it never expires."
  expiresAt: String
  "The identifier of the assignment."
  id: ID!
  "What the write that returned the assignment learned about the publication of its policy version; null for a read."
  propagation: Propagation
  "The assigned role."
  roleId: ID!
  "The name of the assigned role."
  roleName: String
  "Where the role applies."
  scope: AssignmentScope!
  "Who holds the role."
  subject: AssignmentSubject!
  "When the assignment was last changed, as an RFC 3339 UTC time."
  updatedAt: String!
  "The version of the assignment."
  version: Int!
}

"Filters of the assignment list."
input UserRoleFilter {
  "Whether assignments that have expired are listed as well; default `false`."
  includeExpired: Boolean
  "Only assignments scoped to this project."
  projectId: String
  "Only assignments of this role."
  roleId: String
  "Only assignments of the subject with this id: a user UUID or a service name."
  subjectId: String
  "Only assignments of subjects of this kind: `user` or `service`."
  subjectKind: String
}

"One page of role assignments."
type UserRolePage {
  "The assignments of the page."
  items: [UserRole!]!
  "The `after` value of the next page; null on the last page."
  nextCursor: String
}

"The effective permissions of a user."
type UserRolePermissions {
  "The exact keys in key order, then the wildcard patterns."
  permissions: [EffectivePermission!]!
  "The policy version the permissions were composed at."
  policyVersion: Int!
  "The user whose permissions these are."
  userId: ID!
}

"The cut-off of the tokens of one user."
type UserTokenCutoff {
  "The actor that set the cut-off: `system:user-service` for a cut-off of a User service event and the actor of the audit record for an operator cut-off; null when the audit log holds no record of it."
  actor: String
  "Who caused the cut-off: `user-service` or `operator`."
  source: String!
  "Tokens issued at or before this RFC 3339 UTC time are refused."
  tokensValidAfter: String!
  "When the cut-off was last moved, as an RFC 3339 UTC time."
  updatedAt: String!
  "The user."
  userId: ID!
}

"Input of the access-validation query."
input ValidateAccessInput {
  "The subject's access token as the caller received it; an empty one is decided as `token_missing`."
  credential: String!
  "A GraphQL document to check; exactly one of `rest`, `graphql` and `permissions` is given. The decision is all-or-nothing and `denied` lists every coordinate the subject does not hold."
  graphql: AccessGraphQlTargetInput
  "The policy version that the decision must reflect at least; a version that IAM has not issued yet fails with `VALIDATION_FAILED`."
  minPolicyVersion: Int
  "The permission keys to check, 1 to 100; exactly one of `rest`, `graphql` and `permissions` is given."
  permissions: [String!]
  "The project in which the check is made; without it, project assignments contribute their projects to `scopes`."
  projectId: String
  "An opaque identifier of the caller's request, 1 to 128 visible ASCII characters; the response echoes it."
  requestId: String!
  "A REST request to check; exactly one of `rest`, `graphql` and `permissions` is given."
  rest: AccessRestTargetInput
  "The target service, as registered in IAM."
  service: String!
}

"A wildcard grant that would cover added coordinates."
type WildcardGain {
  "The added coordinates the pattern would cover."
  coordinates: [String!]!
  "The wildcard pattern, such as `gql:billing:Query.*`."
  pattern: String!
  "The identifier of the role that holds the grant."
  role: String!
}

"Directs the executor to include this field or fragment only when the `if` argument is true."
directive @include(if: Boolean!) on FIELD | FRAGMENT_SPREAD | INLINE_FRAGMENT
"Directs the executor to skip this field or fragment when the `if` argument is true."
directive @skip(if: Boolean!) on FIELD | FRAGMENT_SPREAD | INLINE_FRAGMENT
schema {
  query: Query
  mutation: Mutation
}
"#;

#[test]
fn the_sdl_is_the_documented_schema() {
    assert_eq!(sdl(), EXPECTED_SDL);
}

#[test]
fn the_sdl_has_the_template_and_iam_operations_and_nothing_else_to_call() {
    let text = sdl();

    assert!(text.contains("resolveToken(input: ResolveTokenInput!): TokenResolution!"));
    assert!(
        text.contains("validateAccessBatch(inputs: [ValidateAccessInput!]!): [AccessValidation!]!")
    );
    assert!(text.contains("exampleApiResource(id: ID!)"));
    assert!(text.contains("exampleApiResources("));
    assert!(text.contains("createExampleApiResource(input: CreateExampleApiResourceInput!)"));
    assert!(text.contains("createRole(input: CreateRoleInput!): Role!"));
    assert!(text.contains(
        "createGraphqlPermissions(input: CreateGraphqlPermissionsInput!): GraphqlPermissionsActivation!"
    ));
    assert!(text.contains(
        "createRestPermissions(input: CreateRestPermissionsInput!): RestPermissionsActivation!"
    ));
    assert!(text.contains("resyncPolicy(input: ResyncPolicyInput!): BulkOperation!"));
    assert!(text.contains("revokeSessions(input: RevokeSessionsInput!): RevocationPayload!"));
    assert!(
        text.contains(
            "setGlobalTokenCutoff(input: SetGlobalTokenCutoffInput!): RevocationPayload!"
        )
    );
    assert!(text.contains("retireGraphqlSpec(input: RetireGraphqlSpecInput!): SpecRetirement!"));
    assert!(text.contains("retireOpenapiSpec(input: RetireOpenapiSpecInput!): SpecRetirement!"));
    assert!(text.contains("updateRole(input: UpdateRoleInput!): Role!"));
    assert!(text.contains("setRolePermissions(input: SetRolePermissionsInput!): Role!"));
    assert!(text.contains("permissions: [RolePermission!]!"));
    assert!(text.contains("deleteRole(input: DeleteRoleInput!): DeleteRolePayload!"));
    assert!(text.contains("createRatePolicy(input: CreateRatePolicyInput!): RatePolicy!"));
    assert!(text.contains("updateRatePolicy(input: UpdateRatePolicyInput!): RatePolicy!"));
    assert!(
        text.contains("deleteRatePolicy(input: DeleteRatePolicyInput!): DeleteRatePolicyPayload!")
    );
    assert!(text.contains("ratePolicy(id: ID!): RatePolicy"));
    assert!(text.contains("ratePolicies("));
    assert!(text.contains("role(id: ID!): Role"));
    assert!(text.contains("roles("));
    assert!(text.contains("assignUserRole(input: AssignUserRoleInput!): UserRole!"));
    assert!(text.contains("updateUserRole(input: UpdateUserRoleInput!): UserRole!"));
    assert!(text.contains("revokeUserRole(input: RevokeUserRoleInput!): RevokeUserRolePayload!"));
    assert!(text.contains("userRole(id: ID!): UserRole"));
    assert!(text.contains("userRoles("));
    assert!(text.contains("userRolePermissions("));
    assert!(text.contains("graphqlSpec("));
    assert!(text.contains("graphqlPermission(id: ID!): GraphqlPermission"));
    assert!(text.contains("graphqlPermissions("));
    assert!(text.contains("restPermission(id: ID!): RestPermission"));
    assert!(text.contains("restPermissions("));
    assert!(text.contains("graphqlSpecs("));
    assert!(text.contains("loadOpenapiSpec(input: LoadOpenapiSpecInput!): OpenApiSpec!"));
    for absent in [
        "node",
        "Connection",
        "updateExampleApiResource",
        "deleteExampleApiResource",
        "type Subscription",
    ] {
        assert!(!text.contains(absent), "the SDL contains `{absent}`");
    }
}

#[test]
fn twenty_generations_are_byte_identical() {
    let first = sdl();

    for _ in 0..20 {
        assert_eq!(sdl(), first);
    }
}

#[tokio::test]
async fn the_builder_gives_a_schema_with_the_two_roots() {
    let schema: ApiSchema = builder().finish();

    let response = schema.execute(Request::new("{ query: __typename }")).await;
    let mutation = schema
        .execute(Request::new("mutation { mutation: __typename }"))
        .await;

    assert_eq!(
        response.data.into_json().unwrap(),
        serde_json::json!({ "query": "Query" })
    );
    assert_eq!(
        mutation.data.into_json().unwrap(),
        serde_json::json!({ "mutation": "Mutation" })
    );
}

fn principal() -> Principal {
    Principal::from(TokenIdentity::from(&AccessToken::new(AccessTokenParts {
        subject: SubjectId::User(Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap()),
        session: Some(SessionId::new("session-1").unwrap()),
        token_id: TokenId::new("jti-1").unwrap(),
        roles: vec!["ROLE_USER".to_owned()],
        issued_at: SystemTime::UNIX_EPOCH,
        expires_at: SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_mins(15))
            .unwrap(),
    })))
}

fn iam_state() -> IamState {
    let resolved = TokenResolution::Resolved(principal());
    let queries =
        FakeQueryBus::answering(move |_query: ResolveSubjectTokenQuery| Ok(resolved.clone()));
    let command_bus: Arc<dyn CommandBus> = Arc::new(FakeCommandBus::unregistered());
    let query_bus: Arc<dyn QueryBus> = Arc::new(queries);
    IamState {
        command_bus,
        query_bus,
        uuid_generator: Arc::new(SequenceUuidGenerator::starting_at(1)),
        clock: Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
        request_digester: Arc::new(FakeRequestDigester),
    }
}

#[tokio::test]
async fn resolve_token_is_merged_into_the_query_root_and_reaches_the_iam_state() {
    let schema: ApiSchema = builder().data(iam_state()).finish();
    let request = Request::new(
        "{ resolveToken(input: { credential: \"any\" }) { resolved subjectKind sessionId } }",
    )
    .data(Some(principal()));

    let response = schema.execute(request).await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        serde_json::json!({ "resolveToken": {
            "resolved": true,
            "subjectKind": "user",
            "sessionId": "session-1",
        } })
    );
}

#[tokio::test]
async fn resolve_token_without_the_iam_state_in_the_schema_data_is_an_internal_error() {
    let schema: ApiSchema = builder().finish();
    let request = Request::new("{ resolveToken(input: { credential: \"any\" }) { resolved } }")
        .data(Some(principal()));

    let response = schema.execute(request).await;

    let code = response
        .errors
        .first()
        .and_then(|error| error.extensions.as_ref())
        .and_then(|extensions| extensions.get("code"))
        .cloned();
    assert_eq!(
        code,
        Some(async_graphql::Value::String(
            "INTERNAL_SERVER_ERROR".to_owned()
        ))
    );
}

fn error_code(response: &async_graphql::Response) -> Option<async_graphql::Value> {
    response
        .errors
        .first()
        .and_then(|error| error.extensions.as_ref())
        .and_then(|extensions| extensions.get("code"))
        .cloned()
}

#[tokio::test]
async fn create_role_is_merged_into_the_mutation_root_and_needs_an_authenticated_caller() {
    let schema: ApiSchema = builder().data(iam_state()).finish();
    let request = Request::new("mutation { createRole(input: { name: \"Billing\" }) { id } }");

    let response = schema.execute(request).await;

    assert_eq!(
        error_code(&response),
        Some(async_graphql::Value::String("UNAUTHENTICATED".to_owned()))
    );
}

#[tokio::test]
async fn update_role_is_merged_into_the_mutation_root_and_needs_an_authenticated_caller() {
    let schema: ApiSchema = builder().data(iam_state()).finish();
    let request = Request::new(
        "mutation { updateRole(input: { id: \"0190f2a8-7b3c-7d4e-8f10-1234567890cd\", \
         expectedVersion: 1, name: \"Billing\" }) { id } }",
    );

    let response = schema.execute(request).await;

    assert_eq!(
        error_code(&response),
        Some(async_graphql::Value::String("UNAUTHENTICATED".to_owned()))
    );
}

#[tokio::test]
async fn the_role_queries_are_merged_into_the_query_root_and_need_an_authenticated_caller() {
    let schema: ApiSchema = builder().data(iam_state()).finish();
    let single = Request::new("{ role(id: \"0190f2a8-7b3c-7d4e-8f10-1234567890cd\") { id } }");
    let page = Request::new("{ roles { items { id } } }");

    let single = schema.execute(single).await;
    let page = schema.execute(page).await;

    for response in [single, page] {
        assert_eq!(
            error_code(&response),
            Some(async_graphql::Value::String("UNAUTHENTICATED".to_owned()))
        );
    }
}

#[tokio::test]
async fn assign_user_role_is_merged_into_the_mutation_root_and_needs_an_authenticated_caller() {
    let schema: ApiSchema = builder().data(iam_state()).finish();
    let request = Request::new(
        "mutation { assignUserRole(input: { subject: { kind: \"user\", \
         id: \"0190f2a8-7b3c-7d4e-8f10-1234567890ab\" }, \
         roleId: \"0190f2a8-7b3c-7d4e-8f10-1234567890cd\", scope: { kind: \"global\" } }) { id } }",
    );

    let response = schema.execute(request).await;

    assert_eq!(
        error_code(&response),
        Some(async_graphql::Value::String("UNAUTHENTICATED".to_owned()))
    );
}

#[tokio::test]
async fn the_assignment_changes_are_merged_into_the_mutation_root_and_need_an_authenticated_caller()
{
    let schema: ApiSchema = builder().data(iam_state()).finish();
    let update = Request::new(
        "mutation { updateUserRole(input: { id: \"0190f2a8-7b3c-7d4e-8f10-1234567890cd\", \
         expectedVersion: 1, expiresAt: null }) { id } }",
    );
    let revoke = Request::new(
        "mutation { revokeUserRole(input: { id: \"0190f2a8-7b3c-7d4e-8f10-1234567890cd\", \
         expectedVersion: 1 }) { id } }",
    );

    let update = schema.execute(update).await;
    let revoke = schema.execute(revoke).await;

    for response in [update, revoke] {
        assert_eq!(
            error_code(&response),
            Some(async_graphql::Value::String("UNAUTHENTICATED".to_owned()))
        );
    }
}

#[tokio::test]
async fn delete_role_is_merged_into_the_mutation_root_and_needs_an_authenticated_caller() {
    let schema: ApiSchema = builder().data(iam_state()).finish();
    let request = Request::new(
        "mutation { deleteRole(input: { id: \"0190f2a8-7b3c-7d4e-8f10-1234567890cd\", \
         expectedVersion: 1 }) { id revokedAssignments } }",
    );

    let response = schema.execute(request).await;

    assert_eq!(
        error_code(&response),
        Some(async_graphql::Value::String("UNAUTHENTICATED".to_owned()))
    );
}

#[tokio::test]
async fn the_assignment_queries_are_merged_into_the_query_root_and_need_an_authenticated_caller() {
    let schema: ApiSchema = builder().data(iam_state()).finish();
    let single = Request::new("{ userRole(id: \"0190f2a8-7b3c-7d4e-8f10-1234567890cd\") { id } }");
    let page = Request::new("{ userRoles { items { id } } }");

    let single = schema.execute(single).await;
    let page = schema.execute(page).await;

    for response in [single, page] {
        assert_eq!(
            error_code(&response),
            Some(async_graphql::Value::String("UNAUTHENTICATED".to_owned()))
        );
    }
}

#[tokio::test]
async fn the_security_audit_queries_are_merged_into_the_query_root_and_need_an_authenticated_caller()
 {
    let schema: ApiSchema = builder().data(iam_state()).finish();
    let single =
        Request::new("{ securityAuditEvent(id: \"0190f2a8-7b3c-7d4e-8f10-1234567890cd\") { id } }");
    let page = Request::new(
        "{ securityAuditEvents(filter: { outcome: \"rejected\", targetType: \"role\" }) \
         { items { id } nextCursor } }",
    );

    let single = schema.execute(single).await;
    let page = schema.execute(page).await;

    for response in [single, page] {
        assert_eq!(
            error_code(&response),
            Some(async_graphql::Value::String("UNAUTHENTICATED".to_owned()))
        );
    }
}

#[tokio::test]
async fn the_revocation_queries_are_merged_into_the_query_root_and_need_an_authenticated_caller() {
    let schema: ApiSchema = builder().data(iam_state()).finish();
    let queries = [
        "{ sessionRevocation(id: \"0190f2a8-7b3c-7d4e-8f10-1234567890cd\") { id } }",
        "{ sessionRevocations(filter: { source: \"operator\" }) { items { id } nextCursor } }",
        "{ userTokenCutoff(userId: \"0190f2a8-7b3c-7d4e-8f10-1234567890ab\") { source actor } }",
        "{ globalTokenCutoff { source actor } }",
    ];

    for query in queries {
        let response = schema.execute(Request::new(query)).await;

        assert_eq!(
            error_code(&response),
            Some(async_graphql::Value::String("UNAUTHENTICATED".to_owned())),
            "{query}"
        );
    }
}

async fn errors_of(query: &str) -> Vec<String> {
    let schema: ApiSchema = builder().finish();
    schema
        .execute(Request::new(query))
        .await
        .errors
        .into_iter()
        .map(|error| error.message)
        .collect()
}

#[tokio::test]
async fn a_page_of_sdl_documents_is_too_complex_to_run() {
    let errors = errors_of("{ graphqlSpecs(first: 100) { items { id sdl } } }").await;

    assert_eq!(errors, ["Query is too complex."]);
}

#[tokio::test]
async fn aliases_cannot_multiply_sdl_reads_past_the_complexity_limit() {
    let aliases = ["s0", "s1", "s2", "s3", "s4"]
        .map(|alias| format!("{alias}: graphqlSpec(id: \"x\") {{ sdl }}"))
        .join(" ");

    let errors = errors_of(&format!("{{ {aliases} }}")).await;

    assert_eq!(errors, ["Query is too complex."]);
}

#[tokio::test]
async fn one_sdl_document_and_a_full_page_without_sdl_stay_within_the_limits() {
    let single = errors_of("{ graphqlSpec(id: \"x\") { sdl diff { __typename } } }").await;
    let page = errors_of("{ graphqlSpecs(first: 100) { items { id } nextCursor } }").await;

    assert!(!single.iter().any(|message| message.contains("too complex")));
    assert!(!page.iter().any(|message| message.contains("too complex")));
}

#[tokio::test]
async fn a_query_deeper_than_the_limit_is_refused() {
    let nested = (0..=MAX_QUERY_DEPTH).fold(String::from("name"), |inner, _| {
        format!("ofType {{ {inner} }}")
    });
    let deep = format!("{{ __type(name: \"Query\") {{ {nested} }} }}");

    assert_eq!(errors_of(&deep).await, ["Query is nested too deep."]);
}

#[test]
fn the_iam_sdl_holds_the_iam_operations_under_the_served_root_names() {
    let sdl = iam_sdl();

    assert!(sdl.contains("createRole"), "{sdl}");
    assert!(sdl.contains("type Mutation"), "{sdl}");
    assert!(sdl.contains("type Query"), "{sdl}");
    assert!(
        !sdl.contains("IamQuery") && !sdl.contains("IamMutation"),
        "{sdl}"
    );
}

#[test]
fn the_iam_sdl_holds_no_operation_of_another_context() {
    assert!(!iam_sdl().contains("ExampleApiResource"));
}

#[test]
fn the_same_build_produces_the_same_iam_sdl() {
    assert_eq!(iam_sdl(), iam_sdl());
}

#[test]
fn every_iam_root_field_has_an_authorization_row_and_every_row_a_field() {
    use iam_application::OperationRules;
    use iam_application::graphql::AsyncGraphQlSchemaParser;
    use iam_domain::GraphQlSchemaParser as _;

    let graph = AsyncGraphQlSchemaParser.parse(&iam_sdl()).unwrap();
    let roots: std::collections::BTreeSet<String> = graph
        .coordinates()
        .iter()
        .map(|(coordinate, _flags)| coordinate.to_string())
        .filter(|coordinate| {
            coordinate.starts_with("Query.") || coordinate.starts_with("Mutation.")
        })
        .collect();
    let rows: std::collections::BTreeSet<String> = OperationRules::graphql()
        .iter()
        .map(|rule| rule.coordinate.to_owned())
        .collect();

    assert_eq!(rows, roots);
}
