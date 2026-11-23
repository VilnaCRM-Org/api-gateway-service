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

"Input of the assignment mutation."
input AssignUserRoleInput {
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
  "What the role is for, at most 1,000 characters."
  description: String
  "Makes the creation safe to repeat for 24 hours: 1 to 255 visible ASCII characters."
  idempotencyKey: String
  "The name of the role: 1 to 100 characters, unique without regard to case among the roles that are not deleted."
  name: String!
}

"Input of the role-deletion mutation."
input DeleteRoleInput {
  "The version the caller read; required, and the deletion is refused when it is not the current one."
  expectedVersion: Int
  "The role to delete."
  id: ID!
  "Makes the deletion safe to repeat for 24 hours: 1 to 255 visible ASCII characters."
  idempotencyKey: String
}

"The result of a role deletion."
type DeleteRolePayload {
  "The identifier of the deleted role."
  id: ID!
  "The policy version that the deletion produced."
  policyVersion: Int
  "The number of assignments that the deletion revoked."
  revokedAssignments: Int!
  "The final version of the role."
  version: Int!
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
  "Assigns an existing role to a user or a service principal at global or project scope, takes the next policy version and records `iam.user_role.assigned`, and `iam.privileged_role.assigned` as well when the role grants a wildcard or a reserved key."
  assignUserRole(input: AssignUserRoleInput!): UserRole!
  "Creates an example API resource."
  createExampleApiResource(input: CreateExampleApiResourceInput!): ExampleApiResource!
  "Activates a draft GraphQL specification version and makes its fields grantable permissions: the catalogue of the service becomes the union of its active versions, the next policy version is taken and `iam.graphql_permissions.created` is recorded. An activation that would remove the sensitive or always-audit flag from a key fails with `FLAG_DOWNGRADE_CONFIRMATION_REQUIRED` unless `confirmFlagDowngrade` is true, and one that would orphan grants fails with `ORPHAN_CONFIRMATION_REQUIRED` unless `confirmOrphans` is true. A version that is active already is a no-op."
  createGraphqlPermissions(input: CreateGraphqlPermissionsInput!): GraphqlPermissionsActivation!
  "Activates a draft `OpenAPI` specification version and makes its operations grantable permissions: the catalogue of the service becomes the union of its active versions, the next policy version is taken and `iam.rest_permissions.created` is recorded. An activation that would remove the sensitive or always-audit flag from a key fails with `FLAG_DOWNGRADE_CONFIRMATION_REQUIRED` unless `confirmFlagDowngrade` is true, and one that would orphan grants fails with `ORPHAN_CONFIRMATION_REQUIRED` unless `confirmOrphans` is true. A version that is active already is a no-op."
  createRestPermissions(input: CreateRestPermissionsInput!): RestPermissionsActivation!
  "Creates a custom role without grants at version 1 and records `iam.role.created`."
  createRole(input: CreateRoleInput!): Role!
  "Deletes a custom role when `expectedVersion` is the current version and revokes every assignment of it in the same transaction: the role and its assignments leave the active listings at once, the next policy version is committed, and `iam.role.deleted`, one `iam.user_role.revoked` per revoked assignment and the audit records are written. The payload reports the number of revoked assignments."
  deleteRole(input: DeleteRoleInput!): DeleteRolePayload!
  "Loads the SDL of a service as a draft version and returns it with its diff against the active versions; an SDL that the service already holds returns its version and changes nothing. The service `iam` is reserved."
  loadGraphqlSpec(input: LoadGraphqlSpecInput!): GraphqlSpec!
  "Loads the `OpenAPI` document of a service as a draft version and returns it with its diff against the active versions; a document that the service already holds returns its version and changes nothing. The service `iam` is reserved."
  loadOpenapiSpec(input: LoadOpenapiSpecInput!): OpenApiSpec!
  "Retires an active GraphQL specification version: its fields leave the catalogue of the service unless another active version holds them, the next policy version is taken and `iam.graphql_spec.retired` is recorded. A retirement that would orphan grants fails with `ORPHAN_CONFIRMATION_REQUIRED` unless `confirmOrphans` is true; with the confirmation the grants become inactive and `iam.permissions.orphaned` is recorded."
  retireGraphqlSpec(input: RetireGraphqlSpecInput!): SpecRetirement!
  "Retires an active `OpenAPI` specification version: its operations leave the catalogue of the service unless another active version holds them, the next policy version is taken and `iam.openapi_spec.retired` is recorded. A retirement that would orphan grants fails with `ORPHAN_CONFIRMATION_REQUIRED` unless `confirmOrphans` is true; with the confirmation the grants become inactive and `iam.permissions.orphaned` is recorded."
  retireOpenapiSpec(input: RetireOpenapiSpecInput!): SpecRetirement!
  "Revokes an assignment when `expectedVersion` is the current version: it leaves the active listings at once, the next policy version is committed, and `iam.user_role.revoked` and an audit record are written in the same transaction."
  revokeUserRole(input: RevokeUserRoleInput!): RevokeUserRolePayload!
  "Replaces the whole grant set of a role when `expectedVersion` is the current version: every key must be in an active catalogue or be one of the four wildcard forms of a service that has a catalogue, and at most 5,000 keys are accepted; unknown keys fail with `VALIDATION_FAILED` and one violation per key. The change increases the version, updates the grant count, takes the next policy version and records `iam.role_permissions.changed` with the added and removed keys; an added wildcard is audited with `coversFutureElements=true`."
  setRolePermissions(input: SetRolePermissionsInput!): Role!
  "Renames a custom role or changes its description when `expectedVersion` is the current version, increases the version and records `iam.role.updated`."
  updateRole(input: UpdateRoleInput!): Role!
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

"Query root."
type Query {
  "Retrieves an example API resource by id."
  exampleApiResource(id: ID!): ExampleApiResource
  "Retrieves one page of example API resources, newest first."
  exampleApiResources(
    "Number of items per page, from 1 to 100."
    itemsPerPage: Int! = 30,
    "Page number, from 1."
    page: Int! = 1
  ): [ExampleApiResource!]!
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
  "Retrieves a role assignment by id; null when it is unknown or revoked."
  userRole(id: ID!): UserRole
  "Retrieves one page of role assignments that are not revoked, in a stable order, filtered by subject, role, project and expiry."
  userRoles(
    "The nextCursor of the previous page."
    after: String,
    "Only assignments that match the filter."
    filter: UserRoleFilter,
    "Page size, from 1 to 100."
    first: Int = 30
  ): UserRolePage!
  "Decides whether a subject may perform a REST operation or hold permission keys; a valid request always gets a decision."
  validateAccess(input: ValidateAccessInput!): AccessValidation!
  "Decides 1 to 100 checks of the shape of `validateAccess` and returns one decision per input, in the order of the inputs, each with its own `decisionId`; an input that cannot be read is a `deny` with the reason `malformed_operation` and does not fail the others. A batch of no input or of more than 100 fails with `VALIDATION_FAILED`."
  validateAccessBatch(inputs: [ValidateAccessInput!]!): [AccessValidation!]!
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

"Input of the assignment-revocation mutation."
input RevokeUserRoleInput {
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

"Input of the mutation that replaces the grants of a role."
input SetRolePermissionsInput {
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

"Input of the role-update mutation."
input UpdateRoleInput {
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

"Input of the assignment-update mutation."
input UpdateUserRoleInput {
  "The version the caller read; required, and the update is refused when it is not the current one."
  expectedVersion: Int
  "The new expiry, as an RFC 3339 UTC time in the future; null clears the expiry. The field is required."
  expiresAt: String
  "The assignment to change."
  id: ID!
  "Makes the update safe to repeat for 24 hours: 1 to 255 visible ASCII characters."
  idempotencyKey: String
}

"A role assignment."
type UserRole {
  "When the assignment was created, as an RFC 3339 UTC time."
  createdAt: String!
  "When the assignment expires, as an RFC 3339 UTC time; null when it never expires."
  expiresAt: String
  "The identifier of the assignment."
  id: ID!
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
    assert!(text.contains("retireGraphqlSpec(input: RetireGraphqlSpecInput!): SpecRetirement!"));
    assert!(text.contains("retireOpenapiSpec(input: RetireOpenapiSpecInput!): SpecRetirement!"));
    assert!(text.contains("updateRole(input: UpdateRoleInput!): Role!"));
    assert!(text.contains("setRolePermissions(input: SetRolePermissionsInput!): Role!"));
    assert!(text.contains("permissions: [RolePermission!]!"));
    assert!(text.contains("deleteRole(input: DeleteRoleInput!): DeleteRolePayload!"));
    assert!(text.contains("role(id: ID!): Role"));
    assert!(text.contains("roles("));
    assert!(text.contains("assignUserRole(input: AssignUserRoleInput!): UserRole!"));
    assert!(text.contains("updateUserRole(input: UpdateUserRoleInput!): UserRole!"));
    assert!(text.contains("revokeUserRole(input: RevokeUserRoleInput!): RevokeUserRolePayload!"));
    assert!(text.contains("userRole(id: ID!): UserRole"));
    assert!(text.contains("userRoles("));
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
