//! GraphQL adapter of the IAM context: the query and mutation roots, the conversion of IAM problems
//! to GraphQL errors and the `expectedVersion` rule of the update and delete inputs.
//!
//! [`IamQuery`] holds the token-resolution and role queries and [`IamMutation`] the role mutation;
//! the composition root merges both into the schema roots.
//!
//! The resolvers share the use-case calls of the REST handlers and the REST DTOs, so both
//! transports apply one set of rules; every failure becomes a problem first and a GraphQL error
//! second.

pub mod access_decision;
pub mod access_validation;
pub mod authorization;
pub mod bulk_operation;
pub mod document_analyzer;
pub mod global_token_cutoff;
pub mod graphql_activation;
pub mod graphql_permission;
pub mod graphql_spec;
pub mod openapi_spec;
pub mod policy_resync;
pub mod propagation;
pub mod rate_policy;
pub mod rest_activation;
pub mod rest_permission;
pub mod revocation_read;
pub mod role_deletion;
pub mod role_permission;
pub mod route;
pub mod route_configuration;
pub mod schema_parser;
pub mod security_audit_event;
pub mod session_revocation;
pub mod spec_retirement;
pub mod upstream;
pub mod user_role;
pub mod user_role_permission;

use async_graphql::{
    ComplexObject, Context, Error, ErrorExtensions as _, ID, InputObject, MaybeUndefined, Object,
    SimpleObject,
};
use iam_domain::{EntityVersion, IdempotencyKey};
use shared_application::graphql::{problem_to_error, violations_value};
use shared_application::http::{Problem, Violation};
use validator::Validate as _;

use crate::command::update_role::DescriptionUpdate;
use crate::error::{
    IamError, TYPE_FLAG_DOWNGRADE_CONFIRMATION, TYPE_LAST_ADMINISTRATOR, TYPE_ORPHAN_CONFIRMATION,
};
use crate::http::IamState;
use crate::http::dto::{
    CreateRoleRequest, DEFAULT_PAGE_SIZE, DescriptionPatch, ListRolesParams, RolePageResponse,
    RoleResponse, TokenResolutionRequest, TokenResolutionResponse, UpdateRoleRequest,
};
use crate::http::extract::VersionedWriteHeaders;
use crate::http::handler::resolve_credential;
use crate::http::role::{create_role, find_role, list_roles, parse_role_id, update_role};
use crate::principal::Principal;
use propagation::{PropagationObject, WriteOutcomeMapper, write_mode};

use access_decision::{
    AccessDecisionFilterInput, AccessDecisionObject, AccessDecisionPageObject,
    access_decision_field, access_decisions_field,
};
use access_validation::{
    AccessValidationObject, ValidateAccessInput, validate_access_batch_field, validate_access_field,
};
use bulk_operation::{
    BulkOperationObject, BulkOperationPageObject, bulk_operation_field, bulk_operations_field,
};
use global_token_cutoff::{SetGlobalTokenCutoffInput, set_global_token_cutoff_field};
use graphql_activation::{
    CreateGraphQlPermissionsInput, GraphQlPermissionsActivationObject,
    create_graphql_permissions_field,
};
use graphql_permission::{
    GraphQlPermissionFilterInput, GraphQlPermissionObject, GraphQlPermissionPageObject,
    graphql_permission_field, graphql_permissions_field,
};
use graphql_spec::{
    GraphQlSpecFilterInput, GraphQlSpecObject, GraphQlSpecPageObject, LoadGraphQlSpecInput,
    graphql_spec_field, graphql_specs_field, load_graphql_spec_field,
};
use openapi_spec::{
    LoadOpenApiSpecInput, OpenApiSpecFilterInput, OpenApiSpecObject, OpenApiSpecPageObject,
    load_openapi_spec_field, openapi_spec_field, openapi_specs_field,
};
use policy_resync::{ResyncPolicyInput, resync_policy_field};
use rate_policy::{
    CreateRatePolicyInput, DeleteRatePolicyInput, DeleteRatePolicyPayload, RatePolicyObject,
    RatePolicyPageObject, UpdateRatePolicyInput, create_rate_policy_field,
    delete_rate_policy_field, rate_policies_field, rate_policy_field, update_rate_policy_field,
};
use rest_activation::{
    CreateRestPermissionsInput, RestPermissionsActivationObject, create_rest_permissions_field,
};
use rest_permission::{
    RestPermissionFilterInput, RestPermissionObject, RestPermissionPageObject,
    rest_permission_field, rest_permissions_field,
};
use revocation_read::{
    GlobalTokenCutoffObject, SessionRevocationFilterInput, SessionRevocationObject,
    SessionRevocationPageObject, UserTokenCutoffObject, global_token_cutoff_field,
    session_revocation_field, session_revocations_field, user_token_cutoff_field,
};
use role_deletion::{DeleteRoleInput, DeleteRolePayload, delete_role_field};
use role_permission::{
    RolePermissionObject, SetRolePermissionsInput, role_permissions_field,
    set_role_permissions_field,
};
use route::{
    CreateRouteInput, DeleteRouteInput, DeleteRoutePayload, RouteFilterInput, RouteObject,
    RoutePageObject, UpdateRouteInput, create_route_field, delete_route_field, route_field,
    routes_field, update_route_field,
};
use route_configuration::{
    ApplyRouteConfigurationInput, ApplyRouteConfigurationPayload, RouteConfigurationObject,
    apply_route_configuration_field, route_configuration_field,
};
use security_audit_event::{
    SecurityAuditAnchorInput, SecurityAuditChainVerificationObject, SecurityAuditEventFilterInput,
    SecurityAuditEventObject, SecurityAuditEventPageObject,
    security_audit_chain_verification_field, security_audit_event_field,
    security_audit_events_field,
};
use session_revocation::{RevocationPayload, RevokeSessionsInput, revoke_sessions_field};
use spec_retirement::{
    RetireGraphQlSpecInput, RetireOpenApiSpecInput, SpecRetirementObject,
    retire_graphql_spec_field, retire_openapi_spec_field,
};
use upstream::{
    CreateUpstreamInput, DeleteUpstreamInput, DeleteUpstreamPayload, UpdateUpstreamInput,
    UpstreamObject, UpstreamPageObject, create_upstream_field, delete_upstream_field,
    update_upstream_field, upstream_field, upstreams_field,
};
use user_role::{
    AssignUserRoleInput, RevokeUserRoleInput, RevokeUserRolePayload, UpdateUserRoleInput,
    UserRoleFilterInput, UserRoleObject, UserRolePageObject, assign_user_role_field,
    revoke_user_role_field, update_user_role_field, user_role_field, user_roles_field,
};
use user_role_permission::{UserRolePermissionsObject, user_role_permissions_field};

pub use authorization::IamAuthorizationExtension;
pub use document_analyzer::AsyncGraphQlDocumentAnalyzer;
pub use schema_parser::AsyncGraphQlSchemaParser;

/// Query root of the IAM context.
#[derive(Debug, Default)]
pub struct IamQuery;

/// Mutation root of the IAM context.
#[derive(Debug, Default)]
pub struct IamMutation;

/// Input of the token-resolution query.
// Its `Debug` output never shows the credential.
#[derive(InputObject)]
#[graphql(name = "ResolveTokenInput")]
pub struct ResolveTokenInput {
    /// The User service token to resolve; an empty one resolves as `token_missing`.
    pub credential: String,
}

impl std::fmt::Debug for ResolveTokenInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolveTokenInput").finish_non_exhaustive()
    }
}

/// The resolution of a credential: the subject and its token claims, or the reason it is refused.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "TokenResolution")]
pub struct TokenResolutionObject {
    /// Whether the credential is valid and unrevoked.
    pub resolved: bool,
    /// Why the credential is refused: `token_missing`, `token_invalid`, `token_expired` or `token_revoked`.
    pub reason: Option<String>,
    /// The user id, or the service name of a service principal.
    pub subject_id: Option<String>,
    /// `user` or `service`.
    pub subject_kind: Option<String>,
    /// The User service session of the token, when it names one.
    pub session_id: Option<String>,
    /// The roles claim of the token as issued.
    pub roles: Option<Vec<String>>,
    /// When the token expires, in seconds since 1970-01-01T00:00:00Z.
    pub expires_at: Option<i64>,
}

impl From<TokenResolutionResponse> for TokenResolutionObject {
    fn from(response: TokenResolutionResponse) -> Self {
        Self {
            resolved: response.resolved,
            reason: response.reason,
            subject_id: response.subject_id,
            subject_kind: response.subject_kind,
            session_id: response.session_id,
            roles: response.roles,
            expires_at: response.expires_at,
        }
    }
}

/// Input of the role-creation mutation.
#[derive(Debug, InputObject)]
#[graphql(name = "CreateRoleInput")]
pub struct CreateRoleInput {
    /// The name of the role: 1 to 100 characters, unique without regard to case among the roles that are not deleted.
    pub name: String,
    /// What the role is for, at most 1,000 characters.
    pub description: Option<String>,
    /// Makes the creation safe to repeat for 24 hours: 1 to 255 visible ASCII characters.
    pub idempotency_key: Option<String>,
    /// What the write waits for: `PUBLISHED` (the default) returns once Kafka acknowledged the policy version; `PROPAGATED` is refused with `VALIDATION_FAILED` until the gateway pods report their versions.
    pub consistency: Option<String>,
}

/// Input of the role-update mutation.
#[derive(Debug, InputObject)]
#[graphql(name = "UpdateRoleInput")]
pub struct UpdateRoleInput {
    /// The role to change.
    pub id: ID,
    /// The version the caller read; required, and the update is refused when it is not the current one.
    pub expected_version: Option<i64>,
    /// The new name of the role: 1 to 100 characters, unique without regard to case among the roles that are not deleted.
    pub name: Option<String>,
    /// The new description, at most 1,000 characters; null removes it and an absent field keeps it.
    pub description: MaybeUndefined<String>,
    /// Makes the update safe to repeat for 24 hours: 1 to 255 visible ASCII characters.
    pub idempotency_key: Option<String>,
    /// What the write waits for: `PUBLISHED` (the default) returns once Kafka acknowledged the policy version; `PROPAGATED` is refused with `VALIDATION_FAILED` until the gateway pods report their versions.
    pub consistency: Option<String>,
}

/// Filters of the role list.
#[derive(Debug, Default, InputObject)]
#[graphql(name = "RoleFilter")]
pub struct RoleFilterInput {
    /// Only roles whose name starts with this text, without regard to case.
    pub name_prefix: Option<String>,
    /// Only roles of this kind: `system` or `custom`.
    pub kind: Option<String>,
}

/// A role.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "Role", complex)]
pub struct RoleObject {
    /// The identifier of the role.
    pub id: ID,
    /// The name of the role.
    pub name: String,
    /// What the role is for.
    pub description: Option<String>,
    /// `system` for a role that IAM manages, `custom` for one that an administrator manages.
    pub kind: String,
    /// The number of permission grants of the role.
    pub grant_count: i64,
    /// The version of the role.
    pub version: i64,
    /// When the role was created, as an RFC 3339 UTC time.
    pub created_at: String,
    /// When the role was last changed, as an RFC 3339 UTC time.
    pub updated_at: String,
    /// What the write that returned the role learned about the publication of its policy version; null for a read and for a change that does not affect decisions.
    pub propagation: Option<PropagationObject>,
}

impl From<RoleResponse> for RoleObject {
    fn from(response: RoleResponse) -> Self {
        Self {
            id: ID::from(response.id),
            name: response.name,
            description: response.description,
            kind: response.kind,
            grant_count: response.grant_count,
            version: response.version,
            created_at: response.created_at,
            updated_at: response.updated_at,
            propagation: None,
        }
    }
}

#[ComplexObject]
impl RoleObject {
    /// The grants of the role in key order, each with its key, kind, service, active flag and wildcard flag.
    async fn permissions(
        &self,
        ctx: &Context<'_>,
    ) -> async_graphql::Result<Vec<RolePermissionObject>> {
        role_permissions_field(ctx, &self.id)
            .await
            .map_err(iam_problem_to_graphql_error)
    }
}

/// One page of roles.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "RolePage")]
pub struct RolePageObject {
    /// The roles of the page.
    pub items: Vec<RoleObject>,
    /// The `after` value of the next page; null on the last page.
    pub next_cursor: Option<String>,
}

impl From<RolePageResponse> for RolePageObject {
    fn from(page: RolePageResponse) -> Self {
        Self {
            items: page.items.into_iter().map(RoleObject::from).collect(),
            next_cursor: page.next_cursor,
        }
    }
}

/// The schema was built without the `IamState` data.
#[derive(Debug, thiserror::Error)]
#[error("the GraphQL schema has no IamState data")]
struct MissingState;

fn state<'ctx>(ctx: &Context<'ctx>) -> Result<&'ctx IamState, Problem> {
    ctx.data::<IamState>()
        .map_err(|_error| Problem::internal(&MissingState))
}

/// The caller that the authentication middleware resolved from a valid token; any other request is
/// refused as unauthenticated.
fn require_caller<'ctx>(ctx: &Context<'ctx>) -> Result<&'ctx Principal, Problem> {
    ctx.data_opt::<Option<Principal>>()
        .and_then(Option::as_ref)
        .ok_or_else(|| Problem::from(IamError::Unauthenticated))
}

/// The idempotency key of an input; a value that is not 1 to 255 visible ASCII characters is a
/// violation of `idempotencyKey`.
fn idempotency_key(text: Option<&str>) -> Result<Option<IdempotencyKey>, Problem> {
    text.map(IdempotencyKey::new).transpose().map_err(|error| {
        Problem::validation_failed(vec![Violation {
            property_path: error.property_path().to_owned(),
            message: error.to_string(),
            code: error.code().to_owned(),
        }])
    })
}

async fn resolve_token(
    ctx: &Context<'_>,
    input: ResolveTokenInput,
) -> Result<TokenResolutionObject, Problem> {
    require_caller(ctx)?;
    let request = TokenResolutionRequest {
        credential: input.credential,
    };
    request.validate()?;
    let response = resolve_credential(state(ctx)?, request.credential).await?;
    Ok(TokenResolutionObject::from(response))
}

async fn create_role_field(
    ctx: &Context<'_>,
    input: CreateRoleInput,
) -> Result<RoleObject, Problem> {
    let caller = require_caller(ctx)?;
    let key = idempotency_key(input.idempotency_key.as_deref())?;
    let request = CreateRoleRequest {
        name: input.name,
        description: input.description,
    };
    request.validate()?;
    write_mode(input.consistency.as_deref())?;
    let (role, receipt) = create_role(state(ctx)?, caller, key, request).await?;
    Ok(RoleObject {
        propagation: WriteOutcomeMapper::propagation(&receipt),
        ..RoleObject::from(RoleResponse::from(role))
    })
}

async fn update_role_field(
    ctx: &Context<'_>,
    input: UpdateRoleInput,
) -> Result<RoleObject, Problem> {
    let caller = require_caller(ctx)?;
    let expected = expected_version(input.expected_version)?;
    let id = parse_role_id(input.id.as_str())?;
    let key = idempotency_key(input.idempotency_key.as_deref())?;
    let description = match input.description {
        MaybeUndefined::Undefined => DescriptionUpdate::Keep,
        MaybeUndefined::Null => DescriptionUpdate::Remove,
        MaybeUndefined::Value(text) => DescriptionUpdate::Set(text),
    };
    let request = UpdateRoleRequest {
        name: input.name,
        description: DescriptionPatch(description),
    };
    request.validate()?;
    write_mode(input.consistency.as_deref())?;
    let headers = VersionedWriteHeaders { expected, key };
    let (role, receipt) = update_role(state(ctx)?, caller, id, headers, request).await?;
    Ok(RoleObject {
        propagation: WriteOutcomeMapper::propagation(&receipt),
        ..RoleObject::from(RoleResponse::from(role))
    })
}

async fn role_field(ctx: &Context<'_>, id: &ID) -> Result<Option<RoleObject>, Problem> {
    require_caller(ctx)?;
    let role = find_role(state(ctx)?, parse_role_id(id.as_str())?).await?;
    Ok(role.map(|role| RoleObject::from(RoleResponse::from(role))))
}

async fn roles_field(
    ctx: &Context<'_>,
    params: ListRolesParams,
) -> Result<RolePageObject, Problem> {
    require_caller(ctx)?;
    params.validate()?;
    let page = list_roles(state(ctx)?, params).await?;
    Ok(RolePageObject::from(RolePageResponse::from(page)))
}

#[Object]
impl IamMutation {
    /// Creates a custom role without grants at version 1 and records `iam.role.created`.
    async fn create_role(
        &self,
        ctx: &Context<'_>,
        input: CreateRoleInput,
    ) -> async_graphql::Result<RoleObject> {
        create_role_field(ctx, input)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Registers an upstream at version 1, writes its `upstream/<name>` state record, takes the next policy version and records `iam.upstream.created`. The caller needs `iam:route:{catalogService}` or `iam:route:*`; an upstream of the `iam` service is refused with `CONFLICT`. A repeated `idempotencyKey` with the same input within 24 hours returns the original result.
    async fn create_upstream(
        &self,
        ctx: &Context<'_>,
        input: CreateUpstreamInput,
    ) -> async_graphql::Result<UpstreamObject> {
        create_upstream_field(ctx, input)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Changes the settings named in the input when `expectedVersion` is the current version, increases the version, takes the next policy version and records `iam.upstream.updated`. The name cannot change. The caller needs `iam:route:{catalogService}` or `iam:route:*` for the service before and after the change; a system upstream and one of the `iam` service are refused with `CONFLICT`.
    async fn update_upstream(
        &self,
        ctx: &Context<'_>,
        input: UpdateUpstreamInput,
    ) -> async_graphql::Result<UpstreamObject> {
        update_upstream_field(ctx, input)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Deletes an upstream when `expectedVersion` is the current version and no route references it: its state record becomes a tombstone, the next policy version is committed, and `iam.upstream.deleted` and an audit record are written in the same transaction. An upstream that a route references is refused with `CONFLICT`, and so are a system upstream and one of the `iam` service.
    async fn delete_upstream(
        &self,
        ctx: &Context<'_>,
        input: DeleteUpstreamInput,
    ) -> async_graphql::Result<DeleteUpstreamPayload> {
        delete_upstream_field(ctx, input)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Registers a route of one host, a set of methods and a path pattern that the gateway forwards to an upstream, at version 1, writes its `route/<id>` state record, takes the next policy version and records `iam.route.created`. The caller needs `iam:route:{service}` or `iam:route:*`, and `iam:route:anonymous` to make the route anonymous or audit-only. The route `service` must equal the `catalogService` of its upstream. A route that overlaps another route of its host, or whose candidate route table the gateway could not build, is refused with `CONFLICT`, and so is a route of the `iam` service. A repeated `idempotencyKey` with the same input within 24 hours returns the original result.
    async fn create_route(
        &self,
        ctx: &Context<'_>,
        input: CreateRouteInput,
    ) -> async_graphql::Result<RouteObject> {
        create_route_field(ctx, input)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Changes the members named in the input when `expectedVersion` is the current version, increases the version, takes the next policy version and records `iam.route.updated`. The caller needs `iam:route:{service}` or `iam:route:*` for the service before and after the change, and `iam:route:anonymous` to change `anonymous` or `enforcement`; a system route and one of the `iam` service are refused with `CONFLICT`. A null `cors` removes the CORS policy.
    async fn update_route(
        &self,
        ctx: &Context<'_>,
        input: UpdateRouteInput,
    ) -> async_graphql::Result<RouteObject> {
        update_route_field(ctx, input)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Deletes a route when `expectedVersion` is the current version: its state record becomes a tombstone, the next policy version is committed, and `iam.route.deleted` and an audit record are written in the same transaction. A system route and one of the `iam` service are refused with `CONFLICT`.
    async fn delete_route(
        &self,
        ctx: &Context<'_>,
        input: DeleteRouteInput,
    ) -> async_graphql::Result<DeleteRoutePayload> {
        delete_route_field(ctx, input)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Replaces the full route set of one host atomically when `expectedVersion` is the version that `routeConfiguration` returned: routes of the set that the host lacks are created, routes whose methods and path pattern match a stored route are updated, and stored routes that the set omits are deleted, all in one transaction under one policy version, with their `route/<id>` state records, `iam.route.*` events, `iam.route_configuration.applied` and an audit record. The whole set is validated first: one violation, conflict or route the caller may not write rejects it (`VALIDATION_FAILED`, `CONFLICT`, `FORBIDDEN`), and the candidate route table of the host must build. A set larger than `ROUTE_CONFIGURATION_MAX_ROUTES` routes is refused with `VALIDATION_FAILED`. With `dryRun` the mutation runs every check and returns the diff without writing anything. A set whose diff deletes a route, clears `anonymous` or moves `enforcement` from `audit` to `enforce` is revocation-class. The caller needs `iam:route:{service}` or `iam:route:*` for every service the set touches, and `iam:route:anonymous` to create an anonymous or audit-only route or change either flag.
    async fn apply_route_configuration(
        &self,
        ctx: &Context<'_>,
        input: ApplyRouteConfigurationInput,
    ) -> async_graphql::Result<ApplyRouteConfigurationPayload> {
        apply_route_configuration_field(ctx, input)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Assigns an existing role to a user or a service principal at global or project scope, takes the next policy version and records `iam.user_role.assigned`, and `iam.privileged_role.assigned` as well when the role grants a wildcard or a reserved key.
    async fn assign_user_role(
        &self,
        ctx: &Context<'_>,
        input: AssignUserRoleInput,
    ) -> async_graphql::Result<UserRoleObject> {
        assign_user_role_field(ctx, input)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Sets, extends, shortens or clears the expiry of an assignment when `expectedVersion` is the current version, increases the version, takes the next policy version and records `iam.user_role.updated`. `expiresAt` is required: a time in the future, or null to clear the expiry.
    async fn update_user_role(
        &self,
        ctx: &Context<'_>,
        input: UpdateUserRoleInput,
    ) -> async_graphql::Result<UserRoleObject> {
        update_user_role_field(ctx, input)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Revokes an assignment when `expectedVersion` is the current version: it leaves the active listings at once, the next policy version is committed, and `iam.user_role.revoked` and an audit record are written in the same transaction.
    async fn revoke_user_role(
        &self,
        ctx: &Context<'_>,
        input: RevokeUserRoleInput,
    ) -> async_graphql::Result<RevokeUserRolePayload> {
        revoke_user_role_field(ctx, input)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Renames a custom role or changes its description when `expectedVersion` is the current version, increases the version and records `iam.role.updated`.
    async fn update_role(
        &self,
        ctx: &Context<'_>,
        input: UpdateRoleInput,
    ) -> async_graphql::Result<RoleObject> {
        update_role_field(ctx, input)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Deletes a custom role when `expectedVersion` is the current version and revokes every assignment of it in the same transaction: the role and its assignments leave the active listings at once, the next policy version is committed, and `iam.role.deleted`, one `iam.user_role.revoked` per revoked assignment and the audit records are written. The payload reports the number of revoked assignments.
    async fn delete_role(
        &self,
        ctx: &Context<'_>,
        input: DeleteRoleInput,
    ) -> async_graphql::Result<DeleteRolePayload> {
        delete_role_field(ctx, input)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Creates a rate policy at version 1, takes the next policy version and records `iam.rate_policy.created`. The period `periodMs` is a multiple of 1,000.
    async fn create_rate_policy(
        &self,
        ctx: &Context<'_>,
        input: CreateRatePolicyInput,
    ) -> async_graphql::Result<RatePolicyObject> {
        create_rate_policy_field(ctx, input)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Changes the fields of a rate policy that the input names when `expectedVersion` is the current version, increases the version, takes the next policy version and records `iam.rate_policy.updated`.
    async fn update_rate_policy(
        &self,
        ctx: &Context<'_>,
        input: UpdateRatePolicyInput,
    ) -> async_graphql::Result<RatePolicyObject> {
        update_rate_policy_field(ctx, input)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Deletes a rate policy when `expectedVersion` is the current version and no route references it: the rate policy leaves the listings at once, the next policy version is committed, and `iam.rate_policy.deleted` and an audit record are written. A rate policy that a route references fails with `CONFLICT`.
    async fn delete_rate_policy(
        &self,
        ctx: &Context<'_>,
        input: DeleteRatePolicyInput,
    ) -> async_graphql::Result<DeleteRatePolicyPayload> {
        delete_rate_policy_field(ctx, input)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Replaces the whole grant set of a role when `expectedVersion` is the current version: every key must be in an active catalogue or be one of the four wildcard forms of a service that has a catalogue, and at most 5,000 keys are accepted; unknown keys fail with `VALIDATION_FAILED` and one violation per key. The change increases the version, updates the grant count, takes the next policy version and records `iam.role_permissions.changed` with the added and removed keys; an added wildcard is audited with `coversFutureElements=true`.
    async fn set_role_permissions(
        &self,
        ctx: &Context<'_>,
        input: SetRolePermissionsInput,
    ) -> async_graphql::Result<RoleObject> {
        set_role_permissions_field(ctx, input)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Activates a draft GraphQL specification version and makes its fields grantable permissions: the catalogue of the service becomes the union of its active versions, the next policy version is taken and `iam.graphql_permissions.created` is recorded. An activation that would remove the sensitive or always-audit flag from a key fails with `FLAG_DOWNGRADE_CONFIRMATION_REQUIRED` unless `confirmFlagDowngrade` is true, and one that would orphan grants fails with `ORPHAN_CONFIRMATION_REQUIRED` unless `confirmOrphans` is true. A version that is active already is a no-op.
    async fn create_graphql_permissions(
        &self,
        ctx: &Context<'_>,
        input: CreateGraphQlPermissionsInput,
    ) -> async_graphql::Result<GraphQlPermissionsActivationObject> {
        create_graphql_permissions_field(ctx, input)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Activates a draft `OpenAPI` specification version and makes its operations grantable permissions: the catalogue of the service becomes the union of its active versions, the next policy version is taken and `iam.rest_permissions.created` is recorded. An activation that would remove the sensitive or always-audit flag from a key fails with `FLAG_DOWNGRADE_CONFIRMATION_REQUIRED` unless `confirmFlagDowngrade` is true, and one that would orphan grants fails with `ORPHAN_CONFIRMATION_REQUIRED` unless `confirmOrphans` is true. A version that is active already is a no-op.
    async fn create_rest_permissions(
        &self,
        ctx: &Context<'_>,
        input: CreateRestPermissionsInput,
    ) -> async_graphql::Result<RestPermissionsActivationObject> {
        create_rest_permissions_field(ctx, input)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Resyncs the policy state: republishes the complete current policy as a new log epoch, with versions continuing above the highest version of the state topic, as a bulk operation of kind `resync`, and records `iam.policy.resynced`. `reason` is required. Needs `iam:policy:resync`. Returns the bulk operation; follow it with `bulkOperation(id)` until it is `completed`. A repeated `idempotencyKey` with the same input within 24 hours returns the original operation.
    async fn resync_policy(
        &self,
        ctx: &Context<'_>,
        input: ResyncPolicyInput,
    ) -> async_graphql::Result<BulkOperationObject> {
        resync_policy_field(ctx, input)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Revokes sessions of a user: each listed session gets a revocation record and its state record, the next policy version is committed, and `iam.session.revoked` and an audit record are written in the same transaction. An empty or missing `sessionIds` sets the cut-off of every token of the user to the commit time plus 2 seconds instead and records `iam.user_tokens.cut_off`. Needs `iam:revoke:sessions`. A repeated `idempotencyKey` with the same input within 24 hours returns the original result.
    async fn revoke_sessions(
        &self,
        ctx: &Context<'_>,
        input: RevokeSessionsInput,
    ) -> async_graphql::Result<RevocationPayload> {
        revoke_sessions_field(ctx, input)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Sets the global token cut-off: every token issued before the commit time plus 2 seconds is refused, the next policy version is committed, and `iam.global_tokens.cut_off` and an audit record are written in the same transaction. A cut-off never moves back. Needs `iam:revoke:global`. A repeated `idempotencyKey` within 24 hours returns the original result.
    async fn set_global_token_cutoff(
        &self,
        ctx: &Context<'_>,
        input: SetGlobalTokenCutoffInput,
    ) -> async_graphql::Result<RevocationPayload> {
        set_global_token_cutoff_field(ctx, input)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Retires an active GraphQL specification version: its fields leave the catalogue of the service unless another active version holds them, the next policy version is taken and `iam.graphql_spec.retired` is recorded. A retirement that would orphan grants fails with `ORPHAN_CONFIRMATION_REQUIRED` unless `confirmOrphans` is true; with the confirmation the grants become inactive and `iam.permissions.orphaned` is recorded.
    async fn retire_graphql_spec(
        &self,
        ctx: &Context<'_>,
        input: RetireGraphQlSpecInput,
    ) -> async_graphql::Result<SpecRetirementObject> {
        retire_graphql_spec_field(ctx, input)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Retires an active `OpenAPI` specification version: its operations leave the catalogue of the service unless another active version holds them, the next policy version is taken and `iam.openapi_spec.retired` is recorded. A retirement that would orphan grants fails with `ORPHAN_CONFIRMATION_REQUIRED` unless `confirmOrphans` is true; with the confirmation the grants become inactive and `iam.permissions.orphaned` is recorded.
    async fn retire_openapi_spec(
        &self,
        ctx: &Context<'_>,
        input: RetireOpenApiSpecInput,
    ) -> async_graphql::Result<SpecRetirementObject> {
        retire_openapi_spec_field(ctx, input)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Loads the SDL of a service as a draft version and returns it with its diff against the active versions; an SDL that the service already holds returns its version and changes nothing. The service `iam` is reserved.
    async fn load_graphql_spec(
        &self,
        ctx: &Context<'_>,
        input: LoadGraphQlSpecInput,
    ) -> async_graphql::Result<GraphQlSpecObject> {
        load_graphql_spec_field(ctx, input)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Loads the `OpenAPI` document of a service as a draft version and returns it with its diff against the active versions; a document that the service already holds returns its version and changes nothing. The service `iam` is reserved.
    async fn load_openapi_spec(
        &self,
        ctx: &Context<'_>,
        input: LoadOpenApiSpecInput,
    ) -> async_graphql::Result<OpenApiSpecObject> {
        load_openapi_spec_field(ctx, input)
            .await
            .map_err(iam_problem_to_graphql_error)
    }
}

#[Object]
impl IamQuery {
    /// Retrieves a role by id; null when it is unknown or deleted.
    async fn role(&self, ctx: &Context<'_>, id: ID) -> async_graphql::Result<Option<RoleObject>> {
        role_field(ctx, &id)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Retrieves an upstream by id; null when it is unknown or deleted.
    async fn upstream(
        &self,
        ctx: &Context<'_>,
        id: ID,
    ) -> async_graphql::Result<Option<UpstreamObject>> {
        upstream_field(ctx, &id)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Retrieves one page of the upstreams that are not deleted, in a stable order.
    #[graphql(complexity = "page_complexity(first, child_complexity)")]
    async fn upstreams(
        &self,
        ctx: &Context<'_>,
        #[graphql(default = 30, desc = "Page size, from 1 to 100.")] first: Option<i32>,
        #[graphql(desc = "The nextCursor of the previous page.")] after: Option<String>,
    ) -> async_graphql::Result<UpstreamPageObject> {
        upstreams_field(ctx, first, after)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Retrieves a route by id; null when it is unknown or deleted.
    async fn route(&self, ctx: &Context<'_>, id: ID) -> async_graphql::Result<Option<RouteObject>> {
        route_field(ctx, &id)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Retrieves one page of the routes that are not deleted, in a stable order; the filter keeps the routes that match every field given.
    #[graphql(complexity = "page_complexity(first, child_complexity)")]
    async fn routes(
        &self,
        ctx: &Context<'_>,
        #[graphql(default = 30, desc = "Page size, from 1 to 100.")] first: Option<i32>,
        #[graphql(desc = "The nextCursor of the previous page.")] after: Option<String>,
        #[graphql(desc = "Keeps the routes of this host, upstream and catalogue service.")]
        filter: Option<RouteFilterInput>,
    ) -> async_graphql::Result<RoutePageObject> {
        routes_field(ctx, first, after, filter.unwrap_or_default())
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Verifies the security audit hash chain and records the verification in the audit log; the result is valid with the number of records checked, or invalid with the id of the first record where the chain breaks. Needs `iam:audit:read`.
    async fn security_audit_chain_verification(
        &self,
        ctx: &Context<'_>,
        #[graphql(
            desc = "Anchors published as iam.security_audit.anchored, at most 100; the chain is invalid at an anchored record whose hash differs."
        )]
        anchors: Option<Vec<SecurityAuditAnchorInput>>,
    ) -> async_graphql::Result<SecurityAuditChainVerificationObject> {
        security_audit_chain_verification_field(ctx, anchors)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Retrieves an access decision of the gateway by id from the log store and records the read in the audit log; null when the log store holds none. Needs `iam:audit:read`.
    async fn access_decision(
        &self,
        ctx: &Context<'_>,
        id: ID,
    ) -> async_graphql::Result<Option<AccessDecisionObject>> {
        access_decision_field(ctx, &id)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Retrieves one page of the access decisions of the gateway from the log store, newest first, and records the search in the audit log. The filter needs a time range (`from` and `until`, at most `ACCESS_LOG_QUERY_MAX_RANGE` long) and keeps the decisions that match every other field given. A query that exceeds `ACCESS_LOG_QUERY_TIMEOUT` fails with `QUERY_TIMEOUT` and no partial page; a log store that cannot be reached fails with `SERVICE_UNAVAILABLE`. Needs `iam:audit:read`.
    #[graphql(complexity = "access_page_complexity(first, child_complexity)")]
    async fn access_decisions(
        &self,
        ctx: &Context<'_>,
        #[graphql(default = 30, desc = "Page size, from 1 to 500.")] first: Option<i32>,
        #[graphql(desc = "The nextCursor of the previous page.")] after: Option<String>,
        #[graphql(
            desc = "The required time range and the subject, decision, reason, upstream, route and status that the decisions must have."
        )]
        filter: Option<AccessDecisionFilterInput>,
    ) -> async_graphql::Result<AccessDecisionPageObject> {
        access_decisions_field(ctx, first, after, filter.unwrap_or_default())
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Retrieves a security audit record by id and records the read in the audit log; null when it is unknown. Needs `iam:audit:read`.
    async fn security_audit_event(
        &self,
        ctx: &Context<'_>,
        id: ID,
    ) -> async_graphql::Result<Option<SecurityAuditEventObject>> {
        security_audit_event_field(ctx, &id)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Retrieves one page of the security audit records, newest first, and records the search in the audit log; the filter keeps the records that match every field given. Needs `iam:audit:read`.
    #[graphql(complexity = "page_complexity(first, child_complexity)")]
    async fn security_audit_events(
        &self,
        ctx: &Context<'_>,
        #[graphql(default = 30, desc = "Page size, from 1 to 100.")] first: Option<i32>,
        #[graphql(desc = "The nextCursor of the previous page.")] after: Option<String>,
        #[graphql(
            desc = "Keeps the records in a time range, of an actor, an action, a target and an outcome."
        )]
        filter: Option<SecurityAuditEventFilterInput>,
    ) -> async_graphql::Result<SecurityAuditEventPageObject> {
        security_audit_events_field(ctx, first, after, filter.unwrap_or_default())
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Retrieves a session revocation by id with its source and actor; null when it is unknown. Needs `iam:audit:read`.
    async fn session_revocation(
        &self,
        ctx: &Context<'_>,
        id: ID,
    ) -> async_graphql::Result<Option<SessionRevocationObject>> {
        session_revocation_field(ctx, &id)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Retrieves one page of the session revocations, newest first; the filter keeps the revocations that match every field given. Needs `iam:audit:read`.
    #[graphql(complexity = "page_complexity(first, child_complexity)")]
    async fn session_revocations(
        &self,
        ctx: &Context<'_>,
        #[graphql(default = 30, desc = "Page size, from 1 to 100.")] first: Option<i32>,
        #[graphql(desc = "The nextCursor of the previous page.")] after: Option<String>,
        #[graphql(desc = "Keeps the revocations of a user, of a source and in a time range.")]
        filter: Option<SessionRevocationFilterInput>,
    ) -> async_graphql::Result<SessionRevocationPageObject> {
        session_revocations_field(ctx, first, after, filter.unwrap_or_default())
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Retrieves the token cut-off of a user with its source and actor; null when the user has none. Needs `iam:audit:read`.
    async fn user_token_cutoff(
        &self,
        ctx: &Context<'_>,
        user_id: ID,
    ) -> async_graphql::Result<Option<UserTokenCutoffObject>> {
        user_token_cutoff_field(ctx, &user_id)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Retrieves the global token cut-off with its source and actor; null when it was never set. Needs `iam:audit:read`.
    async fn global_token_cutoff(
        &self,
        ctx: &Context<'_>,
    ) -> async_graphql::Result<Option<GlobalTokenCutoffObject>> {
        global_token_cutoff_field(ctx)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Retrieves the route configuration of a host: every route of the host that is not deleted, in the form that `applyRouteConfiguration` accepts, and the version of the set; a host without routes has an empty set.
    async fn route_configuration(
        &self,
        ctx: &Context<'_>,
        host: String,
    ) -> async_graphql::Result<RouteConfigurationObject> {
        route_configuration_field(ctx, &host)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Retrieves a role assignment by id; null when it is unknown or revoked.
    async fn user_role(
        &self,
        ctx: &Context<'_>,
        id: ID,
    ) -> async_graphql::Result<Option<UserRoleObject>> {
        user_role_field(ctx, &id)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Retrieves one page of role assignments that are not revoked, in a stable order, filtered by subject, role, project and expiry.
    async fn user_roles(
        &self,
        ctx: &Context<'_>,
        #[graphql(default = 30, desc = "Page size, from 1 to 100.")] first: Option<i32>,
        #[graphql(desc = "The nextCursor of the previous page.")] after: Option<String>,
        #[graphql(desc = "Only assignments that match the filter.")] filter: Option<
            UserRoleFilterInput,
        >,
    ) -> async_graphql::Result<UserRolePageObject> {
        user_roles_field(ctx, first, after, filter.unwrap_or_default())
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Retrieves a bulk operation by id; null when it is unknown.
    async fn bulk_operation(
        &self,
        ctx: &Context<'_>,
        id: ID,
    ) -> async_graphql::Result<Option<BulkOperationObject>> {
        bulk_operation_field(ctx, &id)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Retrieves one page of bulk operations, oldest first.
    async fn bulk_operations(
        &self,
        ctx: &Context<'_>,
        #[graphql(default = 30, desc = "Page size, from 1 to 100.")] first: Option<i32>,
        #[graphql(desc = "The nextCursor of the previous page.")] after: Option<String>,
    ) -> async_graphql::Result<BulkOperationPageObject> {
        bulk_operations_field(ctx, first, after)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Retrieves the effective permissions of a user: every key and wildcard that its active assignments hold, each with the roles that grant it, its scopes (`all` or project ids), the shortest expiry among the contributing assignments that expire and the policy version the answer was composed at. `projectId` keeps the global assignments and those of the project; `service` keeps the keys and wildcards of the service. A user without assignments has an empty list.
    async fn user_role_permissions(
        &self,
        ctx: &Context<'_>,
        #[graphql(desc = "The user whose permissions are read.")] user_id: ID,
        #[graphql(
            desc = "Only assignments that apply in this project: the global ones and those of the project."
        )]
        project_id: Option<String>,
        #[graphql(desc = "Only keys and wildcards of this service.")] service: Option<String>,
    ) -> async_graphql::Result<UserRolePermissionsObject> {
        user_role_permissions_field(ctx, &user_id, project_id, service)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Retrieves one page of roles in a stable order, filtered by name prefix and kind.
    async fn roles(
        &self,
        ctx: &Context<'_>,
        #[graphql(default = 30, desc = "Page size, from 1 to 100.")] first: Option<i32>,
        #[graphql(desc = "The nextCursor of the previous page.")] after: Option<String>,
        #[graphql(desc = "Only roles that match the filter.")] filter: Option<RoleFilterInput>,
    ) -> async_graphql::Result<RolePageObject> {
        let filter = filter.unwrap_or_default();
        let params = ListRolesParams {
            limit: first.unwrap_or(DEFAULT_PAGE_SIZE),
            after,
            name_prefix: filter.name_prefix,
            kind: filter.kind,
        };
        roles_field(ctx, params)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Retrieves a rate policy by id; null when it is unknown or deleted.
    async fn rate_policy(
        &self,
        ctx: &Context<'_>,
        id: ID,
    ) -> async_graphql::Result<Option<RatePolicyObject>> {
        rate_policy_field(ctx, &id)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Retrieves one page of rate policies in a stable order.
    #[graphql(complexity = "page_complexity(first, child_complexity)")]
    async fn rate_policies(
        &self,
        ctx: &Context<'_>,
        #[graphql(default = 30, desc = "Page size, from 1 to 100.")] first: Option<i32>,
        #[graphql(desc = "The nextCursor of the previous page.")] after: Option<String>,
    ) -> async_graphql::Result<RatePolicyPageObject> {
        rate_policies_field(ctx, first, after)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Retrieves a GraphQL specification version by id; null when it is unknown. The fields `sdl` and `diff` are read only when the query selects them.
    async fn graphql_spec(
        &self,
        ctx: &Context<'_>,
        id: ID,
    ) -> async_graphql::Result<Option<GraphQlSpecObject>> {
        graphql_spec_field(ctx, &id)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Retrieves one page of GraphQL specification versions in a stable order, filtered by service and status.
    #[graphql(complexity = "page_complexity(first, child_complexity)")]
    async fn graphql_specs(
        &self,
        ctx: &Context<'_>,
        #[graphql(default = 30, desc = "Page size, from 1 to 100.")] first: Option<i32>,
        #[graphql(desc = "The nextCursor of the previous page.")] after: Option<String>,
        #[graphql(desc = "Only versions that match the filter.")] filter: Option<
            GraphQlSpecFilterInput,
        >,
    ) -> async_graphql::Result<GraphQlSpecPageObject> {
        graphql_specs_field(ctx, first, after, filter.unwrap_or_default())
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Retrieves an `OpenAPI` specification version by id; null when it is unknown. The fields `document` and `diff` are read only when the query selects them.
    async fn openapi_spec(
        &self,
        ctx: &Context<'_>,
        id: ID,
    ) -> async_graphql::Result<Option<OpenApiSpecObject>> {
        openapi_spec_field(ctx, &id)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Retrieves one page of `OpenAPI` specification versions in a stable order, filtered by service and status.
    #[graphql(complexity = "page_complexity(first, child_complexity)")]
    async fn openapi_specs(
        &self,
        ctx: &Context<'_>,
        #[graphql(default = 30, desc = "Page size, from 1 to 100.")] first: Option<i32>,
        #[graphql(desc = "The nextCursor of the previous page.")] after: Option<String>,
        #[graphql(desc = "Only versions that match the filter.")] filter: Option<
            OpenApiSpecFilterInput,
        >,
    ) -> async_graphql::Result<OpenApiSpecPageObject> {
        openapi_specs_field(ctx, first, after, filter.unwrap_or_default())
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Retrieves a GraphQL permission by id with the active versions that contain its key and the roles that grant it by its exact key; null when it is unknown.
    async fn graphql_permission(
        &self,
        ctx: &Context<'_>,
        id: ID,
    ) -> async_graphql::Result<Option<GraphQlPermissionObject>> {
        graphql_permission_field(ctx, &id)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Retrieves one page of GraphQL permissions in a stable order, filtered by service, type, active state, the sensitive flag and key prefix.
    #[graphql(complexity = "page_complexity(first, child_complexity)")]
    async fn graphql_permissions(
        &self,
        ctx: &Context<'_>,
        #[graphql(default = 30, desc = "Page size, from 1 to 100.")] first: Option<i32>,
        #[graphql(desc = "The nextCursor of the previous page.")] after: Option<String>,
        #[graphql(desc = "Only permissions that match the filter.")] filter: Option<
            GraphQlPermissionFilterInput,
        >,
    ) -> async_graphql::Result<GraphQlPermissionPageObject> {
        graphql_permissions_field(ctx, first, after, filter.unwrap_or_default())
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Retrieves a REST permission by id with the active versions that contain its key and the roles that grant it by its exact key; null when it is unknown.
    async fn rest_permission(
        &self,
        ctx: &Context<'_>,
        id: ID,
    ) -> async_graphql::Result<Option<RestPermissionObject>> {
        rest_permission_field(ctx, &id)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Retrieves one page of REST permissions in a stable order, filtered by service, method, active state, the sensitive flag and path template prefix.
    #[graphql(complexity = "page_complexity(first, child_complexity)")]
    async fn rest_permissions(
        &self,
        ctx: &Context<'_>,
        #[graphql(default = 30, desc = "Page size, from 1 to 100.")] first: Option<i32>,
        #[graphql(desc = "The nextCursor of the previous page.")] after: Option<String>,
        #[graphql(desc = "Only permissions that match the filter.")] filter: Option<
            RestPermissionFilterInput,
        >,
    ) -> async_graphql::Result<RestPermissionPageObject> {
        rest_permissions_field(ctx, first, after, filter.unwrap_or_default())
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Decides whether a subject may perform a REST operation or hold permission keys; a valid request always gets a decision.
    async fn validate_access(
        &self,
        ctx: &Context<'_>,
        input: ValidateAccessInput,
    ) -> async_graphql::Result<AccessValidationObject> {
        validate_access_field(ctx, input)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Decides 1 to 100 checks of the shape of `validateAccess` and returns one decision per input, in the order of the inputs, each with its own `decisionId`; an input that cannot be read is a `deny` with the reason `malformed_operation` and does not fail the others. A batch of no input or of more than 100 fails with `VALIDATION_FAILED`.
    async fn validate_access_batch(
        &self,
        ctx: &Context<'_>,
        inputs: Vec<ValidateAccessInput>,
    ) -> async_graphql::Result<Vec<AccessValidationObject>> {
        validate_access_batch_field(ctx, inputs)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Resolves a User service token into its subject, or says why it is refused.
    async fn resolve_token(
        &self,
        ctx: &Context<'_>,
        input: ResolveTokenInput,
    ) -> async_graphql::Result<TokenResolutionObject> {
        resolve_token(ctx, input)
            .await
            .map_err(iam_problem_to_graphql_error)
    }
}

/// Query root of the gateway's decision API: `validateAccess`, `validateAccessBatch` and
/// `resolveToken`, the same fields as [`IamQuery`] with the same resolvers, and no other.
///
/// A document that selects any other field, a management field such as `createRole` included, is
/// rejected by the schema as an unknown field.
#[derive(Debug, Default)]
pub struct DecisionQuery;

#[Object(name = "Query")]
impl DecisionQuery {
    /// Decides whether a subject may perform a REST operation or hold permission keys; a valid request always gets a decision.
    async fn validate_access(
        &self,
        ctx: &Context<'_>,
        input: ValidateAccessInput,
    ) -> async_graphql::Result<AccessValidationObject> {
        validate_access_field(ctx, input)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Decides 1 to 100 checks of the shape of `validateAccess` and returns one decision per input, in the order of the inputs, each with its own `decisionId`; an input that cannot be read is a `deny` with the reason `malformed_operation` and does not fail the others. A batch of no input or of more than 100 fails with `VALIDATION_FAILED`.
    async fn validate_access_batch(
        &self,
        ctx: &Context<'_>,
        inputs: Vec<ValidateAccessInput>,
    ) -> async_graphql::Result<Vec<AccessValidationObject>> {
        validate_access_batch_field(ctx, inputs)
            .await
            .map_err(iam_problem_to_graphql_error)
    }

    /// Resolves a User service token into its subject, or says why it is refused.
    async fn resolve_token(
        &self,
        ctx: &Context<'_>,
        input: ResolveTokenInput,
    ) -> async_graphql::Result<TokenResolutionObject> {
        resolve_token(ctx, input)
            .await
            .map_err(iam_problem_to_graphql_error)
    }
}

/// The static complexity of a page: its size, clamped to 1 to 100 as the query clamps it, times
/// the complexity of one item.
fn page_complexity(first: Option<i32>, child_complexity: usize) -> usize {
    let size = first.unwrap_or(30).clamp(1, 100);
    usize::try_from(size)
        .unwrap_or(100)
        .saturating_mul(child_complexity)
}

/// The static complexity of a page of access decisions: its size, clamped to 1 to 500 as the query
/// clamps it, times the complexity of one item.
fn access_page_complexity(first: Option<i32>, child_complexity: usize) -> usize {
    let size = first.unwrap_or(30).clamp(1, 500);
    usize::try_from(size)
        .unwrap_or(500)
        .saturating_mul(child_complexity)
}

/// Converts a problem of the IAM context into a GraphQL error.
///
/// Its `extensions.code` follows `architecture.md` section 5.5: the client errors keep their detail (or their title) as the
/// message, a confirmation problem keeps the items it lists as `extensions.violations` (the
/// orphaned grants, for example), a 422 is `VALIDATION_FAILED` with its violations, and every other status is
/// `INTERNAL_SERVER_ERROR` without detail, as the shared `problem_to_error` builds them.
#[must_use]
pub fn iam_problem_to_graphql_error(problem: Problem) -> Error {
    let Some(code) = confirmation_code(problem.r#type).or_else(|| client_code(problem.status))
    else {
        return problem_to_error(problem);
    };
    let message = problem.detail.unwrap_or_else(|| problem.title.to_owned());
    let violations = problem.violations;
    Error::new(message).extend_with(|_error, extensions| {
        extensions.set("code", code);
        if !violations.is_empty() {
            extensions.set("violations", violations_value(violations));
        }
    })
}

/// The GraphQL code of the 409 problem that asks for a confirmation; none for any other type.
fn confirmation_code(problem_type: &str) -> Option<&'static str> {
    match problem_type {
        TYPE_FLAG_DOWNGRADE_CONFIRMATION => Some("FLAG_DOWNGRADE_CONFIRMATION_REQUIRED"),
        TYPE_ORPHAN_CONFIRMATION => Some("ORPHAN_CONFIRMATION_REQUIRED"),
        TYPE_LAST_ADMINISTRATOR => Some("LAST_ADMINISTRATOR"),
        _ => None,
    }
}

/// The GraphQL code of an IAM client error status; none for 422 and the server errors that the
/// shared conversion handles.
const fn client_code(status: u16) -> Option<&'static str> {
    match status {
        401 => Some("UNAUTHENTICATED"),
        403 => Some("FORBIDDEN"),
        404 => Some("NOT_FOUND"),
        409 => Some("CONFLICT"),
        412 => Some("PRECONDITION_FAILED"),
        428 => Some("PRECONDITION_REQUIRED"),
        503 => Some("SERVICE_UNAVAILABLE"),
        504 => Some("QUERY_TIMEOUT"),
        _ => None,
    }
}

/// The entity version that the `expectedVersion` field of an update or delete input names.
///
/// It is [`IamError::PreconditionRequired`] when the field is absent and
/// [`IamError::PreconditionFailed`] when it is below 1 and so matches no version, the GraphQL
/// counterparts of a missing and an unmatched `If-Match`.
///
/// # Errors
///
/// As above.
pub fn expected_version(field: Option<i64>) -> Result<EntityVersion, IamError> {
    let value = field.ok_or(IamError::PreconditionRequired)?;
    EntityVersion::new(value).map_err(|_error| IamError::PreconditionFailed)
}

#[cfg(test)]
mod tests;
