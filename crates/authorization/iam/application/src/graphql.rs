//! GraphQL adapter of the IAM context: the query and mutation roots, the conversion of IAM problems
//! to GraphQL errors and the `expectedVersion` rule of the update and delete inputs.
//!
//! [`IamQuery`] holds the token-resolution and role queries and [`IamMutation`] the role mutation;
//! the composition root merges both into the schema roots.
//!
//! The resolvers share the use-case calls of the REST handlers and the REST DTOs, so both
//! transports apply one set of rules; every failure becomes a problem first and a GraphQL error
//! second.

pub mod schema_parser;

use async_graphql::{Context, Error, ErrorExtensions as _, ID, InputObject, Object, SimpleObject};
use iam_domain::{EntityVersion, IdempotencyKey};
use shared_application::graphql::problem_to_error;
use shared_application::http::{Problem, Violation};
use validator::Validate as _;

use crate::error::IamError;
use crate::http::IamState;
use crate::http::dto::{
    CreateRoleRequest, DEFAULT_PAGE_SIZE, ListRolesParams, RolePageResponse, RoleResponse,
    TokenResolutionRequest, TokenResolutionResponse,
};
use crate::http::handler::resolve_credential;
use crate::http::role::{create_role, find_role, list_roles, parse_role_id};
use crate::principal::Principal;

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
#[graphql(name = "Role")]
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
        }
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
    let (role, _receipt) = create_role(state(ctx)?, caller, key, request).await?;
    Ok(RoleObject::from(RoleResponse::from(role)))
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
}

#[Object]
impl IamQuery {
    /// Retrieves a role by id; null when it is unknown or deleted.
    async fn role(&self, ctx: &Context<'_>, id: ID) -> async_graphql::Result<Option<RoleObject>> {
        role_field(ctx, &id)
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

/// Converts a problem of the IAM context into a GraphQL error.
///
/// Its `extensions.code` follows `architecture.md` section 5.5: the client errors keep their detail (or their title) as the
/// message, a 422 is `VALIDATION_FAILED` with its violations, and every other status is
/// `INTERNAL_SERVER_ERROR` without detail, as the shared `problem_to_error` builds them.
#[must_use]
pub fn iam_problem_to_graphql_error(problem: Problem) -> Error {
    let Some(code) = client_code(problem.status) else {
        return problem_to_error(problem);
    };
    let message = problem.detail.unwrap_or_else(|| problem.title.to_owned());
    Error::new(message).extend_with(|_error, extensions| extensions.set("code", code))
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
