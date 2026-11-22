//! GraphQL adapter of the IAM context: the query and mutation roots, the conversion of IAM problems
//! to GraphQL errors and the `expectedVersion` rule of the update and delete inputs.
//!
//! [`IamQuery`] holds the token-resolution query and the composition root merges it into the schema
//! root. [`IamMutation`] has no field yet: an object type without fields is not valid GraphQL, and
//! the `Object` macro of `async-graphql` refuses one at compile time, so it stays a plain type until
//! the first IAM mutation gives it its `#[Object]` implementation and the composition root merges
//! it too.
//!
//! The resolvers share the use-case calls of the REST handlers and the REST DTOs, so both
//! transports apply one set of rules; every failure becomes a problem first and a GraphQL error
//! second.

use async_graphql::{Context, Error, ErrorExtensions as _, InputObject, Object, SimpleObject};
use iam_domain::EntityVersion;
use shared_application::graphql::problem_to_error;
use shared_application::http::Problem;
use validator::Validate as _;

use crate::error::IamError;
use crate::http::IamState;
use crate::http::dto::{TokenResolutionRequest, TokenResolutionResponse};
use crate::http::handler::resolve_credential;
use crate::principal::Principal;

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

/// The schema was built without the `IamState` data.
#[derive(Debug, thiserror::Error)]
#[error("the GraphQL schema has no IamState data")]
struct MissingState;

fn state<'ctx>(ctx: &Context<'ctx>) -> Result<&'ctx IamState, Problem> {
    ctx.data::<IamState>()
        .map_err(|_error| Problem::internal(&MissingState))
}

/// Refuses the request unless the authentication middleware resolved a valid caller token.
fn require_caller(ctx: &Context<'_>) -> Result<(), Problem> {
    let authenticated = ctx
        .data_opt::<Option<Principal>>()
        .is_some_and(Option::is_some);
    if authenticated {
        Ok(())
    } else {
        Err(Problem::from(IamError::Unauthenticated))
    }
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

#[Object]
impl IamQuery {
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
