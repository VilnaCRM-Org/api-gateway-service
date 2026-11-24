//! GraphQL objects and the resolvers that read session revocations and token cut-offs (FR-81).
//!
//! The resolvers share the use-case calls and the response shapes of the REST handlers, so both
//! transports apply one set of rules.

use async_graphql::{Context, ID, InputObject, SimpleObject};
use shared_application::http::Problem;
use validator::Validate as _;

use super::{require_caller, state};
use crate::http::dto::DEFAULT_PAGE_SIZE;
use crate::http::revocation_read::dto::{
    GlobalTokenCutoffResponse, ListSessionRevocationsParams, SessionRevocationPageResponse,
    SessionRevocationResponse, UserTokenCutoffResponse, parse_user,
};
use crate::http::revocation_read::{
    find_global_token_cutoff, find_session_revocation, find_user_token_cutoff,
    list_session_revocations, parse_session_revocation_id,
};

/// One revoked session with the source and the actor of its revocation.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "SessionRevocation")]
pub struct SessionRevocationObject {
    /// The identifier of the revocation.
    pub id: ID,
    /// The revoked session.
    pub session_id: String,
    /// The user the session belongs to.
    pub user_id: ID,
    /// Who caused the revocation: `user-service` or `operator`.
    pub source: String,
    /// The actor that recorded the revocation: `user:<uuid>`, `service:<name>` or `system:<component>`.
    pub actor: String,
    /// When the revocation was recorded, as an RFC 3339 UTC time.
    pub revoked_at: String,
}

impl From<SessionRevocationResponse> for SessionRevocationObject {
    fn from(response: SessionRevocationResponse) -> Self {
        Self {
            id: ID::from(response.id),
            session_id: response.session_id,
            user_id: ID::from(response.user_id),
            source: response.source,
            actor: response.actor,
            revoked_at: response.revoked_at,
        }
    }
}

/// One page of session revocations.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "SessionRevocationPage")]
pub struct SessionRevocationPageObject {
    /// The revocations of the page, newest first.
    pub items: Vec<SessionRevocationObject>,
    /// The `after` value of the next, older page; null on the last page.
    pub next_cursor: Option<String>,
}

impl From<SessionRevocationPageResponse> for SessionRevocationPageObject {
    fn from(page: SessionRevocationPageResponse) -> Self {
        Self {
            items: page
                .items
                .into_iter()
                .map(SessionRevocationObject::from)
                .collect(),
            next_cursor: page.next_cursor,
        }
    }
}

/// The cut-off of the tokens of one user.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "UserTokenCutoff")]
pub struct UserTokenCutoffObject {
    /// The user.
    pub user_id: ID,
    /// Tokens issued at or before this RFC 3339 UTC time are refused.
    pub tokens_valid_after: String,
    /// Who caused the cut-off: `user-service` or `operator`.
    pub source: String,
    /// The actor that set the cut-off: `system:user-service` for a cut-off of a User service event and the actor of the audit record for an operator cut-off; null when the audit log holds no record of it.
    pub actor: Option<String>,
    /// When the cut-off was last moved, as an RFC 3339 UTC time.
    pub updated_at: String,
}

impl From<UserTokenCutoffResponse> for UserTokenCutoffObject {
    fn from(response: UserTokenCutoffResponse) -> Self {
        Self {
            user_id: ID::from(response.user_id),
            tokens_valid_after: response.tokens_valid_after,
            source: response.source,
            actor: response.actor,
            updated_at: response.updated_at,
        }
    }
}

/// The cut-off of every token.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "GlobalTokenCutoff")]
pub struct GlobalTokenCutoffObject {
    /// Tokens issued at or before this RFC 3339 UTC time are refused.
    pub tokens_valid_after: String,
    /// Who caused the cut-off; the global cut-off is always set by an operator.
    pub source: String,
    /// The actor that set the cut-off: `user:<uuid>`, `service:<name>` or `system:<component>`.
    pub actor: String,
    /// When the cut-off was set, as an RFC 3339 UTC time.
    pub set_at: String,
}

impl From<GlobalTokenCutoffResponse> for GlobalTokenCutoffObject {
    fn from(response: GlobalTokenCutoffResponse) -> Self {
        Self {
            tokens_valid_after: response.tokens_valid_after,
            source: response.source,
            actor: response.actor,
            set_at: response.set_at,
        }
    }
}

/// The filters of the session revocation list: a revocation must meet every one that is given.
#[derive(Debug, Default, InputObject)]
#[graphql(name = "SessionRevocationFilterInput")]
pub struct SessionRevocationFilterInput {
    /// Only the revocations of the sessions of this user.
    pub user_id: Option<ID>,
    /// Only the revocations that this source caused: `user-service` or `operator`.
    pub source: Option<String>,
    /// Only the revocations from this RFC 3339 UTC time on.
    pub from: Option<String>,
    /// Only the revocations before this RFC 3339 UTC time.
    pub until: Option<String>,
}

/// Reads one session revocation as the caller of the request; null when it is unknown.
pub(super) async fn session_revocation_field(
    ctx: &Context<'_>,
    id: &ID,
) -> Result<Option<SessionRevocationObject>, Problem> {
    require_caller(ctx)?;
    let id = parse_session_revocation_id(id.as_str())?;
    let revocation = find_session_revocation(state(ctx)?, id).await?;
    Ok(revocation.map(|revocation| {
        SessionRevocationObject::from(SessionRevocationResponse::from(&revocation))
    }))
}

/// Lists the session revocations as the caller of the request.
pub(super) async fn session_revocations_field(
    ctx: &Context<'_>,
    first: Option<i32>,
    after: Option<String>,
    filter: SessionRevocationFilterInput,
) -> Result<SessionRevocationPageObject, Problem> {
    require_caller(ctx)?;
    let params = ListSessionRevocationsParams {
        limit: Some(first.unwrap_or(DEFAULT_PAGE_SIZE)),
        after,
        user_id: filter.user_id.map(|id| id.to_string()),
        source: filter.source,
        from: filter.from,
        until: filter.until,
    };
    params.validate()?;
    let page = list_session_revocations(state(ctx)?, params).await?;
    Ok(SessionRevocationPageObject::from(
        SessionRevocationPageResponse::from(&page),
    ))
}

/// Reads the token cut-off of a user as the caller of the request; null when the user has none.
pub(super) async fn user_token_cutoff_field(
    ctx: &Context<'_>,
    user_id: &ID,
) -> Result<Option<UserTokenCutoffObject>, Problem> {
    require_caller(ctx)?;
    let user = parse_user("userId", user_id.as_str())?;
    let view = find_user_token_cutoff(state(ctx)?, user).await?;
    Ok(view.map(|view| UserTokenCutoffObject::from(UserTokenCutoffResponse::from(&view))))
}

/// Reads the global token cut-off as the caller of the request; null when it was never set.
pub(super) async fn global_token_cutoff_field(
    ctx: &Context<'_>,
) -> Result<Option<GlobalTokenCutoffObject>, Problem> {
    require_caller(ctx)?;
    let cutoff = find_global_token_cutoff(state(ctx)?).await?;
    Ok(
        cutoff
            .map(|cutoff| GlobalTokenCutoffObject::from(GlobalTokenCutoffResponse::from(&cutoff))),
    )
}
