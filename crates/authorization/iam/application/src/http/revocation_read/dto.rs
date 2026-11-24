//! Wire shapes of the reads of session revocations and token cut-offs (FR-81).
//!
//! The list parameters keep their schema constraints and their validator attributes on the same
//! field so that both stay equal; the values that the domain owns are checked when the query is
//! built, which reports the first violation.

use std::time::SystemTime;

use iam_domain::{GlobalTokenCutoff, RevocationSource, SessionRevocation, SessionRevocationId};
use serde::{Deserialize, Serialize};
use shared_domain::Uuid;
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

use crate::error::IamError;
use crate::http::dto::DEFAULT_PAGE_SIZE;
use crate::query::get_user_token_cutoff::UserTokenCutoffView;
use crate::query::list_session_revocations::{ListSessionRevocationsQuery, SessionRevocationPage};

/// One revoked session with the source and the actor of its revocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = SessionRevocation)]
pub struct SessionRevocationResponse {
    /// The identifier of the revocation.
    #[schema(format = Uuid)]
    pub id: String,
    /// The revoked session.
    pub session_id: String,
    /// The user the session belongs to.
    #[schema(format = Uuid)]
    pub user_id: String,
    /// Who caused the revocation: `user-service` or `operator`.
    #[schema(example = "operator")]
    pub source: String,
    /// The actor that recorded the revocation: `user:<uuid>`, `service:<name>` or
    /// `system:<component>`.
    #[schema(example = "user:0190f2a8-7b3c-7d4e-8f10-1234567890ab")]
    pub actor: String,
    /// When the revocation was recorded, as an RFC 3339 UTC time.
    #[schema(format = DateTime, example = "2026-11-23T10:15:30.123456Z")]
    pub revoked_at: String,
}

impl From<&SessionRevocation> for SessionRevocationResponse {
    fn from(revocation: &SessionRevocation) -> Self {
        Self {
            id: revocation.id.to_string(),
            session_id: revocation.session.as_str().to_owned(),
            user_id: revocation.user.to_string(),
            source: revocation.source.as_str().to_owned(),
            actor: revocation.revoked_by.to_string(),
            revoked_at: time_text(revocation.revoked_at),
        }
    }
}

/// One page of session revocations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = SessionRevocationPage)]
pub struct SessionRevocationPageResponse {
    /// The revocations of the page, newest first.
    pub items: Vec<SessionRevocationResponse>,
    /// The `after` value of the next, older page; absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(format = Uuid)]
    pub next_cursor: Option<String>,
}

impl From<&SessionRevocationPage> for SessionRevocationPageResponse {
    fn from(page: &SessionRevocationPage) -> Self {
        Self {
            items: page
                .revocations
                .iter()
                .map(SessionRevocationResponse::from)
                .collect(),
            next_cursor: page.next_after.map(|id| id.to_string()),
        }
    }
}

/// The cut-off of the tokens of one user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = UserTokenCutoff)]
pub struct UserTokenCutoffResponse {
    /// The user.
    #[schema(format = Uuid)]
    pub user_id: String,
    /// Tokens issued at or before this RFC 3339 UTC time are refused.
    #[schema(format = DateTime, example = "2026-11-23T10:15:32.000000Z")]
    pub tokens_valid_after: String,
    /// Who caused the cut-off: `user-service` or `operator`.
    #[schema(example = "operator")]
    pub source: String,
    /// The actor that set the cut-off: `system:user-service` for a cut-off of a User service
    /// event and the actor of the audit record for an operator cut-off; absent when the audit
    /// log holds no record of it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// When the cut-off was last moved, as an RFC 3339 UTC time.
    #[schema(format = DateTime, example = "2026-11-23T10:15:30.123456Z")]
    pub updated_at: String,
}

impl From<&UserTokenCutoffView> for UserTokenCutoffResponse {
    fn from(view: &UserTokenCutoffView) -> Self {
        let cutoff = &view.cutoff;
        Self {
            user_id: cutoff.user.to_string(),
            tokens_valid_after: time_text(cutoff.tokens_valid_after),
            source: cutoff.source.as_str().to_owned(),
            actor: view.actor.as_ref().map(ToString::to_string),
            updated_at: time_text(cutoff.updated_at),
        }
    }
}

/// The cut-off of every token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = GlobalTokenCutoff)]
pub struct GlobalTokenCutoffResponse {
    /// Tokens issued at or before this RFC 3339 UTC time are refused.
    #[schema(format = DateTime, example = "2026-11-23T10:15:32.000000Z")]
    pub tokens_valid_after: String,
    /// Who caused the cut-off; the global cut-off is always set by an operator.
    #[schema(example = "operator")]
    pub source: String,
    /// The actor that set the cut-off: `user:<uuid>`, `service:<name>` or `system:<component>`.
    #[schema(example = "user:0190f2a8-7b3c-7d4e-8f10-1234567890ab")]
    pub actor: String,
    /// When the cut-off was set, as an RFC 3339 UTC time.
    #[schema(format = DateTime, example = "2026-11-23T10:15:30.123456Z")]
    pub set_at: String,
}

impl From<&GlobalTokenCutoff> for GlobalTokenCutoffResponse {
    fn from(cutoff: &GlobalTokenCutoff) -> Self {
        Self {
            tokens_valid_after: time_text(cutoff.tokens_valid_after),
            source: RevocationSource::Operator.as_str().to_owned(),
            actor: cutoff.set_by.to_string(),
            set_at: time_text(cutoff.set_at),
        }
    }
}

/// Query parameters of the session revocation list; `limit` is signed so that a negative value is
/// a 422, not a parse error.
#[derive(Debug, Clone, Default, Deserialize, IntoParams, Validate)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct ListSessionRevocationsParams {
    /// The largest number of revocations of the page; 30 when absent.
    #[param(minimum = 1, maximum = 100, default = 30)]
    #[validate(range(min = 1, max = 100, message = "This value must be between 1 and 100."))]
    pub limit: Option<i32>,
    /// The `nextCursor` of the previous page; absent for the first page.
    #[param(format = Uuid)]
    pub after: Option<String>,
    /// Only the revocations of the sessions of this user.
    #[param(format = Uuid)]
    pub user_id: Option<String>,
    /// Only the revocations that this source caused: `user-service` or `operator`.
    pub source: Option<String>,
    /// Only the revocations from this RFC 3339 UTC time on.
    #[param(format = DateTime)]
    pub from: Option<String>,
    /// Only the revocations before this RFC 3339 UTC time.
    #[param(format = DateTime)]
    pub until: Option<String>,
}

impl ListSessionRevocationsParams {
    /// The query for these parameters; call it after validation, which makes `limit` positive.
    ///
    /// # Errors
    ///
    /// [`IamError::Invalid`] with a violation of the first parameter that is not valid.
    pub fn into_query(self) -> Result<ListSessionRevocationsQuery, IamError> {
        let after = self
            .after
            .as_deref()
            .map(|text| SessionRevocationId::parse(text).map_err(|_error| uuid_violation("after")))
            .transpose()?;
        let user = self
            .user_id
            .as_deref()
            .map(|text| parse_user("userId", text))
            .transpose()?;
        let source = self
            .source
            .as_deref()
            .map(|text| {
                RevocationSource::parse(text).map_err(|_error| {
                    IamError::invalid_property(
                        "source",
                        "This value must be user-service or operator.",
                        "choice",
                    )
                })
            })
            .transpose()?;
        let from = self
            .from
            .as_deref()
            .map(|text| bound("from", text))
            .transpose()?;
        let until = self
            .until
            .as_deref()
            .map(|text| bound("until", text))
            .transpose()?;
        Ok(ListSessionRevocationsQuery {
            limit: self.limit.unwrap_or(DEFAULT_PAGE_SIZE).unsigned_abs(),
            after,
            user,
            source,
            from,
            until,
        })
    }
}

/// The user that a path segment or an argument names.
///
/// # Errors
///
/// [`IamError::Invalid`] with a violation of `property` when the text is not a UUID.
pub(crate) fn parse_user(property: &str, text: &str) -> Result<Uuid, IamError> {
    Uuid::parse(text).map_err(|_error| uuid_violation(property))
}

/// The violation of a value that is not a UUID.
fn uuid_violation(property: &str) -> IamError {
    IamError::invalid_property(property, "This value is not a valid UUID.", "uuid")
}

/// A bound of the time range, an RFC 3339 UTC time not before 1970.
fn bound(property: &str, text: &str) -> Result<SystemTime, IamError> {
    humantime::parse_rfc3339(text)
        .ok()
        .filter(|time| time.duration_since(SystemTime::UNIX_EPOCH).is_ok())
        .ok_or_else(|| {
            IamError::invalid_property(
                property,
                "This value must be an RFC 3339 UTC time such as 2026-11-23T08:00:00Z.",
                "format",
            )
        })
}

/// A time as an RFC 3339 UTC text with microseconds.
fn time_text(time: SystemTime) -> String {
    humantime::format_rfc3339_micros(time).to_string()
}

#[cfg(test)]
mod tests;
