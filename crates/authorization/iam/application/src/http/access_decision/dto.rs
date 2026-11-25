//! Wire shapes of the access decisions of the IAM context.
//!
//! The list parameters keep their schema constraints and their validator attributes on the same
//! field so that both stay equal; the values that the domain owns are checked when the query is
//! built, which reports the first violation.

use std::time::SystemTime;

use iam_domain::{
    AccessDecision, AccessLogCursor, AccessLogEntry, AccessLogFilter, ActorRef, DecisionReason,
    SubjectKind,
};
use serde::{Deserialize, Serialize};
use shared_domain::Uuid;
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

use crate::error::IamError;
use crate::http::dto::DEFAULT_PAGE_SIZE;
use crate::query::get_access_decisions::{AccessDecisionPage, GetAccessDecisionsQuery};

/// One access decision of the gateway.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = AccessDecision)]
pub struct AccessDecisionResponse {
    /// The identifier of the decision, a UUID v7.
    #[schema(format = Uuid)]
    pub id: String,
    /// When the decision was made, as an RFC 3339 UTC time.
    #[schema(format = DateTime, example = "2026-11-23T10:15:30.123456Z")]
    pub occurred_at: String,
    /// The HTTP method of the request.
    #[schema(example = "GET")]
    pub method: String,
    /// The host of the request.
    pub host: String,
    /// The matched route.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(format = Uuid)]
    pub route_id: Option<String>,
    /// The path template of the matched route; never the concrete path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_template: Option<String>,
    /// The status of the answer.
    #[schema(example = 403)]
    pub status: u16,
    /// The registered name of the upstream.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream: Option<String>,
    /// Microseconds from the receipt of the request to the end of the response.
    pub latency_us: u64,
    /// The bytes of the request body that were announced.
    pub bytes_in: u64,
    /// The bytes of the response body that were announced.
    pub bytes_out: u64,
    /// The request id of the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// The subject that the token proved; absent without a valid token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,
    /// The kind of the subject: `user` or `service`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_kind: Option<String>,
    /// The kind of the decision: `allow`, `deny` or `error`.
    #[schema(example = "deny")]
    pub decision: String,
    /// The reason code of the decision.
    #[schema(example = "permission_missing")]
    pub reason: String,
    /// The permission key the operation required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permission_key: Option<String>,
    /// The keys that were denied, for a denial.
    pub denied: Vec<String>,
    /// The project of the request, when it names one.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(format = Uuid)]
    pub project_id: Option<String>,
    /// The version of the policy snapshot that decided.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<i64>,
}

impl From<&AccessLogEntry> for AccessDecisionResponse {
    fn from(entry: &AccessLogEntry) -> Self {
        let record = &entry.record;
        Self {
            id: record.decision_id.to_string(),
            occurred_at: humantime::format_rfc3339_micros(record.occurred_at).to_string(),
            method: record.method.clone(),
            host: record.host.clone(),
            route_id: record.route_id.map(|id| id.to_string()),
            route_template: record.route_template.clone(),
            status: record.status,
            upstream: record.upstream.clone(),
            latency_us: record.latency_us,
            bytes_in: record.bytes_in,
            bytes_out: record.bytes_out,
            request_id: record.request_id.clone(),
            subject_id: record.subject_id.clone(),
            subject_kind: record.subject_kind.map(|kind| kind.as_str().to_owned()),
            decision: record.decision.as_str().to_owned(),
            reason: record.reason.as_str().to_owned(),
            permission_key: record.permission_key.clone(),
            denied: record.denied.clone(),
            project_id: record.project_id.map(|id| id.to_string()),
            policy_version: record.policy_version,
        }
    }
}

/// One page of access decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = AccessDecisionPage)]
pub struct AccessDecisionPageResponse {
    /// The decisions of the page, newest first.
    pub items: Vec<AccessDecisionResponse>,
    /// The `after` value of the next, older page; absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

impl From<&AccessDecisionPage> for AccessDecisionPageResponse {
    fn from(page: &AccessDecisionPage) -> Self {
        Self {
            items: page
                .entries
                .iter()
                .map(AccessDecisionResponse::from)
                .collect(),
            next_cursor: page.next.map(AccessLogCursor::encode),
        }
    }
}

/// Query parameters of the access decision search; `limit` is signed so that a negative value is
/// a 422, not a parse error, and `status` is signed for the same reason.
#[derive(Debug, Clone, Default, Deserialize, IntoParams, Validate)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct ListAccessDecisionsParams {
    /// The largest number of decisions of the page; 30 when absent.
    #[param(minimum = 1, maximum = 500, default = 30)]
    #[validate(range(min = 1, max = 500, message = "This value must be between 1 and 500."))]
    pub limit: Option<i32>,
    /// The `nextCursor` of the previous page; absent for the first page.
    pub after: Option<String>,
    /// The decisions from this RFC 3339 UTC time on; required.
    #[param(format = DateTime)]
    pub from: Option<String>,
    /// The decisions before this RFC 3339 UTC time; required, and at most
    /// `ACCESS_LOG_QUERY_MAX_RANGE` after `from`.
    #[param(format = DateTime)]
    pub until: Option<String>,
    /// Only the decisions about this subject: a user id or a service name.
    pub subject_id: Option<String>,
    /// Only the decisions about subjects of this kind: `user` or `service`.
    pub subject_kind: Option<String>,
    /// Only the decisions of this kind: `allow`, `deny` or `error`.
    pub decision: Option<String>,
    /// Only the decisions with this reason code, such as `permission_missing`.
    pub reason: Option<String>,
    /// Only the decisions that went to this upstream.
    pub upstream: Option<String>,
    /// Only the decisions of this route.
    #[param(format = Uuid)]
    pub route_id: Option<String>,
    /// Only the decisions with this response status.
    #[param(minimum = 100, maximum = 599)]
    #[validate(range(
        min = 100,
        max = 599,
        message = "This value must be between 100 and 599."
    ))]
    pub status: Option<i32>,
}

impl ListAccessDecisionsParams {
    /// The query for these parameters, asked by `caller`; call it after validation, which makes
    /// `limit` and `status` positive.
    ///
    /// # Errors
    ///
    /// [`IamError::Invalid`] with a violation of the first parameter that is not valid.
    pub fn into_query(self, caller: ActorRef) -> Result<GetAccessDecisionsQuery, IamError> {
        let cursor = self.after.as_deref().map(cursor).transpose()?;
        let from = bound("from", self.from.as_deref())?;
        let until = bound("until", self.until.as_deref())?;
        let filter = self.filter()?;
        Ok(GetAccessDecisionsQuery {
            actor: caller,
            from,
            until,
            filter,
            limit: self.limit.unwrap_or(DEFAULT_PAGE_SIZE).unsigned_abs(),
            cursor,
        })
    }

    /// The conditions of the parameters on the structured fields of a decision.
    fn filter(&self) -> Result<AccessLogFilter, IamError> {
        Ok(AccessLogFilter {
            subject_id: non_empty("subjectId", self.subject_id.as_deref())?,
            subject_kind: self.subject_kind.as_deref().map(subject_kind).transpose()?,
            decision: self.decision.as_deref().map(decision).transpose()?,
            reason: self.reason.as_deref().map(reason).transpose()?,
            upstream: non_empty("upstream", self.upstream.as_deref())?,
            route_id: self.route_id.as_deref().map(route_id).transpose()?,
            status: self.status.and_then(|status| u16::try_from(status).ok()),
        })
    }
}

/// The kind of subject that a text names.
fn subject_kind(text: &str) -> Result<SubjectKind, IamError> {
    SubjectKind::parse(text).map_err(|_error| {
        IamError::invalid_property("subjectKind", "This value must be user or service.", "enum")
    })
}

/// The kind of decision that a text names.
fn decision(text: &str) -> Result<AccessDecision, IamError> {
    AccessDecision::parse(text).ok_or_else(|| {
        IamError::invalid_property(
            "decision",
            "This value must be allow, deny or error.",
            "enum",
        )
    })
}

/// The reason code that a text names.
fn reason(text: &str) -> Result<DecisionReason, IamError> {
    DecisionReason::parse(text).ok_or_else(|| {
        IamError::invalid_property("reason", "This value is not a known reason code.", "enum")
    })
}

/// The cursor that a text names.
fn cursor(text: &str) -> Result<AccessLogCursor, IamError> {
    AccessLogCursor::parse(text).ok_or_else(|| {
        IamError::invalid_property("after", "This value is not a valid cursor.", "format")
    })
}

/// A bound of the time range: required, an RFC 3339 UTC time not before 1970.
fn bound(property: &str, text: Option<&str>) -> Result<SystemTime, IamError> {
    let text = text.ok_or_else(|| {
        IamError::invalid_property(property, "This value is required.", "required")
    })?;
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

/// A text filter that must not be empty or hold control characters.
fn non_empty(property: &str, text: Option<&str>) -> Result<Option<String>, IamError> {
    match text {
        Some(text) if text.is_empty() || text.len() > 255 || text.chars().any(char::is_control) => {
            Err(IamError::invalid_property(
                property,
                "This value must be 1 to 255 characters without control characters.",
                "format",
            ))
        }
        other => Ok(other.map(str::to_owned)),
    }
}

/// The route id that a text names.
fn route_id(text: &str) -> Result<Uuid, IamError> {
    Uuid::parse(text).map_err(|_error| {
        IamError::invalid_property("routeId", "This value is not a valid UUID.", "uuid")
    })
}

#[cfg(test)]
mod tests;
