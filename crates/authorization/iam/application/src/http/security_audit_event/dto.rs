//! Wire shapes of the security audit records of the IAM context.
//!
//! The list parameters keep their schema constraints and their validator attributes on the same
//! field so that both stay equal; the values that the domain owns are checked when the query is
//! built, which reports the first violation.

use std::time::SystemTime;

use iam_domain::{
    ActorRef, AuditAction, AuditOutcome, InvalidIamValue, SecurityAuditFilter,
    StoredSecurityAuditEvent,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

use crate::error::IamError;
use crate::http::dto::DEFAULT_PAGE_SIZE;
use crate::query::get_security_audit_events::{
    GetSecurityAuditEventsQuery, SecurityAuditEventPage,
};

/// One security audit record with its place in the hash chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = SecurityAuditEvent)]
pub struct SecurityAuditEventResponse {
    /// The identifier of the record.
    #[schema(format = Uuid)]
    pub id: String,
    /// The gap-free sequence number of the record in the chain, starting at 1.
    pub seq: i64,
    /// When the action happened, as an RFC 3339 UTC time.
    #[schema(format = DateTime, example = "2026-11-23T10:15:30.123456Z")]
    pub occurred_at: String,
    /// Who performed the action: `user:<uuid>`, `service:<name>` or `system:<component>`.
    #[schema(example = "user:0190f2a8-7b3c-7d4e-8f10-1234567890ab")]
    pub actor: String,
    /// The service that called on behalf of the actor, when it differs from the actor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller_service: Option<String>,
    /// What was done, such as `role.create`.
    #[schema(example = "role.create")]
    pub action: String,
    /// The type of what it was done to, such as `role`.
    #[schema(example = "role")]
    pub target_type: String,
    /// The identifier of what it was done to.
    pub target_id: String,
    /// Where it applies: `global` or `project:<uuid>`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// The state before the change, as a summary of identifiers, names and keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<String>,
    /// The state after the change, as a summary of identifiers, names and keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
    /// Whether the change took effect: `committed` or `rejected`.
    #[schema(example = "committed")]
    pub outcome: String,
    /// Why an attempt was refused, such as `forbidden`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The policy version that resulted from the change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<i64>,
    /// The request id of the caller.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// The hash of the previous record, 64 lower-case hexadecimal digits; all zeros for the first.
    pub prev_hash: String,
    /// The hash of this record: `SHA-256(prevHash || canonical form)`, 64 lower-case hexadecimal
    /// digits.
    pub hash: String,
}

impl From<&StoredSecurityAuditEvent> for SecurityAuditEventResponse {
    fn from(record: &StoredSecurityAuditEvent) -> Self {
        let parts = record.event().parts();
        Self {
            id: parts.id.to_string(),
            seq: record.seq(),
            occurred_at: humantime::format_rfc3339_micros(parts.occurred_at).to_string(),
            actor: parts.actor.to_string(),
            caller_service: parts.caller_service.as_ref().map(ToString::to_string),
            action: parts.action.to_string(),
            target_type: parts.target.target_type().to_owned(),
            target_id: parts.target.target_id().to_owned(),
            scope: parts.scope.as_ref().map(ToString::to_string),
            before: parts
                .before
                .as_ref()
                .map(|summary| summary.as_str().to_owned()),
            after: parts
                .after
                .as_ref()
                .map(|summary| summary.as_str().to_owned()),
            outcome: parts.outcome.as_str().to_owned(),
            reason: parts
                .reason
                .as_ref()
                .map(|reason| reason.as_str().to_owned()),
            policy_version: parts.policy_version.map(iam_domain::PolicyVersion::value),
            request_id: parts.request_id.as_ref().map(ToString::to_string),
            prev_hash: record.prev_hash().to_string(),
            hash: record.hash().to_string(),
        }
    }
}

/// One page of security audit records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = SecurityAuditEventPage)]
pub struct SecurityAuditEventPageResponse {
    /// The records of the page, newest first.
    pub items: Vec<SecurityAuditEventResponse>,
    /// The `after` value of the next, older page; absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

impl From<&SecurityAuditEventPage> for SecurityAuditEventPageResponse {
    fn from(page: &SecurityAuditEventPage) -> Self {
        Self {
            items: page
                .events
                .iter()
                .map(SecurityAuditEventResponse::from)
                .collect(),
            next_cursor: page.next_before.map(|seq| seq.to_string()),
        }
    }
}

/// Query parameters of the security audit search; `limit` is signed so that a negative value is a
/// 422, not a parse error.
#[derive(Debug, Clone, Default, Deserialize, IntoParams, Validate)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct ListSecurityAuditEventsParams {
    /// The largest number of records of the page; 30 when absent.
    #[param(minimum = 1, maximum = 100, default = 30)]
    #[validate(range(min = 1, max = 100, message = "This value must be between 1 and 100."))]
    pub limit: Option<i32>,
    /// The `nextCursor` of the previous page; absent for the first page.
    pub after: Option<String>,
    /// Only the records from this RFC 3339 UTC time on.
    #[param(format = DateTime)]
    pub from: Option<String>,
    /// Only the records before this RFC 3339 UTC time.
    #[param(format = DateTime)]
    pub until: Option<String>,
    /// Only the records of this actor: `user:<uuid>`, `service:<name>` or `system:<component>`.
    pub actor: Option<String>,
    /// Only the records of this action, such as `role.create`.
    pub action: Option<String>,
    /// Only the records about targets of this type, such as `role`.
    pub target_type: Option<String>,
    /// Only the records about this target; needs `targetType`.
    pub target_id: Option<String>,
    /// Only the records of this outcome: `committed` or `rejected`.
    pub outcome: Option<String>,
}

impl ListSecurityAuditEventsParams {
    /// The query for these parameters, asked by `caller`; call it after validation, which makes
    /// `limit` positive.
    ///
    /// # Errors
    ///
    /// [`IamError::Invalid`] with a violation of the first parameter that is not valid.
    pub fn into_query(self, caller: ActorRef) -> Result<GetSecurityAuditEventsQuery, IamError> {
        let before_seq = self.after.as_deref().map(cursor).transpose()?;
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
        let mut filter = SecurityAuditFilter::new()
            .within(from, until)
            .map_err(invalid)?;
        if let Some(text) = self.actor.as_deref() {
            filter = filter.by_actor(ActorRef::parse(text).map_err(invalid)?);
        }
        if let Some(text) = self.action.as_deref() {
            filter = filter.of_action(AuditAction::new(text).map_err(invalid)?);
        }
        if let Some(text) = self.outcome.as_deref() {
            filter = filter.with_outcome(AuditOutcome::parse(text).map_err(invalid)?);
        }
        filter = with_target(
            filter,
            self.target_type.as_deref(),
            self.target_id.as_deref(),
        )?;
        Ok(GetSecurityAuditEventsQuery {
            actor: caller,
            filter,
            limit: self.limit.unwrap_or(DEFAULT_PAGE_SIZE).unsigned_abs(),
            before_seq,
        })
    }
}

/// The filter with the target conditions of the parameters.
fn with_target(
    filter: SecurityAuditFilter,
    target_type: Option<&str>,
    target_id: Option<&str>,
) -> Result<SecurityAuditFilter, IamError> {
    match (target_type, target_id) {
        (Some(kind), id) => filter.about(kind, id).map_err(invalid),
        (None, Some(_id)) => Err(IamError::invalid_property(
            "targetType",
            "This value is required with targetId.",
            "required",
        )),
        (None, None) => Ok(filter),
    }
}

/// The sequence number that a cursor names.
fn cursor(text: &str) -> Result<i64, IamError> {
    text.parse::<i64>()
        .ok()
        .filter(|seq| *seq >= 1)
        .ok_or_else(|| {
            IamError::invalid_property("after", "This value is not a valid cursor.", "format")
        })
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

/// The violation that the domain value error describes.
fn invalid(error: InvalidIamValue) -> IamError {
    IamError::invalid_property(error.property_path(), &error.to_string(), error.code())
}

#[cfg(test)]
mod tests;
