//! GraphQL objects and the resolvers that read the security audit log.
//!
//! The resolvers share the use-case calls and the response shapes of the REST handlers, so both
//! transports apply one set of rules.

use async_graphql::{Context, ID, InputObject, SimpleObject};
use shared_application::http::Problem;
use validator::Validate as _;

use super::{require_caller, state};
use crate::http::dto::DEFAULT_PAGE_SIZE;
use crate::http::security_audit_event::dto::{
    ListSecurityAuditEventsParams, SecurityAuditEventPageResponse, SecurityAuditEventResponse,
};
use crate::http::security_audit_event::{
    find_security_audit_event, list_security_audit_events, parse_security_audit_event_id,
};

/// One security audit record with its place in the hash chain.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "SecurityAuditEvent")]
pub struct SecurityAuditEventObject {
    /// The identifier of the record.
    pub id: ID,
    /// The gap-free sequence number of the record in the chain, starting at 1.
    pub seq: i64,
    /// When the action happened, as an RFC 3339 UTC time.
    pub occurred_at: String,
    /// Who performed the action: `user:<uuid>`, `service:<name>` or `system:<component>`.
    pub actor: String,
    /// The service that called on behalf of the actor, when it differs from the actor.
    pub caller_service: Option<String>,
    /// What was done, such as `role.create`.
    pub action: String,
    /// The type of what it was done to, such as `role`.
    pub target_type: String,
    /// The identifier of what it was done to.
    pub target_id: String,
    /// Where it applies: `global` or `project:<uuid>`.
    pub scope: Option<String>,
    /// The state before the change, as a summary of identifiers, names and keys.
    pub before: Option<String>,
    /// The state after the change, as a summary of identifiers, names and keys.
    pub after: Option<String>,
    /// Whether the change took effect: `committed` or `rejected`.
    pub outcome: String,
    /// Why an attempt was refused, such as `forbidden`.
    pub reason: Option<String>,
    /// The policy version that resulted from the change.
    pub policy_version: Option<i64>,
    /// The request id of the caller.
    pub request_id: Option<String>,
    /// The hash of the previous record, 64 lower-case hexadecimal digits; all zeros for the first.
    pub prev_hash: String,
    /// The hash of this record: `SHA-256(prevHash || canonical form)`, 64 lower-case hexadecimal digits.
    pub hash: String,
}

impl From<SecurityAuditEventResponse> for SecurityAuditEventObject {
    fn from(response: SecurityAuditEventResponse) -> Self {
        Self {
            id: ID::from(response.id),
            seq: response.seq,
            occurred_at: response.occurred_at,
            actor: response.actor,
            caller_service: response.caller_service,
            action: response.action,
            target_type: response.target_type,
            target_id: response.target_id,
            scope: response.scope,
            before: response.before,
            after: response.after,
            outcome: response.outcome,
            reason: response.reason,
            policy_version: response.policy_version,
            request_id: response.request_id,
            prev_hash: response.prev_hash,
            hash: response.hash,
        }
    }
}

/// One page of security audit records.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "SecurityAuditEventPage")]
pub struct SecurityAuditEventPageObject {
    /// The records of the page, newest first.
    pub items: Vec<SecurityAuditEventObject>,
    /// The `after` value of the next, older page; null on the last page.
    pub next_cursor: Option<String>,
}

impl From<SecurityAuditEventPageResponse> for SecurityAuditEventPageObject {
    fn from(page: SecurityAuditEventPageResponse) -> Self {
        Self {
            items: page
                .items
                .into_iter()
                .map(SecurityAuditEventObject::from)
                .collect(),
            next_cursor: page.next_cursor,
        }
    }
}

/// The filters of the security audit search: a record must meet every one that is given.
#[derive(Debug, Default, InputObject)]
#[graphql(name = "SecurityAuditEventFilterInput")]
pub struct SecurityAuditEventFilterInput {
    /// Only the records from this RFC 3339 UTC time on.
    pub from: Option<String>,
    /// Only the records before this RFC 3339 UTC time.
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

/// Reads one audit record as the caller of the request; null when it is unknown.
pub(super) async fn security_audit_event_field(
    ctx: &Context<'_>,
    id: &ID,
) -> Result<Option<SecurityAuditEventObject>, Problem> {
    let caller = require_caller(ctx)?;
    let id = parse_security_audit_event_id(id.as_str())?;
    let record = find_security_audit_event(state(ctx)?, caller, id).await?;
    Ok(record
        .map(|record| SecurityAuditEventObject::from(SecurityAuditEventResponse::from(&record))))
}

/// Searches the audit log as the caller of the request.
pub(super) async fn security_audit_events_field(
    ctx: &Context<'_>,
    first: Option<i32>,
    after: Option<String>,
    filter: SecurityAuditEventFilterInput,
) -> Result<SecurityAuditEventPageObject, Problem> {
    let caller = require_caller(ctx)?;
    let params = ListSecurityAuditEventsParams {
        limit: Some(first.unwrap_or(DEFAULT_PAGE_SIZE)),
        after,
        from: filter.from,
        until: filter.until,
        actor: filter.actor,
        action: filter.action,
        target_type: filter.target_type,
        target_id: filter.target_id,
        outcome: filter.outcome,
    };
    params.validate()?;
    let page = list_security_audit_events(state(ctx)?, caller, params).await?;
    Ok(SecurityAuditEventPageObject::from(
        SecurityAuditEventPageResponse::from(&page),
    ))
}
