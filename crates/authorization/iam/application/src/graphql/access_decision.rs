//! GraphQL objects and the resolvers that read the access decisions of the gateway.
//!
//! The resolvers share the use-case calls and the response shapes of the REST handlers, so both
//! transports apply one set of rules.

use async_graphql::{Context, ID, InputObject, SimpleObject};
use shared_application::http::Problem;
use validator::Validate as _;

use super::{require_caller, state};
use crate::http::access_decision::dto::{
    AccessDecisionPageResponse, AccessDecisionResponse, ListAccessDecisionsParams,
};
use crate::http::access_decision::{
    find_access_decision, list_access_decisions, parse_access_decision_id,
};
use crate::http::dto::DEFAULT_PAGE_SIZE;

/// One access decision of the gateway.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "AccessDecision")]
pub struct AccessDecisionObject {
    /// The identifier of the decision, a UUID v7.
    pub id: ID,
    /// When the decision was made, as an RFC 3339 UTC time.
    pub occurred_at: String,
    /// The HTTP method of the request.
    pub method: String,
    /// The host of the request.
    pub host: String,
    /// The matched route.
    pub route_id: Option<ID>,
    /// The path template of the matched route; never the concrete path.
    pub route_template: Option<String>,
    /// The status of the answer.
    pub status: i32,
    /// The registered name of the upstream.
    pub upstream: Option<String>,
    /// Microseconds from the receipt of the request to the end of the response.
    pub latency_us: i64,
    /// The bytes of the request body that were announced.
    pub bytes_in: i64,
    /// The bytes of the response body that were announced.
    pub bytes_out: i64,
    /// The request id of the request.
    pub request_id: Option<String>,
    /// The subject that the token proved; null without a valid token.
    pub subject_id: Option<String>,
    /// The kind of the subject: `user` or `service`.
    pub subject_kind: Option<String>,
    /// The kind of the decision: `allow`, `deny` or `error`.
    pub decision: String,
    /// The reason code of the decision.
    pub reason: String,
    /// The permission key the operation required.
    pub permission_key: Option<String>,
    /// The keys that were denied, for a denial.
    pub denied: Vec<String>,
    /// The project of the request, when it names one.
    pub project_id: Option<ID>,
    /// The version of the policy snapshot that decided.
    pub policy_version: Option<i64>,
}

impl From<AccessDecisionResponse> for AccessDecisionObject {
    fn from(response: AccessDecisionResponse) -> Self {
        Self {
            id: ID::from(response.id),
            occurred_at: response.occurred_at,
            method: response.method,
            host: response.host,
            route_id: response.route_id.map(ID::from),
            route_template: response.route_template,
            status: i32::from(response.status),
            upstream: response.upstream,
            latency_us: i64::try_from(response.latency_us).unwrap_or(i64::MAX),
            bytes_in: i64::try_from(response.bytes_in).unwrap_or(i64::MAX),
            bytes_out: i64::try_from(response.bytes_out).unwrap_or(i64::MAX),
            request_id: response.request_id,
            subject_id: response.subject_id,
            subject_kind: response.subject_kind,
            decision: response.decision,
            reason: response.reason,
            permission_key: response.permission_key,
            denied: response.denied,
            project_id: response.project_id.map(ID::from),
            policy_version: response.policy_version,
        }
    }
}

/// One page of access decisions.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "AccessDecisionPage")]
pub struct AccessDecisionPageObject {
    /// The decisions of the page, newest first.
    pub items: Vec<AccessDecisionObject>,
    /// The `after` value of the next, older page; null on the last page.
    pub next_cursor: Option<String>,
}

impl From<AccessDecisionPageResponse> for AccessDecisionPageObject {
    fn from(page: AccessDecisionPageResponse) -> Self {
        Self {
            items: page
                .items
                .into_iter()
                .map(AccessDecisionObject::from)
                .collect(),
            next_cursor: page.next_cursor,
        }
    }
}

/// The time range and the filters of the access decision search: a decision must meet every filter that is given; the range is required and nullable here so that a missing bound is `VALIDATION_FAILED` like over REST.
#[derive(Debug, Default, InputObject)]
#[graphql(name = "AccessDecisionFilterInput")]
pub struct AccessDecisionFilterInput {
    /// The decisions from this RFC 3339 UTC time on; required.
    pub from: Option<String>,
    /// The decisions before this RFC 3339 UTC time; required, and at most `ACCESS_LOG_QUERY_MAX_RANGE` after `from`.
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
    pub route_id: Option<String>,
    /// Only the decisions with this response status.
    pub status: Option<i32>,
}

/// Reads one decision as the caller of the request; null when the log store holds none.
pub(super) async fn access_decision_field(
    ctx: &Context<'_>,
    id: &ID,
) -> Result<Option<AccessDecisionObject>, Problem> {
    let caller = require_caller(ctx)?;
    let id = parse_access_decision_id(id.as_str())?;
    let entry = find_access_decision(state(ctx)?, caller, id).await?;
    Ok(entry.map(|entry| AccessDecisionObject::from(AccessDecisionResponse::from(&entry))))
}

/// Searches the access decisions as the caller of the request.
pub(super) async fn access_decisions_field(
    ctx: &Context<'_>,
    first: Option<i32>,
    after: Option<String>,
    filter: AccessDecisionFilterInput,
) -> Result<AccessDecisionPageObject, Problem> {
    let caller = require_caller(ctx)?;
    let params = ListAccessDecisionsParams {
        limit: Some(first.unwrap_or(DEFAULT_PAGE_SIZE)),
        after,
        from: filter.from,
        until: filter.until,
        subject_id: filter.subject_id,
        subject_kind: filter.subject_kind,
        decision: filter.decision,
        reason: filter.reason,
        upstream: filter.upstream,
        route_id: filter.route_id,
        status: filter.status,
    };
    params.validate()?;
    let page = list_access_decisions(state(ctx)?, caller, params).await?;
    Ok(AccessDecisionPageObject::from(
        AccessDecisionPageResponse::from(&page),
    ))
}
