//! GraphQL objects, inputs and resolvers of the rate-policy operations (FR-64).
//!
//! The resolvers share the use-case calls and the DTOs of the REST handlers, so both transports
//! apply one set of rules.

use async_graphql::{Context, ID, InputObject, SimpleObject};
use iam_domain::{ChangeReceipt, PolicyVersion};
use shared_application::http::Problem;
use validator::Validate as _;

use super::propagation::{PropagationObject, WriteOutcomeMapper, write_mode};
use super::{expected_version, idempotency_key, require_caller, state};
use crate::http::dto::DEFAULT_PAGE_SIZE;
use crate::http::extract::VersionedWriteHeaders;
use crate::http::rate_policy::dto::{
    CreateRatePolicyRequest, ListRatePoliciesParams, RatePolicyPageResponse, RatePolicyResponse,
    UpdateRatePolicyRequest,
};
use crate::http::rate_policy::{
    create_rate_policy, delete_rate_policy, find_rate_policy, list_rate_policies,
    parse_rate_policy_id, update_rate_policy,
};

/// Input of the rate-policy creation mutation.
#[derive(Debug, InputObject)]
#[graphql(name = "CreateRatePolicyInput")]
pub struct CreateRatePolicyInput {
    /// The name: 1 to 100 characters, unique among the rate policies that are not deleted.
    pub name: String,
    /// What requests are counted by: `ip`, `subject`, `subject_route` or `route`.
    pub key: String,
    /// The number of requests allowed per period, from 1 to 4,294,967,295.
    pub limit: i64,
    /// The period in milliseconds: a multiple of 1,000, from 1,000 to 4,294,967,295,000.
    pub period_ms: i64,
    /// The number of requests allowed above the limit in a burst, from 0 to 4,294,967,295.
    pub burst: i64,
    /// What the limit becomes without the shared counter: `divided` or `full`.
    pub fallback: String,
    /// Makes the creation safe to repeat for 24 hours: 1 to 255 visible ASCII characters.
    pub idempotency_key: Option<String>,
    /// What the write waits for: `PUBLISHED` (the default) returns once Kafka acknowledged the policy version; `PROPAGATED` is refused with `VALIDATION_FAILED` until the gateway pods report their versions.
    pub consistency: Option<String>,
}

/// Input of the rate-policy update mutation.
#[derive(Debug, InputObject)]
#[graphql(name = "UpdateRatePolicyInput")]
pub struct UpdateRatePolicyInput {
    /// The rate policy to change.
    pub id: ID,
    /// The version the caller read; required, and the update is refused when it is not the current one.
    pub expected_version: Option<i64>,
    /// The new name; an absent field keeps it.
    pub name: Option<String>,
    /// The new key kind; an absent field keeps it.
    pub key: Option<String>,
    /// The new limit; an absent field keeps it.
    pub limit: Option<i64>,
    /// The new period in milliseconds; an absent field keeps it.
    pub period_ms: Option<i64>,
    /// The new burst; an absent field keeps it.
    pub burst: Option<i64>,
    /// The new fallback; an absent field keeps it.
    pub fallback: Option<String>,
    /// Makes the update safe to repeat for 24 hours: 1 to 255 visible ASCII characters.
    pub idempotency_key: Option<String>,
    /// What the write waits for: `PUBLISHED` (the default) returns once Kafka acknowledged the policy version; `PROPAGATED` is refused with `VALIDATION_FAILED` until the gateway pods report their versions.
    pub consistency: Option<String>,
}

/// Input of the rate-policy deletion mutation.
#[derive(Debug, InputObject)]
#[graphql(name = "DeleteRatePolicyInput")]
pub struct DeleteRatePolicyInput {
    /// The rate policy to delete.
    pub id: ID,
    /// The version the caller read; required, and the deletion is refused when it is not the current one.
    pub expected_version: Option<i64>,
    /// Makes the deletion safe to repeat for 24 hours: 1 to 255 visible ASCII characters.
    pub idempotency_key: Option<String>,
    /// What the write waits for: `PUBLISHED` (the default) returns once Kafka acknowledged the policy version; `PROPAGATED` is refused with `VALIDATION_FAILED` until the gateway pods report their versions.
    pub consistency: Option<String>,
}

/// A rate policy.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "RatePolicy")]
pub struct RatePolicyObject {
    /// The identifier of the rate policy.
    pub id: ID,
    /// The name of the rate policy.
    pub name: String,
    /// What requests are counted by: `ip`, `subject`, `subject_route` or `route`.
    pub key: String,
    /// The number of requests allowed per period.
    pub limit: i64,
    /// The period in milliseconds.
    pub period_ms: i64,
    /// The number of requests allowed above the limit in a burst.
    pub burst: i64,
    /// What the limit becomes without the shared counter: `divided` or `full`.
    pub fallback: String,
    /// The version of the rate policy.
    pub version: i64,
    /// When the rate policy was created, as an RFC 3339 UTC time.
    pub created_at: String,
    /// When the rate policy was last changed, as an RFC 3339 UTC time.
    pub updated_at: String,
    /// What the write that returned the rate policy learned about the publication of its policy version; null for a read.
    pub propagation: Option<PropagationObject>,
}

impl From<RatePolicyResponse> for RatePolicyObject {
    fn from(response: RatePolicyResponse) -> Self {
        Self {
            id: ID::from(response.id),
            name: response.name,
            key: response.key,
            limit: response.limit,
            period_ms: response.period_ms,
            burst: response.burst,
            fallback: response.fallback,
            version: response.version,
            created_at: response.created_at,
            updated_at: response.updated_at,
            propagation: None,
        }
    }
}

/// One page of rate policies.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "RatePolicyPage")]
pub struct RatePolicyPageObject {
    /// The rate policies of the page.
    pub items: Vec<RatePolicyObject>,
    /// The `after` value of the next page; null on the last page.
    pub next_cursor: Option<String>,
}

impl From<RatePolicyPageResponse> for RatePolicyPageObject {
    fn from(page: RatePolicyPageResponse) -> Self {
        Self {
            items: page.items.into_iter().map(RatePolicyObject::from).collect(),
            next_cursor: page.next_cursor,
        }
    }
}

/// The result of a rate-policy deletion.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "DeleteRatePolicyPayload")]
pub struct DeleteRatePolicyPayload {
    /// The identifier of the deleted rate policy.
    pub id: ID,
    /// The final version of the rate policy.
    pub version: i64,
    /// The policy version that the deletion produced.
    pub policy_version: Option<i64>,
    /// What the deletion learned about the publication of its policy version.
    pub propagation: Option<PropagationObject>,
}

impl From<&ChangeReceipt> for DeleteRatePolicyPayload {
    fn from(receipt: &ChangeReceipt) -> Self {
        Self {
            id: ID::from(receipt.target().target_id()),
            version: receipt.entity_version().value(),
            policy_version: receipt.policy_version().map(PolicyVersion::value),
            propagation: WriteOutcomeMapper::propagation(receipt),
        }
    }
}

/// Creates a rate policy as the caller of the request.
pub(super) async fn create_rate_policy_field(
    ctx: &Context<'_>,
    input: CreateRatePolicyInput,
) -> Result<RatePolicyObject, Problem> {
    let caller = require_caller(ctx)?;
    let key = idempotency_key(input.idempotency_key.as_deref())?;
    let request = CreateRatePolicyRequest {
        name: input.name,
        key: input.key,
        limit: input.limit,
        period_ms: input.period_ms,
        burst: input.burst,
        fallback: input.fallback,
    };
    request.validate()?;
    write_mode(input.consistency.as_deref())?;
    let (policy, receipt) = create_rate_policy(state(ctx)?, caller, key, request).await?;
    Ok(RatePolicyObject {
        propagation: WriteOutcomeMapper::propagation(&receipt),
        ..RatePolicyObject::from(RatePolicyResponse::from(policy))
    })
}

/// Updates a rate policy as the caller of the request.
pub(super) async fn update_rate_policy_field(
    ctx: &Context<'_>,
    input: UpdateRatePolicyInput,
) -> Result<RatePolicyObject, Problem> {
    let caller = require_caller(ctx)?;
    let expected = expected_version(input.expected_version)?;
    let id = parse_rate_policy_id(input.id.as_str())?;
    let key = idempotency_key(input.idempotency_key.as_deref())?;
    let request = UpdateRatePolicyRequest {
        name: input.name,
        key: input.key,
        limit: input.limit,
        period_ms: input.period_ms,
        burst: input.burst,
        fallback: input.fallback,
    };
    request.validate()?;
    write_mode(input.consistency.as_deref())?;
    let headers = VersionedWriteHeaders { expected, key };
    let (policy, receipt) = update_rate_policy(state(ctx)?, caller, id, headers, request).await?;
    Ok(RatePolicyObject {
        propagation: WriteOutcomeMapper::propagation(&receipt),
        ..RatePolicyObject::from(RatePolicyResponse::from(policy))
    })
}

/// Deletes a rate policy as the caller of the request.
pub(super) async fn delete_rate_policy_field(
    ctx: &Context<'_>,
    input: DeleteRatePolicyInput,
) -> Result<DeleteRatePolicyPayload, Problem> {
    let caller = require_caller(ctx)?;
    let expected = expected_version(input.expected_version)?;
    let id = parse_rate_policy_id(input.id.as_str())?;
    let key = idempotency_key(input.idempotency_key.as_deref())?;
    write_mode(input.consistency.as_deref())?;
    let headers = VersionedWriteHeaders { expected, key };
    let receipt = delete_rate_policy(state(ctx)?, caller, id, headers).await?;
    Ok(DeleteRatePolicyPayload::from(&receipt))
}

/// Reads a rate policy; none when it is unknown or deleted.
pub(super) async fn rate_policy_field(
    ctx: &Context<'_>,
    id: &ID,
) -> Result<Option<RatePolicyObject>, Problem> {
    require_caller(ctx)?;
    let policy = find_rate_policy(state(ctx)?, parse_rate_policy_id(id.as_str())?).await?;
    Ok(policy.map(|policy| RatePolicyObject::from(RatePolicyResponse::from(policy))))
}

/// Reads one page of rate policies.
pub(super) async fn rate_policies_field(
    ctx: &Context<'_>,
    first: Option<i32>,
    after: Option<String>,
) -> Result<RatePolicyPageObject, Problem> {
    require_caller(ctx)?;
    let params = ListRatePoliciesParams {
        limit: first.unwrap_or(DEFAULT_PAGE_SIZE),
        after,
    };
    params.validate()?;
    let page = list_rate_policies(state(ctx)?, params).await?;
    Ok(RatePolicyPageObject::from(RatePolicyPageResponse::from(
        page,
    )))
}

#[cfg(test)]
mod tests;
