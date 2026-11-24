//! The data of the rate-policy operations: the request bodies, the responses and the list
//! parameters, shared by the REST handlers and the GraphQL resolvers (FR-64).

use iam_domain::{
    ChangeReceipt, EntityVersion, RateFallback, RateKeyKind, RatePolicyId, RatePolicyParts,
};
use serde::{Deserialize, Serialize};
use shared_application::http::Violation;
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

use crate::error::IamError;
use crate::http::dto::DEFAULT_PAGE_SIZE;
use crate::query::list_rate_policies::{ListRatePoliciesQuery, RatePolicyPage};
use crate::rate_policy_values::{RatePolicyPatch, RatePolicyValues, period_ms_of};

/// The message of the violation of a key kind that names no kind.
const KEY_MESSAGE: &str = "This value must be one of ip, subject, subject_route or route.";

/// The message of the violation of a fallback that names no fallback.
const FALLBACK_MESSAGE: &str = "This value must be one of divided or full.";

/// The key kind that `text` names.
///
/// # Errors
///
/// A violation of `key`.
pub(crate) fn parse_key(text: &str) -> Result<RateKeyKind, Violation> {
    RateKeyKind::parse(text).ok_or_else(|| violation("key", KEY_MESSAGE, "enum"))
}

/// The fallback that `text` names.
///
/// # Errors
///
/// A violation of `fallback`.
pub(crate) fn parse_fallback(text: &str) -> Result<RateFallback, Violation> {
    RateFallback::parse(text).ok_or_else(|| violation("fallback", FALLBACK_MESSAGE, "enum"))
}

/// One violated constraint of a value.
fn violation(property_path: &str, message: &str, code: &str) -> Violation {
    Violation {
        property_path: property_path.to_owned(),
        message: message.to_owned(),
        code: code.to_owned(),
    }
}

/// The violations of the names that did not parse, as one error.
fn invalid(violations: impl IntoIterator<Item = Violation>) -> IamError {
    IamError::Invalid(violations.into_iter().collect())
}

/// Body of the rate-policy creation operation.
#[derive(Debug, Clone, Deserialize, ToSchema, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[schema(as = CreateRatePolicyRequest)]
pub struct CreateRatePolicyRequest {
    /// The name: 1 to 100 characters without a control character, unique among the rate policies
    /// that are not deleted.
    #[schema(min_length = 1, max_length = 100, example = "per-subject-route")]
    pub name: String,
    /// What requests are counted by: `ip`, `subject`, `subject_route` or `route`.
    #[schema(example = "subject_route")]
    pub key: String,
    /// The number of requests allowed per period, from 1 to 4,294,967,295.
    #[schema(minimum = 1, example = 100)]
    pub limit: i64,
    /// The period in milliseconds: a multiple of 1,000, from 1,000 to 4,294,967,295,000.
    #[schema(minimum = 1000, example = 60000)]
    pub period_ms: i64,
    /// The number of requests allowed above the limit in a burst, from 0 to 4,294,967,295.
    #[schema(minimum = 0, example = 20)]
    pub burst: i64,
    /// What the limit becomes without the shared counter: `divided` or `full`.
    #[schema(example = "divided")]
    pub fallback: String,
}

impl CreateRatePolicyRequest {
    /// The values of the request.
    ///
    /// # Errors
    ///
    /// [`IamError::Invalid`] with a violation for a key kind and one for a fallback that name
    /// nothing; the other values are validated by the command.
    pub fn into_values(self) -> Result<RatePolicyValues, IamError> {
        match (parse_key(&self.key), parse_fallback(&self.fallback)) {
            (Ok(key_kind), Ok(fallback)) => Ok(RatePolicyValues {
                name: self.name,
                key_kind,
                limit: self.limit,
                period_ms: self.period_ms,
                burst: self.burst,
                fallback,
            }),
            (key, fallback) => Err(invalid(key.err().into_iter().chain(fallback.err()))),
        }
    }

    /// The text that the idempotency digest of the request covers: the operation and the fields,
    /// so that a different body under the same key is a different request.
    #[must_use]
    pub fn canonical_form(&self) -> String {
        format!(
            "rate_policy.create:{:?}",
            (
                &self.name,
                &self.key,
                self.limit,
                self.period_ms,
                self.burst,
                &self.fallback
            )
        )
    }
}

/// Body of the rate-policy update operation: every member is optional, and an absent one stays as
/// it is.
#[derive(Debug, Clone, Default, Deserialize, ToSchema, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[schema(as = UpdateRatePolicyRequest)]
pub struct UpdateRatePolicyRequest {
    /// The new name: 1 to 100 characters without a control character, unique among the rate
    /// policies that are not deleted.
    #[serde(default)]
    #[schema(min_length = 1, max_length = 100, example = "per-subject-route")]
    pub name: Option<String>,
    /// The new key kind: `ip`, `subject`, `subject_route` or `route`.
    #[serde(default)]
    #[schema(example = "subject_route")]
    pub key: Option<String>,
    /// The new limit, from 1 to 4,294,967,295.
    #[serde(default)]
    #[schema(minimum = 1, example = 100)]
    pub limit: Option<i64>,
    /// The new period in milliseconds: a multiple of 1,000, from 1,000 to 4,294,967,295,000.
    #[serde(default)]
    #[schema(minimum = 1000, example = 60000)]
    pub period_ms: Option<i64>,
    /// The new burst, from 0 to 4,294,967,295.
    #[serde(default)]
    #[schema(minimum = 0, example = 20)]
    pub burst: Option<i64>,
    /// The new fallback: `divided` or `full`.
    #[serde(default)]
    #[schema(example = "divided")]
    pub fallback: Option<String>,
}

impl UpdateRatePolicyRequest {
    /// The members that the request changes.
    ///
    /// # Errors
    ///
    /// [`IamError::Invalid`] with a violation for a key kind and one for a fallback that name
    /// nothing; the other values are validated by the command.
    pub fn into_patch(self) -> Result<RatePolicyPatch, IamError> {
        let key = self.key.as_deref().map(parse_key).transpose();
        let fallback = self.fallback.as_deref().map(parse_fallback).transpose();
        match (key, fallback) {
            (Ok(key_kind), Ok(fallback)) => Ok(RatePolicyPatch {
                name: self.name,
                key_kind,
                limit: self.limit,
                period_ms: self.period_ms,
                burst: self.burst,
                fallback,
            }),
            (key, fallback) => Err(invalid(key.err().into_iter().chain(fallback.err()))),
        }
    }

    /// The text that the idempotency digest covers: the operation, the rate policy, the version
    /// and the members.
    #[must_use]
    pub fn canonical_form(&self, id: RatePolicyId, expected: EntityVersion) -> String {
        format!(
            "rate_policy.update:{:?}",
            (
                id.to_string(),
                expected.value(),
                &self.name,
                &self.key,
                self.limit,
                self.period_ms,
                self.burst,
                &self.fallback
            )
        )
    }
}

/// The text that the idempotency digest of a rate-policy deletion covers: the operation, the rate
/// policy and the version.
#[must_use]
pub fn delete_rate_policy_canonical_form(id: RatePolicyId, expected: EntityVersion) -> String {
    format!(
        "rate_policy.delete:{:?}",
        (id.to_string(), expected.value())
    )
}

/// The result of a rate-policy deletion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = DeletedRatePolicy)]
pub struct DeleteRatePolicyResponse {
    /// The identifier of the deleted rate policy.
    #[schema(format = Uuid)]
    pub id: String,
    /// The final version of the rate policy.
    #[schema(minimum = 1)]
    pub version: i64,
}

impl From<&ChangeReceipt> for DeleteRatePolicyResponse {
    /// The rate policy that the receipt names and the version the deletion ended at.
    fn from(receipt: &ChangeReceipt) -> Self {
        Self {
            id: receipt.target().target_id().to_owned(),
            version: receipt.entity_version().value(),
        }
    }
}

/// A rate policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = RatePolicy)]
pub struct RatePolicyResponse {
    /// The identifier of the rate policy.
    #[schema(format = Uuid)]
    pub id: String,
    /// The name of the rate policy.
    #[schema(min_length = 1, max_length = 100)]
    pub name: String,
    /// What requests are counted by: `ip`, `subject`, `subject_route` or `route`.
    #[schema(example = "subject_route")]
    pub key: String,
    /// The number of requests allowed per period.
    #[schema(minimum = 1)]
    pub limit: i64,
    /// The period in milliseconds.
    #[schema(minimum = 1000)]
    pub period_ms: i64,
    /// The number of requests allowed above the limit in a burst.
    #[schema(minimum = 0)]
    pub burst: i64,
    /// What the limit becomes without the shared counter: `divided` or `full`.
    #[schema(example = "divided")]
    pub fallback: String,
    /// The version of the rate policy; its `ETag` is this number in double quotes.
    #[schema(minimum = 1)]
    pub version: i64,
    /// When the rate policy was created, as an RFC 3339 UTC time.
    #[schema(format = DateTime, example = "2026-11-23T10:15:30.123456Z")]
    pub created_at: String,
    /// When the rate policy was last changed, as an RFC 3339 UTC time.
    #[schema(format = DateTime, example = "2026-11-23T10:15:30.123456Z")]
    pub updated_at: String,
}

impl From<RatePolicyParts> for RatePolicyResponse {
    fn from(policy: RatePolicyParts) -> Self {
        let fields = &policy.fields;
        Self {
            id: policy.id.to_string(),
            name: fields.name().to_owned(),
            key: fields.key_kind().as_str().to_owned(),
            limit: i64::from(fields.limit()),
            period_ms: period_ms_of(fields),
            burst: i64::from(fields.burst()),
            fallback: fields.fallback().as_str().to_owned(),
            version: policy.version.value(),
            created_at: humantime::format_rfc3339_micros(policy.created_at).to_string(),
            updated_at: humantime::format_rfc3339_micros(policy.updated_at).to_string(),
        }
    }
}

/// One page of rate policies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = RatePolicyPage)]
pub struct RatePolicyPageResponse {
    /// The rate policies of the page.
    pub items: Vec<RatePolicyResponse>,
    /// The `after` value of the next page; absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(format = Uuid)]
    pub next_cursor: Option<String>,
}

impl From<RatePolicyPage> for RatePolicyPageResponse {
    fn from(page: RatePolicyPage) -> Self {
        Self {
            items: page
                .rate_policies
                .into_iter()
                .map(RatePolicyResponse::from)
                .collect(),
            next_cursor: page.next_after.map(|id| id.to_string()),
        }
    }
}

/// Query parameters of the rate-policy list; `limit` is signed so that a negative value is a 422,
/// not a parse error.
#[derive(Debug, Clone, Deserialize, IntoParams, Validate)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct ListRatePoliciesParams {
    /// The largest number of rate policies of the page.
    #[param(minimum = 1, maximum = 100, default = 30)]
    #[validate(range(min = 1, max = 100, message = "This value must be between 1 and 100."))]
    pub limit: i32,
    /// The `nextCursor` of the previous page; absent for the first page.
    #[param(format = Uuid)]
    pub after: Option<String>,
}

impl Default for ListRatePoliciesParams {
    fn default() -> Self {
        Self {
            limit: DEFAULT_PAGE_SIZE,
            after: None,
        }
    }
}

impl ListRatePoliciesParams {
    /// The query for these parameters; call it after validation, which makes `limit` positive.
    ///
    /// # Errors
    ///
    /// [`IamError::Invalid`] with a violation for an `after` that is not a UUID.
    pub fn into_query(self) -> Result<ListRatePoliciesQuery, IamError> {
        let after = self
            .after
            .as_deref()
            .map(RatePolicyId::parse)
            .transpose()
            .map_err(|_error| {
                IamError::Invalid(vec![violation(
                    "after",
                    "This value is not a valid UUID.",
                    "uuid",
                )])
            })?;
        Ok(ListRatePoliciesQuery {
            limit: self.limit.unsigned_abs(),
            after,
        })
    }
}

#[cfg(test)]
mod tests;
