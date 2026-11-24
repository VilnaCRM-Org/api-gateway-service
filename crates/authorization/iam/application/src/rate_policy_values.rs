//! What the rate-policy use cases share: the values of a rate policy as a request carries them,
//! their validation, the partial update of an existing policy and the audit summaries (FR-64).
//!
//! A request names the period in milliseconds (`periodMs`); the aggregate holds whole seconds, so a
//! period that is not a positive multiple of 1,000 ms is a violation of `periodMs`.

use iam_domain::{
    InvalidRatePolicy, RateFallback, RateKeyKind, RatePolicyDraft, RatePolicyFields,
    RatePolicyParts,
};
use shared_application::http::Violation;

use crate::error::IamError;

/// The number of milliseconds of one second.
const MILLIS_PER_SECOND: i64 = 1_000;

/// The message of the violation of an unusable period.
const PERIOD_MESSAGE: &str =
    "This value must be a whole number of seconds between 1000 and 4294967295000 milliseconds.";

/// The values of a rate policy, as a request carries them and before they are validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatePolicyValues {
    /// The name: 1 to 100 characters without a control character, unique among the rate policies
    /// that are not deleted.
    pub name: String,
    /// What requests are counted by.
    pub key_kind: RateKeyKind,
    /// The number of requests allowed per period.
    pub limit: i64,
    /// The period in milliseconds; a positive multiple of 1,000.
    pub period_ms: i64,
    /// The number of requests allowed above the limit in a burst.
    pub burst: i64,
    /// What the limit becomes without the shared counter.
    pub fallback: RateFallback,
}

impl RatePolicyValues {
    /// The values of a stored configuration.
    #[must_use]
    pub fn of(fields: &RatePolicyFields) -> Self {
        Self {
            name: fields.name().to_owned(),
            key_kind: fields.key_kind(),
            limit: i64::from(fields.limit()),
            period_ms: period_ms_of(fields),
            burst: i64::from(fields.burst()),
            fallback: fields.fallback(),
        }
    }

    /// Validates the values.
    ///
    /// # Errors
    ///
    /// [`IamError::Invalid`] with every violation, in the order name, limit, period, burst; the
    /// property of the period is `periodMs`.
    pub fn into_fields(self) -> Result<RatePolicyFields, IamError> {
        RatePolicyFields::new(RatePolicyDraft {
            name: self.name,
            key_kind: self.key_kind,
            limit: self.limit,
            period_seconds: seconds_of(self.period_ms),
            burst: self.burst,
            fallback: self.fallback,
        })
        .map_err(violations)
    }
}

/// What an update changes: every member is optional, and an absent one stays as it is.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RatePolicyPatch {
    /// The new name.
    pub name: Option<String>,
    /// The new key kind.
    pub key_kind: Option<RateKeyKind>,
    /// The new limit.
    pub limit: Option<i64>,
    /// The new period in milliseconds.
    pub period_ms: Option<i64>,
    /// The new burst.
    pub burst: Option<i64>,
    /// The new fallback.
    pub fallback: Option<RateFallback>,
}

impl RatePolicyPatch {
    /// The values of `current` with the members of the patch applied.
    #[must_use]
    pub fn applied_to(self, current: &RatePolicyFields) -> RatePolicyValues {
        let stored = RatePolicyValues::of(current);
        RatePolicyValues {
            name: self.name.unwrap_or(stored.name),
            key_kind: self.key_kind.unwrap_or(stored.key_kind),
            limit: self.limit.unwrap_or(stored.limit),
            period_ms: self.period_ms.unwrap_or(stored.period_ms),
            burst: self.burst.unwrap_or(stored.burst),
            fallback: self.fallback.unwrap_or(stored.fallback),
        }
    }
}

/// The period of a configuration in milliseconds.
#[must_use]
pub fn period_ms_of(fields: &RatePolicyFields) -> i64 {
    i64::from(fields.period_seconds()).saturating_mul(MILLIS_PER_SECOND)
}

/// The whole seconds of a period in milliseconds; zero, which the aggregate refuses, for a period
/// that is not a multiple of 1,000.
const fn seconds_of(period_ms: i64) -> i64 {
    match (
        period_ms.checked_rem(MILLIS_PER_SECOND),
        period_ms.checked_div(MILLIS_PER_SECOND),
    ) {
        (Some(0), Some(seconds)) => seconds,
        _ => 0,
    }
}

/// Every violation of a rate policy, as the `property_path` and `code` of the domain give them;
/// the period is reported under the name of the request, `periodMs`.
fn violations(violations: Vec<InvalidRatePolicy>) -> IamError {
    IamError::Invalid(
        violations
            .into_iter()
            .map(|violation| {
                if matches!(violation, InvalidRatePolicy::PeriodRange) {
                    return Violation {
                        property_path: "periodMs".to_owned(),
                        message: PERIOD_MESSAGE.to_owned(),
                        code: violation.code().to_owned(),
                    };
                }
                Violation {
                    property_path: violation.property_path().to_owned(),
                    message: violation.to_string(),
                    code: violation.code().to_owned(),
                }
            })
            .collect(),
    )
}

/// The state of a rate policy that its audit record keeps: the configuration without the name,
/// and the version.
pub(crate) fn summary_of(policy: &RatePolicyParts) -> String {
    let fields = &policy.fields;
    format!(
        "key={} limit={} periodMs={} burst={} fallback={} version={}",
        fields.key_kind().as_str(),
        fields.limit(),
        period_ms_of(fields),
        fields.burst(),
        fields.fallback().as_str(),
        policy.version.value()
    )
}

#[cfg(test)]
mod tests;
