//! The validated configuration of a rate policy.

use crate::error::InvalidRatePolicy;

/// What a rate policy counts requests by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateKeyKind {
    /// The client address.
    Ip,
    /// The authenticated subject.
    Subject,
    /// The authenticated subject and the route.
    SubjectRoute,
    /// The route.
    Route,
}

impl RateKeyKind {
    /// The kind that [`Self::as_str`] prints; `None` for any other text.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "ip" => Some(Self::Ip),
            "subject" => Some(Self::Subject),
            "subject_route" => Some(Self::SubjectRoute),
            "route" => Some(Self::Route),
            _ => None,
        }
    }

    /// The name of the kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Subject => "subject",
            Self::SubjectRoute => "subject_route",
            Self::Route => "route",
        }
    }
}

/// What the limit becomes when the shared counter is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateFallback {
    /// The limit is divided among the gateway pods.
    Divided,
    /// Every pod applies the full limit.
    Full,
}

impl RateFallback {
    /// The fallback that [`Self::as_str`] prints; `None` for any other text.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "divided" => Some(Self::Divided),
            "full" => Some(Self::Full),
            _ => None,
        }
    }

    /// The name of the fallback.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Divided => "divided",
            Self::Full => "full",
        }
    }
}

/// The unvalidated values of a rate policy, as a request carries them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatePolicyDraft {
    /// The name.
    pub name: String,
    /// What requests are counted by.
    pub key_kind: RateKeyKind,
    /// The number of requests allowed per period.
    pub limit: i64,
    /// The period, in seconds.
    pub period_seconds: i64,
    /// The number of requests allowed above the limit in a burst.
    pub burst: i64,
    /// What the limit becomes without the shared counter.
    pub fallback: RateFallback,
}

/// The validated configuration of a rate policy: everything an update can change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatePolicyFields {
    name: String,
    key_kind: RateKeyKind,
    limit: u32,
    period_seconds: u32,
    burst: u32,
    fallback: RateFallback,
}

impl RatePolicyFields {
    /// The largest number of characters of a name.
    pub const MAX_NAME_CHARS: usize = 100;

    /// Validates the draft.
    ///
    /// # Errors
    ///
    /// Every violation, in the order name, limit, period, burst.
    pub fn new(draft: RatePolicyDraft) -> Result<Self, Vec<InvalidRatePolicy>> {
        let name = name_of(draft.name);
        let limit = positive(draft.limit, InvalidRatePolicy::LimitRange);
        let period = positive(draft.period_seconds, InvalidRatePolicy::PeriodRange);
        let burst = u32::try_from(draft.burst).map_err(|_error| InvalidRatePolicy::BurstRange);
        match (name, limit, period, burst) {
            (Ok(name), Ok(limit), Ok(period_seconds), Ok(burst)) => Ok(Self {
                name,
                key_kind: draft.key_kind,
                limit,
                period_seconds,
                burst,
                fallback: draft.fallback,
            }),
            (name, limit, period, burst) => {
                Err([name.err(), limit.err(), period.err(), burst.err()]
                    .into_iter()
                    .flatten()
                    .collect())
            }
        }
    }

    /// The name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// What requests are counted by.
    #[must_use]
    pub const fn key_kind(&self) -> RateKeyKind {
        self.key_kind
    }

    /// The number of requests allowed per period.
    #[must_use]
    pub const fn limit(&self) -> u32 {
        self.limit
    }

    /// The period, in seconds.
    #[must_use]
    pub const fn period_seconds(&self) -> u32 {
        self.period_seconds
    }

    /// The number of requests allowed above the limit in a burst.
    #[must_use]
    pub const fn burst(&self) -> u32 {
        self.burst
    }

    /// What the limit becomes without the shared counter.
    #[must_use]
    pub const fn fallback(&self) -> RateFallback {
        self.fallback
    }

    /// The names of the properties in which `other` differs from this configuration.
    #[must_use]
    pub fn changed_fields(&self, other: &Self) -> Vec<&'static str> {
        [
            ("name", self.name != other.name),
            ("keyKind", self.key_kind != other.key_kind),
            ("limit", self.limit != other.limit),
            ("periodSeconds", self.period_seconds != other.period_seconds),
            ("burst", self.burst != other.burst),
            ("fallback", self.fallback != other.fallback),
        ]
        .into_iter()
        .filter_map(|(name, changed)| changed.then_some(name))
        .collect()
    }
}

/// A name of 1 to 100 characters without a control character.
fn name_of(value: String) -> Result<String, InvalidRatePolicy> {
    if !(1..=RatePolicyFields::MAX_NAME_CHARS).contains(&value.chars().count()) {
        return Err(InvalidRatePolicy::NameLength);
    }
    if value.chars().any(char::is_control) {
        return Err(InvalidRatePolicy::NameControlCharacter);
    }
    Ok(value)
}

/// A number between 1 and `u32::MAX`.
fn positive(value: i64, violation: InvalidRatePolicy) -> Result<u32, InvalidRatePolicy> {
    u32::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(violation)
}
