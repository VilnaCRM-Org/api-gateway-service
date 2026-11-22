//! The time rules every access token must satisfy.

use std::time::{Duration, SystemTime};

use crate::value_object::token_rejection::TokenRejection;

/// The time claims of a token, in whole seconds since the Unix epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenTimes {
    /// `iat`: when the token was issued.
    pub issued_at: u64,
    /// `nbf`: the first instant the token may be used, when the token names one.
    pub not_before: Option<u64>,
    /// `exp`: when the token expires.
    pub expires_at: u64,
}

/// `exp − iat` must not exceed the maximum lifetime, `iat` and `nbf` must not lie further in the
/// future than the clock skew, and `exp` must not lie further in the past than the clock skew.
///
/// The current time is injected (from the `Clock` port), so the rule is a pure function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenLifetimeRule {
    max_lifetime: Duration,
    clock_skew: Duration,
}

impl TokenLifetimeRule {
    /// The rule for `MAX_TOKEN_LIFETIME` and `JWT_CLOCK_SKEW`.
    #[must_use]
    pub const fn new(max_lifetime: Duration, clock_skew: Duration) -> Self {
        Self {
            max_lifetime,
            clock_skew,
        }
    }

    /// The longest accepted `exp − iat`.
    #[must_use]
    pub const fn max_lifetime(&self) -> Duration {
        self.max_lifetime
    }

    /// The tolerated difference between the issuer's clock and this one.
    #[must_use]
    pub const fn clock_skew(&self) -> Duration {
        self.clock_skew
    }

    /// Checks the time claims against `now`.
    ///
    /// # Errors
    ///
    /// Returns [`TokenRejection::Invalid`] when `exp` precedes `iat`, when `exp − iat` exceeds the
    /// maximum lifetime, or when `iat` or `nbf` lies beyond the skew in the future; and
    /// [`TokenRejection::Expired`] when `exp` lies beyond the skew in the past.
    pub fn check(&self, times: TokenTimes, now: SystemTime) -> Result<(), TokenRejection> {
        let lifetime = times
            .expires_at
            .checked_sub(times.issued_at)
            .ok_or(TokenRejection::Invalid)?;
        if lifetime > self.max_lifetime.as_secs() {
            return Err(TokenRejection::Invalid);
        }
        let now = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        let skew = self.clock_skew.as_secs();
        let latest_start = now.saturating_add(skew);
        let starts_late = times.not_before.is_some_and(|nbf| nbf > latest_start);
        if times.issued_at > latest_start || starts_late {
            return Err(TokenRejection::Invalid);
        }
        if times.expires_at.saturating_add(skew) < now {
            return Err(TokenRejection::Expired);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
