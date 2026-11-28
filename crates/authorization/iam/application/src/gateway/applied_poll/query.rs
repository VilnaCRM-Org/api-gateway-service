//! The query string of `GET /internal/policy/applied` (Story 13.3).

use std::time::Duration;

use iam_domain::PolicyVersion;
use serde::Deserialize;
use validator::Validate;

/// `atLeast=V&offset=O&wait=T`: the version the write produced, the offset of the write in the
/// state topic and how long the caller is willing to wait, in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Validate)]
pub struct AppliedQuery {
    /// The version the pod must have published and re-evaluated its streams for.
    #[serde(rename = "atLeast")]
    #[validate(range(min = 0))]
    pub at_least: i64,
    /// The offset of the write, which a bootstrapping pod compares with its captured `HW0`.
    #[validate(range(min = 0))]
    pub offset: i64,
    /// The longest the caller waits, in milliseconds; the pod caps it.
    pub wait: u64,
}

impl AppliedQuery {
    /// The version, which validation has shown to be at least zero.
    #[must_use]
    pub fn version(&self) -> PolicyVersion {
        PolicyVersion::new(self.at_least).unwrap_or(PolicyVersion::ZERO)
    }

    /// The wait the caller asked for.
    #[must_use]
    pub const fn wait(&self) -> Duration {
        Duration::from_millis(self.wait)
    }
}

#[cfg(test)]
mod tests;
