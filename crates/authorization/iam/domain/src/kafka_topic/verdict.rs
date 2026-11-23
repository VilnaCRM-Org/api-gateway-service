//! The verdict on the configuration of the state topic.

use super::config_gates::ConfigGates;

/// Where the value behind a check came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckSource {
    /// The broker or the topic reported the value.
    Broker,
    /// The broker does not report the value; the negative probe of Story 1.3 decided.
    Fallback,
}

impl CheckSource {
    /// The word that names the source in a log line.
    #[must_use]
    pub const fn identifier(self) -> &'static str {
        match self {
            Self::Broker => "broker",
            Self::Fallback => "fallback",
        }
    }
}

/// One setting that breaks a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// The offending setting, such as `cleanup.policy`.
    pub setting: String,
    /// What the rule requires.
    pub expected: String,
    /// What the cluster has; `not reported` when it returned nothing.
    pub actual: String,
    /// Where the value came from.
    pub source: CheckSource,
}

impl Violation {
    /// A violation of `setting` that the broker reported.
    #[must_use]
    pub fn new(setting: &str, expected: &str, actual: &str) -> Self {
        Self {
            setting: setting.to_owned(),
            expected: expected.to_owned(),
            actual: actual.to_owned(),
            source: CheckSource::Broker,
        }
    }

    /// The same violation, decided by the fallback.
    #[must_use]
    pub const fn decided_by_fallback(mut self) -> Self {
        self.source = CheckSource::Fallback;
        self
    }
}

/// Whether the state topic may be published to, and why not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigurationVerdict {
    gates: ConfigGates,
    violations: Vec<Violation>,
    allow_everyone_source: Option<CheckSource>,
}

impl ConfigurationVerdict {
    /// A verdict under `gates` with its `violations` and the source of the
    /// `allow.everyone.if.no.acl.found` check, when that was made.
    #[must_use]
    pub const fn new(
        gates: ConfigGates,
        violations: Vec<Violation>,
        allow_everyone_source: Option<CheckSource>,
    ) -> Self {
        Self {
            gates,
            violations,
            allow_everyone_source,
        }
    }

    /// Whether no rule is broken.
    #[must_use]
    pub const fn passed(&self) -> bool {
        self.violations.is_empty()
    }

    /// The gates the verdict was reached under.
    #[must_use]
    pub const fn gates(&self) -> ConfigGates {
        self.gates
    }

    /// The broken rules, in the order they were checked.
    #[must_use]
    pub fn violations(&self) -> &[Violation] {
        &self.violations
    }

    /// Where the `allow.everyone.if.no.acl.found` check got its value; `None` when the check was
    /// not made (relaxed gates).
    #[must_use]
    pub const fn allow_everyone_source(&self) -> Option<CheckSource> {
        self.allow_everyone_source
    }

    /// The offending settings with what is wrong, for a log line or an error message; empty when
    /// the verdict passed.
    #[must_use]
    pub fn describe(&self) -> String {
        self.violations
            .iter()
            .map(|violation| {
                format!(
                    "{} is {} but must be {} ({})",
                    violation.setting,
                    violation.actual,
                    violation.expected,
                    violation.source.identifier()
                )
            })
            .collect::<Vec<_>>()
            .join("; ")
    }
}

#[cfg(test)]
mod tests;
