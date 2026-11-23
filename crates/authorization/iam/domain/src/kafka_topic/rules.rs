//! The rules of FR-72 on the configuration of the state topic.

use super::config_gates::ConfigGates;
use super::observation::{AllowEveryoneEvidence, TopicObservation};
use super::verdict::{CheckSource, ConfigurationVerdict, Violation};

/// The one principal that may write the state topic.
pub const CONTROL_PRINCIPAL: &str = "User:iam-control";

/// What a violation names as the value of a setting that the cluster did not return.
const NOT_REPORTED: &str = "not reported";

/// The setting of the broker that decides whether a topic without an ACL is open to everyone.
const ALLOW_EVERYONE: &str = "allow.everyone.if.no.acl.found";

/// Judges an observation of the state topic under one strictness.
#[derive(Debug, Clone, Copy)]
pub struct ConfigurationRules {
    gates: ConfigGates,
}

impl ConfigurationRules {
    /// The rules under `gates`.
    #[must_use]
    pub const fn new(gates: ConfigGates) -> Self {
        Self { gates }
    }

    /// The verdict on `observation`: every broken rule, in a fixed order.
    ///
    /// The topic rules always apply, with the replication factor and `min.insync.replicas` relaxed
    /// under [`ConfigGates::Relaxed`]. The ACL rules apply under [`ConfigGates::Enforce`] only.
    #[must_use]
    pub fn evaluate(self, observation: &TopicObservation) -> ConfigurationVerdict {
        let mut violations = self.topic_violations(observation);
        let source = match self.gates {
            ConfigGates::Enforce => {
                violations.extend(Self::writer_violations(observation));
                let (violation, checked) = Self::allow_everyone(observation);
                violations.extend(violation);
                checked
            }
            ConfigGates::Relaxed => None,
        };
        ConfigurationVerdict::new(self.gates, violations, source)
    }

    fn topic_violations(self, observation: &TopicObservation) -> Vec<Violation> {
        [
            exact(
                "cleanup.policy",
                "compact",
                observation.cleanup_policy.as_deref(),
            ),
            exact(
                "unclean.leader.election.enable",
                "false",
                observation.unclean_leader_election.as_deref(),
            ),
            self.min_insync_replicas(observation.min_insync_replicas.as_deref()),
            exact(
                "message.timestamp.type",
                "LogAppendTime",
                observation.message_timestamp_type.as_deref(),
            ),
            partitions(observation.partition_count),
            self.replication_factor(observation.replication_factor),
        ]
        .into_iter()
        .flatten()
        .collect()
    }

    fn min_insync_replicas(self, actual: Option<&str>) -> Option<Violation> {
        let (expected, accepted): (&str, fn(u32) -> bool) = match self.gates {
            ConfigGates::Enforce => ("2", |value| value == 2),
            ConfigGates::Relaxed => ("at least 1", |value| value >= 1),
        };
        let valid = actual
            .and_then(|text| text.parse::<u32>().ok())
            .is_some_and(accepted);
        (!valid).then(|| {
            Violation::new(
                "min.insync.replicas",
                expected,
                actual.unwrap_or(NOT_REPORTED),
            )
        })
    }

    fn replication_factor(self, actual: usize) -> Option<Violation> {
        let (expected, valid) = match self.gates {
            ConfigGates::Enforce => ("3", actual == 3),
            ConfigGates::Relaxed => ("at least 1", actual >= 1),
        };
        (!valid).then(|| Violation::new("replication.factor", expected, &actual.to_string()))
    }

    fn writer_violations(observation: &TopicObservation) -> Vec<Violation> {
        observation
            .writers
            .iter()
            .filter(|principal| principal.as_str() != CONTROL_PRINCIPAL)
            .map(|principal| {
                Violation::new("acl.write", "only User:iam-control may write", principal)
            })
            .collect()
    }

    /// The violation of `allow.everyone.if.no.acl.found`, if any, and the source of the check, when
    /// there was one.
    fn allow_everyone(observation: &TopicObservation) -> (Option<Violation>, Option<CheckSource>) {
        match &observation.allow_everyone {
            Some(AllowEveryoneEvidence::Read(value)) => (
                exact(ALLOW_EVERYONE, "false", Some(value)),
                Some(CheckSource::Broker),
            ),
            Some(AllowEveryoneEvidence::ProbeRefused) => (None, Some(CheckSource::Fallback)),
            Some(AllowEveryoneEvidence::ProbeAnswered) => (
                Some(
                    Violation::new(
                        ALLOW_EVERYONE,
                        "false",
                        "a principal without an ACL was answered",
                    )
                    .decided_by_fallback(),
                ),
                Some(CheckSource::Fallback),
            ),
            None => (
                Some(Violation::new(ALLOW_EVERYONE, "false", "not checked")),
                None,
            ),
        }
    }
}

/// A violation of `setting` unless the cluster reports exactly `expected`.
fn exact(setting: &str, expected: &str, actual: Option<&str>) -> Option<Violation> {
    (actual != Some(expected))
        .then(|| Violation::new(setting, expected, actual.unwrap_or(NOT_REPORTED)))
}

/// A violation unless the topic has exactly one partition, the one the policy log uses.
fn partitions(count: usize) -> Option<Violation> {
    (count != 1).then(|| Violation::new("partitions", "1", &count.to_string()))
}

#[cfg(test)]
mod tests;
