//! The strictness of the Kafka configuration gates.

/// How strictly the configuration of the state topic is judged (`KAFKA_CONFIG_GATES`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigGates {
    /// Every rule of FR-72 applies: replication factor 3, `min.insync.replicas` 2 and the ACL
    /// checks.
    Enforce,
    /// The rules that a single-node compose broker cannot meet are relaxed: any replication factor
    /// and any `min.insync.replicas` of at least 1 pass, and the ACL checks are skipped. Only
    /// `dev` and `test` may use it.
    Relaxed,
}

impl ConfigGates {
    /// The value of `KAFKA_CONFIG_GATES` that selects the gate.
    #[must_use]
    pub const fn identifier(self) -> &'static str {
        match self {
            Self::Enforce => "enforce",
            Self::Relaxed => "relaxed",
        }
    }
}

#[cfg(test)]
mod tests;
