//! Kafka topic inspector double of the IAM context.

use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use iam_domain::{
    ConfigGates, ConfigurationVerdict, KafkaInspectionError, KafkaTopicInspector, Violation,
};

/// What the double answers.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Reply {
    Passed,
    Failed(Vec<Violation>),
    Unreachable,
}

/// An inspector that gives the same answer every time and counts its calls.
#[derive(Debug)]
pub struct FakeTopicInspector {
    reply: Reply,
    inspections: AtomicUsize,
}

impl FakeTopicInspector {
    /// An inspector whose verdict passes.
    #[must_use]
    pub const fn passing() -> Self {
        Self {
            reply: Reply::Passed,
            inspections: AtomicUsize::new(0),
        }
    }

    /// An inspector whose verdict fails with `violations`.
    #[must_use]
    pub const fn failing(violations: Vec<Violation>) -> Self {
        Self {
            reply: Reply::Failed(violations),
            inspections: AtomicUsize::new(0),
        }
    }

    /// An inspector that cannot reach the cluster.
    #[must_use]
    pub const fn unreachable() -> Self {
        Self {
            reply: Reply::Unreachable,
            inspections: AtomicUsize::new(0),
        }
    }

    /// How many times the cluster was asked.
    #[must_use]
    pub fn inspections(&self) -> usize {
        self.inspections.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl KafkaTopicInspector for FakeTopicInspector {
    async fn inspect(&self) -> Result<ConfigurationVerdict, KafkaInspectionError> {
        self.inspections.fetch_add(1, Ordering::SeqCst);
        match &self.reply {
            Reply::Passed => Ok(ConfigurationVerdict::new(
                ConfigGates::Relaxed,
                Vec::new(),
                None,
            )),
            Reply::Failed(violations) => Ok(ConfigurationVerdict::new(
                ConfigGates::Relaxed,
                violations.clone(),
                None,
            )),
            Reply::Unreachable => Err(KafkaInspectionError::Unavailable(
                "in-memory cluster outage".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests;
