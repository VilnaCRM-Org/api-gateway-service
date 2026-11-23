//! The Kafka health probe: the cluster answers and the state topic passes its configuration rules.

use std::sync::Arc;

use health_check_domain::{Dependency, HealthProbe};
use iam_domain::KafkaTopicInspector;
use shared_domain::BoxError;

/// The state topic breaks a configuration rule.
#[derive(Debug, thiserror::Error)]
#[error("the Kafka topic configuration breaks a rule: {0}")]
struct TopicConfigurationBroken(String);

/// Healthy when the inspector reaches the cluster and its verdict passes.
#[derive(Debug)]
pub struct KafkaProbe {
    inspector: Arc<dyn KafkaTopicInspector>,
}

impl KafkaProbe {
    /// A probe over `inspector`.
    #[must_use]
    pub fn new(inspector: Arc<dyn KafkaTopicInspector>) -> Self {
        Self { inspector }
    }

    /// Probe logic, kept out of the `#[async_trait]` body so coverage and complexity see it.
    async fn probe(&self) -> Result<(), BoxError> {
        let verdict = self.inspector.inspect().await?;
        if verdict.passed() {
            Ok(())
        } else {
            Err(TopicConfigurationBroken(verdict.describe()).into())
        }
    }
}

#[async_trait::async_trait]
impl HealthProbe for KafkaProbe {
    fn dependency(&self) -> Dependency {
        Dependency::Kafka
    }

    async fn check(&self) -> Result<(), BoxError> {
        self.probe().await
    }
}

#[cfg(test)]
mod tests;
