//! Port that checks the configuration of the Kafka state topic (FR-54, FR-55, FR-72).

use shared_domain::BoxError;

use crate::kafka_topic::ConfigurationVerdict;

/// The cluster could not be asked.
#[derive(Debug, thiserror::Error)]
pub enum KafkaInspectionError {
    /// The cluster cannot be reached, refused the connection or answered with a failure.
    #[error("the Kafka cluster is unavailable")]
    Unavailable(#[source] BoxError),
}

/// Reads the configuration and the ACLs of the state topic and judges them.
///
/// The relay of Story 7.4 consults the verdict before it publishes; the readiness probe reports
/// the dependency healthy only while the cluster answers and the verdict passes.
#[async_trait::async_trait]
pub trait KafkaTopicInspector: std::fmt::Debug + Send + Sync {
    /// Reads the cluster once and returns the verdict under the gates the inspector was built with.
    ///
    /// # Errors
    ///
    /// [`KafkaInspectionError::Unavailable`] when the cluster cannot be asked; a topic that is
    /// misconfigured is a failed verdict, not an error.
    async fn inspect(&self) -> Result<ConfigurationVerdict, KafkaInspectionError>;
}
