//! `KrafkaTopicInspector`: reads the state topic and its cluster and judges them (FR-72).

use std::sync::Arc;

use iam_domain::{
    AllowEveryoneEvidence, ConfigGates, ConfigurationRules, ConfigurationVerdict,
    KafkaInspectionError, KafkaTopicInspector, TopicObservation,
};
use shared_domain::{BoxError, error_chain};

use super::cluster::{ClusterConnector, ClusterReader};
use super::krafka_cluster::KrafkaConnector;
use super::settings::KafkaSettings;

/// Checks the configuration and the ACLs of the state topic.
///
/// Every inspection opens its own connection, so a cluster that was down is found again as soon as
/// it is back. Under [`ConfigGates::Relaxed`] every inspection logs a warning that names the
/// relaxed gate.
#[derive(Debug)]
pub struct KrafkaTopicInspector {
    connector: Arc<dyn ClusterConnector>,
    topic: String,
    gates: ConfigGates,
}

impl KrafkaTopicInspector {
    /// An inspector of the `POLICY_TOPIC` of `settings`, under its `KAFKA_CONFIG_GATES`; nothing
    /// is opened until the first inspection.
    #[must_use]
    pub fn new(settings: &KafkaSettings) -> Self {
        Self::with_connector(
            Arc::new(KrafkaConnector::new(settings.clone())),
            settings.policy_topic.clone(),
            settings.gates,
        )
    }

    /// An inspector of `topic` that reads the cluster through `connector`.
    #[must_use]
    pub fn with_connector(
        connector: Arc<dyn ClusterConnector>,
        topic: String,
        gates: ConfigGates,
    ) -> Self {
        Self {
            connector,
            topic,
            gates,
        }
    }

    /// Reads everything the rules of the gates need.
    async fn observe(&self, cluster: &dyn ClusterReader) -> Result<TopicObservation, BoxError> {
        let settings = cluster.topic_settings(&self.topic).await?;
        let layout = cluster.topic_layout(&self.topic).await?;
        let (writers, allow_everyone) = match self.gates {
            ConfigGates::Enforce => (
                cluster.topic_writers(&self.topic).await?,
                Some(self.allow_everyone(cluster).await?),
            ),
            ConfigGates::Relaxed => (Vec::new(), None),
        };
        Ok(TopicObservation {
            cleanup_policy: settings.cleanup_policy,
            unclean_leader_election: settings.unclean_leader_election,
            min_insync_replicas: settings.min_insync_replicas,
            message_timestamp_type: settings.message_timestamp_type,
            partition_count: layout.partitions,
            replication_factor: layout.replication_factor,
            writers,
            allow_everyone,
        })
    }

    /// `allow.everyone.if.no.acl.found` from the broker, or from the negative probe when the
    /// broker does not return it.
    async fn allow_everyone(
        &self,
        cluster: &dyn ClusterReader,
    ) -> Result<AllowEveryoneEvidence, BoxError> {
        if let Some(value) = cluster.allow_everyone().await? {
            return Ok(AllowEveryoneEvidence::Read(value));
        }
        let refused = cluster.refuses_principal_without_acl(&self.topic).await?;
        Ok(if refused {
            AllowEveryoneEvidence::ProbeRefused
        } else {
            AllowEveryoneEvidence::ProbeAnswered
        })
    }

    async fn verdict(&self) -> Result<ConfigurationVerdict, BoxError> {
        let cluster = self.connector.connect().await?;
        let observation = self.observe(cluster.as_ref()).await?;
        Ok(ConfigurationRules::new(self.gates).evaluate(&observation))
    }

    fn log(&self, verdict: &ConfigurationVerdict) {
        if self.gates == ConfigGates::Relaxed {
            self.warn_relaxed();
        }
        if !verdict.passed() {
            self.warn_violations(verdict);
        }
    }

    fn warn_relaxed(&self) {
        let gates = self.gates.identifier();
        tracing::warn!(
            topic = %self.topic,
            gates,
            "KAFKA_CONFIG_GATES is relaxed: the replication factor, min.insync.replicas and the ACLs are not enforced"
        );
    }

    fn warn_violations(&self, verdict: &ConfigurationVerdict) {
        let violations = verdict.describe();
        tracing::warn!(
            topic = %self.topic,
            violations = %violations,
            "the Kafka topic configuration breaks a rule"
        );
    }

    async fn inspect_topic(&self) -> Result<ConfigurationVerdict, KafkaInspectionError> {
        let verdict = self.verdict().await.map_err(|error| {
            let cause = error_chain(error.as_ref());
            tracing::warn!(
                topic = %self.topic,
                cause = %cause,
                "the Kafka cluster could not be inspected"
            );
            KafkaInspectionError::Unavailable(error)
        })?;
        self.log(&verdict);
        Ok(verdict)
    }
}

#[async_trait::async_trait]
impl KafkaTopicInspector for KrafkaTopicInspector {
    async fn inspect(&self) -> Result<ConfigurationVerdict, KafkaInspectionError> {
        self.inspect_topic().await
    }
}

#[cfg(test)]
mod tests;
