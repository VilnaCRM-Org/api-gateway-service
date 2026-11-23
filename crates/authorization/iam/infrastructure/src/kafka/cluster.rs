//! The reads of the inspector, as a seam between the rules and the Kafka client.

use std::sync::Arc;

use shared_domain::BoxError;

/// The settings of the state topic that the rules judge; a setting the broker did not return is
/// `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TopicSettings {
    /// `cleanup.policy`.
    pub cleanup_policy: Option<String>,
    /// `unclean.leader.election.enable`.
    pub unclean_leader_election: Option<String>,
    /// `min.insync.replicas`.
    pub min_insync_replicas: Option<String>,
    /// `message.timestamp.type`.
    pub message_timestamp_type: Option<String>,
}

/// The partitions and replicas of a topic; zero for a topic that does not exist.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TopicLayout {
    /// The number of partitions.
    pub partitions: usize,
    /// The smallest number of replicas of a partition.
    pub replication_factor: usize,
}

/// The cluster did not give an answer the inspector needs.
#[derive(Debug, thiserror::Error)]
pub enum ClusterReadError {
    /// A reply that must name the resource did not.
    #[error("the cluster returned no answer for {0}")]
    NoAnswer(String),
    /// The cluster lists no broker to ask for its configuration.
    #[error("the cluster lists no broker")]
    NoBroker,
}

/// One connection to the cluster, asked once per inspection.
#[async_trait::async_trait]
pub trait ClusterReader: std::fmt::Debug + Send + Sync {
    /// The judged settings of `topic`; all `None` for a topic that does not exist.
    async fn topic_settings(&self, topic: &str) -> Result<TopicSettings, BoxError>;

    /// The partitions and replicas of `topic`.
    async fn topic_layout(&self, topic: &str) -> Result<TopicLayout, BoxError>;

    /// The principals that hold an allowing ACL that lets them write `topic`.
    async fn topic_writers(&self, topic: &str) -> Result<Vec<String>, BoxError>;

    /// `allow.everyone.if.no.acl.found` of a broker; `None` when the broker does not return it.
    async fn allow_everyone(&self) -> Result<Option<String>, BoxError>;

    /// The negative probe: whether a principal that holds no ACL on `topic` is refused.
    async fn refuses_principal_without_acl(&self, topic: &str) -> Result<bool, BoxError>;
}

/// Opens a [`ClusterReader`].
#[async_trait::async_trait]
pub trait ClusterConnector: std::fmt::Debug + Send + Sync {
    /// Connects to the cluster.
    async fn connect(&self) -> Result<Arc<dyn ClusterReader>, BoxError>;
}
