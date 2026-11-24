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

/// What the negative probe found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// An authenticated principal without an ACL was refused by the broker.
    Refused,
    /// A principal without an ACL was answered.
    Answered,
    /// The probe could not be run, as no probe principal is configured; it is no evidence.
    NotChecked,
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

    /// `allow.everyone.if.no.acl.found` of the cluster, read from every broker: `Some("true")` (or
    /// another value other than `false`) when any broker reports it, `Some("false")` when every
    /// broker reports `false`, and `None` when a broker does not report it.
    async fn allow_everyone(&self) -> Result<Option<String>, BoxError>;

    /// The negative probe: whether an authenticated principal that holds no ACL on `topic` is
    /// refused. A network error is an error, never a refusal.
    async fn probe_principal_without_acl(&self, topic: &str) -> Result<ProbeOutcome, BoxError>;
}

/// Opens a [`ClusterReader`].
#[async_trait::async_trait]
pub trait ClusterConnector: std::fmt::Debug + Send + Sync {
    /// Connects to the cluster.
    async fn connect(&self) -> Result<Arc<dyn ClusterReader>, BoxError>;
}
