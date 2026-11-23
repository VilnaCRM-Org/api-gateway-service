//! What the infrastructure layer read from the cluster about the state topic.

/// What was learned about `allow.everyone.if.no.acl.found`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowEveryoneEvidence {
    /// `DescribeConfigs` on the broker returned this value.
    Read(String),
    /// The broker did not return the setting, and the fallback of Story 1.3 (a negative probe
    /// by a principal that holds no ACL on the state topic) was refused with
    /// `TOPIC_AUTHORIZATION_FAILED`.
    ProbeRefused,
    /// The broker did not return the setting, and the principal without an ACL was answered: the
    /// cluster allows everyone when no ACL is found.
    ProbeAnswered,
}

/// The configuration of the state topic and of its cluster, as the cluster reports it.
///
/// A setting the broker did not return is `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopicObservation {
    /// `cleanup.policy` of the topic.
    pub cleanup_policy: Option<String>,
    /// `unclean.leader.election.enable` of the topic.
    pub unclean_leader_election: Option<String>,
    /// `min.insync.replicas` of the topic.
    pub min_insync_replicas: Option<String>,
    /// `message.timestamp.type` of the topic.
    pub message_timestamp_type: Option<String>,
    /// The number of partitions.
    pub partition_count: usize,
    /// The smallest number of replicas of a partition; 0 when the topic has no partition.
    pub replication_factor: usize,
    /// The principals, such as `User:iam-control` or `User:*`, that hold an allowing ACL that lets
    /// them write the topic.
    pub writers: Vec<String>,
    /// `allow.everyone.if.no.acl.found`; `None` when it was not gathered.
    pub allow_everyone: Option<AllowEveryoneEvidence>,
}
