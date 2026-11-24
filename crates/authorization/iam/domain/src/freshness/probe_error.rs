//! Why a probe of the state topic produced no proof.

/// A probe that fails produces no proof, however plausible the answers it did get.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProbeError {
    /// The cluster could not be asked or did not answer in time.
    #[error("the cluster could not be asked: {0}")]
    Unavailable(String),
    /// Fewer replica brokers answered than the quorum needs.
    #[error("{answered} replica brokers answered, {needed} are needed")]
    QuorumShort {
        /// The brokers that answered.
        answered: usize,
        /// The brokers the quorum needs.
        needed: usize,
    },
    /// The replica brokers name different leaders or different leader epochs.
    #[error("the replica brokers disagree on the leader or its epoch")]
    LeaderDisagreement,
    /// The leader epoch is lower than one the probe saw before.
    #[error("the leader epoch {reported} is lower than the epoch {seen} seen before")]
    EpochRegressed {
        /// The highest epoch seen.
        seen: i32,
        /// The epoch the brokers report now.
        reported: i32,
    },
    /// The state topic has other than exactly one partition.
    #[error("the state topic has {found} partitions, exactly one is required")]
    PartitionCount {
        /// The partitions the brokers report.
        found: usize,
    },
    /// The broker answered `OFFSET_NOT_AVAILABLE`.
    #[error("the broker answered OFFSET_NOT_AVAILABLE")]
    OffsetNotAvailable,
    /// The broker answered `FENCED_LEADER_EPOCH`.
    #[error("the broker answered FENCED_LEADER_EPOCH")]
    FencedLeaderEpoch,
    /// The broker answered `UNKNOWN_LEADER_EPOCH`.
    #[error("the broker answered UNKNOWN_LEADER_EPOCH")]
    UnknownLeaderEpoch,
    /// The watermark is lower than one the probe saw before.
    #[error("the watermark went back from {seen} to {reported}")]
    WatermarkRegressed {
        /// The highest watermark seen.
        seen: i64,
        /// The watermark the broker reports now.
        reported: i64,
    },
    /// A partition other than the state partition holds records.
    #[error("partition {partition} holds records, only the state partition may")]
    OtherPartitionWritten {
        /// The partition.
        partition: i32,
    },
}
