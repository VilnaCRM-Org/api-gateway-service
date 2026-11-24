//! The wiring of the anti-entropy task: its ports over PostgreSQL and the state topic, its
//! settings, and the counter and the hold that it shares with the outbox relay (FR-77).

use std::sync::Arc;

use iam_application::{AntiEntropyCounters, AntiEntropyPorts, AntiEntropySettings, TopicAheadHold};
use iam_infrastructure::{
    JsonStateRecordCodec, KrafkaPolicyLogTail, PgAntiEntropyStore, PgTaskStateRepository,
    Sha256PolicyDigest,
};

use crate::config::Config;

/// What the anti-entropy task needs from the composition root.
#[derive(Debug, Clone)]
pub struct AntiEntropyAdapters {
    /// The reads of PostgreSQL and of the state topic.
    pub ports: AntiEntropyPorts,
    /// The head interval and the full interval.
    pub settings: AntiEntropySettings,
    /// `anti_entropy_repairs_total`.
    pub counters: Arc<AntiEntropyCounters>,
    /// Set while the topic is ahead of PostgreSQL; the relay publishes nothing then.
    pub hold: Arc<TopicAheadHold>,
}

impl AntiEntropyAdapters {
    /// The production wiring over the pool of the application and the Kafka connection of
    /// `iam-control`.
    #[must_use]
    pub fn connect(config: &Config, pool: &sqlx::PgPool) -> Self {
        Self {
            ports: AntiEntropyPorts {
                store: Arc::new(PgAntiEntropyStore::new(pool.clone())),
                tail: Arc::new(KrafkaPolicyLogTail::new(config.kafka.clone())),
                task_states: Arc::new(PgTaskStateRepository::new(pool.clone())),
                codec: Arc::new(JsonStateRecordCodec),
                digest: Arc::new(Sha256PolicyDigest),
            },
            settings: config.anti_entropy,
            counters: Arc::new(AntiEntropyCounters::new()),
            hold: Arc::new(TopicAheadHold::new()),
        }
    }
}
