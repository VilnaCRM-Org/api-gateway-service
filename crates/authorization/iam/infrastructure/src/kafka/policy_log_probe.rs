//! `KrafkaPolicyLogProbe`: the probe that proves the freshness of a pod against the state topic
//! (FR-73, NFR-36, ADR 0024).
//!
//! One probe records `t_s` on the boot clock before it sends anything, asks the replica brokers
//! of the state partition for its metadata, each through a client seeded with that broker only,
//! and accepts the answers only when at least a majority of the replicas answered with the same
//! leader and leader epoch, the epoch is at least the highest one seen and the topic has exactly
//! one partition. Then it sends `ListOffsets` with the isolation `READ_COMMITTED` for every
//! partition through the consumer path, which carries the leader epoch of its freshly refreshed
//! metadata, so the answer for the state partition is the last stable offset, `HW(t_s)`. Any error
//! code, a regressed watermark or records on another partition yield no proof.

mod join;
mod judge;

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use iam_domain::freshness::proof::FreshnessProof;
use iam_domain::{BootClock, PolicyLogProbe, ProbeError, STATE_PARTITION};
use krafka::consumer::{Consumer, IsolationLevel};
use krafka::{BrokerInfo, KrafkaError, PartitionInfo, TopicInfo};

use self::join::{Pending, join_all};
use self::judge::{Leadership, Seen, agreed, failure, quorum_needed};
use super::krafka_cluster::{authenticated, builder};
use super::settings::KafkaSettings;

/// Probes the state topic for the proof of freshness.
pub struct KrafkaPolicyLogProbe {
    settings: KafkaSettings,
    clock: Arc<dyn BootClock>,
    seen: Mutex<Seen>,
    consumer: Mutex<Option<Arc<Consumer>>>,
}

impl std::fmt::Debug for KrafkaPolicyLogProbe {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KrafkaPolicyLogProbe")
            .field("topic", &self.settings.policy_topic)
            .finish_non_exhaustive()
    }
}

/// The topic as one metadata answer shows it.
struct Layout {
    topic: TopicInfo,
    partition: PartitionInfo,
    brokers: Vec<BrokerInfo>,
}

impl KrafkaPolicyLogProbe {
    /// A probe of the state topic of `settings`, which carry the principal `iam-gateway`. Nothing
    /// is opened until the first probe; `clock` is where `t_s` is read.
    #[must_use]
    pub fn new(settings: KafkaSettings, clock: Arc<dyn BootClock>) -> Self {
        Self {
            settings,
            clock,
            seen: Mutex::new(Seen::default()),
            consumer: Mutex::new(None),
        }
    }

    async fn consumer(&self) -> Result<Arc<Consumer>, ProbeError> {
        let open = self
            .consumer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(consumer) = open {
            return Ok(consumer);
        }
        let opened = Arc::new(
            open_consumer(&self.settings)
                .await
                .map_err(|error| failure(&error))?,
        );
        *self.consumer.lock().unwrap_or_else(PoisonError::into_inner) = Some(Arc::clone(&opened));
        Ok(opened)
    }

    /// Takes the cached consumer, if any, and closes it, so the next probe opens a new one.
    async fn release(&self) {
        let open = self
            .consumer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(consumer) = open {
            report_close(consumer.close().await);
        }
    }

    /// The metadata of the state topic, freshly fetched from the cluster.
    async fn layout(&self, consumer: &Consumer) -> Result<Layout, ProbeError> {
        let metadata = consumer
            .fetch_metadata(Some(&self.settings.policy_topic))
            .await
            .map_err(|error| failure(&error))?;
        layout_of(
            metadata.topics,
            metadata.brokers,
            &self.settings.policy_topic,
        )
    }

    /// What each replica broker that answers reports about the state partition.
    async fn replica_views(&self, layout: &Layout) -> Vec<Leadership> {
        let mut asks: Vec<Pending<'_, Option<Leadership>>> = Vec::new();
        for replica in &layout.partition.replicas {
            let Some(broker) = layout.brokers.iter().find(|broker| broker.id() == *replica) else {
                continue;
            };
            let settings = KafkaSettings {
                bootstrap_servers: broker.address().to_owned(),
                ..self.settings.clone()
            };
            asks.push(Box::pin(ask_broker(settings)));
        }
        join_all(asks).await.into_iter().flatten().collect()
    }

    /// The last stable offset of the state partition, with `ListOffsets` sent for every
    /// partition of the topic.
    async fn last_stable_offset(
        &self,
        consumer: &Consumer,
        layout: &Layout,
    ) -> Result<i64, ProbeError> {
        let stable = self.high_watermark(consumer, STATE_PARTITION).await?;
        let mut others: Vec<i32> = layout
            .topic
            .partitions
            .keys()
            .copied()
            .filter(|partition| *partition != STATE_PARTITION)
            .collect();
        others.sort_unstable();
        for partition in others {
            if self.high_watermark(consumer, partition).await? != 0 {
                return Err(ProbeError::OtherPartitionWritten { partition });
            }
        }
        Ok(stable)
    }

    async fn high_watermark(&self, consumer: &Consumer, partition: i32) -> Result<i64, ProbeError> {
        let (_low, high) = consumer
            .fetch_watermarks(&self.settings.policy_topic, partition)
            .await
            .map_err(|error| failure(&error))?;
        Ok(high)
    }

    async fn measure(&self) -> Result<i64, ProbeError> {
        let consumer = self.consumer().await?;
        let layout = self.layout(&consumer).await?;
        let own = leadership_of(&layout.partition)?;
        let needed = quorum_needed(layout.partition.replicas.len());
        let asked = self.replica_views(&layout).await;
        if asked.len() < needed {
            return Err(ProbeError::QuorumShort {
                answered: asked.len(),
                needed,
            });
        }
        let leadership = agreed(own, &asked)?;
        self.seen().admit_epoch(leadership.epoch)?;
        let stable = self.last_stable_offset(&consumer, &layout).await;
        drop(consumer);
        let stable = stable?;
        let found = layout.topic.partitions.len();
        if found != 1 {
            return Err(ProbeError::PartitionCount { found });
        }
        self.seen().admit_watermark(stable)?;
        Ok(stable)
    }

    fn seen(&self) -> std::sync::MutexGuard<'_, Seen> {
        self.seen.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[async_trait::async_trait]
impl PolicyLogProbe for KrafkaPolicyLogProbe {
    async fn probe(&self) -> Result<FreshnessProof, ProbeError> {
        let taken_at = self.clock.now();
        let measured = self.measure().await;
        if matches!(measured, Err(ProbeError::Unavailable(_))) {
            self.release().await;
        }
        measured.map(|watermark| FreshnessProof {
            taken_at,
            watermark,
        })
    }
}

/// The layout of the state topic in the metadata answer: the topic, its state partition and the
/// brokers.
fn layout_of(
    topics: Vec<TopicInfo>,
    brokers: Vec<BrokerInfo>,
    name: &str,
) -> Result<Layout, ProbeError> {
    let topic = topics
        .into_iter()
        .find(|topic| topic.name == name)
        .ok_or_else(|| unavailable("the cluster does not list the state topic"))?;
    let partition = topic
        .partitions
        .get(&STATE_PARTITION)
        .cloned()
        .ok_or_else(|| unavailable("the state topic has no state partition"))?;
    Ok(Layout {
        topic,
        partition,
        brokers,
    })
}

fn unavailable(reason: &str) -> ProbeError {
    ProbeError::Unavailable(reason.to_owned())
}

/// The leader and the epoch of a partition that has both.
fn leadership_of(partition: &PartitionInfo) -> Result<Leadership, ProbeError> {
    if !partition.is_routable() || partition.leader_epoch < 0 {
        return Err(unavailable(
            "the state partition has no leader or no leader epoch",
        ));
    }
    Ok(Leadership {
        leader: partition.leader,
        epoch: partition.leader_epoch,
    })
}

/// The reader of the probe: `read_committed`, so that `ListOffsets` answers the last stable
/// offset, and a metadata cache that is never fresh, so that every probe asks the cluster again.
async fn open_consumer(settings: &KafkaSettings) -> Result<Consumer, KrafkaError> {
    let kafka = builder(settings, authenticated(settings))
        .metadata_max_age(Duration::ZERO)
        .connect()
        .await?;
    kafka
        .consumer_without_group()
        .isolation_level(IsolationLevel::ReadCommitted)
        .enable_auto_commit(false)
        .build()
        .await
}

/// Asks the one broker `settings` name for the metadata of the state topic: the bootstrap
/// request of a fresh client goes to the broker it is seeded with and to no other. A broker that
/// does not answer, or does not describe a routable state partition, gives no view.
async fn ask_broker(settings: KafkaSettings) -> Option<Leadership> {
    let kafka = builder(&settings, authenticated(&settings))
        .connect()
        .await
        .ok()?;
    let consumer = kafka.consumer_without_group().build().await.ok()?;
    let metadata = consumer.fetch_metadata(None).await;
    report_close(consumer.close().await);
    drop(consumer);
    let topic = metadata
        .ok()?
        .topics
        .into_iter()
        .find(|topic| topic.name == settings.policy_topic)?;
    leadership_of(topic.partitions.get(&STATE_PARTITION)?).ok()
}

fn report_close(closed: Result<(), KrafkaError>) {
    if let Err(error) = closed {
        log_unclosed(&error);
    }
}

fn log_unclosed(error: &KrafkaError) {
    tracing::warn!(%error, "a reader of the freshness probe did not close cleanly");
}

#[cfg(test)]
mod tests;
