//! Capability 3: a Metadata request addressed to a chosen broker names the leader and the leader epoch of
//! partition 0 and the partition count.
//!
//! krafka has no public call that sends a Metadata request to a broker the caller picks: its metadata writer
//! chooses the broker. A client seeded with one broker's address sends its bootstrap Metadata request (for
//! every topic) to that broker, and `Consumer::fetch_metadata(None)` returns that answer from the cache without
//! another request. One fresh client per broker is therefore the per-broker Metadata request the replica-quorum
//! check of the freshness proof needs; the `test-broker` tests prove where the request goes.

use std::time::Duration;

use krafka::testing::{ApiKey, FakeBroker};
use krafka::{Kafka, KrafkaError, TopicInfo};

use super::{
    DEADLINE, PARTITION, POLL, bootstrap_servers, compose_broker, create_topic, unique_topic,
};

/// The node id of the compose broker (`KAFKA_NODE_ID` in `docker-compose.yml`).
const COMPOSE_BROKER: i32 = 1;

const TOPIC: &str = "iam-state";

/// What one broker's Metadata answer says about partition 0 of a topic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Leadership {
    /// The leader of partition 0, `-1` while the broker knows none.
    pub(super) leader: i32,
    /// The leader epoch of partition 0, `-1` while the broker knows none.
    pub(super) leader_epoch: i32,
    /// The partition count of the topic.
    pub(super) partitions: usize,
}

impl Leadership {
    /// Partition 0 of `topic` as one Metadata answer reported it.
    pub(super) fn of(topic: &TopicInfo) -> Option<Self> {
        topic.partition(PARTITION).map(|partition| Self {
            leader: partition.leader,
            leader_epoch: partition.leader_epoch,
            partitions: topic.partition_count(),
        })
    }
}

/// Sends one Metadata request to the broker at `address` and returns `topic` as that broker reported it, or
/// the error of a broker that cannot be reached.
pub(super) async fn try_metadata_from(
    address: &str,
    topic: &str,
) -> Result<Option<TopicInfo>, KrafkaError> {
    let kafka = Kafka::builder(address)
        .client_id("iam-spike-metadata")
        .connect_timeout(Duration::from_secs(2))
        .request_timeout(Duration::from_secs(5))
        .connect()
        .await?;
    let consumer = kafka.consumer_without_group().build().await?;
    let metadata = consumer.fetch_metadata(None).await?;
    drop(consumer);
    Ok(metadata
        .topics
        .into_iter()
        .find(|described| described.name == topic))
}

/// Partition 0 of `topic` as the broker at `address` reports it, or `None` when the broker is unreachable or
/// does not know the topic.
pub(super) async fn leadership_from(address: &str, topic: &str) -> Option<Leadership> {
    try_metadata_from(address, topic)
        .await
        .ok()
        .flatten()
        .as_ref()
        .and_then(Leadership::of)
}

/// The answer most brokers agree on and how many of them gave it; unreachable brokers do not count.
pub(super) fn quorum(reports: &[Option<Leadership>]) -> Option<(Leadership, usize)> {
    reports
        .iter()
        .flatten()
        .map(|report| {
            (
                *report,
                reports
                    .iter()
                    .filter(|other| **other == Some(*report))
                    .count(),
            )
        })
        .max_by_key(|(_, count)| *count)
}

/// Asks the broker at `address` until it names a leader for partition 0 of `topic`: a topic created a moment
/// ago may not have one yet.
async fn elected_leadership(address: &str, topic: &str) -> Option<Leadership> {
    let started = tokio::time::Instant::now();
    loop {
        let report = leadership_from(address, topic).await;
        if report.is_some_and(|leadership| leadership.leader >= 0) || started.elapsed() >= DEADLINE
        {
            return report;
        }
        tokio::time::sleep(POLL).await;
    }
}

/// Partition 0 of [`TOPIC`] as the `test-broker` cluster holds it.
fn cluster_leadership(broker: &FakeBroker) -> Option<Leadership> {
    broker.with_state(|cluster| {
        cluster
            .partition(TOPIC, PARTITION)
            .map(|partition| Leadership {
                leader: partition.leader,
                leader_epoch: partition.leader_epoch,
                partitions: 1,
            })
    })
}

/// The address of node `node_id` of a `test-broker` cluster.
fn address(broker: &FakeBroker, node_id: i32) -> String {
    broker.broker_addr(node_id).unwrap().to_string()
}

#[tokio::test]
async fn a_metadata_request_to_the_compose_broker_names_the_leader_its_epoch_and_the_partition_count()
 {
    let kafka = compose_broker().await;
    let topic = unique_topic("metadata");
    create_topic(&kafka, &topic).await;

    let reported = elected_leadership(&bootstrap_servers(), &topic).await;

    assert_eq!(
        reported.map(|leadership| (leadership.leader, leadership.partitions)),
        Some((COMPOSE_BROKER, 1)),
        "{reported:?}"
    );
    assert!(
        reported.is_some_and(|leadership| leadership.leader_epoch >= 0),
        "{reported:?}"
    );
}

#[tokio::test]
async fn a_client_seeded_with_one_broker_sends_its_metadata_request_to_that_broker() {
    let broker = FakeBroker::start_cluster(3).await.unwrap();
    assert!(broker.create_topic(TOPIC, 1));
    let chosen = 1;
    broker.clear_requests();

    let reported = leadership_from(&address(&broker, chosen), TOPIC).await;
    let nodes = broker.request_nodes(ApiKey::Metadata);

    assert_ne!(nodes, Vec::<i32>::new());
    assert!(nodes.iter().all(|node| *node == chosen), "{nodes:?}");
    assert_eq!(reported, cluster_leadership(&broker));
    assert!(reported.is_some_and(|leadership| leadership.leader_epoch >= 0));
}

#[tokio::test]
async fn after_a_leader_change_each_broker_asked_on_its_own_reports_the_new_leader_and_epoch() {
    let broker = FakeBroker::start_cluster(3).await.unwrap();
    assert!(broker.create_topic(TOPIC, 1));
    let mut before = Vec::new();
    for node in 0..3 {
        before.push(leadership_from(&address(&broker, node), TOPIC).await);
    }
    let (initial, agreeing) = quorum(&before).unwrap();
    let successor = initial
        .leader
        .checked_add(1)
        .and_then(|next| next.checked_rem(3))
        .unwrap();

    assert!(broker.set_leader(TOPIC, PARTITION, successor));
    let mut after = Vec::new();
    for node in 0..3 {
        after.push(leadership_from(&address(&broker, node), TOPIC).await);
    }

    assert_eq!(agreeing, 3, "{before:?}");
    assert_eq!(
        quorum(&after),
        Some((
            Leadership {
                leader: successor,
                leader_epoch: initial.leader_epoch.checked_add(1).unwrap(),
                partitions: 1,
            },
            3
        )),
        "{after:?}"
    );
}

#[test]
fn the_quorum_is_the_answer_most_reachable_brokers_agree_on() {
    let old = Leadership {
        leader: 1,
        leader_epoch: 4,
        partitions: 1,
    };
    let new = Leadership {
        leader: 2,
        leader_epoch: 5,
        partitions: 1,
    };

    assert_eq!(quorum(&[Some(new), None, Some(new)]), Some((new, 2)));
    assert_eq!(quorum(&[Some(old), Some(new), Some(new)]), Some((new, 2)));
    assert_eq!(quorum(&[None, None, None]), None);
}
