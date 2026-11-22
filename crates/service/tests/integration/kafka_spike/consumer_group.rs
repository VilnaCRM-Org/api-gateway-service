//! Capability 8: consumer-group membership with a manual commit after processing, and the rebalance when a
//! member leaves holding records it processed but did not commit, as `iam-control` consumes
//! `user.events.v1` (FR-18).
//!
//! Two members of one group (KIP-848 protocol, no auto-commit) share a three-partition topic on the compose
//! broker. Both commit the first batch after processing it; of the second batch, member A commits and
//! member B does not, then B leaves the group. A must be given B's partitions and receive exactly B's
//! uncommitted records again, and no committed record a second time.
//!
//! A poll can surface a retriable coordinator error (`NOT_COORDINATOR` while a fresh broker still loads
//! `__consumer_offsets`): krafka drops the cached coordinator and the next poll re-discovers it, so the
//! members poll again, as the `iam-control` consume loop must.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use krafka::admin::{CreateTopicsOptions, NewTopic};
use krafka::consumer::{
    AutoOffsetReset, Consumer, ConsumerRebalanceListener, GroupProtocol, TopicPartition,
};
use krafka::{ConsumerRecord, Kafka, KrafkaError, Record};

use super::{DEADLINE, POLL, compose_broker, unique_topic};

/// The partition count of the test topic.
const PARTITIONS: i32 = 3;

/// The records each batch writes to every partition.
const PER_PARTITION: usize = 4;

/// Polls an assignment must stay unchanged to count as settled.
const SETTLED_POLLS: usize = 3;

/// A record's identity: its partition and offset.
type Position = (i32, i64);

/// The partitions a member was given and had taken away, as the rebalance callbacks reported them.
#[derive(Default)]
struct Rebalances {
    assigned: Mutex<Vec<i32>>,
    revoked: Mutex<Vec<i32>>,
}

impl Rebalances {
    fn assigned(&self) -> Vec<i32> {
        self.assigned.lock().unwrap().clone()
    }

    /// The partitions revoked after the first `skip` revocations.
    fn revoked_after(&self, skip: usize) -> Vec<i32> {
        self.revoked
            .lock()
            .unwrap()
            .iter()
            .skip(skip)
            .copied()
            .collect()
    }

    fn revocation_count(&self) -> usize {
        self.revoked.lock().unwrap().len()
    }
}

impl ConsumerRebalanceListener for Rebalances {
    async fn on_partitions_assigned(&self, partitions: &[TopicPartition]) {
        self.assigned
            .lock()
            .unwrap()
            .extend(partitions.iter().map(|partition| partition.partition));
    }

    async fn on_partitions_revoked(&self, partitions: &[TopicPartition]) {
        self.revoked
            .lock()
            .unwrap()
            .extend(partitions.iter().map(|partition| partition.partition));
    }
}

/// What one member received, in delivery order.
#[derive(Default)]
struct Deliveries(Vec<Position>);

impl Deliveries {
    fn record(&mut self, records: &[ConsumerRecord]) {
        self.0.extend(
            records
                .iter()
                .map(|record| (record.partition, record.offset)),
        );
    }

    fn set(&self) -> BTreeSet<Position> {
        self.0.iter().copied().collect()
    }
}

async fn create_partitioned_topic(kafka: &Kafka, topic: &str) {
    let results = kafka
        .admin()
        .create_topics(
            [NewTopic::new(topic, PARTITIONS, 1).unwrap()],
            CreateTopicsOptions::default(),
        )
        .await
        .unwrap();
    assert!(matches!(results.get(topic), Some(Ok(()))), "{results:?}");
}

/// Writes [`PER_PARTITION`] records to every partition and returns their positions.
async fn produce_batch(kafka: &Kafka, topic: &str, batch: &str) -> BTreeSet<Position> {
    let producer = kafka.producer().build().await.unwrap();
    let mut written = BTreeSet::new();
    for partition in 0..PARTITIONS {
        for index in 0..PER_PARTITION {
            let value = format!("{batch}-p{partition}-{index}");
            let sent = producer
                .send(Record::new(topic.to_owned(), value).partition(partition))
                .await
                .unwrap();
            written.insert((sent.partition, sent.offset));
        }
    }
    producer.flush().await.unwrap();
    drop(producer);
    written
}

/// A group member that commits by hand and starts a partition without a committed offset at its start.
async fn member(kafka: &Kafka, group: &str, topic: &str, listener: Arc<Rebalances>) -> Consumer {
    let consumer = kafka
        .consumer(group)
        .group_protocol(GroupProtocol::Consumer)
        .enable_auto_commit(false)
        .auto_offset_reset(AutoOffsetReset::Earliest)
        .fetch_max_wait(Duration::from_millis(100))
        .rebalance_listener(listener)
        .build()
        .await
        .unwrap();
    consumer.subscribe([topic]).await.unwrap();
    consumer
}

/// The records of one poll; a retriable error (the coordinator moved or is still loading) delivered
/// nothing, and the next poll re-discovers the coordinator. Any other error fails the test.
fn delivered(result: Result<Vec<ConsumerRecord>, KrafkaError>) -> Vec<ConsumerRecord> {
    match result {
        Ok(records) => records,
        Err(error) if error.is_retriable() => Vec::new(),
        Err(error) => panic!("poll failed: {error:?}"),
    }
}

async fn assigned(consumer: &Consumer, topic: &str) -> BTreeSet<i32> {
    consumer
        .assignment()
        .await
        .get(topic)
        .map(|partitions| partitions.iter().copied().collect())
        .unwrap_or_default()
}

/// Polls both members until they split the topic between them and the split held for
/// [`SETTLED_POLLS`] polls; the topic is still empty, so nothing is delivered.
async fn settle_split(a: &Consumer, b: &Consumer, topic: &str) -> (BTreeSet<i32>, BTreeSet<i32>) {
    let started = tokio::time::Instant::now();
    let mut last = (BTreeSet::new(), BTreeSet::new());
    let mut unchanged = 0;
    while unchanged < SETTLED_POLLS && started.elapsed() < DEADLINE {
        let (from_a, from_b) = tokio::join!(a.poll(POLL), b.poll(POLL));
        assert!(delivered(from_a).is_empty() && delivered(from_b).is_empty());
        let split = (assigned(a, topic).await, assigned(b, topic).await);
        let complete = !split.0.is_empty()
            && !split.1.is_empty()
            && split.0.union(&split.1).count() == usize::try_from(PARTITIONS).unwrap();
        unchanged = if complete && split == last {
            unchanged.saturating_add(1)
        } else {
            0
        };
        last = split;
    }
    last
}

/// Polls both members until `expected` records arrived between them. A commits after every poll that
/// delivered records; B commits only when `b_commits`.
async fn process(
    a: &Consumer,
    b: &Consumer,
    expected: usize,
    b_commits: bool,
) -> (Deliveries, Deliveries) {
    let started = tokio::time::Instant::now();
    let (mut to_a, mut to_b) = (Deliveries::default(), Deliveries::default());
    while to_a.0.len().saturating_add(to_b.0.len()) < expected && started.elapsed() < DEADLINE {
        let (from_a, from_b) = tokio::join!(a.poll(POLL), b.poll(POLL));
        let (from_a, from_b) = (delivered(from_a), delivered(from_b));
        to_a.record(&from_a);
        to_b.record(&from_b);
        if !from_a.is_empty() {
            a.commit().await.unwrap();
        }
        if b_commits && !from_b.is_empty() {
            b.commit().await.unwrap();
        }
    }
    (to_a, to_b)
}

/// Polls the remaining member until `expected` arrived again, committing after processing, then a few
/// more times so that a duplicate would show.
async fn redeliveries(a: &Consumer, expected: &BTreeSet<Position>) -> Deliveries {
    let started = tokio::time::Instant::now();
    let mut received = Deliveries::default();
    while !received.set().is_superset(expected) && started.elapsed() < DEADLINE {
        let records = delivered(a.poll(POLL).await);
        received.record(&records);
        if !records.is_empty() {
            a.commit().await.unwrap();
        }
    }
    for _ in 0..SETTLED_POLLS {
        received.record(&delivered(a.poll(POLL).await));
    }
    received
}

fn on_partitions(positions: &BTreeSet<Position>, partitions: &BTreeSet<i32>) -> BTreeSet<Position> {
    positions
        .iter()
        .filter(|(partition, _)| partitions.contains(partition))
        .copied()
        .collect()
}

#[tokio::test]
async fn a_member_that_leaves_before_committing_hands_its_uncommitted_records_to_the_other() {
    let kafka = compose_broker().await;
    let topic = unique_topic("group");
    let group = format!("{topic}-group");
    create_partitioned_topic(&kafka, &topic).await;
    let (listener_a, listener_b) = (
        Arc::new(Rebalances::default()),
        Arc::new(Rebalances::default()),
    );
    let a = member(&kafka, &group, &topic, Arc::clone(&listener_a)).await;
    let b = member(&kafka, &group, &topic, Arc::clone(&listener_b)).await;

    let (partitions_a, partitions_b) = settle_split(&a, &b, &topic).await;
    // Revocations while the group converged on the split are not the hand-over under test.
    let settled_revocations_b = listener_b.revocation_count();
    let first = produce_batch(&kafka, &topic, "first").await;
    let (first_a, first_b) = process(&a, &b, first.len(), true).await;
    let second = produce_batch(&kafka, &topic, "second").await;
    drop(kafka);
    let (second_a, second_b) = process(&a, &b, second.len(), false).await;
    let uncommitted = second_b.set();
    b.close().await.unwrap();
    drop(b);
    let again = redeliveries(&a, &uncommitted).await;
    let partitions_after = assigned(&a, &topic).await;
    a.close().await.unwrap();
    drop(a);

    let all: BTreeSet<i32> = (0..PARTITIONS).collect();
    assert!(
        !partitions_a.is_empty() && !partitions_b.is_empty(),
        "{partitions_a:?} {partitions_b:?}"
    );
    assert!(partitions_a.is_disjoint(&partitions_b));
    assert_eq!(
        partitions_a
            .union(&partitions_b)
            .copied()
            .collect::<BTreeSet<_>>(),
        all
    );
    // Before B left, every record was delivered exactly once, to the member that owned its partition.
    let mut before: BTreeMap<Position, usize> = BTreeMap::new();
    for position in first_a
        .0
        .iter()
        .chain(&first_b.0)
        .chain(&second_a.0)
        .chain(&second_b.0)
    {
        *before.entry(*position).or_default() += 1;
    }
    assert!(before.values().all(|count| *count == 1), "{before:?}");
    assert_eq!(first_b.set(), on_partitions(&first, &partitions_b));
    assert_eq!(second_b.set(), on_partitions(&second, &partitions_b));
    assert_eq!(second_a.set(), on_partitions(&second, &partitions_a));
    assert!(!uncommitted.is_empty());
    // B's partitions were reassigned to A, through the callbacks of both members.
    assert_eq!(partitions_after, all);
    let revoked_b: BTreeSet<i32> = listener_b
        .revoked_after(settled_revocations_b)
        .into_iter()
        .collect();
    assert_eq!(revoked_b, partitions_b);
    let assigned_a: BTreeSet<i32> = listener_a.assigned().into_iter().collect();
    assert!(assigned_a.is_superset(&partitions_b), "{assigned_a:?}");
    // A received B's uncommitted records again, each once, and no committed record.
    assert_eq!(again.set(), uncommitted, "{:?}", again.0);
    assert_eq!(again.0.len(), uncommitted.len(), "{:?}", again.0);
}
