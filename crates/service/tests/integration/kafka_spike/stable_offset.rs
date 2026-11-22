//! Capability 7: `ListOffsets` with isolation `READ_COMMITTED` answers the last stable offset of an open
//! transaction, and the broker aborts a transaction whose producer stops before committing.
//!
//! Both tests run against the compose broker, because the transaction timeout is enforced by a real
//! coordinator only: the in-process `test-broker` never expires a transaction. The broker checks for timed
//! out transactions every `transaction.abort.timed.out.transaction.cleanup.interval.ms` (10 s by default),
//! so an abandoned transaction is aborted between the timeout and the timeout plus that interval.

use std::time::Duration;

use krafka::admin::{ListOffsetsOptions, OffsetSpec, TopicPartition};
use krafka::{Kafka, Record};
use tokio::time::Instant;

use super::{PARTITION, compose_broker, create_topic, read, settle, tail, unique_topic, values};

const RELAY: &str = "iam-relay";
/// The `transaction.timeout.ms` of the relay.
const TRANSACTION_TIMEOUT: Duration = Duration::from_secs(10);
/// The broker's default `transaction.abort.timed.out.transaction.cleanup.interval.ms`.
const CLEANUP_INTERVAL: Duration = Duration::from_secs(10);
/// Slack for the marker write and this test's polling.
const MARGIN: Duration = Duration::from_secs(5);
/// How long the test waits for the commit markers of a committed transaction.
const MARKER_DEADLINE: Duration = Duration::from_secs(10);
const PROBE_INTERVAL: Duration = Duration::from_millis(250);

fn record(topic: &str, value: &'static str) -> Record {
    Record::new(topic.to_owned(), value).partition(PARTITION)
}

/// The `Latest` offset of partition 0 that `ListOffsets` answers under the given isolation.
async fn latest_offset(kafka: &Kafka, topic: &str, read_committed: bool) -> i64 {
    let key = TopicPartition::new(topic, PARTITION);
    let listed = kafka
        .admin()
        .list_offsets(
            [(key.clone(), OffsetSpec::Latest)],
            ListOffsetsOptions::default().read_committed(read_committed),
        )
        .await
        .unwrap();
    match listed.get(&key) {
        Some(Ok(offset)) => offset.offset,
        other => panic!("ListOffsets answered {other:?}"),
    }
}

/// Asks `ListOffsets` with `READ_COMMITTED` until the last stable offset passes `offset` or `deadline`
/// passes; returns the last answer and when it came.
async fn stable_offset_beyond(
    kafka: &Kafka,
    topic: &str,
    offset: i64,
    deadline: Instant,
) -> (i64, Instant) {
    loop {
        let stable = latest_offset(kafka, topic, true).await;
        let now = Instant::now();
        if stable > offset || now >= deadline {
            return (stable, now);
        }
        tokio::time::sleep(PROBE_INTERVAL).await;
    }
}

#[tokio::test]
async fn read_committed_list_offsets_answers_below_the_open_transaction_then_beyond_it_after_commit()
 {
    let kafka = compose_broker().await;
    let topic = unique_topic("stable-offset");
    create_topic(&kafka, &topic).await;
    let relay = kafka
        .producer()
        .build_transactional(format!("{RELAY}-{topic}"))
        .await
        .unwrap();
    relay.begin().unwrap();
    assert_eq!(
        relay
            .send(record(&topic, "committed"))
            .await
            .unwrap()
            .partition,
        PARTITION
    );
    relay.commit().await.unwrap();
    relay.begin().unwrap();
    let first_open = relay.send(record(&topic, "open-1")).await.unwrap();
    let last_open = relay.send(record(&topic, "open-2")).await.unwrap();
    relay.flush().await.unwrap();

    let stable_while_open = latest_offset(&kafka, &topic, true).await;
    let high_watermark_while_open = latest_offset(&kafka, &topic, false).await;
    relay.commit().await.unwrap();
    let deadline = Instant::now().checked_add(MARKER_DEADLINE).unwrap();
    let (stable_after_commit, _) =
        stable_offset_beyond(&kafka, &topic, last_open.offset, deadline).await;
    relay.close().await.unwrap();
    drop(relay);
    drop(kafka);

    assert_eq!(stable_while_open, first_open.offset);
    assert!(
        high_watermark_while_open > last_open.offset,
        "{high_watermark_while_open}"
    );
    assert!(
        stable_after_commit > last_open.offset,
        "{stable_after_commit} <= {}",
        last_open.offset
    );
}

#[tokio::test]
async fn the_broker_aborts_the_transaction_of_a_relay_that_stops_without_committing() {
    let kafka = compose_broker().await;
    let topic = unique_topic("transaction-timeout");
    create_topic(&kafka, &topic).await;
    let relay = kafka
        .producer()
        .transaction_timeout(TRANSACTION_TIMEOUT)
        .build_transactional(format!("{RELAY}-{topic}"))
        .await
        .unwrap();
    relay.begin().unwrap();
    assert_eq!(
        relay
            .send(record(&topic, "committed"))
            .await
            .unwrap()
            .partition,
        PARTITION
    );
    relay.commit().await.unwrap();
    // The relay stops here: it writes an open transaction and never commits or aborts it.
    let started = Instant::now();
    relay.begin().unwrap();
    let first_open = relay.send(record(&topic, "abandoned-1")).await.unwrap();
    let last_open = relay.send(record(&topic, "abandoned-2")).await.unwrap();
    relay.flush().await.unwrap();

    let stable_while_open = latest_offset(&kafka, &topic, true).await;
    let bound = TRANSACTION_TIMEOUT
        .checked_add(CLEANUP_INTERVAL)
        .and_then(|bound| bound.checked_add(MARGIN))
        .unwrap();
    let deadline = started.checked_add(bound).unwrap();
    let (stable_after_timeout, aborted_at) =
        stable_offset_beyond(&kafka, &topic, last_open.offset, deadline).await;
    let consumer = tail(&kafka, &topic, 0).await;
    let mut visible = read(&consumer, 1).await;
    visible.extend(settle(&consumer, 3).await);
    drop(consumer);
    let late_commit = relay.commit().await;
    drop(relay);
    drop(kafka);

    assert_eq!(stable_while_open, first_open.offset);
    assert!(
        stable_after_timeout > last_open.offset,
        "the transaction was still open {:?} after it started",
        aborted_at.duration_since(started)
    );
    assert!(aborted_at.duration_since(started) <= bound);
    assert_eq!(values(&visible), [Some("committed".to_owned())]);
    assert!(late_commit.is_err(), "{late_commit:?}");
}
