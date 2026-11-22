//! Capability 10: after a dropped connection the tail reseeks to its in-memory position and reads every
//! record exactly once, in order.

use krafka::Record;
use krafka::consumer::Consumer;
use krafka::testing::FakeBroker;

use super::{DEADLINE, PARTITION, POLL, offsets, start_tail, tail_builder, values};

const TOPIC: &str = "iam-policy-log";
const RECORDS: i64 = 10;
const BROKER: i32 = 0;
/// Records handed out per poll, so that the connection drops while the tail is in progress.
const PER_POLL: i32 = 3;

/// Polls until the tail's in-memory position reaches `end` or [`DEADLINE`] elapsed, appending what it
/// read; a poll error fails the test.
async fn read_to(consumer: &Consumer, end: i64, read: &mut Vec<krafka::ConsumerRecord>) {
    let started = tokio::time::Instant::now();
    while next_position(read) < end && started.elapsed() < DEADLINE {
        read.extend(consumer.poll(POLL).await.unwrap());
    }
}

/// The position the gateway keeps in memory: the offset after the last record it applied.
fn next_position(read: &[krafka::ConsumerRecord]) -> i64 {
    read.last()
        .map_or(0, |record| record.offset.checked_add(1).unwrap())
}

#[tokio::test]
async fn the_tail_reads_every_record_once_in_order_across_a_dropped_connection() {
    let broker = FakeBroker::start().await.unwrap();
    assert!(broker.create_topic(TOPIC, 1));
    let kafka = broker.kafka().connect().await.unwrap();
    let producer = kafka.producer().build().await.unwrap();
    let expected: Vec<Option<String>> = (0..RECORDS).map(|n| Some(n.to_string())).collect();
    for value in expected.iter().flatten() {
        let sent = producer
            .send(Record::new(TOPIC, value.clone()).partition(PARTITION))
            .await
            .unwrap();
        assert_eq!(sent.partition, PARTITION);
    }
    producer.flush().await.unwrap();
    drop(producer);

    let consumer = start_tail(tail_builder(&kafka).max_poll_records(PER_POLL), TOPIC, 0).await;
    let mut applied = Vec::new();
    read_to(&consumer, 1, &mut applied).await;
    let before_drop = applied.len();
    broker.crash(BROKER);
    // Records already buffered before the drop are still handed out and applied; an error is not.
    if let Ok(buffered) = consumer.poll(POLL).await {
        applied.extend(buffered);
    }
    broker.restart(BROKER);
    consumer
        .seek(TOPIC, PARTITION, next_position(&applied))
        .await
        .unwrap();
    read_to(&consumer, RECORDS, &mut applied).await;
    drop(consumer);

    assert!(
        (1..RECORDS).contains(&i64::try_from(before_drop).unwrap()),
        "{before_drop}"
    );
    assert_eq!(offsets(&applied), (0..RECORDS).collect::<Vec<_>>());
    assert_eq!(values(&applied), expected);
}
