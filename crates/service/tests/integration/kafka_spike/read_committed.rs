//! Capability 2: a reader without a group stops at the last stable offset under `read_committed`.

use krafka::Record;
use krafka::testing::FakeBroker;

use super::{PARTITION, offsets, read, settle, tail, values};

const TOPIC: &str = "iam-policy-log";
const RELAY: &str = "iam-relay";

fn record(value: &'static str) -> Record {
    Record::new(TOPIC, value).partition(PARTITION)
}

#[tokio::test]
async fn the_tail_stops_at_the_last_stable_offset_until_the_open_transaction_commits() {
    let broker = FakeBroker::start().await.unwrap();
    assert!(broker.create_topic(TOPIC, 1));
    let kafka = broker.kafka().connect().await.unwrap();
    let relay = kafka.producer().build_transactional(RELAY).await.unwrap();
    relay.begin().unwrap();
    let committed = relay.send(record("committed")).await.unwrap();
    assert_eq!(committed.partition, PARTITION);
    relay.commit().await.unwrap();
    relay.begin().unwrap();
    let first_open = relay.send(record("open-1")).await.unwrap();
    let second_open = relay.send(record("open-2")).await.unwrap();
    assert_eq!(second_open.partition, PARTITION);
    relay.flush().await.unwrap();

    let consumer = tail(&kafka, TOPIC, 0).await;
    let mut before_commit = read(&consumer, 1).await;
    before_commit.extend(settle(&consumer, 3).await);
    let lag = consumer.lag().await;
    let stable_while_open = broker.last_stable_offset(TOPIC, PARTITION);
    let open = broker.transaction_is_open(RELAY);
    relay.commit().await.unwrap();
    drop(relay);
    let after_commit = read(&consumer, 2).await;
    drop(consumer);

    assert!(open);
    assert_eq!(stable_while_open, Some(first_open.offset));
    assert_eq!(values(&before_commit), [Some("committed".to_owned())]);
    let reported = lag.values().next().and_then(|lag| lag.last_stable_offset);
    assert_eq!(reported, Some(first_open.offset), "{lag:?}");
    assert_eq!(
        values(&after_commit),
        [Some("open-1".to_owned()), Some("open-2".to_owned())]
    );
    assert_eq!(
        offsets(&after_commit),
        [first_open.offset, first_open.offset + 1]
    );
}
