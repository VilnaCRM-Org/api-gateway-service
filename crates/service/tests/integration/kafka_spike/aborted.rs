//! Capability 7: a `read_committed` reader never returns a record of an aborted transaction.

use krafka::testing::FakeBroker;
use krafka::{Kafka, Record};

use super::{PARTITION, compose_broker, create_topic, read, settle, tail, unique_topic, values};

const TOPIC: &str = "iam-state";
const RELAY: &str = "iam-relay";

fn record(topic: &str, value: &'static str) -> Record {
    Record::new(topic.to_owned(), value).partition(PARTITION)
}

/// Commits `before`, aborts a transaction of two records, then commits `after`.
async fn commit_abort_commit(kafka: &Kafka, topic: &str, transactional_id: &str) {
    let relay = kafka
        .producer()
        .build_transactional(transactional_id)
        .await
        .unwrap();
    relay.begin().unwrap();
    assert_eq!(
        relay.send(record(topic, "before")).await.unwrap().partition,
        PARTITION
    );
    relay.commit().await.unwrap();
    relay.begin().unwrap();
    assert_eq!(
        relay
            .send(record(topic, "aborted-1"))
            .await
            .unwrap()
            .partition,
        PARTITION
    );
    assert_eq!(
        relay
            .send(record(topic, "aborted-2"))
            .await
            .unwrap()
            .partition,
        PARTITION
    );
    relay.abort().await.unwrap();
    relay.begin().unwrap();
    assert_eq!(
        relay.send(record(topic, "after")).await.unwrap().partition,
        PARTITION
    );
    relay.commit().await.unwrap();
    relay.close().await.unwrap();
    drop(relay);
}

async fn read_committed_values(kafka: &Kafka, topic: &str) -> Vec<Option<String>> {
    let consumer = tail(kafka, topic, 0).await;
    let mut records = read(&consumer, 2).await;
    records.extend(settle(&consumer, 3).await);
    drop(consumer);
    values(&records)
}

#[tokio::test]
async fn a_read_committed_reader_skips_every_record_of_an_aborted_transaction() {
    let broker = FakeBroker::start().await.unwrap();
    assert!(broker.create_topic(TOPIC, 1));
    let kafka = broker.kafka().connect().await.unwrap();

    commit_abort_commit(&kafka, TOPIC, RELAY).await;
    let visible = read_committed_values(&kafka, TOPIC).await;
    drop(kafka);

    assert_eq!(
        visible,
        [Some("before".to_owned()), Some("after".to_owned())]
    );
    assert_eq!(broker.all_records(TOPIC).unwrap().len(), 4);
    assert_eq!(broker.aborted_transactions(TOPIC, PARTITION).len(), 1);
}

#[tokio::test]
async fn the_compose_broker_hides_an_aborted_transaction_from_a_read_committed_reader() {
    let kafka = compose_broker().await;
    let topic = unique_topic("aborted");
    create_topic(&kafka, &topic).await;
    let transactional_id = format!("{RELAY}-{topic}");

    commit_abort_commit(&kafka, &topic, &transactional_id).await;
    let visible = read_committed_values(&kafka, &topic).await;
    drop(kafka);

    assert_eq!(
        visible,
        [Some("before".to_owned()), Some("after".to_owned())]
    );
}
