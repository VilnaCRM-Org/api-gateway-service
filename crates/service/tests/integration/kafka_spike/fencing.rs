//! Capability 7: a second relay with the transactional id `iam-relay` fences the first one; the zombie's
//! commit fails with a fencing error and none of its records becomes visible to a `read_committed` reader.

use krafka::error::ErrorCode;
use krafka::producer::TransactionalProducer;
use krafka::testing::FakeBroker;
use krafka::{Kafka, KrafkaError, Record};

use super::{PARTITION, compose_broker, create_topic, read, settle, tail, unique_topic, values};

const TOPIC: &str = "iam-state";
const RELAY: &str = "iam-relay";

fn record(topic: &str, value: &'static str) -> Record {
    Record::new(topic.to_owned(), value).partition(PARTITION)
}

/// Whether `error` is the fencing error krafka reports for a producer whose epoch another producer with
/// the same transactional id bumped.
fn is_fencing(error: &KrafkaError) -> bool {
    matches!(
        error,
        KrafkaError::Fenced { .. }
            | KrafkaError::Broker {
                code: ErrorCode::ProducerFenced | ErrorCode::InvalidProducerEpoch,
                ..
            }
    )
}

/// The zombie writes two records in an open transaction; the successor initialises with the same id and
/// commits one record of its own; then the zombie tries to commit. Returns the zombie's commit result.
async fn zombie_and_successor(
    kafka: &Kafka,
    topic: &str,
    transactional_id: &str,
) -> Result<(), KrafkaError> {
    let zombie = kafka
        .producer()
        .build_transactional(transactional_id)
        .await
        .unwrap();
    zombie.begin().unwrap();
    assert_eq!(
        zombie
            .send(record(topic, "zombie-1"))
            .await
            .unwrap()
            .partition,
        PARTITION
    );
    assert_eq!(
        zombie
            .send(record(topic, "zombie-2"))
            .await
            .unwrap()
            .partition,
        PARTITION
    );
    zombie.flush().await.unwrap();

    let successor: TransactionalProducer = kafka
        .producer()
        .build_transactional(transactional_id)
        .await
        .unwrap();
    assert_eq!(successor.producer_id(), zombie.producer_id());
    assert!(successor.producer_epoch() > zombie.producer_epoch());
    successor.begin().unwrap();
    assert_eq!(
        successor
            .send(record(topic, "successor"))
            .await
            .unwrap()
            .partition,
        PARTITION
    );
    successor.commit().await.unwrap();

    let zombie_commit = zombie.commit().await;
    drop(zombie);
    drop(successor);
    zombie_commit
}

#[tokio::test]
async fn a_second_iam_relay_fences_the_first_whose_records_never_become_visible() {
    let broker = FakeBroker::start().await.unwrap();
    assert!(broker.create_topic(TOPIC, 1));
    let kafka = broker.kafka().connect().await.unwrap();

    let zombie_commit = zombie_and_successor(&kafka, TOPIC, RELAY).await;
    let consumer = tail(&kafka, TOPIC, 0).await;
    let mut visible = read(&consumer, 1).await;
    visible.extend(settle(&consumer, 3).await);
    drop(consumer);
    drop(kafka);

    let error = zombie_commit.unwrap_err();
    assert!(is_fencing(&error), "{error:?}");
    assert!(error.is_fatal(), "{error:?}");
    assert_eq!(values(&visible), [Some("successor".to_owned())]);
    let committed = broker.committed_records(TOPIC).unwrap();
    assert_eq!(values(&committed), [Some("successor".to_owned())]);
    assert_eq!(broker.aborted_transactions(TOPIC, PARTITION).len(), 1);
}

#[tokio::test]
async fn the_compose_broker_fences_the_first_relay_when_a_second_one_initialises() {
    let kafka = compose_broker().await;
    let topic = unique_topic("fencing");
    create_topic(&kafka, &topic).await;
    // The compose broker outlives the run and other tests run beside this one: the id is unique per run.
    let transactional_id = format!("{RELAY}-{topic}");

    let zombie_commit = zombie_and_successor(&kafka, &topic, &transactional_id).await;
    let consumer = tail(&kafka, &topic, 0).await;
    let mut visible = read(&consumer, 1).await;
    visible.extend(settle(&consumer, 3).await);
    drop(consumer);
    drop(kafka);

    let error = zombie_commit.unwrap_err();
    assert!(is_fencing(&error), "{error:?}");
    assert_eq!(values(&visible), [Some("successor".to_owned())]);
}
