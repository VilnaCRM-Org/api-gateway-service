//! Capability 2: a position below the log start offset is reported to the caller and never reset by krafka.

use krafka::admin::{DeleteRecordsOptions, TopicPartition};
use krafka::{KrafkaError, Record};

use super::{
    PARTITION, compose_broker, create_topic, first_error, offsets, read, tail, unique_topic, values,
};

const RETAINED_FROM: i64 = 3;

#[tokio::test]
async fn a_position_below_the_log_start_is_reported_and_never_reset() {
    let kafka = compose_broker().await;
    let topic = unique_topic("out-of-range");
    create_topic(&kafka, &topic).await;
    let producer = kafka.producer().build().await.unwrap();
    for value in ["0", "1", "2", "3", "4"] {
        let sent = producer
            .send(Record::new(topic.clone(), value).partition(PARTITION))
            .await
            .unwrap();
        assert_eq!(sent.partition, PARTITION);
    }
    producer.flush().await.unwrap();
    drop(producer);
    let deleted = kafka
        .admin()
        .delete_records(
            [(TopicPartition::new(topic.clone(), PARTITION), RETAINED_FROM)],
            DeleteRecordsOptions::default(),
        )
        .await
        .unwrap();

    let consumer = tail(&kafka, &topic, 0).await;
    drop(kafka);
    let first = first_error(&consumer).await;
    let position_after_first = consumer.position(&topic, PARTITION).await;
    let second = first_error(&consumer).await;
    let position_after_second = consumer.position(&topic, PARTITION).await;
    consumer
        .seek(&topic, PARTITION, RETAINED_FROM)
        .await
        .unwrap();
    let retained = read(&consumer, 2).await;
    drop(consumer);

    let low = deleted
        .get(&TopicPartition::new(topic.clone(), PARTITION))
        .and_then(|result| result.as_ref().ok())
        .copied();
    assert_eq!(low, Some(RETAINED_FROM), "{deleted:?}");
    assert!(
        matches!(&first, Err(KrafkaError::NoOffset { partitions }) if partitions == &[(topic.clone(), PARTITION)]),
        "{first:?}"
    );
    assert_eq!(position_after_first, Some(0));
    assert!(
        matches!(&second, Err(KrafkaError::NoOffset { .. })),
        "{second:?}"
    );
    assert_eq!(position_after_second, Some(0));
    assert_eq!(offsets(&retained), [3, 4]);
    assert_eq!(
        values(&retained),
        [Some("3".to_owned()), Some("4".to_owned())]
    );
}
