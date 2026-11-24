use std::io;

use iam_domain::ProbeError;
use krafka::consumer::FetchMetadataResult;
use krafka::testing::FakeBroker;
use krafka::{KrafkaError, PartitionInfo};
use test_support::log::LogRecorder;
use tracing::Level;

use super::{layout_of, leadership_of, report_close};

const TOPIC: &str = "iam-state-unit";

/// The metadata of a topic of one partition on a broker of its own.
async fn metadata() -> FetchMetadataResult {
    let broker = FakeBroker::start().await.unwrap();
    broker.with_state(|state| assert!(state.create_topic(TOPIC, 1)));
    let kafka = broker.kafka().connect().await.unwrap();
    let consumer = kafka.consumer_without_group().build().await.unwrap();
    let topic = TOPIC.to_owned();
    let answer = consumer.fetch_metadata(Some(&topic)).await.unwrap();
    drop(consumer);
    answer
}

/// The metadata of the only partition of that topic.
async fn partition() -> PartitionInfo {
    metadata()
        .await
        .topics
        .into_iter()
        .find(|found| found.name == TOPIC)
        .unwrap()
        .partitions
        .get(&0)
        .cloned()
        .unwrap()
}

#[tokio::test]
async fn a_partition_with_a_leader_and_an_epoch_is_led() {
    let partition = partition().await;

    let led = leadership_of(&partition);

    assert!(led.is_ok(), "{led:?}");
}

#[tokio::test]
async fn a_partition_without_a_leader_or_without_an_epoch_is_unavailable() {
    let healthy = partition().await;
    let mut leaderless = healthy.clone();
    leaderless.leader = -1;
    let mut epochless = healthy;
    epochless.leader_epoch = -1;

    let without_leader = leadership_of(&leaderless);
    let without_epoch = leadership_of(&epochless);

    assert!(matches!(without_leader, Err(ProbeError::Unavailable(_))));
    assert!(matches!(without_epoch, Err(ProbeError::Unavailable(_))));
}

#[test]
fn a_reader_that_closes_cleanly_is_not_reported() {
    let (recorder, _guard) = LogRecorder::install();

    report_close(Ok(()));

    assert_eq!(recorder.lines().len(), 0);
}

#[test]
fn a_reader_that_does_not_close_cleanly_is_one_warning() {
    let (recorder, _guard) = LogRecorder::install();

    report_close(Err(KrafkaError::network(io::Error::other("broken pipe"))));

    let lines = recorder.lines();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].level, Level::WARN);
    assert!(lines[0].field("error").unwrap().contains("broken pipe"));
}

#[tokio::test]
async fn the_layout_holds_the_topic_its_state_partition_and_the_brokers() {
    let answer = metadata().await;

    let layout = layout_of(answer.topics, answer.brokers, TOPIC).unwrap();

    assert_eq!(layout.topic.name, TOPIC);
    assert_eq!(layout.partition.partition, 0);
    assert_eq!(layout.brokers.len(), 1);
}

#[tokio::test]
async fn a_topic_the_cluster_does_not_list_is_unavailable() {
    let answer = metadata().await;

    let layout = layout_of(answer.topics, answer.brokers, "another-topic");

    assert!(matches!(layout, Err(ProbeError::Unavailable(_))));
}

#[tokio::test]
async fn a_topic_without_the_state_partition_is_unavailable() {
    let mut answer = metadata().await;
    for topic in &mut answer.topics {
        topic.partitions.clear();
    }

    let layout = layout_of(answer.topics, answer.brokers, TOPIC);

    assert!(matches!(layout, Err(ProbeError::Unavailable(_))));
}
