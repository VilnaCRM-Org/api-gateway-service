//! `KrafkaPolicyLogProbe` against krafka's in-process `test-broker` (Story 9.5): the proof it
//! produces, every error the broker can inject, the quorum of the replica brokers and the last
//! stable offset under an open transaction.

use std::sync::Arc;
use std::time::Duration;

use iam_domain::{BootClock as _, BootInstant, ConfigGates, PolicyLogProbe as _, ProbeError};
use iam_infrastructure::{KafkaSecurity, KafkaSettings, KrafkaPolicyLogProbe};
use krafka::error::ErrorCode;
use krafka::testing::{ApiKey, Control, FakeBroker};
use krafka::{Kafka, Record};
use rstest::rstest;
use test_support::boot_clock::FakeBootClock;

const TOPIC: &str = "iam-state-probe";
const PARTITION: i32 = 0;

fn settings(broker: &FakeBroker) -> KafkaSettings {
    KafkaSettings {
        bootstrap_servers: broker.bootstrap_servers(),
        security: KafkaSecurity::Plaintext,
        client_id: "iam-gateway-probe-test".to_owned(),
        connect_timeout: Duration::from_secs(2),
        request_timeout: Duration::from_secs(5),
        retry_delay: Duration::from_millis(100),
        gates: ConfigGates::Relaxed,
        policy_topic: TOPIC.to_owned(),
        events_topic: "unused-events-topic".to_owned(),
    }
}

fn start_instant() -> BootInstant {
    BootInstant::from_elapsed(Duration::from_secs(100))
}

/// A cluster of `brokers` brokers with the state topic on one partition whose replicas are all of
/// them, led by the first.
async fn cluster(brokers: usize) -> FakeBroker {
    let broker = FakeBroker::start_cluster(brokers).await.unwrap();
    broker.with_state(|state| {
        assert!(state.create_topic(TOPIC, 1));
        let partition = state.partition_mut(TOPIC, PARTITION).unwrap();
        partition.replicas = (0..i32::try_from(brokers).unwrap()).collect();
        partition.isr = partition.replicas.clone();
    });
    broker
}

fn probe_of(broker: &FakeBroker) -> (KrafkaPolicyLogProbe, Arc<FakeBootClock>) {
    let clock = Arc::new(FakeBootClock::starting_at(start_instant()));
    (
        KrafkaPolicyLogProbe::new(settings(broker), Arc::<FakeBootClock>::clone(&clock)),
        clock,
    )
}

fn record(value: &'static str, partition: i32) -> Record {
    Record::new(TOPIC, value).partition(partition)
}

async fn produce(broker: &FakeBroker, count: usize, partition: i32) {
    let kafka = broker.kafka().connect().await.unwrap();
    let producer = kafka.producer().build().await.unwrap();
    for _ in 0..count {
        let _metadata = producer.send(record("v", partition)).await.unwrap();
    }
    producer.flush().await.unwrap();
    drop(producer);
}

#[tokio::test]
async fn a_healthy_topic_yields_a_proof_of_its_last_stable_offset_taken_on_the_boot_clock() {
    let broker = cluster(3).await;
    produce(&broker, 3, PARTITION).await;
    let (probe, _clock) = probe_of(&broker);

    let proof = probe.probe().await.unwrap();

    assert_eq!(proof.watermark, 3);
    assert_eq!(proof.taken_at, start_instant());
}

#[tokio::test]
async fn the_time_of_the_proof_is_read_before_the_request_is_sent() {
    let broker = cluster(1).await;
    produce(&broker, 1, PARTITION).await;
    let (probe, clock) = probe_of(&broker);
    let moved = Arc::<FakeBootClock>::clone(&clock);
    broker.on(ApiKey::ListOffsets, move |_| {
        moved.advance(Duration::from_secs(5));
        Control::Delay(Duration::from_millis(50))
    });

    let proof = probe.probe().await.unwrap();

    assert_eq!(proof.taken_at, start_instant());
    assert!(clock.now() > start_instant());
}

#[rstest]
#[case::offset_not_available(ErrorCode::OffsetNotAvailable, ProbeError::OffsetNotAvailable)]
#[case::fenced_leader_epoch(ErrorCode::FencedLeaderEpoch, ProbeError::FencedLeaderEpoch)]
#[case::unknown_leader_epoch(ErrorCode::UnknownLeaderEpoch, ProbeError::UnknownLeaderEpoch)]
#[tokio::test]
async fn an_error_of_list_offsets_yields_no_proof(
    #[case] code: ErrorCode,
    #[case] expected: ProbeError,
) {
    let broker = cluster(1).await;
    produce(&broker, 1, PARTITION).await;
    let (probe, _clock) = probe_of(&broker);
    broker.on(ApiKey::ListOffsets, move |_| Control::Error(code));

    let outcome = probe.probe().await;

    assert_eq!(outcome, Err(expected));
}

#[tokio::test]
async fn a_watermark_that_went_backwards_yields_no_proof() {
    let broker = cluster(1).await;
    produce(&broker, 3, PARTITION).await;
    let (probe, _clock) = probe_of(&broker);
    assert_eq!(probe.probe().await.unwrap().watermark, 3);

    broker.with_state(|state| state.partition_mut(TOPIC, PARTITION).unwrap().next_offset = 2);
    let outcome = probe.probe().await;

    assert_eq!(
        outcome,
        Err(ProbeError::WatermarkRegressed {
            seen: 3,
            reported: 2
        })
    );
}

#[tokio::test]
async fn records_on_a_second_partition_yield_no_proof() {
    let broker = cluster(1).await;
    produce(&broker, 1, PARTITION).await;
    assert_eq!(broker.add_partitions(TOPIC, 2), 1);
    produce(&broker, 1, 1).await;
    let (probe, _clock) = probe_of(&broker);

    let outcome = probe.probe().await;

    assert_eq!(
        outcome,
        Err(ProbeError::OtherPartitionWritten { partition: 1 })
    );
}

#[tokio::test]
async fn a_topic_with_a_second_partition_yields_no_proof_even_when_it_is_empty() {
    let broker = cluster(1).await;
    assert_eq!(broker.add_partitions(TOPIC, 2), 1);
    let (probe, _clock) = probe_of(&broker);

    let outcome = probe.probe().await;

    assert_eq!(outcome, Err(ProbeError::PartitionCount { found: 2 }));
}

#[tokio::test]
async fn one_reachable_replica_broker_of_three_is_not_a_quorum() {
    let broker = cluster(3).await;
    produce(&broker, 1, PARTITION).await;
    let (probe, _clock) = probe_of(&broker);
    assert!(probe.probe().await.is_ok());
    broker.crash(1);
    broker.crash(2);

    let outcome = probe.probe().await;

    assert_eq!(
        outcome,
        Err(ProbeError::QuorumShort {
            answered: 1,
            needed: 2
        })
    );
}

#[tokio::test]
async fn an_epoch_lower_than_one_already_seen_yields_no_proof() {
    let broker = cluster(1).await;
    produce(&broker, 1, PARTITION).await;
    assert!(broker.bump_leader_epoch(TOPIC, PARTITION));
    assert!(broker.bump_leader_epoch(TOPIC, PARTITION));
    let (probe, _clock) = probe_of(&broker);
    assert!(probe.probe().await.is_ok());

    broker.with_state(|state| {
        let partition = state.partition_mut(TOPIC, PARTITION).unwrap();
        partition.leader_epoch -= 1;
    });
    let outcome = probe.probe().await;

    assert!(
        matches!(
            outcome,
            Err(ProbeError::EpochRegressed { .. }
                | ProbeError::LeaderDisagreement
                | ProbeError::UnknownLeaderEpoch)
        ),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn the_first_proof_stops_below_an_open_relay_transaction_and_the_next_one_requires_it() {
    let broker = cluster(1).await;
    let kafka: Kafka = broker.kafka().connect().await.unwrap();
    let relay = kafka
        .producer()
        .build_transactional("iam-relay-probe-test")
        .await
        .unwrap();
    relay.begin().unwrap();
    let _committed = relay.send(record("committed", PARTITION)).await.unwrap();
    relay.commit().await.unwrap();
    relay.begin().unwrap();
    let first_open = relay.send(record("open-1", PARTITION)).await.unwrap();
    let second_open = relay.send(record("open-2", PARTITION)).await.unwrap();
    relay.flush().await.unwrap();
    let (probe, _clock) = probe_of(&broker);

    let before_commit = probe.probe().await.unwrap();
    relay.commit().await.unwrap();
    drop(relay);
    let after_commit = probe.probe().await.unwrap();

    assert_eq!(before_commit.watermark, first_open.offset);
    assert!(after_commit.watermark > second_open.offset);
}

#[tokio::test]
async fn a_partition_without_a_leader_yields_no_proof_and_the_next_probe_reads_again() {
    let broker = cluster(1).await;
    produce(&broker, 1, PARTITION).await;
    let (probe, _clock) = probe_of(&broker);
    assert!(probe.probe().await.is_ok());
    broker.with_state(|state| state.partition_mut(TOPIC, PARTITION).unwrap().leader = -1);

    let outcome = probe.probe().await;

    assert!(
        matches!(outcome, Err(ProbeError::Unavailable(_))),
        "{outcome:?}"
    );
    broker.with_state(|state| state.partition_mut(TOPIC, PARTITION).unwrap().leader = 0);
    assert!(probe.probe().await.is_ok());
}

#[tokio::test]
async fn a_replica_that_the_cluster_does_not_list_cannot_answer_and_is_not_asked() {
    let broker = cluster(1).await;
    broker.with_state(|state| {
        state.partition_mut(TOPIC, PARTITION).unwrap().replicas = vec![0, 7];
    });
    let (probe, _clock) = probe_of(&broker);

    let outcome = probe.probe().await;

    assert_eq!(
        outcome,
        Err(ProbeError::QuorumShort {
            answered: 1,
            needed: 2
        })
    );
}

#[tokio::test]
async fn a_cluster_that_stops_answering_yields_no_proof() {
    let broker = cluster(1).await;
    produce(&broker, 1, PARTITION).await;
    let (probe, _clock) = probe_of(&broker);
    assert!(probe.probe().await.is_ok());
    broker.crash(0);

    let outcome = probe.probe().await;

    assert!(outcome.is_err(), "{outcome:?}");
}
