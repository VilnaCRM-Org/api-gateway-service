//! Capability 3 on the 3-broker compose profile `kafka-cluster`, run by hand outside `make ci`: after the
//! partition leader stops, do at least 2 of the 3 brokers report the same new leader and leader epoch?
//!
//! The test needs the three brokers of the profile and an operator who stops broker 1 while it waits; the
//! procedure and the recorded observations are in `docs/spikes/phase-0.md`, labelled as compose-host
//! measurements. Each broker is asked on its own with a fresh client seeded with that broker only (see
//! `broker_metadata`), as the replica-quorum check of the freshness proof asks them.

use std::collections::HashMap;
use std::time::Duration;

use krafka::Kafka;
use krafka::admin::{CreateTopicsOptions, NewTopic};

use super::broker_metadata::{Leadership, leadership_from, quorum};
use super::{PARTITION, POLL, unique_topic};

/// The in-network listeners of the three brokers, by node id.
const BROKERS: [(i32, &str); 3] = [
    (1, "kafka-cluster-1:19092"),
    (2, "kafka-cluster-2:19092"),
    (3, "kafka-cluster-3:19092"),
];

/// How long the operator has to stop broker 1 and the cluster to elect its successor.
const ELECTION_DEADLINE: Duration = Duration::from_secs(180);

/// Partition 0 of `topic` as each broker reports it, in node order; `None` for a broker that is down.
async fn reports(topic: &str) -> Vec<Option<Leadership>> {
    let mut reports = Vec::new();
    for (_, address) in BROKERS {
        reports.push(leadership_from(address, topic).await);
    }
    reports
}

/// The node ids of the reachable brokers whose report differs from the quorum's `agreed` answer: the brokers
/// that still named an older leader or epoch after the quorum agreed on the new one.
fn laggards(reports: &[Option<Leadership>], agreed: Leadership) -> Vec<i32> {
    BROKERS
        .iter()
        .zip(reports)
        .filter_map(|((node, _), report)| report.filter(|seen| *seen != agreed).map(|_| *node))
        .collect()
}

/// Creates `topic` with one partition whose replicas are brokers 1, 2 and 3, so that broker 1, the preferred
/// replica, leads it.
async fn create_replicated_topic(topic: &str) {
    let seeds = BROKERS.map(|(_, address)| address).join(",");
    let assignment = HashMap::from([(PARTITION, BROKERS.map(|(node, _)| node).to_vec())]);
    let new_topic = NewTopic::with_replica_assignment(topic, assignment)
        .unwrap()
        .with_config("min.insync.replicas", "2")
        .with_config("unclean.leader.election.enable", "false");
    let results = Kafka::builder(seeds)
        .connect()
        .await
        .unwrap()
        .admin()
        .create_topics([new_topic], CreateTopicsOptions::default())
        .await
        .unwrap();
    assert!(matches!(results.get(topic), Some(Ok(()))), "{results:?}");
}

#[tokio::test]
#[ignore = "needs the kafka-cluster compose profile and an operator who stops kafka-cluster-1; see docs/spikes/phase-0.md"]
async fn after_the_leader_stops_at_least_two_of_three_brokers_report_the_same_new_leader_and_epoch()
{
    let topic = unique_topic("quorum");
    create_replicated_topic(&topic).await;
    let started = tokio::time::Instant::now();
    let mut before = reports(&topic).await;
    while quorum(&before).is_none_or(|(_, agreeing)| agreeing < 3)
        && started.elapsed() < ELECTION_DEADLINE
    {
        tokio::time::sleep(POLL).await;
        before = reports(&topic).await;
    }
    let (initial, _) = quorum(&before).unwrap();

    let mut after = reports(&topic).await;
    while quorum(&after)
        .is_none_or(|(leadership, agreeing)| leadership.leader == initial.leader || agreeing < 2)
        && started.elapsed() < ELECTION_DEADLINE
    {
        tokio::time::sleep(POLL).await;
        after = reports(&topic).await;
    }
    let successor = quorum(&after);
    let lagging = successor.map(|(agreed, _)| laggards(&after, agreed));
    println!(
        "compose-host observation: before {before:?}; after {after:?}; quorum {successor:?}; brokers still \
         naming an older leader or epoch after the quorum agreed: {lagging:?}"
    );

    assert_eq!(
        quorum(&before).map(|(_, agreeing)| agreeing),
        Some(3),
        "{before:?}"
    );
    assert_eq!(initial.leader, 1, "{before:?}");
    assert!(
        successor.is_some_and(|(leadership, agreeing)| leadership.leader != initial.leader
            && leadership.leader_epoch > initial.leader_epoch
            && agreeing >= 2),
        "{after:?}"
    );
}

#[test]
fn a_laggard_is_a_reachable_broker_whose_report_differs_from_the_quorum() {
    let old = Leadership {
        leader: 1,
        leader_epoch: 0,
        partitions: 1,
    };
    let new = Leadership {
        leader: 2,
        leader_epoch: 1,
        partitions: 1,
    };

    assert_eq!(
        laggards(&[None, Some(new), Some(new)], new),
        Vec::<i32>::new()
    );
    assert_eq!(laggards(&[None, Some(new), Some(old)], new), vec![3]);
    assert_eq!(laggards(&[Some(old), Some(new), None], new), vec![1]);
}
