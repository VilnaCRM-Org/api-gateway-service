use std::sync::Arc;
use std::time::Duration;

use iam_domain::{FreshnessRule, PeerFreshnessClient as _};
use test_support::peer_freshness_reader::FakePeerFreshnessReader;
use test_support::rng::FakeRng;

use super::{PEER_READ_TIMEOUT, PeerSet, PeerSetPorts};
use crate::endpoint_directory::{EndpointDirectory, ZoneSource};
use crate::peer_readiness::fixtures::{Cluster, current, stale, version, zone};

const SIX: [(&str, &str); 6] = [
    ("gw-a1", "a"),
    ("gw-a2", "a"),
    ("gw-b1", "b"),
    ("gw-b2", "b"),
    ("gw-c1", "c"),
    ("gw-c2", "c"),
];

fn asked_sorted(cluster: &Cluster) -> Vec<String> {
    let mut asked = cluster.reader.asked();
    asked.sort();
    asked
}

#[test]
fn a_pod_knows_its_name_and_its_zone_from_the_peers_slices() {
    let cluster = Cluster::of(&SIX);
    let member = cluster.member("gw-b1", 1);

    assert_eq!(member.peers.pod(), "gw-b1");
    assert_eq!(member.peers.own_zone(), Some(zone("b")));
}

#[test]
fn a_pod_without_a_name_has_the_empty_one() {
    let cluster = Cluster::of(&SIX);
    let directory = EndpointDirectory::new(ZoneSource {
        peers: cluster.target.clone(),
        pod: None,
        explicit: None,
    });
    let peers = PeerSet::new(PeerSetPorts {
        view: directory.view(),
        target: cluster.target.clone(),
        pod: None,
        reader: Arc::<FakePeerFreshnessReader>::clone(&cluster.reader),
        rng: Arc::new(FakeRng::seeded(1)),
        rule: FreshnessRule::new(Duration::from_secs(15), Duration::from_secs(2)),
    });

    assert_eq!(peers.pod(), "");
    assert_eq!(peers.own_zone(), None);
}

#[tokio::test]
async fn a_small_fleet_is_asked_entirely_except_the_pod_itself() {
    let cluster = Cluster::of(&SIX);
    cluster.reader.report_all(current(5));
    let member = cluster.member("gw-a1", 1);

    let reports = member.peers.reports().await;

    assert_eq!(reports.len(), 5);
    assert!(reports.iter().all(|report| report.current));
    assert_eq!(
        asked_sorted(&cluster),
        ["gw-a2", "gw-b1", "gw-b2", "gw-c1", "gw-c2"]
    );
}

#[tokio::test]
async fn a_peer_that_is_not_ready_is_not_asked() {
    let cluster = Cluster::of(&SIX);
    cluster.reader.report_all(current(5));
    let member = cluster.member("gw-a1", 1);
    cluster.publish(&["gw-c2"]);

    let reports = member.peers.reports().await;

    assert_eq!(reports.len(), 4);
    assert!(!cluster.reader.asked().contains(&"gw-c2".to_owned()));
}

#[tokio::test]
async fn a_peer_that_does_not_answer_is_left_out() {
    let cluster = Cluster::of(&SIX);
    cluster.reader.report("gw-a2", current(5));
    cluster.reader.report("gw-b1", stale(5));
    let member = cluster.member("gw-a1", 1);

    let reports = member.peers.reports().await;

    assert_eq!(reports.len(), 2);
    assert_eq!(reports.iter().filter(|report| !report.current).count(), 1);
    assert_eq!(asked_sorted(&cluster).len(), 5);
}

#[tokio::test(start_paused = true)]
async fn a_peer_that_hangs_is_left_out_after_the_read_timeout() {
    let cluster = Cluster::of(&SIX);
    cluster.reader.report_all(current(5));
    cluster.reader.hang("gw-b1");
    let member = cluster.member("gw-a1", 1);
    let started = tokio::time::Instant::now();

    let reports = member.peers.reports().await;

    assert_eq!(reports.len(), 4);
    assert_eq!(started.elapsed(), PEER_READ_TIMEOUT);
}

#[tokio::test]
async fn the_reports_carry_the_zone_and_the_version_of_the_peer() {
    let cluster = Cluster::of(&SIX);
    cluster.reader.report("gw-b1", current(9));
    let member = cluster.member("gw-a1", 1);

    let reports = member.peers.reports().await;

    let report = reports.first().unwrap();
    assert_eq!(report.zone, Some(zone("b")));
    assert_eq!(report.version, Some(version(9)));
}

#[tokio::test]
async fn the_cross_check_reads_the_versions_of_the_peers_that_answered() {
    let cluster = Cluster::of(&SIX);
    cluster.reader.report("gw-a2", current(7));
    cluster.reader.report("gw-b2", stale(8));
    let member = cluster.member("gw-a1", 1);

    let mut versions = member.peers.applied_versions().await;
    versions.sort();

    assert_eq!(versions, [version(7), version(8)]);
}

#[test]
fn the_ready_pods_of_the_own_zone_are_listed_without_the_pod_itself() {
    let cluster = Cluster::of(&SIX);
    let member = cluster.member("gw-a1", 1);

    assert_eq!(member.peers.zone_pods(), ["gw-a2"]);

    cluster.publish(&["gw-a2"]);
    assert_eq!(member.peers.zone_pods(), Vec::<String>::new());
}

#[tokio::test]
async fn a_fleet_of_twelve_peers_is_asked_five_with_three_in_the_own_zone() {
    let pods: Vec<(String, String)> = (0..13)
        .map(|index| {
            let zone_name = ["a", "b", "c"].get(index % 3).copied().unwrap_or("a");
            (format!("gw-{index:02}"), zone_name.to_owned())
        })
        .collect();
    let pods: Vec<(&str, &str)> = pods
        .iter()
        .map(|(pod, zone_name)| (pod.as_str(), zone_name.as_str()))
        .collect();
    let cluster = Cluster::of(&pods);
    cluster.reader.report_all(current(5));
    let member = cluster.member("gw-00", 1);

    let reports = member.peers.reports().await;

    assert_eq!(reports.len(), 5);
    let own = reports
        .iter()
        .filter(|report| report.zone == Some(zone("a")))
        .count();
    assert_eq!(own, 3);
}
