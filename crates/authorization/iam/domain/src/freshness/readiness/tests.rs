use rstest::rstest;

use super::{AzFloor, ReadinessVerdict, ZoneRoster, judge};
use crate::endpoint::zone::Zone;
use crate::freshness::hysteresis::ReadinessPressure;
use crate::freshness::peer_report::PeerReport;

fn zone(name: &str) -> Zone {
    Zone::new(name).unwrap()
}

fn peer(zone_name: &str, current: bool) -> PeerReport {
    PeerReport {
        zone: Some(zone(zone_name)),
        version: None,
        current,
    }
}

#[test]
fn a_current_pod_is_fresh_whatever_its_peers_say() {
    let peers = [peer("a", false), peer("b", false)];

    assert_eq!(
        judge(true, Some(&zone("a")), &peers),
        ReadinessVerdict::Fresh
    );
    assert!(ReadinessVerdict::Fresh.is_fresh());
    assert!(!ReadinessVerdict::Local.is_fresh());
}

#[test]
fn a_stale_pod_among_fresh_peers_is_a_local_problem() {
    let peers = [
        peer("a", true),
        peer("b", true),
        peer("b", true),
        peer("c", true),
        peer("c", true),
    ];

    assert_eq!(
        judge(false, Some(&zone("a")), &peers),
        ReadinessVerdict::Local
    );
}

#[test]
fn a_stale_pod_whose_zone_peers_are_stale_among_fresh_other_zones_is_zone_shaped() {
    let peers = [
        peer("a", false),
        peer("b", true),
        peer("b", true),
        peer("c", true),
        peer("c", true),
    ];

    assert_eq!(
        judge(false, Some(&zone("a")), &peers),
        ReadinessVerdict::AzShaped
    );
}

#[test]
fn a_stale_pod_among_stale_peers_everywhere_is_a_fleet_wide_problem() {
    let peers = [
        peer("a", false),
        peer("b", false),
        peer("b", false),
        peer("c", false),
        peer("c", false),
    ];

    assert_eq!(
        judge(false, Some(&zone("a")), &peers),
        ReadinessVerdict::FleetWide
    );
}

#[test]
fn a_pod_that_has_no_peer_answer_cannot_tell_a_local_problem_and_stays_ready() {
    assert_eq!(
        judge(false, Some(&zone("a")), &[]),
        ReadinessVerdict::FleetWide
    );
}

#[test]
fn a_tie_between_fresh_and_stale_peers_is_not_a_majority_of_fresh_ones() {
    let peers = [peer("b", true), peer("c", false)];

    assert_eq!(
        judge(false, Some(&zone("a")), &peers),
        ReadinessVerdict::FleetWide
    );
}

#[test]
fn a_pod_of_an_unknown_zone_counts_every_peer_as_another_zone() {
    let peers = [peer("a", true), peer("b", true), peer("c", false)];

    assert_eq!(judge(false, None, &peers), ReadinessVerdict::Local);
}

#[test]
fn peers_without_a_zone_share_the_zone_of_a_pod_without_one() {
    let unzoned = |current| PeerReport {
        zone: None,
        version: None,
        current,
    };
    let peers = [unzoned(false), peer("b", true), peer("c", true)];

    assert_eq!(judge(false, None, &peers), ReadinessVerdict::AzShaped);
}

#[rstest]
#[case::fresh(ReadinessVerdict::Fresh, false, ReadinessPressure::Settled)]
#[case::fresh_protected(ReadinessVerdict::Fresh, true, ReadinessPressure::Settled)]
#[case::local(ReadinessVerdict::Local, false, ReadinessPressure::Shed)]
#[case::local_protected(ReadinessVerdict::Local, true, ReadinessPressure::Hold)]
#[case::zone_shaped(ReadinessVerdict::AzShaped, false, ReadinessPressure::Shed)]
#[case::zone_shaped_protected(ReadinessVerdict::AzShaped, true, ReadinessPressure::Hold)]
#[case::fleet_wide(ReadinessVerdict::FleetWide, false, ReadinessPressure::Hold)]
#[case::fleet_wide_protected(ReadinessVerdict::FleetWide, true, ReadinessPressure::Hold)]
fn a_verdict_asks_for_the_pressure_the_floor_allows(
    #[case] verdict: ReadinessVerdict,
    #[case] protected: bool,
    #[case] expected: ReadinessPressure,
) {
    assert_eq!(verdict.pressure(protected), expected);
}

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|name| (*name).to_owned()).collect()
}

#[test]
fn the_last_ready_pod_of_a_zone_is_protected() {
    let floor = AzFloor::new(1);
    let alone = ZoneRoster {
        pod: "gateway-b",
        self_ready: true,
        others_ready: &[],
        fresh_peers: 0,
    };

    assert!(floor.protects(&alone));
    assert_eq!(floor.pods(), 1);
}

#[test]
fn of_two_stale_pods_the_one_with_the_smaller_name_stays() {
    let floor = AzFloor::new(1);
    let others_of_a = names(&["gateway-b"]);
    let others_of_b = names(&["gateway-a"]);
    let first = ZoneRoster {
        pod: "gateway-a",
        self_ready: true,
        others_ready: &others_of_a,
        fresh_peers: 0,
    };
    let second = ZoneRoster {
        pod: "gateway-b",
        self_ready: true,
        others_ready: &others_of_b,
        fresh_peers: 0,
    };

    assert!(floor.protects(&first));
    assert!(!floor.protects(&second));
}

#[test]
fn a_fresh_peer_in_the_zone_satisfies_the_floor() {
    let floor = AzFloor::new(1);
    let others = names(&["gateway-a", "gateway-c"]);
    let roster = ZoneRoster {
        pod: "gateway-b",
        self_ready: true,
        others_ready: &others,
        fresh_peers: 1,
    };

    assert!(!floor.protects(&roster));
}

#[test]
fn a_floor_of_two_keeps_the_two_smallest_stale_pods() {
    let floor = AzFloor::new(2);
    let others = names(&["gateway-a", "gateway-b", "gateway-d"]);
    let kept = ZoneRoster {
        pod: "gateway-b",
        self_ready: true,
        others_ready: &others,
        fresh_peers: 0,
    };
    let shed = ZoneRoster {
        pod: "gateway-e",
        self_ready: true,
        others_ready: &others,
        fresh_peers: 0,
    };

    assert!(floor.protects(&kept));
    assert!(!floor.protects(&shed));
}

#[test]
fn an_unready_pod_is_protected_while_its_zone_falls_short_of_the_floor() {
    let floor = AzFloor::new(1);
    let covered = names(&["gateway-a"]);
    let short = ZoneRoster {
        pod: "gateway-b",
        self_ready: false,
        others_ready: &[],
        fresh_peers: 0,
    };
    let enough = ZoneRoster {
        pod: "gateway-b",
        self_ready: false,
        others_ready: &covered,
        fresh_peers: 0,
    };

    assert!(floor.protects(&short));
    assert!(!floor.protects(&enough));
}

#[test]
fn a_floor_of_zero_protects_no_pod() {
    let roster = ZoneRoster {
        pod: "gateway-a",
        self_ready: true,
        others_ready: &[],
        fresh_peers: 0,
    };

    assert!(!AzFloor::new(0).protects(&roster));
}
