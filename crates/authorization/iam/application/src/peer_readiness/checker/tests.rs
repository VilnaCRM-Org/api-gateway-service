use std::time::Duration;

use iam_domain::ReadinessTransition;
use tokio::sync::watch;

use super::{CHECK_INTERVAL, PeerReadinessChecker};
use crate::peer_readiness::fixtures::{Cluster, Member, current, stale};

const SIX: [(&str, &str); 6] = [
    ("gw-a1", "a"),
    ("gw-a2", "a"),
    ("gw-b1", "b"),
    ("gw-b2", "b"),
    ("gw-c1", "c"),
    ("gw-c2", "c"),
];

/// Two checks of the member, which end with the verdict of the second.
async fn twice(member: &Member) -> ReadinessTransition {
    member.checker.check_once().await;
    member.checker.check_once().await
}

#[test]
fn the_task_has_a_name_and_the_check_runs_every_two_seconds() {
    assert_eq!(PeerReadinessChecker::name(), "peer-readiness-checker");
    assert_eq!(CHECK_INTERVAL, Duration::from_secs(2));
}

#[tokio::test]
async fn a_fresh_pod_stays_ready() {
    let cluster = Cluster::of(&SIX);
    cluster.reader.report_all(current(5));
    let member = cluster.member("gw-a1", 1);
    member.prove(&cluster.clock);

    for _ in 0..4 {
        assert_eq!(
            member.checker.check_once().await,
            ReadinessTransition::Unchanged
        );
    }

    assert!(member.gate.is_ready());
}

#[tokio::test]
async fn a_stale_pod_among_fresh_peers_fails_readiness_after_the_second_check() {
    let cluster = Cluster::of(&SIX);
    cluster.reader.report_all(current(5));
    let member = cluster.member("gw-a1", 1);

    let first = member.checker.check_once().await;
    assert_eq!(first, ReadinessTransition::Unchanged);
    assert!(member.gate.is_ready());
    assert!(!*member.gate.shedding().borrow());

    let second = member.checker.check_once().await;
    assert_eq!(second, ReadinessTransition::BecameUnready);
    assert!(!member.gate.is_ready());
    assert!(*member.gate.shedding().borrow());
}

#[tokio::test]
async fn the_pod_is_ready_again_only_after_three_consecutive_fresh_verdicts() {
    let cluster = Cluster::of(&SIX);
    cluster.reader.report_all(current(5));
    let member = cluster.member("gw-a1", 1);
    assert_eq!(twice(&member).await, ReadinessTransition::BecameUnready);

    member.prove(&cluster.clock);
    assert_eq!(twice(&member).await, ReadinessTransition::Unchanged);
    assert!(!member.gate.is_ready());

    let third = member.checker.check_once().await;
    assert_eq!(third, ReadinessTransition::BecameReady);
    assert!(member.gate.is_ready());
    assert!(!*member.gate.shedding().borrow());
}

#[tokio::test]
async fn a_stale_verdict_between_fresh_ones_restarts_the_restore_count() {
    let cluster = Cluster::of(&SIX);
    cluster.reader.report_all(current(5));
    let member = cluster.member("gw-a1", 1);
    assert_eq!(twice(&member).await, ReadinessTransition::BecameUnready);

    member.prove(&cluster.clock);
    twice(&member).await;
    cluster.clock.advance(Duration::from_secs(3));
    member.checker.check_once().await;
    member.prove(&cluster.clock);
    twice(&member).await;

    assert!(!member.gate.is_ready());
}

#[tokio::test]
async fn of_two_stale_pods_of_a_zone_exactly_one_goes_unready_and_the_last_stays() {
    let cluster = Cluster::of(&SIX);
    cluster.reader.report_all(current(5));
    cluster.reader.report("gw-a1", stale(5));
    cluster.reader.report("gw-a2", stale(5));
    let first = cluster.member("gw-a1", 1);
    let second = cluster.member("gw-a2", 1);

    for _ in 0..3 {
        first.checker.check_once().await;
        second.checker.check_once().await;
    }

    assert!(first.gate.is_ready());
    assert!(!second.gate.is_ready());
}

#[tokio::test]
async fn the_last_ready_pod_of_a_zone_stays_ready_after_its_sibling_left() {
    let cluster = Cluster::of(&SIX);
    cluster.reader.report_all(current(5));
    cluster.reader.report("gw-a1", stale(5));
    cluster.reader.report("gw-a2", stale(5));
    let first = cluster.member("gw-a1", 1);
    let second = cluster.member("gw-a2", 1);
    for _ in 0..2 {
        second.checker.check_once().await;
    }
    cluster.publish(&["gw-a2"]);

    for _ in 0..4 {
        first.checker.check_once().await;
    }

    assert!(!second.gate.is_ready());
    assert!(first.gate.is_ready());
}

#[tokio::test]
async fn an_unready_pod_returns_when_its_zone_would_otherwise_have_no_ready_pod() {
    let cluster = Cluster::of(&SIX);
    cluster.reader.report_all(current(5));
    cluster.reader.report("gw-a1", stale(5));
    cluster.reader.report("gw-a2", stale(5));
    let second = cluster.member("gw-a2", 1);
    twice(&second).await;
    twice(&second).await;
    assert!(!second.gate.is_ready());
    cluster.publish(&["gw-a1", "gw-a2"]);

    let transition = second.checker.check_once().await;

    assert_eq!(transition, ReadinessTransition::BecameReady);
    assert!(second.gate.is_ready());
}

#[tokio::test]
async fn when_every_pod_is_stale_every_pod_stays_ready() {
    let cluster = Cluster::of(&SIX);
    cluster.reader.report_all(stale(5));
    let members: Vec<Member> = SIX
        .iter()
        .map(|(pod, _zone)| cluster.member(pod, 1))
        .collect();

    for _ in 0..4 {
        for member in &members {
            member.checker.check_once().await;
        }
    }

    assert!(members.iter().all(|member| member.gate.is_ready()));
}

#[tokio::test]
async fn a_pod_that_gets_no_answer_from_any_peer_stays_ready() {
    let cluster = Cluster::of(&SIX);
    let member = cluster.member("gw-a1", 1);

    for _ in 0..4 {
        member.checker.check_once().await;
    }

    assert!(member.gate.is_ready());
}

#[tokio::test(start_paused = true)]
async fn the_task_checks_every_interval_until_it_is_stopped() {
    let cluster = Cluster::of(&SIX);
    cluster.reader.report_all(current(5));
    let member = cluster.member("gw-a1", 1);
    let gate = std::sync::Arc::clone(&member.gate);
    let (stop, stopping) = watch::channel(false);

    let task = tokio::spawn(member.checker.run(stopping));
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(gate.is_ready());
    tokio::time::sleep(Duration::from_secs(2)).await;

    assert!(!gate.is_ready());
    stop.send_replace(true);
    task.await.unwrap();
}
