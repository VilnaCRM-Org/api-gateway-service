use iam_domain::ReadyPeers as _;

use super::FakeReadyPeers;

#[test]
fn reports_the_count_it_was_given_and_the_one_it_is_set_to() {
    let peers = FakeReadyPeers::new(3);
    assert_eq!(peers.ready_endpoints(), 3);

    peers.set(1);

    assert_eq!(peers.ready_endpoints(), 1);
}

#[test]
fn no_peers_by_default() {
    assert_eq!(FakeReadyPeers::default().ready_endpoints(), 0);
}
