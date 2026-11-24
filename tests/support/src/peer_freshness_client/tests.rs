use iam_domain::{PeerFreshnessClient as _, PolicyVersion};

use super::FakePeerFreshnessClient;
use crate::block_on;

#[test]
fn reports_what_the_test_set() {
    let peers = FakePeerFreshnessClient::new();
    assert_eq!(
        block_on(peers.applied_versions()),
        Vec::<PolicyVersion>::new()
    );

    let version = PolicyVersion::new(4).unwrap();
    peers.report(vec![version]);

    assert_eq!(block_on(peers.applied_versions()), vec![version]);
}
