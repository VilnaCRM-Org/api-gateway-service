use iam_domain::PeerFreshnessClient as _;

use super::EmptyPeerFreshnessClient;

#[tokio::test]
async fn an_empty_peer_set_reports_no_version() {
    assert_eq!(
        EmptyPeerFreshnessClient.applied_versions().await,
        Vec::<iam_domain::PolicyVersion>::new()
    );
}
