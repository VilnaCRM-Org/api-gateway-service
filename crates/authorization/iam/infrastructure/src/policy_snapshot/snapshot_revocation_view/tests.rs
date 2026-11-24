use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    AccessToken, AccessTokenParts, GlobalRevocationState, RepositoryError, RevocationStatus,
    RevocationView as _, ServiceName, SessionId, SubjectId, TokenId, TokenIdentity,
    UserRevocationState,
};
use shared_domain::Uuid;
use test_support::policy_view::{FakePolicyView, RevocationSnapshot};

use super::SnapshotRevocationView;

const USER: &str = "3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a";

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn identity(subject: SubjectId, session: Option<&str>) -> TokenIdentity {
    TokenIdentity::from(&AccessToken::new(AccessTokenParts {
        subject,
        session: session.map(|session| SessionId::new(session).unwrap()),
        token_id: TokenId::new("token-1").unwrap(),
        roles: Vec::new(),
        issued_at: at(100),
        expires_at: at(1_000),
    }))
}

fn user() -> SubjectId {
    SubjectId::User(Uuid::parse(USER).unwrap())
}

fn view(snapshot: RevocationSnapshot) -> SnapshotRevocationView {
    SnapshotRevocationView::new(Arc::new(FakePolicyView::with_snapshot(Arc::new(snapshot))))
}

#[tokio::test]
async fn a_snapshot_without_records_revokes_nothing() {
    let status = view(RevocationSnapshot::new())
        .status(&identity(user(), Some("sid-1")))
        .await;

    assert_eq!(status.unwrap(), RevocationStatus::default());
}

#[tokio::test]
async fn a_revoked_session_is_reported_for_its_tokens_only() {
    let snapshot = RevocationSnapshot::new().with_revoked_session(SessionId::new("sid-1").unwrap());
    let view = view(snapshot);

    let revoked = view.status(&identity(user(), Some("sid-1"))).await.unwrap();
    let other = view.status(&identity(user(), Some("sid-2"))).await.unwrap();
    let none = view.status(&identity(user(), None)).await.unwrap();

    assert!(revoked.session_revoked);
    assert!(!other.session_revoked);
    assert!(!none.session_revoked);
}

#[tokio::test]
async fn the_user_and_global_cutoffs_are_read_in_whole_microseconds() {
    let snapshot = RevocationSnapshot::new()
        .with_user_cutoff(UserRevocationState {
            user: Uuid::parse(USER).unwrap(),
            tokens_valid_after_micros: 2_000_000,
            prune_after_micros: 9_000_000,
        })
        .with_global_cutoff(GlobalRevocationState {
            tokens_valid_after_micros: 3_000_000,
        });

    let status = view(snapshot)
        .status(&identity(user(), None))
        .await
        .unwrap();

    assert_eq!(status.user_cutoff, Some(at(2)));
    assert_eq!(status.global_cutoff, Some(at(3)));
}

#[tokio::test]
async fn a_service_principal_has_no_user_cutoff() {
    let snapshot = RevocationSnapshot::new().with_user_cutoff(UserRevocationState {
        user: Uuid::parse(USER).unwrap(),
        tokens_valid_after_micros: 2_000_000,
        prune_after_micros: 9_000_000,
    });
    let service = SubjectId::Service(ServiceName::new("user-service").unwrap());

    let status = view(snapshot)
        .status(&identity(service, None))
        .await
        .unwrap();

    assert_eq!(status.user_cutoff, None);
}

#[tokio::test]
async fn a_gateway_without_a_snapshot_cannot_answer() {
    let view = SnapshotRevocationView::new(Arc::new(FakePolicyView::failing()));

    let status = view.status(&identity(user(), None)).await;

    assert!(matches!(status, Err(RepositoryError::Unavailable(_))));
}

#[tokio::test]
async fn a_cutoff_before_1970_is_unusable() {
    let snapshot = RevocationSnapshot::new().with_global_cutoff(GlobalRevocationState {
        tokens_valid_after_micros: -1,
    });

    let status = view(snapshot).status(&identity(user(), None)).await;

    assert!(matches!(status, Err(RepositoryError::Unavailable(_))));
}
