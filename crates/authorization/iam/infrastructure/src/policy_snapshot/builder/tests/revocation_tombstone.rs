//! How a gateway pod's snapshot treats revocation records and their tombstones (FR-79): it never
//! drops an entry by clock, only when the tombstone is applied, and the digest stays that of
//! PostgreSQL.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    AccessToken, AccessTokenParts, PolicyState, RevocationRule, RevocationView as _, SessionId,
    SessionRevocationState, StateKey, SubjectId, TokenId, TokenIdentity, TokenRejection,
    UserRevocationState,
};
use test_support::policy_view::FakePolicyView;

use super::support::{Edit, Rig, uuid};
use crate::policy_snapshot::SnapshotRevocationView;

const PRUNE_AFTER_MICROS: i64 = 9_000_000;

fn session_edit(session: &SessionId, user: shared_domain::Uuid) -> Edit {
    (
        StateKey::SessionRevocation(session.clone()),
        Some(PolicyState::SessionRevocation(SessionRevocationState {
            session: session.clone(),
            user,
            revoked_at_micros: 1_000_000,
            prune_after_micros: PRUNE_AFTER_MICROS,
        })),
    )
}

fn user_edit(user: shared_domain::Uuid) -> Edit {
    (
        StateKey::UserRevocation(user),
        Some(PolicyState::UserRevocation(UserRevocationState {
            user,
            tokens_valid_after_micros: 2_000_000,
            prune_after_micros: PRUNE_AFTER_MICROS,
        })),
    )
}

fn identity(user: shared_domain::Uuid, session: &SessionId) -> TokenIdentity {
    let issued_at = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(1))
        .unwrap();
    TokenIdentity::from(&AccessToken::new(AccessTokenParts {
        subject: SubjectId::User(user),
        session: Some(session.clone()),
        token_id: TokenId::new("token-1").unwrap(),
        roles: Vec::new(),
        issued_at,
        expires_at: issued_at.checked_add(Duration::from_mins(15)).unwrap(),
    }))
}

#[tokio::test]
async fn a_pod_still_refuses_the_revoked_tokens_long_after_every_prune_after_without_a_tombstone() {
    let user = uuid(5_001);
    let session = SessionId::new("sid-1").unwrap();
    let mut rig = Rig::new();
    rig.apply(vec![session_edit(&session, user), user_edit(user)]);
    rig.builder.flush();
    // Nothing in the snapshot depends on the clock of the pod: reading it years after the
    // prune-after instants of the records still reports them.
    let view = SnapshotRevocationView::new(Arc::new(FakePolicyView::with_snapshot(rig.snapshot())));

    let status = view.status(&identity(user, &session)).await.unwrap();

    assert!(status.session_revoked);
    assert!(status.user_cutoff.is_some());
    assert_eq!(
        RevocationRule::check(&identity(user, &session), &status),
        Err(TokenRejection::Revoked)
    );
}

#[test]
fn an_applied_tombstone_drops_the_entry_and_the_digest_stays_that_of_the_writer() {
    let user = uuid(5_001);
    let session = SessionId::new("sid-1").unwrap();
    let mut rig = Rig::new();
    rig.apply(vec![session_edit(&session, user), user_edit(user)]);
    rig.builder.flush();
    assert!(rig.snapshot().session_revoked(&session));

    rig.apply(vec![
        (StateKey::SessionRevocation(session.clone()), None),
        (StateKey::UserRevocation(user), None),
    ]);
    rig.builder.flush();

    let snapshot = rig.snapshot();
    assert!(!snapshot.session_revoked(&session));
    assert_eq!(snapshot.user_cutoff(user), None);
    assert_eq!(rig.builder.digest(), rig.digest);
}
