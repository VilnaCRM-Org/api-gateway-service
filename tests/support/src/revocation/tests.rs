use std::time::{Duration, SystemTime};

use iam_domain::{
    AccessToken, AccessTokenParts, ActorRef, GlobalTokenCutoff, InboundEvent, InboundOutcome,
    RepositoryError, RevocationRepository as _, RevocationSource, RevocationStatus,
    RevocationView as _, ServiceName, SessionId, SessionRevocation, SessionRevocationId, SubjectId,
    TokenId, TokenIdentity, UserTokenCutoff,
};
use shared_domain::Uuid;

use super::{FakeRevocationRepository, FakeRevocationView};
use crate::block_on;

const USER: &str = "0190f2a8-7b3c-7d4e-8f00-123456789abc";

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn user() -> Uuid {
    Uuid::parse(USER).unwrap()
}

fn session() -> SessionId {
    SessionId::new("session-1").unwrap()
}

fn identity(subject: SubjectId, session: Option<SessionId>) -> TokenIdentity {
    TokenIdentity::from(&AccessToken::new(AccessTokenParts {
        subject,
        session,
        token_id: TokenId::new("token-1").unwrap(),
        roles: Vec::new(),
        issued_at: at(1_000),
        expires_at: at(1_900),
    }))
}

fn user_identity() -> TokenIdentity {
    identity(SubjectId::User(user()), Some(session()))
}

fn revocation(id: &str, session: SessionId, revoked_at: u64) -> SessionRevocation {
    SessionRevocation {
        id: SessionRevocationId::parse(id).unwrap(),
        session,
        user: user(),
        source: RevocationSource::UserService,
        revoked_by: ActorRef::parse("system:user-service").unwrap(),
        revoked_at: at(revoked_at),
        prune_after: at(revoked_at.checked_add(900).unwrap()),
    }
}

fn user_cutoff(seconds: u64) -> UserTokenCutoff {
    UserTokenCutoff {
        user: user(),
        tokens_valid_after: at(seconds),
        source: RevocationSource::Operator,
        updated_at: at(seconds),
        prune_after: at(seconds.checked_add(900).unwrap()),
    }
}

fn global_cutoff(seconds: u64) -> GlobalTokenCutoff {
    GlobalTokenCutoff {
        tokens_valid_after: at(seconds),
        set_by: ActorRef::parse(&format!("user:{USER}")).unwrap(),
        set_at: at(seconds),
    }
}

fn event(id: &str) -> InboundEvent {
    InboundEvent {
        event_id: Uuid::parse(id).unwrap(),
        topic: "user-events".to_owned(),
        partition: 0,
        offset: 7,
        event_type: "SessionRevoked".to_owned(),
        outcome: InboundOutcome::Applied,
        error: None,
        processed_at: at(1_000),
    }
}

const FIRST: &str = "0190f2a8-7b3c-7d4e-8f00-000000000001";
const SECOND: &str = "0190f2a8-7b3c-7d4e-8f00-000000000002";

#[test]
fn a_new_repository_holds_no_revocation() {
    let repository = FakeRevocationRepository::new();

    assert_eq!(
        block_on(repository.session_revocation(&session())).unwrap(),
        None
    );
    assert_eq!(block_on(repository.user_cutoff(user())).unwrap(), None);
    assert_eq!(block_on(repository.global_cutoff()).unwrap(), None);
    assert_eq!(
        block_on(repository.status(&user_identity())).unwrap(),
        RevocationStatus::default()
    );
}

#[test]
fn a_revoked_session_keeps_its_first_record() {
    let repository = FakeRevocationRepository::new();

    block_on(repository.revoke_session(&revocation(FIRST, session(), 1_000))).unwrap();
    block_on(repository.revoke_session(&revocation(SECOND, session(), 2_000))).unwrap();

    assert_eq!(
        block_on(repository.session_revocation(&session())).unwrap(),
        Some(revocation(FIRST, session(), 1_000))
    );
}

#[test]
fn a_record_id_of_another_session_already_exists() {
    let repository = FakeRevocationRepository::new();
    block_on(repository.revoke_session(&revocation(FIRST, session(), 1_000))).unwrap();

    let other = revocation(FIRST, SessionId::new("session-2").unwrap(), 1_000);

    assert!(matches!(
        block_on(repository.revoke_session(&other)),
        Err(RepositoryError::AlreadyExists)
    ));
}

#[test]
fn the_user_cutoff_never_moves_back() {
    let repository = FakeRevocationRepository::new();

    block_on(repository.set_user_cutoff(&user_cutoff(2_000))).unwrap();
    block_on(repository.set_user_cutoff(&user_cutoff(1_000))).unwrap();

    assert_eq!(
        block_on(repository.user_cutoff(user())).unwrap(),
        Some(user_cutoff(2_000))
    );
    block_on(repository.set_user_cutoff(&user_cutoff(3_000))).unwrap();
    assert_eq!(
        block_on(repository.user_cutoff(user())).unwrap(),
        Some(user_cutoff(3_000))
    );
}

#[test]
fn the_global_cutoff_never_moves_back() {
    let repository = FakeRevocationRepository::new();

    block_on(repository.set_global_cutoff(&global_cutoff(2_000))).unwrap();
    block_on(repository.set_global_cutoff(&global_cutoff(1_000))).unwrap();

    assert_eq!(
        block_on(repository.global_cutoff()).unwrap(),
        Some(global_cutoff(2_000))
    );
    block_on(repository.set_global_cutoff(&global_cutoff(3_000))).unwrap();
    assert_eq!(
        block_on(repository.global_cutoff()).unwrap(),
        Some(global_cutoff(3_000))
    );
}

#[test]
fn an_event_id_is_recorded_once() {
    let repository = FakeRevocationRepository::new();

    assert!(block_on(repository.record_inbound_event(&event(FIRST))).unwrap());
    assert!(!block_on(repository.record_inbound_event(&event(FIRST))).unwrap());
    assert!(block_on(repository.record_inbound_event(&event(SECOND))).unwrap());
}

#[test]
fn the_view_reads_the_session_and_both_cutoffs_of_a_user_token() {
    let repository = FakeRevocationRepository::new();
    block_on(repository.revoke_session(&revocation(FIRST, session(), 1_000))).unwrap();
    block_on(repository.set_user_cutoff(&user_cutoff(1_500))).unwrap();
    block_on(repository.set_global_cutoff(&global_cutoff(1_200))).unwrap();

    let status = block_on(repository.status(&user_identity())).unwrap();

    assert_eq!(
        status,
        RevocationStatus {
            session_revoked: true,
            user_cutoff: Some(at(1_500)),
            global_cutoff: Some(at(1_200)),
        }
    );
}

#[test]
fn a_service_token_has_no_session_and_no_user_cutoff() {
    let repository = FakeRevocationRepository::new();
    block_on(repository.revoke_session(&revocation(FIRST, session(), 1_000))).unwrap();
    block_on(repository.set_user_cutoff(&user_cutoff(1_500))).unwrap();
    let service = SubjectId::Service(ServiceName::new("user-service").unwrap());

    let status = block_on(repository.status(&identity(service, None))).unwrap();

    assert_eq!(status, RevocationStatus::default());
}

#[test]
fn a_failing_repository_is_unavailable_until_it_recovers() {
    let repository = FakeRevocationRepository::new();
    repository.fail(true);

    assert!(matches!(
        block_on(repository.global_cutoff()),
        Err(RepositoryError::Unavailable(_))
    ));
    assert!(matches!(
        block_on(repository.status(&user_identity())),
        Err(RepositoryError::Unavailable(_))
    ));
    repository.fail(false);
    assert_eq!(block_on(repository.global_cutoff()).unwrap(), None);
}

#[test]
fn the_view_double_answers_its_status_and_counts_its_calls() {
    let view = FakeRevocationView::new();

    assert_eq!(
        block_on(view.status(&user_identity())).unwrap(),
        RevocationStatus::default()
    );
    let revoked = RevocationStatus {
        session_revoked: true,
        ..RevocationStatus::default()
    };
    view.answer(revoked);
    assert_eq!(block_on(view.status(&user_identity())).unwrap(), revoked);
    view.fail();
    assert!(matches!(
        block_on(view.status(&user_identity())),
        Err(RepositoryError::Unavailable(_))
    ));
    assert_eq!(view.calls(), 3);
}
