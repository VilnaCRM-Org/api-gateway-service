use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, ChangeId, ChangeStatement, DecisionEffect, IamUnitOfWork, RevocationSource,
    RevocationStatement, SessionId, StateKey, TokenLifetimeFloor,
};
use shared_domain::{Command as _, CommandHandler as _, Uuid};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::token_lifetime_floor::FakeTokenLifetimeFloor;
use test_support::unit_of_work::FakeIamUnitOfWork;

use super::{RevokeSessionsCommand, RevokeSessionsCommandHandler};
use crate::error::IamError;

const USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";
const CHANGE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ac";
const MARGIN: u64 = 120 + 60;

fn at() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(600_000))
        .unwrap()
}

fn after(seconds: u64) -> SystemTime {
    at().checked_add(Duration::from_secs(seconds)).unwrap()
}

fn user() -> Uuid {
    Uuid::parse(USER).unwrap()
}

fn session(value: &str) -> SessionId {
    SessionId::new(value).unwrap()
}

fn command(sessions: &[&str]) -> RevokeSessionsCommand {
    RevokeSessionsCommand {
        change_id: ChangeId::parse(CHANGE).unwrap(),
        user_id: user(),
        session_ids: sessions.iter().map(|value| session(value)).collect(),
        actor: ActorRef::User(user()),
        idempotency: None,
    }
}

fn handler(
    floor: FakeTokenLifetimeFloor,
    unit_of_work: &Arc<FakeIamUnitOfWork>,
) -> RevokeSessionsCommandHandler {
    let unit_of_work: Arc<dyn IamUnitOfWork> = Arc::<FakeIamUnitOfWork>::clone(unit_of_work);
    let floor: Arc<dyn TokenLifetimeFloor> = Arc::new(floor);
    RevokeSessionsCommandHandler::new(
        unit_of_work,
        floor,
        Duration::from_mins(15),
        Arc::new(FixedClock::at(at())),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    )
}

#[test]
fn the_command_is_named_after_its_type() {
    assert_eq!(RevokeSessionsCommand::NAME, "RevokeSessionsCommand");
}

#[tokio::test]
async fn a_revoked_session_is_written_with_its_event_and_audit_record_as_a_revocation_class_change()
{
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    handler(FakeTokenLifetimeFloor::new(), &unit_of_work)
        .handle(command(&["sid-1"]))
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    let change = committed.first().unwrap();
    let parts = change.parts();
    assert_eq!(parts.effect, DecisionEffect::RevocationClass);
    let [ChangeStatement::SaveRevocation(statement)] = parts.statements.as_slice() else {
        panic!("one revocation statement");
    };
    let RevocationStatement::Session(revocation) = statement.as_ref() else {
        panic!("a session revocation");
    };
    assert_eq!(revocation.session, session("sid-1"));
    assert_eq!(revocation.user, user());
    assert_eq!(revocation.source, RevocationSource::Operator);
    assert_eq!(revocation.revoked_by, ActorRef::User(user()));
    assert_eq!(revocation.revoked_at, at());
    assert_eq!(revocation.prune_after, after(900 + MARGIN));
    assert_eq!(parts.events.len(), 1);
    assert_eq!(
        parts.events.first().unwrap().parts().event_type.as_str(),
        "iam.session.revoked"
    );
    assert_eq!(parts.audit.parts().action.as_str(), "session.revoke");
    assert_eq!(
        statement.state_key(),
        StateKey::SessionRevocation(session("sid-1"))
    );
}

#[tokio::test]
async fn every_listed_session_gets_a_statement_and_an_event_and_repeats_collapse() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    handler(FakeTokenLifetimeFloor::new(), &unit_of_work)
        .handle(command(&["sid-1", "sid-2", "sid-1"]))
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    let parts = committed.first().unwrap().parts();
    assert_eq!(parts.statements.len(), 2);
    assert_eq!(parts.events.len(), 2);
}

#[tokio::test]
async fn an_empty_list_sets_the_cutoff_of_the_user_at_the_commit_time_plus_the_margin() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    handler(FakeTokenLifetimeFloor::new(), &unit_of_work)
        .handle(command(&[]))
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    let parts = committed.first().unwrap().parts();
    let [ChangeStatement::SaveRevocation(statement)] = parts.statements.as_slice() else {
        panic!("one revocation statement");
    };
    let RevocationStatement::UserCutoff(cutoff) = statement.as_ref() else {
        panic!("a user cut-off");
    };
    assert_eq!(cutoff.user, user());
    assert_eq!(cutoff.tokens_valid_after, after(2));
    assert_eq!(cutoff.source, RevocationSource::Operator);
    assert_eq!(cutoff.prune_after, after(2 + 900 + MARGIN));
    assert_eq!(
        parts.events.first().unwrap().parts().event_type.as_str(),
        "iam.user_tokens.cut_off"
    );
    assert_eq!(parts.audit.parts().action.as_str(), "user_tokens.cut_off");
}

#[tokio::test]
async fn the_longest_lifetime_ever_configured_sizes_the_prune_instant() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    handler(
        FakeTokenLifetimeFloor::holding(Duration::from_mins(30)),
        &unit_of_work,
    )
    .handle(command(&["sid-1"]))
    .await
    .unwrap();

    let committed = unit_of_work.committed();
    let parts = committed.first().unwrap().parts();
    let [ChangeStatement::SaveRevocation(statement)] = parts.statements.as_slice() else {
        panic!("one revocation statement");
    };
    let RevocationStatement::Session(revocation) = statement.as_ref() else {
        panic!("a session revocation");
    };
    assert_eq!(revocation.prune_after, after(1_800 + MARGIN));
}

#[tokio::test]
async fn an_unreadable_floor_is_a_storage_failure_and_commits_nothing() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let floor = FakeTokenLifetimeFloor::new();
    floor.fail(true);

    let error = handler(floor, &unit_of_work)
        .handle(command(&["sid-1"]))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn a_failing_unit_of_work_is_a_storage_failure() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::failing());

    let error = handler(FakeTokenLifetimeFloor::new(), &unit_of_work)
        .handle(command(&["sid-1"]))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}

#[test]
fn the_parts_of_an_empty_session_list_name_the_user_and_revoke_nothing() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let handler = handler(FakeTokenLifetimeFloor::new(), &unit_of_work);
    let actor = ActorRef::User(user());
    let revoking = super::Revoking {
        user: user(),
        actor: &actor,
        now: at(),
        policy: iam_domain::PrunePolicy::new(Duration::from_mins(15)),
    };

    let (statements, events, target) = handler.session_parts(&revoking, Vec::new()).unwrap();

    assert_eq!(statements.len(), 0);
    assert_eq!(events.len(), 0);
    assert_eq!(target.id, USER);
    assert_eq!(target.after, format!("sessions=0 user={USER}"));
}
