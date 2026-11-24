use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, ChangeId, ChangeStatement, DecisionEffect, IamUnitOfWork, RevocationStatement,
    StateKey,
};
use shared_domain::{Command as _, CommandHandler as _, Uuid};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::unit_of_work::FakeIamUnitOfWork;

use super::{SetGlobalTokenCutoffCommand, SetGlobalTokenCutoffCommandHandler};
use crate::error::IamError;

const USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";
const CHANGE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ac";

fn at() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(600_000))
        .unwrap()
}

fn actor() -> ActorRef {
    ActorRef::User(Uuid::parse(USER).unwrap())
}

fn command() -> SetGlobalTokenCutoffCommand {
    SetGlobalTokenCutoffCommand {
        change_id: ChangeId::parse(CHANGE).unwrap(),
        actor: actor(),
        idempotency: None,
    }
}

fn handler(unit_of_work: &Arc<FakeIamUnitOfWork>) -> SetGlobalTokenCutoffCommandHandler {
    let unit_of_work: Arc<dyn IamUnitOfWork> = Arc::<FakeIamUnitOfWork>::clone(unit_of_work);
    SetGlobalTokenCutoffCommandHandler::new(
        unit_of_work,
        Arc::new(FixedClock::at(at())),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    )
}

#[test]
fn the_command_is_named_after_its_type() {
    assert_eq!(
        SetGlobalTokenCutoffCommand::NAME,
        "SetGlobalTokenCutoffCommand"
    );
}

#[tokio::test]
async fn the_global_cutoff_is_set_at_the_commit_time_plus_the_margin_with_its_event_and_audit() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    handler(&unit_of_work).handle(command()).await.unwrap();

    let committed = unit_of_work.committed();
    let parts = committed.first().unwrap().parts();
    assert_eq!(parts.effect, DecisionEffect::RevocationClass);
    let [ChangeStatement::SaveRevocation(statement)] = parts.statements.as_slice() else {
        panic!("one revocation statement");
    };
    let RevocationStatement::GlobalCutoff(cutoff) = statement.as_ref() else {
        panic!("the global cut-off");
    };
    assert_eq!(
        cutoff.tokens_valid_after,
        at().checked_add(Duration::from_secs(2)).unwrap()
    );
    assert_eq!(cutoff.set_by, actor());
    assert_eq!(cutoff.set_at, at());
    assert_eq!(statement.state_key(), StateKey::GlobalRevocation);
    assert_eq!(
        parts.events.first().unwrap().parts().event_type.as_str(),
        "iam.global_tokens.cut_off"
    );
    assert_eq!(parts.audit.parts().action.as_str(), "global_tokens.cut_off");
}

#[tokio::test]
async fn a_failing_unit_of_work_is_a_storage_failure() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::failing());

    let error = handler(&unit_of_work).handle(command()).await.unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}
