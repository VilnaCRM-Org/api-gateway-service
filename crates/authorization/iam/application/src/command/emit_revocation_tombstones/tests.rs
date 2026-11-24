use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ChangeReceipt, ChangeStatement, DecisionEffect, ExpiredRevocation, IamChange, IamUnitOfWork,
    PolicyVersion, RepositoryError, RevocationStatement, SessionId, StateKey, WriteMode,
};
use shared_domain::{CommandHandler as _, Uuid};
use test_support::clock::FixedClock;
use test_support::expired_revocation_store::FakeExpiredRevocationStore;
use test_support::id::SequenceUuidGenerator;
use test_support::log::LogRecorder;
use test_support::unit_of_work::FakeIamUnitOfWork;

use super::{EmitRevocationTombstonesCommand, EmitRevocationTombstonesCommandHandler};
use crate::error::IamError;

const USER: &str = "3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a";
const PRUNE_AFTER: u64 = 1_700_000_000;

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn session(id: &str, prune_after: u64) -> ExpiredRevocation {
    ExpiredRevocation::Session {
        session: SessionId::new(id).unwrap(),
        prune_after: at(prune_after),
    }
}

fn cutoff(prune_after: u64) -> ExpiredRevocation {
    ExpiredRevocation::UserCutoff {
        user: Uuid::parse(USER).unwrap(),
        prune_after: at(prune_after),
    }
}

fn handler(
    store: &Arc<FakeExpiredRevocationStore>,
    unit_of_work: &Arc<FakeIamUnitOfWork>,
    now: u64,
) -> EmitRevocationTombstonesCommandHandler {
    EmitRevocationTombstonesCommandHandler::new(
        Arc::<FakeExpiredRevocationStore>::clone(store),
        Arc::<FakeIamUnitOfWork>::clone(unit_of_work),
        Arc::new(FixedClock::at(at(now))),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    )
}

#[tokio::test]
async fn no_tombstone_exists_one_second_before_the_prune_after_instant() {
    let store =
        Arc::new(FakeExpiredRevocationStore::new().holding(vec![session("sid-1", PRUNE_AFTER)]));
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    handler(&store, &unit_of_work, PRUNE_AFTER - 1)
        .handle(EmitRevocationTombstonesCommand)
        .await
        .unwrap();

    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn a_tombstone_is_committed_one_second_after_the_prune_after_instant() {
    let store =
        Arc::new(FakeExpiredRevocationStore::new().holding(vec![session("sid-1", PRUNE_AFTER)]));
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    handler(&store, &unit_of_work, PRUNE_AFTER + 1)
        .handle(EmitRevocationTombstonesCommand)
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    assert_eq!(committed.len(), 1);
    let change = &committed[0];
    assert_eq!(change.parts().effect, DecisionEffect::Affected);
    assert_eq!(change.parts().events.len(), 0);
    assert_eq!(
        change.parts().statements,
        vec![ChangeStatement::SaveRevocation(Box::new(
            RevocationStatement::Prune {
                target: session("sid-1", PRUNE_AFTER),
                now: at(PRUNE_AFTER + 1),
            }
        ))]
    );
    assert_eq!(
        change.parts().statements[0].state_keys(),
        vec![StateKey::SessionRevocation(
            SessionId::new("sid-1").unwrap()
        )]
    );
}

#[tokio::test]
async fn a_record_exactly_at_the_instant_is_not_tombstoned() {
    let store =
        Arc::new(FakeExpiredRevocationStore::new().holding(vec![session("sid-1", PRUNE_AFTER)]));
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    handler(&store, &unit_of_work, PRUNE_AFTER)
        .handle(EmitRevocationTombstonesCommand)
        .await
        .unwrap();

    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn sessions_and_cutoffs_go_in_one_change_with_an_audit_record_each() {
    let store = Arc::new(FakeExpiredRevocationStore::new().holding(vec![
        session("sid-1", PRUNE_AFTER),
        cutoff(PRUNE_AFTER - 10),
        session("sid-2", PRUNE_AFTER + 5),
    ]));
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    handler(&store, &unit_of_work, PRUNE_AFTER + 100)
        .handle(EmitRevocationTombstonesCommand)
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    assert_eq!(committed.len(), 1);
    let audits = committed[0].audits(PolicyVersion::new(1).unwrap());
    let records: Vec<(String, String, String)> = audits
        .iter()
        .map(|audit| {
            let parts = audit.parts();
            (
                parts.action.as_str().to_owned(),
                parts.target.target_type().to_owned(),
                parts.target.target_id().to_owned(),
            )
        })
        .collect();
    let action = "revocation.tombstoned".to_owned();
    assert_eq!(
        records,
        vec![
            (action.clone(), "user_cutoff".to_owned(), USER.to_owned()),
            (
                action.clone(),
                "session_revocation".to_owned(),
                "sid-1".to_owned()
            ),
            (action, "session_revocation".to_owned(), "sid-2".to_owned()),
        ]
    );
    assert_eq!(committed[0].parts().statements.len(), 3);
}

#[tokio::test]
async fn a_run_asks_for_at_most_the_batch_limit_at_the_controlled_time() {
    let store = Arc::new(FakeExpiredRevocationStore::new());
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    handler(&store, &unit_of_work, PRUNE_AFTER)
        .handle(EmitRevocationTombstonesCommand)
        .await
        .unwrap();

    assert_eq!(store.requests(), vec![(at(PRUNE_AFTER), 500)]);
}

#[tokio::test]
async fn a_store_that_fails_fails_the_run() {
    let store = Arc::new(FakeExpiredRevocationStore::failing());
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    let result = handler(&store, &unit_of_work, PRUNE_AFTER)
        .handle(EmitRevocationTombstonesCommand)
        .await;

    assert!(matches!(result, Err(IamError::Storage(_))));
}

#[tokio::test]
async fn a_unit_of_work_that_fails_fails_the_run() {
    let store =
        Arc::new(FakeExpiredRevocationStore::new().holding(vec![session("sid-1", PRUNE_AFTER)]));
    let unit_of_work = Arc::new(FakeIamUnitOfWork::failing());

    let result = handler(&store, &unit_of_work, PRUNE_AFTER + 1)
        .handle(EmitRevocationTombstonesCommand)
        .await;

    assert!(matches!(result, Err(IamError::Storage(_))));
}

/// A unit of work that finds the policy changed under every change.
#[derive(Debug)]
struct ChangedPolicy;

#[async_trait::async_trait]
impl IamUnitOfWork for ChangedPolicy {
    async fn commit(
        &self,
        _change: IamChange,
        _write_mode: WriteMode,
    ) -> Result<ChangeReceipt, RepositoryError> {
        Err(RepositoryError::Conflict)
    }
}

#[tokio::test]
async fn a_policy_that_changed_during_the_run_defers_the_tombstones_to_the_next_run() {
    let (recorder, _guard) = LogRecorder::install();
    let store =
        Arc::new(FakeExpiredRevocationStore::new().holding(vec![session("sid-1", PRUNE_AFTER)]));
    let handler = EmitRevocationTombstonesCommandHandler::new(
        store,
        Arc::new(ChangedPolicy),
        Arc::new(FixedClock::at(at(PRUNE_AFTER + 1))),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    );

    handler
        .handle(EmitRevocationTombstonesCommand)
        .await
        .unwrap();

    let lines = recorder.lines();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].field("count"), Some("1"));
}
