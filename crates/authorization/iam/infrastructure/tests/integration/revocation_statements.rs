//! The revocation statements of `PgIamUnitOfWork`: the rows of the revocation tables and their
//! state records `revocation/session/<sid>`, `revocation/user/<uid>` and `revocation/global`
//! inside the versioned transaction, and the rules that keep the first session record and never
//! move a cut-off back.

use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, ChangeStatement, DecisionEffect, GlobalTokenCutoff, IamUnitOfWork as _, PolicyState,
    RevocationRepository as _, RevocationSource, RevocationStatement, SessionId, SessionRevocation,
    SessionRevocationId, StateKey, StateRecordCodec as _, UserTokenCutoff,
};
use iam_infrastructure::{JsonStateRecordCodec, PgIamUnitOfWork, PgRevocationRepository};
use shared_domain::Uuid;
use sqlx::PgPool;
use test_support::seed::TestRng;
use test_support::unit_of_work::{iam_change, rebuilt};

const USER: &str = "0190f2a8-7b3c-7d4e-8f00-123456789abc";
const FIRST: &str = "0190f2a8-7b3c-7d4e-8f00-000000000001";
const SECOND: &str = "0190f2a8-7b3c-7d4e-8f00-000000000002";

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn user() -> Uuid {
    Uuid::parse(USER).unwrap()
}

fn actor() -> ActorRef {
    ActorRef::User(user())
}

fn session(id: &str, name: &str, revoked_at: u64) -> SessionRevocation {
    SessionRevocation {
        id: SessionRevocationId::parse(id).unwrap(),
        session: SessionId::new(name).unwrap(),
        user: user(),
        source: RevocationSource::Operator,
        revoked_by: actor(),
        revoked_at: at(revoked_at),
        prune_after: at(revoked_at.checked_add(1_080).unwrap()),
    }
}

fn user_cutoff(seconds: u64) -> UserTokenCutoff {
    UserTokenCutoff {
        user: user(),
        tokens_valid_after: at(seconds),
        source: RevocationSource::Operator,
        updated_at: at(seconds),
        prune_after: at(seconds.checked_add(1_080).unwrap()),
    }
}

fn global_cutoff(seconds: u64) -> GlobalTokenCutoff {
    GlobalTokenCutoff {
        tokens_valid_after: at(seconds),
        set_by: actor(),
        set_at: at(seconds),
    }
}

async fn commit(pool: &PgPool, rng: &mut TestRng, statements: Vec<RevocationStatement>) {
    let change = rebuilt(
        &iam_change(rng, DecisionEffect::RevocationClass, 0),
        |parts| {
            parts.statements = statements.into_iter().map(ChangeStatement::from).collect();
        },
    );
    PgIamUnitOfWork::new(pool.clone())
        .commit(change, iam_domain::WriteMode::Published)
        .await
        .unwrap();
}

/// The key and payload of every state row, in write order, without the head.
async fn state_rows(pool: &PgPool) -> Vec<(String, Option<String>)> {
    sqlx::query_as::<_, (String, Option<String>)>(
        "SELECT record_key, payload FROM iam_outbox WHERE kind = 'state' AND record_key <> '__head'
        ORDER BY position",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_session_revocation_writes_its_row_and_its_state_record(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let revocation = session(FIRST, "sid-1", 1_800_000_000);

    commit(
        &pool,
        &mut rng,
        vec![RevocationStatement::Session(revocation.clone())],
    )
    .await;

    let stored = PgRevocationRepository::new(pool.clone())
        .session_revocation(&revocation.session)
        .await
        .unwrap();
    assert_eq!(stored, Some(revocation.clone()));
    let rows = state_rows(&pool).await;
    let [(key, payload)] = rows.as_slice() else {
        panic!("one state row, found {rows:?}");
    };
    assert_eq!(key, "revocation/session/sid-1");
    let state_key = StateKey::SessionRevocation(revocation.session);
    let PolicyState::SessionRevocation(state) = JsonStateRecordCodec
        .decode(&state_key, payload.as_deref().unwrap())
        .unwrap()
    else {
        panic!("a session revocation state");
    };
    assert_eq!(state.user, user());
    assert_eq!(state.revoked_at_micros, 1_800_000_000_000_000);
    assert_eq!(state.prune_after_micros, 1_800_001_080_000_000);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_session_that_is_revoked_again_keeps_its_first_record_and_writes_no_new_state(
    pool: PgPool,
) {
    let mut rng = TestRng::from_env();
    let first = session(FIRST, "sid-1", 1_800_000_000);
    commit(
        &pool,
        &mut rng,
        vec![RevocationStatement::Session(first.clone())],
    )
    .await;

    commit(
        &pool,
        &mut rng,
        vec![RevocationStatement::Session(session(
            SECOND,
            "sid-1",
            1_800_000_500,
        ))],
    )
    .await;

    let stored = PgRevocationRepository::new(pool.clone())
        .session_revocation(&first.session)
        .await
        .unwrap();
    assert_eq!(stored, Some(first));
    assert_eq!(state_rows(&pool).await.len(), 1);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_user_cutoff_and_the_global_cutoff_write_their_rows_and_state_records(pool: PgPool) {
    let mut rng = TestRng::from_env();

    commit(
        &pool,
        &mut rng,
        vec![
            RevocationStatement::UserCutoff(user_cutoff(1_800_000_000)),
            RevocationStatement::GlobalCutoff(global_cutoff(1_800_000_100)),
        ],
    )
    .await;

    let repository = PgRevocationRepository::new(pool.clone());
    assert_eq!(
        repository.user_cutoff(user()).await.unwrap(),
        Some(user_cutoff(1_800_000_000))
    );
    assert_eq!(
        repository.global_cutoff().await.unwrap(),
        Some(global_cutoff(1_800_000_100))
    );
    let mut keys: Vec<_> = state_rows(&pool)
        .await
        .into_iter()
        .map(|(key, _payload)| key)
        .collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "revocation/global".to_owned(),
            format!("revocation/user/{USER}"),
        ]
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_cutoff_never_moves_back_and_a_later_one_replaces_the_state(pool: PgPool) {
    let mut rng = TestRng::from_env();
    commit(
        &pool,
        &mut rng,
        vec![RevocationStatement::UserCutoff(user_cutoff(1_800_000_500))],
    )
    .await;

    commit(
        &pool,
        &mut rng,
        vec![RevocationStatement::UserCutoff(user_cutoff(1_800_000_000))],
    )
    .await;

    let repository = PgRevocationRepository::new(pool.clone());
    assert_eq!(
        repository
            .user_cutoff(user())
            .await
            .unwrap()
            .unwrap()
            .tokens_valid_after,
        at(1_800_000_500)
    );
    assert_eq!(state_rows(&pool).await.len(), 1);
    commit(
        &pool,
        &mut rng,
        vec![RevocationStatement::UserCutoff(user_cutoff(1_800_000_900))],
    )
    .await;
    assert_eq!(
        repository
            .user_cutoff(user())
            .await
            .unwrap()
            .unwrap()
            .tokens_valid_after,
        at(1_800_000_900)
    );
    assert_eq!(state_rows(&pool).await.len(), 2);
}
