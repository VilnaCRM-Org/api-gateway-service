//! The state rows of `PgIamUnitOfWork`: one row per changed entity with its full new state, the
//! running digest and the `__head` row of each versioned transaction.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use iam_domain::{
    AssignmentScope, ChangeStatement, DecisionEffect, EntityVersion, IamUnitOfWork as _,
    PolicyDigest as _, PolicyDigestValue, PolicyState, PolicyVersion, RepositoryError, Role,
    RoleId, RoleKind, RoleParts, RoleStatement, StateKey, StateRecordCodec as _, SubjectRef,
    UserRole, UserRoleParts, UserRoleStatement,
};
use iam_infrastructure::{JsonStateRecordCodec, PgIamUnitOfWork, Sha256PolicyDigest};
use sqlx::PgPool;
use test_support::role::{role, role_change, role_writer};
use test_support::seed::TestRng;
use test_support::unit_of_work::{iam_change, rebuilt};
use test_support::user_role::{user_role, user_subject};

const POLICY_TOPIC: &str = "iam.policy.state.v1";

/// One stored state row: version, sequence, count, key, payload and digest after the row.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Row {
    version: i64,
    seq: i32,
    count: i32,
    key: String,
    payload: Option<String>,
    digest_after: Vec<u8>,
}

async fn rows(pool: &PgPool) -> Vec<Row> {
    sqlx::query_as::<_, (i64, i32, i32, String, Option<String>, Vec<u8>)>(
        "SELECT policy_version, seq, count, record_key, payload, digest_after FROM iam_outbox
        WHERE kind = 'state' ORDER BY position",
    )
    .fetch_all(pool)
    .await
    .unwrap()
    .into_iter()
    .map(|(version, seq, count, key, payload, digest_after)| Row {
        version,
        seq,
        count,
        key,
        payload,
        digest_after,
    })
    .collect()
}

async fn epoch_digest(pool: &PgPool) -> Vec<u8> {
    sqlx::query_scalar("SELECT digest FROM iam_policy_epoch WHERE id = 1")
        .fetch_one(pool)
        .await
        .unwrap()
}

/// The digest of the state that the rows build when replayed into an empty map: the highest
/// version per key wins and a tombstone deletes the key.
fn replayed_digest(rows: &[Row]) -> Vec<u8> {
    let mut state: BTreeMap<&str, (i64, Option<&str>)> = BTreeMap::new();
    for row in rows.iter().filter(|row| row.key != "__head") {
        let newer = state
            .get(row.key.as_str())
            .is_none_or(|(version, _)| *version <= row.version);
        if newer {
            state.insert(&row.key, (row.version, row.payload.as_deref()));
        }
    }
    state
        .into_iter()
        .filter_map(|(key, (_version, payload))| payload.map(|payload| (key, payload)))
        .fold(PolicyDigestValue::ZERO, |digest, (key, payload)| {
            let key = StateKey::parse(key).unwrap();
            digest.combined(Sha256PolicyDigest.entity_hash(&key, payload))
        })
        .as_bytes()
        .to_vec()
}

fn at() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(1_700_000_000))
        .unwrap()
}

fn with_statements(rng: &mut TestRng, statements: Vec<ChangeStatement>) -> iam_domain::IamChange {
    rebuilt(&iam_change(rng, DecisionEffect::Affected, 0), |parts| {
        parts.statements = statements;
    })
}

fn insert_role(role: &Role, rng: &mut TestRng) -> ChangeStatement {
    ChangeStatement::SaveRole(Box::new(RoleStatement::insert(role, role_writer(rng))))
}

fn insert_assignment(user_role: &UserRole) -> ChangeStatement {
    ChangeStatement::SaveUserRole(Box::new(UserRoleStatement::insert(user_role)))
}

fn revoke(parts: &UserRoleParts) -> ChangeStatement {
    let revoked = UserRoleParts {
        version: EntityVersion::new(2).unwrap(),
        updated_at: at(),
        revoked_at: Some(at()),
        ..parts.clone()
    };
    ChangeStatement::SaveUserRole(Box::new(UserRoleStatement::update(
        &UserRole::restore(revoked),
        EntityVersion::INITIAL,
    )))
}

/// A role deleted at version 2.
fn delete(role: &Role, rng: &mut TestRng) -> ChangeStatement {
    let deleted = Role::restore(RoleParts {
        version: EntityVersion::new(2).unwrap(),
        updated_at: at(),
        deleted_at: Some(at()),
        ..role.parts().clone()
    });
    ChangeStatement::SaveRole(Box::new(RoleStatement::update(
        &deleted,
        EntityVersion::INITIAL,
        role_writer(rng),
    )))
}

/// Two roles, three assignments and the subjects that hold them.
struct World {
    doomed: Role,
    kept: Role,
    first: SubjectRef,
    second: SubjectRef,
    on_doomed: [UserRole; 2],
}

async fn seeded(pool: &PgPool, rng: &mut TestRng) -> World {
    let unit = PgIamUnitOfWork::new(pool.clone());
    let doomed = role(rng, "Doomed", RoleKind::Custom);
    let kept = role(rng, "Kept", RoleKind::Custom);
    let first = user_subject(rng);
    let second = user_subject(rng);
    let global = AssignmentScope::Global;
    let first_doomed = user_role(rng, doomed.parts().id, first.clone(), global);
    let second_doomed = user_role(rng, doomed.parts().id, second.clone(), global);
    let first_kept = user_role(rng, kept.parts().id, first.clone(), global);
    let inserts = vec![insert_role(&doomed, rng), insert_role(&kept, rng)];
    unit.commit(with_statements(rng, inserts)).await.unwrap();
    let assigned = vec![
        insert_assignment(&first_doomed),
        insert_assignment(&second_doomed),
        insert_assignment(&first_kept),
    ];
    unit.commit(with_statements(rng, assigned)).await.unwrap();
    World {
        doomed,
        kept,
        first,
        second,
        on_doomed: [first_doomed, second_doomed],
    }
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_role_created_through_the_unit_of_work_writes_its_state_and_the_head(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let created = role(&mut rng, "Editor", RoleKind::Custom);
    let writer = role_writer(&mut rng);
    let change = role_change(&mut rng, vec![RoleStatement::insert(&created, writer)]);

    PgIamUnitOfWork::new(pool.clone())
        .commit(change)
        .await
        .unwrap();

    let stored = rows(&pool).await;
    let [role_row, head_row] = stored.as_slice() else {
        panic!("expected a role row and a head row, found {stored:?}");
    };
    let id = created.parts().id;
    assert_eq!(role_row.key, format!("role/{id}"));
    assert_eq!((role_row.version, role_row.seq, role_row.count), (1, 1, 2));
    let payload = role_row.payload.as_deref().unwrap();
    assert!(payload.contains(r#""schemaVersion":1"#));
    let PolicyState::Role(state) = JsonStateRecordCodec
        .decode(&StateKey::Role(id), payload)
        .unwrap()
    else {
        panic!("expected a role state");
    };
    assert_eq!(state.name, "Editor");
    assert_eq!(state.version, EntityVersion::INITIAL);
    assert_eq!(state.grants.len(), 0);
    assert_eq!(head_row.key, "__head");
    assert_eq!((head_row.version, head_row.seq, head_row.count), (1, 2, 2));
    let PolicyState::Head(head) = JsonStateRecordCodec
        .decode(&StateKey::Head, head_row.payload.as_deref().unwrap())
        .unwrap()
    else {
        panic!("expected a head");
    };
    assert_eq!(head.version, PolicyVersion::new(1).unwrap());
    assert_eq!(head.digest.as_bytes().to_vec(), epoch_digest(&pool).await);
    assert_eq!(head_row.digest_after, epoch_digest(&pool).await);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_state_row_is_an_unpublished_state_row_of_the_policy_topic(pool: PgPool) {
    let mut rng = TestRng::from_env();
    seeded(&pool, &mut rng).await;

    let (topics, unpublished, others): (i64, i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE topic = $1), count(*) FILTER (WHERE published_at IS NULL),
            count(*) FILTER (WHERE event_type IS NOT NULL OR aggregate_id IS NOT NULL)
        FROM iam_outbox WHERE kind = 'state'",
    )
    .bind(POLICY_TOPIC)
    .fetch_one(&pool)
    .await
    .unwrap();

    let total = i64::try_from(rows(&pool).await.len()).unwrap();
    assert_eq!((topics, unpublished, others), (total, total, 0));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_deleted_role_is_a_tombstone_and_each_affected_subject_gets_its_remaining_list(
    pool: PgPool,
) {
    let mut rng = TestRng::from_env();
    let world = seeded(&pool, &mut rng).await;
    let statements = vec![
        delete(&world.doomed, &mut rng),
        revoke(world.on_doomed[0].parts()),
        revoke(world.on_doomed[1].parts()),
    ];
    let change = with_statements(&mut rng, statements);

    PgIamUnitOfWork::new(pool.clone())
        .commit(change)
        .await
        .unwrap();

    let version: Vec<Row> = rows(&pool)
        .await
        .into_iter()
        .filter(|row| row.version == 3)
        .collect();
    let sequence: Vec<i32> = version.iter().map(|row| row.seq).collect();
    assert_eq!(sequence, [1, 2, 3, 4]);
    assert!(version.iter().all(|row| row.count == 4));
    let find = |key: String| version.iter().find(|row| row.key == key).unwrap();
    assert_eq!(
        find(format!("role/{}", world.doomed.parts().id)).payload,
        None
    );
    assert_eq!(
        find(format!("subject/{}", subject_path(&world.second))).payload,
        None
    );
    let remaining = find(format!("subject/{}", subject_path(&world.first)));
    let PolicyState::Subject(state) = JsonStateRecordCodec
        .decode(
            &StateKey::Subject(world.first.clone()),
            remaining.payload.as_deref().unwrap(),
        )
        .unwrap()
    else {
        panic!("expected a subject state");
    };
    let roles: Vec<RoleId> = state
        .assignments
        .iter()
        .map(|assignment| assignment.role)
        .collect();
    assert_eq!(roles, [world.kept.parts().id]);
    assert_eq!(version.last().unwrap().key, "__head");
}

/// The `<kind>/<id>` path of a subject key.
fn subject_path(subject: &SubjectRef) -> String {
    format!("{}/{}", subject.kind().as_str(), subject.id())
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_digest_after_the_last_record_of_every_version_is_the_stored_digest(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let world = seeded(&pool, &mut rng).await;
    let after_seed = rows(&pool).await;
    let stored_after_seed = epoch_digest(&pool).await;
    let statements = vec![
        delete(&world.doomed, &mut rng),
        revoke(world.on_doomed[0].parts()),
        revoke(world.on_doomed[1].parts()),
    ];
    let change = with_statements(&mut rng, statements);

    PgIamUnitOfWork::new(pool.clone())
        .commit(change)
        .await
        .unwrap();

    let all = rows(&pool).await;
    assert_eq!(after_seed.last().unwrap().digest_after, stored_after_seed);
    assert_eq!(all.last().unwrap().digest_after, epoch_digest(&pool).await);
    assert_ne!(stored_after_seed, epoch_digest(&pool).await);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn replaying_the_state_rows_into_an_empty_map_gives_the_digest_of_postgresql(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let world = seeded(&pool, &mut rng).await;
    let unit = PgIamUnitOfWork::new(pool.clone());
    assert_eq!(
        replayed_digest(&rows(&pool).await),
        epoch_digest(&pool).await
    );
    let first_revocation = vec![revoke(world.on_doomed[0].parts())];
    unit.commit(with_statements(&mut rng, first_revocation))
        .await
        .unwrap();
    assert_eq!(
        replayed_digest(&rows(&pool).await),
        epoch_digest(&pool).await
    );
    let last = vec![
        delete(&world.doomed, &mut rng),
        revoke(world.on_doomed[1].parts()),
    ];
    unit.commit(with_statements(&mut rng, last)).await.unwrap();

    assert_eq!(
        replayed_digest(&rows(&pool).await),
        epoch_digest(&pool).await
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_change_that_does_not_affect_decisions_writes_no_state_row_and_keeps_the_digest(
    pool: PgPool,
) {
    let mut rng = TestRng::from_env();
    let created = role(&mut rng, "Draft", RoleKind::Custom);
    let change = rebuilt(
        &iam_change(&mut rng, DecisionEffect::Unaffected, 1),
        |parts| parts.statements = vec![insert_role(&created, &mut rng)],
    );

    PgIamUnitOfWork::new(pool.clone())
        .commit(change)
        .await
        .unwrap();

    assert_eq!(rows(&pool).await.len(), 0);
    assert_eq!(epoch_digest(&pool).await, vec![0; 16]);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_statement_that_fails_leaves_no_state_row_and_no_head(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let created = role(&mut rng, "Twice", RoleKind::Custom);
    let statements = vec![
        insert_role(&created, &mut rng),
        insert_role(&created, &mut rng),
    ];
    let change = with_statements(&mut rng, statements);

    let error = PgIamUnitOfWork::new(pool.clone())
        .commit(change)
        .await
        .unwrap_err();

    assert!(matches!(error, RepositoryError::AlreadyExists));
    assert_eq!(rows(&pool).await.len(), 0);
    assert_eq!(epoch_digest(&pool).await, vec![0; 16]);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_change_that_changes_no_entity_writes_only_the_head(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let change = with_statements(&mut rng, Vec::new());

    PgIamUnitOfWork::new(pool.clone())
        .commit(change)
        .await
        .unwrap();

    let stored = rows(&pool).await;
    let [head] = stored.as_slice() else {
        panic!("expected the head alone, found {stored:?}");
    };
    assert_eq!((head.key.as_str(), head.seq, head.count), ("__head", 1, 1));
    assert_eq!(head.digest_after, vec![0; 16]);
}
