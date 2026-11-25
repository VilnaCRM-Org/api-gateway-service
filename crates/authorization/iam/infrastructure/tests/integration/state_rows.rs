//! The state rows of `PgIamUnitOfWork`: one row per changed entity with its full new state, the
//! running digest and the `__head` row of each versioned transaction.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, AssignmentScope, BulkKind, BulkOperation, BulkOperationId, ChangeStatement,
    DecisionEffect, EntityVersion, EpochChange, IamUnitOfWork as _, LogEpoch, PermissionGrant,
    PermissionGrantSet, PolicyDigest as _, PolicyDigestValue, PolicyState, PolicyVersion,
    RepositoryError, Republication, ResyncStart, Role, RoleId, RoleKind, RoleName, RoleParts,
    RoleStatement, StateKey, StateRecordCodec as _, SubjectRef, SystemComponent, UserRole,
    UserRoleParts, UserRoleStatement,
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
    unit.commit(
        with_statements(rng, inserts),
        iam_domain::WriteMode::Published,
    )
    .await
    .unwrap();
    let assigned = vec![
        insert_assignment(&first_doomed),
        insert_assignment(&second_doomed),
        insert_assignment(&first_kept),
    ];
    unit.commit(
        with_statements(rng, assigned),
        iam_domain::WriteMode::Published,
    )
    .await
    .unwrap();
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
        .commit(change, iam_domain::WriteMode::Published)
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
        .commit(change, iam_domain::WriteMode::Published)
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
        .commit(change, iam_domain::WriteMode::Published)
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
    unit.commit(
        with_statements(&mut rng, first_revocation),
        iam_domain::WriteMode::Published,
    )
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
    unit.commit(
        with_statements(&mut rng, last),
        iam_domain::WriteMode::Published,
    )
    .await
    .unwrap();

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
        .commit(change, iam_domain::WriteMode::Published)
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
        .commit(change, iam_domain::WriteMode::Published)
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
        .commit(change, iam_domain::WriteMode::Published)
        .await
        .unwrap();

    let stored = rows(&pool).await;
    let [head] = stored.as_slice() else {
        panic!("expected the head alone, found {stored:?}");
    };
    assert_eq!((head.key.as_str(), head.seq, head.count), ("__head", 1, 1));
    assert_eq!(head.digest_after, vec![0; 16]);
}

/// The log epoch and the version of the policy epoch row.
async fn epoch_row(pool: &PgPool) -> (i64, i64) {
    sqlx::query_as("SELECT log_epoch, version FROM iam_policy_epoch WHERE id = 1")
        .fetch_one(pool)
        .await
        .unwrap()
}

/// The start of a resync from the log epoch `from` with the version floor `floor`.
fn resync_start(from: i64, floor: i64) -> ChangeStatement {
    let epoch = EpochChange::new(
        LogEpoch::new(from).unwrap(),
        PolicyVersion::new(floor).unwrap(),
    )
    .unwrap();
    let operation = BulkOperation::pending(
        BulkOperationId::parse("0190f2a8-7b3c-7d4e-8f10-000000000001").unwrap(),
        BulkKind::Resync,
        3,
        ActorRef::System(SystemComponent::Startup),
        at(),
    )
    .unwrap();
    ChangeStatement::StartResync(Box::new(ResyncStart::new(epoch, operation.parts().clone())))
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_republication_writes_the_unchanged_state_again_under_the_next_version(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let world = seeded(&pool, &mut rng).await;
    let before = rows(&pool).await;
    let digest = epoch_digest(&pool).await;
    let keys = vec![
        StateKey::Role(world.kept.parts().id),
        StateKey::Subject(world.first.clone()),
    ];
    let change = with_statements(
        &mut rng,
        vec![ChangeStatement::RepublishState(Box::new(
            Republication::new(keys.clone(), Vec::new()),
        ))],
    );

    PgIamUnitOfWork::new(pool.clone())
        .commit(change, iam_domain::WriteMode::Published)
        .await
        .unwrap();

    let again: Vec<Row> = rows(&pool).await.split_off(before.len());
    let written: Vec<&str> = again.iter().map(|row| row.key.as_str()).collect();
    assert_eq!(again.len(), 3);
    assert!(
        keys.iter()
            .all(|key| written.contains(&key.to_string().as_str()))
    );
    assert_eq!(written.last(), Some(&"__head"));
    assert!(again.iter().all(|row| row.version == 3 && row.count == 3));
    assert_eq!(epoch_digest(&pool).await, digest);
    assert_eq!(replayed_digest(&rows(&pool).await), digest);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_new_log_epoch_raises_the_version_above_the_floor_and_stamps_the_rows(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let world = seeded(&pool, &mut rng).await;
    let statements = vec![
        resync_start(0, 500),
        ChangeStatement::RepublishState(Box::new(Republication::new(
            vec![StateKey::Role(world.kept.parts().id)],
            Vec::new(),
        ))),
    ];
    let change = with_statements(&mut rng, statements);

    let receipt = PgIamUnitOfWork::new(pool.clone())
        .commit(change, iam_domain::WriteMode::Published)
        .await
        .unwrap();

    assert_eq!(epoch_row(&pool).await, (1, 501));
    assert_eq!(receipt.policy_version(), PolicyVersion::new(501).ok());
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM iam_bulk_operations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stored, 1);
    let epochs: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT log_epoch, policy_version FROM iam_outbox WHERE kind = 'state'
        AND policy_version > 2 ORDER BY position",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_ne!(epochs.len(), 0);
    assert!(epochs.iter().all(|row| *row == (1, 501)));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_version_already_above_the_floor_keeps_counting_from_where_it_is(pool: PgPool) {
    let mut rng = TestRng::from_env();
    seeded(&pool, &mut rng).await;
    let change = with_statements(&mut rng, vec![resync_start(0, 1)]);

    PgIamUnitOfWork::new(pool.clone())
        .commit(change, iam_domain::WriteMode::Published)
        .await
        .unwrap();

    assert_eq!(epoch_row(&pool).await, (1, 3));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_new_log_epoch_from_a_stale_epoch_is_a_conflict_and_writes_nothing(pool: PgPool) {
    let mut rng = TestRng::from_env();
    seeded(&pool, &mut rng).await;
    let change = with_statements(&mut rng, vec![resync_start(4, 9)]);

    let refused = PgIamUnitOfWork::new(pool.clone())
        .commit(change, iam_domain::WriteMode::Published)
        .await
        .unwrap_err();

    assert!(matches!(refused, RepositoryError::Conflict));
    assert_eq!(epoch_row(&pool).await, (0, 2));
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM iam_bulk_operations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stored, 0);
}

/// The grants of `values`.
fn grant_set(values: &[&str]) -> PermissionGrantSet {
    PermissionGrantSet::new(
        values
            .iter()
            .map(|value| PermissionGrant::parse(value).unwrap()),
    )
    .unwrap()
}

/// The version after `version`.
fn after(version: EntityVersion) -> EntityVersion {
    EntityVersion::new(version.value().saturating_add(1)).unwrap()
}

/// `stored` as its next version with the name and the grants given.
fn next_version_of(stored: &RoleParts, name: &str, grants: PermissionGrantSet) -> Role {
    Role::restore(RoleParts {
        name: RoleName::new(name.to_owned()).unwrap(),
        grants,
        version: after(stored.version),
        updated_at: at(),
        ..stored.clone()
    })
}

/// The deletion of `stored` at the version after its own, guarded by its version.
fn delete_current(stored: &RoleParts, rng: &mut TestRng) -> ChangeStatement {
    let deleted = Role::restore(RoleParts {
        version: after(stored.version),
        updated_at: at(),
        deleted_at: Some(at()),
        ..stored.clone()
    });
    update_role(stored, &deleted, rng)
}

/// The update of `stored` to `next`, guarded by the version of `stored`.
fn update_role(stored: &RoleParts, next: &Role, rng: &mut TestRng) -> ChangeStatement {
    ChangeStatement::SaveRole(Box::new(RoleStatement::update(
        next,
        stored.version,
        role_writer(rng),
    )))
}

/// A change that does not affect decisions and runs `statements`.
fn unaffected(rng: &mut TestRng, statements: Vec<ChangeStatement>) -> iam_domain::IamChange {
    rebuilt(&iam_change(rng, DecisionEffect::Unaffected, 0), |parts| {
        parts.statements = statements;
    })
}

async fn commit(pool: &PgPool, change: iam_domain::IamChange) {
    PgIamUnitOfWork::new(pool.clone())
        .commit(change, iam_domain::WriteMode::Published)
        .await
        .unwrap();
}

/// The head digest and the digest of the records on the topic must be the same digest.
async fn assert_head_matches_records(pool: &PgPool) {
    let stored = rows(pool).await;
    assert_eq!(replayed_digest(&stored), epoch_digest(pool).await);
    if let Some(last) = stored.last() {
        assert_eq!(last.digest_after, epoch_digest(pool).await);
    }
}

async fn published_state(pool: &PgPool, id: RoleId) -> Option<String> {
    sqlx::query_scalar("SELECT published_state FROM iam_roles WHERE id = $1")
        .bind(id.as_uuid().as_uuid())
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_role_created_empty_and_then_granted_keeps_the_head_digest_equal_to_the_records(
    pool: PgPool,
) {
    let mut rng = TestRng::from_env();
    let created = role(&mut rng, "Empty", RoleKind::Custom);
    let insert = insert_role(&created, &mut rng);
    commit(&pool, unaffected(&mut rng, vec![insert])).await;
    assert_eq!(rows(&pool).await.len(), 0);
    assert_eq!(published_state(&pool, created.parts().id).await, None);
    let granted = next_version_of(
        created.parts(),
        "Empty",
        grant_set(&["rest:core:GET /users"]),
    );
    let grant = update_role(created.parts(), &granted, &mut rng);
    commit(&pool, with_statements(&mut rng, vec![grant])).await;
    assert_head_matches_records(&pool).await;

    let regranted = next_version_of(
        granted.parts(),
        "Empty",
        grant_set(&["rest:core:POST /users", "gql:core:Query.*"]),
    );
    let regrant = update_role(granted.parts(), &regranted, &mut rng);
    commit(&pool, with_statements(&mut rng, vec![regrant])).await;

    assert_head_matches_records(&pool).await;
    let stored = rows(&pool).await;
    let published = published_state(&pool, created.parts().id).await.unwrap();
    let last_role_row = stored
        .iter()
        .rev()
        .find(|row| row.key.starts_with("role/"))
        .unwrap();
    assert_eq!(last_role_row.payload.as_deref(), Some(published.as_str()));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_published_role_renamed_without_a_version_keeps_the_head_digest_equal_to_the_records(
    pool: PgPool,
) {
    let mut rng = TestRng::from_env();
    let created = role(&mut rng, "Before", RoleKind::Custom);
    let first = next_version_of(
        created.parts(),
        "Before",
        grant_set(&["rest:core:GET /users"]),
    );
    let insert = insert_role(&created, &mut rng);
    commit(&pool, with_statements(&mut rng, vec![insert])).await;
    let grant = update_role(created.parts(), &first, &mut rng);
    commit(&pool, with_statements(&mut rng, vec![grant])).await;
    let renamed = next_version_of(first.parts(), "After", first.parts().grants.clone());
    let rename = update_role(first.parts(), &renamed, &mut rng);
    commit(&pool, unaffected(&mut rng, vec![rename])).await;
    assert_head_matches_records(&pool).await;
    let regranted = next_version_of(
        renamed.parts(),
        "After",
        grant_set(&["rest:core:POST /users"]),
    );
    let regrant = update_role(renamed.parts(), &regranted, &mut rng);

    commit(&pool, with_statements(&mut rng, vec![regrant])).await;

    assert_head_matches_records(&pool).await;
    let published = published_state(&pool, created.parts().id).await.unwrap();
    assert!(published.contains(r#""name":"After""#), "{published}");
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_role_that_was_never_published_is_deleted_without_a_tombstone(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let created = role(&mut rng, "Never published", RoleKind::Custom);
    let insert = insert_role(&created, &mut rng);
    commit(&pool, unaffected(&mut rng, vec![insert])).await;
    let doomed = delete(&created, &mut rng);

    commit(&pool, with_statements(&mut rng, vec![doomed])).await;

    assert_head_matches_records(&pool).await;
    assert!(
        rows(&pool)
            .await
            .iter()
            .all(|row| !row.key.starts_with("role/"))
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_rows_name_the_topics_of_the_unit_of_work(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let created = role(&mut rng, "Routed", RoleKind::Custom);
    let insert = insert_role(&created, &mut rng);
    let change = with_statements(&mut rng, vec![insert]);

    PgIamUnitOfWork::new(pool.clone())
        .with_policy_topic("custom.policy".to_owned())
        .with_events_topic("custom.events".to_owned())
        .commit(change, iam_domain::WriteMode::Published)
        .await
        .unwrap();

    let topics: Vec<String> =
        sqlx::query_scalar("SELECT DISTINCT topic FROM iam_outbox WHERE kind = 'state'")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(topics, vec!["custom.policy".to_owned()]);
}

/// A deterministic stream of choices drawn from the seed of the test (splitmix64).
struct Choices(u64);

impl Choices {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mixed = (self.0 ^ (self.0 >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        let mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        mixed ^ (mixed >> 31)
    }

    fn below(&mut self, bound: usize) -> usize {
        let bound = u64::try_from(bound).unwrap();
        usize::try_from(self.next().checked_rem(bound).unwrap()).unwrap()
    }

    /// A subset of `keys`, possibly empty.
    fn grants(&mut self, keys: &[&str]) -> PermissionGrantSet {
        let chosen: Vec<&str> = keys
            .iter()
            .copied()
            .filter(|_key| self.below(2) == 0)
            .collect();
        grant_set(&chosen)
    }
}

const GRANT_KEYS: [&str; 4] = [
    "rest:core:GET /users",
    "rest:core:POST /users",
    "gql:core:Query.*",
    "iam:grant:sensitive",
];

/// The roles and assignments that the random sequence has stored.
struct Stored {
    roles: Vec<Role>,
    assignments: Vec<UserRoleParts>,
    subjects: Vec<SubjectRef>,
    counter: usize,
}

impl Stored {
    fn next_name(&mut self) -> String {
        self.counter = self.counter.saturating_add(1);
        format!("Role {}", self.counter)
    }

    fn assignments_of(&self, role: RoleId) -> Vec<UserRoleParts> {
        self.assignments
            .iter()
            .filter(|assignment| assignment.role_id == role)
            .cloned()
            .collect()
    }

    fn forget_assignment(&mut self, id: iam_domain::UserRoleId) {
        self.assignments.retain(|assignment| assignment.id != id);
    }
}

/// The effect and statements of one step.
type Step = (DecisionEffect, Vec<ChangeStatement>);

/// The effect and statements of one random step; an impossible step is `None`.
fn step(choices: &mut Choices, stored: &mut Stored, rng: &mut TestRng) -> Option<Step> {
    match choices.below(7) {
        0 => Some(create_role(choices, stored, rng, false)),
        1 => Some(create_role(choices, stored, rng, true)),
        2 | 3 => edit_role(choices, stored, rng),
        4 => assign(choices, stored, rng),
        5 => revoke_one(choices, stored),
        _ => delete_one(choices, stored, rng),
    }
}

/// A new role: empty by a change that does not affect decisions, or with random grants by one that
/// does.
fn create_role(
    choices: &mut Choices,
    stored: &mut Stored,
    rng: &mut TestRng,
    granted: bool,
) -> Step {
    let name = stored.next_name();
    let empty = role(rng, &name, RoleKind::Custom);
    let grants = if granted {
        choices.grants(&GRANT_KEYS)
    } else {
        PermissionGrantSet::default()
    };
    let created = Role::restore(RoleParts {
        grants,
        ..empty.parts().clone()
    });
    let statement = insert_role(&created, rng);
    stored.roles.push(created);
    let effect = if granted {
        DecisionEffect::Affected
    } else {
        DecisionEffect::Unaffected
    };
    (effect, vec![statement])
}

/// A rename, which does not affect decisions, or a grant replacement, which does.
fn edit_role(choices: &mut Choices, stored: &mut Stored, rng: &mut TestRng) -> Option<Step> {
    let index = pick(choices, stored.roles.len())?;
    let current = stored.roles.get(index)?.parts().clone();
    let (name, grants, effect) = if choices.below(2) == 0 {
        let name = stored.next_name();
        (name, current.grants.clone(), DecisionEffect::Unaffected)
    } else {
        let grants = choices.grants(&GRANT_KEYS);
        (
            current.name.as_str().to_owned(),
            grants,
            DecisionEffect::Affected,
        )
    };
    let next = next_version_of(&current, &name, grants);
    let statement = update_role(&current, &next, rng);
    *stored.roles.get_mut(index)? = next;
    Some((effect, vec![statement]))
}

/// A new global assignment of a role to a subject that does not hold it.
fn assign(choices: &mut Choices, stored: &mut Stored, rng: &mut TestRng) -> Option<Step> {
    let role_index = pick(choices, stored.roles.len())?;
    let subject_index = pick(choices, stored.subjects.len())?;
    let role_id = stored.roles.get(role_index)?.parts().id;
    let subject = stored.subjects.get(subject_index)?.clone();
    let held = stored
        .assignments
        .iter()
        .any(|assignment| assignment.role_id == role_id && assignment.subject == subject);
    if held {
        return None;
    }
    let assignment = user_role(rng, role_id, subject, AssignmentScope::Global);
    let statement = insert_assignment(&assignment);
    stored.assignments.push(assignment.parts().clone());
    Some((DecisionEffect::Affected, vec![statement]))
}

/// The revocation of one stored assignment.
fn revoke_one(choices: &mut Choices, stored: &mut Stored) -> Option<Step> {
    let index = pick(choices, stored.assignments.len())?;
    let assignment = stored.assignments.get(index)?.clone();
    stored.forget_assignment(assignment.id);
    Some((DecisionEffect::Affected, vec![revoke(&assignment)]))
}

/// The deletion of one stored role with the revocation of its assignments.
fn delete_one(choices: &mut Choices, stored: &mut Stored, rng: &mut TestRng) -> Option<Step> {
    let index = pick(choices, stored.roles.len())?;
    let doomed = stored.roles.remove(index);
    let mut statements = vec![delete_current(doomed.parts(), rng)];
    for assignment in stored.assignments_of(doomed.parts().id) {
        stored.forget_assignment(assignment.id);
        statements.push(revoke(&assignment));
    }
    Some((DecisionEffect::Affected, statements))
}

fn pick(choices: &mut Choices, len: usize) -> Option<usize> {
    (len > 0).then(|| choices.below(len))
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_head_digest_equals_the_digest_of_the_emitted_records_after_any_sequence_of_changes(
    pool: PgPool,
) {
    let mut rng = TestRng::from_env();
    let mut choices = Choices(rng.seed());
    let subjects = (0..3).map(|_| user_subject(&mut rng)).collect();
    let mut stored = Stored {
        roles: Vec::new(),
        assignments: Vec::new(),
        subjects,
        counter: 0,
    };
    for _ in 0..120 {
        let Some((effect, statements)) = step(&mut choices, &mut stored, &mut rng) else {
            continue;
        };
        let change = rebuilt(&iam_change(&mut rng, effect, 0), |parts| {
            parts.statements = statements;
        });
        commit(&pool, change).await;
        assert_head_matches_records(&pool).await;
    }
}
