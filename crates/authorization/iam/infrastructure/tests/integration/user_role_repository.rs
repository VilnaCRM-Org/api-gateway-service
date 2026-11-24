//! `PgUserRoleRepository` and the assignment statements of `PgIamUnitOfWork`: the partial unique
//! index over subject, role and scope among assignments that are not revoked, the check
//! constraints of the subject and the scope, the version guard of updates and the filters of
//! pages.

use std::time::{Duration, SystemTime};

use iam_domain::{
    AssignmentExpiry, AssignmentScope, EntityVersion, IamUnitOfWork as _, ProjectId,
    RepositoryError, RoleId, RoleKind, RoleStatement, ServiceName, SubjectKind, SubjectRef,
    UserRole, UserRoleId, UserRolePageQuery, UserRoleParts, UserRoleRepository as _,
    UserRoleStatement,
};
use iam_infrastructure::{PgIamUnitOfWork, PgUserRoleRepository};
use sqlx::PgPool;
use test_support::role::{role, role_change, role_writer};
use test_support::seed::TestRng;
use test_support::unit_of_work::uuid_v7;
use test_support::user_role::{user_role, user_role_change, user_subject};

/// A time after every fixture time, at which the expiries below have passed.
const LATE: u64 = 4_200_000_000;
/// One second before [`LATE`].
const BEFORE_LATE: u64 = 4_199_999_999;
/// Two seconds before [`LATE`], when no expiry below has passed yet.
const EARLIER: u64 = 4_199_999_998;

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

/// The stored time keeps whole microseconds only.
fn micros(time: SystemTime) -> SystemTime {
    let since = time.duration_since(SystemTime::UNIX_EPOCH).unwrap();
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_micros(
            u64::try_from(since.as_micros()).unwrap(),
        ))
        .unwrap()
}

/// The parts as the store keeps them: times in whole microseconds.
fn as_stored(parts: &UserRoleParts) -> UserRoleParts {
    UserRoleParts {
        expires_at: parts
            .expires_at
            .map(|expiry| AssignmentExpiry::restore(micros(expiry.at()))),
        created_at: micros(parts.created_at),
        updated_at: micros(parts.updated_at),
        ..parts.clone()
    }
}

/// Stores a custom role and returns its id: an assignment must name a stored role.
async fn stored_role(pool: &PgPool, rng: &mut TestRng, name: &str) -> RoleId {
    let created = role(rng, name, RoleKind::Custom);
    let writer = role_writer(rng);
    PgIamUnitOfWork::new(pool.clone())
        .commit(
            role_change(rng, vec![RoleStatement::insert(&created, writer)]),
            iam_domain::WriteMode::Published,
        )
        .await
        .unwrap();
    created.parts().id
}

/// Commits one change that runs `statements`.
async fn save(
    pool: &PgPool,
    rng: &mut TestRng,
    statements: Vec<UserRoleStatement>,
) -> Result<(), RepositoryError> {
    PgIamUnitOfWork::new(pool.clone())
        .commit(
            user_role_change(rng, statements),
            iam_domain::WriteMode::Published,
        )
        .await
        .map(|_receipt| ())
}

/// Inserts `parts` as a new assignment.
async fn insert(
    pool: &PgPool,
    rng: &mut TestRng,
    parts: &UserRoleParts,
) -> Result<(), RepositoryError> {
    let statement = UserRoleStatement::insert(&UserRole::restore(parts.clone()));
    save(pool, rng, vec![statement]).await
}

/// `parts` revoked at version 2.
fn revoked(parts: &UserRoleParts) -> UserRoleParts {
    UserRoleParts {
        version: EntityVersion::new(2).unwrap(),
        updated_at: at(LATE),
        revoked_at: Some(at(LATE)),
        ..parts.clone()
    }
}

/// Revokes the stored `parts`, which holds version 1.
async fn revoke(pool: &PgPool, rng: &mut TestRng, parts: &UserRoleParts) {
    let statement =
        UserRoleStatement::update(&UserRole::restore(revoked(parts)), EntityVersion::INITIAL);
    save(pool, rng, vec![statement]).await.unwrap();
}

async fn found(pool: &PgPool, id: UserRoleId) -> Option<UserRoleParts> {
    PgUserRoleRepository::new(pool.clone())
        .find_by_id(id)
        .await
        .unwrap()
        .map(|found| found.parts().clone())
}

async fn page(pool: &PgPool, query: &UserRolePageQuery) -> Vec<UserRoleId> {
    PgUserRoleRepository::new(pool.clone())
        .find_page(query)
        .await
        .unwrap()
        .into_iter()
        .map(|found| found.parts().id)
        .collect()
}

fn query() -> UserRolePageQuery {
    UserRolePageQuery {
        limit: 100,
        after: None,
        subject_kind: None,
        subject_id: None,
        role_id: None,
        project_id: None,
        include_expired: false,
        now: at(LATE),
    }
}

fn project(rng: &mut TestRng) -> AssignmentScope {
    AssignmentScope::Project(ProjectId::from_uuid(uuid_v7(rng)))
}

fn service(name: &str) -> SubjectRef {
    SubjectRef::service(ServiceName::new(name).unwrap())
}

fn sorted(mut ids: Vec<UserRoleId>) -> Vec<UserRoleId> {
    ids.sort();
    ids
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn an_inserted_assignment_is_found_with_its_state(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let role_id = stored_role(&pool, &mut rng, "Billing").await;
    let subject = user_subject(&mut rng);
    let scope = project(&mut rng);
    let assignment = UserRoleParts {
        expires_at: Some(AssignmentExpiry::restore(at(LATE))),
        ..user_role(&mut rng, role_id, subject, scope).parts().clone()
    };

    insert(&pool, &mut rng, &assignment).await.unwrap();

    assert_eq!(
        found(&pool, assignment.id).await,
        Some(as_stored(&assignment))
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn an_active_duplicate_of_subject_role_and_scope_already_exists(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let role_id = stored_role(&pool, &mut rng, "Billing").await;
    let subject = user_subject(&mut rng);
    let scope = project(&mut rng);
    for scope in [scope, AssignmentScope::Global] {
        let first = user_role(&mut rng, role_id, subject.clone(), scope);
        let again = user_role(&mut rng, role_id, subject.clone(), scope);
        insert(&pool, &mut rng, first.parts()).await.unwrap();

        let duplicate = insert(&pool, &mut rng, again.parts()).await;

        assert!(matches!(duplicate, Err(RepositoryError::AlreadyExists)));
        assert_eq!(found(&pool, again.parts().id).await, None);
    }
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn an_expired_assignment_still_holds_its_triple(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let role_id = stored_role(&pool, &mut rng, "Billing").await;
    let subject = user_subject(&mut rng);
    let expired = UserRoleParts {
        expires_at: Some(AssignmentExpiry::restore(at(1))),
        ..user_role(&mut rng, role_id, subject.clone(), AssignmentScope::Global)
            .parts()
            .clone()
    };
    insert(&pool, &mut rng, &expired).await.unwrap();
    let again = user_role(&mut rng, role_id, subject, AssignmentScope::Global);

    assert!(matches!(
        insert(&pool, &mut rng, again.parts()).await,
        Err(RepositoryError::AlreadyExists)
    ));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_triple_of_a_revoked_assignment_can_be_assigned_again(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let role_id = stored_role(&pool, &mut rng, "Billing").await;
    let subject = user_subject(&mut rng);
    let scope = project(&mut rng);
    let first = user_role(&mut rng, role_id, subject.clone(), scope);
    insert(&pool, &mut rng, first.parts()).await.unwrap();
    revoke(&pool, &mut rng, first.parts()).await;
    let again = user_role(&mut rng, role_id, subject, scope);

    insert(&pool, &mut rng, again.parts()).await.unwrap();

    assert_eq!(found(&pool, first.parts().id).await, None);
    assert_eq!(
        found(&pool, again.parts().id).await,
        Some(as_stored(again.parts()))
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn an_update_changes_the_expiry_only_at_the_expected_version(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let role_id = stored_role(&pool, &mut rng, "Billing").await;
    let subject = user_subject(&mut rng);
    let first = user_role(&mut rng, role_id, subject, AssignmentScope::Global);
    insert(&pool, &mut rng, first.parts()).await.unwrap();
    let changed = UserRoleParts {
        expires_at: Some(AssignmentExpiry::restore(at(LATE))),
        version: EntityVersion::new(2).unwrap(),
        updated_at: at(LATE),
        ..first.parts().clone()
    };
    let update = |expected: i64| {
        UserRoleStatement::update(
            &UserRole::restore(changed.clone()),
            EntityVersion::new(expected).unwrap(),
        )
    };

    let stale = save(&pool, &mut rng, vec![update(2)]).await;
    save(&pool, &mut rng, vec![update(1)]).await.unwrap();
    let again = save(&pool, &mut rng, vec![update(1)]).await;

    assert!(matches!(stale, Err(RepositoryError::Conflict)));
    assert!(matches!(again, Err(RepositoryError::Conflict)));
    assert_eq!(
        found(&pool, first.parts().id).await,
        Some(as_stored(&changed))
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_revoked_assignment_refuses_an_update(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let role_id = stored_role(&pool, &mut rng, "Billing").await;
    let subject = user_subject(&mut rng);
    let first = user_role(&mut rng, role_id, subject, AssignmentScope::Global);
    insert(&pool, &mut rng, first.parts()).await.unwrap();
    revoke(&pool, &mut rng, first.parts()).await;
    let statement = UserRoleStatement::update(
        &UserRole::restore(UserRoleParts {
            version: EntityVersion::new(3).unwrap(),
            revoked_at: None,
            ..revoked(first.parts())
        }),
        EntityVersion::new(2).unwrap(),
    );

    assert!(matches!(
        save(&pool, &mut rng, vec![statement]).await,
        Err(RepositoryError::Conflict)
    ));
}

/// Inserts one raw row with the given subject and scope columns and returns the violated check
/// constraint.
async fn violated_check(
    pool: &PgPool,
    role_id: RoleId,
    subject: (&str, &str),
    scope: (&str, Option<sqlx::types::Uuid>),
) -> Option<String> {
    let error = sqlx::query(
        "INSERT INTO iam_user_roles (id, subject_kind, subject_id, role_id, scope_kind,
            project_id, version, created_by, created_at, updated_at)
        VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, 1, 'system:bootstrap', now(), now())",
    )
    .bind(subject.0)
    .bind(subject.1)
    .bind(role_id.as_uuid().as_uuid())
    .bind(scope.0)
    .bind(scope.1)
    .execute(pool)
    .await
    .unwrap_err();
    let database = error.as_database_error().unwrap();
    assert!(database.is_check_violation());
    database.constraint().map(str::to_owned)
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_check_constraints_reject_an_invalid_subject_or_scope(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let role_id = stored_role(&pool, &mut rng, "Billing").await;
    let user = "9c8b7a6f-5e4d-4c3b-a291-807f6e5d4c3b";
    let project_id = Some(uuid_v7(&mut rng).as_uuid());
    let long_name = "a".repeat(64);

    for (subject, scope, constraint) in [
        (
            ("user", user),
            ("project", None),
            "iam_user_roles_scope_project_check",
        ),
        (
            ("user", user),
            ("global", project_id),
            "iam_user_roles_scope_project_check",
        ),
        (
            ("user", "billing-service"),
            ("global", None),
            "iam_user_roles_user_subject_check",
        ),
        (
            ("user", "9C8B7A6F-5E4D-4C3B-A291-807F6E5D4C3B"),
            ("global", None),
            "iam_user_roles_user_subject_check",
        ),
        (
            ("service", "Billing Service"),
            ("global", None),
            "iam_user_roles_service_subject_check",
        ),
        (
            ("service", long_name.as_str()),
            ("global", None),
            "iam_user_roles_service_subject_check",
        ),
        (
            ("group", user),
            ("global", None),
            "iam_user_roles_subject_kind_check",
        ),
        (
            ("user", user),
            ("tenant", None),
            "iam_user_roles_scope_kind_check",
        ),
    ] {
        assert_eq!(
            violated_check(&pool, role_id, subject, scope)
                .await
                .as_deref(),
            Some(constraint),
            "{subject:?} {scope:?}"
        );
    }
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn pages_exclude_revoked_rows_and_list_expired_rows_only_when_requested(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let billing = stored_role(&pool, &mut rng, "Billing").await;
    let support = stored_role(&pool, &mut rng, "Support").await;
    let user = user_subject(&mut rng);
    let scope = project(&mut rng);
    let active_user = user_role(&mut rng, billing, user.clone(), scope);
    let expired_user = UserRoleParts {
        expires_at: Some(AssignmentExpiry::restore(at(BEFORE_LATE))),
        ..user_role(&mut rng, support, user.clone(), AssignmentScope::Global)
            .parts()
            .clone()
    };
    let revoked_user = user_role(&mut rng, billing, user.clone(), AssignmentScope::Global);
    let active_service = user_role(&mut rng, billing, service("billing-service"), scope);
    let expired_service = UserRoleParts {
        expires_at: Some(AssignmentExpiry::restore(at(LATE))),
        ..user_role(
            &mut rng,
            support,
            service("billing-service"),
            AssignmentScope::Global,
        )
        .parts()
        .clone()
    };
    for parts in [
        active_user.parts(),
        &expired_user,
        revoked_user.parts(),
        active_service.parts(),
        &expired_service,
    ] {
        insert(&pool, &mut rng, parts).await.unwrap();
    }
    revoke(&pool, &mut rng, revoked_user.parts()).await;
    let active = |parts: &UserRole| parts.parts().id;

    assert_eq!(
        page(&pool, &query()).await,
        sorted(vec![active(&active_user), active(&active_service)])
    );
    assert_eq!(
        page(
            &pool,
            &UserRolePageQuery {
                include_expired: true,
                ..query()
            }
        )
        .await,
        sorted(vec![
            active(&active_user),
            expired_user.id,
            active(&active_service),
            expired_service.id,
        ])
    );
    assert_eq!(
        page(
            &pool,
            &UserRolePageQuery {
                subject_kind: Some(SubjectKind::Service),
                include_expired: true,
                ..query()
            }
        )
        .await,
        sorted(vec![active(&active_service), expired_service.id])
    );
    assert_eq!(
        page(
            &pool,
            &UserRolePageQuery {
                subject_kind: Some(SubjectKind::User),
                subject_id: Some(user.id().to_string()),
                ..query()
            }
        )
        .await,
        vec![active(&active_user)]
    );
    assert_eq!(
        page(
            &pool,
            &UserRolePageQuery {
                role_id: Some(support),
                include_expired: true,
                ..query()
            }
        )
        .await,
        sorted(vec![expired_user.id, expired_service.id])
    );
    assert_eq!(
        page(
            &pool,
            &UserRolePageQuery {
                project_id: scope.project_id(),
                ..query()
            }
        )
        .await,
        sorted(vec![active(&active_user), active(&active_service)])
    );
    assert_eq!(
        page(
            &pool,
            &UserRolePageQuery {
                now: at(EARLIER),
                ..query()
            }
        )
        .await,
        sorted(vec![
            active(&active_user),
            expired_user.id,
            active(&active_service),
            expired_service.id,
        ])
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn pages_follow_the_identifiers_after_the_cursor(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let role_id = stored_role(&pool, &mut rng, "Billing").await;
    let mut ids = Vec::new();
    for _index in 0..5 {
        let subject = user_subject(&mut rng);
        let assignment = user_role(&mut rng, role_id, subject, AssignmentScope::Global);
        insert(&pool, &mut rng, assignment.parts()).await.unwrap();
        ids.push(assignment.parts().id);
    }
    let ids = sorted(ids);

    let first = page(
        &pool,
        &UserRolePageQuery {
            limit: 2,
            ..query()
        },
    )
    .await;
    let second = page(
        &pool,
        &UserRolePageQuery {
            limit: 2,
            after: first.last().copied(),
            ..query()
        },
    )
    .await;

    assert_eq!(first, ids[..2].to_vec());
    assert_eq!(second, ids[2..4].to_vec());
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_stored_row_that_breaks_an_invariant_is_unavailable(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let role_id = stored_role(&pool, &mut rng, "Billing").await;
    let subject = user_subject(&mut rng);
    let assignment = user_role(&mut rng, role_id, subject, AssignmentScope::Global);
    insert(&pool, &mut rng, assignment.parts()).await.unwrap();
    sqlx::query("UPDATE iam_user_roles SET created_by = 'nobody'")
        .execute(&pool)
        .await
        .unwrap();

    let repository = PgUserRoleRepository::new(pool.clone());

    assert!(matches!(
        repository.find_by_id(assignment.parts().id).await,
        Err(RepositoryError::Unavailable(_))
    ));
    assert!(matches!(
        repository.find_page(&query()).await,
        Err(RepositoryError::Unavailable(_))
    ));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_down_migration_removes_the_table(pool: PgPool) {
    let down =
        include_str!("../../../../../../migrations/20261122205127_create_iam_user_roles.down.sql");

    sqlx::raw_sql(down).execute(&pool).await.unwrap();

    let exists: bool = sqlx::query_scalar("SELECT to_regclass('iam_user_roles') IS NOT NULL")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!exists);
}
