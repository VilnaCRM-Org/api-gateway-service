//! `PgRoleRepository` and the role statements of `PgIamUnitOfWork`: unique names without regard to
//! case among roles that are not deleted, the version guard of updates, the stored grants and
//! stable pages.

use std::collections::BTreeSet;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, EntityVersion, IamUnitOfWork as _, PermissionGrant, PermissionGrantSet,
    RepositoryError, Role, RoleGrant, RoleId, RoleKind, RolePageQuery, RoleParts, RolePatch,
    RoleRepository as _, RoleStamp, RoleStatement,
};
use iam_infrastructure::{PgIamUnitOfWork, PgRoleRepository};
use shared_domain::UuidGenerator as _;
use sqlx::PgPool;
use test_support::id::SequenceUuidGenerator;
use test_support::role::{role, role_change, role_writer};
use test_support::seed::TestRng;

fn version(value: i64) -> EntityVersion {
    EntityVersion::new(value).unwrap()
}

/// The event ids of the role stamps; every test runs against its own database.
static EVENT_IDS: SequenceUuidGenerator = SequenceUuidGenerator::starting_at(1);

fn stamp(actor: &ActorRef, role: &Role) -> RoleStamp {
    RoleStamp {
        event_id: EVENT_IDS.generate(),
        actor: actor.clone(),
        occurred_at: role
            .parts()
            .updated_at
            .checked_add(Duration::from_secs(60))
            .unwrap(),
    }
}

fn grants(values: &[&str]) -> PermissionGrantSet {
    PermissionGrantSet::new(
        values
            .iter()
            .map(|value| PermissionGrant::parse(value).unwrap()),
    )
    .unwrap()
}

/// Commits one change that runs `statements`.
async fn save(
    pool: &PgPool,
    rng: &mut TestRng,
    statements: Vec<RoleStatement>,
) -> Result<(), RepositoryError> {
    PgIamUnitOfWork::new(pool.clone())
        .commit(
            role_change(rng, statements),
            iam_domain::WriteMode::Published,
        )
        .await
        .map(|_receipt| ())
}

/// The stored parts of a role, as the repository rebuilds them.
async fn stored(pool: &PgPool, id: RoleId) -> Option<RoleParts> {
    PgRoleRepository::new(pool.clone())
        .find_by_id(id)
        .await
        .unwrap()
        .map(|role| role.parts().clone())
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

async fn count(pool: &PgPool, sql: &'static str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(pool).await.unwrap()
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn an_inserted_role_is_found_with_its_state_and_its_grants(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let writer = role_writer(&mut rng);
    let mut created = role(&mut rng, "Billing", RoleKind::Custom);
    created
        .replace_permissions(
            Some(version(1)),
            grants(&[
                "rest:core:GET /users",
                "gql:billing:*",
                "iam:grant:sensitive",
            ]),
            stamp(&writer, &created),
        )
        .unwrap();

    save(
        &pool,
        &mut rng,
        vec![RoleStatement::insert(&created, writer.clone())],
    )
    .await
    .unwrap();

    let found = stored(&pool, created.parts().id).await.unwrap();
    let mut expected = created.parts().clone();
    expected.created_at = micros(expected.created_at);
    expected.updated_at = micros(expected.updated_at);
    assert_eq!(found, expected);
    let granted_by: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT granted_by FROM iam_role_permissions WHERE role_id = $1",
    )
    .bind(created.parts().id.as_uuid().as_uuid())
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(granted_by, vec![writer.to_string()]);
    let kinds: Vec<(String, String, bool)> = sqlx::query_as(
        "SELECT key_kind, service, is_wildcard FROM iam_role_permissions ORDER BY permission_key",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        kinds,
        vec![
            ("gql".to_owned(), "billing".to_owned(), true),
            ("iam".to_owned(), "iam".to_owned(), false),
            ("rest".to_owned(), "core".to_owned(), false),
        ]
    );
    assert_eq!(
        count(&pool, "SELECT grant_count::bigint FROM iam_roles").await,
        3
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn an_unknown_role_is_not_found(pool: PgPool) {
    let id = role(&mut TestRng::from_env(), "Billing", RoleKind::Custom)
        .parts()
        .id;

    assert_eq!(stored(&pool, id).await, None);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_name_in_use_without_regard_to_case_is_a_duplicate(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let writer = role_writer(&mut rng);
    let billing = role(&mut rng, "Billing", RoleKind::Custom);
    save(
        &pool,
        &mut rng,
        vec![RoleStatement::insert(&billing, writer.clone())],
    )
    .await
    .unwrap();
    let duplicate = role(&mut rng, "billing", RoleKind::Custom);

    let error = save(
        &pool,
        &mut rng,
        vec![RoleStatement::insert(&duplicate, writer)],
    )
    .await
    .unwrap_err();

    assert!(matches!(error, RepositoryError::AlreadyExists));
    assert_eq!(stored(&pool, duplicate.parts().id).await, None);
    assert_eq!(count(&pool, "SELECT count(*) FROM iam_roles").await, 1);
    assert_eq!(
        count(&pool, "SELECT count(*) FROM iam_change_receipts").await,
        1
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_name_of_a_deleted_role_can_be_used_again(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let writer = role_writer(&mut rng);
    let mut billing = role(&mut rng, "Billing", RoleKind::Custom);
    save(
        &pool,
        &mut rng,
        vec![RoleStatement::insert(&billing, writer.clone())],
    )
    .await
    .unwrap();
    billing
        .delete(Some(version(1)), 0, stamp(&writer, &billing))
        .unwrap();
    save(
        &pool,
        &mut rng,
        vec![RoleStatement::update(&billing, version(1), writer.clone())],
    )
    .await
    .unwrap();
    let again = role(&mut rng, "billing", RoleKind::Custom);

    save(&pool, &mut rng, vec![RoleStatement::insert(&again, writer)])
        .await
        .unwrap();

    assert_eq!(stored(&pool, billing.parts().id).await, None);
    let found = stored(&pool, again.parts().id).await.unwrap();
    assert_eq!(found.name.as_str(), "billing");
    assert_eq!(count(&pool, "SELECT count(*) FROM iam_roles").await, 2);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn an_update_with_an_outdated_version_changes_no_row_and_is_a_conflict(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let writer = role_writer(&mut rng);
    let mut billing = role(&mut rng, "Billing", RoleKind::Custom);
    save(
        &pool,
        &mut rng,
        vec![RoleStatement::insert(&billing, writer.clone())],
    )
    .await
    .unwrap();
    let before = stored(&pool, billing.parts().id).await.unwrap();
    billing
        .update(
            Some(version(1)),
            RolePatch::default(),
            stamp(&writer, &billing),
        )
        .unwrap();
    billing
        .replace_permissions(
            Some(version(2)),
            grants(&["rest:core:GET /users"]),
            stamp(&writer, &billing),
        )
        .unwrap();

    let error = save(
        &pool,
        &mut rng,
        vec![RoleStatement::update(&billing, version(2), writer)],
    )
    .await
    .unwrap_err();

    assert!(matches!(error, RepositoryError::Conflict));
    assert_eq!(stored(&pool, billing.parts().id).await, Some(before));
    assert_eq!(
        count(&pool, "SELECT count(*) FROM iam_role_permissions").await,
        0
    );
    assert_eq!(
        count(&pool, "SELECT count(*) FROM iam_change_receipts").await,
        1
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn an_update_at_the_current_version_replaces_the_state_and_the_grants(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let first_writer = role_writer(&mut rng);
    let second_writer = role_writer(&mut rng);
    let mut billing = role(&mut rng, "Billing", RoleKind::Custom);
    billing
        .replace_permissions(
            Some(version(1)),
            grants(&["rest:core:GET /users", "rest:core:POST /users"]),
            stamp(&first_writer, &billing),
        )
        .unwrap();
    save(
        &pool,
        &mut rng,
        vec![RoleStatement::insert(&billing, first_writer.clone())],
    )
    .await
    .unwrap();
    billing
        .replace_permissions(
            Some(version(2)),
            grants(&["rest:core:GET /users", "gql:core:Query.*"]),
            stamp(&second_writer, &billing),
        )
        .unwrap();

    save(
        &pool,
        &mut rng,
        vec![RoleStatement::update(
            &billing,
            version(2),
            second_writer.clone(),
        )],
    )
    .await
    .unwrap();

    let found = stored(&pool, billing.parts().id).await.unwrap();
    assert_eq!(found.version, version(3));
    assert_eq!(found.grants, billing.parts().grants);
    let grantors: Vec<(String, String)> = sqlx::query_as(
        "SELECT permission_key, granted_by FROM iam_role_permissions ORDER BY permission_key",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        grantors,
        vec![
            ("gql:core:Query.*".to_owned(), second_writer.to_string()),
            ("rest:core:GET /users".to_owned(), first_writer.to_string()),
        ]
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn an_update_of_an_unknown_role_is_a_conflict(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let writer = role_writer(&mut rng);
    let mut unknown = role(&mut rng, "Billing", RoleKind::Custom);
    unknown
        .update(
            Some(version(1)),
            RolePatch::default(),
            stamp(&writer, &unknown),
        )
        .unwrap();

    let error = save(
        &pool,
        &mut rng,
        vec![RoleStatement::update(&unknown, version(1), writer)],
    )
    .await
    .unwrap_err();

    assert!(matches!(error, RepositoryError::Conflict));
    assert_eq!(count(&pool, "SELECT count(*) FROM iam_roles").await, 0);
}

/// Reads every page of `limit` roles with the filters and returns the identifiers in page order.
async fn read_all_pages(
    repository: &PgRoleRepository,
    limit: u32,
    name_prefix: &str,
    kind: RoleKind,
) -> Vec<RoleId> {
    let mut seen = Vec::new();
    let mut after = None;
    loop {
        let page = repository
            .find_page(&RolePageQuery {
                limit,
                after,
                name_prefix: Some(name_prefix.to_owned()),
                kind: Some(kind),
            })
            .await
            .unwrap();
        assert!(page.len() <= usize::try_from(limit).unwrap());
        let Some(last) = page.last() else {
            return seen;
        };
        after = Some(last.parts().id);
        seen.extend(page.iter().map(|role| role.parts().id));
    }
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn pages_of_every_size_list_each_matching_role_exactly_once_in_a_stable_order(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let writer = role_writer(&mut rng);
    let prefixes = ["Team-", "TEAM-", "team-", "Other-"];
    let roles: Vec<Role> = (0..250_usize)
        .map(|index| {
            let prefix = prefixes.get(index % 4).unwrap();
            let kind = if index % 3 == 0 {
                RoleKind::System
            } else {
                RoleKind::Custom
            };
            role(&mut rng, &format!("{prefix}{index}"), kind)
        })
        .collect();
    let mut expected: Vec<RoleId> = roles
        .iter()
        .map(Role::parts)
        .filter(|role| {
            role.kind == RoleKind::Custom && role.name.comparison_form().starts_with("team-")
        })
        .map(|role| role.id)
        .collect();
    expected.sort();
    let statements = roles
        .iter()
        .map(|role| RoleStatement::insert(role, writer.clone()))
        .collect();
    save(&pool, &mut rng, statements).await.unwrap();
    let repository = PgRoleRepository::new(pool.clone());

    for limit in [1, 37, 100] {
        let seen = read_all_pages(&repository, limit, "tEaM-", RoleKind::Custom).await;

        assert_eq!(seen, expected, "pages of {limit}");
        assert_eq!(
            seen.iter().collect::<BTreeSet<_>>().len(),
            seen.len(),
            "pages of {limit} repeat a role"
        );
    }
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_grants_of_a_role_are_listed_with_their_active_flag_in_key_order(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let writer = role_writer(&mut rng);
    let mut created = role(&mut rng, "Billing", RoleKind::Custom);
    created
        .replace_permissions(
            Some(version(1)),
            grants(&[
                "rest:core:GET /users",
                "gql:billing:*",
                "gql:billing:Query.old",
            ]),
            stamp(&writer, &created),
        )
        .unwrap();
    save(
        &pool,
        &mut rng,
        vec![RoleStatement::insert(&created, writer)],
    )
    .await
    .unwrap();
    sqlx::query("UPDATE iam_role_permissions SET active = FALSE WHERE permission_key = $1")
        .bind("gql:billing:Query.old")
        .execute(&pool)
        .await
        .unwrap();

    let found = PgRoleRepository::new(pool)
        .find_grants(created.parts().id)
        .await
        .unwrap();

    let listed: Vec<(String, bool)> = found
        .iter()
        .map(|grant| (grant.grant.to_string(), grant.active))
        .collect();
    assert_eq!(
        listed,
        vec![
            ("gql:billing:*".to_owned(), true),
            ("gql:billing:Query.old".to_owned(), false),
            ("rest:core:GET /users".to_owned(), true),
        ]
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_deleted_or_unknown_role_has_no_listed_grants(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let writer = role_writer(&mut rng);
    let mut deleted = role(&mut rng, "Gone", RoleKind::Custom);
    deleted
        .replace_permissions(
            Some(version(1)),
            grants(&["gql:billing:*"]),
            stamp(&writer, &deleted),
        )
        .unwrap();
    save(
        &pool,
        &mut rng,
        vec![RoleStatement::insert(&deleted, writer.clone())],
    )
    .await
    .unwrap();
    let repository = PgRoleRepository::new(pool.clone());
    let unknown = role(&mut rng, "Unknown", RoleKind::Custom);
    deleted
        .delete(Some(version(2)), 0, stamp(&writer, &deleted))
        .unwrap();
    save(
        &pool,
        &mut rng,
        vec![RoleStatement::update(&deleted, version(2), writer)],
    )
    .await
    .unwrap();

    assert_eq!(
        repository.find_grants(deleted.parts().id).await.unwrap(),
        Vec::<RoleGrant>::new()
    );
    assert_eq!(
        repository.find_grants(unknown.parts().id).await.unwrap(),
        Vec::<RoleGrant>::new()
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn pages_leave_out_deleted_roles(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let writer = role_writer(&mut rng);
    let kept = role(&mut rng, "Team-kept", RoleKind::Custom);
    let mut deleted = role(&mut rng, "Team-deleted", RoleKind::Custom);
    save(
        &pool,
        &mut rng,
        vec![
            RoleStatement::insert(&kept, writer.clone()),
            RoleStatement::insert(&deleted, writer.clone()),
        ],
    )
    .await
    .unwrap();
    deleted
        .delete(Some(version(1)), 0, stamp(&writer, &deleted))
        .unwrap();
    save(
        &pool,
        &mut rng,
        vec![RoleStatement::update(&deleted, version(1), writer)],
    )
    .await
    .unwrap();

    let seen = read_all_pages(&PgRoleRepository::new(pool), 10, "team", RoleKind::Custom).await;

    assert_eq!(seen, vec![kept.parts().id]);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_length_checks_refuse_a_long_name_and_a_long_description(pool: PgPool) {
    let insert = "INSERT INTO iam_roles (id, name, description, kind, grant_count, version, \
        created_at, updated_at) VALUES (gen_random_uuid(), $1, $2, 'custom', 0, 1, now(), now())";
    let long_name = sqlx::query(insert)
        .bind("x".repeat(101))
        .bind(None::<String>)
        .execute(&pool)
        .await
        .unwrap_err();
    let long_description = sqlx::query(insert)
        .bind("Billing")
        .bind(Some("x".repeat(1_001)))
        .execute(&pool)
        .await
        .unwrap_err();
    let empty_name = sqlx::query(insert)
        .bind("")
        .bind(None::<String>)
        .execute(&pool)
        .await
        .unwrap_err();

    for error in [long_name, long_description, empty_name] {
        assert!(
            error
                .as_database_error()
                .is_some_and(sqlx::error::DatabaseError::is_check_violation)
        );
    }
    sqlx::query(insert)
        .bind("x".repeat(100))
        .bind(Some("x".repeat(1_000)))
        .execute(&pool)
        .await
        .unwrap();
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_down_migration_removes_both_tables(pool: PgPool) {
    let newer =
        include_str!("../../../../../../migrations/20261122205127_create_iam_user_roles.down.sql");
    let down = include_str!(
        "../../../../../../migrations/20261122192547_create_iam_roles_and_permissions.down.sql"
    );
    sqlx::raw_sql(newer).execute(&pool).await.unwrap();

    sqlx::raw_sql(down).execute(&pool).await.unwrap();

    let exists: bool = sqlx::query_scalar(
        "SELECT to_regclass('iam_roles') IS NOT NULL OR to_regclass('iam_role_permissions') IS NOT NULL",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!exists);
}
