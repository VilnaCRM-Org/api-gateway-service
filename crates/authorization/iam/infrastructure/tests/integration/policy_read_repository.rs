//! `PgPolicyReadRepository`: the subject's assignments, the compiled role sets (active grants
//! only), the active REST templates and GraphQL type graphs of a service and the policy epoch,
//! each group read in one `REPEATABLE READ READ ONLY` snapshot.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    AssignmentScope, GqlName, GraphQlCoordinate, HttpMethod, PathTemplate, PermissionFlags,
    PermissionKey, PolicyEpochRepository as _, PolicyReadRepository as _, RepositoryError, RoleId,
    ServiceName, SubjectRef,
};
use iam_infrastructure::{PgPolicyEpochRepository, PgPolicyReadRepository, PolicyReadHook};
use shared_infrastructure::persistence::{PostgresSettings, connect_lazy};
use sqlx::PgPool;
use sqlx::types::time::OffsetDateTime;
use test_support::seed::TestRng;
use test_support::unit_of_work::uuid_v7;

/// URL that nothing listens on: the "unreachable database" case. No container is stopped.
const DEAD_DATABASE_URL: &str = "postgres://app:unused@127.0.0.1:1/app";
const SUBJECT: &str = "3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a";
const PROJECT: &str = "01890a5d-ac96-774b-bcce-b302099a8057";
const GET_ORDERS: &str = "rest:orders:GET /api/orders";
const GONE: &str = "rest:orders:GET /api/gone";

fn subject() -> SubjectRef {
    SubjectRef::new(iam_domain::SubjectKind::User, SUBJECT).unwrap()
}

fn orders() -> ServiceName {
    ServiceName::new("orders").unwrap()
}

fn key(value: &str) -> PermissionKey {
    PermissionKey::parse(value).unwrap()
}

/// Inserts a role whose grants are `(key, active)` pairs.
async fn seed_role(pool: &PgPool, rng: &mut TestRng, grants: &[(&str, bool)]) -> RoleId {
    let role = RoleId::from_uuid(uuid_v7(rng));
    sqlx::query(
        "INSERT INTO iam_roles (id, name, kind, grant_count, version, created_at, updated_at)
        VALUES ($1, $2, 'custom', $3, 1, now(), now())",
    )
    .bind(role.as_uuid().as_uuid())
    .bind(format!("role-{role}"))
    .bind(i32::try_from(grants.len()).unwrap())
    .execute(pool)
    .await
    .unwrap();
    for (grant, active) in grants {
        sqlx::query(
            "INSERT INTO iam_role_permissions (role_id, permission_key, key_kind, service,
                is_wildcard, active, orphaned_at, granted_by, granted_at)
            VALUES ($1, $2, 'rest', 'orders', FALSE, $3,
                CASE WHEN $3 THEN NULL ELSE now() END, 'system:test', now())",
        )
        .bind(role.as_uuid().as_uuid())
        .bind(*grant)
        .bind(*active)
        .execute(pool)
        .await
        .unwrap();
    }
    role
}

/// Assigns `role` to the subject; `project` makes it a project assignment and `expires_at` gives
/// it an expiry.
async fn assign(
    pool: &PgPool,
    rng: &mut TestRng,
    role: RoleId,
    project: Option<&str>,
    expires_at: Option<SystemTime>,
) {
    sqlx::query(
        "INSERT INTO iam_user_roles (id, subject_kind, subject_id, role_id, scope_kind, project_id,
            expires_at, version, created_by, created_at, updated_at)
        VALUES ($1, 'user', $2, $3, $4, $5::uuid, $6, 1, 'system:test', now(), now())",
    )
    .bind(uuid_v7(rng).as_uuid())
    .bind(SUBJECT)
    .bind(role.as_uuid().as_uuid())
    .bind(if project.is_some() {
        "project"
    } else {
        "global"
    })
    .bind(project.map(|id| sqlx::types::Uuid::parse_str(id).unwrap()))
    .bind(expires_at.map(OffsetDateTime::from))
    .execute(pool)
    .await
    .unwrap();
}

/// Revokes every assignment of the subject and advances the policy version, in one commit.
async fn revoke_all_and_advance(pool: &PgPool) {
    let mut transaction = pool.begin().await.unwrap();
    sqlx::query("UPDATE iam_user_roles SET revoked_at = now() WHERE subject_id = $1")
        .bind(SUBJECT)
        .execute(&mut *transaction)
        .await
        .unwrap();
    sqlx::query("UPDATE iam_policy_epoch SET version = version + 1 WHERE id = 1")
        .execute(&mut *transaction)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
}

/// Commits a role revocation after the assignment rows of a read were read.
#[derive(Debug)]
struct RevokeAfterAssignments {
    pool: PgPool,
}

#[async_trait::async_trait]
impl PolicyReadHook for RevokeAfterAssignments {
    async fn after_assignments_read(&self) {
        revoke_all_and_advance(&self.pool).await;
    }
}

/// Stores an active `OpenAPI` version of `orders` with the operations of the constants above.
async fn seed_openapi(pool: &PgPool, rng: &mut TestRng, status: &str) {
    let spec = uuid_v7(rng).as_uuid();
    let document = format!("{{\"status\":\"{status}\",\"id\":\"{spec}\"}}");
    sqlx::query(
        "INSERT INTO iam_openapi_specs (id, service, content_hash, document, status, uploaded_by,
            created_at)
        VALUES ($1, 'orders', sha256(convert_to($2, 'UTF8')), $2, $3, 'system:test', now())",
    )
    .bind(spec)
    .bind(document)
    .bind(status)
    .execute(pool)
    .await
    .unwrap();
    for (template, sensitive) in [("/api/orders", false), ("/api/orders/{}", true)] {
        sqlx::query(
            "INSERT INTO iam_openapi_spec_operations (spec_id, method, path_template, sensitive,
                audit_always)
            VALUES ($1, 'GET', $2, $3, FALSE)",
        )
        .bind(spec)
        .bind(template)
        .bind(sensitive)
        .execute(pool)
        .await
        .unwrap();
    }
}

/// Stores a GraphQL version of `orders` with `Query.order` returning `Order`, which `Node`
/// implements.
async fn seed_graphql(pool: &PgPool, rng: &mut TestRng, status: &str) {
    let spec = uuid_v7(rng).as_uuid();
    let sdl = format!("type Query {{ order: Order }} # {status} {spec}");
    sqlx::query(
        "INSERT INTO iam_graphql_specs (id, service, content_hash, sdl, status, uploaded_by,
            created_at)
        VALUES ($1, 'orders', sha256(convert_to($2, 'UTF8')), $2, $3, 'system:test', now())",
    )
    .bind(spec)
    .bind(sdl)
    .bind(status)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO iam_graphql_spec_fields (spec_id, type_name, field_name, return_type,
            sensitive, audit_always)
        VALUES ($1, 'Query', 'order', 'Order', TRUE, FALSE)",
    )
    .bind(spec)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO iam_graphql_spec_possible_types (spec_id, abstract_type, possible_type)
        VALUES ($1, 'Node', 'Order')",
    )
    .bind(spec)
    .execute(pool)
    .await
    .unwrap();
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn assignments_carry_their_expiry_and_orphaned_grants_are_not_compiled(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let role = seed_role(&pool, &mut rng, &[(GET_ORDERS, true), (GONE, false)]).await;
    let expired = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(1_000))
        .unwrap();
    assign(&pool, &mut rng, role, None, Some(expired)).await;
    assign(&pool, &mut rng, role, Some(PROJECT), None).await;
    let repository = PgPolicyReadRepository::new(pool.clone());

    let policy = repository.read_subject_policy(&subject()).await.unwrap();

    let expiries: Vec<_> = policy
        .assignments()
        .iter()
        .map(|assignment| (assignment.scope(), assignment.expires_at()))
        .collect();
    assert_eq!(policy.assignments().len(), 2);
    assert!(expiries.contains(&(AssignmentScope::Global, Some(expired))));
    assert!(
        expiries
            .iter()
            .any(|(scope, expires)| scope.project_id().is_some() && expires.is_none())
    );
    let set = policy.role_sets().get(&role).unwrap();
    assert!(set.holds(&key(GET_ORDERS), PermissionFlags::NONE));
    assert!(!set.holds(&key(GONE), PermissionFlags::NONE));
    assert_eq!(set.key_count(), 1);
    let epoch = PgPolicyEpochRepository::new(pool).current().await.unwrap();
    assert_eq!(policy.epoch(), epoch);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_revoked_assignment_and_a_role_without_grants_are_read_as_stored(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let empty = seed_role(&pool, &mut rng, &[]).await;
    let revoked = seed_role(&pool, &mut rng, &[(GET_ORDERS, true)]).await;
    assign(&pool, &mut rng, empty, None, None).await;
    assign(&pool, &mut rng, revoked, None, None).await;
    sqlx::query("UPDATE iam_user_roles SET revoked_at = now() WHERE role_id = $1")
        .bind(revoked.as_uuid().as_uuid())
        .execute(&pool)
        .await
        .unwrap();
    let repository = PgPolicyReadRepository::new(pool);

    let policy = repository.read_subject_policy(&subject()).await.unwrap();

    assert_eq!(policy.assignments().len(), 1);
    assert_eq!(policy.assignments()[0].role_id(), empty);
    assert!(policy.role_sets().get(&empty).unwrap().is_empty());
    assert!(!policy.role_sets().contains_key(&revoked));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_subject_without_assignments_reads_the_current_epoch_alone(pool: PgPool) {
    let repository = PgPolicyReadRepository::new(pool.clone());

    let policy = repository.read_subject_policy(&subject()).await.unwrap();

    assert_eq!(policy.assignments(), []);
    assert!(policy.role_sets().is_empty());
    assert_eq!(policy.policy_version().value(), 0);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_revocation_committed_after_the_assignments_were_read_stays_invisible(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let role = seed_role(&pool, &mut rng, &[(GET_ORDERS, true)]).await;
    assign(&pool, &mut rng, role, None, None).await;
    let hook = Arc::new(RevokeAfterAssignments { pool: pool.clone() });
    let repository = PgPolicyReadRepository::new(pool.clone()).with_hook(hook);

    let during = repository.read_subject_policy(&subject()).await.unwrap();

    assert_eq!(during.policy_version().value(), 0);
    assert_eq!(during.assignments().len(), 1);
    assert!(during.role_sets().contains_key(&role));
    let after = PgPolicyReadRepository::new(pool)
        .read_subject_policy(&subject())
        .await
        .unwrap();
    assert_eq!(after.policy_version().value(), 1);
    assert_eq!(after.assignments(), []);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_write_committed_before_the_read_shows_data_and_version_together(pool: PgPool) {
    let mut rng = TestRng::from_env();
    let role = seed_role(&pool, &mut rng, &[(GET_ORDERS, true)]).await;
    assign(&pool, &mut rng, role, None, None).await;
    revoke_all_and_advance(&pool).await;
    let repository = PgPolicyReadRepository::new(pool);

    let policy = repository.read_subject_policy(&subject()).await.unwrap();

    assert_eq!(policy.policy_version().value(), 1);
    assert_eq!(policy.assignments(), []);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_missing_epoch_row_is_not_found(pool: PgPool) {
    sqlx::query("DELETE FROM iam_policy_epoch")
        .execute(&pool)
        .await
        .unwrap();
    let repository = PgPolicyReadRepository::new(pool);

    let error = repository
        .read_subject_policy(&subject())
        .await
        .unwrap_err();

    assert!(matches!(error, RepositoryError::NotFound));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_service_without_an_active_version_has_no_catalogue(pool: PgPool) {
    let mut rng = TestRng::from_env();
    seed_openapi(&pool, &mut rng, "draft").await;
    seed_graphql(&pool, &mut rng, "retired").await;
    let repository = PgPolicyReadRepository::new(pool);

    let found = repository.read_service_catalog(&orders()).await.unwrap();

    assert!(found.is_none());
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_catalogue_holds_the_active_templates_and_type_graphs_with_the_epoch(pool: PgPool) {
    let mut rng = TestRng::from_env();
    seed_openapi(&pool, &mut rng, "active").await;
    seed_openapi(&pool, &mut rng, "retired").await;
    seed_graphql(&pool, &mut rng, "active").await;
    let repository = PgPolicyReadRepository::new(pool);

    let catalog = repository
        .read_service_catalog(&orders())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(catalog.service(), &orders());
    assert_eq!(catalog.policy_version().value(), 0);
    assert_eq!(catalog.rest_operations().len(), 1);
    let operations = &catalog.rest_operations()[0];
    assert_eq!(operations.len(), 2);
    let details = operations
        .get(
            HttpMethod::parse("GET").unwrap(),
            &PathTemplate::from_stored("/api/orders/{}").unwrap(),
        )
        .unwrap();
    assert!(details.flags.is_sensitive());
    assert_eq!(catalog.type_graphs().len(), 1);
    let graph = &catalog.type_graphs()[0];
    let coordinate = GraphQlCoordinate::new(
        GqlName::parse("Query").unwrap(),
        GqlName::parse("order").unwrap(),
    );
    assert!(graph.field(&coordinate).unwrap().flags.is_sensitive());
    let node = GqlName::parse("Node").unwrap();
    assert_eq!(graph.possible_types(&node).count(), 1);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_service_with_only_a_graphql_version_has_a_catalogue_without_templates(pool: PgPool) {
    let mut rng = TestRng::from_env();
    seed_graphql(&pool, &mut rng, "active").await;
    let repository = PgPolicyReadRepository::new(pool);

    let catalog = repository
        .read_service_catalog(&orders())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(catalog.rest_operations(), []);
    assert_eq!(catalog.type_graphs().len(), 1);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_catalogue_of_another_service_is_not_mixed_in(pool: PgPool) {
    let mut rng = TestRng::from_env();
    seed_openapi(&pool, &mut rng, "active").await;
    let repository = PgPolicyReadRepository::new(pool);

    let found = repository
        .read_service_catalog(&ServiceName::new("billing").unwrap())
        .await
        .unwrap();

    assert!(found.is_none());
}

#[tokio::test]
async fn an_unreachable_database_is_unavailable_for_both_reads() {
    let pool = connect_lazy(&PostgresSettings {
        url: DEAD_DATABASE_URL.to_owned(),
        max_connections: 1,
        acquire_timeout: Duration::from_millis(500),
        statement_timeout: Duration::from_secs(1),
    })
    .unwrap();
    let repository = PgPolicyReadRepository::new(pool);

    let policy = repository
        .read_subject_policy(&subject())
        .await
        .unwrap_err();
    let catalog = repository
        .read_service_catalog(&orders())
        .await
        .unwrap_err();

    assert!(matches!(policy, RepositoryError::Unavailable(_)));
    assert!(matches!(catalog, RepositoryError::Unavailable(_)));
}
