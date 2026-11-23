//! The startup registration of IAM's own specifications against PostgreSQL: the catalogue, the
//! idempotence, the concurrent starts, the rolling deployments and the stop of the per-replica
//! tasks.

use std::time::Duration;

use clap::Parser as _;
use iam_application::RegisterOwnSpecsCommand;
use serde_json::Value;
use service::bootstrap::{
    Adapters, TaskMode, TaskStop, register_iam_documents, register_iam_specs, start_tasks,
};
use service::cli::{Cli, Command};
use service::config::Config;
use service::graphql::schema::iam_sdl;
use service::openapi::iam_document;
use sqlx::PgPool;
use test_support::seed::TestRng;
use test_support::unit_of_work::uuid_v7;
use tokio::sync::watch;

use crate::support::database_url;

const REST_KEY: &str = "rest:iam:POST /api/roles";
const REMOVED_KEY: &str = "rest:iam:GET /api/roles/{}";
const GRAPHQL_KEY: &str = "gql:iam:Mutation.createRole";
const REMOVED_PATH: &str = "/api/roles/{id}";

fn config(database_url: String) -> Config {
    let Command::Serve(args) = Cli::parse_from(["service", "serve"]).command else {
        panic!("`serve` arguments expected");
    };
    let mut config = Config::from_args(args).unwrap();
    config.database.url = database_url;
    config.database.acquire_timeout = Duration::from_secs(30);
    config
}

/// A new instance on the database of `pool`: its own pool and its own lock connection.
async fn instance(pool: &PgPool) -> Adapters {
    Adapters::connect(&config(database_url(pool).await))
        .await
        .unwrap()
}

/// The contract of a build that no longer has the operation at [`REMOVED_PATH`].
fn contract_without_an_operation() -> RegisterOwnSpecsCommand {
    let mut document: Value = serde_json::from_str(&iam_document().unwrap()).unwrap();
    document["paths"]
        .as_object_mut()
        .unwrap()
        .remove(REMOVED_PATH)
        .unwrap();
    RegisterOwnSpecsCommand {
        openapi_document: document.to_string(),
        graphql_sdl: iam_sdl(),
    }
}

fn current_contract() -> RegisterOwnSpecsCommand {
    RegisterOwnSpecsCommand {
        openapi_document: iam_document().unwrap(),
        graphql_sdl: iam_sdl(),
    }
}

async fn count(pool: &PgPool, statement: &'static str) -> i64 {
    sqlx::query_scalar(statement).fetch_one(pool).await.unwrap()
}

async fn key_is_active(pool: &PgPool, table_statement: &'static str, key: &str) -> bool {
    sqlx::query_scalar::<_, bool>(table_statement)
        .bind(key)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// What the registration wrote, to compare before and after a repeated start.
async fn written(pool: &PgPool) -> (i64, i64, i64, i64) {
    (
        count(pool, "SELECT count(*) FROM iam_openapi_specs").await,
        count(pool, "SELECT count(*) FROM iam_graphql_specs").await,
        count(pool, "SELECT count(*) FROM iam_outbox").await,
        count(pool, "SELECT count(*) FROM iam_security_audit_events").await,
    )
}

/// Gives a custom role an active grant of `key`.
async fn grant(pool: &PgPool, key: &str) {
    let role = uuid_v7(&mut TestRng::from_env());
    sqlx::query(
        "INSERT INTO iam_roles (id, name, kind, grant_count, version, created_at, updated_at)
        VALUES ($1, 'grantee', 'custom', 1, 1, now(), now())",
    )
    .bind(role.as_uuid())
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO iam_role_permissions
            (role_id, permission_key, key_kind, service, is_wildcard, active, granted_by, granted_at)
        VALUES ($1, $2, 'rest', 'iam', false, true, 'system:startup', now())",
    )
    .bind(role.as_uuid())
    .bind(key)
    .execute(pool)
    .await
    .unwrap();
}

async fn inactive_grants(pool: &PgPool) -> i64 {
    count(
        pool,
        "SELECT count(*) FROM iam_role_permissions WHERE service = 'iam' AND NOT active",
    )
    .await
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_fresh_database_gets_the_iam_catalogue_and_active_versions(pool: PgPool) {
    let adapters = instance(&pool).await;

    register_iam_specs(&adapters).await.unwrap();

    assert!(
        key_is_active(
            &pool,
            "SELECT EXISTS (SELECT 1 FROM iam_rest_permissions WHERE permission_key = $1 AND active)",
            REST_KEY
        )
        .await
    );
    assert!(
        key_is_active(
            &pool,
            "SELECT EXISTS (SELECT 1 FROM iam_graphql_permissions WHERE permission_key = $1 AND active)",
            GRAPHQL_KEY
        )
        .await
    );
    let rest = "SELECT count(*) FROM iam_openapi_specs WHERE service = 'iam' AND status = 'active'";
    let graphql =
        "SELECT count(*) FROM iam_graphql_specs WHERE service = 'iam' AND status = 'active'";
    assert_eq!(count(&pool, rest).await, 1);
    assert_eq!(count(&pool, graphql).await, 1);
    let actors = count(
        &pool,
        "SELECT count(*) FROM iam_security_audit_events WHERE actor <> 'system:startup'",
    )
    .await;
    assert_eq!(actors, 0);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_second_start_of_the_same_build_writes_nothing(pool: PgPool) {
    register_iam_specs(&instance(&pool).await).await.unwrap();
    let first = written(&pool).await;

    register_iam_specs(&instance(&pool).await).await.unwrap();

    assert_eq!(written(&pool).await, first);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn two_instances_that_start_together_register_once(pool: PgPool) {
    let (first, second) = (instance(&pool).await, instance(&pool).await);

    let (one, other) = tokio::join!(register_iam_specs(&first), register_iam_specs(&second));

    one.unwrap();
    other.unwrap();
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM iam_security_audit_events WHERE action = 'openapi_spec.activate'"
        )
        .await,
        1
    );
    assert_eq!(
        count(&pool, "SELECT count(*) FROM iam_openapi_specs").await,
        1
    );
    assert_eq!(
        count(&pool, "SELECT count(*) FROM iam_graphql_specs").await,
        1
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_contract_that_removes_an_operation_is_activated_beside_the_older_version(pool: PgPool) {
    let adapters = instance(&pool).await;
    register_iam_documents(&adapters, current_contract())
        .await
        .unwrap();
    grant(&pool, REMOVED_KEY).await;

    register_iam_documents(&adapters, contract_without_an_operation())
        .await
        .unwrap();

    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM iam_openapi_specs WHERE service = 'iam' AND status = 'active'"
        )
        .await,
        2
    );
    assert_eq!(inactive_grants(&pool).await, 0);
    assert!(
        key_is_active(
            &pool,
            "SELECT EXISTS (SELECT 1 FROM iam_rest_permissions WHERE permission_key = $1 AND active)",
            REMOVED_KEY
        )
        .await
    );
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM iam_security_audit_events
            WHERE action = 'openapi_spec.activate' AND actor = 'system:startup'"
        )
        .await,
        2
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_rollback_between_two_builds_orphans_no_grant_at_any_point(pool: PgPool) {
    let adapters = instance(&pool).await;
    register_iam_documents(&adapters, current_contract())
        .await
        .unwrap();
    grant(&pool, REMOVED_KEY).await;
    let mut versions = Vec::new();

    for contract in [
        contract_without_an_operation(),
        current_contract(),
        contract_without_an_operation(),
    ] {
        register_iam_documents(&adapters, contract).await.unwrap();
        versions.push((
            inactive_grants(&pool).await,
            count(&pool, "SELECT count(*) FROM iam_openapi_specs").await,
        ));
    }

    assert_eq!(versions, [(0, 2), (0, 2), (0, 2)]);
}

#[tokio::test]
async fn a_task_in_flight_stops_within_the_grace_period_of_the_shutdown() {
    let grace = Duration::from_secs(5);
    let (stop, stopping) = watch::channel(false);
    let mut supervisor = bare_supervisor(stopping);
    supervisor.spawn("test task", async move |mut shutdown| {
        drop(shutdown.wait_for(|stopping| *stopping).await);
        tokio::time::sleep(Duration::from_millis(200)).await;
    });
    let started = tokio::time::Instant::now();

    stop.send_replace(true);
    let outcome = supervisor.stop(grace).await;

    assert_eq!(outcome, TaskStop::Drained);
    assert!(started.elapsed() < grace, "{:?}", started.elapsed());
}

fn bare_supervisor(stopping: watch::Receiver<bool>) -> service::bootstrap::TaskSupervisor {
    service::bootstrap::TaskSupervisor::new(TaskMode::Test, stopping)
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_supervisor_of_the_production_wiring_starts_without_tasks(pool: PgPool) {
    let adapters = instance(&pool).await;
    let (_stop, stopping) = watch::channel(false);

    let supervisor = start_tasks(&adapters, TaskMode::Serve, stopping);

    assert!(supervisor.is_empty());
}
