//! `service iam-bootstrap` as a process against PostgreSQL: the system role, the global assignment,
//! the audit record, the refusal of a second run, the concurrent runs and the exit statuses.

use std::process::Output;

use iam_domain::PlatformAdministrator;
use sqlx::PgPool;

use crate::support::{Scratch, database_url, stack_with, stderr, stdout};

const USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";
const OTHER_USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ac";

/// The text values of the variables of the service that bootstraps against `url`.
fn variables(url: &str) -> Vec<(&'static str, String)> {
    stack_with(url)
}

fn pairs<'a>(owned: &'a [(&'static str, String)]) -> Vec<(&'static str, &'a str)> {
    owned
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect()
}

/// Runs `iam-bootstrap` with `arguments` against the database of `pool`.
async fn bootstrap(pool: &PgPool, arguments: &[&str]) -> Output {
    let url = database_url(pool).await;
    let owned = variables(&url);
    let scratch = Scratch::new();
    let mut command: Vec<&str> = vec!["iam-bootstrap"];
    command.extend_from_slice(arguments);
    scratch.run(&command, &pairs(&owned))
}

async fn number(pool: &PgPool, statement: &'static str) -> i64 {
    sqlx::query_scalar(statement).fetch_one(pool).await.unwrap()
}

const IAM_HOST: &str = "iam.example.test";

const UPSTREAMS: &str =
    "SELECT count(*) FROM iam_upstreams WHERE name = 'iam-control' AND deleted_at IS NULL";

const ROUTES: &str =
    "SELECT count(*) FROM iam_routes WHERE host = 'iam.example.test' AND deleted_at IS NULL";

const ADMINISTRATORS: &str = "SELECT count(*) FROM iam_user_roles a JOIN iam_roles r ON r.id = a.role_id \
     WHERE r.name = 'iam-platform-admin' AND a.scope_kind = 'global' AND a.revoked_at IS NULL";

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn an_empty_database_gets_the_registered_specifications_the_system_role_and_the_assignment(
    pool: PgPool,
) {
    let output = bootstrap(&pool, &["--admin-user", USER]).await;

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(
        stdout(&output),
        format!("bootstrapped user:{USER}\nno IAM routes seeded: --iam-host is absent\n")
    );
    assert!(
        number(
            &pool,
            "SELECT count(*) FROM iam_rest_permissions WHERE service = 'iam' AND active"
        )
        .await
            > 0
    );
    assert!(
        number(
            &pool,
            "SELECT count(*) FROM iam_graphql_permissions WHERE service = 'iam' AND active"
        )
        .await
            > 0
    );
    let (kind, grants): (String, i32) =
        sqlx::query_as("SELECT kind, grant_count FROM iam_roles WHERE name = 'iam-platform-admin'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(kind, "system");
    assert_eq!(
        usize::try_from(grants).unwrap(),
        PlatformAdministrator::GRANTS.len()
    );
    let mut keys: Vec<String> = sqlx::query_scalar(
        "SELECT p.permission_key FROM iam_role_permissions p JOIN iam_roles r ON r.id = p.role_id \
         WHERE r.name = 'iam-platform-admin' ORDER BY 1",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let mut expected: Vec<String> = PlatformAdministrator::GRANTS
        .iter()
        .map(|grant| (*grant).to_owned())
        .collect();
    keys.sort();
    expected.sort();
    assert_eq!(keys, expected);
    let (subject_kind, subject_id): (String, String) = sqlx::query_as(
        "SELECT subject_kind, subject_id FROM iam_user_roles WHERE revoked_at IS NULL",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((subject_kind.as_str(), subject_id.as_str()), ("user", USER));
    assert_eq!(number(&pool, ADMINISTRATORS).await, 1);
    let audits = number(
        &pool,
        "SELECT count(*) FROM iam_security_audit_events \
         WHERE actor = 'system:bootstrap' AND outcome = 'committed' AND action = 'iam.bootstrap'",
    )
    .await;
    assert_eq!(audits, 1);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_service_principal_becomes_the_administrator_with_admin_service(pool: PgPool) {
    let output = bootstrap(&pool, &["--admin-service", "schemathesis"]).await;

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(
        stdout(&output),
        "bootstrapped service:schemathesis\nno IAM routes seeded: --iam-host is absent\n"
    );
    let (subject_kind, subject_id): (String, String) = sqlx::query_as(
        "SELECT subject_kind, subject_id FROM iam_user_roles WHERE revoked_at IS NULL",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        (subject_kind.as_str(), subject_id.as_str()),
        ("service", "schemathesis")
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_second_run_exits_1_and_changes_nothing(pool: PgPool) {
    let first = bootstrap(&pool, &["--admin-user", USER]).await;
    let before = (
        number(&pool, "SELECT count(*) FROM iam_user_roles").await,
        number(&pool, "SELECT count(*) FROM iam_roles").await,
        number(&pool, "SELECT count(*) FROM iam_security_audit_events").await,
        number(&pool, "SELECT count(*) FROM iam_outbox").await,
        number(&pool, "SELECT version FROM iam_policy_epoch").await,
    );

    let second = bootstrap(&pool, &["--admin-user", OTHER_USER]).await;

    assert_eq!(first.status.code(), Some(0), "{}", stderr(&first));
    assert_eq!(second.status.code(), Some(1), "{}", stderr(&second));
    assert!(
        stderr(&second).starts_with("error: an active assignment of iam-platform-admin exists"),
        "{}",
        stderr(&second)
    );
    let after = (
        number(&pool, "SELECT count(*) FROM iam_user_roles").await,
        number(&pool, "SELECT count(*) FROM iam_roles").await,
        number(&pool, "SELECT count(*) FROM iam_security_audit_events").await,
        number(&pool, "SELECT count(*) FROM iam_outbox").await,
        number(&pool, "SELECT version FROM iam_policy_epoch").await,
    );
    assert_eq!(after, before);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn two_concurrent_runs_on_an_empty_database_create_one_administrator(pool: PgPool) {
    let url = database_url(&pool).await;
    let owned = variables(&url);
    let scratches = [Scratch::new(), Scratch::new()];
    let subjects = [USER, OTHER_USER];
    let mut children: Vec<std::process::Child> = scratches
        .iter()
        .zip(subjects)
        .map(|(scratch, subject)| {
            scratch
                .service(&["iam-bootstrap", "--admin-user", subject], &pairs(&owned))
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap()
        })
        .collect();

    let mut statuses: Vec<Option<i32>> = children
        .iter_mut()
        .map(|child| child.wait().unwrap().code())
        .collect();

    statuses.sort();
    assert_eq!(statuses, [Some(0), Some(1)]);
    assert_eq!(number(&pool, ADMINISTRATORS).await, 1);
    assert_eq!(
        number(
            &pool,
            "SELECT count(*) FROM iam_roles WHERE name = 'iam-platform-admin'"
        )
        .await,
        1
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn an_invalid_subject_or_configuration_exits_2_with_a_message_and_changes_nothing(
    pool: PgPool,
) {
    let invalid_uuid = bootstrap(&pool, &["--admin-user", "not-a-uuid"]).await;
    let both = bootstrap(
        &pool,
        &["--admin-user", USER, "--admin-service", "schemathesis"],
    )
    .await;
    let neither = bootstrap(&pool, &[]).await;
    let scratch = Scratch::new();
    let no_database = scratch.run(&["iam-bootstrap", "--admin-user", USER], &[]);

    for output in [&invalid_uuid, &both, &neither, &no_database] {
        assert_eq!(output.status.code(), Some(2), "{}", stderr(output));
        assert_eq!(stdout(output), "");
        assert_ne!(stderr(output), "");
    }
    assert!(stderr(&invalid_uuid).contains("--admin-user"));
    assert!(stderr(&both).contains("cannot be used together"));
    assert!(stderr(&neither).contains("is required"));
    assert!(stderr(&no_database).contains("DATABASE_URL"));
    assert_eq!(number(&pool, "SELECT count(*) FROM iam_roles").await, 0);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_run_that_follows_the_last_administrator_ending_creates_the_role_again(pool: PgPool) {
    let first = bootstrap(&pool, &["--admin-user", USER]).await;
    sqlx::query("UPDATE iam_user_roles SET revoked_at = now() WHERE revoked_at IS NULL")
        .execute(&pool)
        .await
        .unwrap();

    let again = bootstrap(&pool, &["--admin-user", OTHER_USER]).await;

    assert_eq!(first.status.code(), Some(0), "{}", stderr(&first));
    assert_eq!(again.status.code(), Some(0), "{}", stderr(&again));
    assert_eq!(number(&pool, ADMINISTRATORS).await, 1);
    assert_eq!(
        number(
            &pool,
            "SELECT count(*) FROM iam_roles WHERE name = 'iam-platform-admin'"
        )
        .await,
        1
    );
}

/// The seeded entries: the paths of the routes with their body limits and the graphql flag.
async fn seeded_routes(pool: &PgPool) -> Vec<(String, i64, bool)> {
    sqlx::query_as(
        "SELECT path_pattern, body_limit, graphql FROM iam_routes \
         WHERE host = 'iam.example.test' AND deleted_at IS NULL ORDER BY path_pattern",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// The rows of the entries that a seed changes, to compare before and after a run.
async fn seeded_rows(pool: &PgPool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT id::text || ':' || version::text FROM iam_upstreams \
         UNION ALL SELECT id::text || ':' || version::text FROM iam_routes ORDER BY 1",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn an_iam_host_seeds_the_system_upstream_and_routes_with_their_state_records_and_audit(
    pool: PgPool,
) {
    let output = bootstrap(&pool, &["--admin-user", USER, "--iam-host", IAM_HOST]).await;

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(
        stdout(&output),
        format!("bootstrapped user:{USER}\nseeded the IAM upstream and routes of {IAM_HOST}\n")
    );
    assert_eq!(number(&pool, UPSTREAMS).await, 1);
    let (namespace, service_name, catalog, port, protocol, forward, system): (
        String,
        String,
        String,
        i32,
        String,
        bool,
        bool,
    ) = sqlx::query_as(
        "SELECT namespace, service_name, catalog_service, port, protocol, forward_credentials, \
         system FROM iam_upstreams WHERE name = 'iam-control'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        (namespace.as_str(), service_name.as_str(), catalog.as_str()),
        ("iam", "iam-control", "iam")
    );
    assert_eq!(
        (port, protocol.as_str(), forward, system),
        (80, "http1", true, true)
    );
    let six_mebibytes = 6 * 1024 * 1024;
    assert_eq!(
        seeded_routes(&pool).await,
        [
            ("/api/graphql".to_owned(), six_mebibytes, true),
            ("/api/graphql-specs".to_owned(), six_mebibytes, false),
            ("/api/openapi-specs".to_owned(), six_mebibytes, false),
            ("/api/{rest:*}".to_owned(), 1_048_576, false),
        ]
    );
    let flagged: i64 = number(
        &pool,
        "SELECT count(*) FROM iam_routes WHERE system AND service = 'iam' AND enforcement = 'enforce'",
    )
    .await;
    assert_eq!(flagged, 4);
    let states = number(
        &pool,
        "SELECT count(*) FROM iam_outbox WHERE kind = 'state' AND payload IS NOT NULL \
         AND (record_key = 'upstream/iam-control' OR record_key LIKE 'route/%')",
    )
    .await;
    assert_eq!(states, 5);
    let audits = number(
        &pool,
        "SELECT count(*) FROM iam_security_audit_events WHERE actor = 'system:bootstrap' \
         AND outcome = 'committed' AND action IN ('upstream.create', 'route.create')",
    )
    .await;
    assert_eq!(audits, 5);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_rerun_after_the_last_administrator_was_lost_leaves_the_seeded_entries_unchanged(
    pool: PgPool,
) {
    let first = bootstrap(&pool, &["--admin-user", USER, "--iam-host", IAM_HOST]).await;
    let before = seeded_rows(&pool).await;
    sqlx::query("UPDATE iam_user_roles SET revoked_at = now() WHERE revoked_at IS NULL")
        .execute(&pool)
        .await
        .unwrap();

    let again = bootstrap(&pool, &["--admin-user", OTHER_USER, "--iam-host", IAM_HOST]).await;

    assert_eq!(first.status.code(), Some(0), "{}", stderr(&first));
    assert_eq!(again.status.code(), Some(0), "{}", stderr(&again));
    assert_eq!(number(&pool, UPSTREAMS).await, 1);
    assert_eq!(number(&pool, ROUTES).await, 4);
    assert_eq!(seeded_rows(&pool).await, before);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn two_concurrent_runs_with_an_iam_host_seed_one_upstream_and_one_route_set(pool: PgPool) {
    let url = database_url(&pool).await;
    let owned = variables(&url);
    let scratches = [Scratch::new(), Scratch::new()];
    let subjects = [USER, OTHER_USER];
    let mut children: Vec<std::process::Child> = scratches
        .iter()
        .zip(subjects)
        .map(|(scratch, subject)| {
            scratch
                .service(
                    &[
                        "iam-bootstrap",
                        "--admin-user",
                        subject,
                        "--iam-host",
                        IAM_HOST,
                    ],
                    &pairs(&owned),
                )
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap()
        })
        .collect();

    let mut statuses: Vec<Option<i32>> = children
        .iter_mut()
        .map(|child| child.wait().unwrap().code())
        .collect();

    statuses.sort();
    assert_eq!(statuses, [Some(0), Some(1)]);
    assert_eq!(number(&pool, UPSTREAMS).await, 1);
    assert_eq!(number(&pool, ROUTES).await, 4);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn an_invalid_iam_host_exits_2_and_changes_nothing(pool: PgPool) {
    let invalid = bootstrap(&pool, &["--admin-user", USER, "--iam-host", "Not A Host"]).await;

    assert_eq!(invalid.status.code(), Some(2), "{}", stderr(&invalid));
    assert_eq!(stdout(&invalid), "");
    assert!(
        stderr(&invalid).contains("--iam-host"),
        "{}",
        stderr(&invalid)
    );
    assert_eq!(number(&pool, "SELECT count(*) FROM iam_roles").await, 0);
    assert_eq!(number(&pool, "SELECT count(*) FROM iam_upstreams").await, 0);
    assert_eq!(number(&pool, "SELECT count(*) FROM iam_routes").await, 0);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn without_an_iam_host_the_administrator_is_created_and_no_route_is_seeded(pool: PgPool) {
    let output = bootstrap(&pool, &["--admin-user", USER]).await;

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(
        stdout(&output).contains("no IAM routes seeded"),
        "{}",
        stdout(&output)
    );
    assert_eq!(number(&pool, ADMINISTRATORS).await, 1);
    assert_eq!(number(&pool, "SELECT count(*) FROM iam_upstreams").await, 0);
    assert_eq!(number(&pool, "SELECT count(*) FROM iam_routes").await, 0);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn repair_restores_a_deleted_seeded_route_and_audits_it_as_the_bootstrap(pool: PgPool) {
    let first = bootstrap(&pool, &["--admin-user", USER, "--iam-host", IAM_HOST]).await;
    sqlx::query("DELETE FROM iam_routes WHERE path_pattern = '/api/graphql'")
        .execute(&pool)
        .await
        .unwrap();
    let versions = number(&pool, "SELECT version FROM iam_policy_epoch").await;

    let repair = bootstrap(&pool, &["--repair-routes", "--iam-host", IAM_HOST]).await;

    assert_eq!(first.status.code(), Some(0), "{}", stderr(&first));
    assert_eq!(repair.status.code(), Some(0), "{}", stderr(&repair));
    assert_eq!(
        stdout(&repair),
        format!("repaired the IAM upstream and routes of {IAM_HOST}\n")
    );
    assert_eq!(number(&pool, UPSTREAMS).await, 1);
    assert_eq!(number(&pool, ROUTES).await, 4);
    let restored: (bool, bool) = sqlx::query_as(
        "SELECT graphql, system FROM iam_routes WHERE path_pattern = '/api/graphql'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(restored, (true, true));
    assert!(number(&pool, "SELECT version FROM iam_policy_epoch").await > versions);
    let audits = number(
        &pool,
        "SELECT count(*) FROM iam_security_audit_events WHERE actor = 'system:bootstrap' \
         AND action = 'route.create'",
    )
    .await;
    assert_eq!(audits, 5);
    assert_eq!(number(&pool, ADMINISTRATORS).await, 1);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn repair_works_without_an_administrator_and_restores_a_changed_route(pool: PgPool) {
    let first = bootstrap(&pool, &["--admin-user", USER, "--iam-host", IAM_HOST]).await;
    sqlx::query("UPDATE iam_user_roles SET revoked_at = now() WHERE revoked_at IS NULL")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE iam_routes SET body_limit = 1000 WHERE path_pattern = '/api/openapi-specs'",
    )
    .execute(&pool)
    .await
    .unwrap();

    let repair = bootstrap(&pool, &["--repair-routes", "--iam-host", IAM_HOST]).await;

    assert_eq!(first.status.code(), Some(0), "{}", stderr(&first));
    assert_eq!(repair.status.code(), Some(0), "{}", stderr(&repair));
    assert_eq!(number(&pool, ADMINISTRATORS).await, 0);
    let limit = number(
        &pool,
        "SELECT body_limit FROM iam_routes WHERE path_pattern = '/api/openapi-specs'",
    )
    .await;
    assert_eq!(limit, 6 * 1024 * 1024);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn repair_without_an_iam_host_exits_2(pool: PgPool) {
    let repair = bootstrap(&pool, &["--repair-routes"]).await;

    assert_eq!(repair.status.code(), Some(2), "{}", stderr(&repair));
    assert_eq!(stdout(&repair), "");
    assert!(
        stderr(&repair).contains("--iam-host"),
        "{}",
        stderr(&repair)
    );
    assert_eq!(number(&pool, "SELECT count(*) FROM iam_routes").await, 0);
}
