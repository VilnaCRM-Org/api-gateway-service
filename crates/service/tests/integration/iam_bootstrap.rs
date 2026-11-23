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

const ADMINISTRATORS: &str = "SELECT count(*) FROM iam_user_roles a JOIN iam_roles r ON r.id = a.role_id \
     WHERE r.name = 'iam-platform-admin' AND a.scope_kind = 'global' AND a.revoked_at IS NULL";

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn an_empty_database_gets_the_registered_specifications_the_system_role_and_the_assignment(
    pool: PgPool,
) {
    let output = bootstrap(&pool, &["--admin-user", USER]).await;

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(stdout(&output), format!("bootstrapped user:{USER}\n"));
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
    assert_eq!(stdout(&output), "bootstrapped service:schemathesis\n");
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
