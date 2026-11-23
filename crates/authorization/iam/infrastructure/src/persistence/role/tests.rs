use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, EntityVersion, PermissionGrant, PermissionGrantSet, RepositoryError, Role,
    RoleDescription, RoleFields, RoleId, RoleKind, RoleStamp, RoleStatement,
};
use rstest::rstest;
use shared_domain::Uuid;
use sqlx::types::Uuid as SqlUuid;
use sqlx::types::time::OffsetDateTime;

use super::{
    GrantColumns, GrantRow, RoleRow, WriteRow, key_kind, restore_all, restore_grants, role_grant,
    translate, updated,
};

const ROLE: &str = "7f1c2a4e-1d0b-4f5e-9a3c-2b6d8e0f1a2b";
const OTHER: &str = "8a2d3b5f-2e1c-4a6f-8b4d-3c7e9f1a2b3c";
const USER: &str = "3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a";
const EVENT: &str = "01890a5d-ac96-774b-bcce-b302099a8057";

fn grant(value: &str) -> PermissionGrant {
    PermissionGrant::parse(value).unwrap()
}

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn row(id: &str, name: &str, kind: &str, version: i64) -> RoleRow {
    RoleRow {
        id: SqlUuid::parse_str(id).unwrap(),
        name: name.to_owned(),
        description: Some("Bills".to_owned()),
        kind: kind.to_owned(),
        version,
        created_at: OffsetDateTime::from(at(1_700_000_000)),
        updated_at: OffsetDateTime::from(at(1_700_000_100)),
    }
}

fn grant_row(id: &str, key: &str) -> GrantRow {
    GrantRow {
        role_id: SqlUuid::parse_str(id).unwrap(),
        permission_key: key.to_owned(),
    }
}

fn unavailable(result: &Result<impl std::fmt::Debug, RepositoryError>) -> bool {
    matches!(result, Err(RepositoryError::Unavailable(_)))
}

#[rstest]
#[case("rest:core:GET /users", "rest")]
#[case("rest:core:*", "rest")]
#[case("rest:core:GET *", "rest")]
#[case("gql:core:Query.users", "gql")]
#[case("gql:core:*", "gql")]
#[case("gql:core:Query.*", "gql")]
fn every_grant_has_its_stored_key_kind(#[case] value: &str, #[case] kind: &str) {
    assert_eq!(key_kind(&grant(value)), kind);
}

#[test]
fn a_reserved_key_is_stored_with_the_iam_kind() {
    assert_eq!(key_kind(&grant("iam:grant:sensitive")), "iam");
}

#[test]
fn the_grant_columns_follow_the_order_of_the_grant_set() {
    let grants =
        PermissionGrantSet::new([grant("rest:core:GET /users"), grant("gql:billing:*")]).unwrap();

    let columns = GrantColumns::of(&grants);

    let order: Vec<String> = grants.iter().map(ToString::to_string).collect();
    assert_eq!(order, ["rest:core:GET /users", "gql:billing:*"]);
    assert_eq!(columns.keys, order);
    assert_eq!(columns.kinds, ["rest", "gql"]);
    assert_eq!(columns.services, ["core", "billing"]);
    assert_eq!(columns.wildcards, [false, true]);
}

#[test]
fn a_write_row_holds_the_state_of_the_role_and_the_grantor() {
    let actor = ActorRef::User(Uuid::parse(USER).unwrap());
    let role = Role::create(
        RoleId::parse(ROLE).unwrap(),
        RoleFields::new("Billing".to_owned(), Some("Bills".to_owned())).unwrap(),
        RoleStamp {
            event_id: Uuid::parse(EVENT).unwrap(),
            actor: actor.clone(),
            occurred_at: at(1_700_000_000),
        },
    );

    let row = WriteRow::of(&RoleStatement::insert(&role, actor.clone()));

    assert_eq!(row.id, SqlUuid::parse_str(ROLE).unwrap());
    assert_eq!(row.name, "Billing");
    assert_eq!(row.description.as_deref(), Some("Bills"));
    assert_eq!(row.kind, "custom");
    assert_eq!(row.grant_count, 0);
    assert_eq!(row.version, 1);
    assert_eq!(row.created_at, OffsetDateTime::from(at(1_700_000_000)));
    assert_eq!(row.updated_at, row.created_at);
    assert_eq!(row.deleted_at, None);
    assert_eq!(row.granted_by, actor.to_string());
    assert_eq!(row.grants.keys, Vec::<String>::new());
    assert_eq!(row.grants.kinds, Vec::<String>::new());
    assert_eq!(row.grants.services, Vec::<String>::new());
    assert_eq!(row.grants.wildcards, Vec::<bool>::new());
}

#[test]
fn an_update_that_changes_no_row_is_a_conflict() {
    assert!(matches!(updated(0), Err(RepositoryError::Conflict)));
    assert!(updated(1).is_ok());
}

/// A database error that reports a unique violation, as PostgreSQL does for a taken name.
#[derive(Debug)]
struct UniqueViolation;

impl std::fmt::Display for UniqueViolation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("duplicate key value violates unique constraint")
    }
}

impl std::error::Error for UniqueViolation {}

impl sqlx::error::DatabaseError for UniqueViolation {
    fn message(&self) -> &'static str {
        "duplicate key value violates unique constraint"
    }

    fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
        self
    }

    fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
        self
    }

    fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
        self
    }

    fn kind(&self) -> sqlx::error::ErrorKind {
        sqlx::error::ErrorKind::UniqueViolation
    }
}

#[test]
fn a_unique_violation_is_a_duplicate() {
    assert!(matches!(
        translate(sqlx::Error::Database(Box::new(UniqueViolation))),
        RepositoryError::AlreadyExists
    ));
}

#[test]
fn a_missing_row_is_not_a_duplicate() {
    assert!(matches!(
        translate(sqlx::Error::RowNotFound),
        RepositoryError::Unavailable(_)
    ));
}

#[test]
fn stored_rows_are_restored_in_order_with_their_grants() {
    let roles = restore_all(
        vec![
            row(OTHER, "Support", "system", 3),
            row(ROLE, "Billing", "custom", 1),
        ],
        vec![
            grant_row(ROLE, "rest:core:GET /users"),
            grant_row(OTHER, "gql:core:*"),
            grant_row(ROLE, "gql:billing:Query.*"),
        ],
    )
    .unwrap();

    let parts: Vec<_> = roles.iter().map(Role::parts).collect();
    let [support, billing] = parts.as_slice() else {
        panic!("expected two roles, got {}", parts.len());
    };
    assert_eq!(support.id, RoleId::parse(OTHER).unwrap());
    assert_eq!(support.kind, RoleKind::System);
    assert_eq!(support.version, EntityVersion::new(3).unwrap());
    assert_eq!(
        support.grants,
        PermissionGrantSet::new([grant("gql:core:*")]).unwrap()
    );
    assert_eq!(billing.name.as_str(), "Billing");
    assert_eq!(
        billing.description.as_ref().map(RoleDescription::as_str),
        Some("Bills")
    );
    assert_eq!(
        billing.grants,
        PermissionGrantSet::new([grant("rest:core:GET /users"), grant("gql:billing:Query.*")])
            .unwrap()
    );
    assert_eq!(billing.created_at, at(1_700_000_000));
    assert_eq!(billing.updated_at, at(1_700_000_100));
    assert_eq!(billing.deleted_at, None);
}

#[rstest]
#[case(row(ROLE, "", "custom", 1))]
#[case(row(ROLE, "Billing", "builtin", 1))]
#[case(row(ROLE, "Billing", "custom", 0))]
fn a_stored_role_that_breaks_an_invariant_is_unavailable(#[case] stored: RoleRow) {
    assert!(unavailable(&restore_all(vec![stored], Vec::new())));
}

#[test]
fn a_stored_description_that_is_too_long_is_unavailable() {
    let mut stored = row(ROLE, "Billing", "custom", 1);
    stored.description = Some("x".repeat(1_001));

    assert!(unavailable(&restore_all(vec![stored], Vec::new())));
}

#[test]
fn a_stored_key_that_is_not_a_grant_is_unavailable() {
    assert!(unavailable(&restore_grants(&["not a key".to_owned()])));
    assert_eq!(
        restore_grants(&["rest:core:*".to_owned()]).unwrap(),
        PermissionGrantSet::new([grant("rest:core:*")]).unwrap()
    );
}

#[rstest]
#[case("rest:core:GET /items", true)]
#[case("gql:core:Query.*", false)]
fn a_stored_grant_keeps_its_key_and_its_active_flag(#[case] key: &str, #[case] active: bool) {
    let stored = role_grant(key, active).unwrap();

    assert_eq!(stored.grant, grant(key));
    assert_eq!(stored.active, active);
}

#[test]
fn a_stored_grant_key_that_is_not_a_grant_is_unavailable() {
    assert!(unavailable(&role_grant("not a key", true)));
}
