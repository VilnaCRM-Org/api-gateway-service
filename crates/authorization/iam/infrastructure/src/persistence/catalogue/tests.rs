use iam_domain::{KeyRename, OrphanedGrant, PermissionKey, RepositoryError, RoleId};
use sqlx::types::Uuid as SqlUuid;

use super::{OrphanColumns, RenameColumns, expect_rows, state_filter, translate_entry};

const ROLE_A: &str = "0b7e5d3c-2a19-4f8e-8d6c-5b4a39281706";
const ROLE_B: &str = "7f1c2a4e-1d0b-4f5e-9a3c-2b6d8e0f1a2b";

fn role(value: &str) -> RoleId {
    RoleId::parse(value).unwrap()
}

fn sql(value: &str) -> SqlUuid {
    SqlUuid::parse_str(value).unwrap()
}

fn key(value: &str) -> PermissionKey {
    PermissionKey::parse(value).unwrap()
}

#[test]
fn the_expected_number_of_rows_is_accepted() {
    assert!(expect_rows(3, 3).is_ok());
    assert!(expect_rows(0, 0).is_ok());
}

#[test]
fn a_different_number_of_rows_is_a_conflict() {
    assert!(matches!(expect_rows(2, 3), Err(RepositoryError::Conflict)));
    assert!(matches!(expect_rows(4, 3), Err(RepositoryError::Conflict)));
}

#[test]
fn orphaned_grants_become_parallel_columns() {
    let columns = OrphanColumns::of(&[
        OrphanedGrant {
            role: role(ROLE_A),
            key: key("gql:billing:Query.old"),
        },
        OrphanedGrant {
            role: role(ROLE_B),
            key: key("gql:billing:Query.older"),
        },
    ]);

    assert_eq!(columns.roles, vec![sql(ROLE_A), sql(ROLE_B)]);
    assert_eq!(
        columns.keys,
        vec!["gql:billing:Query.old", "gql:billing:Query.older"]
    );
}

#[test]
fn a_rename_makes_one_row_for_each_role_that_holds_the_old_key() {
    let columns = RenameColumns::of(&[KeyRename {
        from: key("gql:billing:Query.a"),
        to: key("gql:billing:Query.b"),
        roles: vec![role(ROLE_A), role(ROLE_B)],
    }]);

    assert_eq!(columns.roles, vec![sql(ROLE_A), sql(ROLE_B)]);
    assert_eq!(columns.from, vec!["gql:billing:Query.a"; 2]);
    assert_eq!(columns.to, vec!["gql:billing:Query.b"; 2]);
}

#[test]
fn a_rename_without_roles_makes_no_row() {
    let columns = RenameColumns::of(&[KeyRename {
        from: key("gql:billing:Query.a"),
        to: key("gql:billing:Query.b"),
        roles: Vec::new(),
    }]);

    assert_eq!(columns, RenameColumns::default());
}

#[test]
fn open_state_filters_allow_every_stored_state() {
    assert_eq!(
        state_filter(None, None),
        ["false:false", "false:true", "true:false", "true:true"]
    );
}

#[test]
fn a_set_state_filter_allows_only_its_value() {
    assert_eq!(state_filter(Some(true), None), ["true:false", "true:true"]);
    assert_eq!(
        state_filter(None, Some(false)),
        ["false:false", "true:false"]
    );
    assert_eq!(state_filter(Some(false), Some(true)), ["false:true"]);
}

#[test]
fn a_storage_error_that_is_not_a_duplicate_is_unavailable() {
    assert!(matches!(
        translate_entry(sqlx::Error::PoolTimedOut),
        RepositoryError::Unavailable(_)
    ));
}

/// A database error that reports a unique violation, as PostgreSQL does for a key stored already.
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
fn a_created_key_that_is_stored_already_is_a_conflict() {
    assert!(matches!(
        translate_entry(sqlx::Error::Database(Box::new(UniqueViolation))),
        RepositoryError::Conflict
    ));
}
