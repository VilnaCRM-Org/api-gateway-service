use std::error::Error as _;

use rstest::rstest;
use shared_domain::Uuid;

use super::*;

const ACTOR: &str = "user:0190f2a8-7b3c-7d4e-8f00-123456789abc";

fn change_id() -> ChangeId {
    ChangeId::parse("0190f2a8-7b3c-7d4e-8f00-000000000001").unwrap()
}

fn row() -> Row {
    Row {
        actor: ACTOR.to_owned(),
        target_type: "role".to_owned(),
        target_id: "r-1".to_owned(),
        entity_version: 4,
        policy_version: Some(9),
    }
}

#[test]
fn a_valid_row_is_restored_with_every_column() {
    let receipt = restore(change_id(), &row()).unwrap();

    assert_eq!(receipt.change_id(), change_id());
    assert_eq!(
        receipt.actor(),
        &ActorRef::User(Uuid::parse("0190f2a8-7b3c-7d4e-8f00-123456789abc").unwrap())
    );
    assert_eq!(receipt.target(), &AuditTarget::new("role", "r-1").unwrap());
    assert_eq!(receipt.entity_version().value(), 4);
    assert_eq!(receipt.policy_version(), PolicyVersion::new(9).ok());
}

#[test]
fn a_row_without_a_policy_version_is_a_change_that_did_not_affect_decisions() {
    let receipt = restore(
        change_id(),
        &Row {
            policy_version: None,
            ..row()
        },
    )
    .unwrap();

    assert_eq!(receipt.policy_version(), None);
}

#[rstest]
#[case::actor(Row { actor: "robot:1".to_owned(), ..row() })]
#[case::target_type(Row { target_type: "Role".to_owned(), ..row() })]
#[case::target_id(Row { target_id: String::new(), ..row() })]
#[case::entity_version(Row { entity_version: 0, ..row() })]
#[case::policy_version(Row { policy_version: Some(-1), ..row() })]
fn a_row_that_breaks_a_domain_invariant_is_unavailable(#[case] row: Row) {
    let error = restore(change_id(), &row).unwrap_err();

    assert!(matches!(error, RepositoryError::Unavailable(_)));
    assert!(error.source().is_some());
}

#[test]
fn a_missing_row_is_not_found() {
    assert!(matches!(
        translate(sqlx::Error::RowNotFound),
        RepositoryError::NotFound
    ));
}

#[test]
fn any_other_database_error_is_unavailable() {
    let error = translate(sqlx::Error::PoolTimedOut);

    assert!(matches!(error, RepositoryError::Unavailable(_)));
    assert!(error.source().is_some());
}
