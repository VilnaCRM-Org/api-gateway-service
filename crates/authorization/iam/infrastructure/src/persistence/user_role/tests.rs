use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, AssignmentExpiry, AssignmentScope, EntityVersion, ProjectId, RepositoryError, RoleId,
    ServiceName, SubjectRef, UserRoleId, UserRoleParts,
};
use rstest::rstest;
use shared_domain::Uuid;
use sqlx::types::Uuid as SqlUuid;
use sqlx::types::time::OffsetDateTime;

use super::{UserRoleRow, WriteRow, restore};

const USER_ROLE: &str = "0b7e5d3c-2a19-4f8e-8d6c-5b4a39281706";
const ROLE: &str = "7f1c2a4e-1d0b-4f5e-9a3c-2b6d8e0f1a2b";
const PROJECT: &str = "5e4d3c2b-1a09-4f8e-a7d6-c5b4a3928170";
const SUBJECT: &str = "9c8b7a6f-5e4d-4c3b-a291-807f6e5d4c3b";
const USER: &str = "3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a";

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn sql(id: &str) -> SqlUuid {
    SqlUuid::parse_str(id).unwrap()
}

fn parts(subject: SubjectRef, scope: AssignmentScope) -> UserRoleParts {
    UserRoleParts {
        id: UserRoleId::parse(USER_ROLE).unwrap(),
        subject,
        role_id: RoleId::parse(ROLE).unwrap(),
        scope,
        expires_at: Some(AssignmentExpiry::restore(at(1_800_000_000))),
        version: EntityVersion::new(3).unwrap(),
        created_by: ActorRef::User(Uuid::parse(USER).unwrap()),
        created_at: at(1_700_000_000),
        updated_at: at(1_700_000_100),
        revoked_at: None,
    }
}

fn user() -> SubjectRef {
    SubjectRef::user(Uuid::parse(SUBJECT).unwrap())
}

fn project() -> AssignmentScope {
    AssignmentScope::Project(ProjectId::parse(PROJECT).unwrap())
}

fn row() -> UserRoleRow {
    UserRoleRow {
        id: sql(USER_ROLE),
        subject_kind: "user".to_owned(),
        subject_id: SUBJECT.to_owned(),
        role_id: sql(ROLE),
        scope_kind: "project".to_owned(),
        project_id: Some(sql(PROJECT)),
        expires_at: Some(OffsetDateTime::from(at(1_800_000_000))),
        version: 3,
        created_by: format!("user:{USER}"),
        created_at: OffsetDateTime::from(at(1_700_000_000)),
        updated_at: OffsetDateTime::from(at(1_700_000_100)),
    }
}

#[test]
fn a_write_row_holds_every_column_of_a_project_scoped_user_assignment() {
    let row = WriteRow::of(&UserRoleParts {
        revoked_at: Some(at(1_700_000_200)),
        ..parts(user(), project())
    });

    assert_eq!(
        row,
        WriteRow {
            id: sql(USER_ROLE),
            subject_kind: "user",
            subject_id: SUBJECT.to_owned(),
            role_id: sql(ROLE),
            scope_kind: "project",
            project_id: Some(sql(PROJECT)),
            expires_at: Some(OffsetDateTime::from(at(1_800_000_000))),
            version: 3,
            created_by: format!("user:{USER}"),
            created_at: OffsetDateTime::from(at(1_700_000_000)),
            updated_at: OffsetDateTime::from(at(1_700_000_100)),
            revoked_at: Some(OffsetDateTime::from(at(1_700_000_200))),
        }
    );
}

#[test]
fn a_global_service_assignment_without_an_expiry_has_no_project_and_no_expiry() {
    let subject = SubjectRef::service(ServiceName::new("billing-service").unwrap());
    let row = WriteRow::of(&UserRoleParts {
        expires_at: None,
        ..parts(subject, AssignmentScope::Global)
    });

    assert_eq!(row.subject_kind, "service");
    assert_eq!(row.subject_id, "billing-service");
    assert_eq!(row.scope_kind, "global");
    assert_eq!(row.project_id, None);
    assert_eq!(row.expires_at, None);
    assert_eq!(row.revoked_at, None);
}

#[test]
fn a_stored_row_is_restored_through_the_value_objects() {
    let restored = restore(&row()).unwrap();

    assert_eq!(restored.parts(), &parts(user(), project()));
}

#[test]
fn a_stored_global_service_row_without_an_expiry_is_restored() {
    let restored = restore(&UserRoleRow {
        subject_kind: "service".to_owned(),
        subject_id: "billing-service".to_owned(),
        scope_kind: "global".to_owned(),
        project_id: None,
        expires_at: None,
        ..row()
    })
    .unwrap();

    assert_eq!(
        restored.parts(),
        &UserRoleParts {
            expires_at: None,
            ..parts(
                SubjectRef::service(ServiceName::new("billing-service").unwrap()),
                AssignmentScope::Global
            )
        }
    );
}

#[rstest]
#[case::subject_kind(UserRoleRow { subject_kind: "group".to_owned(), ..row() })]
#[case::user_id(UserRoleRow { subject_id: "billing-service".to_owned(), ..row() })]
#[case::service_name(UserRoleRow {
    subject_kind: "service".to_owned(),
    subject_id: "Billing".to_owned(),
    ..row()
})]
#[case::scope_kind(UserRoleRow { scope_kind: "tenant".to_owned(), ..row() })]
#[case::missing_project(UserRoleRow { project_id: None, ..row() })]
#[case::version(UserRoleRow { version: 0, ..row() })]
#[case::creator(UserRoleRow { created_by: "nobody".to_owned(), ..row() })]
fn a_stored_row_that_breaks_an_invariant_is_unavailable(#[case] stored: UserRoleRow) {
    assert!(matches!(
        restore(&stored),
        Err(RepositoryError::Unavailable(_))
    ));
}
