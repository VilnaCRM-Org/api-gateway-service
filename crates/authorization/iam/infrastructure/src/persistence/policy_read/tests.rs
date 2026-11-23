use std::time::{Duration, SystemTime};

use iam_domain::{AssignmentScope, PermissionFlags, PermissionKey, RepositoryError, RoleId};
use shared_domain::Uuid;
use sqlx::types::Uuid as SqlUuid;
use sqlx::types::time::OffsetDateTime;

use super::{AssignmentRow, RoleGrantRow, compile_role_sets, restore_assignments};

const ROLE: &str = "7f1c2a4e-1d0b-4f5e-9a3c-2b6d8e0f1a2b";
const OTHER_ROLE: &str = "3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a";
const PROJECT: &str = "01890a5d-ac96-774b-bcce-b302099a8057";

fn sql_uuid(text: &str) -> SqlUuid {
    SqlUuid::parse_str(text).unwrap()
}

fn role_id(text: &str) -> RoleId {
    RoleId::from_uuid(Uuid::from_uuid(sql_uuid(text)))
}

fn assignment(scope_kind: &str, project: Option<&str>, expires: bool) -> AssignmentRow {
    AssignmentRow {
        role_id: sql_uuid(ROLE),
        scope_kind: scope_kind.to_owned(),
        project_id: project.map(sql_uuid),
        expires_at: expires.then(|| OffsetDateTime::from(SystemTime::UNIX_EPOCH)),
    }
}

fn grant(role: &str, key: Option<&str>, active: Option<bool>) -> RoleGrantRow {
    RoleGrantRow {
        role_id: sql_uuid(role),
        permission_key: key.map(str::to_owned),
        active,
    }
}

#[test]
fn a_global_assignment_without_expiry_is_restored() {
    let restored = restore_assignments(&[assignment("global", None, false)]).unwrap();

    assert_eq!(restored.len(), 1);
    assert_eq!(restored[0].role_id(), role_id(ROLE));
    assert_eq!(restored[0].scope(), AssignmentScope::Global);
    assert_eq!(restored[0].expires_at(), None);
}

#[test]
fn a_project_assignment_keeps_its_project_and_its_expiry_even_when_it_has_passed() {
    let restored = restore_assignments(&[assignment("project", Some(PROJECT), true)]).unwrap();

    assert_eq!(
        restored[0].scope().project_id().unwrap().to_string(),
        PROJECT
    );
    assert_eq!(restored[0].expires_at(), Some(SystemTime::UNIX_EPOCH));
    assert!(!restored[0].is_active_at(SystemTime::UNIX_EPOCH + Duration::from_secs(1)));
}

#[test]
fn an_assignment_that_breaks_a_domain_invariant_is_unavailable() {
    let error = restore_assignments(&[assignment("project", None, false)]).unwrap_err();

    assert!(matches!(error, RepositoryError::Unavailable(_)));
}

#[test]
fn active_grants_are_compiled_and_orphaned_grants_are_excluded() {
    let key = "rest:orders:GET /api/orders";
    let gone = "rest:orders:GET /api/gone";
    let sets = compile_role_sets(vec![
        grant(ROLE, Some(key), Some(true)),
        grant(ROLE, Some(gone), Some(false)),
        grant(ROLE, Some("rest:billing:*"), Some(true)),
    ])
    .unwrap();

    let set = &sets[&role_id(ROLE)];
    assert!(set.holds(&PermissionKey::parse(key).unwrap(), PermissionFlags::NONE));
    assert!(!set.holds(&PermissionKey::parse(gone).unwrap(), PermissionFlags::NONE));
    assert_eq!(set.key_count(), 1);
    assert_eq!(set.wildcard_count(), 1);
}

#[test]
fn a_role_without_grants_gets_an_empty_set_and_roles_stay_apart() {
    let sets = compile_role_sets(vec![
        grant(ROLE, None, None),
        grant(OTHER_ROLE, Some("rest:orders:GET /api/orders"), Some(true)),
    ])
    .unwrap();

    assert!(sets[&role_id(ROLE)].is_empty());
    assert_eq!(sets[&role_id(OTHER_ROLE)].key_count(), 1);
    assert_eq!(sets.len(), 2);
}

#[test]
fn no_rows_compile_to_no_role_set() {
    assert!(compile_role_sets(Vec::new()).unwrap().is_empty());
}

#[test]
fn a_stored_key_that_is_not_a_grant_is_unavailable() {
    let error = compile_role_sets(vec![grant(ROLE, Some("not a key"), Some(true))]).unwrap_err();

    assert!(matches!(error, RepositoryError::Unavailable(_)));
}
