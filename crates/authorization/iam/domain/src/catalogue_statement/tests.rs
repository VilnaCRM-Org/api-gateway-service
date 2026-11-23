use std::time::SystemTime;

use super::{CatalogueStatement, CatalogueStatementParts, EntryFlags, EntryInsert, SpecTransition};
use crate::error::InvalidCatalogueEntry;
use crate::policy::catalogue_activation::{KeyRename, OrphanedGrant};
use crate::value_object::identifier::{PermissionId, RoleId, SpecId};
use crate::value_object::permission_flags::PermissionFlags;
use crate::value_object::permission_key::{PermissionKey, PermissionKeyKind};
use crate::value_object::service_name::ServiceName;
use crate::value_object::spec_status::SpecStatus;

fn key(value: &str) -> PermissionKey {
    PermissionKey::parse(value).unwrap()
}

fn parts() -> CatalogueStatementParts {
    CatalogueStatementParts {
        kind: PermissionKeyKind::Gql,
        service: ServiceName::new("billing").unwrap(),
        transition: SpecTransition {
            spec_id: SpecId::parse("5b2e8c1d-3f4a-4b6c-8d9e-0a1b2c3d4e5f").unwrap(),
            from: SpecStatus::Draft,
            to: SpecStatus::Active,
            activated_at: Some(SystemTime::UNIX_EPOCH),
            retired_at: None,
        },
        created: vec![EntryInsert {
            id: PermissionId::parse("7f1c2a4e-1d0b-4f5e-9a3c-2b6d8e0f1a2b").unwrap(),
            key: key("gql:billing:Query.invoices"),
            flags: PermissionFlags::NONE,
        }],
        reflagged: vec![EntryFlags {
            key: key("gql:billing:Mutation.pay"),
            flags: PermissionFlags::NONE.with_sensitive(),
        }],
        reactivated: vec![key("gql:billing:Query.node")],
        deactivated: vec![key("gql:billing:Query.old")],
        orphaned: vec![OrphanedGrant {
            role: RoleId::parse("0b7e5d3c-2a19-4f8e-8d6c-5b4a39281706").unwrap(),
            key: key("gql:billing:Query.old"),
        }],
        renames: vec![KeyRename {
            from: key("gql:billing:Query.a"),
            to: key("gql:billing:Query.b"),
            roles: Vec::new(),
        }],
        at: SystemTime::UNIX_EPOCH,
    }
}

#[test]
fn a_statement_of_one_service_and_form_is_kept_as_given() {
    let statement = CatalogueStatement::new(parts()).unwrap();

    assert_eq!(statement.parts(), &parts());
}

#[test]
fn a_reserved_form_is_refused() {
    let mut given = parts();
    given.kind = PermissionKeyKind::Reserved;

    assert!(matches!(
        CatalogueStatement::new(given),
        Err(InvalidCatalogueEntry::KeyKind { .. })
    ));
}

#[test]
fn a_created_key_of_another_form_is_refused() {
    let mut given = parts();
    given.created[0].key = key("rest:billing:GET /invoices");

    assert!(matches!(
        CatalogueStatement::new(given),
        Err(InvalidCatalogueEntry::KeyKind {
            expected: "gql",
            found: PermissionKeyKind::Rest
        })
    ));
}

#[test]
fn a_renamed_key_of_another_service_is_refused() {
    let mut given = parts();
    given.renames[0].to = key("gql:orders:Query.b");

    assert_eq!(
        CatalogueStatement::new(given),
        Err(InvalidCatalogueEntry::OutsideService {
            key: "gql:orders:Query.b".to_owned()
        })
    );
}

#[test]
fn an_orphaned_key_of_another_service_is_refused() {
    let mut given = parts();
    given.orphaned[0].key = key("gql:orders:Query.old");

    assert!(matches!(
        CatalogueStatement::new(given),
        Err(InvalidCatalogueEntry::OutsideService { .. })
    ));
}
