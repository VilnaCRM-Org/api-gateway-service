use super::{RestPermission, RestPermissionParts};
use crate::error::InvalidCatalogueEntry;
use crate::value_object::identifier::PermissionId;
use crate::value_object::permission_flags::PermissionFlags;
use crate::value_object::permission_key::{PermissionKey, PermissionKeyKind};

const ID: &str = "5b2e8c1d-3f4a-4b6c-8d9e-0a1b2c3d4e5f";

fn key(value: &str) -> PermissionKey {
    PermissionKey::parse(value).unwrap()
}

fn entry() -> RestPermission {
    RestPermission::create(
        PermissionId::parse(ID).unwrap(),
        key("rest:billing:POST /api/invoices/{}/pay"),
        PermissionFlags::NONE,
    )
    .unwrap()
}

#[test]
fn a_new_entry_is_active_and_names_its_service() {
    let permission = entry();

    assert_eq!(permission.parts().id, PermissionId::parse(ID).unwrap());
    assert_eq!(
        permission.parts().key,
        key("rest:billing:POST /api/invoices/{}/pay")
    );
    assert_eq!(permission.parts().flags, PermissionFlags::NONE);
    assert!(permission.parts().active);
    assert_eq!(permission.service().to_string(), "billing");
}

#[test]
fn an_entry_follows_the_flags_and_the_active_versions() {
    let mut permission = entry();
    let audited = PermissionFlags::NONE.with_audit_always();

    permission.set_flags(audited);
    permission.deactivate();
    assert_eq!(permission.parts().flags, audited);
    assert!(!permission.parts().active);

    permission.activate();
    assert!(permission.parts().active);
}

#[test]
fn a_restored_entry_keeps_its_state() {
    let parts = RestPermissionParts {
        id: PermissionId::parse(ID).unwrap(),
        key: key("rest:billing:GET /api/invoices"),
        flags: PermissionFlags::NONE.with_sensitive(),
        active: false,
    };

    let permission = RestPermission::restore(parts.clone()).unwrap();

    assert_eq!(permission.parts(), &parts);
}

#[test]
fn only_a_rest_key_makes_an_entry() {
    for (text, found) in [
        ("gql:billing:Query.invoice", PermissionKeyKind::Gql),
        ("iam:audit:read", PermissionKeyKind::Reserved),
    ] {
        let refused = RestPermission::create(
            PermissionId::parse(ID).unwrap(),
            key(text),
            PermissionFlags::NONE,
        )
        .unwrap_err();

        assert_eq!(
            refused,
            InvalidCatalogueEntry::KeyKind {
                expected: "rest",
                found
            }
        );
    }
}
