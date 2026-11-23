use iam_domain::{
    EntryFlags, EntryInsert, PermissionFlags, PermissionId, PermissionKey, RepositoryError,
    RestPermissionParts,
};
use sqlx::types::Uuid as SqlUuid;

use super::{Activity, EntryColumns, FlagColumns, PermissionRow, restore, restore_all};
use crate::persistence::catalogue::created_keys;

const ID_A: &str = "0b7e5d3c-2a19-4f8e-8d6c-5b4a39281706";
const ID_B: &str = "7f1c2a4e-1d0b-4f5e-9a3c-2b6d8e0f1a2b";

fn sql(value: &str) -> SqlUuid {
    SqlUuid::parse_str(value).unwrap()
}

fn key(value: &str) -> PermissionKey {
    PermissionKey::parse(value).unwrap()
}

fn row(permission_key: &str) -> PermissionRow {
    PermissionRow {
        id: sql(ID_A),
        permission_key: permission_key.to_owned(),
        sensitive: true,
        audit_always: false,
        active: Activity(true),
    }
}

#[test]
fn a_stored_row_restores_its_key_flags_and_state() {
    let found = restore(&row("rest:billing:POST /invoices/{}/pay")).unwrap();

    assert_eq!(
        found.parts(),
        &RestPermissionParts {
            id: PermissionId::parse(ID_A).unwrap(),
            key: key("rest:billing:POST /invoices/{}/pay"),
            flags: PermissionFlags::NONE.with_sensitive(),
            active: true,
        }
    );
}

#[test]
fn a_stored_audit_flag_is_restored() {
    let mut stored = row("rest:billing:GET /invoices");
    stored.sensitive = false;
    stored.audit_always = true;
    stored.active = Activity(false);

    let found = restore(&stored).unwrap();

    assert_eq!(
        found.parts().flags,
        PermissionFlags::NONE.with_audit_always()
    );
    assert!(!found.parts().active);
}

#[test]
fn a_stored_text_that_is_not_a_key_is_unusable() {
    assert!(matches!(
        restore(&row("not a key")),
        Err(RepositoryError::Unavailable(_))
    ));
}

#[test]
fn a_stored_graphql_key_is_unusable_as_a_rest_entry() {
    assert!(matches!(
        restore(&row("gql:billing:Query.invoices")),
        Err(RepositoryError::Unavailable(_))
    ));
}

#[test]
fn rows_are_restored_in_their_order() {
    let mut second = row("rest:billing:GET /orders");
    second.id = sql(ID_B);

    let found = restore_all(&[row("rest:billing:GET /invoices"), second]).unwrap();

    let keys: Vec<String> = found
        .iter()
        .map(|entry| entry.parts().key.to_string())
        .collect();
    assert_eq!(
        keys,
        ["rest:billing:GET /invoices", "rest:billing:GET /orders"]
    );
}

#[test]
fn entries_become_parallel_columns_with_the_operation_split() {
    let columns = EntryColumns::of(&[
        EntryInsert {
            id: PermissionId::parse(ID_A).unwrap(),
            key: key("rest:billing:POST /invoices/{}/pay"),
            flags: PermissionFlags::NONE.with_sensitive(),
        },
        EntryInsert {
            id: PermissionId::parse(ID_B).unwrap(),
            key: key("rest:billing:GET /invoices"),
            flags: PermissionFlags::NONE.with_audit_always(),
        },
    ]);

    assert_eq!(columns.ids, vec![sql(ID_A), sql(ID_B)]);
    assert_eq!(
        columns.keys,
        vec![
            "rest:billing:POST /invoices/{}/pay",
            "rest:billing:GET /invoices"
        ]
    );
    assert_eq!(columns.methods, vec!["POST", "GET"]);
    assert_eq!(columns.templates, vec!["/invoices/{}/pay", "/invoices"]);
    assert_eq!(columns.flags.sensitive, vec![true, false]);
    assert_eq!(columns.flags.audit_always, vec![false, true]);
}

#[test]
fn an_entry_of_another_form_has_no_columns() {
    let columns = EntryColumns::of(&[EntryInsert {
        id: PermissionId::parse(ID_A).unwrap(),
        key: key("gql:billing:Query.invoices"),
        flags: PermissionFlags::NONE,
    }]);

    assert_eq!(columns, EntryColumns::default());
}

#[test]
fn flag_changes_become_parallel_columns() {
    let columns = FlagColumns::of(&[EntryFlags {
        key: key("rest:billing:GET /invoices"),
        flags: PermissionFlags::NONE.with_sensitive().with_audit_always(),
    }]);

    assert_eq!(columns.keys, vec!["rest:billing:GET /invoices"]);
    assert_eq!(columns.sensitive, vec![true]);
    assert_eq!(columns.audit_always, vec![true]);
}

#[test]
fn the_created_keys_of_a_stored_rest_event_payload_are_read_in_order() {
    let payload = r#"{"id":"1","type":"iam.rest_permissions.created","occurredAt":"x","data":{"createdKeys":["rest:billing:GET /invoices","rest:billing:POST /invoices/{}/pay"],"renamed":[]}}"#;

    assert_eq!(
        created_keys(payload).unwrap(),
        vec![
            key("rest:billing:GET /invoices"),
            key("rest:billing:POST /invoices/{}/pay")
        ]
    );
}
