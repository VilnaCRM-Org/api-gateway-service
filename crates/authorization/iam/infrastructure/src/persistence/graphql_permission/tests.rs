use iam_domain::{
    EntryFlags, EntryInsert, GraphQlPermissionParts, PermissionFlags, PermissionId, PermissionKey,
    RepositoryError,
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
    let found = restore(&row("gql:billing:Mutation.pay")).unwrap();

    assert_eq!(
        found.parts(),
        &GraphQlPermissionParts {
            id: PermissionId::parse(ID_A).unwrap(),
            key: key("gql:billing:Mutation.pay"),
            flags: PermissionFlags::NONE.with_sensitive(),
            active: true,
        }
    );
}

#[test]
fn a_stored_audit_flag_is_restored() {
    let mut stored = row("gql:billing:Query.invoices");
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
fn a_stored_rest_key_is_unusable_as_a_graphql_entry() {
    assert!(matches!(
        restore(&row("rest:billing:GET /invoices")),
        Err(RepositoryError::Unavailable(_))
    ));
}

#[test]
fn rows_are_restored_in_their_order() {
    let mut second = row("gql:billing:Query.node");
    second.id = sql(ID_B);

    let found = restore_all(&[row("gql:billing:Query.invoices"), second]).unwrap();

    let keys: Vec<String> = found
        .iter()
        .map(|entry| entry.parts().key.to_string())
        .collect();
    assert_eq!(
        keys,
        ["gql:billing:Query.invoices", "gql:billing:Query.node"]
    );
}

#[test]
fn entries_become_parallel_columns_with_the_coordinate_split() {
    let columns = EntryColumns::of(&[
        EntryInsert {
            id: PermissionId::parse(ID_A).unwrap(),
            key: key("gql:billing:Mutation.pay"),
            flags: PermissionFlags::NONE.with_sensitive(),
        },
        EntryInsert {
            id: PermissionId::parse(ID_B).unwrap(),
            key: key("gql:billing:__introspection"),
            flags: PermissionFlags::NONE.with_audit_always(),
        },
    ]);

    assert_eq!(columns.ids, vec![sql(ID_A), sql(ID_B)]);
    assert_eq!(
        columns.keys,
        vec!["gql:billing:Mutation.pay", "gql:billing:__introspection"]
    );
    assert_eq!(columns.types, vec!["Mutation", "__introspection"]);
    assert_eq!(columns.fields, vec!["pay", "__introspection"]);
    assert_eq!(columns.flags.sensitive, vec![true, false]);
    assert_eq!(columns.flags.audit_always, vec![false, true]);
}

#[test]
fn an_entry_of_another_form_has_no_columns() {
    let columns = EntryColumns::of(&[EntryInsert {
        id: PermissionId::parse(ID_A).unwrap(),
        key: key("rest:billing:GET /invoices"),
        flags: PermissionFlags::NONE,
    }]);

    assert_eq!(columns, EntryColumns::default());
}

#[test]
fn flag_changes_become_parallel_columns() {
    let columns = FlagColumns::of(&[EntryFlags {
        key: key("gql:billing:Mutation.pay"),
        flags: PermissionFlags::NONE.with_sensitive().with_audit_always(),
    }]);

    assert_eq!(columns.keys, vec!["gql:billing:Mutation.pay"]);
    assert_eq!(columns.sensitive, vec![true]);
    assert_eq!(columns.audit_always, vec![true]);
}

#[test]
fn the_created_keys_of_a_stored_event_payload_are_read_in_order() {
    let payload = r#"{"id":"1","type":"iam.graphql_permissions.created","occurredAt":"x","data":{"createdKeys":["gql:billing:Query.invoices","gql:billing:Mutation.pay"],"renamed":[]}}"#;

    assert_eq!(
        created_keys(payload).unwrap(),
        vec![
            key("gql:billing:Query.invoices"),
            key("gql:billing:Mutation.pay")
        ]
    );
}

#[test]
fn an_event_payload_without_created_keys_is_unusable() {
    assert!(matches!(
        created_keys(r#"{"data":{}}"#),
        Err(RepositoryError::Unavailable(_))
    ));
}

#[test]
fn a_payload_that_is_not_json_is_unusable() {
    assert!(matches!(
        created_keys("not json"),
        Err(RepositoryError::Unavailable(_))
    ));
}

#[test]
fn a_created_key_that_is_not_text_or_not_a_key_is_unusable() {
    for payload in [
        r#"{"data":{"createdKeys":[1]}}"#,
        r#"{"data":{"createdKeys":["not a key"]}}"#,
    ] {
        assert!(matches!(
            created_keys(payload),
            Err(RepositoryError::Unavailable(_))
        ));
    }
}
