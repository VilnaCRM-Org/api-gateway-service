use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, ContentHash, OpenApiSpec, OpenApiSpecContent, OpenApiSpecParts, OpenApiSpecStatement,
    RepositoryError, RestOperationSet, ServiceName, SpecId, SpecStatus,
};
use shared_domain::Uuid;
use sqlx::types::Uuid as SqlUuid;
use sqlx::types::time::OffsetDateTime;
use test_support::openapi_spec::{DOCUMENT_FIXTURE, operations_fixture};

use super::{
    OperationColumns, OperationRow, SpecRow, WriteRow, group, hashed, operation, operation_set,
    restore,
};

const SPEC: &str = "5b2e8c1d-3f4a-4b6c-8d9e-0a1b2c3d4e5f";
const USER: &str = "3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a";

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn sql(id: &str) -> SqlUuid {
    SqlUuid::parse_str(id).unwrap()
}

fn parts(status: SpecStatus) -> OpenApiSpecParts {
    OpenApiSpecParts {
        id: SpecId::parse(SPEC).unwrap(),
        content: OpenApiSpecContent {
            service: ServiceName::new("billing").unwrap(),
            content_hash: ContentHash::new(&[0x11; 32]).unwrap(),
            operations: operations_fixture(),
        },
        status,
        uploaded_by: ActorRef::User(Uuid::parse(USER).unwrap()),
        created_at: at(1_700_000_000),
        activated_at: Some(at(1_700_000_100)),
        retired_at: None,
    }
}

fn row() -> SpecRow {
    SpecRow {
        id: sql(SPEC),
        service: "billing".to_owned(),
        content_hash: vec![0x11; 32],
        status: "active".to_owned(),
        uploaded_by: format!("user:{USER}"),
        created_at: OffsetDateTime::from(at(1_700_000_000)),
        activated_at: Some(OffsetDateTime::from(at(1_700_000_100))),
        retired_at: None,
    }
}

/// A stored operation row with the label and the flags `(sensitive, audit_always)`.
fn operation_row(
    method: &str,
    path_template: &str,
    label: Option<&str>,
    (sensitive, audit): (bool, bool),
) -> OperationRow {
    OperationRow {
        spec_id: sql(SPEC),
        method: method.to_owned(),
        path_template: path_template.to_owned(),
        label: label.map(str::to_owned),
        sensitive,
        audit_always: audit,
    }
}

#[test]
fn a_write_holds_the_columns_of_every_operation() {
    let statement = OpenApiSpecStatement::insert(
        &OpenApiSpec::restore(parts(SpecStatus::Active)),
        DOCUMENT_FIXTURE.to_owned(),
    );

    let row = WriteRow::of(&statement);

    assert_eq!(row.id, sql(SPEC));
    assert_eq!(row.service, "billing");
    assert_eq!(row.content_hash, vec![0x11; 32]);
    assert_eq!(row.document, DOCUMENT_FIXTURE);
    assert_eq!(row.status, "active");
    assert_eq!(row.uploaded_by, format!("user:{USER}"));
    assert_eq!(row.created_at, OffsetDateTime::from(at(1_700_000_000)));
    assert_eq!(
        row.activated_at,
        Some(OffsetDateTime::from(at(1_700_000_100)))
    );
    assert_eq!(row.retired_at, None);
    assert_eq!(row.labelled.methods, ["GET", "POST"]);
    assert_eq!(row.labelled.templates, ["/invoices", "/invoices/{}"]);
    assert_eq!(row.labelled.labels, ["listInvoices", "payInvoice"]);
    assert_eq!(row.labelled.sensitive, [false, true]);
    assert_eq!(row.labelled.audit_always, [false, false]);
    assert_eq!(row.unlabelled.methods, ["DELETE"]);
    assert_eq!(row.unlabelled.templates, ["/invoices/{}"]);
    assert_eq!(row.unlabelled.labels, Vec::<String>::new());
    assert_eq!(row.unlabelled.sensitive, [false]);
    assert_eq!(row.unlabelled.audit_always, [true]);
}

#[test]
fn a_write_of_a_version_without_operations_holds_empty_columns() {
    let mut empty = parts(SpecStatus::Draft);
    empty.content.operations = RestOperationSet::new();
    empty.activated_at = None;

    let row = WriteRow::of(&OpenApiSpecStatement::insert(
        &OpenApiSpec::restore(empty),
        String::new(),
    ));

    assert_eq!(row.labelled, OperationColumns::default());
    assert_eq!(row.unlabelled, OperationColumns::default());
    assert_eq!(row.status, "draft");
    assert_eq!(row.activated_at, None);
}

#[test]
fn a_stored_row_with_its_operations_is_the_version() {
    let restored = restore(&row(), operations_fixture()).unwrap();

    assert_eq!(restored.parts(), &parts(SpecStatus::Active));
}

#[test]
fn a_stored_row_with_an_unusable_value_is_unavailable() {
    let hash = SpecRow {
        content_hash: vec![1, 2, 3],
        ..row()
    };
    let status = SpecRow {
        status: "paused".to_owned(),
        ..row()
    };
    let service = SpecRow {
        service: "Not A Service".to_owned(),
        ..row()
    };
    let actor = SpecRow {
        uploaded_by: "nobody".to_owned(),
        ..row()
    };

    for broken in [hash, status, service, actor] {
        assert!(matches!(
            restore(&broken, RestOperationSet::new()),
            Err(RepositoryError::Unavailable(_))
        ));
    }
}

#[test]
fn stored_operations_make_the_set_with_their_labels_and_flags() {
    let rows = vec![
        operation_row("GET", "/a", None, (false, false)),
        operation_row("POST", "/a", Some("create"), (true, false)),
        operation_row("PUT", "/a/{}", None, (false, true)),
        operation_row("DELETE", "/a/{}", None, (true, true)),
    ];

    let set = operation_set(&rows).unwrap();

    let found: Vec<(String, Option<String>, bool, bool)> = set
        .iter()
        .map(|(key, details)| {
            (
                key.to_string(),
                details.label.clone(),
                details.flags.is_sensitive(),
                details.flags.is_audit_always(),
            )
        })
        .collect();
    assert_eq!(
        found,
        [
            ("GET /a".to_owned(), None, false, false),
            ("POST /a".to_owned(), Some("create".to_owned()), true, false),
            ("PUT /a/{}".to_owned(), None, false, true),
            ("DELETE /a/{}".to_owned(), None, true, true),
        ]
    );
}

#[test]
fn a_stored_operation_with_an_invalid_value_or_a_duplicate_is_unavailable() {
    let method = operation_row("TRACE", "/a", None, (false, false));
    let template = operation_row("GET", "/a/{id}", None, (false, false));
    let first = operation_row("GET", "/a", None, (false, false));
    let second = operation_row("GET", "/a", Some("again"), (false, false));

    assert!(matches!(
        operation_set(&[method]),
        Err(RepositoryError::Unavailable(_))
    ));
    assert!(matches!(
        operation_set(&[template]),
        Err(RepositoryError::Unavailable(_))
    ));
    assert!(matches!(
        operation_set(&[first, second]),
        Err(RepositoryError::Unavailable(_))
    ));
}

#[test]
fn an_operation_row_becomes_an_operation_with_its_label_and_flags() {
    let found = operation(&operation_row(
        "PATCH",
        "/a/{}",
        Some("rename"),
        (true, false),
    ))
    .unwrap();

    assert_eq!(found.method.as_str(), "PATCH");
    assert_eq!(found.template.as_str(), "/a/{}");
    assert_eq!(found.label.as_deref(), Some("rename"));
    assert!(found.flags.is_sensitive());
    assert!(!found.flags.is_audit_always());
}

#[test]
fn rows_are_grouped_by_their_key() {
    let other = "7f1c2a4e-1d0b-4f5e-9a3c-2b6d8e0f1a2b";
    let rows = vec![
        operation_row("GET", "/a", None, (false, false)),
        OperationRow {
            spec_id: sql(other),
            ..operation_row("GET", "/b", None, (false, false))
        },
        operation_row("GET", "/c", None, (false, false)),
    ];

    let grouped = group(rows, |row| row.spec_id);

    assert_eq!(grouped.len(), 2);
    assert_eq!(grouped.get(&sql(SPEC)).map(Vec::len), Some(2));
    assert_eq!(grouped.get(&sql(other)).map(Vec::len), Some(1));
}

#[test]
fn an_insert_that_writes_no_row_means_the_hash_does_not_match() {
    assert!(hashed(1).is_ok());
    assert!(matches!(hashed(0), Err(RepositoryError::Unavailable(_))));
}
