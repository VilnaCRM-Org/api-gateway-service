use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, ContentHash, GraphQlSpec, GraphQlSpecContent, GraphQlSpecParts, GraphQlSpecStatement,
    GraphQlTypeGraph, RepositoryError, ServiceName, SpecId, SpecStatus,
};
use shared_domain::Uuid;
use sqlx::types::Uuid as SqlUuid;
use sqlx::types::time::OffsetDateTime;
use test_support::graphql_spec::{SDL_FIXTURE, type_graph_fixture};

use super::{
    FieldRow, PossibleTypeRow, SpecRow, WriteRow, field, graph, group, hashed, name, restore,
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

fn parts(status: SpecStatus) -> GraphQlSpecParts {
    GraphQlSpecParts {
        id: SpecId::parse(SPEC).unwrap(),
        content: GraphQlSpecContent {
            service: ServiceName::new("billing").unwrap(),
            content_hash: ContentHash::new(&[0x11; 32]).unwrap(),
            type_graph: type_graph_fixture(),
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

/// A stored field row with the flags `(sensitive, audit_always)`.
fn field_row(type_name: &str, field_name: &str, (sensitive, audit): (bool, bool)) -> FieldRow {
    FieldRow {
        spec_id: sql(SPEC),
        type_name: type_name.to_owned(),
        field_name: field_name.to_owned(),
        return_type: "String".to_owned(),
        sensitive,
        audit_always: audit,
    }
}

#[test]
fn a_write_holds_the_columns_of_every_field_and_possible_type() {
    let statement = GraphQlSpecStatement::insert(
        &GraphQlSpec::restore(parts(SpecStatus::Active)),
        SDL_FIXTURE.to_owned(),
    );

    let row = WriteRow::of(&statement);

    assert_eq!(row.id, sql(SPEC));
    assert_eq!(row.service, "billing");
    assert_eq!(row.content_hash, vec![0x11; 32]);
    assert_eq!(row.sdl, SDL_FIXTURE);
    assert_eq!(row.status, "active");
    assert_eq!(row.uploaded_by, format!("user:{USER}"));
    assert_eq!(row.created_at, OffsetDateTime::from(at(1_700_000_000)));
    assert_eq!(
        row.activated_at,
        Some(OffsetDateTime::from(at(1_700_000_100)))
    );
    assert_eq!(row.retired_at, None);
    assert_eq!(row.fields.type_names.len(), 6);
    assert_eq!(row.fields.field_names.len(), 6);
    assert_eq!(row.fields.return_types.len(), 6);
    assert_eq!(row.fields.sensitive.iter().filter(|set| **set).count(), 1);
    assert_eq!(
        row.fields.audit_always.iter().filter(|set| **set).count(),
        0
    );
    assert_eq!(
        row.possible_types.abstract_types,
        ["Node".to_owned(), "Node".to_owned()]
    );
    assert_eq!(
        row.possible_types.possible_types,
        ["Customer".to_owned(), "Invoice".to_owned()]
    );
}

#[test]
fn a_write_of_a_version_without_fields_holds_empty_columns() {
    let mut empty = parts(SpecStatus::Draft);
    empty.content.type_graph = GraphQlTypeGraph::default();
    empty.activated_at = None;

    let row = WriteRow::of(&GraphQlSpecStatement::insert(
        &GraphQlSpec::restore(empty),
        String::new(),
    ));

    assert_eq!(row.fields.type_names, Vec::<String>::new());
    assert_eq!(row.possible_types.abstract_types, Vec::<String>::new());
    assert_eq!(row.status, "draft");
    assert_eq!(row.activated_at, None);
}

#[test]
fn a_stored_row_with_its_graph_is_the_version() {
    let restored = restore(&row(), type_graph_fixture()).unwrap();

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
            restore(&broken, GraphQlTypeGraph::default()),
            Err(RepositoryError::Unavailable(_))
        ));
    }
}

#[test]
fn stored_fields_and_possible_types_make_the_graph() {
    let fields = vec![
        field_row("Query", "a", (false, false)),
        field_row("Query", "b", (true, false)),
        field_row("Query", "c", (false, true)),
        field_row("Query", "d", (true, true)),
    ];
    let possible = vec![PossibleTypeRow {
        spec_id: sql(SPEC),
        abstract_type: "Node".to_owned(),
        possible_type: "Query".to_owned(),
    }];

    let built = graph(&fields, &possible).unwrap();

    let flags: Vec<(bool, bool)> = built
        .fields()
        .map(|(_coordinate, found)| (found.flags.is_sensitive(), found.flags.is_audit_always()))
        .collect();
    assert_eq!(
        flags,
        [(false, false), (true, false), (false, true), (true, true)]
    );
    assert_eq!(built.possible_type_pairs().count(), 1);
}

#[test]
fn a_stored_field_with_an_invalid_name_or_a_duplicate_is_unavailable() {
    let invalid = field_row("1Query", "a", (false, false));
    let first = field_row("Query", "a", (false, false));
    let second = field_row("Query", "a", (false, false));
    let bad_pair = PossibleTypeRow {
        spec_id: sql(SPEC),
        abstract_type: "Node".to_owned(),
        possible_type: "not a name".to_owned(),
    };

    assert!(matches!(
        graph(&[invalid], &[]),
        Err(RepositoryError::Unavailable(_))
    ));
    assert!(matches!(
        graph(&[first, second], &[]),
        Err(RepositoryError::Unavailable(_))
    ));
    assert!(matches!(
        graph(&[], &[bad_pair]),
        Err(RepositoryError::Unavailable(_))
    ));
}

#[test]
fn a_field_row_becomes_a_coordinate_with_its_return_type() {
    let (coordinate, found) = field(&field_row("Query", "a", (true, false))).unwrap();

    assert_eq!(coordinate.to_string(), "Query.a");
    assert_eq!(found.return_type.as_str(), "String");
    assert!(found.flags.is_sensitive());
    assert!(name("Valid_1").is_ok());
    assert!(name("1 invalid").is_err());
}

#[test]
fn rows_are_grouped_by_their_key() {
    let other = "7f1c2a4e-1d0b-4f5e-9a3c-2b6d8e0f1a2b";
    let rows = vec![
        PossibleTypeRow {
            spec_id: sql(SPEC),
            abstract_type: "A".to_owned(),
            possible_type: "B".to_owned(),
        },
        PossibleTypeRow {
            spec_id: sql(other),
            abstract_type: "C".to_owned(),
            possible_type: "D".to_owned(),
        },
        PossibleTypeRow {
            spec_id: sql(SPEC),
            abstract_type: "E".to_owned(),
            possible_type: "F".to_owned(),
        },
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
