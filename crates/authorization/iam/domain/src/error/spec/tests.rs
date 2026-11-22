use rstest::rstest;

use super::{InvalidSpec, SpecPosition, SpecTransitionRefused};
use crate::value_object::spec_status::SpecStatus;

fn line_column(line: u32, column: u32) -> SpecPosition {
    SpecPosition::LineColumn { line, column }
}

#[rstest]
#[case(
    InvalidSpec::TooLarge { limit: 5_242_880 },
    "sdl",
    "length",
    "The document must be at most 5242880 bytes."
)]
#[case(
    InvalidSpec::TooManyTypes { limit: 10_000 },
    "sdl",
    "count",
    "The document must define 10000 types or fewer."
)]
#[case(
    InvalidSpec::TooManyFields { limit: 100_000 },
    "sdl",
    "count",
    "The document must define 100000 fields or fewer."
)]
#[case(
    InvalidSpec::Malformed { message: "Unexpected `}`".to_owned(), position: line_column(3, 7) },
    "sdl",
    "syntax",
    "Unexpected `}` (line 3, column 7)"
)]
#[case(
    InvalidSpec::Malformed {
        message: "External reference".to_owned(),
        position: SpecPosition::JsonPointer("/paths/~1users/get".to_owned()),
    },
    "document",
    "syntax",
    "External reference (pointer /paths/~1users/get)"
)]
#[case(
    InvalidSpec::DuplicateField { coordinate: "Query.me".to_owned() },
    "sdl",
    "duplicate",
    "The field Query.me is defined more than once."
)]
fn an_invalid_spec_exposes_the_property_path_the_code_and_the_message(
    #[case] error: InvalidSpec,
    #[case] property_path: &str,
    #[case] code: &str,
    #[case] message: &str,
) {
    assert_eq!(error.property_path(), property_path);
    assert_eq!(error.code(), code);
    assert_eq!(error.to_string(), message);
}

#[test]
fn only_a_malformed_document_carries_its_position() {
    let malformed = InvalidSpec::Malformed {
        message: "Unexpected end".to_owned(),
        position: line_column(12, 1),
    };

    assert_eq!(malformed.position(), Some(&line_column(12, 1)));
    assert_eq!(InvalidSpec::TooLarge { limit: 1 }.position(), None);
    assert_eq!(InvalidSpec::TooManyTypes { limit: 1 }.position(), None);
    assert_eq!(InvalidSpec::TooManyFields { limit: 1 }.position(), None);
    assert_eq!(
        InvalidSpec::DuplicateField {
            coordinate: "A.b".to_owned()
        }
        .position(),
        None
    );
}

#[test]
fn a_refused_transition_names_both_statuses() {
    let refused = SpecTransitionRefused {
        from: SpecStatus::Draft,
        to: SpecStatus::Retired,
    };

    assert_eq!(
        refused.to_string(),
        "A draft specification version cannot become retired."
    );
    assert_eq!(SpecTransitionRefused::CODE, "status_transition");
    assert_eq!(SpecTransitionRefused::PROPERTY_PATH, "status");
}
