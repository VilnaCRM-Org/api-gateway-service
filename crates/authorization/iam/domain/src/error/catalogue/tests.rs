use rstest::rstest;

use super::{InvalidCatalogueEntry, RenameRefused};
use crate::value_object::permission_key::{PermissionKey, PermissionKeyKind};

fn key(value: &str) -> PermissionKey {
    PermissionKey::parse(value).unwrap()
}

#[test]
fn an_entry_of_the_wrong_form_names_the_expected_form() {
    let error = InvalidCatalogueEntry::KeyKind {
        expected: "gql",
        found: PermissionKeyKind::Rest,
    };

    assert_eq!(
        error.to_string(),
        "This catalogue entry holds gql keys only."
    );
}

#[rstest]
#[case(
    RenameRefused::Unchanged { key: key("gql:billing:Query.a").to_string() },
    "The key gql:billing:Query.a cannot be renamed to itself."
)]
#[case(
    RenameRefused::Scope { from: key("gql:billing:Query.a").to_string(), to: key("gql:orders:Query.a").to_string() },
    "The key gql:billing:Query.a cannot be renamed to gql:orders:Query.a: both must be keys of one service and form."
)]
#[case(
    RenameRefused::Chained { key: key("gql:billing:Query.b").to_string() },
    "The key gql:billing:Query.b cannot be both renamed and the target of a rename."
)]
#[case(
    RenameRefused::Duplicate { key: key("gql:billing:Query.a").to_string() },
    "The key gql:billing:Query.a is renamed more than once."
)]
#[case(
    RenameRefused::OutsideCatalogue { key: key("rest:billing:GET /a").to_string() },
    "The key rest:billing:GET /a does not belong to the catalogue of this service and form."
)]
#[case(
    RenameRefused::TargetMissing { to: key("gql:billing:Query.b").to_string() },
    "The new key gql:billing:Query.b is not in the catalogue."
)]
#[case(
    RenameRefused::SourceStillPresent { from: key("gql:billing:Query.a").to_string() },
    "The old key gql:billing:Query.a is still in the catalogue."
)]
fn a_refused_rename_names_the_keys_involved(#[case] error: RenameRefused, #[case] message: &str) {
    assert_eq!(error.to_string(), message);
}
