use super::AnalyzedDocument;
use crate::value_object::coordinate_set::CoordinateSet;
use crate::value_object::graphql_coordinate::GraphQlCoordinate;
use crate::value_object::permission_flags::PermissionFlags;

#[test]
fn exposes_its_parts() {
    let coordinates: CoordinateSet = std::iter::once((
        GraphQlCoordinate::parse("Query.orders").unwrap(),
        PermissionFlags::NONE,
    ))
    .collect();

    let analyzed = AnalyzedDocument::new(coordinates.clone(), true);

    assert_eq!(analyzed.coordinates(), &coordinates);
    assert!(analyzed.introspection());
}

#[test]
fn the_default_selects_nothing() {
    let analyzed = AnalyzedDocument::default();

    assert!(analyzed.coordinates().is_empty());
    assert!(!analyzed.introspection());
}
