use super::CoordinateSet;
use crate::value_object::graphql_coordinate::GraphQlCoordinate;
use crate::value_object::permission_flags::PermissionFlags;

fn coordinate(value: &str) -> GraphQlCoordinate {
    GraphQlCoordinate::parse(value).unwrap()
}

const SENSITIVE: PermissionFlags = PermissionFlags::NONE.with_sensitive();
const AUDIT: PermissionFlags = PermissionFlags::NONE.with_audit_always();

#[test]
fn a_new_set_is_empty() {
    let set = CoordinateSet::new();

    assert!(set.is_empty());
    assert_eq!(set.len(), 0);
    assert_eq!(set, CoordinateSet::default());
    assert_eq!(set.iter().count(), 0);
}

#[test]
fn keeps_distinct_coordinates_in_order_with_their_flags() {
    let set: CoordinateSet = [
        (coordinate("Query.orders"), PermissionFlags::NONE),
        (coordinate("Mutation.pay"), SENSITIVE),
        (coordinate("Query.invoices"), AUDIT),
    ]
    .into_iter()
    .collect();

    assert_eq!(set.len(), 3);
    assert!(!set.is_empty());
    assert!(set.contains(&coordinate("Mutation.pay")));
    assert!(!set.contains(&coordinate("Mutation.refund")));
    assert_eq!(set.flags(&coordinate("Mutation.pay")), Some(SENSITIVE));
    assert_eq!(set.flags(&coordinate("Mutation.refund")), None);
    let order: Vec<String> = set
        .iter()
        .map(|(coordinate, _flags)| coordinate.to_string())
        .collect();
    assert_eq!(order, ["Mutation.pay", "Query.invoices", "Query.orders"]);
}

#[test]
fn a_repeated_coordinate_keeps_the_most_restrictive_flags() {
    let mut set = CoordinateSet::new();
    set.insert(coordinate("Query.me"), SENSITIVE);
    set.insert(coordinate("Query.me"), AUDIT);
    set.insert(coordinate("Query.me"), PermissionFlags::NONE);

    assert_eq!(set.len(), 1);
    assert_eq!(
        set.flags(&coordinate("Query.me")),
        Some(SENSITIVE.with_audit_always())
    );
}

#[test]
fn the_union_holds_both_sides_with_combined_flags() {
    let left: CoordinateSet = [
        (coordinate("Query.a"), SENSITIVE),
        (coordinate("Query.b"), PermissionFlags::NONE),
    ]
    .into_iter()
    .collect();
    let right: CoordinateSet = [
        (coordinate("Query.b"), AUDIT),
        (coordinate("Query.c"), PermissionFlags::NONE),
    ]
    .into_iter()
    .collect();

    let union = left.union(&right);

    assert_eq!(union, right.union(&left));
    assert_eq!(union.len(), 3);
    assert_eq!(union.flags(&coordinate("Query.a")), Some(SENSITIVE));
    assert_eq!(union.flags(&coordinate("Query.b")), Some(AUDIT));
    assert_eq!(
        union.flags(&coordinate("Query.c")),
        Some(PermissionFlags::NONE)
    );
}
