use super::{GraphQlField, GraphQlTypeGraph};
use crate::error::InvalidSpec;
use crate::value_object::gql_name::GqlName;
use crate::value_object::graphql_coordinate::GraphQlCoordinate;
use crate::value_object::permission_flags::PermissionFlags;

fn name(value: &str) -> GqlName {
    GqlName::parse(value).unwrap()
}

fn coordinate(value: &str) -> GraphQlCoordinate {
    GraphQlCoordinate::parse(value).unwrap()
}

fn field(
    text: &str,
    return_type: &str,
    flags: PermissionFlags,
) -> (GraphQlCoordinate, GraphQlField) {
    (
        coordinate(text),
        GraphQlField {
            return_type: name(return_type),
            flags,
        },
    )
}

fn possible(abstract_type: &str, member: &str) -> (GqlName, GqlName) {
    (name(abstract_type), name(member))
}

const SENSITIVE: PermissionFlags = PermissionFlags::NONE.with_sensitive();

fn graph() -> GraphQlTypeGraph {
    GraphQlTypeGraph::new(
        [
            field("Query.node", "Node", PermissionFlags::NONE),
            field("Query.search", "SearchResult", PermissionFlags::NONE),
            field("Mutation.pay", "Payment", SENSITIVE),
            field("Invoice.id", "ID", PermissionFlags::NONE),
            field("Order.id", "ID", PermissionFlags::NONE),
        ],
        [
            possible("Node", "Order"),
            possible("Node", "Invoice"),
            possible("SearchResult", "Invoice"),
        ],
    )
    .unwrap()
}

#[test]
fn holds_every_field_with_its_return_type_and_flags() {
    let graph = graph();

    assert_eq!(graph.field_count(), 5);
    assert_eq!(
        graph.field(&coordinate("Mutation.pay")),
        Some(&GraphQlField {
            return_type: name("Payment"),
            flags: SENSITIVE,
        })
    );
    assert_eq!(graph.field(&coordinate("Mutation.refund")), None);
    let order: Vec<String> = graph
        .fields()
        .map(|(coordinate, _field)| coordinate.to_string())
        .collect();
    assert_eq!(
        order,
        [
            "Invoice.id",
            "Mutation.pay",
            "Order.id",
            "Query.node",
            "Query.search"
        ]
    );
}

#[test]
fn holds_the_possible_types_of_interfaces_and_unions() {
    let graph = graph();

    let node: Vec<&GqlName> = graph.possible_types(&name("Node")).collect();
    assert_eq!(node, [&name("Invoice"), &name("Order")]);
    let search: Vec<&GqlName> = graph.possible_types(&name("SearchResult")).collect();
    assert_eq!(search, [&name("Invoice")]);
    assert_eq!(graph.possible_types(&name("Invoice")).count(), 0);
}

#[test]
fn lists_every_pair_of_an_abstract_type_and_a_possible_type_in_name_order() {
    let graph = graph();

    let pairs: Vec<(&GqlName, &GqlName)> = graph.possible_type_pairs().collect();

    assert_eq!(
        pairs,
        [
            (&name("Node"), &name("Invoice")),
            (&name("Node"), &name("Order")),
            (&name("SearchResult"), &name("Invoice")),
        ]
    );
    assert_eq!(GraphQlTypeGraph::default().possible_type_pairs().count(), 0);
}

#[test]
fn counts_declaring_abstract_and_possible_types_once() {
    // Query, Mutation, Invoice, Order, Node, SearchResult.
    assert_eq!(graph().type_count(), 6);
}

#[test]
fn exposes_its_coordinates_with_their_flags() {
    let coordinates = graph().coordinates();

    assert_eq!(coordinates.len(), 5);
    assert_eq!(
        coordinates.flags(&coordinate("Mutation.pay")),
        Some(SENSITIVE)
    );
    assert_eq!(
        coordinates.flags(&coordinate("Query.node")),
        Some(PermissionFlags::NONE)
    );
}

#[test]
fn an_empty_graph_has_nothing() {
    let graph = GraphQlTypeGraph::new([], []).unwrap();

    assert_eq!(graph, GraphQlTypeGraph::default());
    assert_eq!(graph.field_count(), 0);
    assert_eq!(graph.type_count(), 0);
    assert!(graph.coordinates().is_empty());
}

#[test]
fn refuses_a_coordinate_given_twice() {
    let result = GraphQlTypeGraph::new(
        [
            field("Query.me", "User", PermissionFlags::NONE),
            field("Query.me", "Account", SENSITIVE),
        ],
        [],
    );

    assert_eq!(
        result,
        Err(InvalidSpec::DuplicateField {
            coordinate: "Query.me".to_owned()
        })
    );
}

/// `count` fields named `f0`, `f1`, … on the type `T`.
fn fields_on_one_type(count: usize) -> Vec<(GraphQlCoordinate, GraphQlField)> {
    (0..count)
        .map(|index| field(&format!("T.f{index}"), "String", PermissionFlags::NONE))
        .collect()
}

#[test]
fn accepts_exactly_the_field_limit() {
    let graph =
        GraphQlTypeGraph::new(fields_on_one_type(GraphQlTypeGraph::MAX_FIELDS), []).unwrap();

    assert_eq!(graph.field_count(), 100_000);
}

#[test]
fn refuses_one_field_more_than_the_limit() {
    let result = GraphQlTypeGraph::new(fields_on_one_type(GraphQlTypeGraph::MAX_FIELDS + 1), []);

    assert_eq!(result, Err(InvalidSpec::TooManyFields { limit: 100_000 }));
}

/// One field on each of `count` types named `T0`, `T1`, ….
fn types(count: usize) -> Vec<(GraphQlCoordinate, GraphQlField)> {
    (0..count)
        .map(|index| field(&format!("T{index}.id"), "ID", PermissionFlags::NONE))
        .collect()
}

#[test]
fn accepts_exactly_the_type_limit() {
    let graph = GraphQlTypeGraph::new(types(GraphQlTypeGraph::MAX_TYPES), []).unwrap();

    assert_eq!(graph.type_count(), 10_000);
}

#[test]
fn accepts_abstract_types_that_reach_exactly_the_type_limit() {
    let graph = GraphQlTypeGraph::new(
        types(GraphQlTypeGraph::MAX_TYPES - 2),
        [possible("Node", "T0"), possible("Other", "T1")],
    )
    .unwrap();

    assert_eq!(graph.type_count(), 10_000);
}

#[test]
fn refuses_one_type_more_than_the_limit() {
    let result = GraphQlTypeGraph::new(
        types(GraphQlTypeGraph::MAX_TYPES - 1),
        [possible("Node", "T0"), possible("Other", "T1")],
    );

    assert_eq!(result, Err(InvalidSpec::TooManyTypes { limit: 10_000 }));
}

fn overlap_graph() -> GraphQlTypeGraph {
    GraphQlTypeGraph::new(
        [
            field("Query.node", "Node", PermissionFlags::NONE),
            field("Node.id", "ID", PermissionFlags::NONE),
            field("User.id", "ID", PermissionFlags::NONE),
            field("Order.id", "ID", PermissionFlags::NONE),
            field("Zed.id", "ID", PermissionFlags::NONE),
        ],
        [
            possible("Node", "User"),
            possible("Node", "Order"),
            possible("Hit", "User"),
            possible("Hit", "Zed"),
            possible("Search", "Zed"),
        ],
    )
    .unwrap()
}

#[test]
fn a_type_declares_fields_only_when_it_has_some() {
    let graph = overlap_graph();

    assert!(graph.declares_fields(&name("User")));
    assert!(graph.declares_fields(&name("Query")));
    assert!(!graph.declares_fields(&name("Search")));
    assert!(!graph.declares_fields(&name("ID")));
    assert!(!graph.declares_fields(&name("Aaa")));
}

#[test]
fn a_type_is_composite_with_fields_or_possible_types() {
    let graph = overlap_graph();

    assert!(graph.is_composite(&name("User")));
    assert!(graph.is_composite(&name("Search")));
    assert!(!graph.is_composite(&name("ID")));
}

#[test]
fn types_overlap_by_equality_membership_or_a_shared_member() {
    let graph = overlap_graph();

    assert!(graph.types_overlap(&name("User"), &name("User")));
    assert!(graph.types_overlap(&name("Node"), &name("User")));
    assert!(graph.types_overlap(&name("User"), &name("Node")));
    assert!(graph.types_overlap(&name("Node"), &name("Hit")));
    assert!(!graph.types_overlap(&name("Node"), &name("Search")));
    assert!(!graph.types_overlap(&name("User"), &name("Order")));
}
