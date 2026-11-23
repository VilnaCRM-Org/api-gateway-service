use std::fmt::Write as _;

use iam_domain::{
    AnalyzedDocument, DocumentLimits, DocumentRefusal, GraphQlCoordinate,
    GraphQlDocumentAnalyzer as _, GraphQlSchemaParser as _, GraphQlTypeGraph, LimitKind,
    PermissionFlags,
};
use rstest::rstest;

use super::AsyncGraphQlDocumentAnalyzer;
use crate::graphql::AsyncGraphQlSchemaParser;

const SDL: &str = "
type Query {
  me: User
  node(id: ID): Node
  search: [SearchResult]
  orders: [Order]
}
type Mutation { pay: Payment @iamSensitive }
type Subscription { orderChanged: Order }
interface Node { id: ID }
type User implements Node { id: ID name: String friend: User }
type Order implements Node { id: ID total: Int }
union SearchResult = User | Order
type Payment { id: ID }
";

fn graph() -> GraphQlTypeGraph {
    AsyncGraphQlSchemaParser.parse(SDL).unwrap()
}

fn analyze_with(
    document: &str,
    operation_name: Option<&str>,
    limits: &DocumentLimits,
) -> Result<AnalyzedDocument, DocumentRefusal> {
    AsyncGraphQlDocumentAnalyzer.analyze(document, operation_name, &graph(), limits)
}

fn analyze(document: &str) -> Result<AnalyzedDocument, DocumentRefusal> {
    analyze_with(document, None, &DocumentLimits::decision_api())
}

fn coordinates(analyzed: &AnalyzedDocument) -> Vec<String> {
    analyzed
        .coordinates()
        .iter()
        .map(|(coordinate, _)| coordinate.to_string())
        .collect()
}

#[rstest]
#[case::plain_fields("{ me { name } }", &["Query.me", "User.name"])]
#[case::aliases("{ a: me { n: name } }", &["Query.me", "User.name"])]
#[case::named_fragment(
    "{ me { ...Parts } } fragment Parts on User { name }",
    &["Query.me", "User.name"]
)]
#[case::the_same_fragment_twice(
    "{ me { ...Parts } other: me { ...Parts } } fragment Parts on User { name }",
    &["Query.me", "User.name"]
)]
#[case::nested_fragments(
    "{ me { ...Outer } } fragment Outer on User { ...Inner } fragment Inner on User { name }",
    &["Query.me", "User.name"]
)]
#[case::interface_outside_a_concrete_fragment(
    r#"{ node(id: "1") { id } }"#,
    &["Node.id", "Query.node"]
)]
#[case::concrete_inline_fragments(
    r#"{ node(id: "1") { id ... on User { name } ... on Order { total } } }"#,
    &["Node.id", "Order.total", "Query.node", "User.name"]
)]
#[case::a_fragment_on_the_interface(
    "{ me { ...Ident } } fragment Ident on Node { id }",
    &["Node.id", "Query.me"]
)]
#[case::an_inline_fragment_without_a_type_condition(
    "{ me { ... @include(if: true) { name } } }",
    &["Query.me", "User.name"]
)]
#[case::a_union_with_type_conditions(
    "{ search { __typename ... on User { name } ... on Order { total } } }",
    &["Order.total", "Query.search", "User.name"]
)]
#[case::typename_is_ignored("{ me { __typename } __typename }", &["Query.me"])]
#[case::a_mutation("mutation { pay { id } }", &["Mutation.pay", "Payment.id"])]
#[case::a_subscription(
    "subscription { orderChanged { total } }",
    &["Order.total", "Subscription.orderChanged"]
)]
fn extracts_the_coordinates_of_a_document(#[case] document: &str, #[case] expected: &[&str]) {
    let analyzed = analyze(document).unwrap();

    assert_eq!(coordinates(&analyzed), expected);
    assert!(!analyzed.introspection());
}

#[rstest]
#[case::schema("{ __schema { types { name } } }", &[])]
#[case::type_lookup(r#"{ __type(name: "User") { name } me { name } }"#, &["Query.me", "User.name"])]
#[case::in_a_root_fragment(
    "{ ...Meta } fragment Meta on Query { __schema { types { name } } }",
    &[]
)]
#[case::in_an_inline_root_fragment("{ ... on Query { __type(name: \"A\") { name } } }", &[])]
fn maps_introspection_to_its_flag(#[case] document: &str, #[case] expected: &[&str]) {
    let analyzed = analyze(document).unwrap();

    assert!(analyzed.introspection());
    assert_eq!(coordinates(&analyzed), expected);
}

#[test]
fn keeps_the_flags_of_the_type_graph() {
    let analyzed = analyze("mutation { pay { id } }").unwrap();
    let pay = GraphQlCoordinate::parse("Mutation.pay").unwrap();
    let id = GraphQlCoordinate::parse("Payment.id").unwrap();

    assert_eq!(
        analyzed.coordinates().flags(&pay),
        Some(PermissionFlags::NONE.with_sensitive())
    );
    assert_eq!(
        analyzed.coordinates().flags(&id),
        Some(PermissionFlags::NONE)
    );
}

#[test]
fn selects_the_named_operation() {
    let document = "query A { me { name } } query B { orders { total } }";

    let analyzed = analyze_with(document, Some("B"), &DocumentLimits::decision_api()).unwrap();

    assert_eq!(coordinates(&analyzed), ["Order.total", "Query.orders"]);
}

#[test]
fn runs_the_only_named_operation_without_a_name() {
    assert!(analyze("query A { me { name } }").is_ok());
}

#[rstest]
#[case::missing_name("query A { me { name } } query B { orders { total } }", None)]
#[case::unknown_name("query A { me { name } }", Some("Z"))]
#[case::a_name_for_an_anonymous_operation("{ me { name } }", Some("A"))]
fn refuses_a_missing_or_unknown_operation(#[case] document: &str, #[case] name: Option<&str>) {
    let result = analyze_with(document, name, &DocumentLimits::decision_api());

    assert_eq!(result, Err(DocumentRefusal::MalformedOperation));
}

#[rstest]
#[case::a_syntax_error("{ me { ")]
#[case::an_empty_document("")]
#[case::a_leaf_with_a_selection("{ me { name { x } } }")]
#[case::a_composite_without_a_selection("{ me }")]
#[case::a_field_of_a_union("{ search { name } }")]
#[case::an_undefined_fragment("{ me { ...Nope } }")]
#[case::an_unknown_type_condition("{ me { ... on Nope { name } } }")]
#[case::a_leaf_type_condition("{ me { ... on String { name } } }")]
#[case::a_type_condition_that_cannot_apply("{ me { ... on Order { total } } }")]
#[case::a_fragment_that_cannot_apply("{ me { ...Cart } } fragment Cart on Order { total }")]
#[case::an_introspection_type_condition("{ me { ... on __Type { name } } }")]
#[case::a_cycle_of_fragments(
    "{ me { ...A } } fragment A on User { ...B } fragment B on User { ...A }"
)]
#[case::introspection_below_the_root("{ me { __schema } }")]
#[case::another_reserved_field("{ __other }")]
#[case::a_root_fragment_in_a_mutation("mutation { ...Q } fragment Q on Query { me { name } }")]
fn refuses_a_document_that_does_not_validate(#[case] document: &str) {
    assert_eq!(analyze(document), Err(DocumentRefusal::MalformedOperation));
}

#[rstest]
#[case::a_root_field("{ nothing }")]
#[case::a_field_of_an_object("{ me { nope } }")]
#[case::a_field_in_a_fragment("{ me { ...F } } fragment F on User { nope }")]
#[case::a_field_of_an_interface(r#"{ node(id: "1") { nope } }"#)]
fn names_a_field_unknown_to_the_catalogue(#[case] document: &str) {
    assert_eq!(analyze(document), Err(DocumentRefusal::UnknownOperation));
}

fn limits_exceeded(kind: LimitKind) -> Result<AnalyzedDocument, DocumentRefusal> {
    Err(DocumentRefusal::LimitsExceeded(kind))
}

#[test]
fn accepts_a_document_of_exactly_the_byte_limit() {
    let document = format!("{{ me {{ name }} }}{}", " ".repeat(65_536 - 15));

    assert_eq!(document.len(), DocumentLimits::DECISION_API_BYTES);
    assert!(analyze(&document).is_ok());
}

#[test]
fn refuses_a_document_over_the_byte_limit_before_parsing() {
    let document = format!(
        "{{ me {{ {}",
        " ".repeat(DocumentLimits::DECISION_API_BYTES)
    );

    assert_eq!(analyze(&document), limits_exceeded(LimitKind::Bytes));
}

#[test]
fn a_route_limit_replaces_the_byte_limit() {
    let limits = DocumentLimits::decision_api().with_bytes(8);

    let result = analyze_with("{ me { name } }", None, &limits);

    assert_eq!(result, limits_exceeded(LimitKind::Bytes));
}

/// A document whose deepest selection is `levels` fields deep: `me`, `friend` repeated and `name`.
fn nested(levels: usize) -> String {
    let friends = levels.checked_sub(2).unwrap();
    format!(
        "{{ me {{ {}name {}}} }}",
        "friend { ".repeat(friends),
        "} ".repeat(friends)
    )
}

#[test]
fn accepts_a_document_of_exactly_the_depth_limit() {
    let analyzed = analyze(&nested(15)).unwrap();

    assert_eq!(
        coordinates(&analyzed),
        ["Query.me", "User.friend", "User.name"]
    );
}

#[test]
fn refuses_a_document_deeper_than_the_limit() {
    assert_eq!(analyze(&nested(16)), limits_exceeded(LimitKind::Depth));
}

#[test]
fn counts_the_depth_through_fragments() {
    let document = "{ me { ...A } } fragment A on User { friend { ...B } } \
                    fragment B on User { friend { name } }";
    // `me`, `friend`, `friend` and `name`: four levels once both fragments are expanded.
    let limits = DocumentLimits {
        depth: 3,
        ..DocumentLimits::decision_api()
    };

    assert_eq!(
        analyze_with(document, None, &limits),
        limits_exceeded(LimitKind::Depth)
    );
    assert!(analyze_with(document, None, &DocumentLimits { depth: 4, ..limits }).is_ok());
}

#[test]
fn refuses_nesting_that_would_overflow_the_parser_as_over_the_depth_limit() {
    let document = "{ a ".repeat(70);

    assert_eq!(analyze(&document), limits_exceeded(LimitKind::Depth));
}

#[test]
fn ignores_brackets_in_strings_and_comments_when_measuring_nesting() {
    let noise = "(".repeat(100);
    let document = format!("# {noise}\n{{ node(id: \"{noise}\") {{ id }} }}");

    assert!(analyze(&document).is_ok());
}

#[test]
fn accepts_exactly_the_coordinate_limit() {
    let document = format!("{{ {} }}", "__typename ".repeat(500));

    assert!(analyze(&document).is_ok());
}

#[test]
fn refuses_more_than_the_coordinate_limit_before_resolution() {
    // `nothing` is unknown, so a refusal as `limits_exceeded` proves the count came first.
    let document = format!("{{ {} }}", "nothing ".repeat(501));

    assert_eq!(analyze(&document), limits_exceeded(LimitKind::Coordinates));
}

#[test]
fn counts_the_fields_of_inline_fragments_and_fragments() {
    let document = "{ me { ... on User { name } ...F } } fragment F on User { name friend { id } }";
    // Five field selections: `me`, `name` of the inline fragment, and `name`, `friend` and `id`
    // of the fragment.
    let limits = DocumentLimits {
        coordinates: 4,
        ..DocumentLimits::decision_api()
    };

    assert_eq!(
        analyze_with(document, None, &limits),
        limits_exceeded(LimitKind::Coordinates)
    );
    assert!(
        analyze_with(
            document,
            None,
            &DocumentLimits {
                coordinates: 5,
                ..limits
            }
        )
        .is_ok()
    );
}

fn aliased(count: usize) -> String {
    let fields = (0..count).fold(String::new(), |mut fields, index| {
        write!(fields, "a{index}: me {{ name }} ").unwrap();
        fields
    });
    format!("{{ {fields}}}")
}

#[test]
fn accepts_exactly_the_alias_limit() {
    assert!(analyze(&aliased(50)).is_ok());
}

#[test]
fn refuses_more_than_the_alias_limit() {
    assert_eq!(analyze(&aliased(51)), limits_exceeded(LimitKind::Aliases));
}

fn with_fragments(count: usize) -> String {
    let definitions = (0..count).fold(String::new(), |mut definitions, index| {
        write!(definitions, "fragment F{index} on User {{ name }} ").unwrap();
        definitions
    });
    format!("{{ me {{ ...F0 }} }} {definitions}")
}

#[test]
fn accepts_exactly_the_fragment_limit() {
    assert!(analyze(&with_fragments(100)).is_ok());
}

#[test]
fn refuses_more_than_the_fragment_limit() {
    assert_eq!(
        analyze(&with_fragments(101)),
        limits_exceeded(LimitKind::Fragments)
    );
}

#[test]
fn a_limit_refusal_wins_over_a_malformed_selection() {
    let definitions = with_fragments(101);
    let document = definitions.replace("{ me { ...F0 } }", "{ nothing { ...Missing } }");

    assert_eq!(analyze(&document), limits_exceeded(LimitKind::Fragments));
}

#[test]
fn does_not_expand_fragments_exponentially() {
    let mut document = String::from("{ me { ...F0 } } ");
    for (index, next) in (0..40).zip(1..) {
        write!(
            document,
            "fragment F{index} on User {{ ...F{next} ...F{next} }} "
        )
        .unwrap();
    }
    document.push_str("fragment F40 on User { name }");

    let analyzed = analyze(&document).unwrap();

    assert_eq!(coordinates(&analyzed), ["Query.me", "User.name"]);
}
