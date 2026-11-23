use iam_domain::{
    GqlName, GraphQlCoordinate, GraphQlSchemaParser as _, GraphQlSpec, GraphQlTypeGraph,
    InvalidSpec, SpecPosition,
};

use super::AsyncGraphQlSchemaParser;

const SDL: &str = "
directive @iamSensitive on FIELD_DEFINITION
directive @iamAuditAlways on FIELD_DEFINITION

type Query {
  user(id: ID!): User
  nodes: [Node!]!
  search: [SearchResult]
}

type Mutation {
  deleteUser(id: ID!): Boolean! @iamSensitive @iamAuditAlways
  renameUser(id: ID!): User @iamAuditAlways
}

type Subscription {
  userChanged: User
}

interface Node {
  id: ID!
}

type User implements Node {
  id: ID!
  email: String! @iamSensitive
}

type Team implements Node {
  id: ID!
}

union SearchResult = User | Team

enum Role { ADMIN }
input UserInput { name: String }
scalar Date
";

fn name(value: &str) -> GqlName {
    GqlName::parse(value).unwrap()
}

fn coordinate(value: &str) -> GraphQlCoordinate {
    GraphQlCoordinate::parse(value).unwrap()
}

fn parse(sdl: &str) -> Result<GraphQlTypeGraph, InvalidSpec> {
    AsyncGraphQlSchemaParser.parse(sdl)
}

fn possible(graph: &GraphQlTypeGraph, abstract_type: &str) -> Vec<String> {
    graph
        .possible_types(&name(abstract_type))
        .map(|member| member.as_str().to_owned())
        .collect()
}

#[test]
fn a_valid_document_yields_every_coordinate_with_its_return_type() {
    let graph = parse(SDL).unwrap();

    let coordinates: Vec<String> = graph.fields().map(|(key, _)| key.to_string()).collect();
    assert_eq!(
        coordinates,
        [
            "Mutation.deleteUser",
            "Mutation.renameUser",
            "Node.id",
            "Query.nodes",
            "Query.search",
            "Query.user",
            "Subscription.userChanged",
            "Team.id",
            "User.email",
            "User.id",
        ]
    );
    let returns = |text: &str| {
        graph
            .field(&coordinate(text))
            .map(|field| field.return_type.as_str().to_owned())
    };
    assert_eq!(returns("Query.nodes").as_deref(), Some("Node"));
    assert_eq!(returns("Query.search").as_deref(), Some("SearchResult"));
    assert_eq!(returns("Query.user").as_deref(), Some("User"));
    assert_eq!(returns("Mutation.deleteUser").as_deref(), Some("Boolean"));
}

#[test]
fn the_possible_types_of_interfaces_and_unions_are_recorded() {
    let graph = parse(SDL).unwrap();

    assert_eq!(possible(&graph, "Node"), ["Team", "User"]);
    assert_eq!(possible(&graph, "SearchResult"), ["Team", "User"]);
    assert_eq!(possible(&graph, "User"), Vec::<String>::new());
}

#[test]
fn the_directives_set_the_sensitive_and_always_audit_flags() {
    let graph = parse(SDL).unwrap();
    let flags = |text: &str| graph.field(&coordinate(text)).unwrap().flags;

    let both = flags("Mutation.deleteUser");
    assert!(both.is_sensitive() && both.is_audit_always());
    let audit = flags("Mutation.renameUser");
    assert!(!audit.is_sensitive() && audit.is_audit_always());
    let sensitive = flags("User.email");
    assert!(sensitive.is_sensitive() && !sensitive.is_audit_always());
    let none = flags("User.id");
    assert!(!none.is_sensitive() && !none.is_audit_always());
}

#[test]
fn renamed_root_types_get_the_root_coordinates() {
    let graph = parse(
        "schema { query: Root mutation: Changes subscription: Events }
         type Root { a: Int }
         type Changes { b: Int }
         type Events { c: Int }",
    )
    .unwrap();

    let coordinates: Vec<String> = graph.fields().map(|(key, _)| key.to_string()).collect();
    assert_eq!(coordinates, ["Mutation.b", "Query.a", "Subscription.c"]);
}

#[test]
fn an_extension_adds_fields_to_its_type() {
    let graph = parse("type Query { a: Int } extend type Query { b: Int }").unwrap();

    assert_eq!(graph.field_count(), 2);
}

#[test]
fn a_syntax_error_carries_the_line_and_column() {
    let error = parse("type Query {\n  a: Int\n}\ntype {").unwrap_err();

    let InvalidSpec::Malformed { position, .. } = error else {
        panic!("expected Malformed, got {error:?}");
    };
    let SpecPosition::LineColumn { line, column } = position else {
        panic!("expected a line and column, got {position:?}");
    };
    assert_eq!(line, 4);
    assert!(column >= 1);
}

#[test]
fn a_schema_error_carries_a_position() {
    let error = parse("schema { query: A query: B }").unwrap_err();

    assert!(matches!(
        error,
        InvalidSpec::Malformed {
            position: SpecPosition::LineColumn { line: 1, .. },
            ..
        }
    ));
}

#[test]
fn a_reserved_field_name_is_malformed_at_its_position() {
    let error = parse("type Query {\n  __x: Int\n}").unwrap_err();

    assert!(matches!(
        error,
        InvalidSpec::Malformed {
            position: SpecPosition::LineColumn { line: 2, .. },
            ..
        }
    ));
}

#[test]
fn a_reserved_type_name_is_malformed() {
    let error = parse("type __T { a: Int }").unwrap_err();

    assert!(matches!(error, InvalidSpec::Malformed { .. }));
}

#[test]
fn a_reserved_return_type_name_is_malformed() {
    let error = parse("type Query { a: __T }").unwrap_err();

    assert!(matches!(error, InvalidSpec::Malformed { .. }));
}

#[test]
fn a_field_defined_twice_is_a_duplicate() {
    let error = parse("type Query { a: Int } extend type Query { a: Int }").unwrap_err();

    assert_eq!(
        error,
        InvalidSpec::DuplicateField {
            coordinate: "Query.a".to_owned()
        }
    );
}

#[test]
fn a_document_over_the_size_limit_is_refused_before_parsing() {
    // Not valid SDL: a parse would answer Malformed, so TooLarge proves the size check came first.
    let sdl = "}".repeat(GraphQlSpec::MAX_SDL_BYTES + 1);

    assert_eq!(
        parse(&sdl).unwrap_err(),
        InvalidSpec::TooLarge {
            limit: GraphQlSpec::MAX_SDL_BYTES
        }
    );
}

#[test]
fn a_document_of_exactly_the_size_limit_is_parsed() {
    let mut sdl = "type Query { a: Int }".to_owned();
    sdl.push_str(&" ".repeat(GraphQlSpec::MAX_SDL_BYTES - sdl.len()));

    assert_eq!(sdl.len(), GraphQlSpec::MAX_SDL_BYTES);
    assert_eq!(parse(&sdl).unwrap().field_count(), 1);
}

fn types(count: usize) -> String {
    (0..count)
        .map(|index| format!("type T{index} {{ a: Int }}\n"))
        .collect::<Vec<_>>()
        .concat()
}

#[test]
fn more_types_than_the_limit_are_refused() {
    let error = parse(&types(GraphQlTypeGraph::MAX_TYPES + 1)).unwrap_err();

    assert_eq!(
        error,
        InvalidSpec::TooManyTypes {
            limit: GraphQlTypeGraph::MAX_TYPES
        }
    );
}

#[test]
fn more_scalars_than_the_type_limit_are_refused() {
    let sdl = (0..=GraphQlTypeGraph::MAX_TYPES)
        .map(|index| format!("scalar S{index}\n"))
        .collect::<Vec<_>>()
        .concat();

    assert_eq!(
        parse(&sdl).unwrap_err(),
        InvalidSpec::TooManyTypes {
            limit: GraphQlTypeGraph::MAX_TYPES
        }
    );
}

#[test]
fn exactly_the_type_limit_is_accepted() {
    let graph = parse(&types(GraphQlTypeGraph::MAX_TYPES)).unwrap();

    assert_eq!(graph.type_count(), GraphQlTypeGraph::MAX_TYPES);
}

fn fields(types: usize, per_type: usize) -> String {
    (0..types)
        .map(|type_index| {
            let body = (0..per_type)
                .map(|field| format!("f{field}: Int\n"))
                .collect::<Vec<_>>()
                .concat();
            format!("type T{type_index} {{\n{body}}}\n")
        })
        .collect::<Vec<_>>()
        .concat()
}

#[test]
fn more_fields_than_the_limit_are_refused() {
    let error = parse(&fields(10, 10_001)).unwrap_err();

    assert_eq!(
        error,
        InvalidSpec::TooManyFields {
            limit: GraphQlTypeGraph::MAX_FIELDS
        }
    );
}

#[test]
fn exactly_the_field_limit_is_accepted() {
    let graph = parse(&fields(10, 10_000)).unwrap();

    assert_eq!(graph.field_count(), GraphQlTypeGraph::MAX_FIELDS);
}

#[test]
fn the_parser_is_default_copy_and_debug() {
    let parser = AsyncGraphQlSchemaParser;
    let copy = parser;

    assert_eq!(format!("{parser:?}"), "AsyncGraphQlSchemaParser");
    assert_eq!(format!("{copy:?}"), "AsyncGraphQlSchemaParser");
}

#[test]
fn a_type_that_takes_a_renamed_root_name_is_malformed() {
    let error = parse(
        "schema { query: Root }
         type Root { a: Int }
         type Query { secret: Int }",
    )
    .unwrap_err();

    assert!(matches!(
        error,
        InvalidSpec::Malformed {
            position: SpecPosition::LineColumn { line: 3, .. },
            ..
        }
    ));
}

#[test]
fn a_root_may_take_the_name_of_another_renamed_root() {
    let graph = parse(
        "schema { query: Root mutation: Query }
         type Root { a: Int }
         type Query { b: Int }",
    )
    .unwrap();

    let coordinates: Vec<String> = graph.fields().map(|(key, _)| key.to_string()).collect();
    assert_eq!(coordinates, ["Mutation.b", "Query.a"]);
}

#[test]
fn return_types_and_union_members_use_the_root_coordinates() {
    let graph = parse(
        "schema { query: Root }
         type Root { self: Root }
         union Any = Root",
    )
    .unwrap();

    let (_, field) = graph.fields().next().unwrap();
    assert_eq!(field.return_type, name("Query"));
    assert_eq!(possible(&graph, "Any"), ["Query"]);
}

#[test]
fn nesting_deeper_than_the_limit_is_refused_before_parsing() {
    let deep = format!(
        "type Query {{ a: {}Int{} }}",
        "[".repeat(65),
        "]".repeat(65)
    );
    let shallow = format!(
        "type Query {{ a: {}Int{} }}",
        "[".repeat(63),
        "]".repeat(63)
    );

    let error = parse(&deep).unwrap_err();

    assert!(matches!(
        error,
        InvalidSpec::Malformed {
            position: SpecPosition::LineColumn {
                line: 1,
                column: 80
            },
            ..
        }
    ));
    assert!(parse(&shallow).is_ok());
}

#[test]
fn brackets_inside_strings_and_comments_do_not_count_as_nesting() {
    let noise = "[".repeat(100);
    let sdl = format!(
        "# {noise}\n\"{noise}\"\ntype A {{ a: Int }}\n\"\"\"{noise} \\\"\"\" {noise}\"\"\"\ntype Query {{ a: Int }}"
    );

    parse(&sdl).unwrap();
}

#[test]
fn an_escaped_quote_does_not_end_a_line_string() {
    let noise = "[".repeat(100);
    let sdl = format!("\"\\\" {noise}\"\ntype Query {{ a: Int }}");

    parse(&sdl).unwrap();
}

#[rstest::rstest]
#[case::block_string("type Query { a: Int }\n\"\"\"unterminated")]
#[case::line_string("type Query { a: Int }\n\"unterminated")]
fn an_unterminated_string_passes_the_nesting_check_and_is_malformed(#[case] sdl: &str) {
    assert!(matches!(parse(sdl), Err(InvalidSpec::Malformed { .. })));
}

#[test]
fn another_directive_sets_no_flag() {
    let graph = parse("type Query { a: Int @deprecated }").unwrap();

    let (_, field) = graph.fields().next().unwrap();
    assert!(!field.flags.is_sensitive() && !field.flags.is_audit_always());
}

#[test]
fn a_carriage_return_ends_a_comment_for_the_nesting_check() {
    let sdl = format!("#\r{}Int{}", "[".repeat(65), "]".repeat(65));

    let error = parse(&format!("type Query {{ a: {sdl} }}")).unwrap_err();

    assert!(matches!(error, InvalidSpec::Malformed { .. }));
}
