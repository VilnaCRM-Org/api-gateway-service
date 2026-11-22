use iam_domain::{
    GqlName, GraphQlCoordinate, GraphQlSchemaParser, GraphQlSpec, GraphQlTypeGraph, InvalidSpec,
    SpecPosition,
};

use super::AsyncGraphQlSchemaParser;

const SDL: &str = r#"
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
"#;

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
    assert!(possible(&graph, "User").is_empty());
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
        .collect()
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
    let sdl: String = (0..=GraphQlTypeGraph::MAX_TYPES)
        .map(|index| format!("scalar S{index}\n"))
        .collect();

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
            let body: String = (0..per_type)
                .map(|field| format!("f{field}: Int\n"))
                .collect();
            format!("type T{type_index} {{\n{body}}}\n")
        })
        .collect()
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
    let parser = AsyncGraphQlSchemaParser::default();
    let copy = parser;

    assert_eq!(format!("{parser:?}"), "AsyncGraphQlSchemaParser");
    assert_eq!(format!("{copy:?}"), "AsyncGraphQlSchemaParser");
}
