use iam_domain::{
    HttpMethod, InvalidSpec, OpenApiDocumentParser as _, OpenApiSpec, PathTemplate,
    PermissionFlags, RestOperationSet, SpecPosition,
};
use rstest::rstest;

use super::JsonOpenApiDocumentParser;

fn parse(document: &str) -> Result<RestOperationSet, InvalidSpec> {
    JsonOpenApiDocumentParser.parse(document)
}

fn template(path: &str) -> PathTemplate {
    PathTemplate::from_openapi_path(path).unwrap()
}

fn pointer(error: &InvalidSpec) -> &str {
    match error.position() {
        Some(SpecPosition::JsonPointer(pointer)) => pointer,
        other => panic!("expected a JSON pointer, found {other:?}"),
    }
}

const DOCUMENT_30: &str = r#"{
  "openapi": "3.0.3",
  "info": {"title": "Billing", "version": "1"},
  "paths": {
    "/invoices": {
      "get": {"operationId": "listInvoices", "responses": {"200": {"description": "ok"}}},
      "post": {"operationId": "createInvoice", "x-iam-audit": "always", "responses": {}}
    },
    "/invoices/{invoiceId}": {
      "delete": {"operationId": "deleteInvoice", "x-iam-sensitive": true, "responses": {}},
      "parameters": [{"name": "invoiceId", "in": "path", "required": true}]
    }
  }
}"#;

const DOCUMENT_31: &str = r#"{
  "openapi": "3.1.0",
  "info": {"title": "Billing", "version": "1"},
  "paths": {
    "/ping": {"get": {"responses": {}}},
    "/items/{id}/": {
      "put": {"operationId": "replaceItem", "x-iam-sensitive": true, "x-iam-audit": "always", "responses": {}},
      "patch": {"responses": {}},
      "head": {"responses": {}},
      "options": {"responses": {}},
      "trace": {"responses": {}}
    }
  }
}"#;

#[test]
fn a_3_0_document_yields_the_method_template_label_and_flags_of_every_operation() {
    let operations = parse(DOCUMENT_30).unwrap();

    assert_eq!(operations.len(), 3);
    let list = operations
        .get(HttpMethod::Get, &template("/invoices"))
        .unwrap();
    assert_eq!(list.label.as_deref(), Some("listInvoices"));
    assert_eq!(list.flags, PermissionFlags::NONE);
    let create = operations
        .get(HttpMethod::Post, &template("/invoices"))
        .unwrap();
    assert_eq!(create.label.as_deref(), Some("createInvoice"));
    assert_eq!(create.flags, PermissionFlags::NONE.with_audit_always());
    let delete = operations
        .get(HttpMethod::Delete, &template("/invoices/{invoiceId}"))
        .unwrap();
    assert_eq!(delete.label.as_deref(), Some("deleteInvoice"));
    assert_eq!(delete.flags, PermissionFlags::NONE.with_sensitive());
}

#[test]
fn a_3_1_document_yields_every_method_except_trace_with_normalised_templates() {
    let operations = parse(DOCUMENT_31).unwrap();

    let keys: Vec<String> = operations.iter().map(|(key, _)| key.to_string()).collect();
    assert_eq!(
        keys,
        [
            "GET /ping",
            "HEAD /items/{}",
            "PUT /items/{}",
            "PATCH /items/{}",
            "OPTIONS /items/{}",
        ]
    );
    let replace = operations
        .get(HttpMethod::Put, &template("/items/{id}"))
        .unwrap();
    assert_eq!(replace.label.as_deref(), Some("replaceItem"));
    assert_eq!(
        replace.flags,
        PermissionFlags::NONE.with_sensitive().with_audit_always()
    );
    let ping = operations.get(HttpMethod::Get, &template("/ping")).unwrap();
    assert_eq!(ping.label, None);
}

#[test]
fn flags_need_the_exact_values() {
    let operations = parse(
        r#"{"openapi":"3.0.0","paths":{"/a":{"get":{"x-iam-sensitive":"true","x-iam-audit":"sometimes","operationId":7}}}}"#,
    )
    .unwrap();

    let details = operations.get(HttpMethod::Get, &template("/a")).unwrap();
    assert_eq!(details.flags, PermissionFlags::NONE);
    assert_eq!(details.label, None);
}

#[test]
fn a_document_without_paths_has_no_operation() {
    let operations = parse(r#"{"openapi":"3.1.0","webhooks":{}}"#).unwrap();

    assert!(operations.is_empty());
}

#[test]
fn extension_members_of_paths_are_not_paths() {
    let operations =
        parse(r#"{"openapi":"3.1.0","paths":{"x-note":{"a":1},"/a":{"get":{}}}}"#).unwrap();

    assert_eq!(operations.len(), 1);
}

#[test]
fn internal_references_are_accepted_and_a_referenced_path_item_is_resolved() {
    let operations = parse(
        r##"{
          "openapi": "3.1.0",
          "paths": {
            "/a": {"$ref": "#/components/pathItems/shared"},
            "/b": {"$ref": "#/components/pathItems/chained"}
          },
          "components": {
            "schemas": {"Pet": {"properties": {"friend": {"$ref": "#/components/schemas/Pet"}}}},
            "pathItems": {
              "shared": {"get": {"operationId": "shared", "x-iam-sensitive": true}},
              "chained": {"$ref": "#/components/pathItems/shared"}
            }
          }
        }"##,
    )
    .unwrap();

    assert_eq!(operations.len(), 2);
    for path in ["/a", "/b"] {
        let details = operations.get(HttpMethod::Get, &template(path)).unwrap();
        assert_eq!(details.label.as_deref(), Some("shared"));
        assert_eq!(details.flags, PermissionFlags::NONE.with_sensitive());
    }
}

#[test]
fn a_reference_to_the_document_itself_is_internal() {
    assert!(parse(r##"{"openapi":"3.0.0","x-self":{"$ref":"#"}}"##).is_ok());
}

#[rstest]
#[case::url(
    r#"{"openapi":"3.0.0","paths":{"/a":{"get":{"responses":{"200":{"content":{"application/json":{"schema":{"$ref":"https://evil.example/schema.json"}}}}}}}}}"#,
    "/paths/~1a/get/responses/200/content/application~1json/schema/$ref"
)]
#[case::file(
    r#"{"openapi":"3.0.0","components":{"schemas":{"A":{"$ref":"other.json#/B"}}}}"#,
    "/components/schemas/A/$ref"
)]
#[case::in_an_array(
    r#"{"openapi":"3.0.0","components":{"schemas":{"A":{"allOf":[{"type":"object"},{"$ref":"./b.yaml"}]}}}}"#,
    "/components/schemas/A/allOf/1/$ref"
)]
#[case::path_item(
    r#"{"openapi":"3.1.0","paths":{"/a":{"$ref":"http://example.com/item"}}}"#,
    "/paths/~1a/$ref"
)]
fn an_external_reference_is_refused_with_its_json_pointer(
    #[case] document: &str,
    #[case] expected: &str,
) {
    let error = parse(document).unwrap_err();

    assert!(matches!(error, InvalidSpec::Malformed { .. }));
    assert_eq!(pointer(&error), expected);
    assert_eq!(error.property_path(), "document");
}

#[test]
fn a_property_named_ref_is_not_a_reference() {
    assert!(
        parse(
            r#"{"openapi":"3.1.0","components":{"schemas":{"A":{"properties":{"$ref":{"type":"string"}}}}}}"#
        )
        .is_ok()
    );
}

#[test]
fn two_operations_that_normalise_to_the_same_key_are_refused() {
    let error = parse(
        r#"{"openapi":"3.0.0","paths":{"/users/{id}":{"get":{}},"/users/{userId}":{"get":{}}}}"#,
    )
    .unwrap_err();

    assert_eq!(
        error,
        InvalidSpec::DuplicateOperation {
            key: "GET /users/{}".to_owned()
        }
    );
}

#[test]
fn the_same_path_with_other_methods_is_not_a_duplicate() {
    let operations = parse(
        r#"{"openapi":"3.0.0","paths":{"/users/{id}":{"get":{}},"/users/{userId}":{"delete":{}}}}"#,
    )
    .unwrap();

    assert_eq!(operations.len(), 2);
}

fn document_with_operations(count: usize) -> String {
    let paths = (0..count)
        .map(|index| format!(r#""/p{index}":{{"get":{{}}}}"#))
        .collect::<Vec<_>>()
        .join(",");
    format!(r#"{{"openapi":"3.1.0","paths":{{{paths}}}}}"#)
}

#[test]
fn five_thousand_operations_are_accepted() {
    let operations = parse(&document_with_operations(RestOperationSet::MAX_OPERATIONS)).unwrap();

    assert_eq!(operations.len(), RestOperationSet::MAX_OPERATIONS);
}

#[test]
fn more_than_five_thousand_operations_are_refused() {
    let error = parse(&document_with_operations(
        RestOperationSet::MAX_OPERATIONS + 1,
    ))
    .unwrap_err();

    assert_eq!(
        error,
        InvalidSpec::TooManyOperations {
            limit: RestOperationSet::MAX_OPERATIONS
        }
    );
}

#[test]
fn a_document_over_five_mebibytes_is_refused_before_it_is_parsed() {
    let document = " ".repeat(OpenApiSpec::MAX_DOCUMENT_BYTES + 1);

    assert_eq!(
        parse(&document),
        Err(InvalidSpec::DocumentTooLarge {
            limit: OpenApiSpec::MAX_DOCUMENT_BYTES
        })
    );
}

#[test]
fn a_document_of_exactly_five_mebibytes_is_read() {
    let padding = " ".repeat(OpenApiSpec::MAX_DOCUMENT_BYTES - 2);
    let document = format!("{{{padding}}}");

    assert_eq!(document.len(), OpenApiSpec::MAX_DOCUMENT_BYTES);
    assert!(matches!(
        parse(&document),
        Err(InvalidSpec::Malformed { .. })
    ));
}

#[rstest]
#[case::yaml("openapi: 3.0.0\npaths:\n  /a:\n    get: {}\n", "YAML is not accepted")]
#[case::empty("", "YAML is not accepted")]
#[case::truncated(r#"{"openapi": "3.0.0","#, "not valid JSON")]
#[case::trailing(r#"{"openapi": "3.0.0"} x"#, "not valid JSON")]
fn content_that_is_not_json_is_refused_at_the_document_root(
    #[case] document: &str,
    #[case] fragment: &str,
) {
    let error = parse(document).unwrap_err();

    assert_eq!(pointer(&error), "");
    assert!(error.to_string().contains(fragment), "{error}");
}

#[rstest]
#[case::array("[]")]
#[case::string(r#""3.0.0""#)]
#[case::missing_version(r#"{"paths":{}}"#)]
#[case::swagger(r#"{"swagger":"2.0","paths":{}}"#)]
#[case::three_two(r#"{"openapi":"3.2.0"}"#)]
#[case::bare_minor(r#"{"openapi":"3.0."}"#)]
#[case::not_text(r#"{"openapi":3}"#)]
fn an_unsupported_version_is_refused_at_the_openapi_member(#[case] document: &str) {
    let error = parse(document).unwrap_err();

    assert!(matches!(error, InvalidSpec::Malformed { .. }));
    assert_eq!(pointer(&error), "/openapi");
}

#[rstest]
#[case::paths_array(r#"{"openapi":"3.0.0","paths":[]}"#, "/paths")]
#[case::bad_template(
    r#"{"openapi":"3.0.0","paths":{"/a/{id":{"get":{}}}}"#,
    "/paths/~1a~1{id"
)]
#[case::no_slash(r#"{"openapi":"3.0.0","paths":{"a":{"get":{}}}}"#, "/paths/a")]
#[case::item_not_object(r#"{"openapi":"3.0.0","paths":{"/a":[]}}"#, "/paths/~1a")]
#[case::operation_not_object(r#"{"openapi":"3.0.0","paths":{"/a":{"get":[]}}}"#, "/paths/~1a/get")]
#[case::unresolved(
    r##"{"openapi":"3.1.0","paths":{"/a":{"$ref":"#/components/nope"}}}"##,
    "/paths/~1a/$ref"
)]
#[case::loop_of_items(
    r##"{"openapi":"3.1.0","paths":{"/a":{"$ref":"#/paths/~1b"},"/b":{"$ref":"#/paths/~1a"}}}"##,
    "/paths/~1a/$ref"
)]
fn a_structural_fault_is_refused_with_its_json_pointer(
    #[case] document: &str,
    #[case] expected: &str,
) {
    let error = parse(document).unwrap_err();

    assert!(matches!(error, InvalidSpec::Malformed { .. }));
    assert_eq!(pointer(&error), expected);
}

#[test]
fn a_path_item_that_references_the_document_root_resolves_to_it() {
    let operations =
        parse(r##"{"openapi":"3.1.0","get":{},"paths":{"/a":{"$ref":"#"}}}"##).unwrap();

    let keys: Vec<String> = operations.iter().map(|(key, _)| key.to_string()).collect();
    assert_eq!(keys, ["GET /a"]);
}

#[test]
fn a_reference_through_an_array_resolves() {
    let operations = parse(
        r##"{"openapi":"3.1.0","paths":{"/a":{"$ref":"#/x-items/1"}},"x-items":[{},{"get":{}}]}"##,
    )
    .unwrap();

    assert_eq!(operations.len(), 1);
}

#[test]
fn an_escaped_pointer_token_resolves() {
    let operations = parse(
        r##"{"openapi":"3.1.0","paths":{"/a":{"$ref":"#/x-a~1b~0c"}},"x-a/b~c":{"get":{}}}"##,
    )
    .unwrap();

    assert_eq!(operations.len(), 1);
}

#[test]
fn a_reference_through_a_scalar_does_not_resolve() {
    let error = parse(
        r##"{"openapi":"3.1.0","paths":{"/a":{"$ref":"#/info/title/x"}},"info":{"title":"t"}}"##,
    )
    .unwrap_err();

    assert_eq!(pointer(&error), "/paths/~1a/$ref");
}

#[test]
fn a_fragment_reference_that_is_not_a_pointer_is_refused() {
    let error = parse(r##"{"openapi":"3.1.0","paths":{"/a":{"$ref":"#foo"}}}"##).unwrap_err();

    assert_eq!(pointer(&error), "/paths/~1a/$ref");
}

#[test]
fn a_long_member_name_above_many_items_is_walked_without_a_pointer_per_item() {
    let name = "k".repeat(1_000_000);
    let items = vec!["0"; 500_000].join(",");
    let document = DOCUMENT_30.replacen('{', &format!(r#"{{"x-{name}": [{items}],"#), 1);

    assert!(document.len() < OpenApiSpec::MAX_DOCUMENT_BYTES);
    assert_eq!(parse(&document).unwrap(), parse(DOCUMENT_30).unwrap());
}

#[test]
fn an_external_reference_under_a_list_is_refused_at_its_escaped_pointer() {
    let document = DOCUMENT_30.replacen(
        '{',
        r#"{"x-a/b~c": [{"skip": 1}, {"$ref": "https://example.test/spec.json"}],"#,
        1,
    );

    let error = parse(&document).unwrap_err();

    assert_eq!(pointer(&error), "/x-a~1b~0c/1/$ref");
}

#[test]
fn a_scalar_has_no_children_to_walk() {
    assert!(super::children(&async_graphql::Value::Null).is_empty());
}
