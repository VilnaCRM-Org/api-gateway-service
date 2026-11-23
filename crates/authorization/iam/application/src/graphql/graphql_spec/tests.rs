use async_graphql::{EmptySubscription, Request, Schema, Value, Variables};
use iam_domain::SpecId;
use serde_json::json;

use super::{
    CoordinateFlagsObject, FlagDowngradeObject, GraphQlSpecFilterInput, GraphQlSpecObject,
    GraphQlSpecPageObject, LoadGraphQlSpecInput, RemovedGrantObject, SpecDiffObject,
    WildcardGainObject,
};
use crate::error::IamError;
use crate::fixtures::principal;
use crate::graphql::{IamMutation, IamQuery};
use crate::graphql_spec_fixtures::{
    Answers, ReadAnswers, SPEC, read_scenario, recorded, scenario, summary,
};
use crate::http::IamState;
use crate::http::graphql_spec::dto::{
    CoordinateFlagsResponse, FlagDowngradeResponse, GraphQlSpecPageResponse,
    GraphQlSpecSummaryResponse, RemovedGrantResponse, SpecDiffResponse, WildcardGainResponse,
};
use crate::principal::Principal;
use crate::query::get_graphql_spec::GetGraphQlSpecQuery;
use crate::query::get_graphql_specs::{GetGraphQlSpecsQuery, GraphQlSpecPage};

type IamSchema = Schema<IamQuery, IamMutation, EmptySubscription>;

const LOAD: &str = "mutation($input: LoadGraphqlSpecInput!) { loadGraphqlSpec(input: $input) \
    { id service contentHash status uploadedBy createdAt activatedAt retiredAt coordinateCount \
    diff { added removed removedGrants { coordinate roles } \
    wildcardGains { role pattern coordinates } \
    flagDowngrades { coordinate before { sensitive auditAlways } after { sensitive auditAlways } } } } }";

fn schema(state: Option<IamState>) -> IamSchema {
    let builder = Schema::build(IamQuery, IamMutation, EmptySubscription);
    match state {
        Some(state) => builder.data(state).finish(),
        None => builder.finish(),
    }
}

/// The caller data a request carries: none at all, or the outcome of the authentication.
enum Caller {
    Absent,
    Data(Option<Principal>),
}

async fn run(
    schema: &IamSchema,
    caller: Caller,
    variables: serde_json::Value,
) -> async_graphql::Response {
    let mut request = Request::new(LOAD).variables(Variables::from_json(variables));
    if let Caller::Data(caller) = caller {
        request = request.data(caller);
    }
    schema.execute(request).await
}

fn input(service: &str, sdl: &str) -> serde_json::Value {
    json!({ "input": { "service": service, "sdl": sdl } })
}

fn error_code(response: &async_graphql::Response) -> Option<Value> {
    response
        .errors
        .first()
        .and_then(|error| error.extensions.as_ref())
        .and_then(|extensions| extensions.get("code"))
        .cloned()
}

fn code_of(name: &str) -> Value {
    Value::String(name.to_owned())
}

#[tokio::test]
async fn a_loaded_specification_returns_the_same_data_as_over_rest() {
    let (state, asked) = scenario(Answers::default());

    let response = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        input("billing", "type Query { invoices: [String!]! }"),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "loadGraphqlSpec": {
            "id": SPEC,
            "service": "billing",
            "contentHash": "ab".repeat(32),
            "status": "draft",
            "uploadedBy": format!("user:{}", crate::fixtures::USER),
            "createdAt": "1970-01-02T00:00:00.000000Z",
            "activatedAt": null,
            "retiredAt": null,
            "coordinateCount": 1,
            "diff": {
                "added": ["Query.invoices"],
                "removed": [],
                "removedGrants": [],
                "wildcardGains": [],
                "flagDowngrades": [],
            },
        } })
    );
    assert_eq!(recorded(&asked.commands).len(), 1);
}

#[tokio::test]
async fn an_sdl_that_the_service_holds_returns_its_version_without_a_command() {
    let answers = Answers {
        existing: Ok(Some(SpecId::parse(SPEC).unwrap())),
        ..Answers::default()
    };
    let (state, asked) = scenario(answers);

    let response = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        input("billing", "type Query { invoices: [String!]! }"),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert!(recorded(&asked.commands).is_empty());
}

#[tokio::test]
async fn the_reserved_service_is_forbidden() {
    let (state, asked) = scenario(Answers::default());

    let response = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        input("iam", "type Query { a: Int }"),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of("FORBIDDEN")));
    assert!(recorded(&asked.commands).is_empty());
}

#[tokio::test]
async fn an_invalid_service_or_an_empty_document_is_a_failed_validation() {
    for variables in [
        input("Not A Service", "type Query { a: Int }"),
        input("", "type Query { a: Int }"),
        input("billing", ""),
    ] {
        let (state, asked) = scenario(Answers::default());

        let response = run(
            &schema(Some(state)),
            Caller::Data(Some(principal())),
            variables,
        )
        .await;

        assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
        assert!(recorded(&asked.commands).is_empty());
    }
}

#[tokio::test]
async fn a_document_that_does_not_parse_is_a_failed_validation() {
    let answers = Answers {
        command: Err(|| {
            IamError::Invalid(vec![shared_application::http::Violation {
                property_path: "sdl".to_owned(),
                message: "unexpected token (line 1, column 14)".to_owned(),
                code: "syntax".to_owned(),
            }])
        }),
        ..Answers::default()
    };
    let (state, _asked) = scenario(answers);

    let response = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        input("billing", "type Query {"),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
}

#[tokio::test]
async fn a_caller_that_the_authentication_refused_or_none_is_unauthenticated() {
    for caller in [Caller::Absent, Caller::Data(None)] {
        let (state, asked) = scenario(Answers::default());

        let response = run(
            &schema(Some(state)),
            caller,
            input("billing", "type Query { a: Int }"),
        )
        .await;

        assert_eq!(error_code(&response), Some(code_of("UNAUTHENTICATED")));
        assert!(recorded(&asked.commands).is_empty());
    }
}

#[tokio::test]
async fn a_schema_without_the_state_is_an_internal_error() {
    let response = run(
        &schema(None),
        Caller::Data(Some(principal())),
        input("billing", "type Query { a: Int }"),
    )
    .await;

    assert_eq!(response.errors.len(), 1);
    assert_eq!(
        error_code(&response),
        Some(code_of("INTERNAL_SERVER_ERROR"))
    );
}

#[test]
fn the_debug_output_of_the_input_does_not_show_the_document() {
    let text = format!(
        "{:?}",
        LoadGraphQlSpecInput {
            service: "billing".to_owned(),
            sdl: "type Secret { a: Int }".to_owned(),
        }
    );

    assert!(text.contains("billing"));
    assert!(!text.contains("Secret"));
}

#[test]
fn the_input_is_read_from_a_graphql_object_and_rejects_other_values() {
    use async_graphql::{InputType as _, Name};

    let object = Value::Object(
        [
            (Name::new("service"), Value::String("billing".to_owned())),
            (
                Name::new("sdl"),
                Value::String("type Query { a: Int }".to_owned()),
            ),
        ]
        .into_iter()
        .collect(),
    );

    let parsed = LoadGraphQlSpecInput::parse(Some(object)).unwrap();

    assert_eq!(parsed.service, "billing");
    assert_eq!(parsed.sdl, "type Query { a: Int }");
    assert!(LoadGraphQlSpecInput::parse(Some(Value::Boolean(true))).is_err());
    for field in ["service", "sdl"] {
        let wrong = Value::Object(
            [
                (Name::new("service"), Value::String("billing".to_owned())),
                (
                    Name::new("sdl"),
                    Value::String("type Query { a: Int }".to_owned()),
                ),
                (Name::new(field), Value::Boolean(true)),
            ]
            .into_iter()
            .collect(),
        );
        assert!(LoadGraphQlSpecInput::parse(Some(wrong)).is_err(), "{field}");
    }
}

#[test]
fn a_diff_with_every_kind_of_change_becomes_its_objects() {
    let flags = |sensitive, audit_always| CoordinateFlagsResponse {
        sensitive,
        audit_always,
    };
    let diff = SpecDiffResponse {
        added: vec!["Query.b".to_owned()],
        removed: vec!["Query.a".to_owned()],
        removed_grants: vec![RemovedGrantResponse {
            coordinate: "Query.a".to_owned(),
            roles: vec!["role-1".to_owned()],
        }],
        wildcard_gains: vec![WildcardGainResponse {
            role: "role-2".to_owned(),
            pattern: "gql:billing:Query.*".to_owned(),
            coordinates: vec!["Query.b".to_owned()],
        }],
        flag_downgrades: vec![FlagDowngradeResponse {
            coordinate: "Query.c".to_owned(),
            before: flags(true, true),
            after: flags(false, true),
        }],
    };

    let object = SpecDiffObject::from(diff);

    assert_eq!(
        object,
        SpecDiffObject {
            added: vec!["Query.b".to_owned()],
            removed: vec!["Query.a".to_owned()],
            removed_grants: vec![RemovedGrantObject {
                coordinate: "Query.a".to_owned(),
                roles: vec!["role-1".to_owned()],
            }],
            wildcard_gains: vec![WildcardGainObject {
                role: "role-2".to_owned(),
                pattern: "gql:billing:Query.*".to_owned(),
                coordinates: vec!["Query.b".to_owned()],
            }],
            flag_downgrades: vec![FlagDowngradeObject {
                coordinate: "Query.c".to_owned(),
                before: CoordinateFlagsObject {
                    sensitive: true,
                    audit_always: true,
                },
                after: CoordinateFlagsObject {
                    sensitive: false,
                    audit_always: true,
                },
            }],
        }
    );
}

const LIST: &str = "query($first: Int, $after: String, $filter: GraphqlSpecFilter) \
    { graphqlSpecs(first: $first, after: $after, filter: $filter) \
    { items { id service contentHash status uploadedBy createdAt activatedAt retiredAt \
    coordinateCount } nextCursor } }";

const ONE: &str = "query($id: ID!) \
    { graphqlSpec(id: $id) { id service status coordinateCount } }";

const WITH_SDL: &str = "query($id: ID!) { graphqlSpec(id: $id) { id sdl } }";

const WITH_DIFF: &str = "query($id: ID!) { graphqlSpec(id: $id) { id diff { added removed \
    removedGrants { coordinate roles } wildcardGains { role pattern coordinates } \
    flagDowngrades { coordinate before { sensitive auditAlways } after { sensitive auditAlways } } } } }";

async fn read(
    schema: &IamSchema,
    caller: Caller,
    query: &str,
    variables: serde_json::Value,
) -> async_graphql::Response {
    let mut request = Request::new(query).variables(Variables::from_json(variables));
    if let Caller::Data(caller) = caller {
        request = request.data(caller);
    }
    schema.execute(request).await
}

fn spec_id() -> SpecId {
    SpecId::parse(SPEC).unwrap()
}

#[tokio::test]
async fn the_list_is_a_page_of_versions_with_the_cursor_of_the_next_page() {
    let (state, asked) = read_scenario(ReadAnswers::default());

    let response = read(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        LIST,
        json!({}),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "graphqlSpecs": {
            "items": [{
                "id": SPEC,
                "service": "billing",
                "contentHash": "ab".repeat(32),
                "status": "draft",
                "uploadedBy": format!("user:{}", crate::fixtures::USER),
                "createdAt": "1970-01-02T00:00:00.000000Z",
                "activatedAt": null,
                "retiredAt": null,
                "coordinateCount": 1,
            }],
            "nextCursor": SPEC,
        } })
    );
    assert_eq!(
        recorded(&asked.pages),
        [GetGraphQlSpecsQuery {
            limit: 30,
            after: None,
            service: None,
            status: None,
            include_sdl: false,
        }]
    );
}

#[tokio::test]
async fn the_list_passes_its_arguments_to_the_query() {
    let (state, asked) = read_scenario(ReadAnswers::default());

    let response = read(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        LIST,
        json!({
            "first": 5,
            "after": SPEC,
            "filter": { "service": "billing", "status": "active" },
        }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        recorded(&asked.pages),
        [GetGraphQlSpecsQuery {
            limit: 5,
            after: Some(spec_id()),
            service: Some(iam_domain::ServiceName::new("billing").unwrap()),
            status: Some(iam_domain::SpecStatus::Active),
            include_sdl: false,
        }]
    );
}

#[tokio::test]
async fn the_last_page_has_a_null_cursor() {
    let answers = ReadAnswers {
        page: Ok(GraphQlSpecPage {
            specs: Vec::new(),
            next_after: None,
        }),
        ..ReadAnswers::default()
    };
    let (state, _asked) = read_scenario(answers);

    let response = read(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        LIST,
        json!({}),
    )
    .await;

    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "graphqlSpecs": { "items": [], "nextCursor": null } })
    );
}

#[tokio::test]
async fn an_invalid_list_argument_is_a_failed_validation_and_asks_nothing() {
    for variables in [
        json!({ "first": 0 }),
        json!({ "first": 101 }),
        json!({ "after": "nope" }),
        json!({ "filter": { "service": "Not A Service" } }),
        json!({ "filter": { "status": "pending" } }),
    ] {
        let (state, asked) = read_scenario(ReadAnswers::default());

        let response = read(
            &schema(Some(state)),
            Caller::Data(Some(principal())),
            LIST,
            variables,
        )
        .await;

        assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
        assert_eq!(recorded(&asked.pages), Vec::<GetGraphQlSpecsQuery>::new());
    }
}

#[tokio::test]
async fn one_version_is_read_by_id_without_its_sdl() {
    let (state, asked) = read_scenario(ReadAnswers::default());

    let response = read(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        ONE,
        json!({ "id": SPEC }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "graphqlSpec": {
            "id": SPEC,
            "service": "billing",
            "status": "draft",
            "coordinateCount": 1,
        } })
    );
    assert_eq!(
        recorded(&asked.ones),
        [GetGraphQlSpecQuery {
            id: spec_id(),
            include_sdl: false,
        }]
    );
}

#[tokio::test]
async fn the_sdl_is_read_only_when_the_query_selects_it() {
    let mut with_sdl = summary();
    with_sdl.sdl = Some("type Query { invoices: String }".to_owned());
    let answers = ReadAnswers {
        one: Ok(Some(with_sdl)),
        ..ReadAnswers::default()
    };
    let (state, asked) = read_scenario(answers);

    let response = read(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        WITH_SDL,
        json!({ "id": SPEC }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "graphqlSpec": {
            "id": SPEC,
            "sdl": "type Query { invoices: String }",
        } })
    );
    assert_eq!(
        recorded(&asked.ones),
        [
            GetGraphQlSpecQuery {
                id: spec_id(),
                include_sdl: false,
            },
            GetGraphQlSpecQuery {
                id: spec_id(),
                include_sdl: true,
            },
        ]
    );
}

#[tokio::test]
async fn an_sdl_that_the_query_did_not_return_is_null() {
    let (state, asked) = read_scenario(ReadAnswers::default());

    let response = read(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        WITH_SDL,
        json!({ "id": SPEC }),
    )
    .await;

    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "graphqlSpec": { "id": SPEC, "sdl": null } })
    );
    assert_eq!(recorded(&asked.ones).len(), 2);
}

#[tokio::test]
async fn an_unknown_version_is_null() {
    let answers = ReadAnswers {
        one: Ok(None),
        ..ReadAnswers::default()
    };
    let (state, _asked) = read_scenario(answers);

    let response = read(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        ONE,
        json!({ "id": SPEC }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "graphqlSpec": null })
    );
}

#[tokio::test]
async fn an_identifier_that_is_not_a_uuid_is_a_failed_validation() {
    let (state, asked) = read_scenario(ReadAnswers::default());

    let response = read(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        ONE,
        json!({ "id": "nope" }),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
    assert_eq!(recorded(&asked.ones), Vec::<GetGraphQlSpecQuery>::new());
}

#[tokio::test]
async fn the_diff_field_reads_the_diff_of_the_version_when_it_is_selected() {
    let (state, asked) = read_scenario(ReadAnswers::default());

    let response = read(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        WITH_DIFF,
        json!({ "id": SPEC }),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "graphqlSpec": {
            "id": SPEC,
            "diff": {
                "added": ["Query.invoices"],
                "removed": [],
                "removedGrants": [],
                "wildcardGains": [],
                "flagDowngrades": [],
            },
        } })
    );
    assert_eq!(recorded(&asked.diffs), [spec_id()]);
}

#[tokio::test]
async fn the_diff_is_not_read_when_the_query_does_not_select_it() {
    let (state, asked) = read_scenario(ReadAnswers::default());

    read(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        ONE,
        json!({ "id": SPEC }),
    )
    .await;

    assert_eq!(recorded(&asked.diffs), Vec::<SpecId>::new());
}

#[tokio::test]
async fn the_diff_of_a_version_that_vanished_is_a_not_found_error() {
    let answers = ReadAnswers {
        diff: Ok(None),
        ..ReadAnswers::default()
    };
    let (state, _asked) = read_scenario(answers);

    let response = read(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        WITH_DIFF,
        json!({ "id": SPEC }),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of("NOT_FOUND")));
}

#[tokio::test]
async fn the_reads_of_a_caller_that_the_authentication_refused_or_none_are_unauthenticated() {
    for absent in [true, false] {
        for (query, variables) in [
            (LIST, json!({})),
            (ONE, json!({ "id": SPEC })),
            (WITH_DIFF, json!({ "id": SPEC })),
        ] {
            let (state, asked) = read_scenario(ReadAnswers::default());
            let caller = if absent {
                Caller::Absent
            } else {
                Caller::Data(None)
            };

            let response = read(&schema(Some(state)), caller, query, variables).await;

            assert_eq!(error_code(&response), Some(code_of("UNAUTHENTICATED")));
            assert_eq!(recorded(&asked.pages), Vec::<GetGraphQlSpecsQuery>::new());
            assert_eq!(recorded(&asked.ones), Vec::<GetGraphQlSpecQuery>::new());
            assert_eq!(recorded(&asked.diffs), Vec::<SpecId>::new());
        }
    }
}

#[tokio::test]
async fn a_read_failure_of_the_storage_is_an_internal_error() {
    for (query, variables) in [
        (LIST, json!({})),
        (ONE, json!({ "id": SPEC })),
        (WITH_SDL, json!({ "id": SPEC })),
        (WITH_DIFF, json!({ "id": SPEC })),
    ] {
        let answers = ReadAnswers {
            page: Err(|| IamError::Storage("down".into())),
            one: Err(|| IamError::Storage("down".into())),
            diff: Err(|| IamError::Storage("down".into())),
        };
        let (state, _asked) = read_scenario(answers);

        let response = read(
            &schema(Some(state)),
            Caller::Data(Some(principal())),
            query,
            variables,
        )
        .await;

        assert_eq!(
            error_code(&response),
            Some(code_of("INTERNAL_SERVER_ERROR"))
        );
    }
}

#[test]
fn a_summary_and_a_page_become_their_objects() {
    let response = GraphQlSpecSummaryResponse::from(summary());
    let page = GraphQlSpecPageObject::from(GraphQlSpecPageResponse {
        items: vec![response.clone()],
        next_cursor: Some(SPEC.to_owned()),
    });

    assert_eq!(page.next_cursor.as_deref(), Some(SPEC));
    assert_eq!(page.items, vec![GraphQlSpecObject::from(response)]);
    assert_eq!(page.items[0].loaded_diff, None);
    assert_eq!(GraphQlSpecFilterInput::default().service, None::<String>);
}

#[test]
fn the_filter_is_read_from_a_graphql_object_and_rejects_other_values() {
    use async_graphql::{InputType as _, Name};

    let filter = |fields: Vec<(&str, Value)>| {
        Value::Object(
            fields
                .into_iter()
                .map(|(name, value)| (Name::new(name), value))
                .collect(),
        )
    };

    let parsed = GraphQlSpecFilterInput::parse(Some(filter(vec![
        ("service", Value::String("billing".to_owned())),
        ("status", Value::String("active".to_owned())),
    ])))
    .unwrap();

    assert_eq!(parsed.service.as_deref(), Some("billing"));
    assert_eq!(parsed.status.as_deref(), Some("active"));
    assert!(GraphQlSpecFilterInput::parse(Some(Value::Boolean(true))).is_err());
    for field in ["service", "status"] {
        let wrong = filter(vec![(field, Value::List(Vec::new()))]);
        assert!(
            GraphQlSpecFilterInput::parse(Some(wrong)).is_err(),
            "{field}"
        );
    }
}
