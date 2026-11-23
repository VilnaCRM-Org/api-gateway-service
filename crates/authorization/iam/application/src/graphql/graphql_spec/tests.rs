use async_graphql::{EmptySubscription, Request, Schema, Value, Variables};
use iam_domain::SpecId;
use serde_json::json;

use super::{
    CoordinateFlagsObject, FlagDowngradeObject, LoadGraphQlSpecInput, RemovedGrantObject,
    SpecDiffObject, WildcardGainObject,
};
use crate::error::IamError;
use crate::fixtures::principal;
use crate::graphql::{IamMutation, IamQuery};
use crate::graphql_spec_fixtures::{Answers, SPEC, recorded, scenario};
use crate::http::IamState;
use crate::http::graphql_spec::dto::{
    CoordinateFlagsResponse, FlagDowngradeResponse, RemovedGrantResponse, SpecDiffResponse,
    WildcardGainResponse,
};
use crate::principal::Principal;

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
