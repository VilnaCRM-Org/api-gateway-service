use async_graphql::{EmptySubscription, Request, Schema, Value, Variables};
use iam_domain::SpecId;
use serde_json::json;

use super::{
    LoadOpenApiSpecInput, OpenApiSpecObject, OperationFlagDowngradeObject, OperationFlagsObject,
    OperationWildcardGainObject, RemovedOperationGrantObject, RestSpecDiffObject,
};
use crate::error::IamError;
use crate::fixtures::principal;
use crate::graphql::{IamMutation, IamQuery};
use crate::http::IamState;
use crate::http::openapi_spec::dto::{
    OpenApiSpecResponse, OperationFlagDowngradeResponse, OperationFlagsResponse,
    OperationWildcardGainResponse, RemovedOperationGrantResponse, RestSpecDiffResponse,
};
use crate::openapi_spec_fixtures::{Answers, SPEC, recorded, scenario, view};
use crate::principal::Principal;

type IamSchema = Schema<IamQuery, IamMutation, EmptySubscription>;

const LOAD: &str = "mutation($input: LoadOpenapiSpecInput!) { loadOpenapiSpec(input: $input) \
    { id service contentHash status uploadedBy createdAt activatedAt retiredAt operationCount \
    diff { added removed removedGrants { operation roles } \
    wildcardGains { role pattern operations } \
    flagDowngrades { operation before { sensitive auditAlways } after { sensitive auditAlways } } } } }";

const DOCUMENT: &str = r#"{"openapi":"3.1.0","info":{"title":"a","version":"1"},"paths":{}}"#;

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

fn input(service: &str, document: &str) -> serde_json::Value {
    json!({ "input": { "service": service, "document": document } })
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
        input("billing", DOCUMENT),
    )
    .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "loadOpenapiSpec": {
            "id": SPEC,
            "service": "billing",
            "contentHash": "ab".repeat(32),
            "status": "draft",
            "uploadedBy": format!("user:{}", crate::fixtures::USER),
            "createdAt": "1970-01-02T00:00:00.000000Z",
            "activatedAt": null,
            "retiredAt": null,
            "operationCount": 1,
            "diff": {
                "added": ["GET /invoices"],
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
async fn a_document_that_the_service_holds_returns_its_version_without_a_command() {
    let answers = Answers {
        existing: Ok(Some(SpecId::parse(SPEC).unwrap())),
        ..Answers::default()
    };
    let (state, asked) = scenario(answers);

    let response = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        input("billing", DOCUMENT),
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
        input("iam", DOCUMENT),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of("FORBIDDEN")));
    assert!(recorded(&asked.commands).is_empty());
}

#[tokio::test]
async fn an_invalid_service_or_an_empty_document_is_a_failed_validation() {
    for variables in [
        input("Not A Service", DOCUMENT),
        input("", DOCUMENT),
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
                property_path: "document".to_owned(),
                message: "External references are not supported. (pointer /paths)".to_owned(),
                code: "syntax".to_owned(),
            }])
        }),
        ..Answers::default()
    };
    let (state, _asked) = scenario(answers);

    let response = run(
        &schema(Some(state)),
        Caller::Data(Some(principal())),
        input("billing", "{}"),
    )
    .await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
}

#[tokio::test]
async fn a_caller_that_the_authentication_refused_or_none_is_unauthenticated() {
    for caller in [Caller::Absent, Caller::Data(None)] {
        let (state, asked) = scenario(Answers::default());

        let response = run(&schema(Some(state)), caller, input("billing", DOCUMENT)).await;

        assert_eq!(error_code(&response), Some(code_of("UNAUTHENTICATED")));
        assert!(recorded(&asked.commands).is_empty());
    }
}

#[tokio::test]
async fn a_schema_without_the_state_is_an_internal_error() {
    let response = run(
        &schema(None),
        Caller::Data(Some(principal())),
        input("billing", DOCUMENT),
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
        LoadOpenApiSpecInput {
            service: "billing".to_owned(),
            document: "{\"secret\":true}".to_owned(),
        }
    );

    assert!(text.contains("billing"));
    assert!(!text.contains("secret"));
}

#[test]
fn the_input_is_read_from_a_graphql_object_and_rejects_other_values() {
    use async_graphql::{InputType as _, Name};

    let object = |extra: Option<&str>| {
        let mut members = vec![
            (Name::new("service"), Value::String("billing".to_owned())),
            (Name::new("document"), Value::String("{}".to_owned())),
        ];
        if let Some(field) = extra {
            members.push((Name::new(field), Value::Boolean(true)));
        }
        Value::Object(members.into_iter().collect())
    };

    let parsed = LoadOpenApiSpecInput::parse(Some(object(None))).unwrap();

    assert_eq!(parsed.service, "billing");
    assert_eq!(parsed.document, "{}");
    assert!(LoadOpenApiSpecInput::parse(Some(Value::Boolean(true))).is_err());
    for field in ["service", "document"] {
        assert!(
            LoadOpenApiSpecInput::parse(Some(object(Some(field)))).is_err(),
            "{field}"
        );
    }
}

#[test]
fn a_diff_with_every_kind_of_change_becomes_its_objects() {
    let flags = |sensitive, audit_always| OperationFlagsResponse {
        sensitive,
        audit_always,
    };
    let diff = RestSpecDiffResponse {
        added: vec!["GET /b".to_owned()],
        removed: vec!["GET /a".to_owned()],
        removed_grants: vec![RemovedOperationGrantResponse {
            operation: "GET /a".to_owned(),
            roles: vec!["role-1".to_owned()],
        }],
        wildcard_gains: vec![OperationWildcardGainResponse {
            role: "role-2".to_owned(),
            pattern: "rest:billing:GET *".to_owned(),
            operations: vec!["GET /b".to_owned()],
        }],
        flag_downgrades: vec![OperationFlagDowngradeResponse {
            operation: "POST /c".to_owned(),
            before: flags(true, true),
            after: flags(false, true),
        }],
    };

    let object = RestSpecDiffObject::from(diff);

    assert_eq!(
        object,
        RestSpecDiffObject {
            added: vec!["GET /b".to_owned()],
            removed: vec!["GET /a".to_owned()],
            removed_grants: vec![RemovedOperationGrantObject {
                operation: "GET /a".to_owned(),
                roles: vec!["role-1".to_owned()],
            }],
            wildcard_gains: vec![OperationWildcardGainObject {
                role: "role-2".to_owned(),
                pattern: "rest:billing:GET *".to_owned(),
                operations: vec!["GET /b".to_owned()],
            }],
            flag_downgrades: vec![OperationFlagDowngradeObject {
                operation: "POST /c".to_owned(),
                before: OperationFlagsObject {
                    sensitive: true,
                    audit_always: true,
                },
                after: OperationFlagsObject {
                    sensitive: false,
                    audit_always: true,
                },
            }],
        }
    );
}

#[test]
fn a_version_with_its_times_becomes_the_object() {
    let mut version = view();
    version.spec.activated_at = Some(version.spec.created_at);
    version.spec.retired_at = Some(version.spec.created_at);

    let object = OpenApiSpecObject::from(OpenApiSpecResponse::from(&version));

    assert_eq!(object.id.as_str(), SPEC);
    assert_eq!(object.operation_count, 1);
    assert_eq!(
        object.activated_at.as_deref(),
        Some("1970-01-02T00:00:00.000000Z")
    );
    assert_eq!(
        object.retired_at.as_deref(),
        Some("1970-01-02T00:00:00.000000Z")
    );
    assert_eq!(object.diff.added, ["GET /invoices"]);
}
