use async_graphql::{EmptySubscription, Request, Schema, Value, Variables};
use iam_domain::{PropagationOutcome, RateFallback, RateKeyKind, RatePolicyId};
use rstest::rstest;
use serde_json::json;

use crate::error::IamError;
use crate::fixtures::{principal, recorded};
use crate::graphql::{IamMutation, IamQuery};
use crate::principal::Principal;
use crate::query::list_rate_policies::RatePolicyPage;
use crate::rate_policy_fixtures::{Answers, POLICY, rate_policy, receipt, receipt_at, scenario};

type IamSchema = Schema<IamQuery, IamMutation, EmptySubscription>;

const CREATE: &str = "mutation($input: CreateRatePolicyInput!) { createRatePolicy(input: $input) \
    { id name key limit periodMs burst fallback version propagation { status policyVersion } } }";
const UPDATE: &str = "mutation($input: UpdateRatePolicyInput!) { updateRatePolicy(input: $input) \
    { id limit version } }";
const DELETE: &str = "mutation($input: DeleteRatePolicyInput!) { deleteRatePolicy(input: $input) \
    { id version policyVersion } }";
const READ: &str = "query($id: ID!) { ratePolicy(id: $id) { id name periodMs version } }";
const LIST: &str = "query($first: Int, $after: String) { ratePolicies(first: $first, after: $after) \
    { items { id } nextCursor } }";

/// The caller data a request carries: none at all, or the outcome of the authentication.
enum Caller {
    Absent,
    Refused,
    Valid,
}

async fn run(
    answers: Answers,
    caller: Caller,
    query: &str,
    variables: serde_json::Value,
) -> (async_graphql::Response, crate::rate_policy_fixtures::Asked) {
    let (state, _commands, _queries, asked) = scenario(answers);
    let schema: IamSchema = Schema::build(IamQuery, IamMutation, EmptySubscription)
        .data(state)
        .finish();
    let mut request = Request::new(query).variables(Variables::from_json(variables));
    match caller {
        Caller::Absent => {}
        Caller::Refused => request = request.data(None::<Principal>),
        Caller::Valid => request = request.data(Some(principal())),
    }
    (schema.execute(request).await, asked)
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

fn creation() -> serde_json::Value {
    json!({ "input": {
        "name": "per-subject",
        "key": "subject_route",
        "limit": 100,
        "periodMs": 60_000,
        "burst": 20,
        "fallback": "divided",
    } })
}

#[tokio::test]
async fn a_created_policy_returns_its_data_and_the_propagation_of_its_policy_version() {
    let answers = Answers {
        receipt: receipt(Some(4)).with_propagation(PropagationOutcome::Published { offset: 9 }),
        ..Answers::default()
    };

    let (response, asked) = run(answers, Caller::Valid, CREATE, creation()).await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "createRatePolicy": {
            "id": POLICY,
            "name": "per-subject",
            "key": "subject_route",
            "limit": 100,
            "periodMs": 60_000,
            "burst": 20,
            "fallback": "divided",
            "version": 1,
            "propagation": { "status": "PUBLISHED", "policyVersion": 4 },
        } })
    );
    let sent = recorded(&asked.commands);
    assert_eq!(sent[0].values.key_kind, RateKeyKind::SubjectRoute);
    assert_eq!(sent[0].values.fallback, RateFallback::Divided);
    assert_eq!(sent[0].values.period_ms, 60_000);
}

#[rstest]
#[case::absent(Caller::Absent)]
#[case::refused(Caller::Refused)]
#[tokio::test]
async fn every_operation_needs_an_authenticated_caller(#[case] caller: Caller) {
    let (response, asked) = run(Answers::default(), caller, CREATE, creation()).await;

    assert_eq!(error_code(&response), Some(code_of("UNAUTHENTICATED")));
    assert!(recorded(&asked.commands).is_empty());
}

#[tokio::test]
async fn a_key_that_names_no_kind_is_a_validation_failure_and_dispatches_nothing() {
    let variables = json!({ "input": {
        "name": "a", "key": "everyone", "limit": 1, "periodMs": 1000, "burst": 0,
        "fallback": "full",
    } });

    let (response, asked) = run(Answers::default(), Caller::Valid, CREATE, variables).await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
    assert!(recorded(&asked.commands).is_empty());
}

#[tokio::test]
async fn the_propagated_consistency_is_refused_before_anything_is_dispatched() {
    let mut variables = creation();
    variables["input"]["consistency"] = json!("PROPAGATED");

    let (response, asked) = run(Answers::default(), Caller::Valid, CREATE, variables).await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
    assert!(recorded(&asked.commands).is_empty());
}

#[tokio::test]
async fn a_duplicate_name_is_a_conflict() {
    let answers = Answers {
        command: Err(|| IamError::Conflict),
        ..Answers::default()
    };

    let (response, _asked) = run(answers, Caller::Valid, CREATE, creation()).await;

    assert_eq!(error_code(&response), Some(code_of("CONFLICT")));
}

#[tokio::test]
async fn an_update_names_the_version_and_returns_the_new_state() {
    let answers = Answers {
        receipt: receipt_at(2, Some(6)),
        rate_policy: Ok(Some(rate_policy(2))),
        ..Answers::default()
    };
    let variables = json!({ "input": { "id": POLICY, "expectedVersion": 1, "limit": 200 } });

    let (response, asked) = run(answers, Caller::Valid, UPDATE, variables).await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "updateRatePolicy": { "id": POLICY, "limit": 100, "version": 2 } })
    );
    let sent = recorded(&asked.updates);
    assert_eq!(sent[0].expected.value(), 1);
    assert_eq!(sent[0].patch.limit, Some(200));
    assert_eq!(sent[0].patch.name, None);
}

#[rstest]
#[case::missing(json!({ "input": { "id": POLICY } }), "PRECONDITION_REQUIRED")]
#[case::below_one(json!({ "input": { "id": POLICY, "expectedVersion": 0 } }), "PRECONDITION_FAILED")]
#[case::bad_id(json!({ "input": { "id": "nope", "expectedVersion": 1 } }), "VALIDATION_FAILED")]
#[tokio::test]
async fn an_update_without_a_usable_version_or_id_is_refused_before_dispatch(
    #[case] variables: serde_json::Value,
    #[case] code: &str,
) {
    let (response, asked) = run(Answers::default(), Caller::Valid, UPDATE, variables).await;

    assert_eq!(error_code(&response), Some(code_of(code)));
    assert!(recorded(&asked.updates).is_empty());
}

#[tokio::test]
async fn a_deleted_policy_reports_its_final_version_and_policy_version() {
    let answers = Answers {
        receipt: receipt_at(2, Some(5)),
        ..Answers::default()
    };
    let variables = json!({ "input": { "id": POLICY, "expectedVersion": 1 } });

    let (response, asked) = run(answers, Caller::Valid, DELETE, variables).await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "deleteRatePolicy": { "id": POLICY, "version": 2, "policyVersion": 5 } })
    );
    assert_eq!(recorded(&asked.deletions)[0].expected.value(), 1);
}

#[tokio::test]
async fn a_policy_that_a_route_references_is_a_conflict() {
    let answers = Answers {
        delete: Err(|| IamError::ReferencedByRoute),
        ..Answers::default()
    };
    let variables = json!({ "input": { "id": POLICY, "expectedVersion": 1 } });

    let (response, _asked) = run(answers, Caller::Valid, DELETE, variables).await;

    assert_eq!(error_code(&response), Some(code_of("CONFLICT")));
}

#[tokio::test]
async fn a_stored_policy_is_read_by_id_and_an_unknown_one_is_null() {
    let (found, asked) = run(
        Answers::default(),
        Caller::Valid,
        READ,
        json!({ "id": POLICY }),
    )
    .await;
    let missing = Answers {
        rate_policy: Ok(None),
        ..Answers::default()
    };
    let (absent, _asked) = run(missing, Caller::Valid, READ, json!({ "id": POLICY })).await;

    assert_eq!(
        found.data.into_json().unwrap(),
        json!({ "ratePolicy": { "id": POLICY, "name": "per-subject", "periodMs": 60_000, "version": 1 } })
    );
    assert_eq!(
        recorded(&asked.rate_policies),
        [RatePolicyId::parse(POLICY).unwrap()]
    );
    assert_eq!(
        absent.data.into_json().unwrap(),
        json!({ "ratePolicy": null })
    );
}

#[tokio::test]
async fn a_page_lists_the_policies_and_names_the_cursor() {
    let answers = Answers {
        page: Ok(RatePolicyPage {
            rate_policies: vec![rate_policy(1)],
            next_after: Some(RatePolicyId::parse(POLICY).unwrap()),
        }),
        ..Answers::default()
    };

    let (response, asked) = run(answers, Caller::Valid, LIST, json!({ "first": 5 })).await;

    assert_eq!(
        response.data.into_json().unwrap(),
        json!({ "ratePolicies": { "items": [{ "id": POLICY }], "nextCursor": POLICY } })
    );
    assert_eq!(recorded(&asked.lists)[0].limit, 5);
}

#[rstest]
#[case::zero(json!({ "first": 0 }))]
#[case::too_large(json!({ "first": 101 }))]
#[case::bad_cursor(json!({ "after": "nope" }))]
#[tokio::test]
async fn invalid_page_arguments_are_validation_failures(#[case] variables: serde_json::Value) {
    let (response, asked) = run(Answers::default(), Caller::Valid, LIST, variables).await;

    assert_eq!(error_code(&response), Some(code_of("VALIDATION_FAILED")));
    assert_eq!(recorded(&asked.lists).len(), 0);
}

#[test]
fn the_inputs_are_read_from_graphql_objects_and_reject_other_values() {
    use async_graphql::InputType as _;

    use super::{CreateRatePolicyInput, DeleteRatePolicyInput, UpdateRatePolicyInput};

    let create =
        CreateRatePolicyInput::parse(Some(Value::from_json(creation()["input"].clone()).unwrap()))
            .unwrap();
    let update = UpdateRatePolicyInput::parse(Some(
        Value::from_json(json!({ "id": POLICY, "expectedVersion": 1, "limit": 200 })).unwrap(),
    ))
    .unwrap();
    let delete = DeleteRatePolicyInput::parse(Some(
        Value::from_json(json!({ "id": POLICY, "expectedVersion": 2 })).unwrap(),
    ))
    .unwrap();

    assert_eq!(create.name, "per-subject");
    assert_eq!(create.period_ms, 60_000);
    assert_eq!(update.limit, Some(200));
    assert_eq!(update.expected_version, Some(1));
    assert_eq!(delete.id.as_str(), POLICY);
    assert_eq!(delete.expected_version, Some(2));
    assert!(CreateRatePolicyInput::parse(Some(Value::Boolean(true))).is_err());
    assert!(UpdateRatePolicyInput::parse(Some(Value::Boolean(true))).is_err());
    assert!(DeleteRatePolicyInput::parse(Some(Value::Boolean(true))).is_err());
    let mut wrong_create = creation()["input"].clone();
    wrong_create["consistency"] = json!(true);
    let wrong_last = json!({ "id": POLICY, "consistency": true });
    assert!(CreateRatePolicyInput::parse(Some(Value::from_json(wrong_create).unwrap())).is_err());
    assert!(
        UpdateRatePolicyInput::parse(Some(Value::from_json(wrong_last.clone()).unwrap())).is_err()
    );
    assert!(DeleteRatePolicyInput::parse(Some(Value::from_json(wrong_last).unwrap())).is_err());
}
