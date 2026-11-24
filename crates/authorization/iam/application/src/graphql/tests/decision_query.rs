use async_graphql::{EmptyMutation, EmptySubscription, Request, Schema};

use crate::graphql::DecisionQuery;

type DecisionSchema = Schema<DecisionQuery, EmptyMutation, EmptySubscription>;

fn schema() -> DecisionSchema {
    Schema::build(DecisionQuery, EmptyMutation, EmptySubscription).finish()
}

async fn errors_of(document: &str) -> Vec<String> {
    schema()
        .execute(Request::new(document))
        .await
        .errors
        .into_iter()
        .map(|error| error.message)
        .collect()
}

#[tokio::test]
async fn the_decision_schema_exposes_only_the_three_decision_fields() {
    let response = schema()
        .execute(Request::new(
            "{ __schema { queryType { name fields { name } } } }",
        ))
        .await
        .data
        .into_json()
        .unwrap();

    let root = &response["__schema"]["queryType"];
    assert_eq!(root["name"], "Query");
    let mut names: Vec<&str> = root["fields"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|field| field["name"].as_str())
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        ["resolveToken", "validateAccess", "validateAccessBatch"]
    );
}

#[tokio::test]
async fn a_management_field_is_an_unknown_field() {
    for document in [
        "{ role(id: \"1\") { id } }",
        "{ roles { items { id } } }",
        "{ createRole(input: { name: \"x\" }) { id } }",
    ] {
        let errors = errors_of(document).await;

        assert!(
            errors
                .iter()
                .any(|message| message.contains("Unknown field")),
            "{document}: {errors:?}"
        );
    }
}

#[tokio::test]
async fn a_mutation_is_refused_because_the_schema_has_none() {
    let mut errors = errors_of("mutation { createRole(input: { name: \"x\" }) { id } }").await;
    errors.dedup();

    assert_eq!(errors, ["Schema is not configured for mutations."]);
}
