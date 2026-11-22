use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_graphql::Request;
use iam_application::http::IamState;
use iam_application::{Principal, ResolveSubjectTokenQuery, TokenResolution};
use iam_domain::{AccessToken, AccessTokenParts, SessionId, SubjectId, TokenId, TokenIdentity};
use shared_domain::{CommandBus, QueryBus, Uuid};
use test_support::bus::{FakeCommandBus, FakeQueryBus};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;

use super::*;

const EXPECTED_SDL: &str = r#""Input of the create mutation."
input CreateExampleApiResourceInput {
  "Description."
  description: String!
  "Name."
  name: String!
}

"Template example resource."
type ExampleApiResource {
  "Description."
  description: String!
  "Identifier."
  id: ID!
  "Name."
  name: String!
}

"Mutation root."
type Mutation {
  "Creates an example API resource."
  createExampleApiResource(input: CreateExampleApiResourceInput!): ExampleApiResource!
}

"Query root."
type Query {
  "Retrieves an example API resource by id."
  exampleApiResource(id: ID!): ExampleApiResource
  "Retrieves one page of example API resources, newest first."
  exampleApiResources(
    "Number of items per page, from 1 to 100."
    itemsPerPage: Int! = 30,
    "Page number, from 1."
    page: Int! = 1
  ): [ExampleApiResource!]!
  "Resolves a User service token into its subject, or says why it is refused."
  resolveToken(input: ResolveTokenInput!): TokenResolution!
}

"Input of the token-resolution query."
input ResolveTokenInput {
  "The User service token to resolve; an empty one resolves as `token_missing`."
  credential: String!
}

"The resolution of a credential: the subject and its token claims, or the reason it is refused."
type TokenResolution {
  "When the token expires, in seconds since 1970-01-01T00:00:00Z."
  expiresAt: Int
  "Why the credential is refused: `token_missing`, `token_invalid`, `token_expired` or `token_revoked`."
  reason: String
  "Whether the credential is valid and unrevoked."
  resolved: Boolean!
  "The roles claim of the token as issued."
  roles: [String!]
  "The User service session of the token, when it names one."
  sessionId: String
  "The user id, or the service name of a service principal."
  subjectId: String
  "`user` or `service`."
  subjectKind: String
}

"Directs the executor to include this field or fragment only when the `if` argument is true."
directive @include(if: Boolean!) on FIELD | FRAGMENT_SPREAD | INLINE_FRAGMENT
"Directs the executor to skip this field or fragment when the `if` argument is true."
directive @skip(if: Boolean!) on FIELD | FRAGMENT_SPREAD | INLINE_FRAGMENT
schema {
  query: Query
  mutation: Mutation
}
"#;

#[test]
fn the_sdl_is_the_documented_schema() {
    assert_eq!(sdl(), EXPECTED_SDL);
}

#[test]
fn the_sdl_has_the_four_operations_and_nothing_else_to_call() {
    let text = sdl();

    assert!(text.contains("resolveToken(input: ResolveTokenInput!): TokenResolution!"));
    assert!(text.contains("exampleApiResource(id: ID!)"));
    assert!(text.contains("exampleApiResources("));
    assert!(text.contains("createExampleApiResource(input: CreateExampleApiResourceInput!)"));
    for absent in [
        "node",
        "Connection",
        "update",
        "delete",
        "type Subscription",
    ] {
        assert!(!text.contains(absent), "the SDL contains `{absent}`");
    }
}

#[test]
fn twenty_generations_are_byte_identical() {
    let first = sdl();

    for _ in 0..20 {
        assert_eq!(sdl(), first);
    }
}

#[tokio::test]
async fn the_builder_gives_a_schema_with_the_two_roots() {
    let schema: ApiSchema = builder().finish();

    let response = schema.execute(Request::new("{ query: __typename }")).await;
    let mutation = schema
        .execute(Request::new("mutation { mutation: __typename }"))
        .await;

    assert_eq!(
        response.data.into_json().unwrap(),
        serde_json::json!({ "query": "Query" })
    );
    assert_eq!(
        mutation.data.into_json().unwrap(),
        serde_json::json!({ "mutation": "Mutation" })
    );
}

fn principal() -> Principal {
    Principal::from(TokenIdentity::from(&AccessToken::new(AccessTokenParts {
        subject: SubjectId::User(Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap()),
        session: Some(SessionId::new("session-1").unwrap()),
        token_id: TokenId::new("jti-1").unwrap(),
        roles: vec!["ROLE_USER".to_owned()],
        issued_at: SystemTime::UNIX_EPOCH,
        expires_at: SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_mins(15))
            .unwrap(),
    })))
}

fn iam_state() -> IamState {
    let resolved = TokenResolution::Resolved(principal());
    let queries =
        FakeQueryBus::answering(move |_query: ResolveSubjectTokenQuery| Ok(resolved.clone()));
    let command_bus: Arc<dyn CommandBus> = Arc::new(FakeCommandBus::unregistered());
    let query_bus: Arc<dyn QueryBus> = Arc::new(queries);
    IamState {
        command_bus,
        query_bus,
        uuid_generator: Arc::new(SequenceUuidGenerator::starting_at(1)),
        clock: Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
    }
}

#[tokio::test]
async fn resolve_token_is_merged_into_the_query_root_and_reaches_the_iam_state() {
    let schema: ApiSchema = builder().data(iam_state()).finish();
    let request = Request::new(
        "{ resolveToken(input: { credential: \"any\" }) { resolved subjectKind sessionId } }",
    )
    .data(Some(principal()));

    let response = schema.execute(request).await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        serde_json::json!({ "resolveToken": {
            "resolved": true,
            "subjectKind": "user",
            "sessionId": "session-1",
        } })
    );
}

#[tokio::test]
async fn resolve_token_without_the_iam_state_in_the_schema_data_is_an_internal_error() {
    let schema: ApiSchema = builder().finish();
    let request = Request::new("{ resolveToken(input: { credential: \"any\" }) { resolved } }")
        .data(Some(principal()));

    let response = schema.execute(request).await;

    let code = response
        .errors
        .first()
        .and_then(|error| error.extensions.as_ref())
        .and_then(|extensions| extensions.get("code"))
        .cloned();
    assert_eq!(
        code,
        Some(async_graphql::Value::String(
            "INTERNAL_SERVER_ERROR".to_owned()
        ))
    );
}
