use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use async_graphql::{EmptySubscription, Object, Request, Schema, Value};
use iam_domain::{
    AccessToken, AccessTokenParts, AssignmentScope, CompiledRoleSet, GrantStatus,
    GraphQlSchemaParser as _, PermissionGrant, RoleAssignment, RoleId, ServiceCatalog, ServiceName,
    SessionId, SubjectId, SubjectPolicy, SubjectRef, TokenId, TokenIdentity,
};
use rstest::rstest;
use shared_domain::Uuid;
use test_support::bus::FakeCommandBus;
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::policy_epoch::seeded_policy_epoch;
use test_support::policy_read::FakePolicyReadRepository;
use test_support::token::FakeTokenRepository;

use super::{IamAuthorizationExtension, owned_coordinates};
use crate::access_decision_service::AccessDecisionService;
use crate::command::record_rejected_attempt::RecordRejectedAttemptCommand;
use crate::error::IamError;
use crate::graphql::AsyncGraphQlSchemaParser;
use crate::iam_access_guard::IamAccessGuard;
use crate::principal::Principal;
use crate::service_catalog_loader::ServiceCatalogLoader;
use iam_domain::PolicyReadRepository;

const USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";
const NOW: u64 = 1_800_000_000;
const IAM_SDL: &str =
    "type Query { roles: String validateAccess: String } type Mutation { createRole: String }";

type Recorded = Arc<Mutex<Vec<RecordRejectedAttemptCommand>>>;

struct Query;

#[Object]
impl Query {
    async fn roles(&self) -> &str {
        "roles"
    }

    async fn validate_access(&self) -> &str {
        "validated"
    }

    async fn example(&self) -> &str {
        "example"
    }
}

struct Mutation;

#[Object]
impl Mutation {
    async fn create_role(&self) -> &str {
        "created"
    }
}

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn user() -> SubjectRef {
    SubjectRef::user(Uuid::parse(USER).unwrap())
}

fn principal() -> Principal {
    Principal::from(TokenIdentity::from(&AccessToken::new(AccessTokenParts {
        subject: SubjectId::User(Uuid::parse(USER).unwrap()),
        session: Some(SessionId::new("session-1").unwrap()),
        token_id: TokenId::new("jti-1").unwrap(),
        roles: Vec::new(),
        issued_at: at(NOW - 60),
        expires_at: at(NOW + 840),
    })))
}

fn holding(grants: &[&str]) -> SubjectPolicy {
    let role = RoleId::parse("00000000-0000-7000-8000-000000000101").unwrap();
    let grants = grants
        .iter()
        .map(|raw| (PermissionGrant::parse(raw).unwrap(), GrantStatus::Active));
    SubjectPolicy::new(
        seeded_policy_epoch(),
        vec![RoleAssignment::new(role, AssignmentScope::Global, None)],
        BTreeMap::from([(role, CompiledRoleSet::compile(grants))]),
    )
}

fn schema(grants: &[&str]) -> (Schema<Query, Mutation, EmptySubscription>, Recorded) {
    let graph = AsyncGraphQlSchemaParser.parse(IAM_SDL).unwrap();
    let catalog = ServiceCatalog::new(
        ServiceName::iam().clone(),
        seeded_policy_epoch(),
        Vec::new(),
        vec![graph],
    );
    let policy: Arc<dyn PolicyReadRepository> = Arc::new(
        FakePolicyReadRepository::new()
            .with_catalog(catalog)
            .with_subject(user(), holding(grants)),
    );
    let decisions = AccessDecisionService::new(
        Arc::new(FakeTokenRepository::new()),
        ServiceCatalogLoader::new(Arc::clone(&policy)),
        policy,
        Arc::new(FixedClock::at(at(NOW))),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    );
    let recorded: Recorded = Arc::default();
    let sink = Arc::clone(&recorded);
    let bus = FakeCommandBus::handling::<RecordRejectedAttemptCommand, _>(move |command| {
        sink.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(command);
        Ok::<(), IamError>(())
    });
    let guard = Arc::new(IamAccessGuard::new(Arc::new(decisions), Arc::new(bus)));
    let schema = Schema::build(Query, Mutation, EmptySubscription)
        .extension(IamAuthorizationExtension::new(guard))
        .finish();
    (schema, recorded)
}

fn request(query: &str, caller: Option<Principal>) -> Request {
    Request::new(query).data(caller)
}

fn code(response: &async_graphql::Response) -> Option<String> {
    let error = response.errors.first()?;
    let extensions = error.extensions.as_ref()?;
    let Value::String(code) = extensions.get("code")? else {
        return None;
    };
    Some(code.clone())
}

fn recorded_actions(recorded: &Recorded) -> Vec<String> {
    recorded
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .map(|command| command.action.as_str().to_owned())
        .collect()
}

fn names(query: &str, operation: Option<&str>) -> Vec<String> {
    let mut request = Request::new(query);
    request.operation_name = operation.map(str::to_owned);
    owned_coordinates(&request)
}

#[tokio::test]
async fn an_iam_field_without_a_principal_is_unauthenticated_and_nothing_runs() {
    let (schema, recorded) = schema(&["gql:iam:*"]);

    let response = schema.execute(request("{ roles }", None)).await;

    assert_eq!(code(&response).as_deref(), Some("UNAUTHENTICATED"));
    assert_eq!(response.data, Value::Null);
    assert_eq!(recorded_actions(&recorded), Vec::<String>::new());
}

#[tokio::test]
async fn a_request_without_principal_data_is_unauthenticated() {
    let (schema, _recorded) = schema(&["gql:iam:*"]);

    let response = schema.execute(Request::new("{ roles }")).await;

    assert_eq!(code(&response).as_deref(), Some("UNAUTHENTICATED"));
}

#[tokio::test]
async fn a_document_of_template_fields_runs_without_a_token() {
    let (schema, recorded) = schema(&[]);

    let response = schema.execute(request("{ example }", None)).await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(
        response.data.into_json().unwrap(),
        serde_json::json!({"example": "example"})
    );
    assert_eq!(recorded_actions(&recorded), Vec::<String>::new());
}

#[tokio::test]
async fn a_caller_without_the_key_is_forbidden_and_the_refusal_is_audited() {
    let (schema, recorded) = schema(&["gql:iam:Query.roles"]);

    let response = schema
        .execute(request("mutation { createRole }", Some(principal())))
        .await;

    assert_eq!(code(&response).as_deref(), Some("FORBIDDEN"));
    assert_eq!(response.data, Value::Null);
    assert_eq!(recorded_actions(&recorded), ["role.create"]);
}

#[tokio::test]
async fn a_template_field_beside_an_iam_field_does_not_escape_the_check() {
    let (schema, recorded) = schema(&[]);

    let response = schema
        .execute(request("{ example roles }", Some(principal())))
        .await;

    assert_eq!(code(&response).as_deref(), Some("FORBIDDEN"));
    assert_eq!(recorded_actions(&recorded), ["role.list"]);
}

#[tokio::test]
async fn a_caller_holding_the_key_runs_the_document() {
    let (schema, recorded) = schema(&["gql:iam:Query.roles"]);

    let response = schema
        .execute(request("{ roles example }", Some(principal())))
        .await;

    assert!(response.errors.is_empty(), "{:?}", response.errors);
    assert_eq!(recorded_actions(&recorded), Vec::<String>::new());
}

#[tokio::test]
async fn token_validation_needs_the_reserved_key() {
    let (schema, recorded) = schema(&["gql:iam:*"]);

    let response = schema
        .execute(request("{ validateAccess }", Some(principal())))
        .await;

    assert_eq!(code(&response).as_deref(), Some("FORBIDDEN"));
    assert_eq!(recorded_actions(&recorded), ["access.validate"]);
}

#[tokio::test]
async fn a_document_that_does_not_parse_is_left_to_execution() {
    let (schema, recorded) = schema(&[]);

    let response = schema.execute(request("{ roles", None)).await;

    assert_ne!(response.errors, Vec::new());
    assert_ne!(code(&response).as_deref(), Some("UNAUTHENTICATED"));
    assert_eq!(recorded_actions(&recorded), Vec::<String>::new());
}

#[rstest]
#[case::plain("{ roles }", None, &["Query.roles"])]
#[case::alias("{ mine: roles }", None, &["Query.roles"])]
#[case::template_only("{ example }", None, &[])]
#[case::mutation("mutation { createRole }", None, &["Mutation.createRole"])]
#[case::same_name_other_root("mutation { roles }", None, &[])]
#[case::inline_fragment("{ ... on Query { roles } }", None, &["Query.roles"])]
#[case::fragment_spread(
    "{ ...Fields } fragment Fields on Query { roles validateAccess }",
    None,
    &["Query.roles", "Query.validateAccess"]
)]
#[case::nested_fragment(
    "{ ...A } fragment A on Query { ...B } fragment B on Query { roles }",
    None,
    &["Query.roles"]
)]
#[case::fragment_cycle(
    "{ ...A } fragment A on Query { roles ...B } fragment B on Query { ...A }",
    None,
    &["Query.roles"]
)]
#[case::unknown_fragment("{ ...Missing example }", None, &[])]
#[case::repeated("{ roles again: roles }", None, &["Query.roles"])]
#[case::subscription("subscription { roles }", None, &[])]
#[case::named_operation(
    "query A { example } query B { roles }",
    Some("A"),
    &[]
)]
#[case::other_named_operation(
    "query A { example } query B { roles }",
    Some("B"),
    &["Query.roles"]
)]
#[case::unknown_operation_name(
    "query A { example } query B { roles }",
    Some("C"),
    &["Query.roles"]
)]
#[case::unnamed_operations(
    "query A { example } query B { roles }",
    None,
    &["Query.roles"]
)]
#[case::malformed("{ roles", None, &[])]
fn the_selected_iam_root_fields_are_collected(
    #[case] query: &str,
    #[case] operation: Option<&str>,
    #[case] expected: &[&str],
) {
    assert_eq!(names(query, operation), expected);
}
