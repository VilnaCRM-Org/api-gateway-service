//! REST handlers that retire a GraphQL or an `OpenAPI` specification version, and the use-case
//! calls that the GraphQL resolvers share.
//!
//! A handler takes the IAM state and the problem-aware extractors only (`ApiPath`,
//! `ValidatedJson`, the IAM extractors `CallerPrincipal` and `IdempotencyKeyHeader`); the test of
//! the `handler` module checks every handler against that rule.

pub mod dto;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::AppendHeaders;
use iam_domain::{ChangeId, ChangeReceipt, IdempotencyKey, IdempotencyRequest, SpecId, SpecStatus};
use shared_application::http::{ApiPath, Problem, ValidatedJson};

use super::IamState;
use super::extract::{CallerPrincipal, IdempotencyKeyHeader};
use super::graphql_activation::current_policy_version;
use super::graphql_spec::{find_graphql_spec, parse_spec_id};
use super::openapi_spec::find_openapi_spec;
use super::response::{IAM_POLICY_VERSION, WriteHeaders};
use super::user_role::find_replay;
use crate::command::retire_graphql_spec::RetireGraphQlSpecCommand;
use crate::command::retire_openapi_spec::RetireOpenApiSpecCommand;
use crate::error::IamError;
use crate::principal::Principal;
use crate::query::get_change_receipt::GetChangeReceiptQuery;
use dto::{RetireSpecRequest, SpecRetirementResponse};

/// The two specification forms a retirement applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SpecForm {
    /// A GraphQL schema.
    GraphQl,
    /// An `OpenAPI` document.
    OpenApi,
}

impl SpecForm {
    /// The operation name that the idempotency digest covers.
    const fn operation(self) -> &'static str {
        match self {
            Self::GraphQl => "graphql_spec",
            Self::OpenApi => "openapi_spec",
        }
    }
}

/// What a retirement produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SpecRetirement {
    /// The retired version.
    pub spec_id: SpecId,
    /// The service of the version.
    pub service: String,
    /// The policy version the retirement produced.
    pub policy_version: i64,
}

impl From<&SpecRetirement> for SpecRetirementResponse {
    fn from(retirement: &SpecRetirement) -> Self {
        Self {
            id: retirement.spec_id.to_string(),
            service: retirement.service.clone(),
            status: SpecStatus::Retired.as_str().to_owned(),
            policy_version: retirement.policy_version,
        }
    }
}

/// Retires the GraphQL version `id` as `caller`, or replays the retirement that `key` already
/// committed; REST and GraphQL share it.
///
/// # Errors
///
/// The problem of a refused request: 404 for an unknown version, 409 for a version that is not
/// active, a concurrent change or orphaned grants without `confirmOrphans`, 422 for a key reused
/// for another request, 500 for a storage failure.
pub(crate) async fn retire_graphql_spec(
    state: &IamState,
    caller: &Principal,
    key: Option<IdempotencyKey>,
    id: SpecId,
    request: &RetireSpecRequest,
) -> Result<SpecRetirement, Problem> {
    retire(state, caller, (SpecForm::GraphQl, id), key, request).await
}

/// Retires the `OpenAPI` version `id` as `caller`, or replays the retirement that `key` already
/// committed; REST and GraphQL share it.
///
/// # Errors
///
/// The problem of a refused request: 404 for an unknown version, 409 for a version that is not
/// active, a concurrent change or orphaned grants without `confirmOrphans`, 422 for a key reused
/// for another request, 500 for a storage failure.
pub(crate) async fn retire_openapi_spec(
    state: &IamState,
    caller: &Principal,
    key: Option<IdempotencyKey>,
    id: SpecId,
    request: &RetireSpecRequest,
) -> Result<SpecRetirement, Problem> {
    retire(state, caller, (SpecForm::OpenApi, id), key, request).await
}

/// The retirement of one version of either form.
async fn retire(
    state: &IamState,
    caller: &Principal,
    (form, id): (SpecForm, SpecId),
    key: Option<IdempotencyKey>,
    request: &RetireSpecRequest,
) -> Result<SpecRetirement, Problem> {
    let actor = caller.actor();
    let idempotency = key.map(|key| IdempotencyRequest {
        key,
        request_digest: state
            .request_digester
            .digest(&request.canonical_form(form.operation(), id)),
    });
    if let Some(replayed) = find_replay(state, &actor, idempotency.as_ref()).await? {
        return committed(state, form, &replayed).await;
    }
    service_of(state, form, id).await?;
    let change_id = ChangeId::from_uuid(state.uuid_generator.generate());
    dispatch(state, form, change_id, (actor, id), (request, idempotency)).await?;
    let receipt = state
        .query_bus
        .ask(GetChangeReceiptQuery { change_id })
        .await?;
    committed(state, form, &receipt).await
}

/// Dispatches the command of `form`.
async fn dispatch(
    state: &IamState,
    form: SpecForm,
    change_id: ChangeId,
    (actor, spec_id): (iam_domain::ActorRef, SpecId),
    (request, idempotency): (&RetireSpecRequest, Option<IdempotencyRequest>),
) -> Result<(), Problem> {
    match form {
        SpecForm::GraphQl => {
            state
                .command_bus
                .dispatch(RetireGraphQlSpecCommand {
                    change_id,
                    actor,
                    spec_id,
                    confirm_orphans: request.confirm_orphans,
                    idempotency,
                })
                .await?;
        }
        SpecForm::OpenApi => {
            state
                .command_bus
                .dispatch(RetireOpenApiSpecCommand {
                    change_id,
                    actor,
                    spec_id,
                    confirm_orphans: request.confirm_orphans,
                    idempotency,
                })
                .await?;
        }
    }
    Ok(())
}

/// The service of the version, or the 404 problem of an unknown one.
async fn service_of(state: &IamState, form: SpecForm, id: SpecId) -> Result<String, Problem> {
    let service = match form {
        SpecForm::GraphQl => find_graphql_spec(state, id, false)
            .await?
            .map(|summary| summary.spec.content.service.to_string()),
        SpecForm::OpenApi => find_openapi_spec(state, id, false)
            .await?
            .map(|summary| summary.spec.content.service.to_string()),
    };
    service.ok_or_else(|| Problem::from(IamError::NotFound))
}

/// The retirement that the receipt of a committed change names.
async fn committed(
    state: &IamState,
    form: SpecForm,
    receipt: &ChangeReceipt,
) -> Result<SpecRetirement, Problem> {
    let spec_id = SpecId::parse(receipt.target().target_id()).map_err(IamError::from)?;
    let service = service_of(state, form, spec_id).await?;
    let policy_version = match receipt.policy_version() {
        Some(version) => version.value(),
        None => current_policy_version(state).await?,
    };
    Ok(SpecRetirement {
        spec_id,
        service,
        policy_version,
    })
}

/// The headers of a retirement: the policy version it produced.
fn retirement_headers(retirement: &SpecRetirement) -> WriteHeaders {
    AppendHeaders(vec![(
        IAM_POLICY_VERSION,
        retirement.policy_version.to_string(),
    )])
}

/// Retires a GraphQL specification version.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 404 for an unknown version, 409 for a version
/// that is not active, a concurrent change or orphaned grants without confirmation, 422 for an id
/// that is not a UUID or a reused idempotency key, 500 when the storage fails.
#[utoipa::path(
    post,
    path = "/graphql-specs/{id}/retirement",
    operation_id = "api_graphql_specs_id_retirement_post",
    tag = "iam",
    summary = "Retires a GraphQL specification.",
    description = "Retires the active version: its fields leave the catalogue of the service unless another active version holds them, the next policy version is taken and `iam.graphql_spec.retired` is recorded. A retirement that would orphan grants is refused with 409 unless `confirmOrphans` is `true`; the problem lists the grants. With the confirmation the grants become inactive, `iam.permissions.orphaned` is recorded and a grant stays inactive when its key returns with a later version until an administrator grants it again. A repeated `Idempotency-Key` with the same body within 24 hours returns the original result.",
    security(("bearerAuth" = [])),
    params(
        ("id" = String, Path, format = Uuid, description = "Version identifier"),
        ("Idempotency-Key" = Option<String>, Header, description = "Makes the retirement safe to repeat for 24 hours; 1 to 255 visible ASCII characters.")
    ),
    request_body(content = RetireSpecRequest, content_type = "application/json"),
    responses(
        (
            status = 200,
            description = "The version was retired.",
            body = SpecRetirementResponse,
            headers(("iam-policy-version" = String, description = "The policy version that the change produced."))
        ),
        (status = 400, description = "Invalid input.", body = Problem, content_type = "application/problem+json"),
        (
            status = 401,
            description = "The caller presented no valid bearer token.",
            body = Problem,
            content_type = "application/problem+json",
            headers(("www-authenticate" = String, description = "The `Bearer` challenge."))
        ),
        (status = 404, description = "Version not found.", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "The version is not active, another change got there first, or the retirement would orphan grants (`/problems/orphan-confirmation-required`) without confirmation.", body = Problem, content_type = "application/problem+json"),
        (status = 413, description = "Request body too large.", body = Problem, content_type = "application/problem+json"),
        (status = 415, description = "Unsupported media type.", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed: an invalid identifier or idempotency key, or the idempotency key was used for another request.", body = Problem, content_type = "application/problem+json"),
        (status = "default", description = "Problem response.", body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn retire_graphql(
    State(state): State<IamState>,
    CallerPrincipal(caller): CallerPrincipal,
    IdempotencyKeyHeader(key): IdempotencyKeyHeader,
    ApiPath(id): ApiPath<String>,
    ValidatedJson(body): ValidatedJson<RetireSpecRequest>,
) -> Result<(StatusCode, WriteHeaders, Json<SpecRetirementResponse>), Problem> {
    let retirement = retire_graphql_spec(&state, &caller, key, parse_spec_id(&id)?, &body).await?;
    let headers = retirement_headers(&retirement);
    Ok((
        StatusCode::OK,
        headers,
        Json(SpecRetirementResponse::from(&retirement)),
    ))
}

/// Retires an `OpenAPI` specification version.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 404 for an unknown version, 409 for a version
/// that is not active, a concurrent change or orphaned grants without confirmation, 422 for an id
/// that is not a UUID or a reused idempotency key, 500 when the storage fails.
#[utoipa::path(
    post,
    path = "/openapi-specs/{id}/retirement",
    operation_id = "api_openapi_specs_id_retirement_post",
    tag = "iam",
    summary = "Retires an OpenAPI specification.",
    description = "Retires the active version: its operations leave the catalogue of the service unless another active version holds them, the next policy version is taken and `iam.openapi_spec.retired` is recorded. A retirement that would orphan grants is refused with 409 unless `confirmOrphans` is `true`; the problem lists the grants. With the confirmation the grants become inactive, `iam.permissions.orphaned` is recorded and a grant stays inactive when its key returns with a later version until an administrator grants it again. A repeated `Idempotency-Key` with the same body within 24 hours returns the original result.",
    security(("bearerAuth" = [])),
    params(
        ("id" = String, Path, format = Uuid, description = "Version identifier"),
        ("Idempotency-Key" = Option<String>, Header, description = "Makes the retirement safe to repeat for 24 hours; 1 to 255 visible ASCII characters.")
    ),
    request_body(content = RetireSpecRequest, content_type = "application/json"),
    responses(
        (
            status = 200,
            description = "The version was retired.",
            body = SpecRetirementResponse,
            headers(("iam-policy-version" = String, description = "The policy version that the change produced."))
        ),
        (status = 400, description = "Invalid input.", body = Problem, content_type = "application/problem+json"),
        (
            status = 401,
            description = "The caller presented no valid bearer token.",
            body = Problem,
            content_type = "application/problem+json",
            headers(("www-authenticate" = String, description = "The `Bearer` challenge."))
        ),
        (status = 404, description = "Version not found.", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "The version is not active, another change got there first, or the retirement would orphan grants (`/problems/orphan-confirmation-required`) without confirmation.", body = Problem, content_type = "application/problem+json"),
        (status = 413, description = "Request body too large.", body = Problem, content_type = "application/problem+json"),
        (status = 415, description = "Unsupported media type.", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed: an invalid identifier or idempotency key, or the idempotency key was used for another request.", body = Problem, content_type = "application/problem+json"),
        (status = "default", description = "Problem response.", body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn retire_openapi(
    State(state): State<IamState>,
    CallerPrincipal(caller): CallerPrincipal,
    IdempotencyKeyHeader(key): IdempotencyKeyHeader,
    ApiPath(id): ApiPath<String>,
    ValidatedJson(body): ValidatedJson<RetireSpecRequest>,
) -> Result<(StatusCode, WriteHeaders, Json<SpecRetirementResponse>), Problem> {
    let retirement = retire_openapi_spec(&state, &caller, key, parse_spec_id(&id)?, &body).await?;
    let headers = retirement_headers(&retirement);
    Ok((
        StatusCode::OK,
        headers,
        Json(SpecRetirementResponse::from(&retirement)),
    ))
}

#[cfg(test)]
mod tests;
