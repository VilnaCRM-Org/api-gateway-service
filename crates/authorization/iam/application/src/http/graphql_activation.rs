//! REST handler that activates a GraphQL specification version, and the use-case call that the
//! GraphQL resolver shares.
//!
//! A handler takes the IAM state and the problem-aware extractors only (`ApiPath`,
//! `ValidatedJson`, the IAM extractors `CallerPrincipal` and `IdempotencyKeyHeader`); the test of
//! the `handler` module checks every handler against that rule.

pub mod dto;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::AppendHeaders;
use iam_domain::{
    ChangeId, ChangeReceipt, IdempotencyKey, IdempotencyRequest, PermissionKey, SpecId, SpecStatus,
};
use shared_application::http::{ApiPath, Problem, ValidatedJson};

use super::IamState;
use super::extract::{CallerPrincipal, IdempotencyKeyHeader};
use super::graphql_spec::{find_graphql_spec, parse_spec_id};
use super::response::{IAM_POLICY_VERSION, WriteHeaders};
use super::user_role::find_replay;
use crate::command::create_graphql_permissions::CreateGraphQlPermissionsCommand;
use crate::error::IamError;
use crate::principal::Principal;
use crate::query::get_change_receipt::GetChangeReceiptQuery;
use crate::query::get_graphql_permissions_created::GetGraphQlPermissionsCreatedQuery;
use crate::query::get_policy_epoch::GetPolicyEpochQuery;
use dto::{CreateGraphQlPermissionsRequest, GraphQlPermissionsActivationResponse};

/// What an activation produced, and whether this call committed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GraphQlActivation {
    /// The activated version.
    pub spec_id: SpecId,
    /// The service of the version.
    pub service: String,
    /// The keys the activation added to the catalogue.
    pub created_keys: Vec<PermissionKey>,
    /// The policy version the activation produced, or the current one for a no-op.
    pub policy_version: i64,
    /// `true` when the activation was committed (by this call or by the call that the same
    /// idempotency key repeats), `false` for a version that was active already.
    pub committed: bool,
}

impl From<&GraphQlActivation> for GraphQlPermissionsActivationResponse {
    fn from(activation: &GraphQlActivation) -> Self {
        Self {
            id: activation.spec_id.to_string(),
            service: activation.service.clone(),
            status: SpecStatus::Active.as_str().to_owned(),
            created_keys: activation
                .created_keys
                .iter()
                .map(ToString::to_string)
                .collect(),
            policy_version: activation.policy_version,
        }
    }
}

/// Activates the version `id` as `caller`, or replays the activation that `key` already
/// committed, or reports that the version is active already; REST and GraphQL share it.
///
/// The receipt of the change and the keys it created are read back, because a command returns no
/// data.
///
/// # Errors
///
/// The problem of a refused request: 404 for an unknown version, 409 for a retired version, a
/// concurrent change, a flag downgrade without `confirmFlagDowngrade` or orphaned grants without
/// `confirmOrphans`, 422 for invalid renames or a key reused for another request, 500 for a
/// storage failure.
pub(crate) async fn create_graphql_permissions(
    state: &IamState,
    caller: &Principal,
    key: Option<IdempotencyKey>,
    id: SpecId,
    request: &CreateGraphQlPermissionsRequest,
) -> Result<GraphQlActivation, Problem> {
    let renames = request.parse()?;
    let actor = caller.actor();
    let idempotency = key.map(|key| IdempotencyRequest {
        key,
        request_digest: state.request_digester.digest(&request.canonical_form(id)),
    });
    if let Some(replayed) = find_replay(state, &actor, idempotency.as_ref()).await? {
        return committed(state, &replayed).await;
    }
    let spec = find_graphql_spec(state, id, false)
        .await?
        .ok_or(IamError::NotFound)?;
    if spec.spec.status == SpecStatus::Active {
        return already_active(state, id, spec.spec.content.service.to_string()).await;
    }
    let change_id = ChangeId::from_uuid(state.uuid_generator.generate());
    let command = CreateGraphQlPermissionsCommand {
        change_id,
        actor,
        spec_id: id,
        renames,
        confirm_orphans: request.confirm_orphans,
        confirm_flag_downgrade: request.confirm_flag_downgrade,
        idempotency,
    };
    state.command_bus.dispatch(command).await?;
    let receipt = state
        .query_bus
        .ask(GetChangeReceiptQuery { change_id })
        .await?;
    committed(state, &receipt).await
}

/// The activation that the receipt of a committed change names, with the keys it created.
async fn committed(
    state: &IamState,
    receipt: &ChangeReceipt,
) -> Result<GraphQlActivation, Problem> {
    let spec_id = SpecId::parse(receipt.target().target_id()).map_err(IamError::from)?;
    let spec = find_graphql_spec(state, spec_id, false)
        .await?
        .ok_or(IamError::NotFound)?;
    let created_keys = state
        .query_bus
        .ask(GetGraphQlPermissionsCreatedQuery { spec_id })
        .await?;
    let policy_version = match receipt.policy_version() {
        Some(version) => version.value(),
        None => current_policy_version(state).await?,
    };
    Ok(GraphQlActivation {
        spec_id,
        service: spec.spec.content.service.to_string(),
        created_keys,
        policy_version,
        committed: true,
    })
}

/// The no-op of a version that is active already: nothing was created and the policy version is
/// the current one.
async fn already_active(
    state: &IamState,
    spec_id: SpecId,
    service: String,
) -> Result<GraphQlActivation, Problem> {
    Ok(GraphQlActivation {
        spec_id,
        service,
        created_keys: Vec::new(),
        policy_version: current_policy_version(state).await?,
        committed: false,
    })
}

/// The current policy version.
pub(crate) async fn current_policy_version(state: &IamState) -> Result<i64, Problem> {
    let epoch = state.query_bus.ask(GetPolicyEpochQuery).await?;
    Ok(epoch.version().value())
}

/// The headers of an activation: the policy version it produced.
fn activation_headers(activation: &GraphQlActivation) -> WriteHeaders {
    AppendHeaders(vec![(
        IAM_POLICY_VERSION,
        activation.policy_version.to_string(),
    )])
}

/// Activates a GraphQL specification version.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 404 for an unknown version, 409 for a retired
/// version, a concurrent change or a missing confirmation, 422 for invalid renames, an id that is
/// not a UUID or a reused idempotency key, 500 when the storage fails.
#[utoipa::path(
    post,
    path = "/graphql-specs/{id}/permissions",
    operation_id = "api_graphql_specs_id_permissions_post",
    tag = "iam",
    summary = "Activates a GraphQL specification.",
    description = "Makes the draft version active and its fields grantable permissions: the catalogue of the service becomes the union of its active versions, the next policy version is taken and `iam.graphql_permissions.created` is recorded with `createdKeys`, `renamed` and `flagChanges`. An activation that would remove the sensitive or always-audit flag from a key is refused with 409 unless `confirmFlagDowngrade` is `true`, and one that would orphan grants is refused with 409 unless `confirmOrphans` is `true`; the problem lists the keys or the grants. `renames` moves the grants of old keys to new keys before anything is orphaned. A version that is active already returns 200 and changes nothing. A repeated `Idempotency-Key` with the same body within 24 hours returns the original result.",
    security(("bearerAuth" = [])),
    params(
        ("id" = String, Path, format = Uuid, description = "Version identifier"),
        ("Idempotency-Key" = Option<String>, Header, description = "Makes the activation safe to repeat for 24 hours; 1 to 255 visible ASCII characters.")
    ),
    request_body(content = CreateGraphQlPermissionsRequest, content_type = "application/json"),
    responses(
        (
            status = 201,
            description = "The version was activated.",
            body = GraphQlPermissionsActivationResponse,
            headers(("iam-policy-version" = String, description = "The policy version that the change produced."))
        ),
        (
            status = 200,
            description = "The version was active already; nothing changed.",
            body = GraphQlPermissionsActivationResponse,
            headers(("iam-policy-version" = String, description = "The current policy version."))
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
        (status = 409, description = "The version is retired, another change got there first, the activation would remove a flag (`/problems/flag-downgrade-confirmation-required`) or orphan grants (`/problems/orphan-confirmation-required`) without confirmation.", body = Problem, content_type = "application/problem+json"),
        (status = 413, description = "Request body too large.", body = Problem, content_type = "application/problem+json"),
        (status = 415, description = "Unsupported media type.", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed: an invalid identifier, rename or idempotency key, or the idempotency key was used for another request.", body = Problem, content_type = "application/problem+json"),
        (status = "default", description = "Problem response.", body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn create(
    State(state): State<IamState>,
    CallerPrincipal(caller): CallerPrincipal,
    IdempotencyKeyHeader(key): IdempotencyKeyHeader,
    ApiPath(id): ApiPath<String>,
    ValidatedJson(body): ValidatedJson<CreateGraphQlPermissionsRequest>,
) -> Result<
    (
        StatusCode,
        WriteHeaders,
        Json<GraphQlPermissionsActivationResponse>,
    ),
    Problem,
> {
    let activation =
        create_graphql_permissions(&state, &caller, key, parse_spec_id(&id)?, &body).await?;
    let status = if activation.committed {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    let headers = activation_headers(&activation);
    Ok((
        status,
        headers,
        Json(GraphQlPermissionsActivationResponse::from(&activation)),
    ))
}

#[cfg(test)]
mod tests;
