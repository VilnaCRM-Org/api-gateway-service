//! REST handlers of the grants of a role, and the use-case calls that the GraphQL resolvers share.
//!
//! A handler takes the IAM state and the problem-aware extractors only (`ApiPath`, `ValidatedJson`,
//! the IAM extractors `CallerPrincipal` and `VersionedWriteHeaders`); the test of the `handler`
//! module checks every handler against that rule.

pub mod dto;

use axum::Json;
use axum::extract::State;
use axum::http::header::ETAG;
use axum::http::{HeaderName, StatusCode};
use iam_domain::{ChangeId, ChangeReceipt, IdempotencyRequest, RoleId};
use shared_application::http::{ApiPath, Problem, ValidatedJson};

use super::IamState;
use super::extract::{CallerPrincipal, VersionedWriteHeaders};
use super::response::{WriteHeaders, change_headers, etag, write_status};
use super::role::parse_role_id;
use super::user_role::find_replay;
use crate::command::set_role_permissions::SetRolePermissionsCommand;
use crate::error::IamError;
use crate::principal::Principal;
use crate::query::get_change_receipt::GetChangeReceiptQuery;
use crate::query::get_role_permissions::{GetRolePermissionsQuery, RolePermissions};
use dto::{RolePermissionsResponse, SetRolePermissionsRequest};

/// The largest body of a replacement: 2 MiB, which leaves room for 5,000 keys of any length that a
/// key may have, above the limit that the composition root sets for the other routes.
pub const ROLE_PERMISSIONS_BODY_LIMIT_BYTES: usize = 2 * 1024 * 1024;

/// The grants of the role `id`, none when the role is unknown or deleted.
///
/// # Errors
///
/// The 500 problem of a storage failure.
pub(crate) async fn find_role_permissions(
    state: &IamState,
    id: RoleId,
) -> Result<Option<RolePermissions>, Problem> {
    Ok(state.query_bus.ask(GetRolePermissionsQuery { id }).await?)
}

/// Replaces the grants of the role `id` as `caller` when it still holds the version `expected`,
/// or replays the replacement that `key` already committed; REST and GraphQL share it.
///
/// The receipt of the change and the grants are read back, because a command returns no data.
///
/// # Errors
///
/// The problem of a refused request: 404 for an unknown role, 409 for a concurrent change, 412 for
/// a stale version, 422 for a key that is in no active catalogue, more than 5,000 keys or a key
/// reused for another request, 500 for a storage failure.
pub(crate) async fn set_role_permissions(
    state: &IamState,
    caller: &Principal,
    id: RoleId,
    headers: VersionedWriteHeaders,
    request: SetRolePermissionsRequest,
) -> Result<(RolePermissions, ChangeReceipt), Problem> {
    let VersionedWriteHeaders { expected, key } = headers;
    let actor = caller.actor();
    let idempotency = key.map(|key| IdempotencyRequest {
        key,
        request_digest: state
            .request_digester
            .digest(&request.canonical_form(id, expected)),
    });
    let receipt = if let Some(replayed) = find_replay(state, &actor, idempotency.as_ref()).await? {
        replayed
    } else {
        let change_id = ChangeId::from_uuid(state.uuid_generator.generate());
        let command = SetRolePermissionsCommand {
            change_id,
            role_id: id,
            actor,
            expected,
            keys: request.keys,
            idempotency,
        };
        state.command_bus.dispatch(command).await?;
        state
            .query_bus
            .ask(GetChangeReceiptQuery { change_id })
            .await?
    };
    let permissions = find_role_permissions(state, id)
        .await?
        .ok_or(IamError::NotFound)?;
    Ok((permissions, receipt))
}

/// Reads the grants of a role.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 404 for an unknown role, 422 for an id that is
/// not a UUID.
#[utoipa::path(
    get,
    path = "/roles/{id}/permissions",
    operation_id = "api_roles_id_permissions_get",
    tag = "iam",
    summary = "Retrieves the permissions of a role.",
    description = "Returns every grant of the role in key order, each with its key, kind (`rest`, `gql` or `reserved`), service, active flag and wildcard flag, with the `ETag` of the role.",
    security(("bearerAuth" = [])),
    params(("id" = String, Path, format = Uuid, description = "Role identifier")),
    responses(
        (
            status = 200,
            description = "The grants of the role.",
            body = RolePermissionsResponse,
            headers(("etag" = String, description = "The version of the role in double quotes."))
        ),
        (status = 400, description = "Invalid identifier.", body = Problem, content_type = "application/problem+json"),
        (
            status = 401,
            description = "The caller presented no valid bearer token.",
            body = Problem,
            content_type = "application/problem+json",
            headers(("www-authenticate" = String, description = "The `Bearer` challenge."))
        ),
        (status = 404, description = "Role not found.", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed.", body = Problem, content_type = "application/problem+json"),
        (status = "default", description = "Problem response.", body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn list(
    State(state): State<IamState>,
    CallerPrincipal(_caller): CallerPrincipal,
    ApiPath(id): ApiPath<String>,
) -> Result<([(HeaderName, String); 1], Json<RolePermissionsResponse>), Problem> {
    let permissions = find_role_permissions(&state, parse_role_id(&id)?)
        .await?
        .ok_or(IamError::NotFound)?;
    let tag = etag(permissions.version);
    Ok((
        [(ETAG, tag)],
        Json(RolePermissionsResponse::from(&permissions)),
    ))
}

/// Replaces the grants of a role.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 403 for a system role, 404 for an unknown role,
/// 409 for a concurrent change, 412 for a stale `If-Match`, 422 for unknown keys, more than 5,000
/// keys or a reused idempotency key, 428 without `If-Match`, 500 when the storage fails.
#[utoipa::path(
    put,
    path = "/roles/{id}/permissions",
    operation_id = "api_roles_id_permissions_put",
    tag = "iam",
    summary = "Replaces the permissions of a role.",
    description = "Replaces the whole grant set of the role with `keys` when `If-Match` holds the current `ETag`: every key must be in an active catalogue or be one of the four wildcard forms of a service that has a catalogue, and at most 5,000 keys are accepted; unknown keys return 422 with one violation per key. The change increases the version, updates the grant count, takes the next policy version and records `iam.role_permissions.changed` with the added and removed keys; an added wildcard is audited with `coversFutureElements=true`. A repeated `Idempotency-Key` with the same request within 24 hours returns the original result.",
    security(("bearerAuth" = [])),
    params(
        ("id" = String, Path, format = Uuid, description = "Role identifier"),
        ("If-Match" = String, Header, description = "The `ETag` of the version the replacement changes, such as `\"3\"`."),
        ("Idempotency-Key" = Option<String>, Header, description = "Makes the replacement safe to repeat for 24 hours; 1 to 255 visible ASCII characters."),
        ("Prefer" = Option<String>, Header, description = "What the write waits for: `wait=published` (the default) returns once Kafka acknowledged the policy version, `wait=propagated` is refused with 422 until the gateway pods report their versions.")
    ),
    request_body(content = SetRolePermissionsRequest, content_type = "application/json"),
    responses(
        (
            status = 200,
            description = "The grants were replaced.",
            body = RolePermissionsResponse,
            headers(
                ("etag" = String, description = "The new version of the role in double quotes."),
                ("iam-policy-version" = String, description = "The policy version that the change produced."),
                ("iam-policy-offset" = String, description = "The offset at which Kafka stored the `__head` record of the policy version; present when the change affected decisions and was acknowledged.")
            )
        ),
        (
            status = 202,
            description = "The change is committed and its policy version was not acknowledged by Kafka within `PUBLISH_WAIT_TIMEOUT`; it may not be in force on the gateway yet.",
            body = RolePermissionsResponse,
            headers(
                ("etag" = String, description = "The new version of the role in double quotes."),
                ("iam-policy-version" = String, description = "The policy version that the change produced."),
                ("iam-propagation-status" = String, description = "`committed_pending_propagation`.")
            )
        ),
        (status = 400, description = "Invalid input.", body = Problem, content_type = "application/problem+json"),
        (
            status = 401,
            description = "The caller presented no valid bearer token.",
            body = Problem,
            content_type = "application/problem+json",
            headers(("www-authenticate" = String, description = "The `Bearer` challenge."))
        ),
        (status = 403, description = "A system role cannot be changed.", body = Problem, content_type = "application/problem+json"),
        (status = 404, description = "Role not found.", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "The role changed concurrently.", body = Problem, content_type = "application/problem+json"),
        (status = 412, description = "`If-Match` is not the current version.", body = Problem, content_type = "application/problem+json"),
        (status = 413, description = "Request body too large.", body = Problem, content_type = "application/problem+json"),
        (status = 415, description = "Unsupported media type.", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed: unknown keys, more than 5,000 keys, or the idempotency key was used for another request.", body = Problem, content_type = "application/problem+json"),
        (status = 428, description = "`If-Match` is missing.", body = Problem, content_type = "application/problem+json"),
        (status = "default", description = "Problem response.", body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn replace(
    State(state): State<IamState>,
    CallerPrincipal(caller): CallerPrincipal,
    ApiPath(id): ApiPath<String>,
    headers: VersionedWriteHeaders,
    ValidatedJson(body): ValidatedJson<SetRolePermissionsRequest>,
) -> Result<(StatusCode, WriteHeaders, Json<RolePermissionsResponse>), Problem> {
    let (permissions, receipt) =
        set_role_permissions(&state, &caller, parse_role_id(&id)?, headers, body).await?;
    Ok((
        write_status(&receipt, StatusCode::OK),
        change_headers(&receipt),
        Json(RolePermissionsResponse::from(&permissions)),
    ))
}

#[cfg(test)]
mod tests;
