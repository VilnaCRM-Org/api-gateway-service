//! REST handlers of the declarative route configuration of a host, and the use-case calls that
//! the GraphQL resolvers share (FR-58).
//!
//! A handler takes the IAM state and the problem-aware extractors only (`ApiPath`,
//! `ValidatedQuery`, `ValidatedJson`, the IAM extractors `CallerPrincipal` and
//! `VersionedWriteHeaders`); the test of the `handler` module checks every handler against that
//! rule.

pub mod dto;

use axum::Json;
use axum::extract::{FromRequestParts, State};
use axum::http::header::ETAG;
use axum::http::request::Parts;
use axum::http::{HeaderName, StatusCode};
use axum::response::AppendHeaders;
use iam_domain::{ChangeId, ChangeReceipt, EntityVersion};
use shared_application::http::{ApiPath, Problem, ValidatedJson, ValidatedQuery};

use super::IamState;
use super::extract::{CallerPrincipal, VersionedWriteHeaders};
use super::response::{WriteHeaders, change_headers, etag, write_status};
use crate::command::apply_route_configuration::ApplyRouteConfigurationCommand;
use crate::principal::Principal;
use crate::query::get_change_receipt::GetChangeReceiptQuery;
use crate::query::get_route_configuration::{GetRouteConfigurationQuery, RouteConfiguration};
use crate::query::preview_route_configuration::{
    PreviewRouteConfigurationQuery, RouteConfigurationPreview,
};
use dto::{
    ApplyRouteConfigurationParams, ApplyRouteConfigurationRequest, RouteConfigurationDiffResponse,
    RouteConfigurationResponse,
};

/// The largest body of a route configuration: 6 MiB, which leaves room for 1,000 routes with
/// long patterns and CORS policies, above the limit that the composition root sets for the other
/// routes.
pub const ROUTE_CONFIGURATION_BODY_LIMIT_BYTES: usize = 6 * 1024 * 1024;

/// The host of the path and the `dryRun` parameter of the query of a route-configuration write.
///
/// It reads both through the problem-aware extractors, so that their rejections are problem
/// documents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteConfigurationTarget {
    /// The host the set replaces.
    pub host: String,
    /// Whether the request only reports the diff.
    pub dry_run: bool,
}

impl<S> FromRequestParts<S> for RouteConfigurationTarget
where
    S: Send + Sync,
{
    type Rejection = Problem;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let ApiPath(host) = ApiPath::<String>::from_request_parts(parts, state).await?;
        let ValidatedQuery(params) =
            ValidatedQuery::<ApplyRouteConfigurationParams>::from_request_parts(parts, state)
                .await?;
        Ok(Self {
            host,
            dry_run: params.dry_run,
        })
    }
}

/// What a write of a route configuration asks for.
#[derive(Debug)]
pub(crate) struct RouteConfigurationWrite<'a> {
    /// The host the set replaces.
    pub host: &'a str,
    /// The version of the stored set that the caller read.
    pub expected: EntityVersion,
    /// Whether the write only reports the diff.
    pub dry_run: bool,
    /// The declared set.
    pub request: ApplyRouteConfigurationRequest,
}

/// What an application of a set did: the diff, and the receipt when it committed a change.
#[derive(Debug)]
pub(crate) struct AppliedRouteConfiguration {
    /// What the set changes, as the dry run reports it.
    pub preview: RouteConfigurationPreview,
    /// The receipt of the committed change; none for a dry run and for a set that changes
    /// nothing.
    pub receipt: Option<ChangeReceipt>,
}

/// The full route set of the host `host`.
///
/// # Errors
///
/// The 422 problem of a host that is not a host name, the 500 problem of a storage failure.
pub(crate) async fn get_route_configuration(
    state: &IamState,
    host: &str,
) -> Result<RouteConfiguration, Problem> {
    Ok(state
        .query_bus
        .ask(GetRouteConfigurationQuery {
            host: host.to_owned(),
        })
        .await?)
}

/// Replaces the route set of `host` as `caller` when the stored set still has the version
/// `expected`, or only reports the diff for a dry run; REST and GraphQL share it.
///
/// The dry run runs every check of the application. A set that changes nothing commits nothing.
///
/// # Errors
///
/// The problem of a refused request: 403 for a caller without the route key of a service or
/// `iam:route:anonymous` where the set needs it, 409 for a conflict of the set or a route that IAM
/// manages itself, 412 for a stale version, 422 for a set larger than
/// `ROUTE_CONFIGURATION_MAX_ROUTES` or a route with invalid values, 500 for a storage failure.
pub(crate) async fn apply_route_configuration(
    state: &IamState,
    caller: &Principal,
    write: RouteConfigurationWrite<'_>,
) -> Result<AppliedRouteConfiguration, Problem> {
    let RouteConfigurationWrite {
        host,
        expected,
        dry_run,
        request,
    } = write;
    let routes = request.into_drafts()?;
    let actor = caller.actor();
    let preview = state
        .query_bus
        .ask(PreviewRouteConfigurationQuery {
            host: host.to_owned(),
            routes: routes.clone(),
            expected,
            actor: actor.clone(),
        })
        .await?;
    if dry_run || preview.diff.is_empty() {
        return Ok(AppliedRouteConfiguration {
            preview,
            receipt: None,
        });
    }
    let change_id = ChangeId::from_uuid(state.uuid_generator.generate());
    state
        .command_bus
        .dispatch(ApplyRouteConfigurationCommand {
            change_id,
            host: host.to_owned(),
            routes,
            actor,
            expected,
        })
        .await?;
    let receipt = state
        .query_bus
        .ask(GetChangeReceiptQuery { change_id })
        .await?;
    Ok(AppliedRouteConfiguration {
        preview,
        receipt: Some(receipt),
    })
}

/// The headers of a response about a set: those of the committed change, or the `ETag` of the
/// stored set when nothing was committed.
fn applied_headers(applied: &AppliedRouteConfiguration) -> WriteHeaders {
    applied.receipt.as_ref().map_or_else(
        || AppendHeaders(vec![(ETAG, etag(applied.preview.version))]),
        change_headers,
    )
}

/// The status of a response about a set.
fn applied_status(applied: &AppliedRouteConfiguration) -> StatusCode {
    applied.receipt.as_ref().map_or(StatusCode::OK, |receipt| {
        write_status(receipt, StatusCode::OK)
    })
}

/// The response about a set.
fn applied_response(
    applied: &AppliedRouteConfiguration,
    dry_run: bool,
) -> RouteConfigurationDiffResponse {
    RouteConfigurationDiffResponse::of(
        &applied.preview,
        dry_run,
        applied
            .receipt
            .as_ref()
            .map(|receipt| receipt.entity_version().value()),
    )
}

/// Reads the route configuration of a host.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 403 without the operation key, 422 for a host
/// that is not a host name.
#[utoipa::path(
    get,
    path = "/route-configurations/{host}",
    operation_id = "api_route_configurations_host_get",
    tag = "iam",
    summary = "Retrieves the route configuration of a host.",
    description = "Returns every route of the host that is not deleted, in the form that the replacement accepts, and the version of the set as its `ETag`; a host without routes has an empty set. The `ETag` is the `If-Match` of a later replacement.",
    security(("bearerAuth" = [])),
    params(("host" = String, Path, description = "The lower-case DNS name of the host")),
    responses(
        (
            status = 200,
            description = "The route configuration of the host.",
            body = RouteConfigurationResponse,
            headers(("etag" = String, description = "The version of the set in double quotes."))
        ),
        (status = 400, description = "Invalid host.", body = Problem, content_type = "application/problem+json"),
        (
            status = 401,
            description = "The caller presented no valid bearer token.",
            body = Problem,
            content_type = "application/problem+json",
            headers(("www-authenticate" = String, description = "The `Bearer` challenge."))
        ),
        (status = 403, description = "The caller lacks the operation key.", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed.", body = Problem, content_type = "application/problem+json"),
        (status = "default", description = "Problem response.", body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn get_one(
    State(state): State<IamState>,
    CallerPrincipal(_caller): CallerPrincipal,
    ApiPath(host): ApiPath<String>,
) -> Result<([(HeaderName, String); 1], Json<RouteConfigurationResponse>), Problem> {
    let configuration = get_route_configuration(&state, &host).await?;
    let tag = etag(configuration.version);
    Ok((
        [(ETAG, tag)],
        Json(RouteConfigurationResponse::from(configuration)),
    ))
}

/// Replaces the route configuration of a host, or reports what it would change.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 403 without the route key of a service or
/// without `iam:route:anonymous` for an anonymous or audit-only route, 409 for a conflicting set
/// or a route that IAM manages itself, 412 for a stale `If-Match`, 422 for a set larger than the
/// limit or invalid fields, 428 without `If-Match`, 500 when the storage fails.
#[utoipa::path(
    put,
    path = "/route-configurations/{host}",
    operation_id = "api_route_configurations_host_put",
    tag = "iam",
    summary = "Replaces the route configuration of a host.",
    description = "Replaces the full route set of the host atomically when `If-Match` holds the `ETag` that the retrieval returned: routes of the set that the host lacks are created, routes whose methods and path pattern match a stored route are updated, and stored routes that the set omits are deleted, all in one transaction under one policy version, with their `route/<id>` state records, `iam.route.*` events, `iam.route_configuration.applied` and an audit record. The whole set is validated first: one violation, conflict or route the caller may not write rejects it, and the candidate route table of the host must build. A set holds at most `ROUTE_CONFIGURATION_MAX_ROUTES` routes (1,000 by default); a larger set is refused with 422. With `dryRun=true` the operation runs every check and returns the diff without writing anything. A set whose diff deletes a route, clears `anonymous` or moves `enforcement` from `audit` to `enforce` is revocation-class. The caller needs `iam:route:{service}` or `iam:route:*` for every service the set touches, and `iam:route:anonymous` to create an anonymous or audit-only route or change either flag. A repeated request fails with 412 once the set changed, which makes it safe to repeat.",
    security(("bearerAuth" = [])),
    params(
        ("host" = String, Path, description = "The lower-case DNS name of the host"),
        ("If-Match" = String, Header, description = "The `ETag` of the set the replacement changes, as the retrieval returned it."),
        ("Prefer" = Option<String>, Header, description = "What the write waits for: `wait=published` (the default) returns once Kafka acknowledged the policy version, `wait=propagated` is refused with 422 until the gateway pods report their versions."),
        ApplyRouteConfigurationParams
    ),
    request_body(content = ApplyRouteConfigurationRequest, content_type = "application/json"),
    responses(
        (
            status = 200,
            description = "The diff of the set; the set was applied unless `dryRun` is true.",
            body = RouteConfigurationDiffResponse,
            headers(
                ("etag" = String, description = "The version of the set in double quotes."),
                ("iam-policy-version" = String, description = "The policy version that the change produced; absent for a dry run and for a set that changes nothing."),
                ("iam-policy-offset" = String, description = "The offset at which Kafka stored the `__head` record of the policy version; present when the change was acknowledged.")
            )
        ),
        (
            status = 202,
            description = "The change is committed and its policy version was not acknowledged by Kafka within `PUBLISH_WAIT_TIMEOUT`; it may not be in force on the gateway yet.",
            body = RouteConfigurationDiffResponse,
            headers(
                ("etag" = String, description = "The version of the set in double quotes."),
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
        (status = 403, description = "The caller lacks the operation key, the route key of a service or `iam:route:anonymous`.", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "The set holds conflicting routes or a route table that the gateway could not build, or it changes a route that IAM manages itself.", body = Problem, content_type = "application/problem+json"),
        (status = 412, description = "`If-Match` is not the current version of the set.", body = Problem, content_type = "application/problem+json"),
        (status = 413, description = "Request body too large.", body = Problem, content_type = "application/problem+json"),
        (status = 415, description = "Unsupported media type.", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed, or the set holds more than `ROUTE_CONFIGURATION_MAX_ROUTES` routes.", body = Problem, content_type = "application/problem+json"),
        (status = 428, description = "`If-Match` is missing.", body = Problem, content_type = "application/problem+json"),
        (status = "default", description = "Problem response.", body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn apply(
    State(state): State<IamState>,
    CallerPrincipal(caller): CallerPrincipal,
    target: RouteConfigurationTarget,
    headers: VersionedWriteHeaders,
    ValidatedJson(body): ValidatedJson<ApplyRouteConfigurationRequest>,
) -> Result<
    (
        StatusCode,
        WriteHeaders,
        Json<RouteConfigurationDiffResponse>,
    ),
    Problem,
> {
    let write = RouteConfigurationWrite {
        host: &target.host,
        expected: headers.expected,
        dry_run: target.dry_run,
        request: body,
    };
    let applied = apply_route_configuration(&state, &caller, write).await?;
    Ok((
        applied_status(&applied),
        applied_headers(&applied),
        Json(applied_response(&applied, target.dry_run)),
    ))
}

#[cfg(test)]
mod tests;
