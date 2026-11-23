//! REST handler that loads GraphQL specifications, and the use-case call that the GraphQL
//! resolver shares.
//!
//! A handler takes the IAM state and the problem-aware extractors only (`ValidatedJson` and the
//! IAM extractor `CallerPrincipal`); the test of the `handler` module checks every handler against
//! that rule.

pub mod dto;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header::LOCATION;
use axum::response::AppendHeaders;
use iam_domain::{ChangeId, SpecId};
use shared_application::http::{Problem, ValidatedJson};

use super::IamState;
use super::extract::CallerPrincipal;
use super::response::WriteHeaders;
use crate::command::load_graphql_spec::{
    LoadGraphQlSpecCommand, content_hash_of, loadable_service,
};
use crate::error::IamError;
use crate::principal::Principal;
use crate::query::find_graphql_spec::FindGraphQlSpecQuery;
use crate::query::get_graphql_spec_diff::{GetGraphQlSpecDiffQuery, GraphQlSpecView};
use dto::{GraphQlSpecResponse, LoadGraphQlSpecRequest};

/// The path of the specification collection, under which a version has its `Location`.
const GRAPHQL_SPECS_PATH: &str = "/api/graphql-specs";

/// A version that an upload produced, and whether the upload created it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LoadedGraphQlSpec {
    /// The version with its diff against the active versions.
    pub view: GraphQlSpecView,
    /// `true` for a new draft, `false` when the service already held the same SDL.
    pub created: bool,
}

/// Loads the SDL as a draft of the service as `caller`, or finds the version that already holds
/// the same SDL; REST and GraphQL share it.
///
/// The version is read back with its diff, because a command returns no data. The reserved
/// service and the name are checked before the lookup, so an identical upload of a version the
/// caller may not load reveals nothing.
///
/// # Errors
///
/// The problem of a refused request: 403 for the reserved service `iam`, 422 for an invalid
/// service name or SDL, 409 for a concurrent upload of the same SDL, 500 for a storage failure.
pub(crate) async fn load_graphql_spec(
    state: &IamState,
    caller: &Principal,
    request: LoadGraphQlSpecRequest,
) -> Result<LoadedGraphQlSpec, Problem> {
    let actor = caller.actor();
    let service = loadable_service(&request.service, &actor)?;
    let content_hash = content_hash_of(state.request_digester.as_ref(), &request.sdl);
    let existing = state
        .query_bus
        .ask(FindGraphQlSpecQuery {
            service,
            content_hash,
        })
        .await?;
    let (id, created) = if let Some(id) = existing {
        (id, false)
    } else {
        let id = SpecId::from_uuid(state.uuid_generator.generate());
        let command = LoadGraphQlSpecCommand {
            change_id: ChangeId::from_uuid(state.uuid_generator.generate()),
            spec_id: id,
            actor,
            service: request.service,
            sdl: request.sdl,
        };
        state.command_bus.dispatch(command).await?;
        (id, true)
    };
    let view = state
        .query_bus
        .ask(GetGraphQlSpecDiffQuery { id })
        .await?
        .ok_or(IamError::NotFound)?;
    Ok(LoadedGraphQlSpec { view, created })
}

/// Loads a GraphQL specification.
///
/// # Errors
///
/// A problem document: 401 without a valid token, 403 for the reserved service `iam`, 413 for a
/// body over 6 MiB, 422 for an invalid service name or SDL, 500 when the storage fails.
#[utoipa::path(
    post,
    path = "/graphql-specs",
    operation_id = "api_graphql_specs_post",
    tag = "iam",
    summary = "Loads a GraphQL specification.",
    description = "Stores the SDL of a service as a draft version and records `iam.graphql_spec.loaded`. The response lists what the version adds and removes against the active versions of the service. An SDL that an earlier version of the service already holds returns that version with 200 and changes nothing. The service `iam` is reserved for IAM's own schema.",
    security(("bearerAuth" = [])),
    request_body(content = LoadGraphQlSpecRequest, content_type = "application/json"),
    responses(
        (
            status = 201,
            description = "The draft version was created.",
            body = GraphQlSpecResponse,
            headers(("location" = String, description = "Path of the version."))
        ),
        (
            status = 200,
            description = "The service already holds this SDL; its version is returned.",
            body = GraphQlSpecResponse,
            headers(("location" = String, description = "Path of the version."))
        ),
        (status = 400, description = "Invalid input.", body = Problem, content_type = "application/problem+json"),
        (
            status = 401,
            description = "The caller presented no valid bearer token.",
            body = Problem,
            content_type = "application/problem+json",
            headers(("www-authenticate" = String, description = "The `Bearer` challenge."))
        ),
        (status = 403, description = "The service `iam` is reserved for IAM's own schema.", body = Problem, content_type = "application/problem+json"),
        (status = 409, description = "The same SDL was uploaded concurrently.", body = Problem, content_type = "application/problem+json"),
        (status = 413, description = "Request body too large.", body = Problem, content_type = "application/problem+json"),
        (status = 415, description = "Unsupported media type.", body = Problem, content_type = "application/problem+json"),
        (status = 422, description = "Validation failed: an invalid service name or an SDL that does not parse.", body = Problem, content_type = "application/problem+json"),
        (status = "default", description = "Problem response.", body = Problem, content_type = "application/problem+json"),
    )
)]
pub async fn load(
    State(state): State<IamState>,
    CallerPrincipal(caller): CallerPrincipal,
    ValidatedJson(body): ValidatedJson<LoadGraphQlSpecRequest>,
) -> Result<(StatusCode, WriteHeaders, Json<GraphQlSpecResponse>), Problem> {
    let loaded = load_graphql_spec(&state, &caller, body).await?;
    let status = if loaded.created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    let response = GraphQlSpecResponse::from(&loaded.view);
    let location = format!("{GRAPHQL_SPECS_PATH}/{}", response.id);
    let headers = AppendHeaders(vec![(LOCATION, location)]);
    Ok((status, headers, Json(response)))
}

#[cfg(test)]
mod tests;
