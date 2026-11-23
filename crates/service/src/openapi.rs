//! The `OpenAPI` document of the REST API (AD-16).

use axum::extract::DefaultBodyLimit;
use shared_domain::BoxError;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};
use utoipa_axum::router::OpenApiRouter;

use crate::http::AppState;

/// Version of the API contract, not of the release.
///
/// It changes only in a pull request that changes the contract: the major number when a breaking
/// change is approved, the minor number when operations or fields are added.
pub const API_VERSION: &str = "1.0.0";

/// Static metadata of the document; title, description, contact URL and version are set in
/// [`api_router`].
#[derive(Debug, OpenApi)]
#[openapi(
    info(
        contact(name = "VilnaCRM Support", email = "support@vilnacrm.com"),
        license(name = "CC0-1.0", url = "https://creativecommons.org/publicdomain/zero/1.0/"),
    ),
    servers((url = "/", description = "Current host")),
    tags(
        (name = "ExampleApiResource", description = "Template example resource endpoints."),
        (name = "HealthCheck", description = "Runtime health-check endpoints."),
        (name = "iam", description = "IAM endpoints: authentication and authorization of API callers."),
    ),
    modifiers(&BearerAuth)
)]
pub struct ApiDoc;

/// Name of the HTTP bearer security scheme that every IAM operation requires.
pub const BEARER_AUTH: &str = "bearerAuth";

/// Adds the [`BEARER_AUTH`] security scheme to the document.
#[derive(Debug)]
struct BearerAuth;

impl Modify for BearerAuth {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let scheme = HttpBuilder::new()
            .scheme(HttpAuthScheme::Bearer)
            .bearer_format("JWT")
            .description(Some("A User service access token."))
            .build();
        openapi
            .components
            .get_or_insert_default()
            .add_security_scheme(BEARER_AUTH, SecurityScheme::Http(scheme));
    }
}

/// The `OpenAPI` document could not be serialised.
#[derive(Debug, thiserror::Error)]
#[error("the OpenAPI document could not be serialised")]
pub struct ExportError(#[source] BoxError);

impl ExportError {
    fn new<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self(Box::new(source))
    }
}

/// One router for every REST operation, built without any state value.
///
/// The routes of each context are nested under `/api`.
#[must_use]
pub fn api_router() -> OpenApiRouter<AppState> {
    template_api_router().merge(iam_api_router())
}

/// The REST operations of the template's contexts with the document metadata, without the IAM
/// operations, which the router serves behind the authentication of IAM's callers.
#[must_use]
pub fn template_api_router() -> OpenApiRouter<AppState> {
    let mut document = ApiDoc::openapi();
    concat!(env!("CARGO_PKG_DESCRIPTION"), " API").clone_into(&mut document.info.title);
    document.info.description = Some(format!(
        "This API provides endpoints to manage {} data within VilnaCRM.",
        env!("CARGO_PKG_DESCRIPTION")
    ));
    API_VERSION.clone_into(&mut document.info.version);
    if let Some(contact) = document.info.contact.as_mut() {
        contact.url = Some(env!("CARGO_PKG_REPOSITORY").to_owned());
    }
    OpenApiRouter::with_openapi(document)
        .nest("/api", health_check_application::router())
        .nest("/api", some_module_application::http::router())
}

/// The largest body of a request to a route that uploads a specification document: 6 MiB, which
/// leaves room above the 5 MiB document limit for the JSON envelope and its escapes.
pub const SPECIFICATION_BODY_LIMIT_BYTES: usize = 6 * 1024 * 1024;

/// The REST operations of the IAM context, nested under `/api`.
///
/// The routes that upload specification documents take [`SPECIFICATION_BODY_LIMIT_BYTES`]; every
/// other route keeps the limit of the whole router.
#[must_use]
pub fn iam_api_router() -> OpenApiRouter<AppState> {
    let specifications = OpenApiRouter::new()
        .nest("/api", iam_application::http::specification_router())
        .layer(DefaultBodyLimit::max(SPECIFICATION_BODY_LIMIT_BYTES));
    OpenApiRouter::new()
        .nest("/api", iam_application::http::router())
        .merge(specifications)
}

/// The document.
#[must_use]
pub fn document() -> utoipa::openapi::OpenApi {
    api_router().into_openapi()
}

/// The document as YAML.
///
/// # Errors
///
/// Returns [`ExportError`] when the document cannot be serialised.
pub fn yaml() -> Result<String, ExportError> {
    document().to_yaml().map_err(ExportError::new)
}

/// The tag that every operation of the IAM context carries.
pub const IAM_TAG: &str = "iam";

/// The members of a path item that are operations.
const OPERATION_MEMBERS: [&str; 8] = [
    "get", "put", "post", "delete", "options", "head", "patch", "trace",
];

/// Whether the operation lists `tag`.
fn has_tag(operation: &serde_json::Value, tag: &str) -> bool {
    operation
        .get("tags")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|tags| tags.iter().any(|candidate| candidate.as_str() == Some(tag)))
}

/// Removes the operations of the path item that do not carry `tag` and says whether one is left.
fn retain_tagged(item: &mut serde_json::Value, tag: &str) -> bool {
    let Some(members) = item.as_object_mut() else {
        return false;
    };
    members.retain(|name, operation| {
        !OPERATION_MEMBERS.contains(&name.as_str()) || has_tag(operation, tag)
    });
    OPERATION_MEMBERS
        .iter()
        .any(|name| members.contains_key(*name))
}

/// The document of the operations that carry `tag`, as JSON: every other operation and every path
/// without one is removed.
///
/// # Errors
///
/// Returns [`ExportError`] when the document cannot be serialised.
pub fn tagged_json(document: &utoipa::openapi::OpenApi, tag: &str) -> Result<String, ExportError> {
    let mut value = serde_json::to_value(document).map_err(ExportError::new)?;
    retain_tagged_paths(&mut value, tag);
    serde_json::to_string(&value).map_err(ExportError::new)
}

/// Keeps the path items of the JSON document that still hold an operation tagged `tag`; a
/// document without a `paths` object is left as it is.
fn retain_tagged_paths(document: &mut serde_json::Value, tag: &str) {
    if let Some(paths) = document
        .get_mut("paths")
        .and_then(serde_json::Value::as_object_mut)
    {
        paths.retain(|_path, item| retain_tagged(item, tag));
    }
}

/// IAM's own `OpenAPI` document as JSON: the operations of [`document`] tagged [`IAM_TAG`].
///
/// IAM registers it as its own specification at startup. The same build always yields the same
/// bytes, so the content hash identifies the build's contract.
///
/// # Errors
///
/// Returns [`ExportError`] when the document cannot be serialised.
pub fn iam_document() -> Result<String, ExportError> {
    tagged_json(&document(), IAM_TAG)
}

#[cfg(test)]
mod tests;
