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

#[cfg(test)]
mod tests;
