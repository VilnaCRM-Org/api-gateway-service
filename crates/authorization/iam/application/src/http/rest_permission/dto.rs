//! Wire shapes of the REST catalogue read operations.
//!
//! Each one keeps its schema constraints and its validator attributes on the same field so that
//! both stay equal.

use iam_domain::{HttpMethod, PermissionId, PermissionKey, ServiceName};
use serde::{Deserialize, Serialize};
use shared_application::http::Violation;
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

use crate::error::IamError;
use crate::http::dto::DEFAULT_PAGE_SIZE;
use crate::http::graphql_spec::dto::violation_of;
use crate::http::openapi_spec::dto::OperationFlagsResponse;
use crate::query::get_rest_permissions::{
    GetRestPermissionsQuery, RestPermissionPage, RestPermissionView,
};

/// A REST catalogue entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = RestPermission)]
pub struct RestPermissionResponse {
    /// The identifier of the entry.
    #[schema(format = Uuid)]
    pub id: String,
    /// The permission key, `rest:{service}:{METHOD} {template}`.
    #[schema(example = "rest:billing:POST /api/invoices/{}/pay")]
    pub key: String,
    /// The service of the key.
    #[schema(example = "billing")]
    pub service: String,
    /// The HTTP method of the key.
    #[schema(example = "POST")]
    pub method: String,
    /// The normalised path template of the key; parameters are written `{}`.
    #[schema(example = "/api/invoices/{}/pay")]
    pub template: String,
    /// The flags of the entry: the most restrictive ones across the active versions.
    pub flags: OperationFlagsResponse,
    /// Whether some active version holds the key.
    pub active: bool,
    /// The identifiers of the active versions that contain the key, in order.
    pub versions: Vec<String>,
    /// The identifiers of the roles that grant the key by its exact key, in order. Wildcard
    /// grants are not listed.
    pub roles: Vec<String>,
}

impl From<RestPermissionView> for RestPermissionResponse {
    fn from(view: RestPermissionView) -> Self {
        let permission = &view.permission;
        let (method, template) = match &permission.key {
            PermissionKey::Rest {
                method, template, ..
            } => (method.to_string(), template.to_string()),
            PermissionKey::Gql { .. } | PermissionKey::Reserved(_) => {
                (String::new(), String::new())
            }
        };
        Self {
            id: permission.id.to_string(),
            key: permission.key.to_string(),
            service: permission.key.service().to_string(),
            method,
            template,
            flags: OperationFlagsResponse::from(permission.flags),
            active: permission.active,
            versions: view.versions.iter().map(ToString::to_string).collect(),
            roles: view.roles.iter().map(ToString::to_string).collect(),
        }
    }
}

/// One page of REST catalogue entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = RestPermissionPage)]
pub struct RestPermissionPageResponse {
    /// The entries of the page.
    pub items: Vec<RestPermissionResponse>,
    /// The `after` value of the next page; absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(format = Uuid)]
    pub next_cursor: Option<String>,
}

impl From<RestPermissionPage> for RestPermissionPageResponse {
    fn from(page: RestPermissionPage) -> Self {
        Self {
            items: page
                .permissions
                .into_iter()
                .map(RestPermissionResponse::from)
                .collect(),
            next_cursor: page.next_after.map(|id| id.to_string()),
        }
    }
}

/// Query parameters of the entry list; `limit` is signed so that a negative value is a 422, not a
/// parse error.
#[derive(Debug, Clone, Deserialize, IntoParams, Validate)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct ListRestPermissionsParams {
    /// The largest number of entries of the page.
    #[param(minimum = 1, maximum = 100, default = 30)]
    #[validate(range(min = 1, max = 100, message = "This value must be between 1 and 100."))]
    pub limit: i32,
    /// The `nextCursor` of the previous page; absent for the first page.
    #[param(format = Uuid)]
    pub after: Option<String>,
    /// Only entries of this service.
    #[param(max_length = 63, example = "billing")]
    #[validate(length(max = 63, message = "This value must contain 63 characters or fewer."))]
    pub service: Option<String>,
    /// Only entries of this HTTP method, in upper case.
    #[param(example = "GET")]
    #[validate(length(max = 7, message = "This value must contain 7 characters or fewer."))]
    pub method: Option<String>,
    /// Only active (`true`) or only inactive (`false`) entries.
    pub active: Option<bool>,
    /// Only entries that are sensitive (`true`) or not (`false`).
    pub sensitive: Option<bool>,
    /// Only entries whose normalised path template starts with this text; parameters are written
    /// `{}`.
    #[param(max_length = 2048, example = "/api/invoices")]
    #[validate(length(
        max = 2048,
        message = "This value must contain 2048 characters or fewer."
    ))]
    pub template_prefix: Option<String>,
}

impl Default for ListRestPermissionsParams {
    fn default() -> Self {
        Self {
            limit: DEFAULT_PAGE_SIZE,
            after: None,
            service: None,
            method: None,
            active: None,
            sensitive: None,
            template_prefix: None,
        }
    }
}

/// The HTTP method that the text holds.
fn parse_method(text: &str) -> Result<HttpMethod, Violation> {
    HttpMethod::parse(text).ok_or_else(|| Violation {
        property_path: "method".to_owned(),
        message: "This value is not a valid HTTP method.".to_owned(),
        code: "choice".to_owned(),
    })
}

impl ListRestPermissionsParams {
    /// The query for these parameters; call it after validation, which makes `limit` positive.
    ///
    /// # Errors
    ///
    /// [`IamError::Invalid`] with a violation for each of `after`, `service` and `method` that
    /// does not hold a UUID, a service name or an upper-case HTTP method.
    pub fn into_query(self) -> Result<GetRestPermissionsQuery, IamError> {
        let after = self.after.as_deref().map(PermissionId::parse).transpose();
        let service = self.service.as_deref().map(ServiceName::new).transpose();
        let method = self.method.as_deref().map(parse_method).transpose();
        match (after, service, method) {
            (Ok(after), Ok(service), Ok(method)) => Ok(GetRestPermissionsQuery {
                limit: self.limit.unsigned_abs(),
                after,
                service,
                method,
                active: self.active,
                sensitive: self.sensitive,
                template_prefix: self.template_prefix,
            }),
            (after, service, method) => Err(IamError::Invalid(
                after
                    .err()
                    .map(|error| violation_of("after", error))
                    .into_iter()
                    .chain(service.err().map(|error| violation_of("service", error)))
                    .chain(method.err())
                    .collect(),
            )),
        }
    }
}

#[cfg(test)]
mod tests;
