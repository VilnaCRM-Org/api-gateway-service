//! Wire shapes of the GraphQL catalogue read operations.
//!
//! Each one keeps its schema constraints and its validator attributes on the same field so that
//! both stay equal.

use iam_domain::{GqlCoordinate, GqlName, PermissionId, PermissionKey, ServiceName};
use serde::{Deserialize, Serialize};
use shared_application::http::Violation;
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

use crate::error::IamError;
use crate::http::dto::DEFAULT_PAGE_SIZE;
use crate::http::graphql_spec::dto::{CoordinateFlagsResponse, violation_of};
use crate::query::get_graphql_permissions::{
    GetGraphQlPermissionsQuery, GraphQlPermissionPage, GraphQlPermissionView,
};

/// The type and the field that the introspection entry shows, as the catalogue stores them.
const INTROSPECTION: &str = "__introspection";

/// A GraphQL catalogue entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = GraphQlPermission)]
pub struct GraphQlPermissionResponse {
    /// The identifier of the entry.
    #[schema(format = Uuid)]
    pub id: String,
    /// The permission key, `gql:{service}:{Type}.{field}` or `gql:{service}:__introspection`.
    #[schema(example = "gql:billing:Query.invoices")]
    pub key: String,
    /// The service of the key.
    #[schema(example = "billing")]
    pub service: String,
    /// The GraphQL type of the key; `__introspection` for the introspection key.
    #[serde(rename = "type")]
    #[schema(example = "Query")]
    pub type_name: String,
    /// The field of the key; `__introspection` for the introspection key.
    #[schema(example = "invoices")]
    pub field: String,
    /// The flags of the entry: the most restrictive ones across the active versions.
    pub flags: CoordinateFlagsResponse,
    /// Whether some active version holds the key.
    pub active: bool,
    /// The identifiers of the active versions that contain the key, in order.
    pub versions: Vec<String>,
    /// The identifiers of the roles that grant the key by its exact key, in order. Wildcard
    /// grants are not listed.
    pub roles: Vec<String>,
}

impl From<GraphQlPermissionView> for GraphQlPermissionResponse {
    fn from(view: GraphQlPermissionView) -> Self {
        let permission = &view.permission;
        let (type_name, field) = match &permission.key {
            PermissionKey::Gql {
                coordinate: GqlCoordinate::Field { type_name, field },
                ..
            } => (type_name.to_string(), field.to_string()),
            PermissionKey::Gql {
                coordinate: GqlCoordinate::Introspection,
                ..
            }
            | PermissionKey::Rest { .. }
            | PermissionKey::Reserved(_) => (INTROSPECTION.to_owned(), INTROSPECTION.to_owned()),
        };
        Self {
            id: permission.id.to_string(),
            key: permission.key.to_string(),
            service: permission.key.service().to_string(),
            type_name,
            field,
            flags: CoordinateFlagsResponse::from(permission.flags),
            active: permission.active,
            versions: view.versions.iter().map(ToString::to_string).collect(),
            roles: view.roles.iter().map(ToString::to_string).collect(),
        }
    }
}

/// One page of GraphQL catalogue entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = GraphQlPermissionPage)]
pub struct GraphQlPermissionPageResponse {
    /// The entries of the page.
    pub items: Vec<GraphQlPermissionResponse>,
    /// The `after` value of the next page; absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(format = Uuid)]
    pub next_cursor: Option<String>,
}

impl From<GraphQlPermissionPage> for GraphQlPermissionPageResponse {
    fn from(page: GraphQlPermissionPage) -> Self {
        Self {
            items: page
                .permissions
                .into_iter()
                .map(GraphQlPermissionResponse::from)
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
pub struct ListGraphQlPermissionsParams {
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
    /// Only entries of this GraphQL type.
    #[serde(rename = "type")]
    #[param(rename = "type", max_length = 255, example = "Query")]
    #[validate(length(
        max = 255,
        message = "This value must contain 255 characters or fewer."
    ))]
    pub type_name: Option<String>,
    /// Only active (`true`) or only inactive (`false`) entries.
    pub active: Option<bool>,
    /// Only entries that are sensitive (`true`) or not (`false`).
    pub sensitive: Option<bool>,
    /// Only entries whose key starts with this text.
    #[param(max_length = 512, example = "gql:billing:Query.")]
    #[validate(length(
        max = 512,
        message = "This value must contain 512 characters or fewer."
    ))]
    pub key_prefix: Option<String>,
}

impl Default for ListGraphQlPermissionsParams {
    fn default() -> Self {
        Self {
            limit: DEFAULT_PAGE_SIZE,
            after: None,
            service: None,
            type_name: None,
            active: None,
            sensitive: None,
            key_prefix: None,
        }
    }
}

/// The GraphQL type name that the text holds.
fn parse_type(text: &str) -> Result<GqlName, Violation> {
    GqlName::parse(text).ok_or_else(|| Violation {
        property_path: "type".to_owned(),
        message: "This value is not a valid GraphQL name.".to_owned(),
        code: "pattern".to_owned(),
    })
}

impl ListGraphQlPermissionsParams {
    /// The query for these parameters; call it after validation, which makes `limit` positive.
    ///
    /// # Errors
    ///
    /// [`IamError::Invalid`] with a violation for each of `after`, `service` and `type` that does
    /// not hold a UUID, a service name or a GraphQL name.
    pub fn into_query(self) -> Result<GetGraphQlPermissionsQuery, IamError> {
        let after = self.after.as_deref().map(PermissionId::parse).transpose();
        let service = self.service.as_deref().map(ServiceName::new).transpose();
        let type_name = self.type_name.as_deref().map(parse_type).transpose();
        match (after, service, type_name) {
            (Ok(after), Ok(service), Ok(type_name)) => Ok(GetGraphQlPermissionsQuery {
                limit: self.limit.unsigned_abs(),
                after,
                service,
                type_name,
                active: self.active,
                sensitive: self.sensitive,
                key_prefix: self.key_prefix,
            }),
            (after, service, type_name) => Err(IamError::Invalid(
                after
                    .err()
                    .map(|error| violation_of("after", error))
                    .into_iter()
                    .chain(service.err().map(|error| violation_of("service", error)))
                    .chain(type_name.err())
                    .collect(),
            )),
        }
    }
}

#[cfg(test)]
mod tests;
