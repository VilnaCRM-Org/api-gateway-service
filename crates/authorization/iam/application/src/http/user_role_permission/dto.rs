//! Wire shapes of the effective permissions of a user.

use iam_domain::{
    EffectivePermission, InvalidIamValue, ProjectId, ScopeSet, ServiceName, SubjectKind, SubjectRef,
};
use serde::{Deserialize, Serialize};
use shared_application::http::Violation;
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

use crate::error::IamError;
use crate::query::get_user_role_permissions::{
    GetUserRolePermissionsQuery, UserRolePermissionsView,
};

/// The scope text of a permission that is held in every project.
pub const SCOPE_ALL: &str = "all";

/// A role that grants an effective permission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = GrantingRole)]
pub struct GrantingRoleResponse {
    /// The identifier of the role.
    #[schema(format = Uuid)]
    pub id: String,
    /// The name of the role; absent when the role is no longer stored.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(max_length = 100)]
    pub name: Option<String>,
}

/// One key or wildcard that a user holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = EffectivePermission)]
pub struct EffectivePermissionResponse {
    /// The permission key or the wildcard pattern.
    #[schema(example = "rest:billing:GET /invoices")]
    pub key: String,
    /// The form of the key: `rest` or `gql`, or `reserved` for a reserved `iam:` key.
    #[schema(example = "rest")]
    pub kind: String,
    /// The service of the key.
    #[schema(example = "billing")]
    pub service: String,
    /// Whether the entry is a wildcard pattern; a wildcard never covers a sensitive key.
    pub wildcard: bool,
    /// The roles of the active assignments that grant it, in identifier order.
    pub roles: Vec<GrantingRoleResponse>,
    /// Where it is held: `["all"]` when a global assignment grants it, else the project ids.
    #[schema(example = json!(["all"]))]
    pub scopes: Vec<String>,
    /// The shortest expiry among the contributing assignments that expire, as an RFC 3339 UTC
    /// time; absent when none of them expires.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(format = DateTime, example = "2027-01-15T08:00:00.000000Z")]
    pub expires_at: Option<String>,
}

/// The effective permissions of a user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = UserRolePermissions)]
pub struct UserRolePermissionsResponse {
    /// The user whose permissions these are.
    #[schema(format = Uuid)]
    pub user_id: String,
    /// The policy version the permissions were composed at.
    #[schema(minimum = 0)]
    pub policy_version: i64,
    /// The exact keys in key order, then the wildcard patterns.
    pub permissions: Vec<EffectivePermissionResponse>,
}

impl From<&UserRolePermissionsView> for UserRolePermissionsResponse {
    fn from(view: &UserRolePermissionsView) -> Self {
        Self {
            user_id: view.subject.id().to_string(),
            policy_version: view.read_model.policy_version().value(),
            permissions: view
                .read_model
                .permissions()
                .iter()
                .map(|permission| entry_of(permission, view))
                .collect(),
        }
    }
}

/// The wire shape of one entry, with the names of its roles.
fn entry_of(
    permission: &EffectivePermission,
    view: &UserRolePermissionsView,
) -> EffectivePermissionResponse {
    let grant = permission.grant();
    EffectivePermissionResponse {
        key: grant.to_string(),
        kind: grant.kind().as_str().to_owned(),
        service: grant.service().to_string(),
        wildcard: grant.is_wildcard(),
        roles: permission
            .roles()
            .iter()
            .map(|role_id| GrantingRoleResponse {
                id: role_id.to_string(),
                name: view
                    .role_names
                    .get(role_id)
                    .and_then(Option::as_ref)
                    .map(ToString::to_string),
            })
            .collect(),
        scopes: scope_texts(permission.scopes()),
        expires_at: permission
            .expires_at()
            .map(|at| humantime::format_rfc3339_micros(at).to_string()),
    }
}

/// `["all"]` for every project, else the project ids in order.
fn scope_texts(scopes: &ScopeSet) -> Vec<String> {
    match scopes {
        ScopeSet::All => vec![SCOPE_ALL.to_owned()],
        ScopeSet::Projects(projects) => projects.iter().map(ToString::to_string).collect(),
    }
}

/// Query parameters of the effective permissions of a user.
#[derive(Debug, Clone, Default, Deserialize, IntoParams, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct UserRolePermissionsParams {
    /// Only assignments that apply in this project: the global ones and those of the project.
    #[param(format = Uuid)]
    pub project_id: Option<String>,
    /// Only keys and wildcards of this service.
    #[param(max_length = 63, example = "billing")]
    #[validate(length(max = 63, message = "This value must contain 63 characters or fewer."))]
    pub service: Option<String>,
}

impl UserRolePermissionsParams {
    /// The query for the user `user_id` and these parameters.
    ///
    /// # Errors
    ///
    /// [`IamError::Invalid`] with a violation for each of `userId`, `projectId` and `service`
    /// that is not a UUID or a service name.
    pub fn into_query(self, user_id: &str) -> Result<GetUserRolePermissionsQuery, IamError> {
        let subject = SubjectRef::new(SubjectKind::User, user_id)
            .map_err(|error| violation_of("userId", error));
        let project = self
            .project_id
            .as_deref()
            .map(ProjectId::parse)
            .transpose()
            .map_err(|error| violation_of("projectId", error));
        let service = self
            .service
            .as_deref()
            .map(ServiceName::new)
            .transpose()
            .map_err(|error| violation_of("service", error));
        match (subject, project, service) {
            (Ok(subject), Ok(project), Ok(service)) => Ok(GetUserRolePermissionsQuery {
                subject,
                project,
                service,
            }),
            (subject, project, service) => Err(IamError::Invalid(
                subject
                    .err()
                    .into_iter()
                    .chain(project.err())
                    .chain(service.err())
                    .collect(),
            )),
        }
    }
}

/// The violation of `property_path` that `error` describes.
fn violation_of(property_path: &str, error: InvalidIamValue) -> Violation {
    Violation {
        property_path: property_path.to_owned(),
        message: error.to_string(),
        code: error.code().to_owned(),
    }
}

#[cfg(test)]
mod tests;
