//! Wire shapes of the role assignments of the IAM context.
//!
//! Each one keeps its schema constraints and its validator attributes on the same field so that
//! both stay equal.

use std::time::SystemTime;

use iam_domain::{
    AssignmentScope, EntityVersion, InvalidIamValue, ProjectId, RoleId, SubjectKind, SubjectRef,
    UserRoleId, UserRoleParts,
};
use serde::{Deserialize, Deserializer, Serialize};
use shared_application::http::Violation;
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

use crate::error::IamError;
use crate::http::dto::DEFAULT_PAGE_SIZE;
use crate::query::get_user_role::UserRoleView;
use crate::query::list_user_roles::{ListUserRolesQuery, UserRolePage};

/// Who holds an assignment: a user or a service principal.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema, Validate)]
#[serde(deny_unknown_fields)]
#[schema(as = AssignmentSubject)]
pub struct SubjectDto {
    /// `user` for a user of the User service, `service` for a service principal.
    #[schema(example = "user")]
    #[validate(length(
        min = 1,
        max = 20,
        message = "This value must contain between 1 and 20 characters."
    ))]
    pub kind: String,
    /// The UUID of a user, or the service name of a service principal such as `billing-worker`.
    #[schema(
        min_length = 1,
        max_length = 255,
        example = "0190f2a8-7b3c-7d4e-8f10-1234567890ab"
    )]
    #[validate(length(
        min = 1,
        max = 255,
        message = "This value must contain between 1 and 255 characters."
    ))]
    pub id: String,
}

impl From<&SubjectRef> for SubjectDto {
    fn from(subject: &SubjectRef) -> Self {
        Self {
            kind: subject.kind().as_str().to_owned(),
            id: subject.id().to_string(),
        }
    }
}

/// Where an assignment applies: every project, or one project.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[schema(as = AssignmentScope)]
pub struct ScopeDto {
    /// `global` for every project, `project` for the project named by `projectId`.
    #[schema(example = "global")]
    #[validate(length(
        min = 1,
        max = 20,
        message = "This value must contain between 1 and 20 characters."
    ))]
    pub kind: String,
    /// The project of a project scope; absent for a global scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(format = Uuid)]
    pub project_id: Option<String>,
}

impl From<AssignmentScope> for ScopeDto {
    fn from(scope: AssignmentScope) -> Self {
        Self {
            kind: scope.kind().to_owned(),
            project_id: scope.project_id().map(|project| project.to_string()),
        }
    }
}

/// Body of the assignment operation.
#[derive(Debug, Clone, Deserialize, ToSchema, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[schema(as = AssignUserRoleRequest)]
pub struct AssignUserRoleRequest {
    /// Who receives the role.
    #[validate(nested)]
    pub subject: SubjectDto,
    /// The role to assign; it must exist.
    #[schema(format = Uuid)]
    #[validate(length(
        min = 1,
        max = 64,
        message = "This value must contain between 1 and 64 characters."
    ))]
    pub role_id: String,
    /// Where the role applies.
    #[validate(nested)]
    pub scope: ScopeDto,
    /// When the assignment expires, as an RFC 3339 UTC time in the future; absent for an
    /// assignment that never expires.
    #[serde(default)]
    #[schema(format = DateTime, example = "2027-01-15T08:00:00Z")]
    #[validate(length(max = 40, message = "This value must contain 40 characters or fewer."))]
    pub expires_at: Option<String>,
}

/// The values of an assignment request once parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAssignment {
    /// Who receives the role.
    pub subject: SubjectRef,
    /// The role to assign.
    pub role_id: RoleId,
    /// Where the role applies.
    pub scope: AssignmentScope,
    /// When the assignment expires.
    pub expires_at: Option<SystemTime>,
}

impl AssignUserRoleRequest {
    /// The text that the idempotency digest of the request covers: the operation and the fields,
    /// so that a different body under the same key is a different request.
    #[must_use]
    pub fn canonical_form(&self) -> String {
        format!(
            "user_role.assign:{:?}",
            (
                &self.subject.kind,
                &self.subject.id,
                &self.role_id,
                &self.scope.kind,
                &self.scope.project_id,
                &self.expires_at
            )
        )
    }

    /// Parses the subject, the role, the scope and the expiry.
    ///
    /// # Errors
    ///
    /// [`IamError::Invalid`] with every violation, in the order subject, role, scope, expiry.
    pub fn parse(&self) -> Result<ParsedAssignment, IamError> {
        let subject = parse_subject(&self.subject);
        let role_id = RoleId::parse(&self.role_id);
        let scope = parse_scope(&self.scope);
        let expires_at = self.expires_at.as_deref().map(parse_expiry).transpose();
        match (subject, role_id, scope, expires_at) {
            (Ok(subject), Ok(role_id), Ok(scope), Ok(expires_at)) => Ok(ParsedAssignment {
                subject,
                role_id,
                scope,
                expires_at,
            }),
            (subject, role_id, scope, expires_at) => Err(IamError::Invalid(
                subject
                    .err()
                    .into_iter()
                    .chain(role_id.err().map(|error| violation_of("roleId", error)))
                    .chain(scope.err())
                    .chain(expires_at.err())
                    .collect(),
            )),
        }
    }
}

/// The subject of a request; a service name that breaks its pattern is a violation of
/// `subject.id`.
fn parse_subject(subject: &SubjectDto) -> Result<SubjectRef, Violation> {
    let kind = SubjectKind::parse(&subject.kind)
        .map_err(|error| violation_of(error.property_path(), error))?;
    SubjectRef::new(kind, &subject.id).map_err(|error| {
        let service_name = matches!(
            error,
            InvalidIamValue::ServiceNameLength | InvalidIamValue::ServiceNamePattern
        );
        let property_path = if service_name {
            "subject.id"
        } else {
            error.property_path()
        };
        violation_of(property_path, error)
    })
}

/// The scope of a request.
fn parse_scope(scope: &ScopeDto) -> Result<AssignmentScope, Violation> {
    let project = scope
        .project_id
        .as_deref()
        .map(ProjectId::parse)
        .transpose()
        .map_err(|_error| violation_of("scope.projectId", InvalidIamValue::Identifier))?;
    AssignmentScope::from_parts(&scope.kind, project)
        .map_err(|error| violation_of(error.property_path(), error))
}

/// The expiry of a request, an RFC 3339 UTC time.
fn parse_expiry(text: &str) -> Result<SystemTime, Violation> {
    humantime::parse_rfc3339(text).map_err(|_error| Violation {
        property_path: "expiresAt".to_owned(),
        message: "This value must be an RFC 3339 UTC time such as 2027-01-15T08:00:00Z.".to_owned(),
        code: "format".to_owned(),
    })
}

/// The violation of `property_path` that `error` describes.
fn violation_of(property_path: &str, error: InvalidIamValue) -> Violation {
    Violation {
        property_path: property_path.to_owned(),
        message: error.to_string(),
        code: error.code().to_owned(),
    }
}

/// The member of an update that must be present: a time, or `null` to clear the expiry.
fn required_expiry<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    Option::<String>::deserialize(deserializer)
}

/// Body of the assignment-update operation.
#[derive(Debug, Clone, Deserialize, ToSchema, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[schema(as = UpdateUserRoleRequest)]
pub struct UpdateUserRoleRequest {
    /// The new expiry, as an RFC 3339 UTC time in the future; `null` clears the expiry. The member
    /// is required, so that an empty body never clears an expiry by accident.
    #[serde(deserialize_with = "required_expiry")]
    #[schema(required = true, nullable = true, value_type = Option<String>, format = DateTime, example = "2027-01-15T08:00:00Z")]
    #[validate(length(max = 40, message = "This value must contain 40 characters or fewer."))]
    pub expires_at: Option<String>,
}

impl UpdateUserRoleRequest {
    /// The text that the idempotency digest covers: the operation, the assignment, the version and
    /// the expiry.
    #[must_use]
    pub fn canonical_form(&self, id: UserRoleId, expected: EntityVersion) -> String {
        format!(
            "user_role.update:{:?}",
            (id.to_string(), expected.value(), &self.expires_at)
        )
    }

    /// Parses the expiry; `None` clears it.
    ///
    /// # Errors
    ///
    /// [`IamError::Invalid`] with a violation of `expiresAt` when the text is not an RFC 3339 UTC
    /// time.
    pub fn parse(&self) -> Result<Option<SystemTime>, IamError> {
        self.expires_at
            .as_deref()
            .map(parse_expiry)
            .transpose()
            .map_err(|violation| IamError::Invalid(vec![violation]))
    }
}

/// The text that the idempotency digest of a revocation covers: the operation, the assignment and
/// the version.
#[must_use]
pub fn revoke_canonical_form(id: UserRoleId, expected: EntityVersion) -> String {
    format!("user_role.revoke:{:?}", (id.to_string(), expected.value()))
}

/// A role assignment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = UserRole)]
pub struct UserRoleResponse {
    /// The identifier of the assignment.
    #[schema(format = Uuid)]
    pub id: String,
    /// Who holds the role.
    pub subject: SubjectDto,
    /// The assigned role.
    #[schema(format = Uuid)]
    pub role_id: String,
    /// The name of the assigned role.
    #[schema(max_length = 100)]
    pub role_name: Option<String>,
    /// Where the role applies.
    pub scope: ScopeDto,
    /// When the assignment expires, as an RFC 3339 UTC time; absent when it never expires.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(format = DateTime, example = "2027-01-15T08:00:00.000000Z")]
    pub expires_at: Option<String>,
    /// The version of the assignment; its `ETag` is this number in double quotes.
    #[schema(minimum = 1)]
    pub version: i64,
    /// When the assignment was created, as an RFC 3339 UTC time.
    #[schema(format = DateTime, example = "2026-11-23T10:15:30.123456Z")]
    pub created_at: String,
    /// When the assignment was last changed, as an RFC 3339 UTC time.
    #[schema(format = DateTime, example = "2026-11-23T10:15:30.123456Z")]
    pub updated_at: String,
}

impl From<UserRoleView> for UserRoleResponse {
    fn from(view: UserRoleView) -> Self {
        let UserRoleView {
            user_role,
            role_name,
        } = view;
        let UserRoleParts {
            id,
            subject,
            role_id,
            scope,
            expires_at,
            version,
            created_at,
            updated_at,
            ..
        } = user_role;
        Self {
            id: id.to_string(),
            subject: SubjectDto::from(&subject),
            role_id: role_id.to_string(),
            role_name: role_name.map(|name| name.to_string()),
            scope: ScopeDto::from(scope),
            expires_at: expires_at
                .map(|expiry| humantime::format_rfc3339_micros(expiry.at()).to_string()),
            version: version.value(),
            created_at: humantime::format_rfc3339_micros(created_at).to_string(),
            updated_at: humantime::format_rfc3339_micros(updated_at).to_string(),
        }
    }
}

/// One page of role assignments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = UserRolePage)]
pub struct UserRolePageResponse {
    /// The assignments of the page.
    pub items: Vec<UserRoleResponse>,
    /// The `after` value of the next page; absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(format = Uuid)]
    pub next_cursor: Option<String>,
}

impl From<UserRolePage> for UserRolePageResponse {
    fn from(page: UserRolePage) -> Self {
        Self {
            items: page
                .user_roles
                .into_iter()
                .map(UserRoleResponse::from)
                .collect(),
            next_cursor: page.next_after.map(|id| id.to_string()),
        }
    }
}

/// Query parameters of the assignment list; `limit` is signed so that a negative value is a 422,
/// not a parse error.
#[derive(Debug, Clone, Deserialize, IntoParams, Validate)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct ListUserRolesParams {
    /// The largest number of assignments of the page.
    #[param(minimum = 1, maximum = 100, default = 30)]
    #[validate(range(min = 1, max = 100, message = "This value must be between 1 and 100."))]
    pub limit: i32,
    /// The `nextCursor` of the previous page; absent for the first page.
    #[param(format = Uuid)]
    pub after: Option<String>,
    /// Only assignments of subjects of this kind: `user` or `service`.
    #[param(example = "service")]
    pub subject_kind: Option<String>,
    /// Only assignments of the subject with this id: a user UUID or a service name.
    #[param(max_length = 255)]
    #[validate(length(
        max = 255,
        message = "This value must contain 255 characters or fewer."
    ))]
    pub subject_id: Option<String>,
    /// Only assignments of this role.
    #[param(format = Uuid)]
    pub role_id: Option<String>,
    /// Only assignments scoped to this project.
    #[param(format = Uuid)]
    pub project_id: Option<String>,
    /// Whether assignments that have expired are listed as well; default `false`.
    pub include_expired: bool,
}

impl Default for ListUserRolesParams {
    fn default() -> Self {
        Self {
            limit: DEFAULT_PAGE_SIZE,
            after: None,
            subject_kind: None,
            subject_id: None,
            role_id: None,
            project_id: None,
            include_expired: false,
        }
    }
}

impl ListUserRolesParams {
    /// The query for these parameters; call it after validation, which makes `limit` positive.
    ///
    /// # Errors
    ///
    /// [`IamError::Invalid`] with a violation for each of `after`, `subjectKind`, `roleId` and
    /// `projectId` that does not hold a UUID or a known kind.
    pub fn into_query(self) -> Result<ListUserRolesQuery, IamError> {
        let after = self.after.as_deref().map(UserRoleId::parse).transpose();
        let kind = self
            .subject_kind
            .as_deref()
            .map(SubjectKind::parse)
            .transpose();
        let role = self.role_id.as_deref().map(RoleId::parse).transpose();
        let project = self.project_id.as_deref().map(ProjectId::parse).transpose();
        match (after, kind, role, project) {
            (Ok(after), Ok(subject_kind), Ok(role_id), Ok(project_id)) => Ok(ListUserRolesQuery {
                limit: self.limit.unsigned_abs(),
                after,
                subject_kind,
                subject_id: self.subject_id,
                role_id,
                project_id,
                include_expired: self.include_expired,
            }),
            (after, kind, role, project) => Err(IamError::Invalid(
                after
                    .err()
                    .map(|error| violation_of("after", error))
                    .into_iter()
                    .chain(kind.err().map(|error| violation_of("subjectKind", error)))
                    .chain(role.err().map(|error| violation_of("roleId", error)))
                    .chain(project.err().map(|error| violation_of("projectId", error)))
                    .collect(),
            )),
        }
    }
}

#[cfg(test)]
mod tests;
