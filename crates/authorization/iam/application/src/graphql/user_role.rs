//! GraphQL objects and the resolvers of the role assignment operations.
//!
//! The resolvers share the use-case calls and the response shapes of the REST handlers, so both
//! transports apply one set of rules.

use async_graphql::{Context, ID, InputObject, MaybeUndefined, SimpleObject};
use shared_application::http::{Problem, Violation};
use validator::Validate as _;

use super::{expected_version, idempotency_key, require_caller, state};
use crate::error::IamError;
use crate::http::dto::DEFAULT_PAGE_SIZE;
use crate::http::extract::VersionedWriteHeaders;
use crate::http::user_role::dto::{
    AssignUserRoleRequest, ListUserRolesParams, ScopeDto, SubjectDto, UpdateUserRoleRequest,
    UserRolePageResponse, UserRoleResponse,
};
use crate::http::user_role::{
    assign_user_role, find_user_role, list_user_roles, parse_user_role_id, revoke_user_role,
    update_user_role,
};

/// Who receives a role, as an input.
#[derive(Debug, InputObject)]
#[graphql(name = "AssignmentSubjectInput")]
pub struct SubjectInput {
    /// `user` for a user of the User service, `service` for a service principal.
    pub kind: String,
    /// The UUID of a user, or the service name of a service principal such as `billing-worker`.
    pub id: String,
}

/// Where an assignment applies, as an input.
#[derive(Debug, InputObject)]
#[graphql(name = "AssignmentScopeInput")]
pub struct ScopeInput {
    /// `global` for every project, `project` for the project named by `projectId`.
    pub kind: String,
    /// The project of a project scope; null for a global scope.
    pub project_id: Option<String>,
}

/// Input of the assignment mutation.
#[derive(Debug, InputObject)]
#[graphql(name = "AssignUserRoleInput")]
pub struct AssignUserRoleInput {
    /// Who receives the role.
    pub subject: SubjectInput,
    /// The role to assign; it must exist.
    pub role_id: String,
    /// Where the role applies.
    pub scope: ScopeInput,
    /// When the assignment expires, as an RFC 3339 UTC time in the future; null for an assignment that never expires.
    pub expires_at: Option<String>,
    /// Makes the assignment safe to repeat for 24 hours: 1 to 255 visible ASCII characters.
    pub idempotency_key: Option<String>,
}

/// Input of the assignment-update mutation.
#[derive(Debug, InputObject)]
#[graphql(name = "UpdateUserRoleInput")]
pub struct UpdateUserRoleInput {
    /// The assignment to change.
    pub id: ID,
    /// The version the caller read; required, and the update is refused when it is not the current one.
    pub expected_version: Option<i64>,
    /// The new expiry, as an RFC 3339 UTC time in the future; null clears the expiry. The field is required.
    pub expires_at: MaybeUndefined<String>,
    /// Makes the update safe to repeat for 24 hours: 1 to 255 visible ASCII characters.
    pub idempotency_key: Option<String>,
}

/// Input of the assignment-revocation mutation.
#[derive(Debug, InputObject)]
#[graphql(name = "RevokeUserRoleInput")]
pub struct RevokeUserRoleInput {
    /// The assignment to revoke.
    pub id: ID,
    /// The version the caller read; required, and the revocation is refused when it is not the current one.
    pub expected_version: Option<i64>,
    /// Makes the revocation safe to repeat for 24 hours: 1 to 255 visible ASCII characters.
    pub idempotency_key: Option<String>,
}

/// The result of a revocation.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "RevokeUserRolePayload")]
pub struct RevokeUserRolePayload {
    /// The identifier of the revoked assignment.
    pub id: ID,
    /// The final version of the assignment.
    pub version: i64,
    /// The policy version that the revocation produced.
    pub policy_version: Option<i64>,
}

/// Filters of the assignment list.
#[derive(Debug, Default, InputObject)]
#[graphql(name = "UserRoleFilter")]
pub struct UserRoleFilterInput {
    /// Only assignments of subjects of this kind: `user` or `service`.
    pub subject_kind: Option<String>,
    /// Only assignments of the subject with this id: a user UUID or a service name.
    pub subject_id: Option<String>,
    /// Only assignments of this role.
    pub role_id: Option<String>,
    /// Only assignments scoped to this project.
    pub project_id: Option<String>,
    /// Whether assignments that have expired are listed as well; default `false`.
    pub include_expired: Option<bool>,
}

/// Who holds an assignment.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "AssignmentSubject")]
pub struct SubjectObject {
    /// `user` or `service`.
    pub kind: String,
    /// The UUID of a user, or the service name of a service principal.
    pub id: String,
}

impl From<SubjectDto> for SubjectObject {
    fn from(subject: SubjectDto) -> Self {
        Self {
            kind: subject.kind,
            id: subject.id,
        }
    }
}

/// Where an assignment applies.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "AssignmentScope")]
pub struct ScopeObject {
    /// `global` or `project`.
    pub kind: String,
    /// The project of a project scope; null for a global scope.
    pub project_id: Option<String>,
}

impl From<ScopeDto> for ScopeObject {
    fn from(scope: ScopeDto) -> Self {
        Self {
            kind: scope.kind,
            project_id: scope.project_id,
        }
    }
}

/// A role assignment.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "UserRole")]
pub struct UserRoleObject {
    /// The identifier of the assignment.
    pub id: ID,
    /// Who holds the role.
    pub subject: SubjectObject,
    /// The assigned role.
    pub role_id: ID,
    /// The name of the assigned role.
    pub role_name: Option<String>,
    /// Where the role applies.
    pub scope: ScopeObject,
    /// When the assignment expires, as an RFC 3339 UTC time; null when it never expires.
    pub expires_at: Option<String>,
    /// The version of the assignment.
    pub version: i64,
    /// When the assignment was created, as an RFC 3339 UTC time.
    pub created_at: String,
    /// When the assignment was last changed, as an RFC 3339 UTC time.
    pub updated_at: String,
}

impl From<UserRoleResponse> for UserRoleObject {
    fn from(response: UserRoleResponse) -> Self {
        Self {
            id: ID::from(response.id),
            subject: SubjectObject::from(response.subject),
            role_id: ID::from(response.role_id),
            role_name: response.role_name,
            scope: ScopeObject::from(response.scope),
            expires_at: response.expires_at,
            version: response.version,
            created_at: response.created_at,
            updated_at: response.updated_at,
        }
    }
}

/// One page of role assignments.
#[derive(Debug, Clone, PartialEq, Eq, SimpleObject)]
#[graphql(name = "UserRolePage")]
pub struct UserRolePageObject {
    /// The assignments of the page.
    pub items: Vec<UserRoleObject>,
    /// The `after` value of the next page; null on the last page.
    pub next_cursor: Option<String>,
}

impl From<UserRolePageResponse> for UserRolePageObject {
    fn from(page: UserRolePageResponse) -> Self {
        Self {
            items: page.items.into_iter().map(UserRoleObject::from).collect(),
            next_cursor: page.next_cursor,
        }
    }
}

/// Assigns a role as the caller of the request.
pub(super) async fn assign_user_role_field(
    ctx: &Context<'_>,
    input: AssignUserRoleInput,
) -> Result<UserRoleObject, Problem> {
    let caller = require_caller(ctx)?;
    let key = idempotency_key(input.idempotency_key.as_deref())?;
    let request = AssignUserRoleRequest {
        subject: SubjectDto {
            kind: input.subject.kind,
            id: input.subject.id,
        },
        role_id: input.role_id,
        scope: ScopeDto {
            kind: input.scope.kind,
            project_id: input.scope.project_id,
        },
        expires_at: input.expires_at,
    };
    request.validate()?;
    let (user_role, _receipt) = assign_user_role(state(ctx)?, caller, key, request).await?;
    Ok(UserRoleObject::from(UserRoleResponse::from(user_role)))
}

/// Reads one assignment; none when it is unknown or revoked.
pub(super) async fn user_role_field(
    ctx: &Context<'_>,
    id: &ID,
) -> Result<Option<UserRoleObject>, Problem> {
    require_caller(ctx)?;
    let user_role = find_user_role(state(ctx)?, parse_user_role_id(id.as_str())?).await?;
    Ok(user_role.map(|view| UserRoleObject::from(UserRoleResponse::from(view))))
}

/// Reads one page of assignments.
pub(super) async fn user_roles_field(
    ctx: &Context<'_>,
    first: Option<i32>,
    after: Option<String>,
    filter: UserRoleFilterInput,
) -> Result<UserRolePageObject, Problem> {
    require_caller(ctx)?;
    let params = ListUserRolesParams {
        limit: first.unwrap_or(DEFAULT_PAGE_SIZE),
        after,
        subject_kind: filter.subject_kind,
        subject_id: filter.subject_id,
        role_id: filter.role_id,
        project_id: filter.project_id,
        include_expired: filter.include_expired.unwrap_or(false),
    };
    params.validate()?;
    let page = list_user_roles(state(ctx)?, params).await?;
    Ok(UserRolePageObject::from(UserRolePageResponse::from(page)))
}

/// The expiry member of an update input: a missing field is a violation of `expiresAt`, because
/// an update that names no expiry would otherwise clear it by accident.
fn required_expiry(field: MaybeUndefined<String>) -> Result<Option<String>, IamError> {
    match field {
        MaybeUndefined::Undefined => Err(IamError::Invalid(vec![Violation {
            property_path: "expiresAt".to_owned(),
            message: "This value should not be missing; use null to clear the expiry.".to_owned(),
            code: "required".to_owned(),
        }])),
        MaybeUndefined::Null => Ok(None),
        MaybeUndefined::Value(text) => Ok(Some(text)),
    }
}

/// Changes the expiry of an assignment as the caller of the request.
pub(super) async fn update_user_role_field(
    ctx: &Context<'_>,
    input: UpdateUserRoleInput,
) -> Result<UserRoleObject, Problem> {
    let caller = require_caller(ctx)?;
    let expected = expected_version(input.expected_version)?;
    let id = parse_user_role_id(input.id.as_str())?;
    let key = idempotency_key(input.idempotency_key.as_deref())?;
    let request = UpdateUserRoleRequest {
        expires_at: required_expiry(input.expires_at)?,
    };
    request.validate()?;
    let headers = VersionedWriteHeaders { expected, key };
    let (user_role, _receipt) = update_user_role(state(ctx)?, caller, id, headers, request).await?;
    Ok(UserRoleObject::from(UserRoleResponse::from(user_role)))
}

/// Revokes an assignment as the caller of the request.
pub(super) async fn revoke_user_role_field(
    ctx: &Context<'_>,
    input: RevokeUserRoleInput,
) -> Result<RevokeUserRolePayload, Problem> {
    let caller = require_caller(ctx)?;
    let expected = expected_version(input.expected_version)?;
    let id = parse_user_role_id(input.id.as_str())?;
    let key = idempotency_key(input.idempotency_key.as_deref())?;
    let headers = VersionedWriteHeaders { expected, key };
    let receipt = revoke_user_role(state(ctx)?, caller, id, headers).await?;
    Ok(RevokeUserRolePayload {
        id: ID::from(receipt.target().target_id()),
        version: receipt.entity_version().value(),
        policy_version: receipt
            .policy_version()
            .map(iam_domain::PolicyVersion::value),
    })
}
