//! Wire shapes of the IAM context.
//!
//! Each one keeps its schema constraints and its validator attributes on the same field so that
//! both stay equal.

use iam_domain::{EntityVersion, RoleId, RoleKind, RoleParts, TokenRejection};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use shared_application::http::Violation;
use utoipa::{IntoParams, ToSchema};
use validator::{Validate, ValidationError};

use crate::command::update_role::DescriptionUpdate;
use crate::error::IamError;
use crate::principal::Principal;
use crate::query::list_roles::{ListRolesQuery, RolePage};
use crate::query::resolve_subject_token::TokenResolution;

/// The page size of a list without a `limit`.
pub(crate) const DEFAULT_PAGE_SIZE: i32 = 30;

/// Body of the token-resolution operation.
///
/// Its `Debug` output never shows the credential.
#[derive(Clone, Deserialize, ToSchema, Validate)]
#[serde(deny_unknown_fields)]
#[schema(as = TokenResolutionRequest)]
pub struct TokenResolutionRequest {
    /// The User service token to resolve; an empty one resolves as `token_missing`.
    #[schema(max_length = 8192, example = "eyJhbGciOiJSUzI1NiJ9.e30.c2lnbmF0dXJl")]
    #[validate(length(
        max = 8192,
        message = "This value must contain at most 8192 characters."
    ))]
    pub credential: String,
}

impl std::fmt::Debug for TokenResolutionRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResolutionRequest")
            .finish_non_exhaustive()
    }
}

/// The answer of the token-resolution operation.
///
/// A resolved credential carries the subject, the session, the roles claim and the expiry; a
/// refused one carries the reason code. The credential itself is never echoed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = TokenResolution)]
pub struct TokenResolutionResponse {
    /// Whether the credential is valid and unrevoked.
    pub resolved: bool,
    /// Why the credential is refused: `token_missing`, `token_invalid`, `token_expired` or
    /// `token_revoked`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "token_expired")]
    pub reason: Option<String>,
    /// The user id, or the service name of a service principal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,
    /// `user` or `service`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "user")]
    pub subject_kind: Option<String>,
    /// The User service session of the token, when it names one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// The roles claim of the token as issued.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
    /// When the token expires, in seconds since 1970-01-01T00:00:00Z.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(minimum = 0)]
    pub expires_at: Option<i64>,
}

impl TokenResolutionResponse {
    /// The answer for a refused credential.
    #[must_use]
    pub fn unresolved(rejection: TokenRejection) -> Self {
        Self {
            resolved: false,
            reason: Some(rejection.code().to_owned()),
            subject_id: None,
            subject_kind: None,
            session_id: None,
            roles: None,
            expires_at: None,
        }
    }

    /// The answer for the principal of a valid credential.
    #[must_use]
    pub fn resolved(principal: &Principal) -> Self {
        Self {
            resolved: true,
            reason: None,
            subject_id: Some(principal.subject().to_string()),
            subject_kind: Some(principal.subject_kind().as_str().to_owned()),
            session_id: principal
                .session()
                .map(|session| session.as_str().to_owned()),
            roles: Some(principal.roles().to_vec()),
            expires_at: Some(epoch_seconds(principal.expires_at())),
        }
    }
}

impl From<TokenResolution> for TokenResolutionResponse {
    fn from(resolution: TokenResolution) -> Self {
        match resolution {
            TokenResolution::Resolved(principal) => Self::resolved(&principal),
            TokenResolution::Unresolved(rejection) => Self::unresolved(rejection),
        }
    }
}

/// Whole seconds since 1970; zero before 1970 and the largest `i64` when the time does not fit.
fn epoch_seconds(time: std::time::SystemTime) -> i64 {
    let elapsed = time
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
}

/// Body of the role-creation operation.
#[derive(Debug, Clone, Deserialize, ToSchema, Validate)]
#[serde(deny_unknown_fields)]
#[schema(as = CreateRoleRequest)]
pub struct CreateRoleRequest {
    /// The name of the role: unique without regard to case among the roles that are not deleted,
    /// without control characters.
    #[schema(min_length = 1, max_length = 100, example = "Billing administrator")]
    #[validate(length(
        min = 1,
        max = 100,
        message = "This value must contain between 1 and 100 characters."
    ))]
    pub name: String,
    /// What the role is for.
    #[serde(default)]
    #[schema(max_length = 1000, example = "Manages invoices and refunds.")]
    #[validate(length(
        max = 1000,
        message = "This value must contain 1000 characters or fewer."
    ))]
    pub description: Option<String>,
}

impl CreateRoleRequest {
    /// The text that the idempotency digest of the request covers: the operation and the fields,
    /// so that a different body under the same key is a different request.
    #[must_use]
    pub fn canonical_form(&self) -> String {
        format!("role.create:{:?}", (&self.name, &self.description))
    }
}

/// What the body of an update says about the description: nothing keeps it, `null` removes it
/// and a string replaces it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DescriptionPatch(pub DescriptionUpdate);

impl<'de> Deserialize<'de> for DescriptionPatch {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = Option::<String>::deserialize(deserializer)?;
        Ok(Self(
            text.map_or(DescriptionUpdate::Remove, DescriptionUpdate::Set),
        ))
    }
}

impl Serialize for DescriptionPatch {
    /// The text of a replacement and `null` otherwise, which is how the validator reports it.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match &self.0 {
            DescriptionUpdate::Set(text) => serializer.serialize_str(text),
            DescriptionUpdate::Keep | DescriptionUpdate::Remove => serializer.serialize_none(),
        }
    }
}

/// The longest description, in characters.
const DESCRIPTION_MAX_CHARS: usize = 1000;

/// The description of an update keeps the limit of the creation.
fn validate_description_patch(patch: &DescriptionPatch) -> Result<(), ValidationError> {
    match &patch.0 {
        DescriptionUpdate::Set(text) if text.chars().count() > DESCRIPTION_MAX_CHARS => {
            Err(ValidationError::new("length")
                .with_message("This value must contain 1000 characters or fewer.".into()))
        }
        DescriptionUpdate::Keep | DescriptionUpdate::Remove | DescriptionUpdate::Set(_) => Ok(()),
    }
}

/// Body of the role-update operation: every member is optional, and an absent one stays as it is.
#[derive(Debug, Clone, Default, Deserialize, ToSchema, Validate)]
#[serde(deny_unknown_fields)]
#[schema(as = UpdateRoleRequest)]
pub struct UpdateRoleRequest {
    /// The new name of the role: unique without regard to case among the roles that are not
    /// deleted, without control characters.
    #[serde(default)]
    #[schema(min_length = 1, max_length = 100, example = "Billing administrator")]
    #[validate(length(
        min = 1,
        max = 100,
        message = "This value must contain between 1 and 100 characters."
    ))]
    pub name: Option<String>,
    /// The new description; `null` removes it and an absent member keeps it.
    #[serde(default)]
    #[schema(value_type = Option<String>, max_length = 1000, example = "Manages invoices and refunds.")]
    #[validate(custom(function = validate_description_patch))]
    pub description: DescriptionPatch,
}

impl UpdateRoleRequest {
    /// The text that the idempotency digest covers: the operation, the role, the version and the
    /// fields.
    #[must_use]
    pub fn canonical_form(&self, id: RoleId, expected: EntityVersion) -> String {
        format!(
            "role.update:{:?}",
            (
                id.to_string(),
                expected.value(),
                &self.name,
                &self.description.0
            )
        )
    }
}

/// A role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = Role)]
pub struct RoleResponse {
    /// The identifier of the role.
    #[schema(format = Uuid)]
    pub id: String,
    /// The name of the role.
    #[schema(min_length = 1, max_length = 100)]
    pub name: String,
    /// What the role is for.
    #[schema(max_length = 1000)]
    pub description: Option<String>,
    /// `system` for a role that IAM manages, `custom` for one that an administrator manages.
    #[schema(example = "custom")]
    pub kind: String,
    /// The number of permission grants of the role.
    #[schema(minimum = 0)]
    pub grant_count: i64,
    /// The version of the role; its `ETag` is this number in double quotes.
    #[schema(minimum = 1)]
    pub version: i64,
    /// When the role was created, as an RFC 3339 UTC time.
    #[schema(format = DateTime, example = "2026-11-23T10:15:30.123456Z")]
    pub created_at: String,
    /// When the role was last changed, as an RFC 3339 UTC time.
    #[schema(format = DateTime, example = "2026-11-23T10:15:30.123456Z")]
    pub updated_at: String,
}

impl From<RoleParts> for RoleResponse {
    fn from(role: RoleParts) -> Self {
        Self {
            id: role.id.to_string(),
            name: role.name.to_string(),
            description: role.description.map(|text| text.as_str().to_owned()),
            kind: role.kind.as_str().to_owned(),
            grant_count: i64::try_from(role.grants.len()).unwrap_or(i64::MAX),
            version: role.version.value(),
            created_at: humantime::format_rfc3339_micros(role.created_at).to_string(),
            updated_at: humantime::format_rfc3339_micros(role.updated_at).to_string(),
        }
    }
}

/// One page of roles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = RolePage)]
pub struct RolePageResponse {
    /// The roles of the page.
    pub items: Vec<RoleResponse>,
    /// The `after` value of the next page; absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(format = Uuid)]
    pub next_cursor: Option<String>,
}

impl From<RolePage> for RolePageResponse {
    fn from(page: RolePage) -> Self {
        Self {
            items: page.roles.into_iter().map(RoleResponse::from).collect(),
            next_cursor: page.next_after.map(|id| id.to_string()),
        }
    }
}

/// Query parameters of the role list; `limit` is signed so that a negative value is a 422, not a
/// parse error.
#[derive(Debug, Clone, Deserialize, IntoParams, Validate)]
#[serde(rename_all = "camelCase", default, deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub struct ListRolesParams {
    /// The largest number of roles of the page.
    #[param(minimum = 1, maximum = 100, default = 30)]
    #[validate(range(min = 1, max = 100, message = "This value must be between 1 and 100."))]
    pub limit: i32,
    /// The `nextCursor` of the previous page; absent for the first page.
    #[param(format = Uuid)]
    pub after: Option<String>,
    /// Only roles whose name starts with this text, compared without regard to case.
    #[param(max_length = 100)]
    #[validate(length(
        max = 100,
        message = "This value must contain 100 characters or fewer."
    ))]
    pub name_prefix: Option<String>,
    /// Only roles of this kind: `system` or `custom`.
    #[param(example = "custom")]
    pub kind: Option<String>,
}

impl Default for ListRolesParams {
    fn default() -> Self {
        Self {
            limit: DEFAULT_PAGE_SIZE,
            after: None,
            name_prefix: None,
            kind: None,
        }
    }
}

impl ListRolesParams {
    /// The query for these parameters; call it after validation, which makes `limit` positive.
    ///
    /// # Errors
    ///
    /// [`IamError::Invalid`] with a violation for an `after` that is not a UUID and one for a
    /// `kind` that is neither `system` nor `custom`.
    pub fn into_query(self) -> Result<ListRolesQuery, IamError> {
        let after = self.after.as_deref().map(RoleId::parse).transpose();
        let kind = self.kind.as_deref().map(RoleKind::parse).transpose();
        match (after, kind) {
            (Ok(after), Ok(kind)) => Ok(ListRolesQuery {
                limit: self.limit.unsigned_abs(),
                after,
                name_prefix: self.name_prefix,
                kind,
            }),
            (after, kind) => Err(IamError::Invalid(
                after
                    .err()
                    .map(|_error| violation("after", "This value is not a valid UUID.", "uuid"))
                    .into_iter()
                    .chain(kind.err().map(|error| {
                        violation(error.property_path(), &error.to_string(), error.code())
                    }))
                    .collect(),
            )),
        }
    }
}

/// One violated constraint of a parameter.
fn violation(property_path: &str, message: &str, code: &str) -> Violation {
    Violation {
        property_path: property_path.to_owned(),
        message: message.to_owned(),
        code: code.to_owned(),
    }
}

#[cfg(test)]
mod tests;
