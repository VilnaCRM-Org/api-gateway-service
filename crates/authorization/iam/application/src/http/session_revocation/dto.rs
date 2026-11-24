//! Wire shapes of the operations that revoke sessions and cut off tokens (FR-1, FR-17).

use iam_domain::{ChangeReceipt, SessionId};
use serde::{Deserialize, Serialize};
use shared_application::http::Violation;
use shared_domain::Uuid;
use utoipa::ToSchema;
use validator::Validate;

use crate::error::IamError;

/// Body of the operation that revokes sessions of a user, or cuts off all of the user's tokens.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, ToSchema, Validate)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[schema(as = RevokeSessionsRequest)]
pub struct RevokeSessionsRequest {
    /// The user whose sessions or tokens are revoked.
    #[schema(format = Uuid)]
    pub user_id: String,
    /// The sessions to revoke, at most 100, each 1 to 255 visible ASCII characters. An empty or
    /// missing list sets the cut-off of every token of the user instead.
    #[serde(default)]
    #[schema(max_items = 100)]
    #[validate(length(max = 100, message = "This value must contain 100 items or fewer."))]
    pub session_ids: Vec<String>,
}

/// The values of a request, once they passed the rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRevocation {
    /// The user.
    pub user_id: Uuid,
    /// The sessions, as listed; empty for the cut-off of the user.
    pub session_ids: Vec<SessionId>,
}

impl RevokeSessionsRequest {
    /// Checks the values of the request.
    ///
    /// # Errors
    ///
    /// [`IamError::Invalid`] with one violation for `userId` that is not a UUID and for each
    /// `sessionIds` entry that is not 1 to 255 visible ASCII characters.
    pub fn parse(&self) -> Result<ParsedRevocation, IamError> {
        let mut violations = Vec::new();
        let user_id = Uuid::parse(&self.user_id).ok();
        if user_id.is_none() {
            violations.push(violation(
                "userId",
                "uuid",
                "This value is not a valid UUID.",
            ));
        }
        let mut session_ids = Vec::with_capacity(self.session_ids.len());
        for (index, text) in self.session_ids.iter().enumerate() {
            match SessionId::new(text) {
                Ok(session) => session_ids.push(session),
                Err(_rejection) => violations.push(violation(
                    &format!("sessionIds[{index}]"),
                    "format",
                    "This value must contain between 1 and 255 visible ASCII characters.",
                )),
            }
        }
        match user_id {
            Some(user_id) if violations.is_empty() => Ok(ParsedRevocation {
                user_id,
                session_ids,
            }),
            _ => Err(IamError::Invalid(violations)),
        }
    }

    /// The text that the idempotency digest of the request covers: the operation, the user and
    /// the sessions in order, so that another body under the same key is another request.
    #[must_use]
    pub fn canonical_form(&self) -> String {
        format!(
            "session.revoke:{:?}",
            (self.user_id.to_lowercase(), &self.session_ids)
        )
    }
}

fn violation(path: &str, code: &str, message: &str) -> Violation {
    Violation {
        property_path: path.to_owned(),
        message: message.to_owned(),
        code: code.to_owned(),
    }
}

/// The result of a revocation write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[schema(as = RevocationResult)]
pub struct RevocationResultResponse {
    /// What the audit record of the change targets: the first revoked session's revocation, the
    /// user of a cut-off, or `current` for the global cut-off.
    pub id: String,
    /// The policy version that the change produced.
    #[schema(minimum = 1)]
    pub policy_version: Option<i64>,
}

impl From<&ChangeReceipt> for RevocationResultResponse {
    fn from(receipt: &ChangeReceipt) -> Self {
        Self {
            id: receipt.target().target_id().to_owned(),
            policy_version: receipt
                .policy_version()
                .map(iam_domain::PolicyVersion::value),
        }
    }
}

#[cfg(test)]
mod tests;
