//! The reason code of a decision.

use crate::value_object::decision::Decision;

/// The twelve reason codes of FR-6, plus `audit_mode_would_deny` for the access records of FR-69.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecisionReason {
    /// `allowed`: every required key is held in the requested scope.
    Allowed,
    /// `token_missing`: the check carries no credential.
    TokenMissing,
    /// `token_invalid`: the credential does not verify.
    TokenInvalid,
    /// `token_expired`: the credential has expired.
    TokenExpired,
    /// `token_revoked`: the credential's session or subject is revoked.
    TokenRevoked,
    /// `unknown_service`: the target service has no active specification.
    UnknownService,
    /// `unknown_operation`: the operation or key is not in the service's catalogue.
    UnknownOperation,
    /// `malformed_operation`: the operation cannot be read.
    MalformedOperation,
    /// `permission_missing`: no active assignment holds a required key.
    PermissionMissing,
    /// `scope_missing`: a required key is held only in other projects.
    ScopeMissing,
    /// `limits_exceeded`: a GraphQL document exceeds a limit.
    LimitsExceeded,
    /// `unavailable`: the check cannot be decided on fresh policy.
    Unavailable,
    /// `audit_mode_would_deny`: a route in audit mode forwarded a request it would deny.
    AuditModeWouldDeny,
}

impl DecisionReason {
    /// The twelve codes a decision response may carry, in the order of FR-6.
    pub const RESPONSE_CODES: [Self; 12] = [
        Self::Allowed,
        Self::TokenMissing,
        Self::TokenInvalid,
        Self::TokenExpired,
        Self::TokenRevoked,
        Self::UnknownService,
        Self::UnknownOperation,
        Self::MalformedOperation,
        Self::PermissionMissing,
        Self::ScopeMissing,
        Self::LimitsExceeded,
        Self::Unavailable,
    ];

    /// The stable snake-case code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::TokenMissing => "token_missing",
            Self::TokenInvalid => "token_invalid",
            Self::TokenExpired => "token_expired",
            Self::TokenRevoked => "token_revoked",
            Self::UnknownService => "unknown_service",
            Self::UnknownOperation => "unknown_operation",
            Self::MalformedOperation => "malformed_operation",
            Self::PermissionMissing => "permission_missing",
            Self::ScopeMissing => "scope_missing",
            Self::LimitsExceeded => "limits_exceeded",
            Self::Unavailable => "unavailable",
            Self::AuditModeWouldDeny => "audit_mode_would_deny",
        }
    }

    /// Parses a code; `None` for any other text.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::RESPONSE_CODES
            .into_iter()
            .chain([Self::AuditModeWouldDeny])
            .find(|reason| reason.as_str() == value)
    }

    /// The decision this reason belongs to: only `allowed` allows.
    #[must_use]
    pub const fn decision(self) -> Decision {
        match self {
            Self::Allowed => Decision::Allow,
            Self::TokenMissing
            | Self::TokenInvalid
            | Self::TokenExpired
            | Self::TokenRevoked
            | Self::UnknownService
            | Self::UnknownOperation
            | Self::MalformedOperation
            | Self::PermissionMissing
            | Self::ScopeMissing
            | Self::LimitsExceeded
            | Self::Unavailable
            | Self::AuditModeWouldDeny => Decision::Deny,
        }
    }
}

impl std::fmt::Display for DecisionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests;
