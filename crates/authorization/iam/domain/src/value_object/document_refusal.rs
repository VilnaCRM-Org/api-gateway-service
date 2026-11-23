//! Why a GraphQL document is not analysed into coordinates.

use crate::value_object::decision_reason::DecisionReason;

/// The limit of [`DocumentLimits`](crate::DocumentLimits) a document exceeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitKind {
    /// The document is larger than the byte limit.
    Bytes,
    /// The selection sets nest deeper than the depth limit.
    Depth,
    /// The document selects more fields than the coordinate limit.
    Coordinates,
    /// The document has more aliases than the alias limit.
    Aliases,
    /// The document defines more fragments than the fragment limit.
    Fragments,
}

/// A document that yields no coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DocumentRefusal {
    /// The document exceeds a limit; it was refused before resolution.
    #[error("the document exceeds a limit")]
    LimitsExceeded(LimitKind),
    /// The document does not parse, does not validate against the type graph or names a missing
    /// or unknown operation.
    #[error("the operation cannot be read")]
    MalformedOperation,
    /// A selected field is unknown to every active version.
    #[error("the operation selects a field no active version has")]
    UnknownOperation,
}

impl DocumentRefusal {
    /// The reason code of the deny decision.
    #[must_use]
    pub const fn reason(self) -> DecisionReason {
        match self {
            Self::LimitsExceeded(_) => DecisionReason::LimitsExceeded,
            Self::MalformedOperation => DecisionReason::MalformedOperation,
            Self::UnknownOperation => DecisionReason::UnknownOperation,
        }
    }
}

#[cfg(test)]
mod tests;
