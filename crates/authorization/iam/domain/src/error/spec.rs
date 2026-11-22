//! Domain errors of the specification aggregates (`GraphQlSpec`, later `OpenApiSpec`).

use crate::value_object::spec_status::SpecStatus;

/// Where a fault sits in a specification document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecPosition {
    /// A line and a column, both counted from 1, as a GraphQL SDL parser reports them.
    LineColumn {
        /// The line, from 1.
        line: u32,
        /// The column, from 1.
        column: u32,
    },
    /// A JSON pointer (RFC 6901), as the `OpenAPI` document parser reports it.
    JsonPointer(String),
}

impl std::fmt::Display for SpecPosition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LineColumn { line, column } => write!(f, "line {line}, column {column}"),
            Self::JsonPointer(pointer) => write!(f, "pointer {pointer}"),
        }
    }
}

/// A specification document that cannot become a version: too large, over a limit, malformed or
/// with a field defined twice.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvalidSpec {
    /// The document is larger than the byte limit; checked before parsing starts.
    #[error("The document must be at most {limit} bytes.")]
    TooLarge {
        /// The largest number of bytes.
        limit: usize,
    },
    /// The document defines more types than the limit.
    #[error("The document must define {limit} types or fewer.")]
    TooManyTypes {
        /// The largest number of types.
        limit: usize,
    },
    /// The document defines more fields than the limit.
    #[error("The document must define {limit} fields or fewer.")]
    TooManyFields {
        /// The largest number of fields.
        limit: usize,
    },
    /// The parser refused the document at a position.
    #[error("{message} ({position})")]
    Malformed {
        /// What the parser reported.
        message: String,
        /// Where the fault sits.
        position: SpecPosition,
    },
    /// A field coordinate is defined twice.
    #[error("The field {coordinate} is defined more than once.")]
    DuplicateField {
        /// The `{Type}.{field}` coordinate.
        coordinate: String,
    },
}

impl InvalidSpec {
    /// The property that carries the invalid document: `document` for a fault located by a JSON
    /// pointer (an `OpenAPI` document), `sdl` for every other one.
    #[must_use]
    pub const fn property_path(&self) -> &'static str {
        match self {
            Self::Malformed {
                position: SpecPosition::JsonPointer(_),
                ..
            } => "document",
            Self::TooLarge { .. }
            | Self::TooManyTypes { .. }
            | Self::TooManyFields { .. }
            | Self::Malformed { .. }
            | Self::DuplicateField { .. } => "sdl",
        }
    }

    /// The machine-readable violation code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::TooLarge { .. } => "length",
            Self::TooManyTypes { .. } | Self::TooManyFields { .. } => "count",
            Self::Malformed { .. } => "syntax",
            Self::DuplicateField { .. } => "duplicate",
        }
    }

    /// Where the fault sits, when the parser located it.
    #[must_use]
    pub const fn position(&self) -> Option<&SpecPosition> {
        match self {
            Self::Malformed { position, .. } => Some(position),
            Self::TooLarge { .. }
            | Self::TooManyTypes { .. }
            | Self::TooManyFields { .. }
            | Self::DuplicateField { .. } => None,
        }
    }
}

/// A specification version refuses a status transition: only `draft` to `active` and `active` to
/// `retired` exist; the application answers 409.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("A {} specification version cannot become {}.", from.as_str(), to.as_str())]
pub struct SpecTransitionRefused {
    /// The status of the version.
    pub from: SpecStatus,
    /// The status the transition asked for.
    pub to: SpecStatus,
}

impl SpecTransitionRefused {
    /// The machine-readable refusal code.
    pub const CODE: &'static str = "status_transition";
    /// The property that carries the refused status.
    pub const PROPERTY_PATH: &'static str = "status";
}

#[cfg(test)]
mod tests;
