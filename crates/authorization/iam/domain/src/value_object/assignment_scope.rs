//! Where an assignment applies.

use crate::error::InvalidIamValue;
use crate::value_object::identifier::ProjectId;

/// The scope of an assignment: every project, or one project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AssignmentScope {
    /// Every project.
    Global,
    /// One project.
    Project(ProjectId),
}

impl AssignmentScope {
    /// Builds the scope from its kind (`global` or `project`) and an optional project id.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIamValue::ScopeKind`] for an unknown kind,
    /// [`InvalidIamValue::ScopeProjectMissing`] for a project scope without a project id and
    /// [`InvalidIamValue::ScopeProjectUnexpected`] for a global scope with one.
    pub fn from_parts(kind: &str, project_id: Option<ProjectId>) -> Result<Self, InvalidIamValue> {
        match (kind, project_id) {
            ("global", None) => Ok(Self::Global),
            ("global", Some(_)) => Err(InvalidIamValue::ScopeProjectUnexpected),
            ("project", Some(project_id)) => Ok(Self::Project(project_id)),
            ("project", None) => Err(InvalidIamValue::ScopeProjectMissing),
            _ => Err(InvalidIamValue::ScopeKind),
        }
    }

    /// The kind: `global` or `project`.
    #[must_use]
    pub const fn kind(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Project(_) => "project",
        }
    }

    /// The project of a project scope.
    #[must_use]
    pub const fn project_id(self) -> Option<ProjectId> {
        match self {
            Self::Global => None,
            Self::Project(project_id) => Some(project_id),
        }
    }

    /// Parses the stable text form `global` or `project:<uuid>`.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIamValue::ScopeKind`] for any other kind and [`InvalidIamValue::Identifier`]
    /// when the project id is not a UUID.
    pub fn parse(value: &str) -> Result<Self, InvalidIamValue> {
        match value.split_once(':') {
            None if value == "global" => Ok(Self::Global),
            Some(("project", project_id)) => ProjectId::parse(project_id).map(Self::Project),
            _ => Err(InvalidIamValue::ScopeKind),
        }
    }
}

impl std::fmt::Display for AssignmentScope {
    /// The stable text form: `global` or `project:<uuid>`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Global => f.write_str("global"),
            Self::Project(project_id) => write!(f, "project:{project_id}"),
        }
    }
}

#[cfg(test)]
mod tests;
