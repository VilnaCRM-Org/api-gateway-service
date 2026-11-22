//! The projects in which a permission is held.

use std::collections::BTreeSet;

use crate::value_object::assignment_scope::AssignmentScope;
use crate::value_object::identifier::ProjectId;

/// Every project, or a set of projects (empty when the permission is held nowhere).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeSet {
    /// Every project: a global assignment holds the permission.
    All,
    /// Exactly these projects.
    Projects(BTreeSet<ProjectId>),
}

impl Default for ScopeSet {
    fn default() -> Self {
        Self::empty()
    }
}

impl ScopeSet {
    /// No project.
    #[must_use]
    pub const fn empty() -> Self {
        Self::Projects(BTreeSet::new())
    }

    /// This set widened by one assignment scope: a global scope makes it [`ScopeSet::All`].
    #[must_use]
    pub fn with(self, scope: AssignmentScope) -> Self {
        match (self, scope) {
            (Self::All, _) | (Self::Projects(_), AssignmentScope::Global) => Self::All,
            (Self::Projects(mut projects), AssignmentScope::Project(project_id)) => {
                projects.insert(project_id);
                Self::Projects(projects)
            }
        }
    }

    /// The projects both sets cover: [`ScopeSet::All`] is the identity.
    #[must_use]
    pub fn intersect(self, other: &Self) -> Self {
        match (self, other) {
            (Self::All, Self::All) => Self::All,
            (Self::All, Self::Projects(projects)) => Self::Projects(projects.clone()),
            (Self::Projects(projects), Self::All) => Self::Projects(projects),
            (Self::Projects(mut projects), Self::Projects(others)) => {
                projects.retain(|project_id| others.contains(project_id));
                Self::Projects(projects)
            }
        }
    }

    /// Whether the set covers the project.
    #[must_use]
    pub fn covers(&self, project_id: ProjectId) -> bool {
        match self {
            Self::All => true,
            Self::Projects(projects) => projects.contains(&project_id),
        }
    }

    /// Whether the set covers every project.
    #[must_use]
    pub const fn is_all(&self) -> bool {
        matches!(self, Self::All)
    }

    /// Whether the set covers no project.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        match self {
            Self::All => false,
            Self::Projects(projects) => projects.is_empty(),
        }
    }
}

#[cfg(test)]
mod tests;
