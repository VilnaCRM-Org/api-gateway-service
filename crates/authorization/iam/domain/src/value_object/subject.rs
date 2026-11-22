//! The subject of an assignment or a decision: a user or a service principal.

use shared_domain::Uuid;

use crate::error::InvalidIamValue;
use crate::value_object::service_name::ServiceName;

/// Whether a subject is a user or a service principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SubjectKind {
    /// A user of the User service.
    User,
    /// A service principal named by its service name.
    Service,
}

impl SubjectKind {
    /// Parses `user` or `service`.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIamValue::SubjectKind`] for any other text.
    pub fn parse(value: &str) -> Result<Self, InvalidIamValue> {
        match value {
            "user" => Ok(Self::User),
            "service" => Ok(Self::Service),
            _ => Err(InvalidIamValue::SubjectKind),
        }
    }

    /// The text form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Service => "service",
        }
    }
}

/// The id of a subject: a UUID for a user, a service name for a service principal.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SubjectId {
    /// A user id.
    User(Uuid),
    /// A service principal's service name.
    Service(ServiceName),
}

impl SubjectId {
    /// The kind of the subject.
    #[must_use]
    pub const fn kind(&self) -> SubjectKind {
        match self {
            Self::User(_) => SubjectKind::User,
            Self::Service(_) => SubjectKind::Service,
        }
    }
}

impl std::fmt::Display for SubjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::User(id) => std::fmt::Display::fmt(id, f),
            Self::Service(name) => std::fmt::Display::fmt(name, f),
        }
    }
}

/// A validated reference to a subject.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SubjectRef(SubjectId);

impl SubjectRef {
    /// Validates the id against the kind: a UUID for a user, a service name for a service.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIamValue::SubjectUserId`] for a user whose id is not a UUID, and the
    /// [`ServiceName`] errors for a service whose id is not a service name.
    pub fn new(kind: SubjectKind, id: &str) -> Result<Self, InvalidIamValue> {
        match kind {
            SubjectKind::User => Uuid::parse(id)
                .map(Self::user)
                .map_err(|_error| InvalidIamValue::SubjectUserId),
            SubjectKind::Service => ServiceName::new(id).map(Self::service),
        }
    }

    /// A user subject.
    #[must_use]
    pub const fn user(id: Uuid) -> Self {
        Self(SubjectId::User(id))
    }

    /// A service principal.
    #[must_use]
    pub const fn service(name: ServiceName) -> Self {
        Self(SubjectId::Service(name))
    }

    /// The kind of the subject.
    #[must_use]
    pub const fn kind(&self) -> SubjectKind {
        self.0.kind()
    }

    /// The id of the subject.
    #[must_use]
    pub const fn id(&self) -> &SubjectId {
        &self.0
    }
}

impl std::fmt::Display for SubjectRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.kind().as_str(), self.0)
    }
}

#[cfg(test)]
mod tests;
