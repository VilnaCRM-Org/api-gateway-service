//! Who performed an audited action.

use shared_domain::Uuid;

use crate::error::InvalidIamValue;
use crate::value_object::service_name::ServiceName;

/// An IAM component that acts on its own behalf.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SystemComponent {
    /// The `iam-bootstrap` command.
    Bootstrap,
    /// The consumer of User service events.
    UserService,
    /// The startup registration of IAM's own specifications.
    Startup,
    /// The periodic maintenance task that purges expired records and anchors the audit chain.
    Maintenance,
}

impl SystemComponent {
    /// Parses the component name; `None` for any other text.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "bootstrap" => Some(Self::Bootstrap),
            "user-service" => Some(Self::UserService),
            "startup" => Some(Self::Startup),
            "maintenance" => Some(Self::Maintenance),
            _ => None,
        }
    }

    /// The component name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap",
            Self::UserService => "user-service",
            Self::Startup => "startup",
            Self::Maintenance => "maintenance",
        }
    }
}

/// The actor of an audit record, with the stable text forms `user:<uuid>`, `service:<name>` and
/// `system:<component>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ActorRef {
    /// A user.
    User(Uuid),
    /// A service principal.
    Service(ServiceName),
    /// An IAM component.
    System(SystemComponent),
}

impl ActorRef {
    /// Parses the stable text form.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidIamValue::ActorFormat`] for any other text.
    pub fn parse(value: &str) -> Result<Self, InvalidIamValue> {
        let actor = match value.split_once(':') {
            Some(("user", id)) => Uuid::parse(id).ok().map(Self::User),
            Some(("service", name)) => ServiceName::new(name).ok().map(Self::Service),
            Some(("system", component)) => SystemComponent::parse(component).map(Self::System),
            _ => None,
        };
        actor.ok_or(InvalidIamValue::ActorFormat)
    }
}

impl std::fmt::Display for ActorRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::User(id) => write!(f, "user:{id}"),
            Self::Service(name) => write!(f, "service:{name}"),
            Self::System(component) => write!(f, "system:{}", component.as_str()),
        }
    }
}

#[cfg(test)]
mod tests;
