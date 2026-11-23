//! An upstream endpoint with its readiness and zone, and the zone-aware rule that picks one
//! (FR-87).

pub mod selector;
pub mod zone;

use zone::Zone;

/// One condition of an endpoint, as Kubernetes reports it in an `EndpointSlice`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Condition {
    /// The endpoint is ready to receive traffic.
    Ready,
    /// The endpoint can serve traffic, even while it terminates.
    Serving,
    /// The endpoint is shutting down.
    Terminating,
}

impl Condition {
    const fn bit(self) -> u8 {
        match self {
            Self::Ready => 0b001,
            Self::Serving => 0b010,
            Self::Terminating => 0b100,
        }
    }
}

/// The conditions `ready`, `serving` and `terminating` of an endpoint, all off by default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EndpointConditions(u8);

impl EndpointConditions {
    /// The conditions of a healthy endpoint: ready and serving, not terminating.
    #[must_use]
    pub const fn healthy() -> Self {
        Self(Condition::Ready.bit() | Condition::Serving.bit())
    }

    /// The conditions with `condition` switched on or off.
    #[must_use]
    pub const fn with(self, condition: Condition, on: bool) -> Self {
        if on {
            Self(self.0 | condition.bit())
        } else {
            Self(self.0 & !condition.bit())
        }
    }

    /// Whether `condition` is on.
    #[must_use]
    pub const fn has(self, condition: Condition) -> bool {
        self.0 & condition.bit() != 0
    }

    /// Whether the endpoint is ready.
    #[must_use]
    pub const fn ready(self) -> bool {
        self.has(Condition::Ready)
    }

    /// Whether the endpoint is serving.
    #[must_use]
    pub const fn serving(self) -> bool {
        self.has(Condition::Serving)
    }

    /// Whether the endpoint is terminating.
    #[must_use]
    pub const fn terminating(self) -> bool {
        self.has(Condition::Terminating)
    }
}

/// The parts of an [`UpstreamEndpoint`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointParts {
    /// An IP address or a fully qualified DNS name.
    pub address: String,
    /// The port.
    pub port: u16,
    /// The zone, when the slice reports one.
    pub zone: Option<Zone>,
    /// The name of the pod behind the endpoint, when the slice reports one.
    pub pod: Option<String>,
    /// The conditions.
    pub conditions: EndpointConditions,
}

/// One address of an upstream Service (or of the gateway peers Service) with its zone and
/// conditions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamEndpoint {
    address: String,
    port: u16,
    zone: Option<Zone>,
    pod: Option<String>,
    conditions: EndpointConditions,
}

impl UpstreamEndpoint {
    /// An endpoint of the parts.
    #[must_use]
    pub fn new(parts: EndpointParts) -> Self {
        Self {
            address: parts.address,
            port: parts.port,
            zone: parts.zone,
            pod: parts.pod,
            conditions: parts.conditions,
        }
    }

    /// The IP address or the fully qualified DNS name.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    /// The port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// The zone, when known.
    #[must_use]
    pub const fn zone(&self) -> Option<&Zone> {
        self.zone.as_ref()
    }

    /// The name of the pod behind the endpoint, when known.
    #[must_use]
    pub fn pod(&self) -> Option<&str> {
        self.pod.as_deref()
    }

    /// The conditions.
    #[must_use]
    pub const fn conditions(&self) -> EndpointConditions {
        self.conditions
    }

    /// Whether a new request may be sent to the endpoint: it is ready and not terminating.
    #[must_use]
    pub const fn is_offered(&self) -> bool {
        self.conditions.ready() && !self.conditions.terminating()
    }
}

#[cfg(test)]
mod tests;
