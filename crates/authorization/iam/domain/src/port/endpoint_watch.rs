//! The endpoint discovery port (board name `EndpointWatch`).
//!
//! A watched Service has one or more `EndpointSlices`. The port lists them with a resource version
//! and then follows their changes from that version, so the application keeps a current set of
//! endpoints per Service without polling (FR-87).

use shared_domain::BoxError;

use crate::endpoint::UpstreamEndpoint;

/// A Service whose endpoints are watched: an upstream Service or the gateway peers Service.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WatchTarget {
    /// The Kubernetes namespace.
    pub namespace: String,
    /// The Kubernetes Service name.
    pub service: String,
}

impl WatchTarget {
    /// The fully qualified DNS name of the Service, with the trailing dot that stops the resolver
    /// from walking its search list: the fallback when no endpoint is known.
    #[must_use]
    pub fn fully_qualified_name(&self) -> String {
        format!("{}.{}.svc.cluster.local.", self.service, self.namespace)
    }
}

impl std::fmt::Display for WatchTarget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}/{}", self.namespace, self.service)
    }
}

/// One `EndpointSlice`: a name and the endpoints it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointSlice {
    /// The name of the slice, unique within the Service.
    pub name: String,
    /// The endpoints of the slice.
    pub endpoints: Vec<UpstreamEndpoint>,
}

/// Every slice of a Service at one resource version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointListing {
    /// The version to resume the watch from.
    pub resource_version: String,
    /// The slices of the Service.
    pub slices: Vec<EndpointSlice>,
}

/// A change of one slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SliceChange {
    /// The slice was added or changed: these are all of its endpoints now.
    Upserted(EndpointSlice),
    /// The slice, named so, was deleted.
    Removed(String),
}

/// The changes one watch call returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchBatch {
    /// The version to resume the next watch from.
    pub resource_version: String,
    /// The changes, oldest first; empty when the watch ended without an event.
    pub changes: Vec<SliceChange>,
}

/// A watch call failed.
#[derive(Debug, thiserror::Error)]
pub enum EndpointWatchError {
    /// The resource version is too old (HTTP 410): list again.
    #[error("the watch resource version expired")]
    Expired,
    /// The source cannot be reached, answered with a failure or sent unusable data: retry from the
    /// same version.
    #[error("the endpoint source is unavailable")]
    Unavailable(#[source] BoxError),
}

/// Lists and watches the endpoints of Services.
#[async_trait::async_trait]
pub trait EndpointWatch: std::fmt::Debug + Send + Sync {
    /// Every slice of `target` and the version to watch from.
    ///
    /// # Errors
    ///
    /// [`EndpointWatchError::Unavailable`] when the source fails.
    async fn list(&self, target: &WatchTarget) -> Result<EndpointListing, EndpointWatchError>;

    /// The changes of `target` after `resource_version`: it returns once at least one event
    /// arrived or the source ended the watch (an empty batch).
    ///
    /// # Errors
    ///
    /// [`EndpointWatchError::Expired`] when the version is too old and
    /// [`EndpointWatchError::Unavailable`] when the connection drops or the source fails.
    async fn watch(
        &self,
        target: &WatchTarget,
        resource_version: &str,
    ) -> Result<WatchBatch, EndpointWatchError>;
}

#[cfg(test)]
mod tests;
