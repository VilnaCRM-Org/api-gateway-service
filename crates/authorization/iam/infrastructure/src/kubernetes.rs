//! Endpoint discovery adapters (FR-87).
//!
//! `KubernetesEndpointWatch` follows the `EndpointSlices` of a Service through the Kubernetes API,
//! and `StaticEndpointWatch` reads a file for compose and the end-to-end suite.
//!
//! The Kubernetes adapter uses a plain hyper client with the `ServiceAccount` token and the
//! in-cluster CA, and sends only `get`, `list` and `watch` requests on `endpointslices`, which is
//! all that its read-only RBAC role grants.

pub mod static_endpoints;
pub mod watch;
mod wire;

pub use static_endpoints::{StaticEndpointWatch, StaticEndpointsError};
pub use watch::{KubernetesEndpointWatch, KubernetesSettings, KubernetesSetupError};
