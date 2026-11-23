//! The endpoint discovery of the gateway: the adapter that `UPSTREAM_DISCOVERY` selects, the
//! directory that the `EndpointWatcher` task fills and the Services it watches (FR-87).

use std::path::Path;
use std::sync::Arc;

use iam_application::{EndpointDirectory, ZoneSource};
use iam_domain::{EndpointWatch, WatchTarget};
use iam_infrastructure::{
    KubernetesEndpointWatch, KubernetesSettings, KubernetesSetupError, StaticEndpointWatch,
    StaticEndpointsError,
};

use crate::config::{GatewayConfig, UpstreamDiscovery};

/// The Service whose `EndpointSlices` list the gateway pods with their zones.
pub const PEERS_SERVICE: &str = "iam-gateway-peers";

/// The namespace of the peers Service when `POD_NAMESPACE` is not set.
const DEFAULT_NAMESPACE: &str = "default";

/// The endpoint discovery cannot be set up.
#[derive(Debug, thiserror::Error)]
pub enum EndpointSetupError {
    /// The static endpoints file cannot be used.
    #[error("the upstream endpoints file cannot be used")]
    Static(#[from] StaticEndpointsError),
    /// The Kubernetes client cannot be built.
    #[error("the Kubernetes endpoint watch cannot be built")]
    Kubernetes(#[from] KubernetesSetupError),
}

/// The ports and state of the endpoint discovery.
pub struct EndpointAdapters {
    /// Lists and watches the endpoints of a Service.
    pub watch: Arc<dyn EndpointWatch>,
    /// The endpoints the watcher published, and the zone of this pod.
    pub directory: Arc<EndpointDirectory>,
    /// The Services the `EndpointWatcher` task follows.
    pub targets: Vec<WatchTarget>,
}

impl std::fmt::Debug for EndpointAdapters {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EndpointAdapters")
            .field("watch", &self.watch)
            .field("targets", &self.targets)
            .finish_non_exhaustive()
    }
}

impl EndpointAdapters {
    /// Wires the adapter of `UPSTREAM_DISCOVERY`: the static file is read now, and the Kubernetes
    /// client reads its certificate authority now, so that a gateway that cannot discover
    /// endpoints does not start.
    ///
    /// # Errors
    ///
    /// [`EndpointSetupError`] when the file or the client cannot be set up.
    pub fn from_config(config: &GatewayConfig) -> Result<Self, EndpointSetupError> {
        let peers = peers_target(config);
        let (watch, targets) = match &config.endpoints.discovery {
            UpstreamDiscovery::Static(file) => static_source(file, &peers)?,
            UpstreamDiscovery::Kubernetes => {
                kubernetes_source(&KubernetesSettings::in_cluster(), config, &peers)?
            }
        };
        let directory = EndpointDirectory::new(ZoneSource {
            peers,
            pod: config.pod_name.clone(),
            explicit: config.endpoints.zone.clone(),
        });
        Ok(Self {
            watch,
            directory: Arc::new(directory),
            targets,
        })
    }
}

type Source = (Arc<dyn EndpointWatch>, Vec<WatchTarget>);

/// The static adapter and every Service of its file, in the namespace of the peers Service.
fn static_source(file: &Path, peers: &WatchTarget) -> Result<Source, EndpointSetupError> {
    let watch = StaticEndpointWatch::new(file)?;
    let targets = watch
        .services()?
        .into_iter()
        .map(|service| WatchTarget {
            namespace: peers.namespace.clone(),
            service,
        })
        .collect();
    let watch: Arc<dyn EndpointWatch> = Arc::new(watch);
    Ok((watch, targets))
}

/// The Kubernetes adapter of `settings`, the in-cluster ones in production, and the Services it
/// watches.
fn kubernetes_source(
    settings: &KubernetesSettings,
    config: &GatewayConfig,
    peers: &WatchTarget,
) -> Result<Source, EndpointSetupError> {
    let watch = KubernetesEndpointWatch::new(settings)?;
    let watch: Arc<dyn EndpointWatch> = Arc::new(watch);
    Ok((watch, kubernetes_targets(config, peers)))
}

/// The peers Service of the namespace of this pod.
fn peers_target(config: &GatewayConfig) -> WatchTarget {
    WatchTarget {
        namespace: config
            .pod_namespace
            .clone()
            .unwrap_or_else(|| DEFAULT_NAMESPACE.to_owned()),
        service: PEERS_SERVICE.to_owned(),
    }
}

/// The Services to watch under Kubernetes discovery: the peers Service, but only when the zone of
/// the pod must come from it (no `GATEWAY_ZONE`) and the pod knows its own name and namespace.
/// The upstream Services are added with the snapshot of the routes.
fn kubernetes_targets(config: &GatewayConfig, peers: &WatchTarget) -> Vec<WatchTarget> {
    let identified = config.pod_name.is_some() && config.pod_namespace.is_some();
    if identified && config.endpoints.zone.is_none() {
        vec![peers.clone()]
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests;
