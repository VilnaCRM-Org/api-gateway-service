//! The endpoints the gateway currently knows for every watched Service, and the zone of the
//! gateway pod (FR-87).
//!
//! The [`EndpointDirectory`] is written by the [`EndpointWatcher`](crate::EndpointWatcher) task;
//! request handling reads it through cheap clones of [`EndpointView`], which never wait for the
//! writer.

use std::collections::BTreeMap;
use std::sync::Arc;

use iam_domain::{EndpointSlice, SliceChange, UpstreamEndpoint, WatchTarget, Zone};
use tokio::sync::watch;

type Slices = BTreeMap<String, Vec<UpstreamEndpoint>>;
type Snapshot = BTreeMap<WatchTarget, Slices>;

/// Where the zone of the gateway pod comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneSource {
    /// The `iam-gateway-peers` Service, whose slices list the gateway pods with their zones.
    pub peers: WatchTarget,
    /// The name of this pod (`POD_NAME`), when the downward API provides it.
    pub pod: Option<String>,
    /// `GATEWAY_ZONE`: when set, it is the zone and the peers slices are not consulted.
    pub explicit: Option<Zone>,
}

/// The writer side: the watcher replaces and updates the slices of a Service.
#[derive(Debug)]
pub struct EndpointDirectory {
    current: watch::Sender<Arc<Snapshot>>,
    zone: Arc<ZoneSource>,
}

impl EndpointDirectory {
    /// An empty directory.
    #[must_use]
    pub fn new(zone: ZoneSource) -> Self {
        Self {
            current: watch::channel(Arc::new(Snapshot::new())).0,
            zone: Arc::new(zone),
        }
    }

    /// A reader of the directory.
    #[must_use]
    pub fn view(&self) -> EndpointView {
        EndpointView {
            current: self.current.subscribe(),
            zone: Arc::clone(&self.zone),
        }
    }

    /// Replaces every slice of `target`: the result of a list.
    pub fn replace(&self, target: &WatchTarget, slices: Vec<EndpointSlice>) {
        let slices: Slices = slices
            .into_iter()
            .map(|slice| (slice.name, slice.endpoints))
            .collect();
        self.current.send_modify(|current| {
            Arc::make_mut(current).insert(target.clone(), slices);
        });
    }

    /// Applies one change of a slice of `target`.
    pub fn apply(&self, target: &WatchTarget, change: SliceChange) {
        self.current.send_modify(|current| {
            let slices = Arc::make_mut(current).entry(target.clone()).or_default();
            match change {
                SliceChange::Upserted(slice) => {
                    slices.insert(slice.name, slice.endpoints);
                }
                SliceChange::Removed(name) => {
                    slices.remove(&name);
                }
            }
        });
    }
}

/// The reader side: a cheap clone of it goes to every user of the endpoints.
#[derive(Debug, Clone)]
pub struct EndpointView {
    current: watch::Receiver<Arc<Snapshot>>,
    zone: Arc<ZoneSource>,
}

impl EndpointView {
    fn snapshot(&self) -> Arc<Snapshot> {
        Arc::clone(&self.current.borrow())
    }

    /// Every endpoint of `target`, whatever its conditions.
    #[must_use]
    pub fn endpoints(&self, target: &WatchTarget) -> Vec<UpstreamEndpoint> {
        self.snapshot().get(target).map_or_else(Vec::new, |slices| {
            slices.values().flatten().cloned().collect()
        })
    }

    /// The endpoints of `target` that a new request may go to: ready and not terminating.
    #[must_use]
    pub fn offered(&self, target: &WatchTarget) -> Vec<UpstreamEndpoint> {
        let mut endpoints = self.endpoints(target);
        endpoints.retain(UpstreamEndpoint::is_offered);
        endpoints
    }

    /// The zone of the gateway pod: `GATEWAY_ZONE` when set, otherwise the zone of the pod's own
    /// entry in the peers slices, and `None` while neither is known.
    #[must_use]
    pub fn own_zone(&self) -> Option<Zone> {
        if let Some(zone) = &self.zone.explicit {
            return Some(zone.clone());
        }
        let pod = self.zone.pod.as_deref()?;
        self.endpoints(&self.zone.peers)
            .into_iter()
            .find(|endpoint| endpoint.pod() == Some(pod))
            .and_then(|endpoint| endpoint.zone().cloned())
    }

    /// Waits until the directory changes; `false` when the directory is gone.
    pub async fn changed(&mut self) -> bool {
        self.current.changed().await.is_ok()
    }
}

#[cfg(test)]
mod tests;
