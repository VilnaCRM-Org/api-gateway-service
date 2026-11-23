//! Endpoint discovery double.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use iam_domain::{
    EndpointListing, EndpointSlice, EndpointWatch, EndpointWatchError, SliceChange,
    UpstreamEndpoint, WatchBatch, WatchTarget,
};

/// The committed development file of upstream endpoints (`UPSTREAM_STATIC_ENDPOINTS_FILE`).
///
/// It lists the compose control plane `app` as the upstream `iam-control`. Tests whose gateway
/// configuration must discover endpoints without a cluster point at it.
pub const DEVELOPMENT_ENDPOINTS_FILE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../config/upstream/dev-static-endpoints.json"
);

#[derive(Debug, Default)]
struct State {
    version: u64,
    slices: BTreeMap<WatchTarget, BTreeMap<String, Vec<UpstreamEndpoint>>>,
    events: Vec<(u64, WatchTarget, SliceChange)>,
    compacted_before: u64,
    failures: u32,
    list_calls: Vec<WatchTarget>,
    watch_calls: Vec<(WatchTarget, String)>,
}

/// An `EndpointWatch` that the test drives.
///
/// It sets and removes slices, expires the history and makes calls fail, and every call it
/// receives is recorded. A watch never waits: it returns the events after the version it is
/// given, or an empty batch.
#[derive(Debug, Default)]
pub struct FakeEndpointWatch(Mutex<State>);

impl FakeEndpointWatch {
    /// A double without slices.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Adds the slice of `target`, or replaces its endpoints, as one event.
    pub fn set_slice(&self, target: &WatchTarget, name: &str, endpoints: Vec<UpstreamEndpoint>) {
        let mut state = self.state();
        state.version = state.version.saturating_add(1);
        let version = state.version;
        state
            .slices
            .entry(target.clone())
            .or_default()
            .insert(name.to_owned(), endpoints.clone());
        let slice = EndpointSlice {
            name: name.to_owned(),
            endpoints,
        };
        state
            .events
            .push((version, target.clone(), SliceChange::Upserted(slice)));
    }

    /// Removes the slice of `target` as one event.
    pub fn remove_slice(&self, target: &WatchTarget, name: &str) {
        let mut state = self.state();
        state.version = state.version.saturating_add(1);
        let version = state.version;
        if let Some(slices) = state.slices.get_mut(target) {
            slices.remove(name);
        }
        state.events.push((
            version,
            target.clone(),
            SliceChange::Removed(name.to_owned()),
        ));
    }

    /// Forgets the history: a watch from an older version expires.
    pub fn expire(&self) {
        let mut state = self.state();
        state.compacted_before = state.version;
        state.events.clear();
    }

    /// The next `count` calls, of either kind, fail as an unavailable source.
    pub fn fail_next(&self, count: u32) {
        self.state().failures = count;
    }

    /// The targets of the `list` calls received, oldest first.
    #[must_use]
    pub fn list_calls(&self) -> Vec<WatchTarget> {
        self.state().list_calls.clone()
    }

    /// The target and the resume version of each `watch` call received, oldest first.
    #[must_use]
    pub fn watch_calls(&self) -> Vec<(WatchTarget, String)> {
        self.state().watch_calls.clone()
    }
}

fn unavailable(reason: &str) -> EndpointWatchError {
    EndpointWatchError::Unavailable(reason.into())
}

/// Counts down a scheduled failure; `true` when this call must fail.
const fn fails(state: &mut State) -> bool {
    let failing = state.failures > 0;
    state.failures = state.failures.saturating_sub(1);
    failing
}

#[async_trait::async_trait]
impl EndpointWatch for FakeEndpointWatch {
    async fn list(&self, target: &WatchTarget) -> Result<EndpointListing, EndpointWatchError> {
        let mut state = self.state();
        state.list_calls.push(target.clone());
        if fails(&mut state) {
            return Err(unavailable("the fake source failed"));
        }
        let slices = state.slices.get(target).map_or_else(Vec::new, |slices| {
            slices
                .iter()
                .map(|(name, endpoints)| EndpointSlice {
                    name: name.clone(),
                    endpoints: endpoints.clone(),
                })
                .collect()
        });
        Ok(EndpointListing {
            resource_version: state.version.to_string(),
            slices,
        })
    }

    async fn watch(
        &self,
        target: &WatchTarget,
        resource_version: &str,
    ) -> Result<WatchBatch, EndpointWatchError> {
        let mut state = self.state();
        state
            .watch_calls
            .push((target.clone(), resource_version.to_owned()));
        if fails(&mut state) {
            return Err(unavailable("the fake source failed"));
        }
        let resume: u64 = resource_version
            .parse()
            .map_err(|_invalid| unavailable("the resource version is not a number"))?;
        if resume < state.compacted_before {
            return Err(EndpointWatchError::Expired);
        }
        let news: Vec<(u64, SliceChange)> = state
            .events
            .iter()
            .filter(|(version, event_target, _change)| *version > resume && event_target == target)
            .map(|(version, _target, change)| (*version, change.clone()))
            .collect();
        drop(state);
        let latest = news.last().map_or(resume, |(version, _change)| *version);
        Ok(WatchBatch {
            resource_version: latest.to_string(),
            changes: news.into_iter().map(|(_version, change)| change).collect(),
        })
    }
}

#[cfg(test)]
mod tests;
