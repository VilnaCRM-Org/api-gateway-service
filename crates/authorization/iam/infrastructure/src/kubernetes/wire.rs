//! The JSON of the Kubernetes `EndpointSlice` API and its mapping to the domain types.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use iam_domain::{
    EndpointConditions, EndpointListing, EndpointParts, EndpointSlice, SliceChange,
    UpstreamEndpoint, WatchBatch, Zone,
};
use serde::Deserialize;

/// The HTTP status the API answers when the resource version is too old.
pub(super) const GONE: i64 = 410;

/// The label that names the controller which manages a slice.
pub(super) const MANAGED_BY_LABEL: &str = "endpointslice.kubernetes.io/managed-by";

/// The only controller whose slices are trusted: the one of the cluster, not a tenant's.
pub(super) const MANAGED_BY_VALUE: &str = "endpointslice-controller.k8s.io";

#[derive(Debug, Default, Deserialize)]
struct Metadata {
    #[serde(default)]
    name: String,
    #[serde(default, rename = "resourceVersion")]
    resource_version: String,
    #[serde(default)]
    labels: HashMap<String, String>,
}

#[derive(Debug, Default, Deserialize)]
struct Conditions {
    ready: Option<bool>,
    serving: Option<bool>,
    terminating: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct TargetRef {
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WireEndpoint {
    #[serde(default)]
    addresses: Vec<String>,
    #[serde(default)]
    conditions: Conditions,
    #[serde(default)]
    zone: Option<String>,
    #[serde(default, rename = "targetRef")]
    target_ref: Option<TargetRef>,
}

#[derive(Debug, Deserialize)]
struct WirePort {
    #[serde(default)]
    port: Option<i64>,
}

#[derive(Debug, Default, Deserialize)]
struct WireSlice {
    #[serde(default)]
    metadata: Metadata,
    #[serde(default, rename = "addressType")]
    address_type: String,
    #[serde(default)]
    endpoints: Vec<WireEndpoint>,
    #[serde(default)]
    ports: Vec<WirePort>,
}

#[derive(Debug, Deserialize)]
struct WireList {
    #[serde(default)]
    metadata: Metadata,
    #[serde(default)]
    items: Vec<WireSlice>,
}

#[derive(Debug, Deserialize)]
struct WireEvent {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    object: serde_json::Value,
}

/// What one line of a watch stream says.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum WatchEvent {
    /// A slice changed; the version is the one to resume from.
    Change(SliceChange, String),
    /// Nothing changed; the version is the one to resume from.
    Bookmark(String),
    /// The version is too old.
    Gone,
    /// The API reported a failure.
    Failed(String),
}

/// The listing in a `EndpointSliceList` body.
pub(super) fn parse_list(body: &[u8]) -> Result<EndpointListing, serde_json::Error> {
    let list: WireList = serde_json::from_slice(body)?;
    Ok(EndpointListing {
        resource_version: list.metadata.resource_version,
        slices: list.items.into_iter().map(map_slice).collect(),
    })
}

/// The event of one line of a watch stream.
pub(super) fn parse_event(line: &[u8]) -> Result<WatchEvent, serde_json::Error> {
    let event: WireEvent = serde_json::from_slice(line)?;
    match event.kind.as_str() {
        "ADDED" | "MODIFIED" => slice_event(event.object, false),
        "DELETED" => slice_event(event.object, true),
        "BOOKMARK" => {
            let slice: WireSlice = serde_json::from_value(event.object)?;
            Ok(WatchEvent::Bookmark(slice.metadata.resource_version))
        }
        _ => Ok(failure(&event.object)),
    }
}

fn slice_event(object: serde_json::Value, deleted: bool) -> Result<WatchEvent, serde_json::Error> {
    let slice: WireSlice = serde_json::from_value(object)?;
    let version = slice.metadata.resource_version.clone();
    let change = if deleted {
        SliceChange::Removed(slice.metadata.name)
    } else {
        SliceChange::Upserted(map_slice(slice))
    };
    Ok(WatchEvent::Change(change, version))
}

/// An `ERROR` event holds a `Status` object; code 410 means the version is too old.
fn failure(object: &serde_json::Value) -> WatchEvent {
    let code = object.get("code").and_then(serde_json::Value::as_i64);
    if code == Some(GONE) {
        return WatchEvent::Gone;
    }
    let message = object
        .get("reason")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    WatchEvent::Failed(format!("the watch failed: {message}"))
}

/// The batch that the events of one watch call make.
pub(super) fn batch(resume: &str, events: Vec<WatchEvent>) -> Result<WatchBatch, WatchEvent> {
    let mut batch = WatchBatch {
        resource_version: resume.to_owned(),
        changes: Vec::new(),
    };
    for event in events {
        match event {
            WatchEvent::Change(change, version) => {
                batch.changes.push(change);
                keep_version(&mut batch.resource_version, version);
            }
            WatchEvent::Bookmark(version) => keep_version(&mut batch.resource_version, version),
            stop @ (WatchEvent::Gone | WatchEvent::Failed(_)) => return Err(stop),
        }
    }
    Ok(batch)
}

fn keep_version(current: &mut String, version: String) {
    if !version.is_empty() {
        *current = version;
    }
}

/// Whether the cluster's own controller manages `slice`.
fn is_managed(slice: &WireSlice) -> bool {
    slice
        .metadata
        .labels
        .get(MANAGED_BY_LABEL)
        .is_some_and(|value| value == MANAGED_BY_VALUE)
}

/// The family of an `addressType` the gateway accepts; `FQDN` and anything else is refused.
fn address_family(address_type: &str) -> Option<AddressFamily> {
    match address_type {
        "IPv4" => Some(AddressFamily::V4),
        "IPv6" => Some(AddressFamily::V6),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressFamily {
    V4,
    V6,
}

/// Whether `address` is a unicast address of `family` that an upstream may have: it parses as an
/// IP address (a host name never does), and is not loopback, link-local, unspecified or multicast.
fn is_routable(address: &str, family: AddressFamily) -> bool {
    match (address.parse::<IpAddr>(), family) {
        (Ok(IpAddr::V4(ip)), AddressFamily::V4) => is_routable_v4(ip),
        (Ok(IpAddr::V6(ip)), AddressFamily::V6) => is_routable_v6(ip),
        _ => false,
    }
}

const fn is_routable_v4(ip: Ipv4Addr) -> bool {
    !(ip.is_loopback() || ip.is_link_local() || ip.is_unspecified() || ip.is_multicast())
}

fn is_routable_v6(ip: Ipv6Addr) -> bool {
    let link_local = ip
        .segments()
        .first()
        .is_some_and(|first| first & 0xffc0 == 0xfe80);
    // An IPv4-mapped address could hide a loopback or link-local IPv4 address, so it is refused.
    ip.to_ipv4_mapped().is_none()
        && !(ip.is_loopback() || link_local || ip.is_unspecified() || ip.is_multicast())
}

fn map_slice(slice: WireSlice) -> EndpointSlice {
    let family = address_family(&slice.address_type);
    let port = slice
        .ports
        .iter()
        .find_map(|port| port.port.and_then(|value| u16::try_from(value).ok()));
    let trusted = family.filter(|_| is_managed(&slice));
    let endpoints = match (port, trusted) {
        (Some(port), Some(family)) => slice
            .endpoints
            .iter()
            .flat_map(|endpoint| map_endpoint(endpoint, port, family))
            .collect(),
        _ => Vec::new(),
    };
    EndpointSlice {
        name: slice.metadata.name,
        endpoints,
    }
}

fn map_endpoint(
    endpoint: &WireEndpoint,
    port: u16,
    family: AddressFamily,
) -> Vec<UpstreamEndpoint> {
    let ready = endpoint.conditions.ready.unwrap_or(true);
    let conditions = EndpointConditions::default()
        .with(iam_domain::Condition::Ready, ready)
        .with(
            iam_domain::Condition::Serving,
            endpoint.conditions.serving.unwrap_or(ready),
        )
        .with(
            iam_domain::Condition::Terminating,
            endpoint.conditions.terminating.unwrap_or(false),
        );
    let zone = endpoint
        .zone
        .as_deref()
        .and_then(|zone| Zone::new(zone).ok());
    let pod = endpoint
        .target_ref
        .as_ref()
        .and_then(|target| target.name.clone());
    endpoint
        .addresses
        .iter()
        .filter(|address| is_routable(address, family))
        .map(|address| {
            UpstreamEndpoint::new(EndpointParts {
                address: address.clone(),
                port,
                zone: zone.clone(),
                pod: pod.clone(),
                conditions,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests;
