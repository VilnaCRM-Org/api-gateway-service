//! `StaticEndpointWatch`: the `EndpointWatch` adapter over a JSON file (`UPSTREAM_STATIC_ENDPOINTS_FILE`),
//! for compose and the end-to-end suite.
//!
//! The file maps a Service name to its endpoints:
//!
//! ```json
//! {"user-service": [{"address": "user-service", "port": 8081, "zone": "zone-a"}]}
//! ```
//!
//! `ready` and `serving` default to `true`, `terminating` to `false`. The file is read again on
//! every call, so a change of the file is a watch event; its version is the digest of its content.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use iam_domain::{
    Condition, EndpointConditions, EndpointListing, EndpointParts, EndpointSlice, EndpointWatch,
    EndpointWatchError, SliceChange, UpstreamEndpoint, WatchBatch, WatchTarget, Zone,
};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

/// The digits of a hexadecimal number.
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// The name of the only slice of a Service in the file.
const SLICE_NAME: &str = "static";

/// The file cannot be used.
#[derive(Debug, thiserror::Error)]
pub enum StaticEndpointsError {
    /// The file cannot be read.
    #[error("the static endpoints file cannot be read")]
    Read(#[source] std::io::Error),
    /// The file is not the expected JSON.
    #[error("the static endpoints file is not valid: {0}")]
    Parse(#[source] serde_json::Error),
    /// An entry holds a value that cannot be an endpoint.
    #[error("the static endpoints of {service} hold an invalid entry: {reason}")]
    Entry {
        /// The Service the entry belongs to.
        service: String,
        /// What is wrong with it.
        reason: &'static str,
    },
}

#[derive(Debug, Deserialize)]
struct FileEndpoint {
    address: String,
    port: u16,
    #[serde(default)]
    zone: Option<String>,
    #[serde(default)]
    pod: Option<String>,
    #[serde(default)]
    ready: Option<bool>,
    #[serde(default)]
    serving: Option<bool>,
    #[serde(default)]
    terminating: Option<bool>,
}

/// The endpoints of every Service of the file and the version of its content.
struct Content {
    version: String,
    services: BTreeMap<String, Vec<UpstreamEndpoint>>,
}

/// Reads the endpoints of the Services from a file.
#[derive(Debug, Clone)]
pub struct StaticEndpointWatch {
    path: PathBuf,
}

impl StaticEndpointWatch {
    /// An adapter over `path`; the file is read and checked now, so that a gateway with a
    /// missing or unparsable file does not start.
    ///
    /// # Errors
    ///
    /// [`StaticEndpointsError`] when the file cannot be read or holds an invalid entry.
    pub fn new(path: &Path) -> Result<Self, StaticEndpointsError> {
        let watch = Self {
            path: path.to_path_buf(),
        };
        watch.read()?;
        Ok(watch)
    }

    /// The names of the Services the file lists.
    ///
    /// # Errors
    ///
    /// [`StaticEndpointsError`] when the file cannot be read or holds an invalid entry.
    pub fn services(&self) -> Result<Vec<String>, StaticEndpointsError> {
        Ok(self.read()?.services.into_keys().collect())
    }

    fn read(&self) -> Result<Content, StaticEndpointsError> {
        let bytes = std::fs::read(&self.path).map_err(StaticEndpointsError::Read)?;
        let raw: BTreeMap<String, Vec<FileEndpoint>> =
            serde_json::from_slice(&bytes).map_err(StaticEndpointsError::Parse)?;
        let mut services = BTreeMap::new();
        for (service, entries) in raw {
            let endpoints = entries
                .into_iter()
                .map(|entry| endpoint(&service, entry))
                .collect::<Result<Vec<_>, _>>()?;
            services.insert(service, endpoints);
        }
        Ok(Content {
            version: digest(&bytes),
            services,
        })
    }

    fn slice(content: &Content, target: &WatchTarget) -> Option<EndpointSlice> {
        content
            .services
            .get(&target.service)
            .map(|endpoints| EndpointSlice {
                name: SLICE_NAME.to_owned(),
                endpoints: endpoints.clone(),
            })
    }
}

fn endpoint(service: &str, entry: FileEndpoint) -> Result<UpstreamEndpoint, StaticEndpointsError> {
    let invalid = |reason| StaticEndpointsError::Entry {
        service: service.to_owned(),
        reason,
    };
    if entry.address.is_empty() {
        return Err(invalid("the address is empty"));
    }
    let zone = entry
        .zone
        .as_deref()
        .map(Zone::new)
        .transpose()
        .map_err(|_invalid_zone| invalid("the zone is not a valid zone label"))?;
    let conditions = EndpointConditions::default()
        .with(Condition::Ready, entry.ready.unwrap_or(true))
        .with(Condition::Serving, entry.serving.unwrap_or(true))
        .with(Condition::Terminating, entry.terminating.unwrap_or(false));
    Ok(UpstreamEndpoint::new(EndpointParts {
        address: entry.address,
        port: entry.port,
        zone,
        pod: entry.pod,
        conditions,
    }))
}

/// The lower-case hexadecimal SHA-256 digest of `bytes`.
fn digest(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        hex.push(nibble(byte / 16));
        hex.push(nibble(byte % 16));
    }
    hex
}

fn nibble(value: u8) -> char {
    HEX_DIGITS
        .get(usize::from(value))
        .copied()
        .map_or('0', char::from)
}

fn unavailable(error: StaticEndpointsError) -> EndpointWatchError {
    EndpointWatchError::Unavailable(error.into())
}

#[async_trait::async_trait]
impl EndpointWatch for StaticEndpointWatch {
    async fn list(&self, target: &WatchTarget) -> Result<EndpointListing, EndpointWatchError> {
        let content = self.read().map_err(unavailable)?;
        Ok(EndpointListing {
            slices: Self::slice(&content, target).into_iter().collect(),
            resource_version: content.version,
        })
    }

    async fn watch(
        &self,
        target: &WatchTarget,
        resource_version: &str,
    ) -> Result<WatchBatch, EndpointWatchError> {
        let content = self.read().map_err(unavailable)?;
        if content.version == resource_version {
            return Ok(WatchBatch {
                resource_version: content.version,
                changes: Vec::new(),
            });
        }
        let change = Self::slice(&content, target).map_or_else(
            || SliceChange::Removed(SLICE_NAME.to_owned()),
            SliceChange::Upserted,
        );
        Ok(WatchBatch {
            resource_version: content.version,
            changes: vec![change],
        })
    }
}

#[cfg(test)]
mod tests;
