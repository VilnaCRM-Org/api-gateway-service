//! `HyperPeerFreshnessClient`: the `PeerFreshnessReader` adapter over a plain hyper client
//! (FR-85, FR-73).
//!
//! It sends one `GET /internal/freshness` to the address and port of a peer taken from the ready
//! endpoints of `iam-gateway-peers`, and reads the published version, the age of the proof and
//! the verdict of the peer from the JSON answer. The call is bounded by a connect timeout here and
//! by the read timeout of the application; a peer that fails, answers other than 200, or sends
//! something unusable reads as `None`.

use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, StatusCode, Uri};
use http_body_util::{BodyExt as _, Empty, Limited};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use iam_domain::{PeerFreshnessReader, PeerObservation, PolicyVersion, UpstreamEndpoint};
use serde::Deserialize;

/// How long the connection to a peer may take.
const CONNECT_TIMEOUT: Duration = Duration::from_millis(400);

/// The longest answer that is read; the report is a few hundred bytes.
const MAX_BODY: usize = 4096;

/// The path of the report of a pod.
const FRESHNESS_PATH: &str = "/internal/freshness";

/// Reads the freshness of one peer pod.
pub struct HyperPeerFreshnessClient {
    client: Client<HttpConnector, Empty<Bytes>>,
}

impl std::fmt::Debug for HyperPeerFreshnessClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HyperPeerFreshnessClient")
            .finish_non_exhaustive()
    }
}

impl Default for HyperPeerFreshnessClient {
    fn default() -> Self {
        Self::new()
    }
}

impl HyperPeerFreshnessClient {
    /// A client that opens plain HTTP connections to the peers.
    #[must_use]
    pub fn new() -> Self {
        let mut connector = HttpConnector::new();
        connector.set_connect_timeout(Some(CONNECT_TIMEOUT));
        connector.set_nodelay(true);
        Self {
            client: Client::builder(TokioExecutor::new()).build(connector),
        }
    }

    async fn fetch(&self, peer: &UpstreamEndpoint) -> Option<PeerObservation> {
        let request = Request::builder()
            .method(Method::GET)
            .uri(peer_uri(peer)?)
            .body(Empty::new())
            .ok()?;
        let response = self.client.request(request).await.ok()?;
        if response.status() != StatusCode::OK {
            return None;
        }
        let body = Limited::new(response.into_body(), MAX_BODY)
            .collect()
            .await
            .ok()?
            .to_bytes();
        parse(&body)
    }
}

/// `http://<address>:<port>/internal/freshness`, with an IPv6 address in brackets.
fn peer_uri(peer: &UpstreamEndpoint) -> Option<Uri> {
    let address = peer.address();
    let host = if address.contains(':') {
        format!("[{address}]")
    } else {
        address.to_owned()
    };
    format!("http://{host}:{}{FRESHNESS_PATH}", peer.port())
        .parse()
        .ok()
}

/// The part of the report of `/internal/freshness` that the comparison reads.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Report {
    version: Option<i64>,
    proof_age_ms: Option<u64>,
    fresh: bool,
}

/// The observation in `body`, `None` when it is not a report.
fn parse(body: &[u8]) -> Option<PeerObservation> {
    let report: Report = serde_json::from_slice(body).ok()?;
    Some(PeerObservation {
        version: report
            .version
            .and_then(|version| PolicyVersion::new(version).ok()),
        fresh: report.fresh,
        proof_age: report.proof_age_ms.map(Duration::from_millis),
    })
}

#[async_trait::async_trait]
impl PeerFreshnessReader for HyperPeerFreshnessClient {
    async fn read(&self, peer: &UpstreamEndpoint) -> Option<PeerObservation> {
        self.fetch(peer).await
    }
}

#[cfg(test)]
mod tests;
