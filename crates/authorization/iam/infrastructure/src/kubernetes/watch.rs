//! `KubernetesEndpointWatch`: the `EndpointWatch` adapter over the Kubernetes API.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header::{ACCEPT, AUTHORIZATION};
use http::{Method, Request, StatusCode, Uri};
use http_body_util::{BodyExt as _, Empty};
use hyper::body::Incoming;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use iam_domain::{EndpointListing, EndpointWatch, EndpointWatchError, WatchBatch, WatchTarget};
use rustls::crypto::aws_lc_rs::default_provider;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject as _;
use shared_domain::BoxError;

use super::wire::{self, WatchEvent};

/// The in-cluster address of the Kubernetes API.
const IN_CLUSTER_API: &str = "https://kubernetes.default.svc";

/// Where Kubernetes mounts the token of the `ServiceAccount` of a pod.
const IN_CLUSTER_TOKEN_FILE: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";

/// Where Kubernetes mounts the certificate authority of the API server in a pod.
const IN_CLUSTER_CA_FILE: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";

/// How long the API holds a watch open before it ends the stream.
const DEFAULT_WATCH_TIMEOUT: Duration = Duration::from_secs(300);

/// The API group and version that serve `EndpointSlices`.
const SLICES_PATH: &str = "apis/discovery.k8s.io/v1";

type Connector = HttpsConnector<HttpConnector>;

/// Where the adapter reaches the Kubernetes API and how it authenticates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KubernetesSettings {
    /// The base URL of the API, such as `https://kubernetes.default.svc`.
    pub api_base: String,
    /// The file with the bearer token, read on every request because Kubernetes rotates it; `None`
    /// sends no token.
    pub token_file: Option<PathBuf>,
    /// The PEM file with the certificate authority of the API server; `None` trusts no authority,
    /// which only a plain `http://` base can use.
    pub ca_file: Option<PathBuf>,
    /// The `timeoutSeconds` of a watch request.
    pub watch_timeout: Duration,
}

impl KubernetesSettings {
    /// The settings of a pod: the cluster-internal API address with the mounted `ServiceAccount`
    /// token and certificate authority.
    #[must_use]
    pub fn in_cluster() -> Self {
        Self {
            api_base: IN_CLUSTER_API.to_owned(),
            token_file: Some(PathBuf::from(IN_CLUSTER_TOKEN_FILE)),
            ca_file: Some(PathBuf::from(IN_CLUSTER_CA_FILE)),
            watch_timeout: DEFAULT_WATCH_TIMEOUT,
        }
    }
}

/// The adapter could not be built.
#[derive(Debug, thiserror::Error)]
pub enum KubernetesSetupError {
    /// The certificate authority file cannot be read or holds no usable certificate.
    #[error("the Kubernetes certificate authority file is unusable: {0}")]
    CertificateAuthority(String),
    /// The TLS client configuration cannot be built.
    #[error("the TLS client configuration is invalid")]
    Tls(#[source] rustls::Error),
    /// The API base is not an `http://` or `https://` URL.
    #[error("the Kubernetes API base is not an http or https URL")]
    ApiBase,
}

/// Lists and watches `EndpointSlices` through the Kubernetes API.
pub struct KubernetesEndpointWatch {
    client: Client<Connector, Empty<Bytes>>,
    api_base: String,
    token_file: Option<PathBuf>,
    watch_timeout: Duration,
}

impl std::fmt::Debug for KubernetesEndpointWatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KubernetesEndpointWatch")
            .field("api_base", &self.api_base)
            .finish_non_exhaustive()
    }
}

impl KubernetesEndpointWatch {
    /// Builds the client: reads the certificate authority now, so that a pod without it does not
    /// start.
    ///
    /// # Errors
    ///
    /// [`KubernetesSetupError`] when the base is not an HTTP URL, the authority file is unusable or
    /// the TLS configuration is invalid.
    pub fn new(settings: &KubernetesSettings) -> Result<Self, KubernetesSetupError> {
        let api_base = settings.api_base.trim_end_matches('/').to_owned();
        if !(api_base.starts_with("https://") || api_base.starts_with("http://")) {
            return Err(KubernetesSetupError::ApiBase);
        }
        let connector = HttpsConnectorBuilder::new()
            .with_tls_config(tls_config(settings.ca_file.as_deref())?)
            .https_or_http()
            .enable_http1()
            .build();
        Ok(Self {
            client: Client::builder(TokioExecutor::new()).build(connector),
            api_base,
            token_file: settings.token_file.clone(),
            watch_timeout: settings.watch_timeout,
        })
    }

    /// The URL of the slices of `target`, with `extra` appended to the query.
    fn url(&self, target: &WatchTarget, extra: &str) -> Result<Uri, BoxError> {
        let namespace = dns_label(&target.namespace)?;
        let service = dns_label(&target.service)?;
        let url = format!(
            "{}/{SLICES_PATH}/namespaces/{namespace}/endpointslices?labelSelector=kubernetes.io%2Fservice-name%3D{service}{extra}",
            self.api_base
        );
        Ok(url.parse()?)
    }

    /// A `GET` request of `uri` with the bearer token, when there is one.
    fn request(&self, uri: Uri) -> Result<Request<Empty<Bytes>>, BoxError> {
        let mut builder = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(ACCEPT, "application/json");
        if let Some(path) = &self.token_file {
            let token = std::fs::read_to_string(path)?;
            builder = builder.header(AUTHORIZATION, format!("Bearer {}", token.trim()));
        }
        Ok(builder.body(Empty::new())?)
    }

    /// Sends a `GET` and returns the response when its status is a success.
    async fn get(&self, uri: Uri) -> Result<http::Response<Incoming>, EndpointWatchError> {
        let request = self.request(uri).map_err(EndpointWatchError::Unavailable)?;
        let response = self
            .client
            .request(request)
            .await
            .map_err(|error| EndpointWatchError::Unavailable(error.into()))?;
        match response.status() {
            status if status.is_success() => Ok(response),
            StatusCode::GONE => Err(EndpointWatchError::Expired),
            status => Err(EndpointWatchError::Unavailable(
                format!("the Kubernetes API answered {status}").into(),
            )),
        }
    }

    async fn list_slices(
        &self,
        target: &WatchTarget,
    ) -> Result<EndpointListing, EndpointWatchError> {
        let uri = self
            .url(target, "")
            .map_err(EndpointWatchError::Unavailable)?;
        let response = self.get(uri).await?;
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|error| EndpointWatchError::Unavailable(error.into()))?
            .to_bytes();
        wire::parse_list(&body).map_err(|error| EndpointWatchError::Unavailable(error.into()))
    }

    async fn watch_slices(
        &self,
        target: &WatchTarget,
        resource_version: &str,
    ) -> Result<WatchBatch, EndpointWatchError> {
        let extra = format!(
            "&watch=true&allowWatchBookmarks=true&timeoutSeconds={}&resourceVersion={}",
            self.watch_timeout.as_secs(),
            encode_version(resource_version)
        );
        let uri = self
            .url(target, &extra)
            .map_err(EndpointWatchError::Unavailable)?;
        let response = self.get(uri).await?;
        let lines = read_lines(response.into_body())
            .await
            .map_err(EndpointWatchError::Unavailable)?;
        let events = lines
            .iter()
            .map(|line| wire::parse_event(line))
            .collect::<Result<Vec<WatchEvent>, _>>()
            .map_err(|error| EndpointWatchError::Unavailable(error.into()))?;
        wire::batch(resource_version, events).map_err(|stop| match stop {
            WatchEvent::Failed(message) => EndpointWatchError::Unavailable(message.into()),
            WatchEvent::Change(..) | WatchEvent::Bookmark(_) | WatchEvent::Gone => {
                EndpointWatchError::Expired
            }
        })
    }
}

#[async_trait::async_trait]
impl EndpointWatch for KubernetesEndpointWatch {
    async fn list(&self, target: &WatchTarget) -> Result<EndpointListing, EndpointWatchError> {
        self.list_slices(target).await
    }

    async fn watch(
        &self,
        target: &WatchTarget,
        resource_version: &str,
    ) -> Result<WatchBatch, EndpointWatchError> {
        self.watch_slices(target, resource_version).await
    }
}

/// `text` when it is a lower-case DNS label or name, so that it cannot add a path segment or a
/// query parameter.
fn dns_label(text: &str) -> Result<&str, &'static str> {
    let valid = !text.is_empty()
        && text.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        });
    if valid {
        Ok(text)
    } else {
        Err("the watch target is not a DNS label")
    }
}

/// A resource version is an opaque string of digits in practice; anything else is percent-encoded
/// so that it cannot add a query parameter.
fn encode_version(version: &str) -> String {
    version
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.') {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

/// Reads the body until it holds a complete line, then returns every complete line it holds.
///
/// A stream that ends without a line returns none; a stream that fails returns the lines that
/// arrived before the failure, or the failure when there are none.
async fn read_lines(mut body: Incoming) -> Result<Vec<Vec<u8>>, BoxError> {
    let mut buffer: Vec<u8> = Vec::new();
    loop {
        match body.frame().await {
            Some(Err(error)) if !buffer.contains(&b'\n') => return Err(error.into()),
            None | Some(Err(_)) => break,
            Some(Ok(frame)) => {
                // A frame other than data, such as trailers, adds nothing.
                buffer.extend_from_slice(&frame.into_data().unwrap_or_default());
                if buffer.contains(&b'\n') {
                    break;
                }
            }
        }
    }
    Ok(complete_lines(&buffer))
}

/// The non-empty lines of `buffer` that end with a newline; an unfinished last line is left out.
fn complete_lines(buffer: &[u8]) -> Vec<Vec<u8>> {
    let mut lines: Vec<&[u8]> = buffer.split(|byte| *byte == b'\n').collect();
    lines.pop();
    lines
        .into_iter()
        .filter(|line| !line.is_empty())
        .map(<[u8]>::to_vec)
        .collect()
}

fn tls_config(ca_file: Option<&std::path::Path>) -> Result<ClientConfig, KubernetesSetupError> {
    let mut roots = RootCertStore::empty();
    if let Some(path) = ca_file {
        let pem = std::fs::read(path)
            .map_err(|error| KubernetesSetupError::CertificateAuthority(error.to_string()))?;
        let mut added = 0_usize;
        for certificate in CertificateDer::pem_slice_iter(&pem) {
            let certificate = certificate
                .map_err(|error| KubernetesSetupError::CertificateAuthority(error.to_string()))?;
            roots
                .add(certificate)
                .map_err(|error| KubernetesSetupError::CertificateAuthority(error.to_string()))?;
            added = added.saturating_add(1);
        }
        if added == 0 {
            return Err(KubernetesSetupError::CertificateAuthority(
                "the file holds no certificate".to_owned(),
            ));
        }
    }
    Ok(
        ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(KubernetesSetupError::Tls)?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

#[cfg(test)]
mod tests;
