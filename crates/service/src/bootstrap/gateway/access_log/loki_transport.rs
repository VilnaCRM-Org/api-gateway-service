//! The transport of the Loki push sink over hyper (Story 14.2).
//!
//! The sink pushes from its own worker thread, so the transport owns a small runtime and waits for
//! each answer on that thread: the request tasks never wait for Loki. A push is acknowledged only
//! by a 2xx answer within [`PUSH_TIMEOUT`]; a refused connection, a timeout or any other status
//! leaves the batch to be pushed again.

use std::time::Duration;

use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderName, HeaderValue, Method, Request, Uri};
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use iam_infrastructure::LokiTransport;
use tokio::runtime::{Builder, Runtime};

/// The header that names the tenant of a push.
const TENANT_HEADER: HeaderName = HeaderName::from_static("x-scope-orgid");

/// How long a push may take, from the connection to the end of the answer.
pub const PUSH_TIMEOUT: Duration = Duration::from_secs(3);

/// The longest answer of Loki that is read; an acknowledgement has no body.
const MAX_ANSWER: usize = 16 * 1_024;

/// Posts push requests to one Loki endpoint.
pub struct HyperLokiTransport {
    runtime: Runtime,
    client: Client<HttpConnector, Full<Bytes>>,
    uri: Uri,
    tenant: HeaderValue,
}

impl std::fmt::Debug for HyperLokiTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HyperLokiTransport")
            .field("uri", &self.uri)
            .finish_non_exhaustive()
    }
}

impl HyperLokiTransport {
    /// A transport that posts to `uri` for `tenant`.
    ///
    /// # Errors
    ///
    /// The error of the operating system when the runtime cannot be built, or an invalid-input
    /// error when `tenant` cannot be a header value.
    pub fn new(uri: Uri, tenant: &str) -> std::io::Result<Self> {
        let tenant = HeaderValue::from_str(tenant)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
        let runtime = Builder::new_current_thread().enable_all().build()?;
        let mut connector = HttpConnector::new();
        connector.set_connect_timeout(Some(PUSH_TIMEOUT));
        let client = Client::builder(TokioExecutor::new()).build(connector);
        Ok(Self {
            runtime,
            client,
            uri,
            tenant,
        })
    }

    /// Whether Loki answered the push with a success status.
    async fn post(&self, body: &str) -> bool {
        let mut request = Request::new(Full::new(Bytes::from(body.to_owned())));
        *request.method_mut() = Method::POST;
        *request.uri_mut() = self.uri.clone();
        request
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        request
            .headers_mut()
            .insert(TENANT_HEADER, self.tenant.clone());
        let Ok(response) = self.client.request(request).await else {
            return false;
        };
        let success = response.status().is_success();
        let drained = Limited::new(response.into_body(), MAX_ANSWER)
            .collect()
            .await
            .is_ok();
        success && drained
    }
}

impl LokiTransport for HyperLokiTransport {
    fn push(&self, body: &str) -> bool {
        self.runtime
            .block_on(async { tokio::time::timeout(PUSH_TIMEOUT, self.post(body)).await })
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests;
