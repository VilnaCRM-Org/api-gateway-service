//! The reading side of the audit lane: the hyper transport of the Loki queries and the wiring of
//! the adapter that reads access decisions (Story 14.3).
//!
//! The transport bounds each call (connection, answer and body) by `ACCESS_LOG_QUERY_TIMEOUT`: a
//! call that takes longer is a timeout, which the use case turns into 504 and never into a
//! partial page; a refused connection or a broken answer is unavailability, which becomes 503.

use std::sync::Arc;
use std::time::Duration;

use axum::http::header::InvalidHeaderValue;
use axum::http::{HeaderName, HeaderValue, Method, Request, Uri};
use http_body_util::{BodyExt as _, Empty, Limited};
use hyper::body::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use iam_domain::{AccessLogQuery, AccessLogQueryError};
use iam_infrastructure::{LokiAccessLogQuery, LokiQueryTransport, LokiResponse};

use super::gateway::access_log::LOKI_APP_LABEL;
use crate::config::{AccessLogQuerySettings, AppEnv, env_label};

/// The header that names the tenant of a query.
const TENANT_HEADER: HeaderName = HeaderName::from_static("x-scope-orgid");

/// The longest answer that is read: a page of 500 decisions with the entries that a cursor skips
/// stays far below it.
const MAX_ANSWER: usize = 32 * 1_024 * 1_024;

/// Gets URLs from one Loki for one tenant.
pub struct HyperLokiQueryTransport {
    client: Client<HttpConnector, Empty<Bytes>>,
    tenant: HeaderValue,
    timeout: Duration,
}

impl std::fmt::Debug for HyperLokiQueryTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HyperLokiQueryTransport")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl HyperLokiQueryTransport {
    /// A transport for `tenant` whose calls take at most `timeout`.
    ///
    /// # Errors
    ///
    /// [`InvalidHeaderValue`] when `tenant` cannot be a header value.
    pub fn new(tenant: &str, timeout: Duration) -> Result<Self, InvalidHeaderValue> {
        let mut connector = HttpConnector::new();
        connector.set_connect_timeout(Some(timeout));
        connector.set_nodelay(true);
        Ok(Self {
            client: Client::builder(TokioExecutor::new()).build(connector),
            tenant: HeaderValue::from_str(tenant)?,
            timeout,
        })
    }

    /// One GET of `url` and the read of its answer, without the time bound.
    async fn fetch(&self, url: &str) -> Result<LokiResponse, AccessLogQueryError> {
        let uri: Uri = url
            .parse()
            .map_err(|_error| AccessLogQueryError::Unavailable)?;
        let mut request = Request::new(Empty::<Bytes>::new());
        *request.method_mut() = Method::GET;
        *request.uri_mut() = uri;
        request
            .headers_mut()
            .insert(TENANT_HEADER, self.tenant.clone());
        let response = self
            .client
            .request(request)
            .await
            .map_err(|_error| AccessLogQueryError::Unavailable)?;
        let status = response.status().as_u16();
        let body = Limited::new(response.into_body(), MAX_ANSWER)
            .collect()
            .await
            .map_err(|_error| AccessLogQueryError::Unavailable)?
            .to_bytes();
        Ok(LokiResponse {
            status,
            body: body.to_vec(),
        })
    }
}

#[async_trait::async_trait]
impl LokiQueryTransport for HyperLokiQueryTransport {
    async fn get(&self, url: &str) -> Result<LokiResponse, AccessLogQueryError> {
        tokio::time::timeout(self.timeout, self.fetch(url))
            .await
            .unwrap_or(Err(AccessLogQueryError::Timeout))
    }
}

/// The adapter that reads access decisions from the Loki of `settings`, for the entries that the
/// gateways of `app_env` labelled.
///
/// Nothing here touches the network; the first connection is made by the first query.
///
/// # Errors
///
/// [`InvalidHeaderValue`] when the tenant cannot be a header value.
pub fn access_log_query(
    settings: &AccessLogQuerySettings,
    app_env: AppEnv,
) -> Result<Arc<dyn AccessLogQuery>, InvalidHeaderValue> {
    let transport = HyperLokiQueryTransport::new(&settings.tenant_id, settings.timeout)?;
    Ok(Arc::new(LokiAccessLogQuery::new(
        Arc::new(transport),
        &settings.query_url.to_string(),
        LOKI_APP_LABEL,
        env_label(app_env),
    )))
}

#[cfg(test)]
mod tests;
