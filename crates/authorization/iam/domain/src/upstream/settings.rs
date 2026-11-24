//! The validated configuration of an upstream.

use crate::error::{InvalidIamValue, InvalidUpstream};
use crate::gateway_seed::IamGatewaySeed;
use crate::value_object::dns::is_label;
use crate::value_object::service_name::ServiceName;
use crate::value_object::upstream_name::UpstreamName;

/// The protocol the gateway speaks to an upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamProtocol {
    /// HTTP/1.1.
    Http1,
    /// HTTP/2 over cleartext.
    H2c,
}

impl UpstreamProtocol {
    /// The protocol that [`Self::as_str`] prints; `None` for any other text.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "http1" => Some(Self::Http1),
            "h2c" => Some(Self::H2c),
            _ => None,
        }
    }

    /// The name of the protocol.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http1 => "http1",
            Self::H2c => "h2c",
        }
    }
}

/// The unvalidated settings of an upstream, as a request carries them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamSettingsDraft {
    /// The Kubernetes namespace.
    pub namespace: String,
    /// The Kubernetes Service name.
    pub service_name: String,
    /// The catalogue service the upstream serves.
    pub catalog_service: String,
    /// The port.
    pub port: i64,
    /// The protocol.
    pub protocol: UpstreamProtocol,
    /// Whether the caller's credentials are forwarded to the upstream.
    pub forward_credentials: bool,
    /// The connect timeout, in milliseconds.
    pub connect_timeout_ms: i64,
    /// The response timeout, in milliseconds.
    pub response_timeout_ms: i64,
    /// The largest number of concurrent requests.
    pub concurrency_limit: i64,
    /// The retry budget, in percent of the requests.
    pub retry_budget_percent: i64,
    /// The number of consecutive failures after which an endpoint is ejected.
    pub outlier_threshold: i64,
}

/// The validated settings of an upstream: everything an update can change besides the name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamSettings {
    namespace: String,
    service_name: String,
    catalog_service: ServiceName,
    port: u16,
    protocol: UpstreamProtocol,
    forward_credentials: bool,
    connect_timeout_ms: u32,
    response_timeout_ms: u32,
    concurrency_limit: u32,
    retry_budget_percent: u8,
    outlier_threshold: u32,
}

impl UpstreamSettings {
    /// The largest retry budget, in percent.
    pub const MAX_RETRY_BUDGET_PERCENT: u8 = 100;

    /// The namespaces an upstream never targets, whatever the configuration: forwarding there
    /// would let a route operator reach the cluster's own services (SSRF).
    pub const RESERVED_NAMESPACES: [&'static str; 2] = ["kube-system", "kube-public"];

    /// Refuses a namespace that is a system namespace, the namespace of the seeded IAM upstream
    /// (so the refusal holds when nothing is configured) or `own`, the configured namespace IAM
    /// runs in.
    ///
    /// # Errors
    ///
    /// [`InvalidUpstream::NamespaceReserved`] for a reserved namespace.
    pub fn check_namespace(&self, own: Option<&str>) -> Result<(), InvalidUpstream> {
        let reserved = Self::RESERVED_NAMESPACES.contains(&self.namespace.as_str())
            || self.namespace == IamGatewaySeed::NAMESPACE
            || own.is_some_and(|own| own == self.namespace);
        if reserved {
            Err(InvalidUpstream::NamespaceReserved)
        } else {
            Ok(())
        }
    }

    /// Validates the draft.
    ///
    /// # Errors
    ///
    /// Every violation, in the order namespace, Service name, catalogue service, port, connect
    /// timeout, response timeout, concurrency limit, retry budget, outlier threshold.
    pub fn new(draft: &UpstreamSettingsDraft) -> Result<Self, Vec<InvalidUpstream>> {
        let mut found = Vec::new();
        let target = target_of(draft, &mut found);
        let limits = limits_of(draft, &mut found);
        match (target, limits) {
            (
                Some((namespace, service_name, catalog_service, port)),
                Some((connect_timeout_ms, response_timeout_ms, concurrency_limit, budget, outlier)),
            ) => Ok(Self {
                namespace,
                service_name,
                catalog_service,
                port,
                protocol: draft.protocol,
                forward_credentials: draft.forward_credentials,
                connect_timeout_ms,
                response_timeout_ms,
                concurrency_limit,
                retry_budget_percent: budget,
                outlier_threshold: outlier,
            }),
            _ => Err(found),
        }
    }

    /// The Kubernetes namespace.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// The Kubernetes Service name.
    #[must_use]
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    /// The catalogue service the upstream serves.
    #[must_use]
    pub const fn catalog_service(&self) -> &ServiceName {
        &self.catalog_service
    }

    /// The port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// The protocol.
    #[must_use]
    pub const fn protocol(&self) -> UpstreamProtocol {
        self.protocol
    }

    /// Whether the caller's credentials are forwarded to the upstream.
    #[must_use]
    pub const fn forward_credentials(&self) -> bool {
        self.forward_credentials
    }

    /// The connect timeout, in milliseconds.
    #[must_use]
    pub const fn connect_timeout_ms(&self) -> u32 {
        self.connect_timeout_ms
    }

    /// The response timeout, in milliseconds.
    #[must_use]
    pub const fn response_timeout_ms(&self) -> u32 {
        self.response_timeout_ms
    }

    /// The largest number of concurrent requests.
    #[must_use]
    pub const fn concurrency_limit(&self) -> u32 {
        self.concurrency_limit
    }

    /// The retry budget, in percent of the requests.
    #[must_use]
    pub const fn retry_budget_percent(&self) -> u8 {
        self.retry_budget_percent
    }

    /// The number of consecutive failures after which an endpoint is ejected.
    #[must_use]
    pub const fn outlier_threshold(&self) -> u32 {
        self.outlier_threshold
    }

    /// The names of the settings in which `other` differs from these.
    #[must_use]
    pub fn changed_fields(&self, other: &Self) -> Vec<&'static str> {
        [
            ("namespace", self.namespace != other.namespace),
            ("serviceName", self.service_name != other.service_name),
            (
                "catalogService",
                self.catalog_service != other.catalog_service,
            ),
            ("port", self.port != other.port),
            ("protocol", self.protocol != other.protocol),
            (
                "forwardCredentials",
                self.forward_credentials != other.forward_credentials,
            ),
            (
                "connectTimeoutMs",
                self.connect_timeout_ms != other.connect_timeout_ms,
            ),
            (
                "responseTimeoutMs",
                self.response_timeout_ms != other.response_timeout_ms,
            ),
            (
                "concurrencyLimit",
                self.concurrency_limit != other.concurrency_limit,
            ),
            (
                "retryBudgetPercent",
                self.retry_budget_percent != other.retry_budget_percent,
            ),
            (
                "outlierThreshold",
                self.outlier_threshold != other.outlier_threshold,
            ),
        ]
        .into_iter()
        .filter_map(|(name, changed)| changed.then_some(name))
        .collect()
    }
}

/// The name and the settings of an upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamFields {
    name: UpstreamName,
    settings: UpstreamSettings,
}

impl UpstreamFields {
    /// Validates the name and the settings together.
    ///
    /// # Errors
    ///
    /// Every violation: the name first, then those of [`UpstreamSettings::new`].
    pub fn new(name: &str, settings: &UpstreamSettingsDraft) -> Result<Self, Vec<InvalidUpstream>> {
        let name = UpstreamName::new(name);
        let settings = UpstreamSettings::new(settings);
        match (name, settings) {
            (Ok(name), Ok(settings)) => Ok(Self { name, settings }),
            (name, settings) => Err(name
                .err()
                .into_iter()
                .chain(settings.err().into_iter().flatten())
                .collect()),
        }
    }

    /// Splits the fields into the name and the settings.
    #[must_use]
    pub fn into_parts(self) -> (UpstreamName, UpstreamSettings) {
        (self.name, self.settings)
    }

    /// The name.
    #[must_use]
    pub const fn name(&self) -> &UpstreamName {
        &self.name
    }

    /// The settings.
    #[must_use]
    pub const fn settings(&self) -> &UpstreamSettings {
        &self.settings
    }
}

/// Where an upstream runs: the namespace, the Service name, the catalogue service and the port.
type Target = (String, String, ServiceName, u16);

/// What an upstream tolerates: the timeouts, the concurrency limit, the retry budget and the
/// outlier threshold.
type Limits = (u32, u32, u32, u8, u32);

/// The validated target of the draft; the violations are added to `found` otherwise.
fn target_of(draft: &UpstreamSettingsDraft, found: &mut Vec<InvalidUpstream>) -> Option<Target> {
    let namespace = gather(
        label(&draft.namespace, InvalidUpstream::NamespaceFormat),
        found,
    );
    let service = gather(
        label(&draft.service_name, InvalidUpstream::ServiceFormat),
        found,
    );
    let catalog = gather(catalog_service_of(&draft.catalog_service), found);
    let port = gather(port_of(draft.port), found);
    Some((namespace?, service?, catalog?, port?))
}

/// The validated limits of the draft; the violations are added to `found` otherwise.
fn limits_of(draft: &UpstreamSettingsDraft, found: &mut Vec<InvalidUpstream>) -> Option<Limits> {
    let connect = positive(
        draft.connect_timeout_ms,
        InvalidUpstream::ConnectTimeoutRange,
    );
    let response = positive(
        draft.response_timeout_ms,
        InvalidUpstream::ResponseTimeoutRange,
    );
    let limit = positive(
        draft.concurrency_limit,
        InvalidUpstream::ConcurrencyLimitRange,
    );
    let budget = budget_of(draft.retry_budget_percent);
    let outlier = positive(
        draft.outlier_threshold,
        InvalidUpstream::OutlierThresholdRange,
    );
    let connect = gather(connect, found);
    let response = gather(response, found);
    let limit = gather(limit, found);
    let budget = gather(budget, found);
    let outlier = gather(outlier, found);
    Some((connect?, response?, limit?, budget?, outlier?))
}

/// The value of a result; its violation is added to `found` otherwise.
fn gather<T>(result: Result<T, InvalidUpstream>, found: &mut Vec<InvalidUpstream>) -> Option<T> {
    result.map_err(|violation| found.push(violation)).ok()
}

/// The text when it is a lower-case DNS label.
fn label(value: &str, violation: InvalidUpstream) -> Result<String, InvalidUpstream> {
    if is_label(value) {
        Ok(value.to_owned())
    } else {
        Err(violation)
    }
}

/// The catalogue service name, mapped to the violations of an upstream.
fn catalog_service_of(value: &str) -> Result<ServiceName, InvalidUpstream> {
    ServiceName::new(value).map_err(|invalid| {
        if invalid == InvalidIamValue::ServiceNameLength {
            InvalidUpstream::CatalogServiceLength
        } else {
            InvalidUpstream::CatalogServicePattern
        }
    })
}

/// A port between 1 and 65,535.
fn port_of(value: i64) -> Result<u16, InvalidUpstream> {
    u16::try_from(value)
        .ok()
        .filter(|port| *port > 0)
        .ok_or(InvalidUpstream::PortRange)
}

/// A number between 1 and `u32::MAX`.
fn positive(value: i64, violation: InvalidUpstream) -> Result<u32, InvalidUpstream> {
    u32::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(violation)
}

/// A retry budget between 0 and 100 percent.
fn budget_of(value: i64) -> Result<u8, InvalidUpstream> {
    u8::try_from(value)
        .ok()
        .filter(|percent| *percent <= UpstreamSettings::MAX_RETRY_BUDGET_PERCENT)
        .ok_or(InvalidUpstream::RetryBudgetRange)
}
