//! The settings of the control-plane Kafka connection.

use std::fmt;
use std::time::Duration;

use iam_domain::ConfigGates;

/// A secret value; it never appears in a `Debug` rendering, a log line or a span.
#[derive(Clone, PartialEq, Eq)]
pub struct KafkaSecret(String);

impl KafkaSecret {
    /// Wraps `value`.
    #[must_use]
    pub const fn new(value: String) -> Self {
        Self(value)
    }

    /// The secret itself, for the one place that hands it to the client.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for KafkaSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KafkaSecret(<redacted>)")
    }
}

/// The SASL mechanism of the connection (`KAFKA_SASL_MECHANISM`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaslMechanism {
    /// SCRAM with SHA-256.
    ScramSha256,
    /// SCRAM with SHA-512.
    ScramSha512,
}

impl SaslMechanism {
    /// The value of `KAFKA_SASL_MECHANISM` that selects the mechanism.
    #[must_use]
    pub const fn identifier(self) -> &'static str {
        match self {
            Self::ScramSha256 => "SCRAM-SHA-256",
            Self::ScramSha512 => "SCRAM-SHA-512",
        }
    }
}

/// How the connection is secured (`KAFKA_SECURITY_PROTOCOL`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KafkaSecurity {
    /// No authentication and no encryption; `dev` and `test` only.
    Plaintext,
    /// SASL SCRAM over TLS.
    SaslSsl {
        /// The SASL mechanism.
        mechanism: SaslMechanism,
        /// The principal name (`KAFKA_SASL_USERNAME`).
        username: String,
        /// The password (`KAFKA_SASL_PASSWORD`).
        password: KafkaSecret,
        /// The PEM file of the certificate authority to trust instead of the system roots
        /// (`KAFKA_CA_FILE`).
        ca_file: Option<String>,
    },
}

/// The control-plane Kafka settings: one connection and the two topics it works on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KafkaSettings {
    /// Comma-separated `host:port` pairs (`KAFKA_BOOTSTRAP_SERVERS`).
    pub bootstrap_servers: String,
    /// How the connection is secured.
    pub security: KafkaSecurity,
    /// The client id (`KAFKA_CLIENT_ID`).
    pub client_id: String,
    /// Timeout of opening a connection (`KAFKA_CONNECT_TIMEOUT`).
    pub connect_timeout: Duration,
    /// Timeout of one request (`KAFKA_REQUEST_TIMEOUT`).
    pub request_timeout: Duration,
    /// The pause between two attempts of a retried request (`KAFKA_RETRY_DELAY`).
    pub retry_delay: Duration,
    /// How strictly the topic configuration is judged (`KAFKA_CONFIG_GATES`).
    pub gates: ConfigGates,
    /// The state topic (`POLICY_TOPIC`).
    pub policy_topic: String,
    /// The events topic (`EVENTS_TOPIC`).
    pub events_topic: String,
}

/// The principal and the client id of the bootstrap connection of a gateway pod.
pub const BOOTSTRAP_PRINCIPAL: &str = "iam-gateway-bootstrap";

impl KafkaSettings {
    /// The settings of the bootstrap connection of a gateway pod: the client id
    /// [`BOOTSTRAP_PRINCIPAL`] and, over SASL, the credentials of that principal; a plaintext
    /// connection carries none.
    #[must_use]
    pub fn bootstrap_principal(&self, username: String, password: KafkaSecret) -> Self {
        let security = match &self.security {
            KafkaSecurity::Plaintext => KafkaSecurity::Plaintext,
            KafkaSecurity::SaslSsl {
                mechanism, ca_file, ..
            } => KafkaSecurity::SaslSsl {
                mechanism: *mechanism,
                username,
                password,
                ca_file: ca_file.clone(),
            },
        };
        Self {
            security,
            client_id: BOOTSTRAP_PRINCIPAL.to_owned(),
            ..self.clone()
        }
    }
}

#[cfg(test)]
mod tests;
