//! The krafka implementation of the cluster reads: `DescribeConfigs`, `DescribeTopics`,
//! `DescribeAcls` and the negative probe of the fallback recorded by Story 1.3.

use std::sync::Arc;

use krafka::admin::{
    AclBinding, AclFilter, AclOperation, AclPatternType, AclPermissionType, AclResourceType,
    AdminClient, ConfigEntry, ConfigResource, DescribeAclsOptions, DescribeClusterOptions,
    DescribeConfigsOptions, DescribeTopicsOptions, TopicDescription,
};
use krafka::auth::{AuthConfig, TlsConfig};
use krafka::error::ErrorCode;
use krafka::{Kafka, KafkaBuilder, KrafkaError};
use shared_domain::BoxError;

use super::cluster::{
    ClusterConnector, ClusterReadError, ClusterReader, TopicLayout, TopicSettings,
};
use super::settings::{KafkaSecurity, KafkaSettings, SaslMechanism};

/// The setting of the broker that decides whether a topic without an ACL is open to everyone.
const ALLOW_EVERYONE: &str = "allow.everyone.if.no.acl.found";

/// Connects to the cluster of the settings with the credentials of `iam-control`.
#[derive(Debug, Clone)]
pub struct KrafkaConnector {
    settings: KafkaSettings,
}

impl KrafkaConnector {
    /// A connector for `settings`; nothing is opened until [`ClusterConnector::connect`].
    #[must_use]
    pub const fn new(settings: KafkaSettings) -> Self {
        Self { settings }
    }
}

#[async_trait::async_trait]
impl ClusterConnector for KrafkaConnector {
    async fn connect(&self) -> Result<Arc<dyn ClusterReader>, BoxError> {
        let kafka = builder(&self.settings, authenticated(&self.settings))
            .connect()
            .await?;
        Ok(Arc::new(KrafkaCluster {
            kafka,
            settings: self.settings.clone(),
        }))
    }
}

/// A connection of `iam-control` to the cluster.
#[derive(Debug)]
struct KrafkaCluster {
    kafka: Kafka,
    settings: KafkaSettings,
}

impl KrafkaCluster {
    fn admin(&self) -> AdminClient {
        admin_of(&self.kafka, &self.settings)
    }

    /// The entries `DescribeConfigs` returns for `resource`; none when the topic does not exist.
    async fn config_entries(
        &self,
        resource: ConfigResource,
        label: &str,
    ) -> Result<Vec<ConfigEntry>, BoxError> {
        let described = self
            .admin()
            .describe_configs([resource.clone()], DescribeConfigsOptions::default())
            .await?;
        Ok(answer_for(described.get(&resource), label)?.unwrap_or_default())
    }

    /// `DescribeTopics` of one topic.
    async fn description(&self, topic: &str) -> Result<Option<TopicDescription>, BoxError> {
        let described = self
            .admin()
            .describe_topics([topic], DescribeTopicsOptions::default())
            .await?;
        answer_for(described.get(topic), topic)
    }
}

#[async_trait::async_trait]
impl ClusterReader for KrafkaCluster {
    async fn topic_settings(&self, topic: &str) -> Result<TopicSettings, BoxError> {
        let entries = self
            .config_entries(ConfigResource::topic(topic), topic)
            .await?;
        Ok(TopicSettings {
            cleanup_policy: value_of(&entries, "cleanup.policy"),
            unclean_leader_election: value_of(&entries, "unclean.leader.election.enable"),
            min_insync_replicas: value_of(&entries, "min.insync.replicas"),
            message_timestamp_type: value_of(&entries, "message.timestamp.type"),
        })
    }

    async fn topic_layout(&self, topic: &str) -> Result<TopicLayout, BoxError> {
        let description = self.description(topic).await?;
        Ok(description
            .as_ref()
            .map_or_else(TopicLayout::default, layout_of))
    }

    async fn topic_writers(&self, topic: &str) -> Result<Vec<String>, BoxError> {
        let filter = AclFilter::for_resource(AclResourceType::Topic, topic)
            .pattern_type(AclPatternType::Match);
        let bindings = self
            .admin()
            .describe_acls(filter, DescribeAclsOptions::default())
            .await?;
        Ok(bindings
            .into_iter()
            .filter(grants_write)
            .map(|binding| binding.principal)
            .collect())
    }

    async fn allow_everyone(&self) -> Result<Option<String>, BoxError> {
        let cluster = self
            .admin()
            .describe_cluster(DescribeClusterOptions::default())
            .await?;
        let broker = cluster
            .brokers
            .first()
            .map(|broker| broker.id)
            .ok_or(ClusterReadError::NoBroker)?;
        let entries = self
            .config_entries(ConfigResource::broker(broker), "the broker")
            .await?;
        Ok(value_of(&entries, ALLOW_EVERYONE))
    }

    async fn refuses_principal_without_acl(&self, topic: &str) -> Result<bool, BoxError> {
        let requires_credentials = matches!(self.settings.security, KafkaSecurity::SaslSsl { .. });
        let Some(kafka) = connect_without_credentials(&self.settings, requires_credentials).await?
        else {
            return Ok(true);
        };
        let described = admin_of(&kafka, &self.settings)
            .describe_topics([topic], DescribeTopicsOptions::default())
            .await;
        match described {
            Ok(topics) => answer_of(topics.get(topic), requires_credentials),
            Err(error) if refused(&error, requires_credentials) => Ok(true),
            Err(error) => Err(error.into()),
        }
    }
}

/// Connects as the probe principal that holds no ACL; `None` when the cluster refuses the
/// connection itself.
async fn connect_without_credentials(
    settings: &KafkaSettings,
    requires_credentials: bool,
) -> Result<Option<Kafka>, BoxError> {
    let connected = builder(settings, unauthenticated(settings)).connect().await;
    probe_connection(connected, requires_credentials)
}

/// The probe principal's connection: `None` when the cluster refuses it.
fn probe_connection(
    connected: Result<Kafka, KrafkaError>,
    requires_credentials: bool,
) -> Result<Option<Kafka>, BoxError> {
    connected.map(Some).or_else(|error| {
        if refused(&error, requires_credentials) {
            Ok(None)
        } else {
            Err(error.into())
        }
    })
}

/// The answer of a describe call for the resource `label`: its value, `None` when the topic does
/// not exist, or the error of the cluster.
fn answer_for<T: Clone>(
    answer: Option<&Result<T, KrafkaError>>,
    label: &str,
) -> Result<Option<T>, BoxError> {
    let answer = answer.ok_or_else(|| ClusterReadError::NoAnswer(label.to_owned()))?;
    answer
        .as_ref()
        .map(|value| Some(value.clone()))
        .or_else(missing_or_error)
}

/// A failed describe answer: `None` for a topic that does not exist, the error otherwise.
fn missing_or_error<T>(error: &KrafkaError) -> Result<Option<T>, BoxError> {
    if is_unknown_topic(error) {
        Ok(None)
    } else {
        Err(error.clone().into())
    }
}

/// The negative probe's answer to `DescribeTopics`: refused when the broker denies the principal,
/// answered when it returns the topic.
fn answer_of(
    answer: Option<&Result<TopicDescription, KrafkaError>>,
    requires_credentials: bool,
) -> Result<bool, BoxError> {
    let answer =
        answer.ok_or_else(|| ClusterReadError::NoAnswer("the negative probe".to_owned()))?;
    answer
        .as_ref()
        .map(|_description| false)
        .or_else(|error| refusal_of(error, requires_credentials))
}

/// A failed answer of the negative probe: refused when the broker denies the principal, the
/// error otherwise.
fn refusal_of(error: &KrafkaError, requires_credentials: bool) -> Result<bool, BoxError> {
    if refused(error, requires_credentials) {
        Ok(true)
    } else {
        Err(error.clone().into())
    }
}

/// Whether `error` is the cluster refusing a principal that holds no ACL.
///
/// A listener that requires credentials closes or fails a connection that offers none, so a
/// network error while connecting without credentials counts as a refusal there.
const fn refused(error: &KrafkaError, requires_credentials: bool) -> bool {
    matches!(error, KrafkaError::Auth { .. })
        || (requires_credentials && matches!(error, KrafkaError::Network(_)))
        || matches!(
            error,
            KrafkaError::Broker {
                code: ErrorCode::TopicAuthorizationFailed
                    | ErrorCode::ClusterAuthorizationFailed
                    | ErrorCode::SaslAuthenticationFailed,
                ..
            }
        )
}

const fn is_unknown_topic(error: &KrafkaError) -> bool {
    matches!(
        error,
        KrafkaError::Broker {
            code: ErrorCode::UnknownTopicOrPartition,
            ..
        }
    )
}

fn layout_of(description: &TopicDescription) -> TopicLayout {
    TopicLayout {
        partitions: description.partitions.len(),
        replication_factor: description
            .partitions
            .iter()
            .map(|partition| partition.replicas.len())
            .min()
            .unwrap_or(0),
    }
}

/// Whether `binding` allows its principal to write the topic.
fn grants_write(binding: &AclBinding) -> bool {
    binding.permission_type == AclPermissionType::Allow
        && matches!(binding.operation, AclOperation::Write | AclOperation::All)
}

/// The explicit value of the entry `name`, if the broker returned one.
fn value_of(entries: &[ConfigEntry], name: &str) -> Option<String> {
    entries
        .iter()
        .find(|entry| entry.name == name)
        .and_then(|entry| entry.config_value().as_str().map(str::to_owned))
}

fn admin_of(kafka: &Kafka, settings: &KafkaSettings) -> AdminClient {
    kafka
        .admin()
        .retry_backoff(settings.retry_delay)
        .default_api_timeout(settings.request_timeout)
}

pub(super) fn builder(settings: &KafkaSettings, security: Option<AuthConfig>) -> KafkaBuilder {
    let builder = Kafka::builder(settings.bootstrap_servers.clone())
        .client_id(settings.client_id.clone())
        .connect_timeout(settings.connect_timeout)
        .request_timeout(settings.request_timeout);
    match security {
        Some(security) => builder.security(security),
        None => builder,
    }
}

/// The security of the connection of `iam-control`; `None` for a plaintext listener.
pub(super) fn authenticated(settings: &KafkaSettings) -> Option<AuthConfig> {
    match &settings.security {
        KafkaSecurity::Plaintext => None,
        KafkaSecurity::SaslSsl {
            mechanism,
            username,
            password,
            ca_file,
        } => {
            let credentials = match mechanism {
                SaslMechanism::ScramSha256 => {
                    AuthConfig::sasl_scram_sha256(username.clone(), password.expose())
                }
                SaslMechanism::ScramSha512 => {
                    AuthConfig::sasl_scram_sha512(username.clone(), password.expose())
                }
            };
            Some(credentials.with_tls(tls(ca_file.as_deref())))
        }
    }
}

/// The security of the probe principal that holds no ACL: TLS without credentials, or none.
fn unauthenticated(settings: &KafkaSettings) -> Option<AuthConfig> {
    match &settings.security {
        KafkaSecurity::Plaintext => None,
        KafkaSecurity::SaslSsl { ca_file, .. } => Some(AuthConfig::ssl(tls(ca_file.as_deref()))),
    }
}

fn tls(ca_file: Option<&str>) -> TlsConfig {
    ca_file.map_or_else(TlsConfig::new, |path| TlsConfig::new().with_ca_cert(path))
}

#[cfg(test)]
mod tests;
