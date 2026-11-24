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
    ClusterConnector, ClusterReadError, ClusterReader, ProbeOutcome, TopicLayout, TopicSettings,
};
use super::settings::{KafkaSecurity, KafkaSettings, ProbeCredentials, SaslMechanism};

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
        if cluster.brokers.is_empty() {
            return Err(ClusterReadError::NoBroker.into());
        }
        let mut reported = Vec::with_capacity(cluster.brokers.len());
        for broker in &cluster.brokers {
            let entries = self
                .config_entries(ConfigResource::broker(broker.id), "the broker")
                .await?;
            reported.push(value_of(&entries, ALLOW_EVERYONE));
        }
        Ok(combined_allow_everyone(&reported))
    }

    async fn probe_principal_without_acl(&self, topic: &str) -> Result<ProbeOutcome, BoxError> {
        let security = match probe_security(&self.settings) {
            ProbeLink::Impossible => return Ok(ProbeOutcome::NotChecked),
            ProbeLink::Anonymous => None,
            ProbeLink::Authenticated(security) => Some(*security),
        };
        let kafka = builder(&self.settings, security).connect().await?;
        let described = admin_of(&kafka, &self.settings)
            .describe_topics([topic], DescribeTopicsOptions::default())
            .await?;
        answer_of(described.get(topic))
    }
}

/// The value of `allow.everyone.if.no.acl.found` that every broker answers with: a value other
/// than `false` as soon as one broker reports it (`true` first), `false` when every broker
/// reports `false`, and `None` when a broker does not report it, so that the probe decides.
fn combined_allow_everyone(reported: &[Option<String>]) -> Option<String> {
    let open = reported
        .iter()
        .flatten()
        .filter(|value| value.as_str() != "false")
        .min_by_key(|value| value.as_str() != "true");
    if let Some(value) = open {
        return Some(value.clone());
    }
    reported
        .iter()
        .all(Option::is_some)
        .then(|| "false".to_owned())
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

/// The negative probe's answer to `DescribeTopics` on an authenticated connection: refused when
/// the broker denies the principal, answered when it returns the topic, and an error otherwise.
fn answer_of<T>(answer: Option<&Result<T, KrafkaError>>) -> Result<ProbeOutcome, BoxError> {
    let answer =
        answer.ok_or_else(|| ClusterReadError::NoAnswer("the negative probe".to_owned()))?;
    answer
        .as_ref()
        .map(|_description| ProbeOutcome::Answered)
        .or_else(refusal_of)
}

/// A failed answer of the negative probe: refused when the broker denies the principal, the
/// error otherwise.
fn refusal_of(error: &KrafkaError) -> Result<ProbeOutcome, BoxError> {
    if refused(error) {
        Ok(ProbeOutcome::Refused)
    } else {
        Err(error.clone().into())
    }
}

/// Whether `error` is the broker denying an authenticated principal that holds no ACL.
///
/// Only `TOPIC_AUTHORIZATION_FAILED` and `CLUSTER_AUTHORIZATION_FAILED` count: a network error, a
/// failed login or any other failure says nothing about the ACLs.
const fn refused(error: &KrafkaError) -> bool {
    matches!(
        error,
        KrafkaError::Broker {
            code: ErrorCode::TopicAuthorizationFailed | ErrorCode::ClusterAuthorizationFailed,
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
            ..
        } => Some(
            scram(*mechanism, username.clone(), password.expose())
                .with_tls(tls(ca_file.as_deref())),
        ),
    }
}

/// How the negative probe connects.
enum ProbeLink {
    /// A plaintext listener: the anonymous principal is the probe.
    Anonymous,
    /// A `SASL_SSL` listener: the probe principal with its credentials.
    Authenticated(Box<AuthConfig>),
    /// A `SASL_SSL` listener without probe credentials: the probe cannot run.
    Impossible,
}

/// The security of the probe principal that holds no ACL. A plaintext listener needs none; a
/// `SASL_SSL` listener needs the configured probe credentials.
fn probe_security(settings: &KafkaSettings) -> ProbeLink {
    match &settings.security {
        KafkaSecurity::Plaintext => ProbeLink::Anonymous,
        KafkaSecurity::SaslSsl {
            mechanism,
            ca_file,
            probe,
            ..
        } => probe.as_ref().map_or(ProbeLink::Impossible, |credentials| {
            ProbeLink::Authenticated(Box::new(credentials_of(
                *mechanism,
                credentials,
                ca_file.as_deref(),
            )))
        }),
    }
}

fn credentials_of(
    mechanism: SaslMechanism,
    credentials: &ProbeCredentials,
    ca_file: Option<&str>,
) -> AuthConfig {
    scram(
        mechanism,
        credentials.username.clone(),
        credentials.password.expose(),
    )
    .with_tls(tls(ca_file))
}

fn scram(mechanism: SaslMechanism, username: String, password: &str) -> AuthConfig {
    match mechanism {
        SaslMechanism::ScramSha256 => AuthConfig::sasl_scram_sha256(username, password),
        SaslMechanism::ScramSha512 => AuthConfig::sasl_scram_sha512(username, password),
    }
}

fn tls(ca_file: Option<&str>) -> TlsConfig {
    ca_file.map_or_else(TlsConfig::new, |path| TlsConfig::new().with_ca_cert(path))
}

#[cfg(test)]
mod tests;
