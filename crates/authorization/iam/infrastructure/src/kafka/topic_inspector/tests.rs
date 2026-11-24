use std::sync::Arc;

use iam_domain::{
    CONTROL_PRINCIPAL, CheckSource, ConfigGates, KafkaInspectionError, KafkaTopicInspector as _,
};
use shared_domain::BoxError;
use test_support::log::LogRecorder;
use tracing::Level;

use super::KrafkaTopicInspector;
use crate::kafka::cluster::{ClusterConnector, ClusterReader, TopicLayout, TopicSettings};

const TOPIC: &str = "iam.policy.state.v1";

fn broken(message: &str) -> BoxError {
    message.into()
}

/// A cluster that answers with what a test scripted.
#[derive(Debug, Clone)]
struct Cluster {
    settings: TopicSettings,
    layout: TopicLayout,
    writers: Vec<String>,
    allow_everyone: Option<String>,
    refuses_probe: bool,
}

impl Cluster {
    fn compliant() -> Self {
        Self {
            settings: TopicSettings {
                cleanup_policy: Some("compact".to_owned()),
                unclean_leader_election: Some("false".to_owned()),
                min_insync_replicas: Some("2".to_owned()),
                message_timestamp_type: Some("LogAppendTime".to_owned()),
            },
            layout: TopicLayout {
                partitions: 1,
                replication_factor: 3,
            },
            writers: vec![CONTROL_PRINCIPAL.to_owned()],
            allow_everyone: Some("false".to_owned()),
            refuses_probe: true,
        }
    }
}

#[async_trait::async_trait]
impl ClusterReader for Cluster {
    async fn topic_settings(&self, _topic: &str) -> Result<TopicSettings, BoxError> {
        Ok(self.settings.clone())
    }

    async fn topic_layout(&self, _topic: &str) -> Result<TopicLayout, BoxError> {
        Ok(self.layout)
    }

    async fn topic_writers(&self, _topic: &str) -> Result<Vec<String>, BoxError> {
        Ok(self.writers.clone())
    }

    async fn allow_everyone(&self) -> Result<Option<String>, BoxError> {
        Ok(self.allow_everyone.clone())
    }

    async fn refuses_principal_without_acl(&self, _topic: &str) -> Result<bool, BoxError> {
        Ok(self.refuses_probe)
    }
}

#[async_trait::async_trait]
impl ClusterConnector for Cluster {
    async fn connect(&self) -> Result<Arc<dyn ClusterReader>, BoxError> {
        Ok(Arc::new(self.clone()))
    }
}

/// A connector whose cluster cannot be reached.
#[derive(Debug)]
struct Unreachable;

#[async_trait::async_trait]
impl ClusterConnector for Unreachable {
    async fn connect(&self) -> Result<Arc<dyn ClusterReader>, BoxError> {
        Err(broken("connection refused"))
    }
}

/// A cluster whose configuration read fails after it connected.
#[derive(Debug)]
struct Failing;

#[async_trait::async_trait]
impl ClusterReader for Failing {
    async fn topic_settings(&self, _topic: &str) -> Result<TopicSettings, BoxError> {
        Err(broken("describe configs failed"))
    }

    async fn topic_layout(&self, _topic: &str) -> Result<TopicLayout, BoxError> {
        Err(broken("describe topics failed"))
    }

    async fn topic_writers(&self, _topic: &str) -> Result<Vec<String>, BoxError> {
        Err(broken("describe acls failed"))
    }

    async fn allow_everyone(&self) -> Result<Option<String>, BoxError> {
        Err(broken("describe broker failed"))
    }

    async fn refuses_principal_without_acl(&self, _topic: &str) -> Result<bool, BoxError> {
        Err(broken("probe failed"))
    }
}

#[async_trait::async_trait]
impl ClusterConnector for Failing {
    async fn connect(&self) -> Result<Arc<dyn ClusterReader>, BoxError> {
        Ok(Arc::new(Self))
    }
}

fn inspector<C: ClusterConnector + 'static>(
    connector: C,
    gates: ConfigGates,
) -> KrafkaTopicInspector {
    KrafkaTopicInspector::with_connector(Arc::new(connector), TOPIC.to_owned(), gates)
}

#[tokio::test]
async fn a_compliant_topic_passes_under_enforce_without_a_warning() {
    let (recorder, _guard) = LogRecorder::install();

    let verdict = inspector(Cluster::compliant(), ConfigGates::Enforce)
        .inspect()
        .await
        .unwrap();

    assert!(verdict.passed(), "{}", verdict.describe());
    assert_eq!(verdict.allow_everyone_source(), Some(CheckSource::Broker));
    assert_eq!(recorder.lines().len(), 0);
}

#[tokio::test]
async fn a_topic_that_breaks_a_rule_fails_and_the_offending_setting_is_logged() {
    let (recorder, _guard) = LogRecorder::install();
    let mut cluster = Cluster::compliant();
    cluster.settings.cleanup_policy = Some("delete".to_owned());

    let verdict = inspector(cluster, ConfigGates::Enforce)
        .inspect()
        .await
        .unwrap();

    assert!(!verdict.passed());
    assert_eq!(
        verdict
            .violations()
            .iter()
            .map(|violation| violation.setting.as_str())
            .collect::<Vec<_>>(),
        ["cleanup.policy"]
    );
    let lines = recorder.lines();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].level, Level::WARN);
    assert!(
        lines[0]
            .field("violations")
            .unwrap()
            .contains("cleanup.policy")
    );
}

#[tokio::test]
async fn another_principal_that_may_write_fails_the_verdict() {
    let mut cluster = Cluster::compliant();
    cluster.writers.push("User:other".to_owned());

    let verdict = inspector(cluster, ConfigGates::Enforce)
        .inspect()
        .await
        .unwrap();

    assert!(verdict.describe().contains("acl.write is User:other"));
}

#[tokio::test]
async fn an_allow_everyone_answer_of_the_broker_fails_the_verdict() {
    let mut cluster = Cluster::compliant();
    cluster.allow_everyone = Some("true".to_owned());

    let verdict = inspector(cluster, ConfigGates::Enforce)
        .inspect()
        .await
        .unwrap();

    assert!(!verdict.passed());
    assert_eq!(verdict.allow_everyone_source(), Some(CheckSource::Broker));
}

#[tokio::test]
async fn a_broker_that_omits_the_setting_is_checked_through_the_fallback_probe() {
    let mut refused = Cluster::compliant();
    refused.allow_everyone = None;
    let mut answered = refused.clone();
    answered.refuses_probe = false;

    let passed = inspector(refused, ConfigGates::Enforce)
        .inspect()
        .await
        .unwrap();
    let failed = inspector(answered, ConfigGates::Enforce)
        .inspect()
        .await
        .unwrap();

    assert!(passed.passed());
    assert_eq!(passed.allow_everyone_source(), Some(CheckSource::Fallback));
    assert!(!failed.passed());
    assert_eq!(failed.allow_everyone_source(), Some(CheckSource::Fallback));
    assert!(failed.describe().ends_with("(fallback)"));
}

#[tokio::test]
async fn relaxed_gates_pass_a_single_node_topic_and_warn_on_every_check() {
    let (recorder, _guard) = LogRecorder::install();
    let mut cluster = Cluster::compliant();
    cluster.layout.replication_factor = 1;
    let relaxed = inspector(cluster, ConfigGates::Relaxed);

    let first = relaxed.inspect().await.unwrap();
    let second = relaxed.inspect().await.unwrap();

    assert!(first.passed() && second.passed());
    let lines = recorder.lines();
    assert_eq!(lines.len(), 2);
    assert!(lines.iter().all(|line| line.level == Level::WARN
        && line.field("gates") == Some("relaxed")
        && line.message.contains("KAFKA_CONFIG_GATES")));
}

#[tokio::test]
async fn an_unreachable_cluster_is_unavailable_and_the_cause_is_logged() {
    let (recorder, _guard) = LogRecorder::install();

    let error = inspector(Unreachable, ConfigGates::Enforce)
        .inspect()
        .await
        .unwrap_err();

    assert!(matches!(error, KafkaInspectionError::Unavailable(_)));
    let lines = recorder.lines();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].field("cause"), Some("connection refused"));
}

#[tokio::test]
async fn a_failed_read_is_unavailable_whichever_read_failed() {
    for gates in [ConfigGates::Enforce, ConfigGates::Relaxed] {
        let error = inspector(Failing, gates).inspect().await.unwrap_err();

        assert!(matches!(error, KafkaInspectionError::Unavailable(_)));
    }
}

#[tokio::test]
async fn the_gateway_judges_the_topic_and_leaves_the_acls_to_iam_control() {
    let mut cluster = Cluster::compliant();
    cluster.writers.push("User:other".to_owned());
    cluster.allow_everyone = Some("true".to_owned());
    let gateway = KrafkaTopicInspector {
        acl_checks: false,
        ..inspector(cluster.clone(), ConfigGates::Enforce)
    };

    let verdict = gateway.inspect().await.unwrap();

    assert!(verdict.passed(), "{}", verdict.describe());
    assert_eq!(verdict.allow_everyone_source(), None);
}

#[tokio::test]
async fn the_gateway_still_fails_a_topic_that_breaks_a_topic_rule() {
    let mut cluster = Cluster::compliant();
    cluster.layout.partitions = 2;
    let gateway = KrafkaTopicInspector {
        acl_checks: false,
        ..inspector(cluster, ConfigGates::Enforce)
    };

    let verdict = gateway.inspect().await.unwrap();

    assert!(verdict.describe().contains("partitions"));
}
