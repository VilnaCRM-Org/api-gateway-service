use std::sync::Arc;

use health_check_domain::{Dependency, HealthProbe as _};
use iam_domain::{
    ConfigGates, ConfigurationVerdict, KafkaInspectionError, KafkaTopicInspector, Violation,
};

use super::KafkaProbe;

/// An inspector that answers what a test scripted.
#[derive(Debug)]
struct ScriptedInspector(Option<ConfigurationVerdict>);

#[async_trait::async_trait]
impl KafkaTopicInspector for ScriptedInspector {
    async fn inspect(&self) -> Result<ConfigurationVerdict, KafkaInspectionError> {
        self.0
            .clone()
            .ok_or_else(|| KafkaInspectionError::Unavailable("connection refused".into()))
    }
}

fn probe(answer: Option<ConfigurationVerdict>) -> KafkaProbe {
    KafkaProbe::new(Arc::new(ScriptedInspector(answer)))
}

#[test]
fn the_probe_reports_the_kafka_dependency() {
    assert_eq!(probe(None).dependency(), Dependency::Kafka);
}

#[tokio::test]
async fn a_passing_verdict_is_healthy() {
    let verdict = ConfigurationVerdict::new(ConfigGates::Enforce, Vec::new(), None);

    assert!(probe(Some(verdict)).check().await.is_ok());
}

#[tokio::test]
async fn a_failed_verdict_is_unhealthy_and_names_the_offending_setting() {
    let violations = vec![Violation::new("cleanup.policy", "compact", "delete")];
    let verdict = ConfigurationVerdict::new(ConfigGates::Enforce, violations, None);

    let error = probe(Some(verdict)).check().await.unwrap_err();

    assert_eq!(
        error.to_string(),
        "the Kafka topic configuration breaks a rule: \
         cleanup.policy is delete but must be compact (broker)"
    );
}

#[tokio::test]
async fn an_unreachable_cluster_is_unhealthy() {
    let error = probe(None).check().await.unwrap_err();

    assert_eq!(error.to_string(), "the Kafka cluster is unavailable");
}
