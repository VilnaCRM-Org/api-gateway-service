use std::io;
use std::time::Duration;

use iam_domain::ConfigGates;
use krafka::KrafkaError;
use krafka::admin::{ConfigEntry, TopicDescription};
use krafka::error::ErrorCode;

use super::{
    ProbeLink, answer_for, answer_of, authenticated, combined_allow_everyone, probe_security,
};
use crate::kafka::cluster::ProbeOutcome;
use crate::kafka::settings::{
    KafkaSecret, KafkaSecurity, KafkaSettings, ProbeCredentials, SaslMechanism,
};

fn unknown_topic() -> KrafkaError {
    KrafkaError::broker(ErrorCode::UnknownTopicOrPartition, "unknown topic")
}

fn network() -> KrafkaError {
    KrafkaError::network(io::Error::other("connection reset"))
}

fn secured(mechanism: SaslMechanism, ca_file: Option<&str>) -> KafkaSettings {
    KafkaSettings {
        bootstrap_servers: "kafka-1:9094".to_owned(),
        security: KafkaSecurity::SaslSsl {
            mechanism,
            username: "iam-control".to_owned(),
            password: KafkaSecret::new("unit-test-password".to_owned()),
            ca_file: ca_file.map(str::to_owned),
            probe: None,
        },
        client_id: "iam-control".to_owned(),
        connect_timeout: Duration::from_secs(1),
        request_timeout: Duration::from_secs(2),
        retry_delay: Duration::from_millis(100),
        gates: ConfigGates::Enforce,
        policy_topic: "iam.policy.state.v1".to_owned(),
        events_topic: "iam.events.v1".to_owned(),
    }
}

fn denied() -> KrafkaError {
    KrafkaError::broker(ErrorCode::TopicAuthorizationFailed, "denied")
}

#[test]
fn described_entries_are_their_value() {
    let answer: Result<Vec<ConfigEntry>, KrafkaError> = Ok(Vec::new());

    let entries = answer_for(Some(&answer), "topic").unwrap();

    assert_eq!(entries.map(|entries| entries.len()), Some(0));
}

#[test]
fn an_unknown_topic_is_no_value() {
    let entries: Result<Vec<ConfigEntry>, KrafkaError> = Err(unknown_topic());
    let description: Result<TopicDescription, KrafkaError> = Err(unknown_topic());

    assert!(answer_for(Some(&entries), "topic").unwrap().is_none());
    assert!(answer_for(Some(&description), "topic").unwrap().is_none());
}

#[test]
fn any_other_error_of_a_described_resource_is_an_error() {
    let entries: Result<Vec<ConfigEntry>, KrafkaError> = Err(denied());
    let description: Result<TopicDescription, KrafkaError> = Err(denied());

    let errors = [
        answer_for(Some(&entries), "topic").unwrap_err(),
        answer_for(Some(&description), "topic").unwrap_err(),
    ];

    for error in errors {
        assert!(
            error.to_string().contains("TopicAuthorizationFailed"),
            "{error}"
        );
    }
}

#[test]
fn a_reply_that_does_not_name_the_resource_is_an_error_naming_it() {
    let entries = answer_for::<Vec<ConfigEntry>>(None, "iam.policy.state.v1").unwrap_err();
    let description = answer_for::<TopicDescription>(None, "iam.policy.state.v1").unwrap_err();

    for error in [entries, description] {
        assert_eq!(
            error.to_string(),
            "the cluster returned no answer for iam.policy.state.v1"
        );
    }
}

fn outcome(answer: &Result<(), KrafkaError>) -> Result<ProbeOutcome, String> {
    answer_of(Some(answer)).map_err(|error| error.to_string())
}

#[test]
fn only_a_topic_or_cluster_authorization_failure_is_a_refusal() {
    let topic = Err(denied());
    let cluster = Err(KrafkaError::broker(
        ErrorCode::ClusterAuthorizationFailed,
        "denied",
    ));

    assert_eq!(outcome(&topic), Ok(ProbeOutcome::Refused));
    assert_eq!(outcome(&cluster), Ok(ProbeOutcome::Refused));
}

#[test]
fn a_network_error_is_never_a_refusal() {
    assert!(outcome(&Err(network())).is_err());
}

#[test]
fn a_failed_login_or_any_other_failure_is_not_a_refusal() {
    let failures = [
        KrafkaError::auth("no credentials"),
        KrafkaError::broker(ErrorCode::SaslAuthenticationFailed, "bad login"),
        unknown_topic(),
    ];

    for failure in failures {
        assert!(outcome(&Err(failure)).is_err());
    }
}

#[test]
fn a_returned_topic_is_an_answer() {
    let answered = Ok(());

    assert_eq!(outcome(&answered), Ok(ProbeOutcome::Answered));
}

#[test]
fn the_probe_without_an_answer_for_the_topic_is_an_error() {
    let error = answer_of::<()>(None).unwrap_err();

    assert_eq!(
        error.to_string(),
        "the cluster returned no answer for the negative probe"
    );
}

#[test]
fn the_probe_of_a_secured_cluster_without_credentials_cannot_run() {
    assert!(matches!(
        probe_security(&secured(SaslMechanism::ScramSha512, None)),
        ProbeLink::Impossible
    ));
}

#[test]
fn the_probe_of_a_secured_cluster_authenticates_with_the_probe_credentials() {
    let mut settings = secured(SaslMechanism::ScramSha256, Some("/etc/ca.pem"));
    if let KafkaSecurity::SaslSsl { probe, .. } = &mut settings.security {
        *probe = Some(ProbeCredentials {
            username: "iam-probe".to_owned(),
            password: KafkaSecret::new("probe-password".to_owned()),
        });
    }

    assert!(matches!(
        probe_security(&settings),
        ProbeLink::Authenticated(_)
    ));
}

fn reported(values: &[Option<&str>]) -> Option<String> {
    combined_allow_everyone(
        &values
            .iter()
            .map(|value| value.map(str::to_owned))
            .collect::<Vec<_>>(),
    )
}

#[test]
fn every_broker_reporting_false_is_false() {
    assert_eq!(
        reported(&[Some("false"), Some("false")]).as_deref(),
        Some("false")
    );
}

#[test]
fn one_broker_reporting_true_refuses_the_cluster() {
    assert_eq!(
        reported(&[Some("false"), Some("true"), Some("false")]).as_deref(),
        Some("true")
    );
    assert_eq!(reported(&[None, Some("true")]).as_deref(), Some("true"));
}

#[test]
fn a_broker_that_does_not_report_the_setting_leaves_it_to_the_probe() {
    assert_eq!(reported(&[Some("false"), None]), None);
    assert_eq!(reported(&[None]), None);
}

#[test]
fn a_value_other_than_false_is_reported_as_it_is() {
    assert_eq!(
        reported(&[Some("false"), Some("maybe")]).as_deref(),
        Some("maybe")
    );
}

#[test]
fn a_plaintext_connection_has_no_security() {
    let mut plaintext = secured(SaslMechanism::ScramSha512, None);
    plaintext.security = KafkaSecurity::Plaintext;

    assert!(authenticated(&plaintext).is_none());
    assert!(matches!(probe_security(&plaintext), ProbeLink::Anonymous));
}

#[test]
fn a_secured_connection_authenticates_with_either_scram_mechanism() {
    assert!(authenticated(&secured(SaslMechanism::ScramSha256, None)).is_some());
    assert!(authenticated(&secured(SaslMechanism::ScramSha512, Some("/etc/ca.pem"))).is_some());
}
