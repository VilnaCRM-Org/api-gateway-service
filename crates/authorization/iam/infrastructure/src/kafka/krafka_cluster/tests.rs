use std::io;
use std::time::Duration;

use iam_domain::ConfigGates;
use krafka::KrafkaError;
use krafka::admin::{ConfigEntry, TopicDescription};
use krafka::error::ErrorCode;

use super::{answer_for, answer_of, authenticated, probe_connection, unauthenticated};
use crate::kafka::settings::{KafkaSecret, KafkaSecurity, KafkaSettings, SaslMechanism};

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

#[test]
fn the_probe_counts_an_authentication_or_authorization_error_as_a_refusal() {
    let auth = Err(KrafkaError::auth("no credentials"));
    let refused = Err(denied());

    assert!(answer_of(Some(&auth), false).unwrap());
    assert!(answer_of(Some(&refused), false).unwrap());
}

#[test]
fn the_probe_counts_a_network_error_as_a_refusal_only_where_credentials_are_required() {
    let failed = Err(network());

    assert!(answer_of(Some(&failed), true).unwrap());
    assert!(answer_of(Some(&failed), false).is_err());
}

#[test]
fn the_probe_without_an_answer_for_the_topic_is_an_error() {
    let error = answer_of(None, false).unwrap_err();

    assert_eq!(
        error.to_string(),
        "the cluster returned no answer for the negative probe"
    );
}

#[test]
fn a_refused_probe_connection_is_none_and_any_other_failure_an_error() {
    assert!(
        probe_connection(Err(KrafkaError::auth("refused")), false)
            .unwrap()
            .is_none()
    );
    assert!(probe_connection(Err(network()), true).unwrap().is_none());
    assert!(probe_connection(Err(unknown_topic()), true).is_err());
}

#[test]
fn a_plaintext_connection_has_no_security() {
    let mut plaintext = secured(SaslMechanism::ScramSha512, None);
    plaintext.security = KafkaSecurity::Plaintext;

    assert!(authenticated(&plaintext).is_none());
    assert!(unauthenticated(&plaintext).is_none());
}

#[test]
fn a_secured_connection_authenticates_with_either_scram_mechanism() {
    assert!(authenticated(&secured(SaslMechanism::ScramSha256, None)).is_some());
    assert!(authenticated(&secured(SaslMechanism::ScramSha512, Some("/etc/ca.pem"))).is_some());
}

#[test]
fn the_probe_of_a_secured_cluster_uses_tls_without_credentials() {
    assert!(unauthenticated(&secured(SaslMechanism::ScramSha512, None)).is_some());
    assert!(unauthenticated(&secured(SaslMechanism::ScramSha512, Some("/etc/ca.pem"))).is_some());
}
