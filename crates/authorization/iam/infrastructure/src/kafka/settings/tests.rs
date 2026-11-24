use std::time::Duration;

use iam_domain::ConfigGates;

use super::{BOOTSTRAP_PRINCIPAL, KafkaSecret, KafkaSecurity, KafkaSettings, SaslMechanism};

fn settings(security: KafkaSecurity) -> KafkaSettings {
    KafkaSettings {
        bootstrap_servers: "broker:9092".to_owned(),
        security,
        client_id: "iam-control".to_owned(),
        connect_timeout: Duration::from_secs(1),
        request_timeout: Duration::from_secs(2),
        retry_delay: Duration::from_millis(100),
        gates: ConfigGates::Relaxed,
        policy_topic: "state".to_owned(),
        events_topic: "events".to_owned(),
    }
}

#[test]
fn a_secret_is_redacted_in_its_debug_rendering_and_exposed_on_request() {
    let secret = KafkaSecret::new("hunter2-secret".to_owned());

    assert_eq!(format!("{secret:?}"), "KafkaSecret(<redacted>)");
    assert_eq!(secret.expose(), "hunter2-secret");
}

#[test]
fn a_mechanism_has_the_identifier_of_its_variable_value() {
    assert_eq!(SaslMechanism::ScramSha256.identifier(), "SCRAM-SHA-256");
    assert_eq!(SaslMechanism::ScramSha512.identifier(), "SCRAM-SHA-512");
}

#[test]
fn the_bootstrap_connection_takes_the_bootstrap_principal_over_sasl() {
    let control = settings(KafkaSecurity::SaslSsl {
        mechanism: SaslMechanism::ScramSha256,
        username: "iam-control".to_owned(),
        password: KafkaSecret::new("control".to_owned()),
        ca_file: Some("/ca.pem".to_owned()),
    });

    let bootstrap = control.bootstrap_principal(
        "iam-gateway-bootstrap".to_owned(),
        KafkaSecret::new("boot".to_owned()),
    );

    assert_eq!(bootstrap.client_id, BOOTSTRAP_PRINCIPAL);
    assert_eq!(bootstrap.policy_topic, "state");
    let KafkaSecurity::SaslSsl {
        mechanism,
        username,
        password,
        ca_file,
    } = bootstrap.security
    else {
        panic!("the bootstrap connection stays on SASL");
    };
    assert_eq!(mechanism, SaslMechanism::ScramSha256);
    assert_eq!(username, "iam-gateway-bootstrap");
    assert_eq!(password.expose(), "boot");
    assert_eq!(ca_file.as_deref(), Some("/ca.pem"));
}

#[test]
fn a_plaintext_bootstrap_connection_carries_no_credentials() {
    let bootstrap = settings(KafkaSecurity::Plaintext)
        .bootstrap_principal("ignored".to_owned(), KafkaSecret::new("ignored".to_owned()));

    assert_eq!(bootstrap.security, KafkaSecurity::Plaintext);
    assert_eq!(bootstrap.client_id, "iam-gateway-bootstrap");
}
