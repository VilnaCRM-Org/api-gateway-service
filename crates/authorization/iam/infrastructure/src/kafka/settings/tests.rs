use super::{KafkaSecret, SaslMechanism};

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
