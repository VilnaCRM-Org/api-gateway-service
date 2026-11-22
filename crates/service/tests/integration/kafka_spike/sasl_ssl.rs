//! Capability 9: SASL SCRAM-SHA-512 over TLS, trusting a custom root CA, as the gateway and `iam-control`
//! connect to the Strimzi listener with the cluster CA from `KAFKA_CA_FILE`.
//!
//! The compose service `kafka-tls` generates the CA, the broker certificate and an unrelated CA under
//! `KAFKA_TLS_DIR` before the broker starts (`scripts/kafka-tls-fixture.sh`); no key is committed. The test
//! creates a SCRAM-SHA-512 user with a password generated for this run through the PLAINTEXT listener, then
//! connects to the `SASL_SSL` listener with the right password, a wrong one and the unrelated CA.

use std::error::Error as _;
use std::io;
use std::num::NonZeroU32;
use std::path::Path;

use aws_lc_rs::{pbkdf2, rand};
use krafka::admin::{
    AlterUserScramCredentialsOptions, ListTopicsOptions, ScramCredentialUpsertion,
};
use krafka::auth::{AuthConfig, ScramMechanism, TlsConfig};
use krafka::{Kafka, KrafkaError};
use shared_domain::UuidGenerator as _;
use shared_infrastructure::id::UuidV7Generator;

use super::{DEADLINE, compose_broker, unique_topic};
use crate::support::stack_variable;

/// The PBKDF2 iteration count of the credential: Kafka's minimum for SCRAM.
const ITERATIONS: u32 = 4096;

/// The length of a SHA-512 salted password.
const SALTED_PASSWORD_LEN: usize = 64;

/// How a connection attempt ended, told apart by the error's type and cause only.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Connected,
    /// `KrafkaError::Auth` caused by a TLS failure: the client rejected the broker's certificate.
    UntrustedCertificate,
    /// `KrafkaError::Auth` without a cause, carrying the broker's `SASL_AUTHENTICATION_FAILED`.
    CredentialsRejected,
    Other(String),
}

/// Whether a cause of `error` is the `InvalidData` I/O error that wraps a TLS failure.
fn caused_by_tls(error: &KrafkaError) -> bool {
    let mut cause = error.source();
    while let Some(current) = cause {
        if current
            .downcast_ref::<io::Error>()
            .is_some_and(|inner| inner.kind() == io::ErrorKind::InvalidData)
        {
            return true;
        }
        cause = current.source();
    }
    false
}

fn outcome(result: Result<Kafka, KrafkaError>) -> Outcome {
    match result {
        Ok(_) => Outcome::Connected,
        Err(error @ KrafkaError::Auth { .. }) if caused_by_tls(&error) => {
            Outcome::UntrustedCertificate
        }
        Err(KrafkaError::Auth {
            message,
            source: None,
            ..
        }) if message.contains("SaslAuthenticationFailed") => Outcome::CredentialsRejected,
        Err(error) => Outcome::Other(format!("{error:?}")),
    }
}

/// Creates a SCRAM-SHA-512 credential for `user` through the PLAINTEXT listener: the salt is random and the
/// salted password is computed here, as `kafka-configs.sh` does.
async fn create_scram_user(user: &str, password: &str) {
    let mut salt = vec![0_u8; 32];
    rand::fill(&mut salt).unwrap();
    let mut salted_password = vec![0_u8; SALTED_PASSWORD_LEN];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA512,
        NonZeroU32::new(ITERATIONS).unwrap(),
        &salt,
        password.as_bytes(),
        &mut salted_password,
    );
    let upsertion = ScramCredentialUpsertion {
        name: user.to_owned(),
        mechanism: ScramMechanism::Sha512,
        iterations: i32::try_from(ITERATIONS).unwrap(),
        salt: salt.into(),
        salted_password: salted_password.into(),
    };
    let results = compose_broker()
        .await
        .admin()
        .alter_user_scram_credentials(
            Vec::new(),
            vec![upsertion],
            AlterUserScramCredentialsOptions::default(),
        )
        .await
        .unwrap();
    assert!(matches!(results.get(user), Some(Ok(()))), "{results:?}");
}

/// Connects to the `SASL_SSL` listener as `user` with `password`, trusting only the CA in `ca_file`.
async fn connect(user: &str, password: &str, ca_file: &Path) -> Result<Kafka, KrafkaError> {
    let tls = TlsConfig::new().with_ca_cert(ca_file.to_str().unwrap());
    let kafka = Kafka::builder(stack_variable("KAFKA_SASL_SSL_BOOTSTRAP_SERVERS"))
        .client_id("iam-spike-scram")
        .security(AuthConfig::sasl_scram_sha512(user, password).with_tls(tls))
        .connect()
        .await?;
    // A request after the handshake: the metadata of the cluster through the authenticated connection.
    kafka
        .admin()
        .list_topics(ListTopicsOptions::default())
        .await?;
    Ok(kafka)
}

/// Retries [`connect`] until it succeeds or [`DEADLINE`] passes: a new credential reaches the broker
/// through the metadata log shortly after `AlterUserScramCredentials` returns.
async fn connect_once_known(user: &str, password: &str, ca_file: &Path) -> Outcome {
    let started = tokio::time::Instant::now();
    loop {
        let attempt = outcome(connect(user, password, ca_file).await);
        if attempt == Outcome::Connected || started.elapsed() >= DEADLINE {
            return attempt;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

#[tokio::test]
async fn scram_over_tls_connects_with_the_custom_ca_and_rejects_a_wrong_password_and_an_untrusted_ca()
 {
    let tls_dir = std::path::PathBuf::from(stack_variable("KAFKA_TLS_DIR"));
    let (trusted, untrusted) = (tls_dir.join("ca.pem"), tls_dir.join("untrusted-ca.pem"));
    let user = unique_topic("scram-user");
    let password = UuidV7Generator.generate().to_string();
    create_scram_user(&user, &password).await;

    let right = connect_once_known(&user, &password, &trusted).await;
    let wrong_password = outcome(connect(&user, &format!("{password}-wrong"), &trusted).await);
    let untrusted_ca = outcome(connect(&user, &password, &untrusted).await);

    assert_eq!(right, Outcome::Connected);
    assert_eq!(wrong_password, Outcome::CredentialsRejected);
    assert_eq!(untrusted_ca, Outcome::UntrustedCertificate);
}
