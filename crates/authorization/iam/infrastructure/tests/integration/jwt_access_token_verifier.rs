//! `JwtAccessTokenVerifier` over a key file on disk: the claims of user and service tokens, the
//! refusal codes, key rotation newest first and the hot reload that keeps the last valid key set.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    AccessToken, AccessTokenVerifier as _, Credential, SubjectId, SubjectKind, TokenLifetimeRule,
    TokenRejection,
};
use iam_infrastructure::{JwtAccessTokenVerifier, JwtSettings};
use serde_json::{Value, json};
use test_support::clock::FixedClock;
use test_support::log::LogRecorder;

#[path = "../../src/token/test_keys.rs"]
mod test_keys;

use test_keys::{
    AUDIENCE, ISSUER, NOW, TestKey, USER_ID, key_file, scratch_dir, service_claims, unsigned,
    user_claims,
};

fn settings() -> JwtSettings {
    JwtSettings {
        issuer: ISSUER.to_owned(),
        audience: AUDIENCE.to_owned(),
        lifetime: TokenLifetimeRule::new(Duration::from_mins(15), Duration::from_secs(30)),
    }
}

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

/// A verifier over the key file `name` holding `keys`, its clock fixed at [`NOW`].
fn verifier_over(name: &str, keys: &[&TestKey]) -> (JwtAccessTokenVerifier, std::path::PathBuf) {
    let path = scratch_dir(name).join("keys.pem");
    std::fs::write(&path, key_file(keys)).unwrap();
    let clock = Arc::new(FixedClock::at(at(NOW)));
    let verifier = JwtAccessTokenVerifier::from_file(&path, &settings(), clock).unwrap();
    (verifier, path)
}

fn verify(verifier: &JwtAccessTokenVerifier, token: &str) -> Result<AccessToken, TokenRejection> {
    verifier.verify(&Credential::new(token.to_owned()))
}

fn with(mut claims: Value, name: &str, value: Value) -> Value {
    claims[name] = value;
    claims
}

fn without(mut claims: Value, name: &str) -> Value {
    claims.as_object_mut().unwrap().remove(name);
    claims
}

fn replace(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
}

#[test]
fn user_and_service_tokens_yield_their_access_tokens() {
    let key = TestKey::generate();
    let (verifier, _path) = verifier_over("claims", &[&key]);

    let user = verify(&verifier, &key.sign(&user_claims())).unwrap();
    let service = verify(&verifier, &key.sign(&service_claims())).unwrap();

    assert_eq!(user.subject_kind(), SubjectKind::User);
    assert_eq!(user.subject().to_string(), USER_ID);
    assert_eq!(
        user.session().map(ToString::to_string).as_deref(),
        Some("session-1")
    );
    assert_eq!(user.token_id().to_string(), "token-1");
    assert_eq!(user.roles(), ["ROLE_USER"]);
    assert_eq!(user.issued_at(), at(NOW));
    assert_eq!(user.expires_at(), at(NOW + 900));
    assert_eq!(service.subject_kind(), SubjectKind::Service);
    assert!(matches!(service.subject(), SubjectId::Service(_)));
    assert_eq!(service.subject().to_string(), "user-service");
    assert_eq!(service.token_id().to_string(), "token-2");
    assert_eq!(service.roles(), ["ROLE_SERVICE"]);
}

#[test]
fn every_refused_token_carries_its_rejection_code() {
    let key = TestKey::generate();
    let (verifier, _path) = verifier_over("refusals", &[&key]);
    let invalid = [
        unsigned(&json!({"alg": "none", "typ": "JWT"}), &user_claims()),
        key.sign(&with(user_claims(), "iss", json!("another-issuer"))),
        key.sign(&with(user_claims(), "aud", json!("another-audience"))),
        key.sign(&without(user_claims(), "sub")),
        key.sign(&without(user_claims(), "jti")),
        key.sign(&without(user_claims(), "sid")),
        key.sign(&with(service_claims(), "sub", json!("Not A Service"))),
        key.sign(&with(user_claims(), "exp", json!(NOW + 901))),
        key.sign(&with(user_claims(), "nbf", json!(NOW + 31))),
        key.sign(&with(
            with(user_claims(), "iat", json!(NOW + 31)),
            "exp",
            json!(NOW + 600),
        )),
    ];

    for token in &invalid {
        assert_eq!(
            verify(&verifier, token).unwrap_err().code(),
            "token_invalid",
            "{token}"
        );
    }
    let expired = key.sign(&with(
        with(user_claims(), "iat", json!(NOW - 900)),
        "exp",
        json!(NOW - 31),
    ));
    assert_eq!(
        verify(&verifier, &expired).unwrap_err().code(),
        "token_expired"
    );
    assert_eq!(verify(&verifier, "").unwrap_err().code(), "token_missing");
}

#[test]
fn a_token_of_the_oldest_of_three_keys_is_accepted() {
    let oldest = TestKey::generate();
    let middle = TestKey::generate();
    let newest = TestKey::generate();
    let (verifier, _path) = verifier_over("rotation", &[&oldest, &middle, &newest]);

    assert_eq!(verifier.key_count(), 3);
    assert!(verify(&verifier, &oldest.sign(&user_claims())).is_ok());
}

#[test]
fn a_replaced_key_file_is_reloaded_and_a_broken_one_keeps_the_last_valid_set() {
    let old = TestKey::generate();
    let new = TestKey::generate();
    let (verifier, path) = verifier_over("hot-reload", &[&old]);
    let verifier = Arc::new(verifier);
    let watch = verifier.watch(Duration::from_millis(10));
    let token = new.sign(&user_claims());
    assert_eq!(
        verify(&verifier, &token).unwrap_err(),
        TokenRejection::Invalid
    );

    replace(&path, new.public_pem());
    let accepted = (0..500).any(|_| {
        std::thread::sleep(Duration::from_millis(10));
        verify(&verifier, &token).is_ok()
    });
    assert!(accepted);

    replace(
        &path,
        "-----BEGIN PUBLIC KEY-----\nbroken\n-----END PUBLIC KEY-----\n",
    );
    let (recorder, guard) = LogRecorder::install();
    assert!(verifier.reload().is_err());
    drop(guard);

    assert!(verify(&verifier, &token).is_ok());
    assert!(verify(&verifier, &old.sign(&user_claims())).is_err());
    let lines = recorder.lines();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].level, tracing::Level::ERROR);
    drop(verifier);
    watch.join().unwrap();
}
