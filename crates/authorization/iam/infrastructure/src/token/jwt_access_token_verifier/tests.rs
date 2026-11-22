use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    AccessTokenVerifier as _, Credential, SubjectId, SubjectKind, TokenLifetimeRule, TokenRejection,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rstest::rstest;
use serde_json::{Value, json};
use shared_domain::Uuid;
use test_support::clock::FixedClock;
use test_support::log::LogRecorder;

use super::{JwtAccessTokenVerifier, JwtSettings};
use crate::token::jwt_key_set::JwtKeySet;
use crate::token::test_keys::{
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

fn clock_at(seconds: u64) -> Arc<FixedClock> {
    Arc::new(FixedClock::at(
        SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(seconds))
            .unwrap(),
    ))
}

fn verifier(keys: &[&TestKey]) -> JwtAccessTokenVerifier {
    verifier_at(keys, NOW)
}

fn verifier_at(keys: &[&TestKey], now: u64) -> JwtAccessTokenVerifier {
    let set = JwtKeySet::parse(&key_file(keys)).unwrap();
    JwtAccessTokenVerifier::new(set, &settings(), clock_at(now))
}

fn verify(verifier: &JwtAccessTokenVerifier, token: &str) -> Result<SubjectId, TokenRejection> {
    verifier
        .verify(&Credential::new(token.to_owned()))
        .map(|token| token.subject().clone())
}

fn with(mut claims: Value, name: &str, value: Value) -> Value {
    claims[name] = value;
    claims
}

fn without(mut claims: Value, name: &str) -> Value {
    claims.as_object_mut().unwrap().remove(name);
    claims
}

#[test]
fn a_user_token_yields_every_claim() {
    let key = TestKey::generate();

    let token = verifier(&[&key])
        .verify(&Credential::new(key.sign(&user_claims())))
        .unwrap();

    assert_eq!(
        token.subject(),
        &SubjectId::User(Uuid::parse(USER_ID).unwrap())
    );
    assert_eq!(token.subject_kind(), SubjectKind::User);
    assert_eq!(token.session().unwrap().as_str(), "session-1");
    assert_eq!(token.token_id().as_str(), "token-1");
    assert_eq!(token.roles(), ["ROLE_USER".to_owned()]);
    assert_eq!(token.audiences(), [AUDIENCE.to_owned()]);
    assert_eq!(
        token.issued_at(),
        SystemTime::UNIX_EPOCH + Duration::from_secs(NOW)
    );
    assert_eq!(
        token.expires_at(),
        SystemTime::UNIX_EPOCH + Duration::from_secs(NOW + 900)
    );
}

#[test]
fn a_service_token_yields_the_service_principal() {
    let key = TestKey::generate();

    let token = verifier(&[&key])
        .verify(&Credential::new(key.sign(&service_claims())))
        .unwrap();

    assert_eq!(token.subject().to_string(), "user-service");
    assert_eq!(token.subject_kind(), SubjectKind::Service);
    assert_eq!(token.session().unwrap().as_str(), "service-session");
    assert_eq!(token.token_id().as_str(), "token-2");
    assert_eq!(token.roles(), ["ROLE_SERVICE".to_owned()]);
    assert_eq!(
        token.audiences(),
        [AUDIENCE.to_owned(), "vilnacrm-iam".to_owned()]
    );
}

#[rstest]
#[case::a_number(json!(7))]
#[case::a_list_of_numbers(json!([7, 8]))]
fn an_audience_that_is_neither_a_string_nor_a_list_of_strings_is_invalid(#[case] aud: Value) {
    let key = TestKey::generate();

    let outcome = verify(
        &verifier(&[&key]),
        &key.sign(&with(user_claims(), "aud", aud)),
    );

    assert_eq!(outcome, Err(TokenRejection::Invalid));
}

#[test]
fn a_token_without_roles_needs_no_session() {
    let key = TestKey::generate();
    let claims = without(without(user_claims(), "roles"), "sid");

    let token = verifier(&[&key])
        .verify(&Credential::new(key.sign(&claims)))
        .unwrap();

    assert_eq!(token.session(), None);
    assert_eq!(token.roles(), Vec::<String>::new());
    assert_eq!(token.subject_kind(), SubjectKind::User);
}

#[rstest]
#[case::empty("")]
#[case::blanks("   ")]
fn a_blank_credential_is_missing(#[case] raw: &str) {
    let key = TestKey::generate();

    assert_eq!(
        verify(&verifier(&[&key]), raw),
        Err(TokenRejection::Missing)
    );
}

#[rstest]
#[case::alg_none(json!({"alg": "none", "typ": "JWT"}))]
#[case::alg_es256(json!({"alg": "ES256", "typ": "JWT"}))]
#[case::alg_eddsa(json!({"alg": "EdDSA", "typ": "JWT"}))]
#[case::alg_unknown(json!({"alg": "XX999"}))]
#[case::not_an_object(json!("RS256"))]
fn a_header_with_another_algorithm_is_invalid(#[case] header: Value) {
    let key = TestKey::generate();

    let token = unsigned(&header, &user_claims());

    assert_eq!(
        verify(&verifier(&[&key]), &token),
        Err(TokenRejection::Invalid)
    );
}

#[rstest]
#[case(Algorithm::HS256)]
#[case(Algorithm::HS384)]
#[case(Algorithm::HS512)]
fn an_hmac_token_is_invalid_even_when_the_secret_is_the_public_key(#[case] algorithm: Algorithm) {
    let key = TestKey::generate();
    let secret = EncodingKey::from_secret(key.public_pem().as_bytes());

    let token = encode(&Header::new(algorithm), &user_claims(), &secret).unwrap();

    assert_eq!(
        verify(&verifier(&[&key]), &token),
        Err(TokenRejection::Invalid)
    );
}

#[rstest]
#[case(Algorithm::RS384)]
#[case(Algorithm::RS512)]
#[case(Algorithm::PS256)]
#[case(Algorithm::PS512)]
fn another_rsa_algorithm_is_invalid(#[case] algorithm: Algorithm) {
    let key = TestKey::generate();

    let token = key.sign_with(&Header::new(algorithm), &user_claims());

    assert_eq!(
        verify(&verifier(&[&key]), &token),
        Err(TokenRejection::Invalid)
    );
}

#[rstest]
#[case::jku("jku", json!("https://evil.example/keys"))]
#[case::x5u("x5u", json!("https://evil.example/cert"))]
#[case::x5c("x5c", json!(["MIIB"]))]
#[case::crit("crit", json!(["exp"]))]
#[case::jwk("jwk", json!({"kty": "RSA", "n": "AQAB", "e": "AQAB"}))]
fn a_header_naming_a_key_or_a_critical_extension_is_invalid(
    #[case] parameter: &str,
    #[case] value: Value,
) {
    let key = TestKey::generate();
    let mut header: Header = serde_json::from_value(json!({"alg": "RS256", "typ": "JWT"})).unwrap();
    let mut raw = serde_json::to_value(&header).unwrap();
    raw[parameter] = value;
    header = serde_json::from_value(raw).unwrap();

    let token = key.sign_with(&header, &user_claims());

    assert_eq!(
        verify(&verifier(&[&key]), &token),
        Err(TokenRejection::Invalid)
    );
}

#[rstest]
#[case::wrong_issuer(with(user_claims(), "iss", json!("league-oauth2")))]
#[case::no_issuer(without(user_claims(), "iss"))]
#[case::wrong_audience(with(user_claims(), "aud", json!("another-api")))]
#[case::no_audience(without(user_claims(), "aud"))]
#[case::no_sub(without(user_claims(), "sub"))]
#[case::empty_sub(with(user_claims(), "sub", json!("")))]
#[case::user_sub_not_a_uuid(with(user_claims(), "sub", json!("alice")))]
#[case::no_jti(without(user_claims(), "jti"))]
#[case::empty_jti(with(user_claims(), "jti", json!("")))]
#[case::roles_without_sid(without(user_claims(), "sid"))]
#[case::empty_sid(with(user_claims(), "sid", json!("")))]
#[case::service_sub_not_a_service_name(with(service_claims(), "sub", json!("User_Service")))]
#[case::service_sub_a_uuid(with(service_claims(), "sub", json!(USER_ID)))]
#[case::no_iat(without(user_claims(), "iat"))]
#[case::no_exp(without(user_claims(), "exp"))]
#[case::float_exp(with(user_claims(), "exp", json!(1_800_000_900.5)))]
#[case::string_iat(with(user_claims(), "iat", json!("1800000000")))]
fn a_token_breaking_a_claim_rule_is_invalid(#[case] claims: Value) {
    let key = TestKey::generate();

    let token = key.sign(&claims);

    assert_eq!(
        verify(&verifier(&[&key]), &token),
        Err(TokenRejection::Invalid)
    );
}

#[test]
fn a_token_signed_by_an_unknown_key_is_invalid() {
    let trusted = TestKey::generate();
    let stranger = TestKey::generate();

    let token = stranger.sign(&user_claims());

    assert_eq!(
        verify(&verifier(&[&trusted]), &token),
        Err(TokenRejection::Invalid)
    );
}

#[rstest]
#[case::not_a_jws("not-a-token")]
#[case::two_segments("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0")]
#[case::bad_signature_encoding("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.!!!")]
fn a_malformed_credential_is_invalid(#[case] raw: &str) {
    let key = TestKey::generate();

    assert_eq!(
        verify(&verifier(&[&key]), raw),
        Err(TokenRejection::Invalid)
    );
}

#[test]
fn an_expiry_beyond_the_skew_is_expired() {
    let key = TestKey::generate();
    let token = key.sign(&user_claims());

    assert!(verify(&verifier_at(&[&key], NOW + 930), &token).is_ok());
    assert_eq!(
        verify(&verifier_at(&[&key], NOW + 931), &token),
        Err(TokenRejection::Expired)
    );
}

#[rstest]
#[case::lifetime_above_the_maximum(with(user_claims(), "exp", json!(NOW + 901)))]
#[case::iat_beyond_the_skew(with(with(user_claims(), "iat", json!(NOW + 31)), "nbf", json!(NOW)))]
#[case::nbf_beyond_the_skew(with(user_claims(), "nbf", json!(NOW + 31)))]
fn a_token_breaking_the_lifetime_rule_is_invalid(#[case] claims: Value) {
    let key = TestKey::generate();

    let token = key.sign(&claims);

    assert_eq!(
        verify(&verifier(&[&key]), &token),
        Err(TokenRejection::Invalid)
    );
}

#[test]
fn a_token_of_the_oldest_of_three_keys_is_accepted_after_the_newer_ones() {
    let oldest = TestKey::generate();
    let middle = TestKey::generate();
    let newest = TestKey::generate();
    let verifier = verifier(&[&oldest, &middle, &newest]);

    assert_eq!(verifier.key_count(), 3);
    for key in [&oldest, &middle, &newest] {
        assert!(verify(&verifier, &key.sign(&user_claims())).is_ok());
    }
}

#[test]
fn a_verifier_without_a_key_file_keeps_its_keys() {
    let key = TestKey::generate();
    let verifier = verifier(&[&key]);

    assert!(verifier.reload().is_ok());
    assert!(!verifier.reload_if_changed());
    assert_eq!(verifier.key_count(), 1);
    assert_eq!(verifier.key_set_version(), 0);
}

#[test]
fn reload_puts_a_new_key_set_in_force_and_keeps_it_when_the_next_file_is_unparsable() {
    let first = TestKey::generate();
    let second = TestKey::generate();
    let path = scratch_dir("reload").join("keys.pem");
    std::fs::write(&path, first.public_pem()).unwrap();
    let verifier = JwtAccessTokenVerifier::from_file(&path, &settings(), clock_at(NOW)).unwrap();
    assert!(verify(&verifier, &first.sign(&user_claims())).is_ok());

    assert_eq!(verifier.key_set_version(), 0);
    std::fs::write(&path, key_file(&[&first, &second])).unwrap();
    verifier.reload().unwrap();
    assert_eq!(verifier.key_count(), 2);
    assert_eq!(verifier.key_set_version(), 1);
    assert!(verify(&verifier, &second.sign(&user_claims())).is_ok());

    std::fs::write(&path, "garbage").unwrap();
    let (recorder, guard) = LogRecorder::install();
    assert!(verifier.reload().is_err());
    drop(guard);

    assert_eq!(verifier.key_count(), 2);
    assert_eq!(verifier.current_key_set_version(), 1);
    assert!(verify(&verifier, &second.sign(&user_claims())).is_ok());
    let lines = recorder.lines();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].level, tracing::Level::ERROR);
    assert_eq!(
        lines[0].field("error"),
        Some("the key file holds no PEM key")
    );
}

#[test]
fn reload_if_changed_reads_the_file_only_after_it_changed() {
    let key = TestKey::generate();
    let path = scratch_dir("changed").join("keys.pem");
    std::fs::write(&path, key.public_pem()).unwrap();
    let verifier = JwtAccessTokenVerifier::from_file(&path, &settings(), clock_at(NOW)).unwrap();

    assert!(!verifier.reload_if_changed());
    std::fs::write(&path, key_file(&[&key, &key])).unwrap();
    assert!(verifier.reload_if_changed());
    assert_eq!(verifier.key_count(), 2);
    assert!(!verifier.reload_if_changed());
    assert_eq!(verifier.current_key_set_version(), 1);
}

#[test]
fn the_watch_reloads_a_replaced_key_file_and_stops_with_the_verifier() {
    let old = TestKey::generate();
    let new = TestKey::generate();
    let path = scratch_dir("watch").join("keys.pem");
    std::fs::write(&path, old.public_pem()).unwrap();
    let verifier =
        Arc::new(JwtAccessTokenVerifier::from_file(&path, &settings(), clock_at(NOW)).unwrap());
    let watch = verifier.watch(Duration::from_millis(10));
    let token = new.sign(&user_claims());

    std::fs::write(&path, key_file(&[&old, &new])).unwrap();
    let accepted = (0..500).any(|_| {
        std::thread::sleep(Duration::from_millis(10));
        verify(&verifier, &token).is_ok()
    });

    assert!(accepted);
    drop(verifier);
    watch.join().unwrap();
}

#[test]
fn a_missing_key_file_fails_at_startup() {
    let path = scratch_dir("missing").join("absent.pem");

    let built = JwtAccessTokenVerifier::from_file(&path, &settings(), clock_at(NOW));

    assert!(built.is_err());
}

#[test]
fn no_part_of_a_raw_token_reaches_the_debug_output_or_the_log() {
    let key = TestKey::generate();
    let verifier = verifier(&[&key]);
    let token = key.sign(&with(user_claims(), "iss", json!("forged")));
    let credential = Credential::new(token.clone());
    let (recorder, guard) = LogRecorder::install();

    let rejection = verifier.verify(&credential).unwrap_err();
    tracing::error!(credential = ?credential, rejection = %rejection, "token refused");
    drop(guard);

    let output = format!("{credential:?} {verifier:?} {:?}", recorder.lines());
    for part in token.split('.') {
        assert!(!output.contains(part), "{output}");
    }
}
