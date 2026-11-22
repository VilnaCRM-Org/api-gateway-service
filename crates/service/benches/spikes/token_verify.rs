//! RS256 verification of a User service access token with one and with three trusted keys, tried
//! newest first as the gateway tries them.
//!
//! The RSA key pairs are generated through `aws-lc-rs` when the bench starts (ADR 0023: the
//! test-key crate is `aws-lc-rs`, never `rsa`, while RUSTSEC-2023-0071 is open); verification goes
//! through `jsonwebtoken` with its `aws_lc_rs` backend.

use std::hint::black_box;
use std::io::Write;

use aws_lc_rs::encoding::{AsDer as _, Pkcs8V1Der};
use aws_lc_rs::rsa::{KeyPair, KeySize};
use aws_lc_rs::signature::{KeyPair as _, RsaPublicKeyComponents};
use criterion::Criterion;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde_json::{Value, json};

use crate::{SpikeError, latency};

/// The criterion group and the prefix of every result line.
const GROUP: &str = "rs256_verify";
const ISSUER: &str = "vilnacrm-user-service";
const AUDIENCE: &str = "vilnacrm-api";
/// 2026-01-01T00:00:00Z.
const ISSUED_AT: u64 = 1_767_225_600;
/// 2100-01-01T00:00:00Z: far enough ahead that `exp` never fails during a run.
const EXPIRES_AT: u64 = 4_102_444_800;

/// A token and the trusted keys it is verified against.
struct Case {
    name: &'static str,
    token: String,
    /// Newest first, the order in which the gateway tries them.
    keys: Vec<DecodingKey>,
}

/// One generated RSA key pair, in the forms `jsonwebtoken` signs and verifies with.
struct GeneratedKey {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

/// The verify cases and the validation rules they share.
pub(crate) struct Fixture {
    cases: [Case; 3],
    validation: Validation,
}

impl Fixture {
    /// Generates three RSA-2048 key pairs and signs the tokens of the three cases:
    /// one trusted key; three keys with the newest signing (one signature check); three keys with
    /// the oldest signing (two failed signature checks, then the match).
    pub(crate) fn generate() -> Result<Self, SpikeError> {
        let oldest = generate_key()?;
        let middle = generate_key()?;
        let newest = generate_key()?;
        let newest_token = sign(&newest.encoding)?;
        let oldest_token = sign(&oldest.encoding)?;
        let three_keys = vec![newest.decoding.clone(), middle.decoding, oldest.decoding];
        Ok(Self {
            cases: [
                Case {
                    name: "one_key",
                    token: newest_token.clone(),
                    keys: vec![newest.decoding],
                },
                Case {
                    name: "three_keys_newest_signs",
                    token: newest_token,
                    keys: three_keys.clone(),
                },
                Case {
                    name: "three_keys_oldest_signs",
                    token: oldest_token,
                    keys: three_keys,
                },
            ],
            validation: validation(),
        })
    }

    /// Fails unless every case's token verifies, so that no figure measures a rejection.
    pub(crate) fn check(&self) -> Result<(), SpikeError> {
        self.cases.iter().try_for_each(|case| {
            verify(&case.token, &case.keys, &self.validation)
                .map(drop)
                .ok_or(SpikeError::NoKeyVerified(case.name))
        })
    }

    /// Registers one criterion benchmark per case.
    pub(crate) fn bench(&self, criterion: &mut Criterion) {
        let mut group = criterion.benchmark_group(GROUP);
        for case in &self.cases {
            group.bench_function(case.name, |bencher| {
                bencher.iter(|| verify(black_box(&case.token), &case.keys, &self.validation));
            });
        }
        group.finish();
    }

    /// Writes the median and the p99 per verification of every case.
    pub(crate) fn report<W: Write>(&self, out: &mut W) -> Result<(), SpikeError> {
        for case in &self.cases {
            let percentiles =
                latency::measure(|| verify(black_box(&case.token), &case.keys, &self.validation))
                    .ok_or(SpikeError::TooFewSamples(case.name))?;
            latency::write(out, GROUP, case.name, percentiles)?;
        }
        Ok(())
    }
}

/// The claims of the first key, newest first, whose signature and claims accept `token`.
fn verify(token: &str, keys: &[DecodingKey], validation: &Validation) -> Option<Value> {
    keys.iter()
        .find_map(|key| decode::<Value>(token, key, validation).ok())
        .map(|data| data.claims)
}

/// The rules of the gateway: RS256 only, the User service issuer and the API audience.
fn validation() -> Validation {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&[AUDIENCE]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    validation
}

/// A fresh RSA-2048 key pair from `aws-lc-rs`; the private half never leaves memory.
fn generate_key() -> Result<GeneratedKey, SpikeError> {
    let pair = KeyPair::generate(KeySize::Rsa2048)?;
    let private: Pkcs8V1Der<'static> = pair.as_der()?;
    let private_pem = pem::encode(&pem::Pem::new("PRIVATE KEY", private.as_ref()));
    let public = RsaPublicKeyComponents::<Vec<u8>>::from(pair.public_key());
    Ok(GeneratedKey {
        encoding: EncodingKey::from_rsa_pem(private_pem.as_bytes())?,
        decoding: DecodingKey::from_rsa_raw_components(&public.n, &public.e),
    })
}

/// An RS256 access token with the claims of a `ROLE_USER` session, signed with `key`.
fn sign(key: &EncodingKey) -> Result<String, SpikeError> {
    let claims = json!({
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "0190f2a8-7b3c-7d4e-8f10-1234567890ab",
        "sid": "session-1",
        "jti": "token-1",
        "roles": ["ROLE_USER"],
        "iat": ISSUED_AT,
        "nbf": ISSUED_AT,
        "exp": EXPIRES_AT,
    });
    Ok(encode(&Header::new(Algorithm::RS256), &claims, key)?)
}
