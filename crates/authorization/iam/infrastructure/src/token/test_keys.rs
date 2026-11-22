//! RSA keys generated at test time and the tokens they sign.

use aws_lc_rs::encoding::{AsDer as _, Pkcs8V1Der, PublicKeyX509Der};
use aws_lc_rs::rsa::{KeyPair, KeySize};
use aws_lc_rs::signature::KeyPair as _;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};

pub(crate) const ISSUER: &str = "vilnacrm-user-service";
pub(crate) const AUDIENCE: &str = "vilnacrm-api";
pub(crate) const USER_ID: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";
/// 2027-01-15T08:00:00Z, the controlled `Clock` of the tests.
pub(crate) const NOW: u64 = 1_800_000_000;

/// An RSA key pair: the private half signs, the public half goes into a key file.
pub(crate) struct TestKey {
    encoding: EncodingKey,
    public_pem: String,
}

impl TestKey {
    pub(crate) fn generate() -> Self {
        let pair = KeyPair::generate(KeySize::Rsa2048).unwrap();
        let private: Pkcs8V1Der<'_> = pair.as_der().unwrap();
        let public: PublicKeyX509Der<'_> = pair.public_key().as_der().unwrap();
        let private_pem = pem("PRIVATE KEY", private.as_ref());
        Self {
            encoding: EncodingKey::from_rsa_pem(private_pem.as_bytes()).unwrap(),
            public_pem: pem("PUBLIC KEY", public.as_ref()),
        }
    }

    pub(crate) fn public_pem(&self) -> &str {
        &self.public_pem
    }

    /// A token with this header and these claims, signed with this key.
    pub(crate) fn sign_with(&self, header: &Header, claims: &Value) -> String {
        encode(header, claims, &self.encoding).unwrap()
    }

    /// An RS256 token with these claims.
    pub(crate) fn sign(&self, claims: &Value) -> String {
        self.sign_with(&Header::new(Algorithm::RS256), claims)
    }
}

/// The public halves of `keys` as one key file, in the given order.
pub(crate) fn key_file(keys: &[&TestKey]) -> String {
    keys.iter().map(|key| key.public_pem()).collect()
}

/// The claims of a valid `ROLE_USER` token issued at [`NOW`].
pub(crate) fn user_claims() -> Value {
    json!({
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": USER_ID,
        "sid": "session-1",
        "jti": "token-1",
        "roles": ["ROLE_USER"],
        "iat": NOW,
        "nbf": NOW,
        "exp": NOW + 900,
    })
}

/// The claims of a valid `ROLE_SERVICE` token issued at [`NOW`].
pub(crate) fn service_claims() -> Value {
    json!({
        "iss": ISSUER,
        "aud": [AUDIENCE, "vilnacrm-iam"],
        "sub": "user-service",
        "sid": "service-session",
        "jti": "token-2",
        "roles": ["ROLE_SERVICE"],
        "iat": NOW,
        "exp": NOW + 600,
    })
}

/// A token with a raw header and claims and a meaningless signature.
pub(crate) fn unsigned(header: &Value, claims: &Value) -> String {
    format!(
        "{}.{}.c2lnbmF0dXJl",
        base64(header.to_string().as_bytes(), URL_SAFE, false),
        base64(claims.to_string().as_bytes(), URL_SAFE, false)
    )
}

const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn pem(label: &str, der: &[u8]) -> String {
    let body = base64(der, STANDARD, true);
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect();
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        lines.join("\n")
    )
}

/// The left shift of each byte of a three-byte group within its 24-bit value.
const BYTE_SHIFTS: [u32; 3] = [16, 8, 0];
/// The right shift of each of the four sextets of a 24-bit value.
const SEXTET_SHIFTS: [u32; 4] = [18, 12, 6, 0];

fn base64(bytes: &[u8], alphabet: &[u8; 64], padded: bool) -> String {
    let mut text = String::new();
    for chunk in bytes.chunks(3) {
        let triple = chunk
            .iter()
            .zip(BYTE_SHIFTS)
            .fold(0_u32, |acc, (byte, shift)| {
                acc | (u32::from(*byte) << shift)
            });
        for (index, shift) in SEXTET_SHIFTS.into_iter().enumerate() {
            if index <= chunk.len() {
                let sextet = (triple >> shift) & 0x3f;
                text.push(char::from(alphabet[usize::try_from(sextet).unwrap()]));
            } else if padded {
                text.push('=');
            }
        }
    }
    text
}

/// A fresh directory for the files of one test.
pub(crate) fn scratch_dir(name: &str) -> std::path::PathBuf {
    let directory = std::env::temp_dir().join(format!("iam-jwt-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    directory
}
