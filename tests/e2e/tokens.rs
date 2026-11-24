//! Ephemeral RSA keys and the User service tokens they sign for the scenarios.
//!
//! Nothing here is committed: each scenario that needs a token generates a key pair, writes the
//! public half to its own `JWT_PUBLIC_KEYS_FILE` and signs tokens with the private half, so no key
//! or token outlives the run.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::encoding::{AsDer as _, Pkcs8V1Der, PublicKeyX509Der};
use aws_lc_rs::rsa::{KeyPair, KeySize};
use aws_lc_rs::signature::KeyPair as _;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};
use shared_domain::Clock as _;
use shared_infrastructure::clock::SystemClock;

/// The issuer and the audience of the defaults of `JWT_ISSUER` and `JWT_AUDIENCE`.
const ISSUER: &str = "vilnacrm-user-service";
const AUDIENCE: &str = "vilnacrm-api";
/// The default of `JWT_CALLER_AUDIENCE`.
const CALLER_AUDIENCE: &str = "vilnacrm-iam";

/// The user that the subject tokens of the scenarios name.
pub(crate) const USER_ID: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";
/// The administrator that the caller tokens of the scenarios name; the scenario policy gives it
/// the keys of the bootstrapped `iam-platform-admin` role (see `administrator_policy`).
pub(crate) const ADMINISTRATOR_ID: &str = "0190f2a8-7b3c-7d4e-8f10-00000000ad02";
/// A service caller that holds no IAM key, for the scenarios of the authorization rule.
pub(crate) const UNPRIVILEGED_SERVICE: &str = "e2e-unprivileged-caller";

/// An RSA key pair: the private half signs, the public half goes into a key file.
pub(crate) struct SigningKey {
    encoding: EncodingKey,
    public_pem: String,
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey").finish_non_exhaustive()
    }
}

impl SigningKey {
    /// A fresh 2048-bit key pair.
    pub(crate) fn generate() -> Self {
        let pair = KeyPair::generate(KeySize::Rsa2048).expect("generate an RSA key");
        let private: Pkcs8V1Der<'_> = pair.as_der().expect("encode the private key");
        let public: PublicKeyX509Der<'_> =
            pair.public_key().as_der().expect("encode the public key");
        let private_pem = pem::encode(&pem::Pem::new("PRIVATE KEY", private.as_ref().to_vec()));
        Self {
            encoding: EncodingKey::from_rsa_pem(private_pem.as_bytes())
                .expect("the private key is valid"),
            public_pem: pem::encode(&pem::Pem::new("PUBLIC KEY", public.as_ref().to_vec())),
        }
    }

    /// The public half in PEM form: the content of a `JWT_PUBLIC_KEYS_FILE`.
    pub(crate) fn public_pem(&self) -> &str {
        &self.public_pem
    }

    /// An RS256 token with these claims.
    fn sign(&self, claims: &Value) -> String {
        encode(&Header::new(Algorithm::RS256), claims, &self.encoding).expect("sign the token")
    }

    /// A `ROLE_USER` token of [`USER_ID`] in `session`, issued now and valid for 10 minutes.
    pub(crate) fn user_token(&self, session: &str) -> String {
        self.sign(&user_claims(USER_ID, session, 0, 600))
    }

    /// A `ROLE_USER` token of [`USER_ID`] in `session` that expired 10 minutes ago, far beyond the
    /// clock skew, with a lifetime within the maximum.
    pub(crate) fn expired_user_token(&self, session: &str) -> String {
        self.sign(&user_claims(USER_ID, session, -1200, -600))
    }

    /// A `ROLE_USER` token of [`ADMINISTRATOR_ID`], the bootstrapped administrator, issued now and
    /// valid for 10 minutes: what an operator presents to call IAM.
    pub(crate) fn administrator_token(&self) -> String {
        self.sign(&user_claims(
            ADMINISTRATOR_ID,
            "e2e-administrator-session",
            0,
            600,
        ))
    }

    /// A `ROLE_SERVICE` token of [`UNPRIVILEGED_SERVICE`] that names the IAM caller audience and
    /// lives for 10 minutes; the service holds no IAM key.
    pub(crate) fn unprivileged_caller_token(&self) -> String {
        self.service_token(UNPRIVILEGED_SERVICE)
    }

    /// A `ROLE_SERVICE` token of `service` with the IAM caller audience, valid for 10 minutes.
    fn service_token(&self, service: &str) -> String {
        let now = seconds_from_now(0);
        self.sign(&json!({
            "iss": ISSUER,
            "aud": [AUDIENCE, CALLER_AUDIENCE],
            "sub": service,
            "sid": format!("{service}-session"),
            "jti": format!("{service}-token"),
            "roles": ["ROLE_SERVICE"],
            "iat": now,
            "nbf": now,
            "exp": seconds_from_now(600),
        }))
    }
}

/// The claims of a `ROLE_USER` token of `subject` that was issued `issued` seconds from now and
/// expires `expires` seconds from now.
fn user_claims(subject: &str, session: &str, issued: i64, expires: i64) -> Value {
    json!({
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": subject,
        "sid": session,
        "jti": format!("e2e-token-{session}"),
        "roles": ["ROLE_USER"],
        "iat": seconds_from_now(issued),
        "nbf": seconds_from_now(issued),
        "exp": seconds_from_now(expires),
    })
}

/// Whole seconds since 1970, `offset` seconds from now.
fn seconds_from_now(offset: i64) -> i64 {
    let now = SystemClock
        .now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is after 1970");
    let now = i64::try_from(now.as_secs()).expect("the clock fits in i64");
    now.saturating_add(offset)
}

/// The instant `offset` from now, for the records a step writes directly.
pub(crate) fn instant_after(offset: Duration) -> SystemTime {
    SystemClock
        .now()
        .checked_add(offset)
        .expect("the instant is representable")
}
