//! [`AccessTokenVerifier`] for RS256 User service tokens, with hot-reloaded public keys.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock, Weak};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};

use iam_domain::{
    AccessToken, AccessTokenParts, AccessTokenVerifier, Credential, ServiceName, SessionId,
    SubjectId, TokenId, TokenLifetimeRule, TokenRejection, TokenTimes,
};
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{Algorithm, Header, TokenData, Validation, decode, decode_header};
use serde::Deserialize;
use shared_domain::{Clock, Uuid};

use crate::token::jwt_key_set::{JwtKeyFileError, JwtKeySet};

/// The role that marks a service principal's token.
const ROLE_SERVICE: &str = "ROLE_SERVICE";

/// What a token must name besides its signature and time claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JwtSettings {
    /// The required `iss` (`JWT_ISSUER`).
    pub issuer: String,
    /// The audience `aud` must contain (`JWT_AUDIENCE`).
    pub audience: String,
    /// `MAX_TOKEN_LIFETIME` and `JWT_CLOCK_SKEW`.
    pub lifetime: TokenLifetimeRule,
}

/// Verifies compact RS256 JWS tokens offline against the keys of `JWT_PUBLIC_KEYS_FILE`.
///
/// The header must name `RS256` and carry none of `jwk`, `jku`, `x5u`, `x5c` and `crit`; `iss` and
/// `aud` must match; `sub`, `jti`, integer `iat` and `exp` are required, `sid` whenever `roles` is
/// present, and a `ROLE_SERVICE` token's `sub` must be a service name. The time claims are checked
/// by [`TokenLifetimeRule`] against the `Clock` port, never against the system time.
#[derive(Debug)]
pub struct JwtAccessTokenVerifier {
    keys: RwLock<Arc<JwtKeySet>>,
    key_set_version: AtomicU64,
    source: Option<KeySource>,
    validation: Validation,
    lifetime: TokenLifetimeRule,
    clock: Arc<dyn Clock>,
}

/// The key file and the fingerprint of the version last read.
#[derive(Debug)]
struct KeySource {
    path: PathBuf,
    seen: Mutex<Option<Fingerprint>>,
}

/// What changes when the key file is replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Fingerprint {
    modified: Option<SystemTime>,
    length: u64,
}

impl Fingerprint {
    fn of(path: &Path) -> Option<Self> {
        std::fs::metadata(path).ok().map(|metadata| Self {
            modified: metadata.modified().ok(),
            length: metadata.len(),
        })
    }
}

/// The claims a User service token carries.
#[derive(Debug, Deserialize)]
struct Claims {
    sub: Option<String>,
    jti: Option<String>,
    sid: Option<String>,
    roles: Option<Vec<String>>,
    iat: u64,
    nbf: Option<u64>,
    exp: u64,
}

impl JwtAccessTokenVerifier {
    /// A verifier over a fixed key set, without a key file to reload.
    #[must_use]
    pub fn new(keys: JwtKeySet, settings: &JwtSettings, clock: Arc<dyn Clock>) -> Self {
        Self::build(keys, None, settings, clock)
    }

    /// A verifier over the keys of `path`, which [`Self::reload`] and [`Self::watch`] read again.
    ///
    /// # Errors
    ///
    /// Returns the [`JwtKeyFileError`] of the file, because the service must not start without a
    /// valid key set.
    pub fn from_file(
        path: &Path,
        settings: &JwtSettings,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, JwtKeyFileError> {
        let fingerprint = Fingerprint::of(path);
        let keys = JwtKeySet::load(path)?;
        let source = KeySource {
            path: path.to_path_buf(),
            seen: Mutex::new(fingerprint),
        };
        Ok(Self::build(keys, Some(source), settings, clock))
    }

    fn build(
        keys: JwtKeySet,
        source: Option<KeySource>,
        settings: &JwtSettings,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.set_issuer(&[settings.issuer.as_str()]);
        validation.set_audience(&[settings.audience.as_str()]);
        validation.set_required_spec_claims(&["iss", "aud"]);
        Self {
            keys: RwLock::new(Arc::new(keys)),
            key_set_version: AtomicU64::new(0),
            source,
            validation,
            lifetime: settings.lifetime,
            clock,
        }
    }

    /// The number of keys in force.
    #[must_use]
    pub fn key_count(&self) -> usize {
        self.current_keys().len()
    }

    /// The number of key sets put in force after the first one.
    #[must_use]
    pub fn current_key_set_version(&self) -> u64 {
        self.key_set_version.load(Ordering::Acquire)
    }

    /// Reads the key file again and puts its keys in force; a verifier without a key file keeps
    /// its keys.
    ///
    /// # Errors
    ///
    /// Returns the [`JwtKeyFileError`] of the file; the last valid key set stays in force and the
    /// failure is logged at error level.
    pub fn reload(&self) -> Result<(), JwtKeyFileError> {
        let Some(source) = &self.source else {
            return Ok(());
        };
        *source.seen.lock().unwrap_or_else(PoisonError::into_inner) = Fingerprint::of(&source.path);
        let keys = JwtKeySet::load(&source.path).inspect_err(log_failed_reload)?;
        log_reload(&keys);
        *self.keys.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(keys);
        self.key_set_version.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    /// Reloads the key file when its modification time or length changed since the last read.
    ///
    /// Returns whether a reload was attempted.
    pub fn reload_if_changed(&self) -> bool {
        let Some(source) = &self.source else {
            return false;
        };
        let current = Fingerprint::of(&source.path);
        let seen = *source.seen.lock().unwrap_or_else(PoisonError::into_inner);
        if current == seen {
            return false;
        }
        let _outcome = self.reload().is_ok();
        true
    }

    /// Starts a thread that checks the key file every `interval` and reloads it when it changed.
    ///
    /// The thread ends after the last `Arc` of the verifier is dropped.
    #[must_use]
    pub fn watch(self: &Arc<Self>, interval: Duration) -> JoinHandle<()> {
        let verifier = Arc::downgrade(self);
        std::thread::spawn(move || watch_loop(&verifier, interval))
    }

    fn current_keys(&self) -> Arc<JwtKeySet> {
        Arc::clone(&self.keys.read().unwrap_or_else(PoisonError::into_inner))
    }

    fn verify_token(&self, credential: &Credential) -> Result<AccessToken, TokenRejection> {
        if credential.is_blank() {
            return Err(TokenRejection::Missing);
        }
        let token = credential.expose();
        let header = decode_header(token).map_err(|_error| TokenRejection::Invalid)?;
        check_header(&header)?;
        let claims = self.decode_claims(token)?.claims;
        let times = TokenTimes {
            issued_at: claims.iat,
            not_before: claims.nbf,
            expires_at: claims.exp,
        };
        self.lifetime.check(times, self.clock.now())?;
        access_token(claims)
    }

    /// Tries the keys newest first; only a signature mismatch moves on to the next key.
    fn decode_claims(&self, token: &str) -> Result<TokenData<Claims>, TokenRejection> {
        let keys = self.current_keys();
        for key in keys.newest_first() {
            match decode::<Claims>(token, key, &self.validation) {
                Ok(data) => return Ok(data),
                Err(error) if matches!(error.kind(), ErrorKind::InvalidSignature) => {}
                Err(_error) => return Err(TokenRejection::Invalid),
            }
        }
        Err(TokenRejection::Invalid)
    }
}

impl AccessTokenVerifier for JwtAccessTokenVerifier {
    fn verify(&self, credential: &Credential) -> Result<AccessToken, TokenRejection> {
        self.verify_token(credential)
    }

    fn key_set_version(&self) -> u64 {
        self.current_key_set_version()
    }
}

fn log_reload(keys: &JwtKeySet) {
    tracing::info!(keys = keys.len(), "reloaded the JWT public keys");
}

fn log_failed_reload(error: &JwtKeyFileError) {
    tracing::error!(
        error = %error,
        "the JWT public key file cannot be reloaded; the last valid key set stays in force"
    );
}

fn watch_loop(verifier: &Weak<JwtAccessTokenVerifier>, interval: Duration) {
    loop {
        std::thread::sleep(interval);
        let Some(verifier) = verifier.upgrade() else {
            break;
        };
        verifier.reload_if_changed();
    }
}

/// Only `RS256`, and no header parameter that names a key or a critical extension.
fn check_header(header: &Header) -> Result<(), TokenRejection> {
    let names_a_key = header.jwk.is_some()
        || header.jku.is_some()
        || header.x5u.is_some()
        || header.x5c.is_some();
    if header.alg != Algorithm::RS256 || names_a_key || header.crit.is_some() {
        return Err(TokenRejection::Invalid);
    }
    Ok(())
}

fn access_token(claims: Claims) -> Result<AccessToken, TokenRejection> {
    let sub = claims
        .sub
        .filter(|sub| !sub.is_empty())
        .ok_or(TokenRejection::Invalid)?;
    let token_id = TokenId::new(claims.jti.as_deref().unwrap_or_default())?;
    let roles = claims.roles;
    let session = match (claims.sid.as_deref(), roles.is_some()) {
        (Some(sid), _) => Some(SessionId::new(sid)?),
        (None, true) => return Err(TokenRejection::Invalid),
        (None, false) => None,
    };
    let roles = roles.unwrap_or_default();
    let subject = if roles.iter().any(|role| role == ROLE_SERVICE) {
        SubjectId::Service(ServiceName::new(&sub).map_err(|_error| TokenRejection::Invalid)?)
    } else {
        SubjectId::User(Uuid::parse(&sub).map_err(|_error| TokenRejection::Invalid)?)
    };
    Ok(AccessToken::new(AccessTokenParts {
        subject,
        session,
        token_id,
        roles,
        issued_at: instant(claims.iat)?,
        expires_at: instant(claims.exp)?,
    }))
}

fn instant(seconds: u64) -> Result<SystemTime, TokenRejection> {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .ok_or(TokenRejection::Invalid)
}

#[cfg(test)]
mod tests;
