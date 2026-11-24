//! The extractors of the IAM handlers: the caller and the header extractors of the writes (FR-2);
//! their rejections are problem documents.

use axum::extract::FromRequestParts;
use axum::http::header::IF_MATCH;
use axum::http::request::Parts;
use axum::http::{HeaderName, HeaderValue};
use iam_domain::{EntityVersion, IdempotencyKey, InvalidIamValue, WriteMode};
use shared_application::http::{Problem, Violation};

use crate::error::IamError;
use crate::principal::Principal;

/// The authenticated caller of the request.
///
/// The authentication middleware of the composition root puts the [`Principal`] of a valid bearer
/// token into the request extensions; a request that reaches a handler without one is rejected
/// with the 401 problem ([`IamError::Unauthenticated`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerPrincipal(pub Principal);

impl<S> FromRequestParts<S> for CallerPrincipal
where
    S: Send + Sync,
{
    type Rejection = Problem;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Self::extract(parts))
    }
}

impl CallerPrincipal {
    /// Reads the principal of the request.
    fn extract(parts: &Parts) -> Result<Self, Problem> {
        parts
            .extensions
            .get::<Principal>()
            .cloned()
            .map(Self)
            .ok_or_else(|| Problem::from(IamError::Unauthenticated))
    }
}

/// The request header that carries the idempotency key of a write.
pub const IDEMPOTENCY_KEY: HeaderName = HeaderName::from_static("idempotency-key");

/// The optional `Idempotency-Key` header of a create, update or delete.
///
/// It is none when the request has no such header. A value that is not 1 to 255 visible ASCII
/// characters is rejected with a 422 problem that names the `idempotencyKey` property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdempotencyKeyHeader(pub Option<IdempotencyKey>);

impl<S> FromRequestParts<S> for IdempotencyKeyHeader
where
    S: Send + Sync,
{
    type Rejection = Problem;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Self::extract(parts))
    }
}

impl IdempotencyKeyHeader {
    /// Reads the header of the request.
    fn extract(parts: &Parts) -> Result<Self, Problem> {
        parts
            .headers
            .get(IDEMPOTENCY_KEY)
            .map(idempotency_key)
            .transpose()
            .map(Self)
    }
}

/// The key of a header value; a value that is not visible ASCII is an invalid key.
fn idempotency_key(value: &HeaderValue) -> Result<IdempotencyKey, Problem> {
    let text = value
        .to_str()
        .map_err(|_error| invalid(InvalidIamValue::IdempotencyKeyFormat))?;
    IdempotencyKey::new(text).map_err(invalid)
}

/// The 422 problem of one invalid value.
fn invalid(error: InvalidIamValue) -> Problem {
    Problem::validation_failed(vec![Violation {
        property_path: error.property_path().to_owned(),
        message: error.to_string(),
        code: error.code().to_owned(),
    }])
}

/// The `If-Match` header of an update or a delete.
///
/// It holds the entity version of the `ETag` the client read. A request without the header is rejected with the 428 problem
/// ([`IamError::PreconditionRequired`]); a value that is not exactly the strong `ETag` of a
/// version (`"<version>"`, as [`etag`](super::response::etag) writes it) can match no version and
/// is rejected with the 412 problem ([`IamError::PreconditionFailed`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IfMatchHeader(pub EntityVersion);

impl<S> FromRequestParts<S> for IfMatchHeader
where
    S: Send + Sync,
{
    type Rejection = Problem;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Self::extract(parts))
    }
}

impl IfMatchHeader {
    /// Reads the header of the request.
    fn extract(parts: &Parts) -> Result<Self, Problem> {
        let value = parts
            .headers
            .get(IF_MATCH)
            .ok_or(IamError::PreconditionRequired)?;
        let version = entity_version(value).ok_or(IamError::PreconditionFailed)?;
        Ok(Self(version))
    }
}

/// The headers of an update: the `If-Match` version and the optional `Idempotency-Key`.
///
/// A missing or unmatched `If-Match` is rejected first, as [`IfMatchHeader`] does; an invalid key
/// next, as [`IdempotencyKeyHeader`] does, and a `Prefer` wait mode that is not delivered last, as
/// [`PreferWaitHeader`] does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionedWriteHeaders {
    /// The version the client read.
    pub expected: EntityVersion,
    /// The idempotency key, when the request carries one.
    pub key: Option<IdempotencyKey>,
}

impl<S> FromRequestParts<S> for VersionedWriteHeaders
where
    S: Send + Sync,
{
    type Rejection = Problem;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Self::extract(parts))
    }
}

impl VersionedWriteHeaders {
    /// Reads both headers of the request.
    fn extract(parts: &Parts) -> Result<Self, Problem> {
        let IfMatchHeader(expected) = IfMatchHeader::extract(parts)?;
        let IdempotencyKeyHeader(key) = IdempotencyKeyHeader::extract(parts)?;
        PreferWaitHeader::extract(parts)?;
        Ok(Self { expected, key })
    }
}

/// The request header with which a write names what it waits for.
pub const PREFER: HeaderName = HeaderName::from_static("prefer");

/// The write mode of the `Prefer: wait=published|propagated` header of a write (FR-75).
///
/// A request without the preference waits for the Kafka acknowledgement (`published`). The mode
/// `propagated` is refused with the 422 problem that names it until the gateway pods report their
/// versions (Story 13.4); any other value is refused with the 422 problem too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreferWaitHeader(pub WriteMode);

impl<S> FromRequestParts<S> for PreferWaitHeader
where
    S: Send + Sync,
{
    type Rejection = Problem;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Self::extract(parts))
    }
}

impl PreferWaitHeader {
    /// Reads the header of the request.
    fn extract(parts: &Parts) -> Result<Self, Problem> {
        let requested = parts
            .headers
            .get_all(PREFER)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .filter_map(wait_preference)
            .next_back();
        let mode = match requested {
            None => WriteMode::Published,
            Some(text) => WriteMode::parse(&text.to_ascii_lowercase()).ok_or_else(|| {
                Problem::from(IamError::invalid_property(
                    "prefer",
                    "The wait preference must be `published` or `propagated`.",
                    "write_mode",
                ))
            })?,
        };
        supported_write_mode(mode, "prefer")
            .map(Self)
            .map_err(Problem::from)
    }
}

/// The value of a `wait=<value>` preference, none for any other preference.
fn wait_preference(preference: &str) -> Option<&str> {
    let (name, value) = preference.split_once('=')?;
    name.trim().eq_ignore_ascii_case("wait").then(|| {
        value
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .trim_matches('"')
    })
}

/// The mode itself when the service delivers it.
///
/// # Errors
///
/// [`IamError::Invalid`] with a violation of `property` that names the mode, for a mode that is not
/// delivered yet; REST (`prefer`) and GraphQL (`consistency`) share the refusal.
pub fn supported_write_mode(mode: WriteMode, property: &str) -> Result<WriteMode, IamError> {
    if mode.is_supported() {
        Ok(mode)
    } else {
        Err(IamError::invalid_property(
            property,
            &format!(
                "The write mode `{}` is not supported yet; use `published`.",
                mode.as_str()
            ),
            "write_mode_unsupported",
        ))
    }
}

/// The version of a strong `ETag`, none for any other text.
fn entity_version(value: &HeaderValue) -> Option<EntityVersion> {
    let digits = value.to_str().ok()?.strip_prefix('"')?.strip_suffix('"')?;
    let version = EntityVersion::new(digits.parse().ok()?).ok()?;
    (version.value().to_string() == digits).then_some(version)
}

#[cfg(test)]
mod tests;
