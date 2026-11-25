//! The framing rules of the public listener (Story 10.9, FR-67): a request whose length or path
//! can be read in two ways is answered 400 before the pipeline sees it.
//!
//! Hop-by-hop headers, including those a `Connection` header names, are removed by the forwarder
//! (`upstream`), so no request reaches an upstream with one.

use axum::extract::Request;
use axum::http::header::{CONTENT_LENGTH, TRANSFER_ENCODING};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse as _, Response};
use shared_application::http::Problem;

/// Why a request is refused as ambiguous.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FramingError {
    /// `Content-Length` and `Transfer-Encoding` are both present.
    #[error("the request carries both Content-Length and Transfer-Encoding")]
    LengthAndEncoding,
    /// `Content-Length` values differ or are not a plain number.
    #[error("the request carries conflicting or invalid Content-Length values")]
    ContentLength,
    /// The path is not an absolute path of printable characters.
    #[error("the request path is not valid")]
    Path,
}

/// Refuses the request when its framing is ambiguous.
///
/// # Errors
///
/// The first rule the request breaks: both length headers, conflicting `Content-Length` values, or
/// an invalid path.
pub fn check(parts: &Parts) -> Result<(), FramingError> {
    check_headers(&parts.headers)?;
    check_path(parts.uri.path())
}

fn check_headers(headers: &HeaderMap) -> Result<(), FramingError> {
    let length = content_length(headers)?;
    if length.is_some() && headers.contains_key(TRANSFER_ENCODING) {
        return Err(FramingError::LengthAndEncoding);
    }
    Ok(())
}

/// The one `Content-Length` value of the request, or the error when the values disagree.
fn content_length(headers: &HeaderMap) -> Result<Option<&str>, FramingError> {
    let mut seen: Option<&str> = None;
    for value in headers.get_all(CONTENT_LENGTH) {
        let text = value
            .to_str()
            .map_err(|_invalid| FramingError::ContentLength)?;
        for token in text.split(',').map(str::trim) {
            seen = merge(seen, token)?;
        }
    }
    Ok(seen)
}

fn merge<'value>(
    seen: Option<&'value str>,
    token: &'value str,
) -> Result<Option<&'value str>, FramingError> {
    if token.is_empty() || !token.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(FramingError::ContentLength);
    }
    match seen {
        Some(previous) if previous != token => Err(FramingError::ContentLength),
        _ => Ok(Some(token)),
    }
}

fn check_path(path: &str) -> Result<(), FramingError> {
    let printable = path
        .bytes()
        .all(|byte| byte.is_ascii_graphic() && byte != b'\\');
    if path.starts_with('/') && printable {
        Ok(())
    } else {
        Err(FramingError::Path)
    }
}

impl From<FramingError> for Response {
    fn from(error: FramingError) -> Self {
        let detail = match error {
            FramingError::LengthAndEncoding | FramingError::ContentLength => {
                "The request length is ambiguous."
            }
            FramingError::Path => "The request path is not valid.",
        };
        Problem::new(StatusCode::BAD_REQUEST)
            .with_detail(detail)
            .into_response()
    }
}

/// The middleware of the public router: an ambiguous request is answered 400.
pub async fn reject_ambiguous(request: Request, next: Next) -> Response {
    let (parts, body) = request.into_parts();
    match check(&parts) {
        Ok(()) => next.run(Request::from_parts(parts, body)).await,
        Err(error) => error.into(),
    }
}

#[cfg(test)]
mod tests;
