//! The GraphQL routes of the pipeline (Story 10.8, FR-8, FR-60).
//!
//! A route flagged `graphql` accepts `POST` only, so an operation never travels in a URL, and a
//! body of `application/json` only. The pipeline buffers the body up to the limit of the route,
//! decodes the envelope, has the [`RequestAuthorizer`](iam_application::RequestAuthorizer)
//! authorize every coordinate that the documents select, and forwards the original bytes: the
//! upstream reads exactly what was authorized.
//!
//! The envelope accepts the members `query`, `operationName`, `variables` and `extensions` and no
//! other, a `query` that is a non-empty string, and no `extensions.persistedQuery`, so no operation
//! reaches an upstream without a document that the gateway authorized. A top-level member given
//! twice is refused, because two parsers could read the two values differently. A JSON array is a
//! batch of at most [`MAX_BATCH_OPERATIONS`] operations.

use std::sync::Arc;

use super::access::Observed;
use super::{Matched, Pipeline, Refusal, permitted, route_of};
use axum::body::{Body, Bytes};
use axum::http::header::{ALLOW, CONTENT_TYPE};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse as _, Response};
use http_body_util::{BodyExt as _, LengthLimitError, Limited};
use iam_application::{
    Authorization, GraphQlAuthorization, GraphQlOperation, MAX_BATCH_OPERATIONS, Principal,
    TracedAuthorization,
};
use iam_domain::{HttpMethod, NormalizedPath, PolicySnapshot, RouteState};
use serde::de::{Error as _, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use shared_application::http::Problem;

/// The `type` of the 400 problem of a body that is not a GraphQL request the gateway accepts.
pub(super) const TYPE_MALFORMED_GRAPHQL_REQUEST: &str = "/problems/malformed_graphql_request";

/// The members of the envelope.
const MEMBERS: [&str; 4] = ["query", "operationName", "variables", "extensions"];

/// How long a subject over its parse budget is told to wait, in seconds.
const BUDGET_RETRY_SECONDS: u64 = 1;

/// Steps 5 to 7 for a GraphQL route: authentication, the policies that count by subject, the
/// body, and the authorization of every coordinate the documents select. The body that comes
/// back holds the bytes the client sent.
pub(super) async fn identify(
    pipeline: &Pipeline,
    matched: &Matched<'_>,
    body: Body,
    seen: &mut Observed,
) -> Result<(Option<Principal>, Body), Refusal> {
    let Matched {
        parts,
        route,
        request,
    } = *matched;
    let principal = pipeline.authenticate(request.snapshot, parts, seen).await?;
    super::cors::csrf(parts, request.method, route)?;
    super::rate_limit::subject(
        pipeline.rate_limits.as_ref(),
        parts,
        request.snapshot,
        route,
        &principal,
    )
    .await?;
    let body = authorize(pipeline, matched, &principal, body, seen).await?;
    Ok((Some(principal), body))
}

async fn authorize(
    pipeline: &Pipeline,
    matched: &Matched<'_>,
    principal: &Principal,
    body: Body,
    seen: &mut Observed,
) -> Result<Body, Refusal> {
    content_type(&matched.parts.headers)?;
    let bytes = buffer(body, matched.route.fields.body_limit().bytes()).await?;
    let operations = decode(&bytes)?;
    let decided = pipeline
        .authorizer
        .authorize_graphql(matched.request, principal, &operations)
        .await;
    match decided {
        GraphQlAuthorization::RateLimited => Err(Refusal::RateLimited(BUDGET_RETRY_SECONDS)),
        GraphQlAuthorization::Decided(traced) => {
            admit(traced, seen)?;
            Ok(Body::from(bytes))
        }
    }
}

/// Records what the decision knows and turns a refusal of it into the refusal of the request.
fn admit(traced: TracedAuthorization, seen: &mut Observed) -> Result<(), Refusal> {
    let TracedAuthorization {
        authorization,
        trace,
        denied,
        audit_slot,
    } = traced;
    seen.decision(trace, denied);
    seen.audit_mode(matches!(authorization, Authorization::WouldDeny(_)));
    seen.hold_audit_slot(audit_slot);
    permitted(authorization)
}

/// The route that serves `POST` on the path of a request that used another method, when it is a
/// GraphQL route: the request is answered 405 with `Allow: POST`.
pub(super) fn post_route<'snapshot>(
    snapshot: &'snapshot Arc<dyn PolicySnapshot>,
    parts: &Parts,
    method: HttpMethod,
    path: &NormalizedPath,
) -> Option<&'snapshot RouteState> {
    if method == HttpMethod::Post {
        return None;
    }
    route_of(snapshot, parts, HttpMethod::Post, path).filter(|route| route.fields.flags().graphql())
}

/// The parameters of the URL that carry a GraphQL operation: only the body is authorized, so an
/// upstream that read one of them could run an operation nobody authorized.
const OPERATION_PARAMETERS: [&str; 8] = [
    "query",
    "operationName",
    "variables",
    "extensions",
    "documentId",
    "queryId",
    "id",
    "doc_id",
];

/// 400 when the query string of a GraphQL route carries a parameter that names an operation. The
/// pairs are split on `&` and `;`, as some upstream frameworks do. The names are compared after percent-decoding and without regard to case, so no spelling slips by.
/// Other parameters are forwarded as they came.
pub(super) fn query_string(parts: &Parts) -> Result<(), Refusal> {
    let carries = parts.uri.query().is_some_and(|query| {
        query
            .split(['&', ';'])
            .filter_map(|pair| pair.split('=').next())
            .map(decode_component)
            .any(|name| {
                OPERATION_PARAMETERS
                    .iter()
                    .any(|parameter| parameter.eq_ignore_ascii_case(&name))
            })
    });
    if carries {
        Err(invalid(
            "A GraphQL operation is sent in the body, not in the query string.",
        ))
    } else {
        Ok(())
    }
}

/// A query-string name with `+` and `%XX` decoded; an escape that is not valid stays as written.
fn decode_component(component: &str) -> String {
    let mut parts = component.split('%');
    let mut decoded: Vec<u8> = parts.next().unwrap_or_default().bytes().collect();
    for part in parts {
        if let Some(value) = part
            .get(..2)
            .and_then(|pair| u8::from_str_radix(pair, 16).ok())
        {
            decoded.push(value);
            decoded.extend(part.get(2..).unwrap_or_default().bytes());
        } else {
            decoded.push(b'%');
            decoded.extend(part.bytes());
        }
    }
    let text = String::from_utf8_lossy(&decoded);
    text.replace('+', " ")
}

/// 415 unless the body is declared `application/json`, with or without parameters, and declared
/// once: two `Content-Type` headers could be read differently by the gateway and the upstream.
fn content_type(headers: &HeaderMap) -> Result<(), Refusal> {
    if headers.get_all(CONTENT_TYPE).iter().count() > 1 {
        return Err(Refusal::UnsupportedMediaType);
    }
    let declared = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    match declared {
        Some(media_type) if media_type.eq_ignore_ascii_case("application/json") => Ok(()),
        _ => Err(Refusal::UnsupportedMediaType),
    }
}

/// The body in memory: 413 when it is above `limit` bytes, 400 when it cannot be read.
async fn buffer(body: Body, limit: u64) -> Result<Bytes, Refusal> {
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    match Limited::new(body, limit).collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(error) if error.downcast_ref::<LengthLimitError>().is_some() => {
            Err(Refusal::PayloadTooLarge)
        }
        Err(_unreadable) => Err(Refusal::BadRequest("The request body cannot be read.")),
    }
}

/// An object whose members are all distinct: a member given twice is an error.
struct Distinct(Map<String, Value>);

impl<'de> Deserialize<'de> for Distinct {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(Members)
    }
}

/// Reads the members of an object one by one and refuses a repeated name.
struct Members;

impl<'de> Visitor<'de> for Members {
    type Value = Distinct;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Distinct, A::Error> {
        let mut members = Map::new();
        while let Some(name) = map.next_key::<String>()? {
            let value = map.next_value::<Value>()?;
            if members.insert(name, value).is_some() {
                return Err(A::Error::custom("a member is given twice"));
            }
        }
        Ok(Distinct(members))
    }
}

/// The operations of the body: one object, or an array of at most [`MAX_BATCH_OPERATIONS`].
fn decode(bytes: &[u8]) -> Result<Vec<GraphQlOperation>, Refusal> {
    let batch = bytes
        .iter()
        .find(|byte| !byte.is_ascii_whitespace())
        .is_some_and(|first| *first == b'[');
    let envelopes: Vec<Distinct> = if batch {
        serde_json::from_slice(bytes).map_err(|_error| invalid("The body is not valid JSON."))?
    } else {
        vec![
            serde_json::from_slice(bytes)
                .map_err(|_error| invalid("The body is not valid JSON."))?,
        ]
    };
    if envelopes.is_empty() || envelopes.len() > MAX_BATCH_OPERATIONS {
        return Err(invalid("A batch holds from 1 to 10 operations."));
    }
    envelopes
        .into_iter()
        .map(|Distinct(members)| operation(&members))
        .collect()
}

/// The operation of one envelope.
fn operation(members: &Map<String, Value>) -> Result<GraphQlOperation, Refusal> {
    if members.keys().any(|name| !MEMBERS.contains(&name.as_str())) {
        return Err(invalid(
            "The request has a member that GraphQL does not define.",
        ));
    }
    if persisted(members.get("extensions")) {
        return Err(invalid("Persisted queries are not accepted."));
    }
    let document = match members.get("query") {
        Some(Value::String(text)) if !text.is_empty() => text.clone(),
        _ => return Err(invalid("The query must be a non-empty string.")),
    };
    let operation_name = match members.get("operationName") {
        None | Some(Value::Null) => None,
        Some(Value::String(name)) => Some(name.clone()),
        Some(_other) => return Err(invalid("The operationName must be a string.")),
    };
    match members.get("variables") {
        None | Some(Value::Null | Value::Object(_)) => {}
        Some(_other) => return Err(invalid("The variables must be an object.")),
    }
    Ok(GraphQlOperation {
        document,
        operation_name,
    })
}

/// Whether `extensions` names a persisted query, or is not an object.
fn persisted(extensions: Option<&Value>) -> bool {
    match extensions {
        None | Some(Value::Null) => false,
        Some(Value::Object(members)) => members.contains_key("persistedQuery"),
        Some(_other) => true,
    }
}

const fn invalid(detail: &'static str) -> Refusal {
    Refusal::BadRequest(detail)
}

/// 400 `malformed_graphql_request`.
pub(super) fn bad_request(detail: &'static str) -> Response {
    Problem {
        r#type: TYPE_MALFORMED_GRAPHQL_REQUEST,
        ..Problem::new(StatusCode::BAD_REQUEST).with_detail(detail)
    }
    .into_response()
}

/// 405 with `Allow: POST`.
pub(super) fn method_not_allowed() -> Response {
    let mut response = Problem::new(StatusCode::METHOD_NOT_ALLOWED)
        .with_detail("A GraphQL operation is sent with POST.")
        .into_response();
    response
        .headers_mut()
        .insert(ALLOW, HeaderValue::from_static("POST"));
    response
}

/// 415.
pub(super) fn unsupported_media_type() -> Response {
    Problem::new(StatusCode::UNSUPPORTED_MEDIA_TYPE)
        .with_detail("A GraphQL request is application/json.")
        .into_response()
}

/// 413.
pub(super) fn payload_too_large() -> Response {
    Problem::new(StatusCode::PAYLOAD_TOO_LARGE)
        .with_detail("The request body is above the limit of the route.")
        .into_response()
}

#[cfg(test)]
mod tests;
