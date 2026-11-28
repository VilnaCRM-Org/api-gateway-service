//! The streams step of the pipeline (Story 11.1, FR-61).
//!
//! A route flagged `streaming` registers the stream it opens, after the decision allowed the
//! opening request and before the request is forwarded: a subject at its stream cap is refused
//! with 429 `connection_limit_exceeded` before any upgrade. The registration travels to the
//! forwarder as a request extension.
//!
//! The registry decides a stream again when the earliest assignment expiry behind it passes, and
//! when a published policy version touches it (Story 11.2). [`PipelineRedecision`] does that with
//! the decision rule of the pipeline: the route is matched again on the current snapshot, the
//! revocation sets of that snapshot are read for the token of the stream, and the authorizer
//! decides the caller again, so the answer is the one a new request of the same caller would get.
//! An operation of a GraphQL socket (Story 11.3) is decided again on its document as well.
//!
//! A stream is registered before it is forwarded, so the version that authorized it may be below
//! the published one by then. [`admit`] decides such a stream again right after its registration.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::http::request::Parts;
use iam_application::{
    Authorization, OperationVerdict, Principal, RequestAuthorizer, RouteRequest,
    SubscriptionAuthorizer,
};
use iam_domain::{
    AssignmentState, HttpMethod, PathNormalizer, PolicySnapshot, PolicyView, RevocationRule,
    RouteState, SubjectId, SubjectRef,
};
use iam_infrastructure::SnapshotRevocationView;
use shared_domain::Clock;

use super::{Refusal, host_of, route_for_host};
use crate::bootstrap::gateway::edge::SubjectClaims;
use crate::bootstrap::gateway::streams::{
    Grant, Redecision, Revalidated, StreamHandle, StreamRecord, Streams,
};

/// What registers a stream: the request, the route it matched and what decided it.
#[derive(Debug, Clone, Copy)]
pub(super) struct Opening<'request> {
    pub(super) parts: &'request Parts,
    pub(super) route: &'request RouteState,
    pub(super) snapshot: &'request Arc<dyn PolicySnapshot>,
    pub(super) principal: Option<&'request Principal>,
    pub(super) key: Option<&'request str>,
}

/// Registers the stream of a request on a route flagged `streaming`; any other request opens no
/// stream.
///
/// # Errors
///
/// [`Refusal::ConnectionLimit`] when the subject holds the most streams it may.
pub(super) fn register(
    streams: Option<&Arc<Streams>>,
    opening: &Opening<'_>,
) -> Result<Option<Arc<StreamHandle>>, Refusal> {
    let Some(streams) = streams.filter(|_| opening.route.fields.flags().streaming()) else {
        return Ok(None);
    };
    let record = record_of(opening, streams.now());
    let handle = streams
        .registry()
        .open(record, grant_of(opening))
        .map_err(|_capped| Refusal::ConnectionLimit)?;
    Ok(Some(Arc::new(holding(handle, opening.parts))))
}

/// The check that follows the registration of `stream`: a stream that was authorized on a version
/// below the published one is decided again at once, and closed when the published version denies
/// it. Any other request, and a route that opens no stream, costs nothing.
pub(super) async fn admit(streams: Option<&Arc<Streams>>, stream: Option<&Arc<StreamHandle>>) {
    if let (Some(streams), Some(stream)) = (streams, stream) {
        streams.admit(stream.id()).await;
    }
}

/// Hands the registration of the stream to the forwarder, as an extension of the request.
pub(super) fn attach(parts: &mut Parts, stream: Option<Arc<StreamHandle>>) {
    if let Some(stream) = stream {
        parts.extensions.insert(stream);
    }
}

/// The handle that keeps the connection slots of the subject, which the serve loop handed the
/// request, until the stream ends.
fn holding(mut handle: StreamHandle, parts: &Parts) -> StreamHandle {
    if let Some(claims) = parts.extensions.get::<Arc<SubjectClaims>>() {
        handle.hold(Arc::clone(claims));
    }
    handle
}

fn record_of(opening: &Opening<'_>, now: SystemTime) -> StreamRecord {
    let principal = opening.principal;
    StreamRecord {
        subject: principal.map(|principal| principal.subject().to_string()),
        session: principal
            .and_then(Principal::session)
            .map(|session| session.as_str().to_owned()),
        required_keys: opening.key.map(str::to_owned).into_iter().collect(),
        scope: "global".to_owned(),
        token_expires_at: principal.map(Principal::expires_at),
        assignment_expires_at: principal
            .and_then(|principal| earliest_expiry(opening.snapshot, principal, now)),
        version: opening.snapshot.version().value(),
        route: Some(opening.route.id),
        service: Some(opening.route.fields.service().clone()),
    }
}

fn grant_of(opening: &Opening<'_>) -> Grant {
    Grant {
        principal: opening.principal.cloned(),
        host: host_of(opening.parts).unwrap_or_default(),
        method: HttpMethod::parse(opening.parts.method.as_str()).unwrap_or(HttpMethod::Get),
        path: opening.parts.uri.path().to_owned(),
        operation: None,
    }
}

fn subject_ref(principal: &Principal) -> SubjectRef {
    match principal.subject() {
        SubjectId::User(id) => SubjectRef::user(*id),
        SubjectId::Service(name) => SubjectRef::service(name.clone()),
    }
}

/// The expiry of an assignment, which the decision rule reads the same way: a stamp before 1970 is
/// the epoch itself, which is expired.
fn expiry_of(state: &AssignmentState) -> Option<SystemTime> {
    let micros = state.expires_at_micros?;
    let elapsed = u64::try_from(micros).unwrap_or_default();
    SystemTime::UNIX_EPOCH.checked_add(Duration::from_micros(elapsed))
}

/// The earliest expiry that is still ahead among the assignments of the caller whose role the
/// snapshot knows; `None` when none of them expires.
pub(super) fn earliest_expiry(
    snapshot: &Arc<dyn PolicySnapshot>,
    principal: &Principal,
    now: SystemTime,
) -> Option<SystemTime> {
    snapshot
        .assignments(&subject_ref(principal))
        .iter()
        .filter(|state| snapshot.role_set(state.role).is_some())
        .filter_map(expiry_of)
        .filter(|at| *at > now)
        .min()
}

/// Decides a stream again with the decision rule of the pipeline, on the current snapshot.
#[derive(Debug)]
pub(super) struct PipelineRedecision {
    view: Arc<dyn PolicyView>,
    authorizer: Arc<RequestAuthorizer>,
    subscriptions: SubscriptionAuthorizer,
    clock: Arc<dyn Clock>,
}

impl PipelineRedecision {
    pub(super) fn new(
        view: Arc<dyn PolicyView>,
        authorizer: Arc<RequestAuthorizer>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            view,
            subscriptions: SubscriptionAuthorizer::new(Arc::clone(&authorizer)),
            authorizer,
            clock,
        }
    }

    /// The next expiry to look at when the current snapshot still allows the stream.
    async fn allowed(&self, grant: &Grant) -> Option<Option<SystemTime>> {
        let snapshot = self.view.current()?;
        let path = PathNormalizer::normalize(&grant.path).ok()?;
        let route = route_for_host(&snapshot, &grant.host, grant.method, &path)?;
        let Some(principal) = grant.principal.as_ref() else {
            return Some(None);
        };
        if revoked(snapshot.as_ref(), principal) {
            return None;
        }
        let request = RouteRequest {
            snapshot: &snapshot,
            service: route.fields.service(),
            enforcement: route.fields.enforcement(),
            method: grant.method,
            path: &path,
            request_id: None,
        };
        match self.authorizer.authorize(&request, principal).await {
            Authorization::Allowed(_) | Authorization::WouldDeny(_) => {}
            Authorization::Denied(_)
            | Authorization::Unavailable
            | Authorization::AuditUnavailable => return None,
        }
        if let Some(operation) = grant.operation.as_deref() {
            let verdict = self
                .subscriptions
                .authorize_operation(&request, principal, operation)
                .await;
            if !matches!(verdict, OperationVerdict::Allowed { .. }) {
                return None;
            }
        }
        Some(earliest_expiry(&snapshot, principal, self.clock.now()))
    }
}

/// Whether the revocation sets of `snapshot` revoke the token of `principal`: its session has a
/// record, or it was issued at or before the cut-off of its user or the global cut-off. A cut-off
/// that cannot be read revokes, since the stream cannot be proven allowed.
fn revoked(snapshot: &dyn PolicySnapshot, principal: &Principal) -> bool {
    let status =
        SnapshotRevocationView::status_of(snapshot, principal.session(), principal.subject());
    match status {
        Ok(status) => RevocationRule::revokes(principal.issued_at(), &status),
        Err(_unreadable) => true,
    }
}

#[async_trait::async_trait]
impl Redecision for PipelineRedecision {
    async fn decide(&self, grant: &Grant) -> Revalidated {
        self.allowed(grant)
            .await
            .map_or(Revalidated::Denied, |next_expiry| Revalidated::Allowed {
                next_expiry,
            })
    }

    fn published(&self) -> Option<i64> {
        self.view
            .current()
            .map(|snapshot| snapshot.version().value())
    }
}

#[cfg(test)]
mod tests;
