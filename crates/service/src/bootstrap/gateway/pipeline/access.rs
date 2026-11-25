//! The access record of the pipeline: the last step, after the response (Story 14.1, FR-50).
//!
//! The pipeline collects what it learns about a request while it decides it, in [`Observed`], and
//! hands the facts to the [`AccessRecorder`] once the response is built. Recording never waits and
//! never changes the response: the channel send of the recorder fails by dropping and counting.
//!
//! A record holds the route template and never the concrete path, the first 8 hexadecimal
//! characters of the credential digest and never the credential, and no cookie, header or body.

use std::sync::Arc;

use axum::http::header::CONTENT_LENGTH;
use axum::http::request::Parts;
use axum::http::{HeaderMap, Response};
use iam_application::{
    AccessFacts, AccessRecorder, DecisionTrace, RequestFacts, ResponseFacts, RouteFacts,
    VerdictFacts,
};
use iam_domain::{
    Decision, DecisionReason, PolicySnapshot, RouteState, SubjectId, TokenIdentity, TokenRejection,
};
use iam_infrastructure::credential_digest_prefix;
use shared_domain::{Clock, UuidGenerator};
use tokio::time::Instant;

use crate::http::authentication::credential;
use crate::http::request_id::REQUEST_ID_HEADER;

/// What the pipeline learned about a request while it decided it.
#[derive(Debug, Default)]
pub(super) struct Observed {
    route: Option<RouteFacts>,
    subject: Option<SubjectId>,
    token_refusal: Option<DecisionReason>,
    policy_version: Option<i64>,
    trace: DecisionTrace,
    denied: Vec<String>,
}

impl Observed {
    /// The snapshot that the request is decided on.
    pub(super) fn snapshot(&mut self, snapshot: &Arc<dyn PolicySnapshot>) {
        self.policy_version = Some(snapshot.version().value());
    }

    /// The route the request matched and the registered name of its upstream.
    pub(super) fn route(&mut self, snapshot: &Arc<dyn PolicySnapshot>, route: &RouteState) {
        let upstream = snapshot
            .upstream_by_id(route.fields.upstream_id())
            .map(|upstream| upstream.name.to_string());
        self.route = Some(RouteFacts {
            id: Some(route.id.as_uuid()),
            template: route.fields.path_pattern().as_str().to_owned(),
            upstream,
        });
    }

    /// The outcome of resolving the token: the subject it proved or why it was refused.
    pub(super) fn token(&mut self, resolved: &Result<TokenIdentity, TokenRejection>) {
        match resolved {
            Ok(identity) => self.subject = Some(identity.subject().clone()),
            Err(rejection) => self.token_refusal = Some(DecisionReason::from(*rejection)),
        }
    }

    /// What the decision knows about the key it was made on and the keys it denied.
    pub(super) fn decision(&mut self, trace: DecisionTrace, denied: Vec<String>) {
        self.trace = trace;
        self.denied = denied;
    }

    /// Why the token was refused, when it was.
    pub(super) const fn token_refusal(&self) -> Option<DecisionReason> {
        self.token_refusal
    }
}

/// A request whose record is not written yet.
#[derive(Debug)]
pub(super) struct Started {
    at: Instant,
    request: RequestFacts,
}

/// The access log step: the recorder and the ports that stamp a record.
#[derive(Debug)]
pub struct PipelineAccessLog {
    recorder: Arc<AccessRecorder>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn UuidGenerator>,
}

impl PipelineAccessLog {
    /// The step over `recorder`; the time of a record comes from `clock` and its decision id from
    /// `ids`.
    #[must_use]
    pub fn new(
        recorder: Arc<AccessRecorder>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn UuidGenerator>,
    ) -> Self {
        Self {
            recorder,
            clock,
            ids,
        }
    }

    /// Notes the request as it arrives.
    pub(super) fn begin(parts: &Parts) -> Started {
        Started {
            at: Instant::now(),
            request: RequestFacts {
                method: parts.method.as_str().to_owned(),
                host: super::host_of(parts).unwrap_or_default(),
                request_id: header_text(&parts.headers, REQUEST_ID_HEADER.as_str()),
                bytes_in: announced_length(&parts.headers),
                credential_digest_prefix: credential_digest_prefix(&credential(&parts.headers)),
            },
        }
    }

    /// Records the decision about the request with the response that answers it.
    pub(super) fn finish<B>(
        &self,
        started: Started,
        seen: Observed,
        verdict: (Decision, DecisionReason),
        response: &Response<B>,
    ) {
        let Started { at, request } = started;
        let Observed {
            route,
            subject,
            policy_version,
            trace,
            denied,
            ..
        } = seen;
        let latency_us = u64::try_from(at.elapsed().as_micros()).unwrap_or(u64::MAX);
        self.recorder.record(AccessFacts {
            decision_id: self.ids.generate(),
            occurred_at: self.clock.now(),
            request,
            route,
            verdict: VerdictFacts {
                decision: verdict.0,
                reason: verdict.1,
                subject,
                policy_version,
                trace,
                denied,
                project_id: None,
            },
            response: ResponseFacts {
                status: response.status().as_u16(),
                bytes_out: announced_length(response.headers()),
                latency_us,
            },
        });
    }
}

/// The text of the header `name`, when it is valid text.
fn header_text(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// The length that the headers announce, zero when they announce none.
fn announced_length(headers: &HeaderMap) -> u64 {
    headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests;
