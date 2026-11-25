//! The rate-limit step of the gateway pipeline (FR-63, FR-65).
//!
//! The pipeline asks the [`RateLimitGate`] twice. Before authentication the gate decides the
//! policies of the route that count by the client address or by the route; after authentication
//! those that count by the subject. A request that authentication refuses therefore never reaches
//! a subject counter. A route without a rate policy never reaches the shared store.
//!
//! Every call of the shared store is bounded by `RATE_LIMIT_STORE_TIMEOUT`, measured on the boot
//! clock. A call that fails or times out is decided by the fallback bucket of the local limiter
//! under the full limit of the policy, so a store problem never answers 503 and never changes who
//! is authorized; Story 12.3 adds the breaker and the conservative limit.

use std::sync::Arc;
use std::time::Duration;

use iam_domain::{
    BootClock, LocalRateLimiter, PolicySnapshot, RateDecision, RateDecisionRule, RateKey,
    RateKeyKind, RateKeyParts, RateLimitStore, RatePolicyFields, RatePolicyId, RequestDigester,
    RouteId, SubjectRef,
};

/// Which of the policies of a route a check decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateStage {
    /// Before authentication: the `ip` and `route` keys.
    Anonymous,
    /// After authentication: the `subject` and `subject_route` keys.
    Authenticated,
}

impl RateStage {
    /// Whether a policy with this key kind belongs to the stage.
    #[must_use]
    pub const fn counts(self, kind: RateKeyKind) -> bool {
        match self {
            Self::Anonymous => matches!(kind, RateKeyKind::Ip | RateKeyKind::Route),
            Self::Authenticated => matches!(kind, RateKeyKind::Subject | RateKeyKind::SubjectRoute),
        }
    }
}

/// What the gate needs of a request to decide its rate policies.
#[derive(Debug, Clone, Copy)]
pub struct RateRequest<'request> {
    /// The snapshot of the request, which holds the rate policies.
    pub snapshot: &'request dyn PolicySnapshot,
    /// The rate policies of the matched route, in the order they apply.
    pub policies: &'request [RatePolicyId],
    /// The route that matched.
    pub route: RouteId,
    /// The client address, when the connection has one.
    pub ip: Option<&'request str>,
    /// The authenticated subject; `None` before authentication.
    pub subject: Option<&'request SubjectRef>,
}

/// Decides the rate policies of a route against the shared counters.
#[derive(Debug)]
pub struct RateLimitGate {
    store: Arc<dyn RateLimitStore>,
    local: Arc<dyn LocalRateLimiter>,
    digester: Arc<dyn RequestDigester>,
    clock: Arc<dyn BootClock>,
    timeout: Duration,
}

/// How a call of the shared store ended, for the latency metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoreOutcome {
    Answered,
    Unavailable,
    TimedOut,
}

impl StoreOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Answered => "answered",
            Self::Unavailable => "unavailable",
            Self::TimedOut => "timed_out",
        }
    }
}

impl RateLimitGate {
    /// A gate over the shared `store` and the `local` limiter. `timeout` bounds every call of the
    /// store and is measured on `clock`; keys are hashed with `digester`.
    #[must_use]
    pub fn new(
        store: Arc<dyn RateLimitStore>,
        local: Arc<dyn LocalRateLimiter>,
        digester: Arc<dyn RequestDigester>,
        clock: Arc<dyn BootClock>,
        timeout: Duration,
    ) -> Self {
        Self {
            store,
            local,
            digester,
            clock,
            timeout,
        }
    }

    /// The flood guard: one request of `ip` against the in-process per-IP bucket. A request
    /// without an address is admitted.
    #[must_use]
    pub fn check_guard(&self, ip: Option<&str>) -> RateDecision {
        let parts = RateKeyParts {
            ip,
            ..RateKeyParts::default()
        };
        RateKey::new(RateKeyKind::Ip, &parts, self.digester.as_ref())
            .map_or(RateDecision::Admit, |key| self.local.check_guard(&key))
    }

    /// Decides the policies of the route that belong to `stage`, in order, and stops at the first
    /// that rejects. Policies the snapshot does not hold, and policies whose key needs a part the
    /// request lacks, are skipped.
    pub async fn check(&self, stage: RateStage, request: &RateRequest<'_>) -> RateDecision {
        let route = request.route.to_string();
        let subject = request.subject.map(ToString::to_string);
        let parts = RateKeyParts {
            subject: subject.as_deref(),
            ip: request.ip,
            route: Some(route.as_str()),
        };
        for id in request.policies {
            let Some(decision) = self.check_policy(stage, request.snapshot, id, &parts).await
            else {
                continue;
            };
            if !decision.is_admitted() {
                return decision;
            }
        }
        RateDecision::Admit
    }

    async fn check_policy(
        &self,
        stage: RateStage,
        snapshot: &dyn PolicySnapshot,
        id: &RatePolicyId,
        parts: &RateKeyParts<'_>,
    ) -> Option<RateDecision> {
        let fields = &snapshot.rate_policy(*id)?.fields;
        if !stage.counts(fields.key_kind()) {
            return None;
        }
        let key = RateKey::new(fields.key_kind(), parts, self.digester.as_ref()).ok()?;
        Some(self.decide(id, &key, fields).await)
    }

    /// One policy: the shared counter under the timeout, the local fallback when it cannot answer.
    async fn decide(
        &self,
        id: &RatePolicyId,
        key: &RateKey,
        fields: &RatePolicyFields,
    ) -> RateDecision {
        let rule = RateDecisionRule::for_policy(fields);
        let started = self.clock.now();
        let answer = tokio::time::timeout(self.timeout, self.store.check(id, key, &rule)).await;
        let elapsed = self.clock.now().saturating_since(started);
        match answer {
            Ok(Ok(decision)) => {
                log_latency(elapsed, StoreOutcome::Answered);
                decision
            }
            Ok(Err(_unavailable)) => {
                log_latency(elapsed, StoreOutcome::Unavailable);
                self.fallback(id, key, fields)
            }
            Err(_elapsed) => {
                log_latency(elapsed, StoreOutcome::TimedOut);
                self.fallback(id, key, fields)
            }
        }
    }

    fn fallback(
        &self,
        id: &RatePolicyId,
        key: &RateKey,
        fields: &RatePolicyFields,
    ) -> RateDecision {
        let rule = RateDecisionRule::conservative(fields, 1);
        self.local.check_fallback(id, key, &rule)
    }
}

fn log_latency(elapsed: Duration, outcome: StoreOutcome) {
    let seconds = elapsed.as_secs_f64();
    let outcome = outcome.as_str();
    tracing::info!(
        metric = "rate_limit_store_latency_seconds",
        seconds,
        outcome,
        "latency of a call of the rate limit store"
    );
}

#[cfg(test)]
mod tests;
