//! The rate-limit step of the gateway pipeline (FR-63, FR-65).
//!
//! The pipeline asks the [`RateLimitGate`] twice. Before authentication the gate decides the
//! policies of the route that count by the client address or by the route; after authentication
//! those that count by the subject. A request that authentication refuses therefore never reaches
//! a subject counter. A route without a rate policy never reaches the shared store.
//!
//! Every call of the shared store is bounded by `RATE_LIMIT_STORE_TIMEOUT`, measured on the boot
//! clock. A call that fails or times out is decided by the fallback bucket of the local limiter
//! under the conservative limit of the policy (`limit / N_ready` for `fallback = divided`, the
//! full limit for `full`, `N_ready` being the ready endpoints of `iam-gateway-peers`), so a store
//! problem never answers 503 and never changes who is authorized.
//!
//! After five consecutive failures or timeouts the [`StoreBreaker`] opens for
//! `RATE_LIMIT_BREAKER_OPEN_DURATION`: no call reaches the store and the local limiter decides
//! every request. When the duration has passed one probe call is let through; its answer closes
//! the breaker and exact counting resumes. Every degraded decision is reported as the metric event
//! `rate_limit_store_degraded`.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use iam_domain::{
    BootClock, BreakerPermit, LocalRateLimiter, PolicySnapshot, RateDecision, RateDecisionRule,
    RateKey, RateKeyKind, RateKeyParts, RateLimitStore, RatePolicyFields, RatePolicyId, ReadyPeers,
    RequestDigester, RouteId, StoreBreaker, SubjectRef,
};

pub use self::peers::EndpointReadyPeers;

mod peers;

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

/// The time bounds of the shared store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateStoreBounds {
    /// `RATE_LIMIT_STORE_TIMEOUT`: the longest one call of the store may take.
    pub store_timeout: Duration,
    /// `RATE_LIMIT_BREAKER_OPEN_DURATION`: how long the breaker stays open before one probe.
    pub breaker_open_duration: Duration,
}

/// The ports a [`RateLimitGate`] decides with.
#[derive(Debug, Clone)]
pub struct RateLimitPorts {
    /// The shared counters.
    pub store: Arc<dyn RateLimitStore>,
    /// The in-process limiter: the flood guard and the fallback buckets.
    pub local: Arc<dyn LocalRateLimiter>,
    /// Hashes the key parts.
    pub digester: Arc<dyn RequestDigester>,
    /// Measures the store timeout and the breaker interval.
    pub clock: Arc<dyn BootClock>,
    /// Counts the ready gateway pods for the conservative limit.
    pub peers: Arc<dyn ReadyPeers>,
}

/// Decides the rate policies of a route against the shared counters.
#[derive(Debug)]
pub struct RateLimitGate {
    ports: RateLimitPorts,
    breaker: Mutex<StoreBreaker>,
    timeout: Duration,
}

/// Why a request was decided by the local limiter, for the degraded metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Degradation {
    Unavailable,
    TimedOut,
    BreakerOpen,
    BreakerOpened,
}

impl Degradation {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::TimedOut => "timed_out",
            Self::BreakerOpen => "breaker_open",
            Self::BreakerOpened => "breaker_opened",
        }
    }
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
    /// A gate over `ports`. `bounds.store_timeout` bounds every call of the store and is
    /// measured on the boot clock; the breaker opens for `bounds.breaker_open_duration`.
    #[must_use]
    pub const fn new(ports: RateLimitPorts, bounds: RateStoreBounds) -> Self {
        Self {
            ports,
            breaker: Mutex::new(StoreBreaker::new(bounds.breaker_open_duration)),
            timeout: bounds.store_timeout,
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
        RateKey::new(RateKeyKind::Ip, &parts, self.ports.digester.as_ref())
            .map_or(RateDecision::Admit, |key| {
                self.ports.local.check_guard(&key)
            })
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
        let key = RateKey::new(fields.key_kind(), parts, self.ports.digester.as_ref()).ok()?;
        Some(self.decide(id, &key, fields).await)
    }

    /// One policy: the shared counter under the timeout and the breaker, the local fallback when
    /// it cannot answer.
    async fn decide(
        &self,
        id: &RatePolicyId,
        key: &RateKey,
        fields: &RatePolicyFields,
    ) -> RateDecision {
        let permit = self.permit();
        if permit == BreakerPermit::Skip {
            log_degraded(Degradation::BreakerOpen);
            return self.fallback(id, key, fields);
        }
        let rule = RateDecisionRule::for_policy(fields);
        let started = self.ports.clock.now();
        let answer =
            tokio::time::timeout(self.timeout, self.ports.store.check(id, key, &rule)).await;
        let elapsed = self.ports.clock.now().saturating_since(started);
        match answer {
            Ok(Ok(decision)) => {
                log_latency(elapsed, StoreOutcome::Answered);
                self.answered(permit);
                decision
            }
            Ok(Err(_unavailable)) => {
                log_latency(elapsed, StoreOutcome::Unavailable);
                self.failed(permit, Degradation::Unavailable);
                self.fallback(id, key, fields)
            }
            Err(_elapsed) => {
                log_latency(elapsed, StoreOutcome::TimedOut);
                self.failed(permit, Degradation::TimedOut);
                self.fallback(id, key, fields)
            }
        }
    }

    fn permit(&self) -> BreakerPermit {
        let now = self.ports.clock.now();
        self.breaker
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .permit(now)
    }

    fn answered(&self, permit: BreakerPermit) {
        self.breaker
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .record_success(permit);
    }

    fn failed(&self, permit: BreakerPermit, reason: Degradation) {
        let now = self.ports.clock.now();
        let opened = self
            .breaker
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .record_failure(permit, now);
        log_degraded(reason);
        if opened {
            log_degraded(Degradation::BreakerOpened);
        }
    }

    /// The local fallback bucket under the conservative limit for the ready pods now.
    fn fallback(
        &self,
        id: &RatePolicyId,
        key: &RateKey,
        fields: &RatePolicyFields,
    ) -> RateDecision {
        let rule = RateDecisionRule::conservative(fields, self.ports.peers.ready_endpoints());
        self.ports.local.check_fallback(id, key, &rule)
    }
}

fn log_degraded(reason: Degradation) {
    let reason = reason.as_str();
    tracing::warn!(
        metric = "rate_limit_store_degraded",
        reason,
        "the rate limit store is degraded; the local limiter decides"
    );
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
