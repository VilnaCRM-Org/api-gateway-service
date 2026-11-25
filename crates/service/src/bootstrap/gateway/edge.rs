//! The edge of the public listener (Story 10.9, FR-67, NFR-21, NFR-40): what bounds a connection
//! before a request reaches the pipeline.
//!
//! [`Edge`] holds the limits of [`EdgeLimits`] and the counters they need: connections per client
//! address and per subject, the age of a connection with its jitter, and the early retirement of a
//! connection that carries too many requests. [`Edge::tune`] applies the header and stream limits
//! to the HTTP server of a connection. [`framing`] refuses ambiguous requests and [`proxy`] reads
//! the Proxy Protocol v2 header.
//!
//! Limits that hyper enforces itself (the header block, the header read timeout, the HTTP/2
//! streams and header list, the buffers) are set on the connection builder; the others are
//! enforced here, per connection.

use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use hyper_util::rt::{TokioExecutor, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use iam_domain::Rng;

pub mod framing;
pub mod proxy;

/// How often a connection checks whether it carries too many requests.
const RETIRE_TICK: Duration = Duration::from_secs(1);

/// How long an HTTP/2 keep-alive ping may stay unanswered.
const PING_TIMEOUT: Duration = Duration::from_secs(10);

/// The numbers of the edge. They are fixed by the story, not read from the environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EdgeLimits {
    /// The largest block of request headers, in bytes; a bigger one gets 431.
    pub header_block: usize,
    /// How long a client may take to send its request headers.
    pub header_read_timeout: Duration,
    /// HTTP/2 `max_concurrent_streams`.
    pub max_concurrent_streams: u32,
    /// HTTP/2 `max_header_list_size`, in bytes.
    pub max_header_list_size: u32,
    /// The bytes one connection may buffer for a client that reads slowly.
    pub buffered_per_connection: u32,
    /// Connections one client address may hold.
    pub connections_per_ip: usize,
    /// Connections one subject may hold.
    pub connections_per_subject: usize,
    /// How long an HTTP/2 connection may stay idle before the gateway pings it.
    pub keep_alive_idle: Duration,
    /// The age after which a connection is ended with `GOAWAY`, before jitter.
    pub connection_age: Duration,
    /// The jitter of the age, in percent either way.
    pub age_jitter_percent: u64,
    /// The request rate (per second) above which a connection is retired early.
    pub early_rate: u64,
    /// How old a connection must be before the rate counts.
    pub early_rate_after: Duration,
    /// The request count after which a connection is retired early, whatever its age.
    pub early_requests: u64,
}

impl Default for EdgeLimits {
    fn default() -> Self {
        Self {
            header_block: 16 * 1024,
            header_read_timeout: Duration::from_secs(10),
            max_concurrent_streams: 128,
            max_header_list_size: 16 * 1024,
            buffered_per_connection: 256 * 1024,
            connections_per_ip: 64,
            connections_per_subject: 32,
            keep_alive_idle: Duration::from_secs(120),
            connection_age: Duration::from_secs(600),
            age_jitter_percent: 20,
            early_rate: 2000,
            early_rate_after: Duration::from_secs(120),
            early_requests: 100_000,
        }
    }
}

/// The age of a connection with its jitter: `base` plus or minus `percent`, chosen by `draw`.
#[must_use]
pub fn jitter_age(base: Duration, percent: u64, draw: u64) -> Duration {
    let millis = u64::try_from(base.as_millis()).unwrap_or(u64::MAX);
    let spread = millis.saturating_mul(percent) / 100;
    let low = millis.saturating_sub(spread);
    let width = spread.saturating_mul(2).saturating_add(1);
    let offset = draw.checked_rem(width).unwrap_or(0);
    Duration::from_millis(low.saturating_add(offset))
}

/// Whether a connection of age `elapsed` that carried `requests` requests must end now.
#[must_use]
pub fn retire_early(limits: &EdgeLimits, elapsed: Duration, requests: u64) -> bool {
    if requests >= limits.early_requests {
        return true;
    }
    let seconds = elapsed.as_secs();
    elapsed >= limits.early_rate_after
        && seconds > 0
        && requests.checked_div(seconds).unwrap_or(0) > limits.early_rate
}

/// A count of what each key holds, with a limit per key.
#[derive(Debug)]
struct Counter<K> {
    limit: usize,
    held: Mutex<HashMap<K, usize>>,
}

impl<K: Eq + Hash + Clone> Counter<K> {
    fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            limit,
            held: Mutex::new(HashMap::new()),
        })
    }

    fn acquire(self: &Arc<Self>, key: K) -> Option<Permit<K>> {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let count = held.entry(key.clone()).or_insert(0);
        if *count >= self.limit {
            return None;
        }
        *count = count.saturating_add(1);
        drop(held);
        Some(Permit {
            counter: Arc::clone(self),
            key,
        })
    }

    fn release(&self, key: &K) {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let emptied = held.get_mut(key).is_some_and(|count| {
            *count = count.saturating_sub(1);
            *count == 0
        });
        if emptied {
            held.remove(key);
        }
    }
}

/// One slot of a [`Counter`], given back when it is dropped.
#[derive(Debug)]
pub struct Permit<K: Eq + Hash + Clone> {
    counter: Arc<Counter<K>>,
    key: K,
}

impl<K: Eq + Hash + Clone> Drop for Permit<K> {
    fn drop(&mut self) {
        self.counter.release(&self.key);
    }
}

/// The slot of a connection among those of its client address.
pub type IpPermit = Permit<IpAddr>;

/// The subjects one connection has claimed, so that a subject holds at most
/// `connections_per_subject` connections whatever the number of its requests.
#[derive(Debug)]
pub struct SubjectClaims {
    counter: Arc<Counter<String>>,
    claimed: Mutex<HashMap<String, Permit<String>>>,
}

impl SubjectClaims {
    /// Claims a slot of `subject` for this connection; a subject the connection already holds
    /// costs nothing more. Returns `false` when the subject is at its limit.
    #[must_use]
    pub fn claim(&self, subject: &str) -> bool {
        let mut claimed = self.claimed.lock().unwrap_or_else(PoisonError::into_inner);
        if claimed.contains_key(subject) {
            return true;
        }
        let Some(permit) = self.counter.acquire(subject.to_owned()) else {
            return false;
        };
        claimed.insert(subject.to_owned(), permit);
        true
    }

    /// How many subjects this connection holds.
    #[must_use]
    pub fn held(&self) -> usize {
        self.claimed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

/// The edge: limits, counters and the settings of the Proxy Protocol.
#[derive(Debug, Clone)]
pub struct Edge {
    limits: EdgeLimits,
    proxy_protocol: bool,
    header_in_serve: bool,
    rng: Option<Arc<dyn Rng>>,
    ips: Arc<Counter<IpAddr>>,
    subjects: Arc<Counter<String>>,
}

impl Edge {
    /// An edge with `limits`; `proxy_protocol` makes every connection start with a v2 header, and
    /// `rng` draws the jitter of the connection age (none: no jitter).
    #[must_use]
    pub fn new(limits: EdgeLimits, proxy_protocol: bool, rng: Option<Arc<dyn Rng>>) -> Self {
        Self {
            ips: Counter::new(limits.connections_per_ip),
            subjects: Counter::new(limits.connections_per_subject),
            limits,
            proxy_protocol,
            header_in_serve: false,
            rng,
        }
    }

    /// The edge of production: the limits of the story, the jitter drawn from `rng`.
    #[must_use]
    pub fn standard(proxy_protocol: bool, rng: Arc<dyn Rng>) -> Self {
        Self::new(EdgeLimits::default(), proxy_protocol, Some(rng))
    }

    /// The same edge, reading the Proxy Protocol header itself when the listener is not TLS (a TLS
    /// listener reads it before the handshake).
    #[must_use]
    pub const fn reading_header_in_serve(mut self, in_serve: bool) -> Self {
        self.header_in_serve = in_serve;
        self
    }

    /// The limits of this edge.
    #[must_use]
    pub const fn limits(&self) -> &EdgeLimits {
        &self.limits
    }

    /// Whether connections start with a Proxy Protocol header.
    #[must_use]
    pub const fn proxy_protocol(&self) -> bool {
        self.proxy_protocol
    }

    /// Whether the server, not the TLS listener, reads the header.
    #[must_use]
    pub const fn header_in_serve(&self) -> bool {
        self.proxy_protocol && self.header_in_serve
    }

    /// A slot among the connections of `ip`, or `None` when it holds the most it may.
    #[must_use]
    pub fn admit(&self, ip: IpAddr) -> Option<IpPermit> {
        self.ips.acquire(ip)
    }

    /// The claims of a new connection on the subjects it will authenticate as.
    #[must_use]
    pub fn claims(&self) -> Arc<SubjectClaims> {
        Arc::new(SubjectClaims {
            counter: Arc::clone(&self.subjects),
            claimed: Mutex::new(HashMap::new()),
        })
    }

    /// The age at which a new connection ends, jittered.
    #[must_use]
    pub fn connection_age(&self) -> Duration {
        let base = self.limits.connection_age;
        self.rng.as_ref().map_or(base, |rng| {
            jitter_age(base, self.limits.age_jitter_percent, rng.next_u64())
        })
    }

    /// Completes when a connection that counts its requests in `requests` must end: it reached its
    /// age, or carried too many requests too fast.
    pub async fn retire<F>(&self, requests: F)
    where
        F: Fn() -> u64,
    {
        tokio::select! {
            () = tokio::time::sleep(self.connection_age()) => {}
            () = self.worn_out(requests) => {}
        }
    }

    async fn worn_out<F>(&self, requests: F)
    where
        F: Fn() -> u64,
    {
        let mut elapsed = Duration::ZERO;
        loop {
            tokio::time::sleep(RETIRE_TICK).await;
            elapsed = elapsed.saturating_add(RETIRE_TICK);
            if retire_early(&self.limits, elapsed, requests()) {
                return;
            }
        }
    }

    /// Applies the header, stream and buffer limits to the server of a connection.
    pub fn tune(&self, builder: &mut Builder<TokioExecutor>) {
        let limits = &self.limits;
        builder
            .http1()
            .timer(TokioTimer::new())
            .max_buf_size(limits.header_block)
            .header_read_timeout(limits.header_read_timeout);
        builder
            .http2()
            .timer(TokioTimer::new())
            .max_concurrent_streams(limits.max_concurrent_streams)
            .max_header_list_size(limits.max_header_list_size)
            .initial_stream_window_size(limits.buffered_per_connection)
            .initial_connection_window_size(limits.buffered_per_connection)
            .keep_alive_interval(limits.keep_alive_idle)
            .keep_alive_timeout(PING_TIMEOUT);
    }
}

#[cfg(test)]
mod tests;
