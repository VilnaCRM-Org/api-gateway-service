//! The access log of the gateway: the writer thread, the recorder of the request path and the sinks
//! (Stories 14.1 and 14.2, FR-50, architecture section 12).
//!
//! The request path builds a record and offers it to a bounded channel with a send that never
//! waits; this module owns the other end, a dedicated thread that applies the per-class budgets and
//! writes the ordinary lane as JSON lines to stdout and the audit lane to Loki, which acknowledges
//! it. The writer publishes the audit entries that Loki has not acknowledged to the [`AuditGate`],
//! which the authorizer reads for audit-or-deny.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;

use iam_application::{
    AccessLogCounters, AccessLogWriter, AccessRecordBuilder, AccessRecorder, AuditGate,
    access_log_channel,
};
use iam_domain::{AccessLogSink, Rng};
use iam_infrastructure::{
    LaneSplitSink, LokiPushAccessLogSink, LokiSinkSettings, StdoutAccessLogSink,
};
use shared_domain::Clock;
use shared_infrastructure::id::UuidV7Generator;

use self::loki_transport::HyperLokiTransport;
use super::pipeline::PipelineAccessLog;
use crate::config::{AccessLogSettings, AppEnv, AuditLaneSettings, DEFAULT_MAX_PENDING, env_label};

pub mod loki_transport;

/// The value of the `app` label of the audit lane.
pub const LOKI_APP_LABEL: &str = "iam-gateway";

/// The name of the writer thread.
pub const WRITER_THREAD: &str = "access-log-writer";

/// The recorder of the request path and the thread that writes what it records.
#[derive(Debug)]
pub struct AccessLogAdapters {
    recorder: Arc<AccessRecorder>,
    counters: Arc<AccessLogCounters>,
    audit_gate: Arc<AuditGate>,
    stop: Arc<AtomicBool>,
    writer: Mutex<Option<JoinHandle<()>>>,
}

impl AccessLogAdapters {
    /// Starts the writer thread over `sink`: records are sampled with `rng`, budgeted by `clock`
    /// seconds and written to `sink`. The audit gate refuses after [`DEFAULT_MAX_PENDING`].
    ///
    /// # Errors
    ///
    /// The error of the operating system when the thread cannot be started.
    pub fn start(
        settings: &AccessLogSettings,
        rng: Arc<dyn Rng>,
        clock: Arc<dyn Clock>,
        sink: Arc<dyn AccessLogSink>,
    ) -> std::io::Result<Self> {
        let gate = AuditGate::new(
            Arc::clone(&clock),
            DEFAULT_MAX_PENDING,
            settings.channel_capacity,
        );
        Self::start_gated(settings, Arc::new(gate), rng, clock, sink)
    }

    /// Starts the writer thread over `sink` like [`Self::start`], publishing the audit entries
    /// that the sink has not acknowledged to `gate`.
    ///
    /// # Errors
    ///
    /// The error of the operating system when the thread cannot be started.
    pub fn start_gated(
        settings: &AccessLogSettings,
        gate: Arc<AuditGate>,
        rng: Arc<dyn Rng>,
        clock: Arc<dyn Clock>,
        sink: Arc<dyn AccessLogSink>,
    ) -> std::io::Result<Self> {
        let counters = Arc::new(AccessLogCounters::new());
        let (channel, receiver) =
            access_log_channel(settings.channel_capacity, Arc::clone(&counters));
        let channel = channel.with_audit_gate(Arc::clone(&gate));
        let recorder = AccessRecorder::new(
            AccessRecordBuilder::new(rng, settings.allow_sample_rate),
            channel,
        );
        let stop = Arc::new(AtomicBool::new(false));
        let writer = AccessLogWriter::new(sink, clock, settings.class_budgets)
            .with_audit_gate(Arc::clone(&gate), Arc::clone(&counters));
        let stopping = Arc::clone(&stop);
        let handle = std::thread::Builder::new()
            .name(WRITER_THREAD.to_owned())
            .spawn(move || writer.run(&receiver, &stopping))?;
        Ok(Self {
            recorder: Arc::new(recorder),
            counters,
            audit_gate: gate,
            stop,
            writer: Mutex::new(Some(handle)),
        })
    }

    /// Starts the writer of production: the ordinary lane to stdout and the audit lane to Loki
    /// through `HyperLokiTransport`, with the audit gate refusing once the oldest unacknowledged
    /// audit entry has waited longer than `audit.max_pending`.
    ///
    /// # Errors
    ///
    /// The error of the operating system when a thread or the runtime of the transport cannot be
    /// started, or an invalid-input error when the tenant cannot be a header value.
    pub fn to_production(
        settings: &AccessLogSettings,
        audit: &AuditLaneSettings,
        app_env: AppEnv,
        rng: Arc<dyn Rng>,
        clock: Arc<dyn Clock>,
    ) -> std::io::Result<Self> {
        let transport = HyperLokiTransport::new(audit.push_url.clone(), &audit.tenant_id)?;
        let sink_settings = LokiSinkSettings {
            app: LOKI_APP_LABEL.to_owned(),
            env: env_label(app_env).to_owned(),
            flush_interval: audit.flush_interval,
        };
        let loki = LokiPushAccessLogSink::start(sink_settings, Arc::new(transport))?;
        let sink = LaneSplitSink::new(Arc::new(StdoutAccessLogSink::new()), Arc::new(loki));
        let gate = AuditGate::new(
            Arc::clone(&clock),
            audit.max_pending,
            settings.channel_capacity,
        );
        Self::start_gated(settings, Arc::new(gate), rng, clock, Arc::new(sink))
    }

    /// Starts the writer over the stdout sink alone, which writes both lanes; the production
    /// wiring is [`Self::to_production`].
    ///
    /// # Errors
    ///
    /// The error of the operating system when the thread cannot be started.
    pub fn to_stdout(
        settings: &AccessLogSettings,
        rng: Arc<dyn Rng>,
        clock: Arc<dyn Clock>,
    ) -> std::io::Result<Self> {
        Self::start(settings, rng, clock, Arc::new(StdoutAccessLogSink::new()))
    }

    /// The recorder that the pipeline and the decision API share.
    #[must_use]
    pub fn recorder(&self) -> Arc<AccessRecorder> {
        Arc::clone(&self.recorder)
    }

    /// The access record step of the public pipeline over the shared recorder, stamping records
    /// with `clock` and new decision ids.
    #[must_use]
    pub fn pipeline_step(&self, clock: &Arc<dyn Clock>) -> Arc<PipelineAccessLog> {
        Arc::new(
            PipelineAccessLog::new(
                self.recorder(),
                Arc::clone(clock),
                Arc::new(UuidV7Generator),
            )
            .with_audit_gate(self.audit_gate()),
        )
    }

    /// The gate of the audit lane that the authorizer reads for audit-or-deny.
    #[must_use]
    pub fn audit_gate(&self) -> Arc<AuditGate> {
        Arc::clone(&self.audit_gate)
    }

    /// The counters of the records that were dropped.
    #[must_use]
    pub fn counters(&self) -> Arc<AccessLogCounters> {
        Arc::clone(&self.counters)
    }

    /// Stops the writer after it wrote what is queued and the pending aggregates, and waits for
    /// it. A second call does nothing.
    pub fn finish(&self) {
        self.stop.store(true, Ordering::Release);
        let handle = self
            .writer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        join_writer(handle);
    }
}

/// Waits for the writer thread, when there still is one, and logs a panic of it.
fn join_writer(handle: Option<JoinHandle<()>>) {
    if writer_panicked(handle) {
        log_writer_panicked();
    }
}

fn log_writer_panicked() {
    tracing::error!("the access log writer panicked");
}

fn writer_panicked(handle: Option<JoinHandle<()>>) -> bool {
    handle.is_some_and(|handle| handle.join().is_err())
}

#[cfg(test)]
mod tests;
