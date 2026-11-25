//! The access log of the gateway: the writer thread, the recorder of the request path and the
//! stdout sink (Story 14.1, FR-50, architecture section 12).
//!
//! The request path builds a record and offers it to a bounded channel with a send that never
//! waits; this module owns the other end, a dedicated thread that applies the per-class budgets and
//! writes JSON lines to stdout. Until Story 14.2 adds the Loki push sink, the audit lane is written
//! through the same sink with the field `lane` set to `audit`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;

use iam_application::{
    AccessLogCounters, AccessLogWriter, AccessRecordBuilder, AccessRecorder, access_log_channel,
};
use iam_domain::{AccessLogSink, Rng};
use iam_infrastructure::StdoutAccessLogSink;
use shared_domain::Clock;
use shared_infrastructure::id::UuidV7Generator;

use super::pipeline::PipelineAccessLog;
use crate::config::AccessLogSettings;

/// The name of the writer thread.
pub const WRITER_THREAD: &str = "access-log-writer";

/// The recorder of the request path and the thread that writes what it records.
#[derive(Debug)]
pub struct AccessLogAdapters {
    recorder: Arc<AccessRecorder>,
    counters: Arc<AccessLogCounters>,
    stop: Arc<AtomicBool>,
    writer: Mutex<Option<JoinHandle<()>>>,
}

impl AccessLogAdapters {
    /// Starts the writer thread over `sink`: records are sampled with `rng`, budgeted by `clock`
    /// seconds and written to `sink`.
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
        let counters = Arc::new(AccessLogCounters::new());
        let (channel, receiver) =
            access_log_channel(settings.channel_capacity, Arc::clone(&counters));
        let recorder = AccessRecorder::new(
            AccessRecordBuilder::new(rng, settings.allow_sample_rate),
            channel,
        );
        let stop = Arc::new(AtomicBool::new(false));
        let writer = AccessLogWriter::new(sink, clock, settings.class_budgets);
        let stopping = Arc::clone(&stop);
        let handle = std::thread::Builder::new()
            .name(WRITER_THREAD.to_owned())
            .spawn(move || writer.run(&receiver, &stopping))?;
        Ok(Self {
            recorder: Arc::new(recorder),
            counters,
            stop,
            writer: Mutex::new(Some(handle)),
        })
    }

    /// Starts the writer over the stdout sink, the production wiring.
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
        Arc::new(PipelineAccessLog::new(
            self.recorder(),
            Arc::clone(clock),
            Arc::new(UuidV7Generator),
        ))
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
