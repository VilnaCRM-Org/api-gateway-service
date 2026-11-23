//! `KrafkaPolicyLogProducer`: appends the records of the outbox to the state topic and the events
//! topic with krafka (FR-46, FR-47).
//!
//! The producer is idempotent, writes with `acks=all` and compresses with lz4; krafka keeps one
//! request in flight per partition, so a batch lands in the order it was given. State records go to
//! the partition the record names (0). Every record carries the framing headers, the relay epoch
//! among them.
//!
//! In [`RelayMode::Transactional`] the producer is the transactional producer `iam-relay`: a new
//! instance fences the older one, and the records of a batch become visible to a `read_committed`
//! reader only when the transaction commits, which is also when the call returns. In
//! [`RelayMode::EpochOnly`] (the ADR 0026 branch for a failed capability 7) the relay-epoch header
//! is the only fencing.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use iam_domain::{PolicyLogError, PolicyLogProducer, PolicyLogRecord};
use krafka::error::ErrorCode;
use krafka::producer::{Acks, DeliveryHandle, Producer, RecordMetadata, TransactionalProducer};
use krafka::{Compression, KrafkaError, Record};
use shared_domain::BoxError;

use super::krafka_cluster::{authenticated, builder};
use super::settings::KafkaSettings;

/// The transactional id of the relay; one producer of the fleet holds it at a time.
pub const TRANSACTIONAL_ID: &str = "iam-relay";

/// How the producer fences a relay that was replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayMode {
    /// The transactional producer `iam-relay` with the given `transaction.timeout.ms`, together
    /// with the relay-epoch header.
    Transactional {
        /// `KAFKA_TRANSACTION_TIMEOUT`.
        transaction_timeout: Duration,
    },
    /// The relay-epoch header only.
    EpochOnly,
}

/// Appends records to Kafka through one lazily opened producer.
///
/// A failed call drops the producer, so the next call opens a new one; in transactional mode that
/// bumps the producer epoch, which is what fences an older relay.
#[derive(Debug)]
pub struct KrafkaPolicyLogProducer {
    settings: KafkaSettings,
    mode: RelayMode,
    transactional_id: String,
    session: Mutex<Option<Arc<Session>>>,
}

/// The open producer.
#[derive(Debug)]
enum Session {
    Idempotent(Box<Producer>),
    Transactional(Box<TransactionalProducer>),
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl KrafkaPolicyLogProducer {
    /// A producer for the cluster of `settings` in `mode`; nothing is opened until the first
    /// [`publish`](PolicyLogProducer::publish).
    #[must_use]
    pub fn new(settings: &KafkaSettings, mode: RelayMode) -> Self {
        Self {
            settings: settings.clone(),
            mode,
            transactional_id: TRANSACTIONAL_ID.to_owned(),
            session: Mutex::new(None),
        }
    }

    /// The same producer under another transactional id, for tests that run next to another
    /// producer of the same broker; production uses [`TRANSACTIONAL_ID`].
    #[must_use]
    pub fn with_transactional_id(mut self, transactional_id: String) -> Self {
        self.transactional_id = transactional_id;
        self
    }

    async fn session(&self) -> Result<Arc<Session>, KrafkaError> {
        let open = locked(&self.session).clone();
        if let Some(session) = open {
            return Ok(session);
        }
        let session =
            Arc::new(Session::open(&self.settings, self.mode, &self.transactional_id).await?);
        *locked(&self.session) = Some(Arc::clone(&session));
        Ok(session)
    }

    fn discard_session(&self) {
        *locked(&self.session) = None;
    }

    async fn append(&self, records: &[PolicyLogRecord]) -> Result<Vec<i64>, PolicyLogError> {
        let appended = match self.session().await {
            Ok(session) => session.append(records).await,
            Err(error) => Err(error),
        };
        appended.map_err(|error| {
            self.discard_session();
            classify(&error)
        })
    }
}

impl Session {
    async fn open(
        settings: &KafkaSettings,
        mode: RelayMode,
        transactional_id: &str,
    ) -> Result<Self, KrafkaError> {
        let kafka = builder(settings, authenticated(settings)).connect().await?;
        let producer = kafka
            .producer()
            .acks(Acks::All)
            .idempotent(true)
            .compression(Compression::Lz4)
            .retry_backoff(settings.retry_delay)
            .delivery_timeout(settings.request_timeout.saturating_mul(5));
        match mode {
            RelayMode::EpochOnly => producer
                .build()
                .await
                .map(|producer| Self::Idempotent(Box::new(producer))),
            RelayMode::Transactional {
                transaction_timeout,
            } => producer
                .transaction_timeout(transaction_timeout)
                .build_transactional(transactional_id)
                .await
                .map(|producer| Self::Transactional(Box::new(producer))),
        }
    }

    async fn append(&self, records: &[PolicyLogRecord]) -> Result<Vec<i64>, KrafkaError> {
        match self {
            Self::Idempotent(producer) => send_plain(producer, records).await,
            Self::Transactional(producer) => append_in_transaction(producer, records).await,
        }
    }
}

/// Sends the records in one transaction and returns their offsets once it committed; a transaction
/// that cannot commit is aborted, so none of its records is ever visible to a `read_committed`
/// reader.
async fn append_in_transaction(
    producer: &TransactionalProducer,
    records: &[PolicyLogRecord],
) -> Result<Vec<i64>, KrafkaError> {
    producer.begin()?;
    match send_all(producer, records).await {
        Ok(offsets) => producer.commit().await.map(|()| offsets),
        Err(error) => Err(abort_after(producer, error).await),
    }
}

/// Aborts the open transaction after `error` and returns the error to report.
///
/// Under the transaction protocol of KIP-890 a fenced producer first learns of it as an abortable
/// produce error (`INVALID_PRODUCER_EPOCH`) and only the abort reports the fencing, so a fenced
/// abort replaces `error`. Any other failing abort is logged, because the broker aborts the
/// transaction at its timeout all the same.
async fn abort_after(producer: &TransactionalProducer, error: KrafkaError) -> KrafkaError {
    reported_after_abort(error, producer.abort().await)
}

/// The error to report for a transaction that failed with `error` and whose abort ended with
/// `aborted`: the abort's own error when it proves the producer fenced, `error` otherwise.
fn reported_after_abort(error: KrafkaError, aborted: Result<(), KrafkaError>) -> KrafkaError {
    match aborted {
        Ok(()) => error,
        Err(abort) if is_fenced(&abort) => abort,
        Err(abort) => {
            log_abort_failed(&abort);
            error
        }
    }
}

fn log_abort_failed(error: &KrafkaError) {
    tracing::warn!(error = %error, "the relay transaction could not be aborted");
}

/// Sends the records without a transaction, in the order given.
async fn send_plain(
    producer: &Producer,
    records: &[PolicyLogRecord],
) -> Result<Vec<i64>, KrafkaError> {
    let mut handles = Vec::with_capacity(records.len());
    for record in records {
        handles.push(producer.enqueue(to_record(record)).await?);
    }
    offsets(handles).await
}

async fn send_all(
    producer: &TransactionalProducer,
    records: &[PolicyLogRecord],
) -> Result<Vec<i64>, KrafkaError> {
    let mut handles = Vec::with_capacity(records.len());
    for record in records {
        handles.push(producer.enqueue(to_record(record)).await?);
    }
    offsets(handles).await
}

/// The stored offset of every handle, in order.
async fn offsets(handles: Vec<DeliveryHandle>) -> Result<Vec<i64>, KrafkaError> {
    let mut stored = Vec::with_capacity(handles.len());
    for handle in handles {
        stored.push(offset_of(&handle.await?)?);
    }
    Ok(stored)
}

/// The offset a broker stored a record at; an acknowledgement without one (a deduplicated retry)
/// does not count, so the row stays unpublished and is sent again.
fn offset_of(metadata: &RecordMetadata) -> Result<i64, KrafkaError> {
    stored_offset(metadata.is_success(), metadata.offset)
}

/// `offset` when the broker stored the record (`stored`), the illegal state otherwise.
fn stored_offset(stored: bool, offset: i64) -> Result<i64, KrafkaError> {
    if stored {
        Ok(offset)
    } else {
        Err(KrafkaError::illegal_state(
            "the broker acknowledged the record without a stored offset",
        ))
    }
}

/// The krafka record of `record`: its key, value (none for a tombstone), partition and headers.
fn to_record(record: &PolicyLogRecord) -> Record {
    let key = Bytes::from(record.key.clone());
    let mut built = record.payload.as_ref().map_or_else(
        || Record::tombstone(record.topic.clone(), key.clone()),
        |payload| Record::new(record.topic.clone(), Bytes::from(payload.clone())).key(key.clone()),
    );
    if let Some(partition) = record.partition {
        built = built.partition(partition);
    }
    for (name, value) in &record.headers {
        built = built.header(*name, Bytes::from(value.clone()));
    }
    built
}

/// A fenced producer is a [`PolicyLogError::Fenced`]; every other failure is unavailable.
fn classify(error: &KrafkaError) -> PolicyLogError {
    let cause: BoxError = Box::new(error.clone());
    if is_fenced(error) {
        PolicyLogError::Fenced(cause)
    } else {
        PolicyLogError::Unavailable(cause)
    }
}

const fn is_fenced(error: &KrafkaError) -> bool {
    matches!(error, KrafkaError::Fenced { .. })
        || matches!(
            error,
            KrafkaError::Broker {
                code: ErrorCode::ProducerFenced | ErrorCode::InvalidProducerEpoch,
                ..
            }
        )
}

#[async_trait::async_trait]
impl PolicyLogProducer for KrafkaPolicyLogProducer {
    async fn publish(&self, records: &[PolicyLogRecord]) -> Result<Vec<i64>, PolicyLogError> {
        self.append(records).await
    }
}

#[cfg(test)]
mod tests;
