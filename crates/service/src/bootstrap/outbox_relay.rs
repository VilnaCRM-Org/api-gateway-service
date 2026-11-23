//! The wiring of the outbox relay: its ports, the dedicated `LISTEN` connection and the task that
//! forwards the notifications of the database to the relay loop (FR-46).

use std::sync::Arc;
use std::time::Duration;

use iam_application::{OutboxRelayPorts, OutboxRelaySettings};
use iam_domain::RepositoryError;
use iam_infrastructure::{
    KrafkaPolicyLogProducer, KrafkaTopicInspector, PgOutboxListener, PgOutboxStore, RelayMode,
};
use shared_infrastructure::persistence::{PostgresSettings, connect_lazy};
use tokio::sync::{Notify, watch};

use crate::config::Config;

/// How long the listener waits before it opens its connection again.
pub(super) const RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// What the outbox relay needs from the composition root.
#[derive(Debug, Clone)]
pub struct OutboxRelayAdapters {
    /// The outbox, the Kafka producer and the topic inspector.
    pub ports: OutboxRelayPorts,
    /// The settings of a batch and of the cleanup.
    pub settings: OutboxRelaySettings,
    /// The pool of the one connection that holds `LISTEN iam_outbox`.
    pub listen_pool: sqlx::PgPool,
    /// Notified for every notification of the database; the relay loop starts its next batch.
    pub wake: Arc<Notify>,
    /// `true` while this replica leads the relay; the listener holds its connection only then.
    pub leading: Arc<watch::Sender<bool>>,
}

impl OutboxRelayAdapters {
    /// The production wiring over the pool of the application. The relay publishes through the
    /// transactional producer `iam-relay` with the timeout of `KAFKA_TRANSACTION_TIMEOUT`; the
    /// pool of the listener holds one connection to `DATABASE_LISTEN_URL` and opens it lazily.
    ///
    /// # Errors
    ///
    /// The parse error when `DATABASE_LISTEN_URL` is not a valid PostgreSQL URL.
    pub fn connect(config: &Config, pool: &sqlx::PgPool) -> Result<Self, sqlx::Error> {
        let listen = PostgresSettings {
            url: config.relay.listen_url.clone(),
            max_connections: 1,
            ..config.database.clone()
        };
        let mode = RelayMode::Transactional {
            transaction_timeout: config.relay.transaction_timeout,
        };
        Ok(Self {
            ports: OutboxRelayPorts {
                store: Arc::new(PgOutboxStore::new(pool.clone())),
                producer: Arc::new(KrafkaPolicyLogProducer::new(&config.kafka, mode)),
                inspector: Arc::new(KrafkaTopicInspector::new(&config.kafka)),
            },
            settings: OutboxRelaySettings::default(),
            listen_pool: connect_lazy(&listen)?,
            wake: Arc::new(Notify::new()),
            leading: Arc::new(watch::channel(false).0),
        })
    }
}

/// Forwards the notifications of `iam_outbox` to `wake` while this replica leads the relay.
///
/// It ends when `shutdown` is set. A lost connection is opened again after [`RECONNECT_DELAY`]; a
/// notification that is lost meanwhile costs one poll of the relay.
pub async fn forward_notifications(
    adapters: OutboxRelayAdapters,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut leading = adapters.leading.subscribe();
    while !*shutdown.borrow() {
        let ready = tokio::select! {
            led = leading.wait_for(|leads| *leads) => {
                drop(led);
                true
            }
            stopping = shutdown.wait_for(|stopping| *stopping) => {
                drop(stopping);
                false
            }
        };
        if !ready {
            return;
        }
        listen_while_leading(&adapters, &mut leading, &mut shutdown).await;
    }
}

/// Holds one `LISTEN` connection until the replica stops leading, the service stops or the
/// connection fails.
async fn listen_while_leading(
    adapters: &OutboxRelayAdapters,
    leading: &mut watch::Receiver<bool>,
    shutdown: &mut watch::Receiver<bool>,
) {
    match PgOutboxListener::connect(&adapters.listen_pool).await {
        Ok(listener) => forward(listener, adapters, leading, shutdown).await,
        Err(error) => {
            log_connect_failed(&error);
            pause(shutdown).await;
        }
    }
}

/// Wakes the relay for every notification of `listener`.
async fn forward(
    mut listener: PgOutboxListener,
    adapters: &OutboxRelayAdapters,
    leading: &mut watch::Receiver<bool>,
    shutdown: &mut watch::Receiver<bool>,
) {
    loop {
        match next_notification(&mut listener, leading, shutdown).await {
            Some(Ok(())) => adapters.wake.notify_one(),
            Some(Err(error)) => {
                log_connection_lost(&error);
                pause(shutdown).await;
                return;
            }
            None => return,
        }
    }
}

/// The next notification, or `None` when the replica stops leading or the service stops.
async fn next_notification(
    listener: &mut PgOutboxListener,
    leading: &mut watch::Receiver<bool>,
    shutdown: &mut watch::Receiver<bool>,
) -> Option<Result<(), RepositoryError>> {
    tokio::select! {
        heard = listener.notified() => Some(heard),
        stopped = leading.wait_for(|leads| !*leads) => {
            drop(stopped);
            None
        }
        stopping = shutdown.wait_for(|stopping| *stopping) => {
            drop(stopping);
            None
        }
    }
}

fn log_connect_failed(error: &RepositoryError) {
    tracing::warn!(error = %error, "the outbox listener could not connect");
}

fn log_connection_lost(error: &RepositoryError) {
    tracing::warn!(error = %error, "the outbox listener lost its connection");
}

/// Waits for [`RECONNECT_DELAY`], or less when the service stops.
async fn pause(shutdown: &mut watch::Receiver<bool>) {
    tokio::select! {
        () = tokio::time::sleep(RECONNECT_DELAY) => {}
        stopping = shutdown.wait_for(|stopping| *stopping) => drop(stopping),
    }
}

#[cfg(test)]
mod tests;
