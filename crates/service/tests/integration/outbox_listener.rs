//! The listener of `iam_outbox` that `service serve` runs beside the outbox relay, against
//! PostgreSQL: it wakes the relay for each notification while this replica leads, lets its
//! connection go when the replica stops leading and takes it again afterwards, and survives a lost
//! connection until the service stops.

use std::sync::Arc;
use std::time::Duration;

use iam_application::{OutboxRelayPorts, OutboxRelaySettings};
use service::bootstrap::{OutboxRelayAdapters, forward_notifications};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use test_support::outbox_store::FakeOutboxStore;
use test_support::policy_log_producer::FakePolicyLogProducer;
use test_support::topic_inspector::FakeTopicInspector;
use tokio::sync::{Notify, watch};

/// How long a test waits for something that must happen.
const DEADLINE: Duration = Duration::from_secs(10);

/// A pool of the one connection that the listener holds, on the database of `pool`.
async fn listen_pool(pool: &PgPool) -> PgPool {
    PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(1))
        .connect_with((*pool.connect_options()).clone())
        .await
        .unwrap()
}

fn adapters(listen_pool: PgPool) -> OutboxRelayAdapters {
    OutboxRelayAdapters {
        ports: OutboxRelayPorts {
            store: Arc::new(FakeOutboxStore::new()),
            producer: Arc::new(FakePolicyLogProducer::acknowledging()),
            inspector: Arc::new(FakeTopicInspector::passing()),
        },
        settings: OutboxRelaySettings::default(),
        listen_pool,
        wake: Arc::new(Notify::new()),
        leading: Arc::new(watch::channel(false).0),
    }
}

/// Notifies the channel until `wake` reports it, which proves that the listener holds its
/// connection.
async fn wakes(pool: &PgPool, wake: &Notify) {
    tokio::time::timeout(DEADLINE, async {
        loop {
            let notified = wake.notified();
            sqlx::query("SELECT pg_notify('iam_outbox', '')")
                .execute(pool)
                .await
                .unwrap();
            if tokio::time::timeout(Duration::from_millis(200), notified)
                .await
                .is_ok()
            {
                return;
            }
        }
    })
    .await
    .unwrap();
}

/// The number of sessions of this database that listen on `iam_outbox`.
async fn listeners(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM pg_stat_activity \
         WHERE datname = current_database() AND query LIKE 'LISTEN %iam_outbox%'",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn until_listeners(pool: &PgPool, expected: i64) {
    tokio::time::timeout(DEADLINE, async {
        while listeners(pool).await != expected {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_listener_lets_its_connection_go_while_the_replica_follows_and_takes_it_again(
    pool: PgPool,
) {
    let adapters = adapters(listen_pool(&pool).await);
    let wake = Arc::clone(&adapters.wake);
    let leading = Arc::clone(&adapters.leading);
    leading.send_replace(true);
    let (stop, stopping) = watch::channel(false);
    let handle = tokio::spawn(forward_notifications(adapters, stopping));
    wakes(&pool, &wake).await;

    leading.send_replace(false);
    until_listeners(&pool, 0).await;
    leading.send_replace(true);
    wakes(&pool, &wake).await;
    stop.send_replace(true);

    tokio::time::timeout(DEADLINE, handle)
        .await
        .unwrap()
        .unwrap();
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_lost_connection_that_cannot_be_opened_again_keeps_the_listener_until_the_service_stops(
    pool: PgPool,
) {
    let listen = listen_pool(&pool).await;
    let adapters = adapters(listen.clone());
    let wake = Arc::clone(&adapters.wake);
    adapters.leading.send_replace(true);
    let (stop, stopping) = watch::channel(false);
    let handle = tokio::spawn(forward_notifications(adapters, stopping));
    wakes(&pool, &wake).await;
    // A closed pool hands out no connection, so the listener cannot open its connection again.
    let closing = tokio::spawn(async move { listen.close().await });

    sqlx::query(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
         WHERE datname = current_database() AND query LIKE 'LISTEN %iam_outbox%'",
    )
    .execute(&pool)
    .await
    .unwrap();
    until_listeners(&pool, 0).await;
    // Past the reconnect delay of one second the listener tries to open its connection again,
    // fails on the closed pool and waits once more, still running.
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    assert!(!handle.is_finished());
    stop.send_replace(true);

    tokio::time::timeout(DEADLINE, handle)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(DEADLINE, closing)
        .await
        .unwrap()
        .unwrap();
}
