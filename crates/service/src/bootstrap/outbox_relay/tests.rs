use std::sync::Arc;
use std::time::Duration;

use iam_application::{OutboxRelayPorts, OutboxRelaySettings};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use test_support::outbox_store::FakeOutboxStore;
use test_support::policy_log_producer::FakePolicyLogProducer;
use test_support::topic_inspector::FakeTopicInspector;
use tokio::sync::{Notify, watch};

use super::{OutboxRelayAdapters, forward_notifications};

/// A pool that points at a database that does not exist, so every connection attempt fails.
fn unreachable_pool() -> PgPool {
    PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(100))
        .connect_lazy("postgres://nobody:none@127.0.0.1:1/none")
        .unwrap()
}

fn adapters() -> OutboxRelayAdapters {
    OutboxRelayAdapters {
        ports: OutboxRelayPorts {
            store: Arc::new(FakeOutboxStore::new()),
            producer: Arc::new(FakePolicyLogProducer::acknowledging()),
            inspector: Arc::new(FakeTopicInspector::passing()),
        },
        settings: OutboxRelaySettings::default(),
        listen_pool: unreachable_pool(),
        wake: Arc::new(Notify::new()),
        leading: Arc::new(watch::channel(false).0),
    }
}

#[tokio::test]
async fn the_listener_ends_when_the_service_stops_while_this_replica_does_not_lead() {
    let (stop, stopping) = watch::channel(false);
    let handle = tokio::spawn(forward_notifications(adapters(), stopping));
    tokio::task::yield_now().await;

    stop.send_replace(true);

    handle.await.unwrap();
}

#[tokio::test]
async fn the_listener_does_not_start_when_the_service_is_stopping_already() {
    let (_stop, stopping) = watch::channel(true);

    forward_notifications(adapters(), stopping).await;
}

#[tokio::test]
async fn a_leader_whose_connection_fails_waits_before_it_tries_again_and_ends_with_the_service() {
    let adapters = adapters();
    adapters.leading.send_replace(true);
    let (stop, stopping) = watch::channel(false);
    let handle = tokio::spawn(forward_notifications(adapters, stopping));
    tokio::time::sleep(Duration::from_millis(300)).await;

    stop.send_replace(true);

    handle.await.unwrap();
}
