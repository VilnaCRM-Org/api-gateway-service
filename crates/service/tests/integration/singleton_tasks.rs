//! Singleton tasks against PostgreSQL: two replicas of the same task never run a batch at once, a
//! terminated lock holder is rolled back, a leader that stops is replaced within one retry
//! interval and a stop signal during a batch commits it or rolls it back within the grace period.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use iam_application::{BatchOutcome, SingletonInterval, SingletonLoop, SingletonWork};
use iam_domain::{
    LeaderBatch, Leadership, SingletonLeadership as _, SingletonTask, TaskStateRepository as _,
};
use iam_infrastructure::{AdvisoryLockLeadership, PgTaskStateRepository};
use service::bootstrap::{TaskMode, TaskStop, TaskSupervisor};
use shared_domain::BoxError;
use shared_infrastructure::clock::SystemClock;
use sqlx::PgPool;
use tokio::sync::{Notify, watch};

const TASK: SingletonTask = SingletonTask::new("integration-singleton", 7_201);
const INTERVAL: Duration = Duration::from_millis(100);
const GRACE: Duration = Duration::from_secs(5);

/// Work that holds its batch for a while and watches how many batches run at once.
#[derive(Debug, Default)]
struct ProbeWork {
    hold: Duration,
    active: AtomicUsize,
    peak: AtomicUsize,
    runs: AtomicUsize,
}

impl ProbeWork {
    fn holding(hold: Duration) -> Arc<Self> {
        Arc::new(Self {
            hold,
            ..Self::default()
        })
    }
}

#[async_trait::async_trait]
impl SingletonWork for ProbeWork {
    async fn run(&self, _batch: &mut dyn LeaderBatch) -> Result<(), BoxError> {
        let now = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::SeqCst);
        tokio::time::sleep(self.hold).await;
        self.active.fetch_sub(1, Ordering::SeqCst);
        self.runs.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// Work that tells the test that its batch started and ends when the test releases it, or never.
#[derive(Debug, Default)]
struct GatedWork {
    started: Notify,
    release: Notify,
    forever: bool,
}

#[async_trait::async_trait]
impl SingletonWork for GatedWork {
    async fn run(&self, _batch: &mut dyn LeaderBatch) -> Result<(), BoxError> {
        self.started.notify_one();
        if self.forever {
            std::future::pending::<()>().await;
        }
        self.release.notified().await;
        Ok(())
    }
}

/// The work as the port that the loop takes.
fn erased<W: SingletonWork + 'static>(work: &Arc<W>) -> Arc<dyn SingletonWork> {
    Arc::<W>::clone(work)
}

fn singleton(pool: &PgPool, work: Arc<dyn SingletonWork>) -> SingletonLoop {
    SingletonLoop::new(
        TASK,
        SingletonInterval::new(INTERVAL).unwrap(),
        Arc::new(AdvisoryLockLeadership::new(pool.clone())),
        Arc::new(SystemClock),
        work,
    )
}

async fn until(limit: Duration, mut done: impl FnMut() -> bool) -> bool {
    tokio::time::timeout(limit, async {
        while !done() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .is_ok()
}

async fn run_count(pool: &PgPool) -> u64 {
    PgTaskStateRepository::new(pool.clone())
        .find(TASK.name())
        .await
        .unwrap()
        .map_or(0, |state| state.run_count)
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn two_replicas_never_run_a_batch_at_once(pool: PgPool) {
    let work = ProbeWork::holding(Duration::from_millis(80));
    let (stop, stopping) = watch::channel(false);
    let replicas: Vec<_> = (0..2)
        .map(|_| {
            let work: Arc<dyn SingletonWork> = erased(&work);
            tokio::spawn(singleton(&pool, work).run(stopping.clone()))
        })
        .collect();

    let ran = until(Duration::from_secs(10), || {
        work.runs.load(Ordering::SeqCst) >= 4
    })
    .await;
    stop.send_replace(true);
    for replica in replicas {
        replica.await.unwrap();
    }

    assert!(ran, "the replicas must run batches");
    assert_eq!(work.peak.load(Ordering::SeqCst), 1);
    assert_eq!(
        run_count(&pool).await,
        u64::try_from(work.runs.load(Ordering::SeqCst)).unwrap()
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_terminated_lock_holder_is_rolled_back_and_the_other_replica_leads(pool: PgPool) {
    let gated = Arc::new(GatedWork::default());
    let first_work: Arc<dyn SingletonWork> = erased(&gated);
    let first = singleton(&pool, first_work);
    let second = singleton(&pool, ProbeWork::holding(Duration::ZERO));
    let first = tokio::spawn(async move { first.run_batch().await });
    gated.started.notified().await;

    let terminated: i64 = sqlx::query_scalar(
        "SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity \
         WHERE datname = current_database() AND state = 'idle in transaction' \
         AND query LIKE '%pg_try_advisory_xact_lock%'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let second_outcome = second.run_batch().await;
    gated.release.notify_one();
    let first_outcome = first.await.unwrap();

    assert_eq!(terminated, 1);
    assert_eq!(second_outcome, BatchOutcome::Committed);
    assert_eq!(first_outcome, BatchOutcome::RolledBack);
    assert_eq!(run_count(&pool).await, 1);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn the_other_replica_runs_the_next_batch_within_one_retry_interval(pool: PgPool) {
    let first_work = ProbeWork::holding(Duration::ZERO);
    let second_work = ProbeWork::holding(Duration::ZERO);
    let (stop_first, first_stopping) = watch::channel(false);
    let (stop_second, second_stopping) = watch::channel(false);
    let first_port: Arc<dyn SingletonWork> = erased(&first_work);
    let second_port: Arc<dyn SingletonWork> = erased(&second_work);
    let first = tokio::spawn(singleton(&pool, first_port).run(first_stopping));
    let second = tokio::spawn(singleton(&pool, second_port).run(second_stopping));
    let started = until(Duration::from_secs(10), || {
        first_work.runs.load(Ordering::SeqCst) >= 1
    })
    .await;

    stop_first.send_replace(true);
    first.await.unwrap();
    let before = second_work.runs.load(Ordering::SeqCst);
    let took_over = until(
        INTERVAL
            .saturating_mul(2)
            .saturating_add(Duration::from_secs(1)),
        || second_work.runs.load(Ordering::SeqCst) > before,
    )
    .await;
    stop_second.send_replace(true);
    second.await.unwrap();

    assert!(started);
    assert!(
        took_over,
        "the survivor must lead within one retry interval"
    );
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_batch_in_flight_at_the_stop_signal_commits_within_the_grace_period(pool: PgPool) {
    let work = ProbeWork::holding(Duration::from_millis(300));
    let (stop, stopping) = watch::channel(false);
    let mut supervisor = TaskSupervisor::new(TaskMode::Serve, stopping);
    let port: Arc<dyn SingletonWork> = erased(&work);
    supervisor.spawn_singleton(singleton(&pool, port));
    let started = until(Duration::from_secs(10), || {
        work.active.load(Ordering::SeqCst) == 1
    })
    .await;

    stop.send_replace(true);
    let outcome = tokio::time::timeout(GRACE, supervisor.stop(GRACE)).await;

    assert!(started);
    assert_eq!(outcome.unwrap(), TaskStop::Drained);
    assert_eq!(run_count(&pool).await, 1);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_batch_that_outlives_the_grace_period_is_aborted_and_rolled_back(pool: PgPool) {
    let work = Arc::new(GatedWork {
        forever: true,
        ..GatedWork::default()
    });
    let (stop, stopping) = watch::channel(false);
    let mut supervisor = TaskSupervisor::new(TaskMode::Serve, stopping);
    let port: Arc<dyn SingletonWork> = erased(&work);
    supervisor.spawn_singleton(singleton(&pool, port));
    work.started.notified().await;

    stop.send_replace(true);
    let outcome = supervisor.stop(Duration::from_millis(300)).await;
    let leadership = AdvisoryLockLeadership::new(pool.clone());
    let freed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Leadership::Leader(batch) = leadership.begin(&TASK).await.unwrap() {
                return batch;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;

    assert_eq!(outcome, TaskStop::Aborted { remaining: 1 });
    assert!(freed.is_ok(), "the aborted batch frees the lock");
    assert_eq!(run_count(&pool).await, 0);
}
