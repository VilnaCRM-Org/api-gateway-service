//! The policy resync against PostgreSQL: the handler starts a new log epoch above the highest
//! version of the topic, the committer republishes every entity under it, and the contract has no
//! cache flush.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_application::{
    PolicyTopicHead, ResyncChunkCommitter, ResyncPolicyCommand, ResyncPolicyCommandHandler,
    ResyncPolicyPorts, ResyncPorts,
};
use iam_domain::{
    BulkChunkCommitter as _, BulkChunker, BulkKind, BulkOperationId, BulkOperationRepository as _,
    BulkStamp, BulkStatus, ChangeId, ChangeStatement, DecisionEffect, IamUnitOfWork as _,
    PolicyDigestValue, RoleKind, RoleStatement, WriteMode,
};
use iam_infrastructure::{
    PgBulkOperationRepository, PgIamUnitOfWork, PgPolicyEpochRepository, PgPolicyStateInventory,
};
use shared_domain::{CommandHandler as _, Uuid};
use shared_infrastructure::clock::SystemClock;
use shared_infrastructure::id::UuidV7Generator;
use sqlx::PgPool;
use test_support::anti_entropy::{FakePolicyLogTail, TextHeadCodec, head_record};
use test_support::role::{role, role_writer};
use test_support::seed::TestRng;
use test_support::unit_of_work::{iam_change, rebuilt};

use crate::support::Scratch;

const ROLES: usize = 3;
const TOPIC_MAXIMUM: i64 = 500;

/// Stores three roles in one versioned change, so the policy is at version 1.
async fn seeded(pool: &PgPool, rng: &mut TestRng) {
    let statements: Vec<ChangeStatement> = (0..ROLES)
        .map(|index| {
            let role = role(rng, &format!("Role {index}"), RoleKind::Custom);
            ChangeStatement::SaveRole(Box::new(RoleStatement::insert(&role, role_writer(rng))))
        })
        .collect();
    let change = rebuilt(&iam_change(rng, DecisionEffect::Affected, 0), |parts| {
        parts.statements = statements;
    });
    PgIamUnitOfWork::new(pool.clone())
        .commit(change, WriteMode::Published)
        .await
        .unwrap();
}

fn handler(pool: &PgPool, topic_maximum: Option<i64>) -> ResyncPolicyCommandHandler {
    let records = topic_maximum
        .map(|version| vec![head_record(0, version, PolicyDigestValue::ZERO, 1)])
        .unwrap_or_default();
    ResyncPolicyCommandHandler::new(ResyncPolicyPorts {
        epochs: Arc::new(PgPolicyEpochRepository::new(pool.clone())),
        inventory: Arc::new(PgPolicyStateInventory::new(pool.clone())),
        topic: PolicyTopicHead::new(
            Arc::new(FakePolicyLogTail::with(records)),
            Arc::new(TextHeadCodec),
        ),
        unit_of_work: Arc::new(PgIamUnitOfWork::new(pool.clone())),
        clock: Arc::new(SystemClock),
        ids: Arc::new(UuidV7Generator),
    })
}

fn committer(pool: &PgPool, chunk_entities: usize) -> ResyncChunkCommitter {
    ResyncChunkCommitter::new(
        ResyncPorts {
            policy_epochs: Arc::new(PgPolicyEpochRepository::new(pool.clone())),
            inventory: Arc::new(PgPolicyStateInventory::new(pool.clone())),
            unit_of_work: Arc::new(PgIamUnitOfWork::new(pool.clone())),
            ids: Arc::new(UuidV7Generator),
        },
        BulkChunker::new(chunk_entities).unwrap(),
    )
}

fn command(change_id: ChangeId) -> ResyncPolicyCommand {
    ResyncPolicyCommand {
        change_id,
        actor: iam_domain::ActorRef::System(iam_domain::SystemComponent::Startup),
        reason: "The state topic lost records.".to_owned(),
        idempotency: None,
    }
}

fn stamp() -> BulkStamp {
    BulkStamp {
        event_id: Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890b0").unwrap(),
        occurred_at: SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(1_700_000_000))
            .unwrap(),
    }
}

async fn epoch_row(pool: &PgPool) -> (i64, i64, Vec<u8>) {
    sqlx::query_as("SELECT log_epoch, version, digest FROM iam_policy_epoch WHERE id = 1")
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Runs the committer until the operation is finished and returns the versions of its chunks.
async fn run_to_the_end(
    pool: &PgPool,
    committer: &ResyncChunkCommitter,
    id: BulkOperationId,
) -> Vec<i64> {
    let repository = PgBulkOperationRepository::new(pool.clone());
    let mut versions = Vec::new();
    for _ in 0..10 {
        let operation = repository.find(id).await.unwrap().unwrap();
        if operation.parts().status.is_finished() {
            break;
        }
        let chunk = committer
            .commit_next_chunk(&operation, stamp())
            .await
            .unwrap();
        versions.push(chunk.version.value());
    }
    versions
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_resync_continues_above_the_topic_maximum_and_republishes_every_entity(pool: PgPool) {
    let mut rng = TestRng::from_env();
    seeded(&pool, &mut rng).await;
    let (_epoch, _version, digest_before) = epoch_row(&pool).await;
    let change_id =
        ChangeId::from_uuid(Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ac").unwrap());

    handler(&pool, Some(TOPIC_MAXIMUM))
        .handle(command(change_id))
        .await
        .unwrap();

    let id = BulkOperationId::from_uuid(change_id.as_uuid());
    let stored = PgBulkOperationRepository::new(pool.clone())
        .find(id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.parts().kind, BulkKind::Resync);
    assert_eq!(stored.parts().status, BulkStatus::Pending);
    assert_eq!(stored.parts().total_records, 3);
    let (log_epoch, version, _digest) = epoch_row(&pool).await;
    assert_eq!((log_epoch, version), (1, TOPIC_MAXIMUM + 1));

    let versions = run_to_the_end(&pool, &committer(&pool, 2), id).await;

    assert_eq!(versions, [TOPIC_MAXIMUM + 2, TOPIC_MAXIMUM + 3]);
    let (log_epoch, version, digest_after) = epoch_row(&pool).await;
    assert_eq!((log_epoch, version), (1, TOPIC_MAXIMUM + 3));
    assert_eq!(digest_after, digest_before);
    let finished = PgBulkOperationRepository::new(pool.clone())
        .find(id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(finished.parts().status, BulkStatus::Completed);
    let republished: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT record_key) FROM iam_outbox
        WHERE kind = 'state' AND log_epoch = 1 AND record_key LIKE 'role/%'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(republished, 3);
    let below: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM iam_outbox WHERE kind = 'state' AND log_epoch = 1
        AND policy_version <= $1",
    )
    .bind(TOPIC_MAXIMUM)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(below, 0);
    let events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM iam_outbox WHERE kind = 'event'
        AND event_type = 'iam.policy.resynced'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(events, 1);
    let audits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM iam_security_audit_events WHERE action = 'policy.resync'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audits, 1);
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_topic_below_postgresql_leaves_the_stored_version_as_the_floor(pool: PgPool) {
    let mut rng = TestRng::from_env();
    seeded(&pool, &mut rng).await;
    let change_id =
        ChangeId::from_uuid(Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ac").unwrap());

    handler(&pool, None)
        .handle(command(change_id))
        .await
        .unwrap();

    let (log_epoch, version, _digest) = epoch_row(&pool).await;
    assert_eq!((log_epoch, version), (1, 2));
}

#[sqlx::test(migrator = "shared_infrastructure::persistence::MIGRATOR")]
async fn a_policy_without_entities_cannot_be_resynced(pool: PgPool) {
    let change_id =
        ChangeId::from_uuid(Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ac").unwrap());

    let refused = handler(&pool, None)
        .handle(command(change_id))
        .await
        .unwrap_err();

    assert!(matches!(refused, iam_application::IamError::Conflict));
    assert_eq!(epoch_row(&pool).await.0, 0);
}

#[test]
fn neither_exported_contract_has_a_cache_flush_operation() {
    let scratch = Scratch::new();

    for command in ["openapi-export", "graphql-export"] {
        let output = scratch.run(&[command], &[]);

        assert_eq!(output.status.code(), Some(0));
        let text = String::from_utf8(output.stdout).unwrap().to_lowercase();
        assert!(!text.contains("flush"), "{command}");
        assert!(!text.contains("cache-flush"), "{command}");
    }
}

#[test]
fn the_exported_contracts_have_the_policy_resync() {
    let scratch = Scratch::new();

    let openapi = scratch.run(&["openapi-export"], &[]);
    let graphql = scratch.run(&["graphql-export"], &[]);

    let openapi = String::from_utf8(openapi.stdout).unwrap();
    let graphql = String::from_utf8(graphql.stdout).unwrap();
    assert!(openapi.contains("/api/policy-resyncs:"));
    assert!(graphql.contains("resyncPolicy(input: ResyncPolicyInput!): BulkOperation!"));
}
