use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;

use iam_domain::{
    ActorRef, BulkChunkCommitter, BulkKind, BulkOperation, BulkOperationId, BulkStamp,
    ChunkCommitError, CommittedChunk, PolicyVersion, SystemComponent,
};
use shared_domain::Uuid;

use super::BulkChunkRouter;

const OPERATION: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890af";

/// A committer that counts its calls and answers a chunk of one record at `version`.
#[derive(Debug)]
struct Counting {
    version: i64,
    calls: Mutex<u32>,
}

impl Counting {
    fn new(version: i64) -> Arc<Self> {
        Arc::new(Self {
            version,
            calls: Mutex::new(0),
        })
    }

    fn calls(&self) -> u32 {
        *self.calls.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[async_trait::async_trait]
impl BulkChunkCommitter for Counting {
    async fn commit_next_chunk(
        &self,
        _operation: &BulkOperation,
        _stamp: BulkStamp,
    ) -> Result<CommittedChunk, ChunkCommitError> {
        let mut calls = self.calls.lock().unwrap_or_else(PoisonError::into_inner);
        *calls = calls.saturating_add(1);
        drop(calls);
        Ok(CommittedChunk {
            records: 1,
            version: PolicyVersion::new(self.version).unwrap(),
        })
    }
}

fn router_of(deletion: &Arc<Counting>, resync: &Arc<Counting>) -> BulkChunkRouter {
    let deletion: Arc<dyn BulkChunkCommitter> = Arc::<Counting>::clone(deletion);
    let resync: Arc<dyn BulkChunkCommitter> = Arc::<Counting>::clone(resync);
    BulkChunkRouter::new(deletion, resync)
}

fn operation(kind: BulkKind) -> BulkOperation {
    BulkOperation::pending(
        BulkOperationId::parse(OPERATION).unwrap(),
        kind,
        3,
        ActorRef::System(SystemComponent::Startup),
        SystemTime::UNIX_EPOCH,
    )
    .unwrap()
}

fn stamp() -> BulkStamp {
    BulkStamp {
        event_id: Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890b0").unwrap(),
        occurred_at: SystemTime::UNIX_EPOCH,
    }
}

#[tokio::test]
async fn a_role_deletion_goes_to_the_role_deletion_committer() {
    let deletion = Counting::new(1);
    let resync = Counting::new(2);
    let router = router_of(&deletion, &resync);

    let chunk = router
        .commit_next_chunk(&operation(BulkKind::RoleDeletion), stamp())
        .await
        .unwrap();

    assert_eq!(chunk.version.value(), 1);
    assert_eq!((deletion.calls(), resync.calls()), (1, 0));
}

#[tokio::test]
async fn a_resync_goes_to_the_resync_committer() {
    let deletion = Counting::new(1);
    let resync = Counting::new(2);
    let router = router_of(&deletion, &resync);

    let chunk = router
        .commit_next_chunk(&operation(BulkKind::Resync), stamp())
        .await
        .unwrap();

    assert_eq!(chunk.version.value(), 2);
    assert_eq!((deletion.calls(), resync.calls()), (0, 1));
}

#[tokio::test]
async fn a_kind_without_a_committer_fails_with_the_reason_and_calls_nobody() {
    let deletion = Counting::new(1);
    let resync = Counting::new(2);
    let router = router_of(&deletion, &resync);

    for kind in [BulkKind::Catalogue, BulkKind::Other] {
        let error = router
            .commit_next_chunk(&operation(kind), stamp())
            .await
            .unwrap_err();

        let ChunkCommitError::Permanent(reason) = error else {
            panic!("a permanent failure expected");
        };
        assert!(reason.contains(kind.as_str()));
    }
    assert_eq!((deletion.calls(), resync.calls()), (0, 0));
}
