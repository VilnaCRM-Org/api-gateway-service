use std::sync::Arc;
use std::time::SystemTime;

use iam_domain::{
    AccessCheck, AccessClass, AccessLane, AccessTarget, Credential, DecisionReason,
    PermissionsTarget, PolicyReadRepository, Rng, SampleRate, ServiceName,
};
use shared_domain::QueryHandler as _;
use test_support::clock::FixedClock;
use test_support::decision_snapshot::DecisionSnapshot;
use test_support::id::SequenceUuidGenerator;
use test_support::policy_view::FakePolicyView;
use test_support::request_digester::FakeRequestDigester;
use test_support::token::FakeTokenRepository;

use super::{
    StaleValidateAccessBatchQueryHandler, StaleValidateAccessQueryHandler,
    ValidateAccessStaleBatchQuery, ValidateAccessStaleQuery,
};
use crate::access_decision_service::AccessDecisionService;
use crate::access_log::{
    AccessLogCounters, AccessLogReceiver, AccessRecordBuilder, AccessRecorder,
    BATCH_VALIDATION_TEMPLATE, DecisionAccessLog, VALIDATION_TEMPLATE, access_log_channel,
};
use crate::query::validate_access::ValidateAccessQuery;
use crate::query::validate_access_batch::{BatchCheck, ValidateAccessBatchQuery};
use crate::service_catalog_loader::ServiceCatalogLoader;

#[derive(Debug)]
struct ZeroRng;

impl Rng for ZeroRng {
    fn next_u64(&self) -> u64 {
        0
    }
}

fn decisions() -> Arc<AccessDecisionService> {
    let version = iam_domain::PolicyVersion::new(5).unwrap();
    let view = Arc::new(FakePolicyView::with_snapshot(Arc::new(
        DecisionSnapshot::at(version),
    )));
    let freshness = Arc::new(crate::freshness::FreshnessState::new(
        iam_domain::FreshnessRule::new(
            std::time::Duration::from_secs(15),
            std::time::Duration::from_secs(2),
        ),
        Arc::new(test_support::boot_clock::FakeBootClock::starting_at(
            iam_domain::BootInstant::from_elapsed(std::time::Duration::from_secs(100)),
        )),
    ));
    let reads = Arc::new(crate::snapshot_policy_reads::SnapshotPolicyReads::new(
        view, freshness,
    ));
    let policy: Arc<dyn PolicyReadRepository> = reads;
    Arc::new(AccessDecisionService::new(
        Arc::new(FakeTokenRepository::new()),
        ServiceCatalogLoader::new(Arc::clone(&policy)),
        policy,
        Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    ))
}

fn log() -> (Arc<DecisionAccessLog>, AccessLogReceiver) {
    let (channel, receiver) = access_log_channel(32, Arc::new(AccessLogCounters::new()));
    let recorder = AccessRecorder::new(
        AccessRecordBuilder::new(Arc::new(ZeroRng), SampleRate::ALL),
        channel,
    );
    let log = DecisionAccessLog::new(
        Arc::new(recorder),
        Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
        Arc::new(FakeRequestDigester),
    );
    (Arc::new(log), receiver)
}

fn query(credential: &str) -> ValidateAccessQuery {
    ValidateAccessQuery {
        credential: Credential::new(credential.to_owned()),
        check: AccessCheck::new(
            ServiceName::new("orders").unwrap(),
            AccessTarget::Permissions(
                PermissionsTarget::new(vec!["rest:orders:GET /api/orders".to_owned()]).unwrap(),
            ),
            None,
            None,
        ),
    }
}

#[tokio::test]
async fn a_stale_single_check_is_the_deny_unavailable_with_one_record_of_its_decision_id() {
    let (log, receiver) = log();
    let handler = StaleValidateAccessQueryHandler::new(decisions()).with_access_log(log);

    let outcome = handler
        .handle(ValidateAccessStaleQuery(query("token")))
        .await
        .unwrap();

    assert_eq!(outcome.reason(), DecisionReason::Unavailable);
    let item = receiver.try_next().unwrap();
    assert!(receiver.try_next().is_none());
    assert_eq!(item.record.decision_id, outcome.decision_id().as_uuid());
    assert_eq!(item.record.reason, DecisionReason::Unavailable);
    assert_eq!(
        item.record.route_template.as_deref(),
        Some(VALIDATION_TEMPLATE)
    );
    assert_eq!(item.lane, AccessLane::Access);
    assert_eq!(item.class, AccessClass::Error);
    assert!(item.record.credential_digest_prefix.is_some());
}

#[tokio::test]
async fn a_stale_batch_leaves_one_record_per_item_and_an_unreadable_item_is_malformed() {
    let (log, receiver) = log();
    let handler = StaleValidateAccessBatchQueryHandler::new(decisions()).with_access_log(log);
    let checks = vec![
        BatchCheck::Valid(query("token")),
        BatchCheck::Malformed,
        BatchCheck::Valid(query("other")),
    ];

    let outcomes = handler
        .handle(ValidateAccessStaleBatchQuery(ValidateAccessBatchQuery {
            checks,
        }))
        .await
        .unwrap();

    let reasons: Vec<_> = outcomes
        .iter()
        .map(iam_domain::DecisionOutcome::reason)
        .collect();
    assert_eq!(
        reasons,
        [
            DecisionReason::Unavailable,
            DecisionReason::MalformedOperation,
            DecisionReason::Unavailable
        ]
    );
    for outcome in &outcomes {
        let item = receiver.try_next().unwrap();
        assert_eq!(item.record.decision_id, outcome.decision_id().as_uuid());
        assert_eq!(item.record.reason, outcome.reason());
        assert_eq!(
            item.record.route_template.as_deref(),
            Some(BATCH_VALIDATION_TEMPLATE)
        );
    }
    assert!(receiver.try_next().is_none());
}

#[tokio::test]
async fn a_stale_handler_without_an_access_log_still_answers() {
    let single = StaleValidateAccessQueryHandler::new(decisions());
    let batch = StaleValidateAccessBatchQueryHandler::new(decisions());

    let outcome = single
        .handle(ValidateAccessStaleQuery(query("token")))
        .await
        .unwrap();
    let outcomes = batch
        .handle(ValidateAccessStaleBatchQuery(ValidateAccessBatchQuery {
            checks: vec![BatchCheck::Malformed],
        }))
        .await
        .unwrap();

    assert_eq!(outcome.reason(), DecisionReason::Unavailable);
    assert_eq!(outcomes[0].reason(), DecisionReason::MalformedOperation);
}
