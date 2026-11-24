use std::sync::Arc;

use iam_domain::{
    AuditSummary, ChangeStatement, DecisionEffect, EntityVersion, GatewayStatement, GuardCheck,
    IamUnitOfWork, IdempotencyKey, IdempotencyRequest, RejectedAttemptLog, RequestDigest,
    ServiceName, UpstreamParts, UpstreamProtocol, UpstreamRepository,
};
use shared_domain::{Command as _, CommandHandler as _};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::unit_of_work::FakeIamUnitOfWork;
use test_support::upstream::FakeUpstreamRepository;

use super::{UpdateUpstreamCommand, UpdateUpstreamCommandHandler, UpstreamPatch};
use crate::error::IamError;
use crate::rejected_attempt_fixtures::FakeRejectedAttemptLog;
use crate::upstream_fixtures::{
    UPSTREAM, actor, at, change_id, upstream, upstream_id, upstream_named,
};

struct World {
    unit_of_work: Arc<FakeIamUnitOfWork>,
    attempts: Arc<FakeRejectedAttemptLog>,
    handler: UpdateUpstreamCommandHandler,
}

fn world_with(upstreams: FakeUpstreamRepository, unit_of_work: FakeIamUnitOfWork) -> World {
    let unit_of_work = Arc::new(unit_of_work);
    let attempts = Arc::new(FakeRejectedAttemptLog::new());
    let committing: Arc<dyn IamUnitOfWork> = Arc::<FakeIamUnitOfWork>::clone(&unit_of_work);
    let log: Arc<dyn RejectedAttemptLog> = Arc::<FakeRejectedAttemptLog>::clone(&attempts);
    let upstreams: Arc<dyn UpstreamRepository> = Arc::new(upstreams);
    let handler = UpdateUpstreamCommandHandler::new(
        upstreams,
        committing,
        log,
        Arc::new(FixedClock::at(at())),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    );
    World {
        unit_of_work,
        attempts,
        handler,
    }
}

fn world(stored: UpstreamParts) -> World {
    world_with(
        FakeUpstreamRepository::holding(vec![stored]),
        FakeIamUnitOfWork::new(),
    )
}

fn command(version: i64, patch: UpstreamPatch) -> UpdateUpstreamCommand {
    UpdateUpstreamCommand {
        change_id: change_id(),
        upstream_id: upstream_id(),
        actor: actor(),
        expected: EntityVersion::new(version).unwrap(),
        patch,
        idempotency: None,
    }
}

fn port_and_protocol() -> UpstreamPatch {
    UpstreamPatch {
        port: Some(9090),
        protocol: Some(UpstreamProtocol::Http1),
        ..UpstreamPatch::default()
    }
}

#[test]
fn the_command_is_named_after_its_type() {
    assert_eq!(UpdateUpstreamCommand::NAME, "UpdateUpstreamCommand");
}

#[tokio::test]
async fn a_patch_changes_the_named_settings_and_keeps_the_others() {
    let world = world(upstream(1));

    world
        .handler
        .handle(command(1, port_and_protocol()))
        .await
        .unwrap();

    let committed = world.unit_of_work.committed();
    let [change] = committed.as_slice() else {
        panic!("one change expected: {committed:?}");
    };
    let parts = change.parts();
    assert_eq!(parts.effect, DecisionEffect::Affected);
    assert_eq!(parts.entity_version, EntityVersion::new(2).unwrap());
    let [ChangeStatement::SaveGateway(statement)] = parts.statements.as_slice() else {
        panic!("one gateway statement expected: {:?}", parts.statements);
    };
    let GatewayStatement::Upstream(statement) = statement.as_ref() else {
        panic!("an upstream statement expected: {statement:?}");
    };
    assert_eq!(statement.expected(), Some(EntityVersion::INITIAL));
    let stored = statement.upstream();
    assert_eq!(stored.settings.port(), 9090);
    assert_eq!(stored.settings.protocol(), UpstreamProtocol::Http1);
    assert_eq!(stored.settings.namespace(), "platform");
    assert_eq!(stored.settings.concurrency_limit(), 256);
    assert_eq!(stored.version, EntityVersion::new(2).unwrap());
    assert_eq!(stored.updated_at, at());
    let types: Vec<&str> = parts
        .events
        .iter()
        .map(|event| event.parts().event_type.as_str())
        .collect();
    assert_eq!(types, ["iam.upstream.updated"]);
    assert_eq!(world.attempts.offered(), Vec::new());
}

#[tokio::test]
async fn every_member_of_a_patch_replaces_its_setting() {
    let world = world(upstream(1));
    let patch = UpstreamPatch {
        name: Some("core".to_owned()),
        namespace: Some("edge".to_owned()),
        service_name: Some("core-v2".to_owned()),
        catalog_service: Some("core".to_owned()),
        port: Some(9090),
        protocol: Some(UpstreamProtocol::Http1),
        forward_credentials: Some(true),
        connect_timeout_ms: Some(500),
        response_timeout_ms: Some(20_000),
        concurrency_limit: Some(64),
        retry_budget_percent: Some(25),
        outlier_threshold: Some(3),
    };

    world.handler.handle(command(1, patch)).await.unwrap();

    let committed = world.unit_of_work.committed();
    let ChangeStatement::SaveGateway(statement) = &committed[0].parts().statements[0] else {
        panic!("a gateway statement expected");
    };
    let GatewayStatement::Upstream(statement) = statement.as_ref() else {
        panic!("an upstream statement expected");
    };
    let settings = &statement.upstream().settings;
    assert_eq!(settings.namespace(), "edge");
    assert_eq!(settings.service_name(), "core-v2");
    assert_eq!(settings.port(), 9090);
    assert_eq!(settings.protocol(), UpstreamProtocol::Http1);
    assert!(settings.forward_credentials());
    assert_eq!(settings.connect_timeout_ms(), 500);
    assert_eq!(settings.response_timeout_ms(), 20_000);
    assert_eq!(settings.concurrency_limit(), 64);
    assert_eq!(settings.retry_budget_percent(), 25);
    assert_eq!(settings.outlier_threshold(), 3);
}

#[tokio::test]
async fn the_audit_record_names_both_versions_and_the_changed_settings() {
    let world = world(upstream(1));

    world
        .handler
        .handle(command(1, port_and_protocol()))
        .await
        .unwrap();

    let committed = world.unit_of_work.committed();
    let audit = committed[0].parts().audit.parts();
    assert_eq!(audit.action.as_str(), "upstream.update");
    assert_eq!(audit.target.target_type(), "upstream");
    assert_eq!(audit.target.target_id(), UPSTREAM);
    assert_eq!(audit.actor, actor());
    assert_eq!(audit.occurred_at, at());
    assert_eq!(
        audit.before.as_ref().map(AuditSummary::as_str),
        Some("catalogService=core version=1")
    );
    assert_eq!(
        audit.after.as_ref().map(AuditSummary::as_str),
        Some("catalogService=core version=2 changed=port,protocol")
    );
}

#[tokio::test]
async fn an_update_that_changes_nothing_still_takes_the_next_version() {
    let world = world(upstream(1));

    world
        .handler
        .handle(command(1, UpstreamPatch::default()))
        .await
        .unwrap();

    let committed = world.unit_of_work.committed();
    assert_eq!(
        committed[0]
            .parts()
            .audit
            .parts()
            .after
            .as_ref()
            .map(AuditSummary::as_str),
        Some("catalogService=core version=2 changed=none")
    );
}

#[tokio::test]
async fn the_route_scope_check_covers_the_service_before_and_after_the_change() {
    let moved = world(upstream(1));
    let kept = world(upstream(1));
    let patch = UpstreamPatch {
        catalog_service: Some("payment".to_owned()),
        ..UpstreamPatch::default()
    };

    moved.handler.handle(command(1, patch)).await.unwrap();
    kept.handler
        .handle(command(1, port_and_protocol()))
        .await
        .unwrap();

    assert_eq!(
        moved.unit_of_work.committed()[0].guard(),
        Some(&GuardCheck::RouteScope {
            services: vec![
                ServiceName::new("core").unwrap(),
                ServiceName::new("payment").unwrap()
            ]
        })
    );
    assert_eq!(
        kept.unit_of_work.committed()[0].guard(),
        Some(&GuardCheck::RouteScope {
            services: vec![ServiceName::new("core").unwrap()]
        })
    );
}

#[tokio::test]
async fn an_idempotency_key_is_kept_on_the_change_and_the_audit_record() {
    let world = world(upstream(1));
    let request = IdempotencyRequest {
        key: IdempotencyKey::new("update-core").unwrap(),
        request_digest: RequestDigest::new(&[7_u8; 32]).unwrap(),
    };
    let mut with_key = command(1, port_and_protocol());
    with_key.idempotency = Some(request.clone());

    world.handler.handle(with_key).await.unwrap();

    let committed = world.unit_of_work.committed();
    assert_eq!(committed[0].parts().idempotency, Some(request.clone()));
    assert_eq!(
        committed[0].parts().audit.parts().idempotency_key,
        Some(request.key)
    );
}

#[tokio::test]
async fn an_unknown_upstream_is_not_found() {
    let world = world_with(FakeUpstreamRepository::new(), FakeIamUnitOfWork::new());

    let error = world
        .handler
        .handle(command(1, port_and_protocol()))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::NotFound));
    assert_eq!(world.unit_of_work.committed(), Vec::new());
}

#[tokio::test]
async fn a_stale_version_is_a_failed_precondition_and_commits_nothing() {
    let world = world(upstream(3));

    let error = world
        .handler
        .handle(command(2, port_and_protocol()))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::PreconditionFailed));
    assert_eq!(world.unit_of_work.committed(), Vec::new());
}

#[tokio::test]
async fn another_name_is_a_violation_of_the_name() {
    let world = world(upstream(1));
    let patch = UpstreamPatch {
        name: Some("other".to_owned()),
        ..UpstreamPatch::default()
    };

    let error = world.handler.handle(command(1, patch)).await.unwrap_err();

    let IamError::Invalid(violations) = error else {
        panic!("a violation expected: {error:?}");
    };
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].property_path, "name");
    assert_eq!(violations[0].code, "renamed");
    assert_eq!(world.unit_of_work.committed(), Vec::new());
}

#[tokio::test]
async fn invalid_settings_are_reported_together_and_commit_nothing() {
    let world = world(upstream(1));
    let patch = UpstreamPatch {
        port: Some(0),
        retry_budget_percent: Some(101),
        ..UpstreamPatch::default()
    };

    let error = world.handler.handle(command(1, patch)).await.unwrap_err();

    let IamError::Invalid(violations) = error else {
        panic!("violations expected: {error:?}");
    };
    let paths: Vec<&str> = violations
        .iter()
        .map(|violation| violation.property_path.as_str())
        .collect();
    assert_eq!(paths, ["port", "retryBudgetPercent"]);
    assert_eq!(world.unit_of_work.committed(), Vec::new());
}

fn assert_system_entry(world: &World, error: &IamError) {
    assert!(matches!(error, IamError::SystemEntry), "{error:?}");
    assert_eq!(world.unit_of_work.committed(), Vec::new());
    let offered = world.attempts.offered();
    let [attempt] = offered.as_slice() else {
        panic!("one attempt expected: {offered:?}");
    };
    assert_eq!(attempt.action.as_str(), "upstream.update");
    assert_eq!(attempt.reason.as_str(), "system_entry");
    assert_eq!(attempt.target.target_id(), UPSTREAM);
}

#[tokio::test]
async fn a_system_upstream_is_refused_and_audited_as_a_rejected_attempt() {
    let mut system = upstream(1);
    system.system = true;
    let world = world(system);

    let error = world
        .handler
        .handle(command(1, port_and_protocol()))
        .await
        .unwrap_err();

    assert_system_entry(&world, &error);
}

#[tokio::test]
async fn an_upstream_of_the_iam_service_is_refused_and_audited() {
    let world = world(upstream_named(upstream_id(), "iam-control", "iam", 1));

    let error = world
        .handler
        .handle(command(1, port_and_protocol()))
        .await
        .unwrap_err();

    assert_system_entry(&world, &error);
}

#[tokio::test]
async fn moving_an_upstream_to_the_iam_service_is_refused_and_audited() {
    let world = world(upstream(1));
    let patch = UpstreamPatch {
        catalog_service: Some("iam".to_owned()),
        ..UpstreamPatch::default()
    };

    let error = world.handler.handle(command(1, patch)).await.unwrap_err();

    assert_system_entry(&world, &error);
}

#[tokio::test]
async fn a_storage_failure_of_the_repository_or_the_unit_of_work_is_the_error_of_the_command() {
    let reading = world_with(FakeUpstreamRepository::failing(), FakeIamUnitOfWork::new());
    let writing = world_with(
        FakeUpstreamRepository::holding(vec![upstream(1)]),
        FakeIamUnitOfWork::failing(),
    );

    let read_error = reading
        .handler
        .handle(command(1, port_and_protocol()))
        .await
        .unwrap_err();
    let write_error = writing
        .handler
        .handle(command(1, port_and_protocol()))
        .await
        .unwrap_err();

    assert!(matches!(read_error, IamError::Storage(_)));
    assert!(matches!(write_error, IamError::Storage(_)));
}

#[rstest::rstest]
#[case::kube_system("kube-system", None)]
#[case::kube_public("kube-public", None)]
#[case::own_namespace("iam", Some("iam"))]
#[case::seed_namespace_when_none_is_configured("iam", None)]
#[case::seed_namespace_when_another_is_configured("iam", Some("platform"))]
#[tokio::test]
async fn moving_to_a_reserved_namespace_is_a_violation_and_commits_nothing(
    #[case] namespace: &str,
    #[case] own: Option<&str>,
) {
    let mut world = world(upstream(1));
    world.handler = world.handler.with_own_namespace(own.map(str::to_owned));
    let patch = UpstreamPatch {
        namespace: Some(namespace.to_owned()),
        ..UpstreamPatch::default()
    };

    let error = world.handler.handle(command(1, patch)).await.unwrap_err();

    let IamError::Invalid(violations) = error else {
        panic!("a violation expected: {error:?}");
    };
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].property_path, "namespace");
    assert_eq!(violations[0].code, "reserved");
    assert_eq!(world.unit_of_work.committed(), Vec::new());
}

#[tokio::test]
async fn a_non_system_upstream_that_squats_the_seeded_name_is_refused_and_audited() {
    let world = world(upstream_named(upstream_id(), "iam-control", "core", 1));

    let error = world
        .handler
        .handle(command(1, port_and_protocol()))
        .await
        .unwrap_err();

    assert_system_entry(&world, &error);
}
