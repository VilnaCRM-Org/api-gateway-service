use std::sync::Arc;

use iam_domain::{
    AuditOutcome, AuditSummary, ChangeStatement, DecisionEffect, EntityVersion, GatewayStatement,
    GuardCheck, IamUnitOfWork, IdempotencyKey, IdempotencyRequest, RejectedAttemptLog,
    RequestDigest, ServiceName,
};
use shared_domain::{Command as _, CommandHandler as _};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::unit_of_work::FakeIamUnitOfWork;

use super::{CreateUpstreamCommand, CreateUpstreamCommandHandler};
use crate::error::IamError;
use crate::rejected_attempt_fixtures::FakeRejectedAttemptLog;
use crate::upstream_fixtures::{actor, at, change_id, draft, upstream_id};

struct World {
    unit_of_work: Arc<FakeIamUnitOfWork>,
    attempts: Arc<FakeRejectedAttemptLog>,
    handler: CreateUpstreamCommandHandler,
}

fn world(unit_of_work: FakeIamUnitOfWork) -> World {
    let unit_of_work = Arc::new(unit_of_work);
    let attempts = Arc::new(FakeRejectedAttemptLog::new());
    let committing: Arc<dyn IamUnitOfWork> = Arc::<FakeIamUnitOfWork>::clone(&unit_of_work);
    let log: Arc<dyn RejectedAttemptLog> = Arc::<FakeRejectedAttemptLog>::clone(&attempts);
    let handler = CreateUpstreamCommandHandler::new(
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

fn command(name: &str, catalog_service: &str) -> CreateUpstreamCommand {
    CreateUpstreamCommand {
        change_id: change_id(),
        upstream_id: upstream_id(),
        actor: actor(),
        name: name.to_owned(),
        settings: draft(catalog_service),
        idempotency: None,
    }
}

#[test]
fn the_command_is_named_after_its_type() {
    assert_eq!(CreateUpstreamCommand::NAME, "CreateUpstreamCommand");
}

#[tokio::test]
async fn a_valid_upstream_is_committed_as_one_insert_with_its_event_and_audit_record() {
    let world = world(FakeIamUnitOfWork::new());

    world.handler.handle(command("core", "core")).await.unwrap();

    let committed = world.unit_of_work.committed();
    let [change] = committed.as_slice() else {
        panic!("one change expected: {committed:?}");
    };
    let parts = change.parts();
    assert_eq!(parts.change_id, change_id());
    assert_eq!(parts.effect, DecisionEffect::Affected);
    assert_eq!(parts.entity_version, EntityVersion::INITIAL);
    let [ChangeStatement::SaveGateway(statement)] = parts.statements.as_slice() else {
        panic!("one gateway statement expected: {:?}", parts.statements);
    };
    let GatewayStatement::Upstream(statement) = statement.as_ref() else {
        panic!("an upstream statement expected: {statement:?}");
    };
    assert_eq!(statement.expected(), None);
    assert_eq!(statement.upstream().id, upstream_id());
    assert_eq!(statement.upstream().name.as_str(), "core");
    assert_eq!(statement.upstream().settings.port(), 8080);
    assert!(!statement.upstream().system);
    assert_eq!(statement.upstream().created_at, at());
    let types: Vec<&str> = parts
        .events
        .iter()
        .map(|event| event.parts().event_type.as_str())
        .collect();
    assert_eq!(types, ["iam.upstream.created"]);
    assert_eq!(parts.events[0].parts().actor, actor());
    assert_eq!(parts.events[0].parts().occurred_at, at());
    assert_eq!(world.attempts.offered(), Vec::new());
}

#[tokio::test]
async fn the_change_asks_for_the_route_scope_check_of_the_catalogue_service() {
    let world = world(FakeIamUnitOfWork::new());

    world
        .handler
        .handle(command("payment-api", "payment"))
        .await
        .unwrap();

    let committed = world.unit_of_work.committed();
    assert_eq!(
        committed[0].guard(),
        Some(&GuardCheck::RouteScope {
            services: vec![ServiceName::new("payment").unwrap()]
        })
    );
}

#[tokio::test]
async fn the_audit_record_names_the_actor_the_upstream_and_the_time_of_the_change() {
    let world = world(FakeIamUnitOfWork::new());

    world.handler.handle(command("core", "core")).await.unwrap();

    let committed = world.unit_of_work.committed();
    let audit = committed[0].parts().audit.parts();
    assert_eq!(audit.action.as_str(), "upstream.create");
    assert_eq!(audit.outcome, AuditOutcome::Committed);
    assert_eq!(audit.actor, actor());
    assert_eq!(audit.target.target_type(), "upstream");
    assert_eq!(audit.target.target_id(), upstream_id().to_string());
    assert_eq!(audit.occurred_at, at());
    assert_eq!(audit.before, None);
    assert_eq!(
        audit.after.as_ref().map(AuditSummary::as_str),
        Some("catalogService=core version=1")
    );
    assert_eq!(audit.idempotency_key, None);
    assert_eq!(committed[0].parts().idempotency, None);
}

#[tokio::test]
async fn the_event_and_the_audit_record_take_distinct_identifiers_from_the_generator() {
    let world = world(FakeIamUnitOfWork::new());

    world.handler.handle(command("core", "core")).await.unwrap();

    let committed = world.unit_of_work.committed();
    let event_id = committed[0].parts().events[0].parts().id;
    let audit_id = committed[0].parts().audit.parts().id.as_uuid();
    assert_ne!(event_id, audit_id);
}

#[tokio::test]
async fn an_idempotency_key_is_kept_on_the_change_and_the_audit_record() {
    let world = world(FakeIamUnitOfWork::new());
    let request = IdempotencyRequest {
        key: IdempotencyKey::new("create-core").unwrap(),
        request_digest: RequestDigest::new(&[7_u8; 32]).unwrap(),
    };
    let mut with_key = command("core", "core");
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
async fn invalid_fields_are_reported_together_and_commit_nothing() {
    let world = world(FakeIamUnitOfWork::new());
    let mut invalid = command("Core Upstream", "core");
    invalid.settings.port = 70_000;

    let error = world.handler.handle(invalid).await.unwrap_err();

    let IamError::Invalid(violations) = error else {
        panic!("violations expected: {error:?}");
    };
    let paths: Vec<&str> = violations
        .iter()
        .map(|violation| violation.property_path.as_str())
        .collect();
    assert_eq!(paths, ["name", "port"]);
    assert_eq!(world.unit_of_work.committed(), Vec::new());
}

#[tokio::test]
async fn an_upstream_of_the_iam_service_is_refused_and_audited_as_a_rejected_attempt() {
    let world = world(FakeIamUnitOfWork::new());

    let error = world
        .handler
        .handle(command("iam-control", "iam"))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::SystemEntry));
    assert_eq!(world.unit_of_work.committed(), Vec::new());
    let offered = world.attempts.offered();
    let [attempt] = offered.as_slice() else {
        panic!("one attempt expected: {offered:?}");
    };
    assert_eq!(attempt.action.as_str(), "upstream.create");
    assert_eq!(attempt.reason.as_str(), "system_entry");
    assert_eq!(attempt.target.target_id(), upstream_id().to_string());
    assert_eq!(attempt.actor, actor());
    assert_eq!(attempt.occurred_at, at());
}

#[tokio::test]
async fn a_refusal_of_the_unit_of_work_is_the_error_of_the_command() {
    let world = world(FakeIamUnitOfWork::failing());

    let error = world
        .handler
        .handle(command("core", "core"))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}

#[rstest::rstest]
#[case::kube_system("kube-system", None)]
#[case::kube_public("kube-public", None)]
#[case::own_namespace("iam", Some("iam"))]
#[case::seed_namespace_when_none_is_configured("iam", None)]
#[case::seed_namespace_when_another_is_configured("iam", Some("platform"))]
#[tokio::test]
async fn a_reserved_namespace_is_a_violation_and_commits_nothing(
    #[case] namespace: &str,
    #[case] own: Option<&str>,
) {
    let mut world = world(FakeIamUnitOfWork::new());
    world.handler = world.handler.with_own_namespace(own.map(str::to_owned));
    let mut command = command("core", "core");
    command.settings.namespace = namespace.to_owned();

    let error = world.handler.handle(command).await.unwrap_err();

    let IamError::Invalid(violations) = error else {
        panic!("a violation expected: {error:?}");
    };
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].property_path, "namespace");
    assert_eq!(violations[0].code, "reserved");
    assert_eq!(world.unit_of_work.committed(), Vec::new());
}

#[tokio::test]
async fn the_seeded_upstream_name_is_reserved_for_every_catalogue_service() {
    let world = world(FakeIamUnitOfWork::new());

    let error = world
        .handler
        .handle(command("iam-control", "core"))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::SystemEntry));
    assert_eq!(world.unit_of_work.committed(), Vec::new());
    let offered = world.attempts.offered();
    let [attempt] = offered.as_slice() else {
        panic!("one attempt expected: {offered:?}");
    };
    assert_eq!(attempt.action.as_str(), "upstream.create");
    assert_eq!(attempt.reason.as_str(), "system_entry");
}
