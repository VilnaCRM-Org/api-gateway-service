use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iam_domain::{
    ActorRef, AuditOutcome, ChangeId, ChangeStatement, DecisionEffect, EntityVersion,
    IamUnitOfWork, ServiceName, SpecId, SpecStatus, SystemComponent,
};
use shared_domain::{Command as _, CommandHandler as _, Uuid};
use test_support::clock::FixedClock;
use test_support::graphql_spec::SDL_FIXTURE;
use test_support::id::SequenceUuidGenerator;
use test_support::request_digester::FakeRequestDigester;
use test_support::unit_of_work::FakeIamUnitOfWork;

use super::{LoadGraphQlSpecCommand, LoadGraphQlSpecCommandHandler, loadable_service};
use crate::error::IamError;
use crate::graphql::AsyncGraphQlSchemaParser;

const USER: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";
const CHANGE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ac";
const SPEC: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ad";

fn at() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_hours(500_000))
        .unwrap()
}

fn user() -> ActorRef {
    ActorRef::User(Uuid::parse(USER).unwrap())
}

fn command(service: &str, sdl: &str, actor: ActorRef) -> LoadGraphQlSpecCommand {
    LoadGraphQlSpecCommand {
        change_id: ChangeId::parse(CHANGE).unwrap(),
        spec_id: SpecId::parse(SPEC).unwrap(),
        actor,
        service: service.to_owned(),
        sdl: sdl.to_owned(),
    }
}

fn handler(unit_of_work: &Arc<FakeIamUnitOfWork>) -> LoadGraphQlSpecCommandHandler {
    let unit_of_work: Arc<dyn IamUnitOfWork> = Arc::<FakeIamUnitOfWork>::clone(unit_of_work);
    LoadGraphQlSpecCommandHandler::new(
        unit_of_work,
        Arc::new(AsyncGraphQlSchemaParser),
        Arc::new(FakeRequestDigester),
        Arc::new(FixedClock::at(at())),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    )
}

#[test]
fn the_command_is_named_after_its_type() {
    assert_eq!(LoadGraphQlSpecCommand::NAME, "LoadGraphQlSpecCommand");
}

#[tokio::test]
async fn a_valid_sdl_is_committed_as_one_draft_insert_with_its_event_and_audit_record() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    handler(&unit_of_work)
        .handle(command("billing", SDL_FIXTURE, user()))
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    assert_eq!(committed.len(), 1);
    let parts = committed[0].parts();
    assert_eq!(parts.change_id, ChangeId::parse(CHANGE).unwrap());
    assert_eq!(parts.effect, DecisionEffect::Unaffected);
    assert_eq!(parts.entity_version, EntityVersion::INITIAL);
    assert_eq!(parts.idempotency, None);
    let [ChangeStatement::SaveGraphQlSpec(statement)] = parts.statements.as_slice() else {
        panic!("one specification insert expected: {:?}", parts.statements);
    };
    assert_eq!(statement.sdl(), SDL_FIXTURE);
    let spec = statement.spec();
    assert_eq!(spec.id, SpecId::parse(SPEC).unwrap());
    assert_eq!(spec.status, SpecStatus::Draft);
    assert_eq!(spec.content.service, ServiceName::new("billing").unwrap());
    assert_eq!(spec.uploaded_by, user());
    assert_eq!(spec.created_at, at());
    let types: Vec<&str> = parts
        .events
        .iter()
        .map(|event| event.parts().event_type.as_str())
        .collect();
    assert_eq!(types, ["iam.graphql_spec.loaded"]);
}

#[tokio::test]
async fn the_audit_record_names_the_actor_the_version_and_the_time_of_the_change() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    handler(&unit_of_work)
        .handle(command("billing", SDL_FIXTURE, user()))
        .await
        .unwrap();

    let committed = unit_of_work.committed();
    let audit = committed[0].parts().audit.parts();
    assert_eq!(audit.action.as_str(), "graphql_spec.load");
    assert_eq!(audit.outcome, AuditOutcome::Committed);
    assert_eq!(audit.actor, user());
    assert_eq!(audit.target.target_type(), "graphql_spec");
    assert_eq!(audit.target.target_id(), SPEC);
    assert_eq!(audit.occurred_at, at());
    let after = audit.after.as_ref().unwrap().as_str();
    assert!(after.starts_with("service=billing hash="));
    let [ChangeStatement::SaveGraphQlSpec(statement)] = committed[0].parts().statements.as_slice()
    else {
        panic!("one specification insert expected");
    };
    let count = statement.spec().content.type_graph.field_count();
    assert!(after.ends_with(&format!(" status=draft coordinates={count}")));
    assert_eq!(audit.before, None);
    assert_eq!(audit.policy_version, None);
    let event_id = committed[0].parts().events[0].parts().id;
    assert_ne!(event_id, audit.id.as_uuid());
}

#[tokio::test]
async fn an_sdl_that_does_not_parse_is_a_violation_of_the_sdl_and_commits_nothing() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    let error = handler(&unit_of_work)
        .handle(command("billing", "type Query {", user()))
        .await
        .unwrap_err();

    let IamError::Invalid(violations) = error else {
        panic!("a validation error expected");
    };
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0].property_path, "sdl");
    assert_eq!(violations[0].code, "syntax");
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn an_invalid_service_name_is_a_violation_of_the_service_and_commits_nothing() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    let error = handler(&unit_of_work)
        .handle(command("Not A Service", SDL_FIXTURE, user()))
        .await
        .unwrap_err();

    let IamError::Invalid(violations) = error else {
        panic!("a validation error expected");
    };
    assert_eq!(violations[0].property_path, "service");
    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn the_reserved_service_is_refused_to_every_actor_but_the_startup_registration() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let service = ActorRef::Service(ServiceName::new("billing").unwrap());

    for actor in [
        user(),
        service,
        ActorRef::System(SystemComponent::Bootstrap),
    ] {
        let error = handler(&unit_of_work)
            .handle(command("iam", SDL_FIXTURE, actor))
            .await
            .unwrap_err();
        assert!(matches!(error, IamError::Forbidden));
    }

    assert_eq!(unit_of_work.committed().len(), 0);
}

#[tokio::test]
async fn the_startup_registration_may_load_the_reserved_service() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());
    let startup = ActorRef::System(SystemComponent::Startup);

    handler(&unit_of_work)
        .handle(command("iam", SDL_FIXTURE, startup))
        .await
        .unwrap();

    assert_eq!(unit_of_work.committed().len(), 1);
}

#[tokio::test]
async fn a_storage_failure_is_a_storage_error() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::failing());

    let error = handler(&unit_of_work)
        .handle(command("billing", SDL_FIXTURE, user()))
        .await
        .unwrap_err();

    assert!(matches!(error, IamError::Storage(_)));
}

#[test]
fn a_loadable_service_is_the_validated_name() {
    let service = loadable_service("billing", &user()).unwrap();

    assert_eq!(service.as_str(), "billing");
}

#[tokio::test]
async fn a_load_asks_for_the_specification_scope_check_of_its_service() {
    let unit_of_work = Arc::new(FakeIamUnitOfWork::new());

    handler(&unit_of_work)
        .handle(command("billing", SDL_FIXTURE, user()))
        .await
        .unwrap();

    assert_eq!(
        unit_of_work.committed()[0].guard(),
        Some(&iam_domain::GuardCheck::Spec {
            service: ServiceName::new("billing").unwrap(),
            flag_downgrade: false,
        })
    );
}
