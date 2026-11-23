use std::sync::{Arc, Mutex, PoisonError};

use iam_domain::{ActorRef, ServiceName, SpecId, SystemComponent};
use shared_domain::{CommandHandler as _, UuidGenerator as _};
use test_support::bus::{FakeCommandBus, FakeQueryBus};
use test_support::id::SequenceUuidGenerator;
use test_support::request_digester::FakeRequestDigester;

use super::{RegisterOwnSpecsCommand, RegisterOwnSpecsCommandHandler};
use crate::command::create_graphql_permissions::CreateGraphQlPermissionsCommand;
use crate::command::create_rest_permissions::CreateRestPermissionsCommand;
use crate::command::load_graphql_spec::{LoadGraphQlSpecCommand, content_hash_of};
use crate::command::load_openapi_spec::LoadOpenApiSpecCommand;
use crate::error::IamError;
use crate::query::find_graphql_spec::FindGraphQlSpecQuery;
use crate::query::find_openapi_spec::FindOpenApiSpecQuery;

const DOCUMENT: &str = r#"{"openapi":"3.1.0"}"#;
const SDL: &str = "type Query { ping: String }";
const KNOWN: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ab";

/// What a double saw, in the order it saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Step {
    FindRest,
    LoadRest { spec_id: SpecId, document: String },
    ActivateRest(SpecId),
    FindGraphQl,
    LoadGraphQl { spec_id: SpecId, sdl: String },
    ActivateGraphQl(SpecId),
}

type Journal = Arc<Mutex<Vec<Step>>>;

fn steps(journal: &Journal) -> Vec<Step> {
    journal
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

fn note(journal: &Journal, step: Step) {
    journal
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(step);
}

fn known() -> SpecId {
    SpecId::parse(KNOWN).unwrap()
}

fn startup() -> ActorRef {
    ActorRef::System(SystemComponent::Startup)
}

fn command() -> RegisterOwnSpecsCommand {
    RegisterOwnSpecsCommand {
        openapi_document: DOCUMENT.to_owned(),
        graphql_sdl: SDL.to_owned(),
    }
}

/// What the doubles answer.
#[derive(Clone, Copy)]
struct Answers {
    rest: Option<SpecId>,
    graphql: Option<SpecId>,
    failing: Option<fn() -> IamError>,
}

impl Answers {
    const fn fresh() -> Self {
        Self {
            rest: None,
            graphql: None,
            failing: None,
        }
    }
}

fn handler(answers: Answers) -> (RegisterOwnSpecsCommandHandler, Journal) {
    let journal: Journal = Arc::default();
    let (load_rest, activate_rest) = (Arc::clone(&journal), Arc::clone(&journal));
    let (load_graphql, activate_graphql) = (Arc::clone(&journal), Arc::clone(&journal));
    let (find_rest, find_graphql) = (Arc::clone(&journal), Arc::clone(&journal));
    let fail = answers.failing;
    let commands = FakeCommandBus::handling(move |load: LoadOpenApiSpecCommand| {
        assert_eq!(load.actor, startup());
        assert_eq!(load.service, "iam");
        note(
            &load_rest,
            Step::LoadRest {
                spec_id: load.spec_id,
                document: load.document,
            },
        );
        fail.map_or(Ok(()), |error| Err(error()))
    })
    .and_handling(move |activate: CreateRestPermissionsCommand| {
        assert_eq!(activate.actor, startup());
        assert_eq!(activate.renames, Vec::new());
        assert!(!activate.confirm_orphans);
        note(&activate_rest, Step::ActivateRest(activate.spec_id));
        Ok(())
    })
    .and_handling(move |load: LoadGraphQlSpecCommand| {
        assert_eq!(load.actor, startup());
        assert_eq!(load.service, "iam");
        note(
            &load_graphql,
            Step::LoadGraphQl {
                spec_id: load.spec_id,
                sdl: load.sdl,
            },
        );
        Ok(())
    })
    .and_handling(move |activate: CreateGraphQlPermissionsCommand| {
        assert_eq!(activate.actor, startup());
        assert!(!activate.confirm_orphans);
        note(&activate_graphql, Step::ActivateGraphQl(activate.spec_id));
        Ok(())
    });
    let queries = FakeQueryBus::answering(move |query: FindOpenApiSpecQuery| {
        assert_eq!(query.service, *ServiceName::iam());
        assert_eq!(
            query.content_hash,
            content_hash_of(&FakeRequestDigester, DOCUMENT)
        );
        note(&find_rest, Step::FindRest);
        Ok(answers.rest)
    })
    .and_answering(move |query: FindGraphQlSpecQuery| {
        assert_eq!(query.service, *ServiceName::iam());
        assert_eq!(
            query.content_hash,
            content_hash_of(&FakeRequestDigester, SDL)
        );
        note(&find_graphql, Step::FindGraphQl);
        Ok(answers.graphql)
    });
    let handler = RegisterOwnSpecsCommandHandler::new(
        Arc::new(commands),
        Arc::new(queries),
        Arc::new(FakeRequestDigester),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    );
    (handler, journal)
}

/// The identifier that the generator of the scenarios gives to its `counter`-th request.
fn spec(counter: u64) -> SpecId {
    SpecId::from_uuid(SequenceUuidGenerator::starting_at(counter).generate())
}

#[tokio::test]
async fn a_fresh_catalogue_loads_and_activates_both_documents() {
    let (handler, journal) = handler(Answers::fresh());

    handler.handle(command()).await.unwrap();

    assert_eq!(
        steps(&journal),
        [
            Step::FindRest,
            Step::LoadRest {
                spec_id: spec(1),
                document: DOCUMENT.to_owned()
            },
            Step::ActivateRest(spec(1)),
            Step::FindGraphQl,
            Step::LoadGraphQl {
                spec_id: spec(4),
                sdl: SDL.to_owned()
            },
            Step::ActivateGraphQl(spec(4)),
        ]
    );
}

#[tokio::test]
async fn documents_the_catalogue_holds_are_activated_without_a_load() {
    let answers = Answers {
        rest: Some(known()),
        graphql: Some(known()),
        failing: None,
    };
    let (handler, journal) = handler(answers);

    handler.handle(command()).await.unwrap();

    assert_eq!(
        steps(&journal),
        [
            Step::FindRest,
            Step::ActivateRest(known()),
            Step::FindGraphQl,
            Step::ActivateGraphQl(known()),
        ]
    );
}

#[tokio::test]
async fn a_known_rest_document_and_a_new_sdl_load_only_the_sdl() {
    let answers = Answers {
        rest: Some(known()),
        ..Answers::fresh()
    };
    let (handler, journal) = handler(answers);

    handler.handle(command()).await.unwrap();

    let steps = steps(&journal);
    assert!(
        steps
            .iter()
            .all(|step| !matches!(step, Step::LoadRest { .. }))
    );
    assert!(
        steps
            .iter()
            .any(|step| matches!(step, Step::LoadGraphQl { .. }))
    );
}

#[tokio::test]
async fn a_refused_load_stops_the_registration_with_its_error() {
    let answers = Answers {
        failing: Some(|| IamError::Conflict),
        ..Answers::fresh()
    };
    let (handler, journal) = handler(answers);

    let error = handler.handle(command()).await.unwrap_err();

    assert!(matches!(error, IamError::Conflict));
    assert_eq!(steps(&journal).len(), 2);
}

#[tokio::test]
async fn a_missing_handler_is_an_internal_error() {
    let handler = RegisterOwnSpecsCommandHandler::new(
        Arc::new(FakeCommandBus::unregistered()),
        Arc::new(FakeQueryBus::unregistered()),
        Arc::new(FakeRequestDigester),
        Arc::new(SequenceUuidGenerator::starting_at(1)),
    );

    let error = handler.handle(command()).await.unwrap_err();

    assert!(matches!(error, IamError::Internal(_)));
}
