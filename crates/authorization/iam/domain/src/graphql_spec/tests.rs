use std::any::Any;
use std::time::{Duration, SystemTime};

use rstest::rstest;
use shared_domain::{AggregateRoot as _, DomainEvent, Uuid};

use super::event::{GraphQlSpecLoaded, GraphQlSpecRetired};
use super::{GraphQlSpec, GraphQlSpecContent, GraphQlSpecParts, SpecActivation, SpecStamp};
use crate::error::{InvalidEventEnvelope, SpecTransitionRefused};
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::content_hash::ContentHash;
use crate::value_object::gql_name::GqlName;
use crate::value_object::graphql_coordinate::GraphQlCoordinate;
use crate::value_object::graphql_type_graph::{GraphQlField, GraphQlTypeGraph};
use crate::value_object::identifier::SpecId;
use crate::value_object::permission_flags::PermissionFlags;
use crate::value_object::service_name::ServiceName;
use crate::value_object::spec_status::SpecStatus;

const SPEC: &str = "5b2e8c1d-3f4a-4b6c-8d9e-0a1b2c3d4e5f";
const USER: &str = "3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a";
const EVENT: &str = "01890a5d-ac96-774b-bcce-b302099a8057";

fn spec_id() -> SpecId {
    SpecId::parse(SPEC).unwrap()
}

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

fn actor() -> ActorRef {
    ActorRef::User(Uuid::parse(USER).unwrap())
}

fn stamp(seconds: u64) -> SpecStamp {
    SpecStamp {
        event_id: Uuid::parse(EVENT).unwrap(),
        actor: actor(),
        occurred_at: at(seconds),
    }
}

fn service() -> ServiceName {
    ServiceName::new("billing").unwrap()
}

fn hash() -> ContentHash {
    ContentHash::new(&[0x11; 32]).unwrap()
}

fn type_graph() -> GraphQlTypeGraph {
    let field = |text: &str, flags| {
        (
            GraphQlCoordinate::parse(text).unwrap(),
            GraphQlField {
                return_type: GqlName::parse("String").unwrap(),
                flags,
            },
        )
    };
    GraphQlTypeGraph::new(
        [
            field("Query.invoices", PermissionFlags::NONE),
            field("Mutation.pay", PermissionFlags::NONE.with_sensitive()),
        ],
        [],
    )
    .unwrap()
}

fn content() -> GraphQlSpecContent {
    GraphQlSpecContent {
        service: service(),
        content_hash: hash(),
        type_graph: type_graph(),
    }
}

fn stored(status: SpecStatus) -> GraphQlSpec {
    GraphQlSpec::restore(GraphQlSpecParts {
        id: spec_id(),
        content: content(),
        status,
        uploaded_by: actor(),
        created_at: at(10),
        activated_at: None,
        retired_at: None,
    })
}

/// Every event the version recorded, each name in order.
fn event_names(spec: &mut GraphQlSpec) -> Vec<&'static str> {
    spec.pull_domain_events()
        .iter()
        .map(|event| event.event_name())
        .collect()
}

/// The single event the version recorded, downcast to its type.
fn single_event<E: DomainEvent + Clone>(spec: &mut GraphQlSpec) -> E {
    let events = spec.pull_domain_events();
    assert_eq!(events.len(), 1);
    let event: &dyn Any = events[0].as_ref();
    event.downcast_ref::<E>().unwrap().clone()
}

#[test]
fn the_sdl_limit_is_five_mebibytes() {
    assert_eq!(GraphQlSpec::MAX_SDL_BYTES, 5_242_880);
}

#[test]
fn loading_builds_a_draft_and_records_the_loaded_event() {
    let mut spec = GraphQlSpec::load(spec_id(), content(), stamp(10));

    assert_eq!(
        spec.parts(),
        &GraphQlSpecParts {
            id: spec_id(),
            content: content(),
            status: SpecStatus::Draft,
            uploaded_by: actor(),
            created_at: at(10),
            activated_at: None,
            retired_at: None,
        }
    );
    assert_eq!(spec.coordinates(), type_graph().coordinates());
    assert_eq!(
        single_event::<GraphQlSpecLoaded>(&mut spec),
        GraphQlSpecLoaded {
            event_id: Uuid::parse(EVENT).unwrap(),
            spec_id: spec_id(),
            service: service(),
            content_hash: hash(),
            coordinate_count: 2,
            actor: actor(),
            occurred_at: at(10),
        }
    );
}

#[test]
fn restoring_records_nothing() {
    let mut spec = stored(SpecStatus::Active);

    assert_eq!(event_names(&mut spec), Vec::<&str>::new());
}

#[test]
fn a_draft_is_activated_then_retired_and_only_the_retirement_is_an_event() {
    let mut spec = stored(SpecStatus::Draft);

    assert_eq!(spec.activate(at(20)), Ok(SpecActivation::Activated));
    assert_eq!(spec.parts().status, SpecStatus::Active);
    assert_eq!(spec.parts().activated_at, Some(at(20)));
    assert_eq!(event_names(&mut spec), Vec::<&str>::new());

    spec.retire(stamp(30)).unwrap();

    assert_eq!(spec.parts().status, SpecStatus::Retired);
    assert_eq!(spec.parts().retired_at, Some(at(30)));
    assert_eq!(spec.parts().activated_at, Some(at(20)));
    let retired = single_event::<GraphQlSpecRetired>(&mut spec);
    assert_eq!(GraphQlSpecRetired::NAME, "iam.graphql_spec.retired");
    assert_eq!(
        retired,
        GraphQlSpecRetired {
            event_id: Uuid::parse(EVENT).unwrap(),
            spec_id: spec_id(),
            service: service(),
            actor: actor(),
            occurred_at: at(30),
        }
    );
}

#[test]
fn activating_an_active_version_changes_nothing() {
    let mut spec = stored(SpecStatus::Active);
    let before = spec.parts().clone();

    assert_eq!(spec.activate(at(20)), Ok(SpecActivation::AlreadyActive));
    assert_eq!(spec.parts(), &before);
    assert_eq!(event_names(&mut spec), Vec::<&str>::new());
}

#[test]
fn activating_a_retired_version_is_refused() {
    let mut spec = stored(SpecStatus::Retired);
    let before = spec.parts().clone();

    assert_eq!(
        spec.activate(at(20)),
        Err(SpecTransitionRefused {
            from: SpecStatus::Retired,
            to: SpecStatus::Active,
        })
    );
    assert_eq!(spec.parts(), &before);
    assert_eq!(event_names(&mut spec), Vec::<&str>::new());
}

#[rstest]
#[case::draft(SpecStatus::Draft)]
#[case::retired(SpecStatus::Retired)]
fn retiring_a_version_that_is_not_active_is_refused(#[case] status: SpecStatus) {
    let mut spec = stored(status);
    let before = spec.parts().clone();

    assert_eq!(
        spec.retire(stamp(30)),
        Err(SpecTransitionRefused {
            from: status,
            to: SpecStatus::Retired,
        })
    );
    assert_eq!(spec.parts(), &before);
    assert_eq!(event_names(&mut spec), Vec::<&str>::new());
}

#[test]
fn pulling_envelopes_names_the_loaded_event_and_drains_it() {
    let mut spec = GraphQlSpec::load(spec_id(), content(), stamp(10));

    let envelopes = spec.pull_envelopes().unwrap();

    assert_eq!(envelopes.len(), 1);
    let parts = envelopes[0].parts();
    assert_eq!(parts.event_type.as_str(), "iam.graphql_spec.loaded");
    assert_eq!(parts.aggregate_id, spec_id().as_uuid());
    assert_eq!(parts.entity_version, None);
    assert_eq!(spec.pull_envelopes().unwrap().len(), 0);
}

#[test]
fn pulling_envelopes_names_the_retired_event() {
    let mut spec = stored(SpecStatus::Active);
    spec.retire(stamp(30)).unwrap();

    let envelopes = spec.pull_envelopes().unwrap();

    assert_eq!(envelopes.len(), 1);
    assert_eq!(
        envelopes[0].parts().event_type.as_str(),
        "iam.graphql_spec.retired"
    );
}

/// An event that is not one of the two events of a version.
#[derive(Debug)]
struct Foreign;

impl DomainEvent for Foreign {
    fn event_id(&self) -> Uuid {
        Uuid::parse(EVENT).unwrap()
    }

    fn aggregate_id(&self) -> Uuid {
        Uuid::parse(SPEC).unwrap()
    }

    fn occurred_at(&self) -> SystemTime {
        at(1)
    }

    fn event_name(&self) -> &'static str {
        "iam.foreign.happened"
    }
}

#[test]
fn an_event_that_a_version_does_not_record_is_refused() {
    let mut spec = stored(SpecStatus::Draft);
    spec.recorded_events().record(Foreign);

    let refused = spec.pull_envelopes();

    assert_eq!(refused, Err(InvalidEventEnvelope::EventType));
}
