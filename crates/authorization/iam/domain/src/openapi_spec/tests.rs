use std::any::Any;
use std::time::{Duration, SystemTime};

use rstest::rstest;
use shared_domain::{AggregateRoot as _, DomainEvent, Uuid};

use super::event::{OpenApiSpecLoaded, OpenApiSpecRetired};
use super::{OpenApiSpec, OpenApiSpecContent, OpenApiSpecParts};
use crate::error::SpecTransitionRefused;
use crate::graphql_spec::{SpecActivation, SpecStamp};
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::content_hash::ContentHash;
use crate::value_object::http_method::HttpMethod;
use crate::value_object::identifier::SpecId;
use crate::value_object::path_template::PathTemplate;
use crate::value_object::permission_flags::PermissionFlags;
use crate::value_object::rest_operation_set::{RestOperation, RestOperationSet};
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

fn operations() -> RestOperationSet {
    let mut set = RestOperationSet::new();
    set.insert(RestOperation {
        method: HttpMethod::Get,
        template: PathTemplate::from_openapi_path("/invoices").unwrap(),
        label: Some("listInvoices".to_owned()),
        flags: PermissionFlags::NONE,
    })
    .unwrap();
    set.insert(RestOperation {
        method: HttpMethod::Post,
        template: PathTemplate::from_openapi_path("/invoices/{id}/pay").unwrap(),
        label: None,
        flags: PermissionFlags::NONE.with_sensitive(),
    })
    .unwrap();
    set
}

fn content() -> OpenApiSpecContent {
    OpenApiSpecContent {
        service: service(),
        content_hash: hash(),
        operations: operations(),
    }
}

fn stored(status: SpecStatus) -> OpenApiSpec {
    OpenApiSpec::restore(OpenApiSpecParts {
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
fn event_names(spec: &mut OpenApiSpec) -> Vec<&'static str> {
    spec.pull_domain_events()
        .iter()
        .map(|event| event.event_name())
        .collect()
}

/// The single event the version recorded, downcast to its type.
fn single_event<E: DomainEvent + Clone>(spec: &mut OpenApiSpec) -> E {
    let events = spec.pull_domain_events();
    assert_eq!(events.len(), 1);
    let event: &dyn Any = events[0].as_ref();
    event.downcast_ref::<E>().unwrap().clone()
}

#[test]
fn the_document_limit_is_five_mebibytes() {
    assert_eq!(OpenApiSpec::MAX_DOCUMENT_BYTES, 5_242_880);
}

#[test]
fn loading_builds_a_draft_and_records_the_loaded_event() {
    let mut spec = OpenApiSpec::load(spec_id(), content(), stamp(10));

    assert_eq!(
        spec.parts(),
        &OpenApiSpecParts {
            id: spec_id(),
            content: content(),
            status: SpecStatus::Draft,
            uploaded_by: actor(),
            created_at: at(10),
            activated_at: None,
            retired_at: None,
        }
    );
    assert_eq!(spec.operations(), &operations());
    assert_eq!(
        single_event::<OpenApiSpecLoaded>(&mut spec),
        OpenApiSpecLoaded {
            event_id: Uuid::parse(EVENT).unwrap(),
            spec_id: spec_id(),
            service: service(),
            content_hash: hash(),
            operation_count: 2,
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
    assert_eq!(
        single_event::<OpenApiSpecRetired>(&mut spec),
        OpenApiSpecRetired {
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
