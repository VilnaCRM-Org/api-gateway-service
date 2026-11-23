use rstest::rstest;
use shared_domain::Uuid;

use super::{ActorRef, SystemComponent};
use crate::error::InvalidIamValue;
use crate::value_object::service_name::ServiceName;

const USER: &str = "0190f2a8-7b3c-7d4e-8f00-123456789abc";

#[test]
fn a_user_actor_renders_as_user_and_its_uuid() {
    let actor = ActorRef::User(Uuid::parse(USER).unwrap());

    assert_eq!(actor.to_string(), format!("user:{USER}"));
    assert_eq!(ActorRef::parse(&actor.to_string()), Ok(actor));
}

#[test]
fn a_service_actor_renders_as_service_and_its_name() {
    let actor = ActorRef::Service(ServiceName::new("core").unwrap());

    assert_eq!(actor.to_string(), "service:core");
    assert_eq!(ActorRef::parse("service:core"), Ok(actor));
}

#[rstest]
#[case(SystemComponent::Bootstrap, "system:bootstrap")]
#[case(SystemComponent::UserService, "system:user-service")]
#[case(SystemComponent::Startup, "system:startup")]
#[case(SystemComponent::Maintenance, "system:maintenance")]
fn a_system_actor_renders_as_system_and_its_component(
    #[case] component: SystemComponent,
    #[case] text: &str,
) {
    let actor = ActorRef::System(component);

    assert_eq!(actor.to_string(), text);
    assert_eq!(ActorRef::parse(text), Ok(actor));
}

#[rstest]
#[case("bootstrap", SystemComponent::Bootstrap)]
#[case("user-service", SystemComponent::UserService)]
#[case("startup", SystemComponent::Startup)]
#[case("maintenance", SystemComponent::Maintenance)]
fn a_component_round_trips_through_its_name(
    #[case] name: &str,
    #[case] component: SystemComponent,
) {
    assert_eq!(SystemComponent::parse(name), Some(component));
    assert_eq!(component.as_str(), name);
}

#[rstest]
#[case("")]
#[case("user")]
#[case("user:")]
#[case("user:core")]
#[case("service:Core")]
#[case("service:")]
#[case("system:cron")]
#[case("system:")]
#[case("admin:core")]
#[case(USER)]
fn rejects_any_other_text(#[case] text: &str) {
    assert_eq!(ActorRef::parse(text), Err(InvalidIamValue::ActorFormat));
}
