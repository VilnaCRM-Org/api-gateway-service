use std::time::SystemTime;

use shared_domain::Uuid;

use super::GraphQlSpecStatement;
use crate::graphql_spec::{GraphQlSpec, GraphQlSpecContent, SpecStamp};
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::content_hash::ContentHash;
use crate::value_object::graphql_type_graph::GraphQlTypeGraph;
use crate::value_object::identifier::SpecId;
use crate::value_object::service_name::ServiceName;

fn spec() -> GraphQlSpec {
    GraphQlSpec::load(
        SpecId::parse("5b2e8c1d-3f4a-4b6c-8d9e-0a1b2c3d4e5f").unwrap(),
        GraphQlSpecContent {
            service: ServiceName::new("billing").unwrap(),
            content_hash: ContentHash::new(&[0x11; 32]).unwrap(),
            type_graph: GraphQlTypeGraph::default(),
        },
        SpecStamp {
            event_id: Uuid::parse("01890a5d-ac96-774b-bcce-b302099a8057").unwrap(),
            actor: ActorRef::User(Uuid::parse("3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a").unwrap()),
            occurred_at: SystemTime::UNIX_EPOCH,
        },
    )
}

#[test]
fn an_insert_carries_the_state_of_the_version_and_its_sdl() {
    let spec = spec();

    let statement = GraphQlSpecStatement::insert(&spec, "type Query { a: Int }".to_owned());

    assert_eq!(statement.spec(), spec.parts());
    assert_eq!(statement.sdl(), "type Query { a: Int }");
}
