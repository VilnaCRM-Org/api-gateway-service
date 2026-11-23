//! Builders of routes for the unit tests of the route aggregate and of the guards.

use std::time::{Duration, SystemTime};

use shared_domain::Uuid;

use super::fields::{RouteDraft, RouteFields};
use super::settings::{EnforcementMode, RetryPolicy, RouteFlags};
use super::{RouteParts, RouteStamp};
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::entity_version::EntityVersion;
use crate::value_object::http_method::HttpMethod;
use crate::value_object::identifier::{RouteId, UpstreamId};

pub(crate) const EVENT: &str = "01890a5d-ac96-774b-bcce-b302099a8057";
pub(crate) const USER: &str = "3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a";

/// The time `seconds` after 1970.
pub(crate) fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds))
        .unwrap()
}

/// The route identifier with the number `number`.
pub(crate) fn route_id(number: u32) -> RouteId {
    RouteId::parse(&format!("00000000-0000-7000-8000-{number:012x}")).unwrap()
}

/// The identifier of the upstream every fixture route forwards to.
pub(crate) fn upstream_id() -> UpstreamId {
    UpstreamId::parse("5b2e9c1a-7d3f-4a6b-8c0d-1e2f3a4b5c6d").unwrap()
}

/// A valid draft on `host` for `path` and `methods`, protected, enforced, of service `core`.
pub(crate) fn draft(host: &str, path: &str, methods: &[HttpMethod]) -> RouteDraft {
    RouteDraft {
        host: host.to_owned(),
        methods: methods.to_vec(),
        path_pattern: path.to_owned(),
        service: "core".to_owned(),
        upstream_id: upstream_id(),
        flags: RouteFlags::default(),
        enforcement: EnforcementMode::Enforce,
        body_limit: 1_048_576,
        request_timeout_ms: 30_000,
        idle_timeout_ms: 60_000,
        retry: RetryPolicy::None,
        rate_policies: Vec::new(),
        cors: None,
    }
}

/// The valid configuration of [`draft`].
pub(crate) fn fields(host: &str, path: &str, methods: &[HttpMethod]) -> RouteFields {
    RouteFields::new(&draft(host, path, methods)).unwrap()
}

/// The stored state of route `number` with `fields`, at version 3.
pub(crate) fn parts(number: u32, fields: RouteFields) -> RouteParts {
    RouteParts {
        id: route_id(number),
        fields,
        system: false,
        version: EntityVersion::new(3).unwrap(),
        created_at: at(10),
        updated_at: at(20),
        deleted_at: None,
    }
}

/// A stamp of the test user at `seconds`.
pub(crate) fn stamp(seconds: u64) -> RouteStamp {
    RouteStamp {
        event_id: Uuid::parse(EVENT).unwrap(),
        actor: ActorRef::User(Uuid::parse(USER).unwrap()),
        occurred_at: at(seconds),
    }
}
