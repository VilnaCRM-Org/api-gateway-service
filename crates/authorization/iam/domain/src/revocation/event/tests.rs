use std::time::{Duration, SystemTime};

use shared_domain::Uuid;

use super::{GlobalTokensCutOff, SessionRevoked, UserTokensCutOff};
use crate::entity::event_envelope::EventEnvelope;
use crate::revocation::revocation_source::RevocationSource;
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::identifier::SessionRevocationId;
use crate::value_object::session_id::SessionId;

const EVENT: &str = "0190a0a0-0000-7000-8000-000000000001";
const USER: &str = "3d9b7c1e-5a2f-4e8d-b6c0-9f1e2d3c4b5a";

fn event_id() -> Uuid {
    Uuid::parse(EVENT).unwrap()
}

fn user() -> Uuid {
    Uuid::parse(USER).unwrap()
}

fn at() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(1_700_000_000))
        .unwrap()
}

#[test]
fn a_revoked_session_is_enveloped_under_its_type_with_the_revocation_as_aggregate() {
    let event = SessionRevoked {
        event_id: event_id(),
        revocation_id: SessionRevocationId::from_uuid(user()),
        session: SessionId::new("sid-1").unwrap(),
        user: user(),
        source: RevocationSource::Operator,
        actor: ActorRef::User(user()),
        occurred_at: at(),
        prune_after: at(),
    };

    let envelope = EventEnvelope::of(&event).unwrap();

    assert_eq!(envelope.parts().event_type.as_str(), "iam.session.revoked");
    assert_eq!(envelope.parts().aggregate_id, user());
    assert!(envelope.parts().data.contains("sessionId"));
    assert!(envelope.parts().data.contains("pruneAfter"));
}

#[test]
fn a_user_cutoff_is_enveloped_with_the_user_as_aggregate() {
    let event = UserTokensCutOff {
        event_id: event_id(),
        user: user(),
        tokens_valid_after: at(),
        source: RevocationSource::Operator,
        actor: ActorRef::User(user()),
        occurred_at: at(),
        prune_after: at(),
    };

    let envelope = EventEnvelope::of(&event).unwrap();

    assert_eq!(
        envelope.parts().event_type.as_str(),
        "iam.user_tokens.cut_off"
    );
    assert_eq!(envelope.parts().aggregate_id, user());
    assert!(envelope.parts().data.contains("tokensValidAfter"));
}

#[test]
fn the_global_cutoff_is_enveloped_as_its_own_aggregate() {
    let event = GlobalTokensCutOff {
        event_id: event_id(),
        tokens_valid_after: at(),
        actor: ActorRef::User(user()),
        occurred_at: at(),
    };

    let envelope = EventEnvelope::of(&event).unwrap();

    assert_eq!(
        envelope.parts().event_type.as_str(),
        "iam.global_tokens.cut_off"
    );
    assert_eq!(envelope.parts().aggregate_id, event_id());
}
