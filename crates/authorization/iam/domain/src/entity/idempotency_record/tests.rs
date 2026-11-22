use shared_domain::Uuid;

use super::{IdempotencyRecord, IdempotencyRequest};
use crate::value_object::actor_ref::ActorRef;
use crate::value_object::idempotency_key::IdempotencyKey;
use crate::value_object::identifier::ChangeId;
use crate::value_object::request_digest::RequestDigest;

#[test]
fn a_record_keeps_the_actor_the_key_the_digest_and_the_change() {
    let actor = ActorRef::User(Uuid::parse("0190f2a8-7b3c-7d4e-8f00-123456789abc").unwrap());
    let key = IdempotencyKey::new("key-1").unwrap();
    let digest = RequestDigest::new(&[7; 32]).unwrap();
    let change_id = ChangeId::parse("0190f2a8-7b3c-7d4e-8f00-000000000001").unwrap();
    let request = IdempotencyRequest {
        key: key.clone(),
        request_digest: digest,
    };

    let record = IdempotencyRecord::new(actor.clone(), request, change_id);

    assert_eq!(record.actor(), &actor);
    assert_eq!(record.key(), &key);
    assert_eq!(record.request_digest(), digest);
    assert_eq!(record.change_id(), change_id);
}
