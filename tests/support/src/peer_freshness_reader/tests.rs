use iam_domain::{
    EndpointConditions, EndpointParts, PeerFreshnessReader as _, PeerObservation, UpstreamEndpoint,
};

use super::FakePeerFreshnessReader;
use crate::block_on;

fn peer(address: &str) -> UpstreamEndpoint {
    UpstreamEndpoint::new(EndpointParts {
        address: address.to_owned(),
        port: 9090,
        zone: None,
        pod: None,
        conditions: EndpointConditions::healthy(),
    })
}

fn observation(fresh: bool) -> PeerObservation {
    PeerObservation {
        version: None,
        fresh,
        proof_age: None,
    }
}

#[test]
fn a_peer_without_an_answer_is_unreachable() {
    let reader = FakePeerFreshnessReader::new();

    assert_eq!(block_on(reader.read(&peer("10.0.0.1"))), None);
}

#[test]
fn a_peer_reports_what_the_test_set_for_its_address() {
    let reader = FakePeerFreshnessReader::new();
    reader.report("10.0.0.1", observation(true));

    assert_eq!(
        block_on(reader.read(&peer("10.0.0.1"))),
        Some(observation(true))
    );
    assert_eq!(block_on(reader.read(&peer("10.0.0.2"))), None);
}

#[test]
fn the_fallback_answers_for_every_peer_without_an_answer_of_its_own() {
    let reader = FakePeerFreshnessReader::new();
    reader.report_all(observation(false));
    reader.report("10.0.0.1", observation(true));

    assert_eq!(
        block_on(reader.read(&peer("10.0.0.1"))),
        Some(observation(true))
    );
    assert_eq!(
        block_on(reader.read(&peer("10.0.0.9"))),
        Some(observation(false))
    );
}

#[test]
fn the_addresses_asked_are_recorded_until_forgotten() {
    let reader = FakePeerFreshnessReader::new();

    assert_eq!(block_on(reader.read(&peer("10.0.0.1"))), None);
    assert_eq!(block_on(reader.read(&peer("10.0.0.2"))), None);
    assert_eq!(reader.asked(), ["10.0.0.1", "10.0.0.2"]);

    reader.forget_asked();
    assert_eq!(reader.asked(), Vec::<String>::new());
}
