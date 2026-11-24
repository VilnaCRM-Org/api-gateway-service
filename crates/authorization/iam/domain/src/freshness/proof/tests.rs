use std::time::Duration;

use super::FreshnessProof;
use crate::value_object::boot_instant::BootInstant;

fn at(seconds: u64) -> BootInstant {
    BootInstant::from_elapsed(Duration::from_secs(seconds))
}

#[test]
fn the_age_is_the_time_since_the_probe_started() {
    let proof = FreshnessProof {
        taken_at: at(10),
        watermark: 42,
    };

    assert_eq!(proof.age(at(14)), Duration::from_secs(4));
}

#[test]
fn the_age_of_a_proof_from_the_future_is_zero() {
    let proof = FreshnessProof {
        taken_at: at(10),
        watermark: 42,
    };

    assert_eq!(proof.age(at(3)), Duration::ZERO);
}
