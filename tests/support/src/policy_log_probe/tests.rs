use std::time::Duration;

use iam_domain::freshness::proof::FreshnessProof;
use iam_domain::{BootInstant, PolicyLogProbe as _, ProbeError};

use super::FakePolicyLogProbe;
use crate::block_on;

#[test]
fn answers_with_the_script_in_order_and_then_fails() {
    let proof = FreshnessProof {
        taken_at: BootInstant::from_elapsed(Duration::from_secs(1)),
        watermark: 3,
    };
    let probe = FakePolicyLogProbe::scripted(vec![Ok(proof), Err(ProbeError::FencedLeaderEpoch)]);

    assert_eq!(block_on(probe.probe()), Ok(proof));
    assert_eq!(block_on(probe.probe()), Err(ProbeError::FencedLeaderEpoch));
    assert!(matches!(
        block_on(probe.probe()),
        Err(ProbeError::Unavailable(_))
    ));
    assert_eq!(probe.probes(), 3);
}
