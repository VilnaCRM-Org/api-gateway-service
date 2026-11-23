//! What the doubles and fixtures of upstreams, routes and rate policies share.

use std::time::{Duration, SystemTime};

use iam_domain::{ChangeStatement, DecisionEffect, IamChange};
use rand::RngExt as _;

use crate::seed::TestRng;
use crate::unit_of_work::{iam_change, rebuilt};

/// A random time after 2020 and before 2100, in whole microseconds.
///
/// # Panics
///
/// Never in practice: the generated time is representable.
#[expect(
    clippy::expect_used,
    reason = "a time before the year 2100 is representable; a failure is a defect of the fixture"
)]
pub fn random_time(rng: &mut TestRng) -> SystemTime {
    let micros = rng
        .rng()
        .random_range(1_577_836_800_000_000_u64..4_102_444_800_000_000);
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_micros(micros))
        .expect("a time before the year 2100")
}

/// A random committed change that affects decisions and runs `statements`, written by a random
/// user.
pub fn gateway_change(rng: &mut TestRng, statements: Vec<ChangeStatement>) -> IamChange {
    rebuilt(&iam_change(rng, DecisionEffect::Affected, 0), |parts| {
        parts.statements = statements;
    })
}

#[cfg(test)]
mod tests;
