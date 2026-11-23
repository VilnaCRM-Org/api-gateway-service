//! The accounted size of a snapshot of 100,000 synthetic subjects, printed as a measurement.

use iam_domain::LogEpoch;

use super::RawEntry;
use super::support::{Edit, Rig, role, subject, version};

const SUBJECTS: u32 = 100_000;
const ROLES: u32 = 50;

fn entry_of(rig: &Rig, edit: &Edit, changed_in: i64) -> RawEntry {
    let (key, state) = edit;
    RawEntry {
        key: key.clone(),
        version: version(changed_in),
        payload: rig.encode(state.as_ref().unwrap()),
    }
}

#[test]
fn the_accounted_size_of_a_hundred_thousand_subjects_is_measured_and_not_a_gate_value() {
    let mut rig = Rig::new();
    let mut entries: Vec<RawEntry> = (1..=ROLES)
        .map(|number| entry_of(&rig, &role(number, &["rest:cat-0:GET /users"]), 1))
        .collect();
    entries.extend((1..=SUBJECTS).map(|number| {
        let roles = if number % 3 == 0 {
            vec![1 + number % ROLES, 1 + (number / ROLES) % ROLES]
        } else {
            vec![1 + number % ROLES]
        };
        entry_of(&rig, &subject(number, &roles), 1)
    }));

    rig.builder
        .rebuild(&entries, version(1), LogEpoch::new(1).unwrap())
        .unwrap();

    let bytes = rig.snapshot().accounted_bytes();
    eprintln!(
        "accounted size of a snapshot of {SUBJECTS} subjects: {bytes} bytes (a measurement on the \
         test host, not a gate value; the 12.5% bound of NFR-38 is proven in Story 16.7)"
    );
    assert!(bytes > usize::try_from(SUBJECTS).unwrap());
    assert!(rig.builder.interned_lists() < 3_000);
    assert_eq!(rig.snapshot().version(), version(1));
}
