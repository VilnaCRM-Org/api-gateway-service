use super::PermissionGrantSet;
use crate::error::InvalidIamValue;
use crate::value_object::permission_grant::PermissionGrant;

fn grant(index: usize) -> PermissionGrant {
    PermissionGrant::parse(&format!("gql:core:Query.field{index}")).unwrap()
}

fn grants(count: usize) -> Vec<PermissionGrant> {
    (0..count).map(grant).collect()
}

#[test]
fn an_empty_set_is_allowed() {
    let set = PermissionGrantSet::new(Vec::new()).unwrap();

    assert!(set.is_empty());
    assert_eq!(set.len(), 0);
    assert_eq!(set, PermissionGrantSet::default());
}

#[test]
fn accepts_exactly_the_maximum_number_of_grants() {
    let set = PermissionGrantSet::new(grants(PermissionGrantSet::MAX_GRANTS)).unwrap();

    assert_eq!(set.len(), 5_000);
    assert!(!set.is_empty());
}

#[test]
fn rejects_one_grant_more_than_the_maximum() {
    assert_eq!(
        PermissionGrantSet::new(grants(5_001)),
        Err(InvalidIamValue::GrantSetTooLarge)
    );
}

#[test]
fn counts_a_repeated_grant_once() {
    let mut repeated = grants(PermissionGrantSet::MAX_GRANTS);
    repeated.push(grant(0));

    let set = PermissionGrantSet::new(repeated).unwrap();

    assert_eq!(set.len(), PermissionGrantSet::MAX_GRANTS);
}

#[test]
fn iterates_in_order_and_answers_membership() {
    let set = PermissionGrantSet::new(vec![grant(2), grant(1)]).unwrap();

    assert!(set.contains(&grant(1)));
    assert!(!set.contains(&grant(3)));
    assert_eq!(
        set.iter().cloned().collect::<Vec<_>>(),
        vec![grant(1), grant(2)]
    );
}
