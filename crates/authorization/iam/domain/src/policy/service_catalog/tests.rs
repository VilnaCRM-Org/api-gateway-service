use super::ServiceCatalog;
use crate::value_object::graphql_type_graph::GraphQlTypeGraph;
use crate::value_object::log_epoch::LogEpoch;
use crate::value_object::policy_digest_value::PolicyDigestValue;
use crate::value_object::policy_epoch::PolicyEpoch;
use crate::value_object::policy_version::PolicyVersion;
use crate::value_object::relay_epoch::RelayEpoch;
use crate::value_object::rest_operation_set::RestOperationSet;
use crate::value_object::service_name::ServiceName;

fn epoch(version: i64) -> PolicyEpoch {
    PolicyEpoch::new(
        PolicyVersion::new(version).unwrap(),
        PolicyDigestValue::new(&[7; PolicyDigestValue::LENGTH]).unwrap(),
        LogEpoch::new(1).unwrap(),
        RelayEpoch::new(2).unwrap(),
        3,
    )
    .unwrap()
}

#[test]
fn a_catalogue_keeps_its_service_stamp_and_active_versions() {
    let service = ServiceName::new("orders").unwrap();
    let catalog = ServiceCatalog::new(
        service.clone(),
        epoch(9),
        vec![RestOperationSet::new(), RestOperationSet::new()],
        vec![GraphQlTypeGraph::default()],
    );

    assert_eq!(catalog.service(), &service);
    assert_eq!(catalog.epoch(), epoch(9));
    assert_eq!(catalog.policy_version().value(), 9);
    assert_eq!(catalog.rest_operations().len(), 2);
    assert_eq!(catalog.type_graphs().len(), 1);
}

#[test]
fn catalogues_of_different_stamps_differ() {
    let service = ServiceName::new("orders").unwrap();
    let before = ServiceCatalog::new(service.clone(), epoch(1), Vec::new(), Vec::new());
    let after = ServiceCatalog::new(service, epoch(2), Vec::new(), Vec::new());

    assert_ne!(before, after);
}
