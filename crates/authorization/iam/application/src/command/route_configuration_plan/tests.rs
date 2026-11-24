use super::{host_of, indexed};
use crate::error::IamError;

#[test]
fn an_error_that_is_not_a_violation_keeps_its_kind_whatever_its_position() {
    assert!(matches!(
        indexed(4, IamError::Forbidden),
        IamError::Forbidden
    ));
}

#[test]
fn a_violation_names_the_position_of_its_route() {
    let error = indexed(
        3,
        IamError::invalid_property("methods", "Required.", "required"),
    );

    let IamError::Invalid(violations) = error else {
        panic!("a validation failure expected");
    };
    assert_eq!(violations[0].property_path, "routes[3].methods");
    assert_eq!(violations[0].code, "required");
}

#[test]
fn a_host_name_is_validated() {
    assert_eq!(
        host_of("app.example.test").unwrap().to_string(),
        "app.example.test"
    );

    let IamError::Invalid(violations) = host_of("Not A Host").unwrap_err() else {
        panic!("a validation failure expected");
    };
    assert_eq!(violations[0].property_path, "host");
}
