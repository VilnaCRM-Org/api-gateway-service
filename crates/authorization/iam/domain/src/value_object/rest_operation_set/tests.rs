use super::{RestOperation, RestOperationDetails, RestOperationKey, RestOperationSet};
use crate::error::InvalidSpec;
use crate::value_object::http_method::HttpMethod;
use crate::value_object::path_template::PathTemplate;
use crate::value_object::permission_flags::PermissionFlags;

fn template(path: &str) -> PathTemplate {
    PathTemplate::from_openapi_path(path).unwrap()
}

fn operation(method: HttpMethod, path: &str) -> RestOperation {
    RestOperation {
        method,
        template: template(path),
        label: None,
        flags: PermissionFlags::NONE,
    }
}

#[test]
fn a_new_set_is_empty() {
    let set = RestOperationSet::new();

    assert!(set.is_empty());
    assert_eq!(set.len(), 0);
    assert_eq!(set.iter().count(), 0);
}

#[test]
fn keeps_the_label_and_the_flags_of_an_operation() {
    let mut set = RestOperationSet::new();
    set.insert(RestOperation {
        method: HttpMethod::Post,
        template: template("/roles/{id}"),
        label: Some("createRole".to_owned()),
        flags: PermissionFlags::NONE.with_sensitive().with_audit_always(),
    })
    .unwrap();

    assert!(!set.is_empty());
    assert_eq!(set.len(), 1);
    assert_eq!(
        set.get(HttpMethod::Post, &template("/roles/{roleId}")),
        Some(&RestOperationDetails {
            label: Some("createRole".to_owned()),
            flags: PermissionFlags::NONE.with_sensitive().with_audit_always(),
        })
    );
    assert_eq!(set.get(HttpMethod::Get, &template("/roles/{id}")), None);
}

#[test]
fn iterates_in_key_order() {
    let mut set = RestOperationSet::new();
    set.insert(operation(HttpMethod::Post, "/b")).unwrap();
    set.insert(operation(HttpMethod::Get, "/b")).unwrap();
    set.insert(operation(HttpMethod::Get, "/a")).unwrap();

    let keys: Vec<String> = set.iter().map(|(key, _)| key.to_string()).collect();

    assert_eq!(keys, ["GET /a", "GET /b", "POST /b"]);
}

#[test]
fn refuses_two_operations_with_the_same_normalised_key() {
    let mut set = RestOperationSet::new();
    set.insert(operation(HttpMethod::Get, "/users/{id}"))
        .unwrap();

    let error = set
        .insert(operation(HttpMethod::Get, "/users/{userId}/"))
        .unwrap_err();

    assert_eq!(
        error,
        InvalidSpec::DuplicateOperation {
            key: "GET /users/{}".to_owned()
        }
    );
    assert_eq!(set.len(), 1);
}

#[test]
fn the_same_path_with_another_method_is_another_operation() {
    let mut set = RestOperationSet::new();
    set.insert(operation(HttpMethod::Get, "/users")).unwrap();

    assert_eq!(set.insert(operation(HttpMethod::Post, "/users")), Ok(()));
    assert_eq!(set.len(), 2);
}

#[test]
fn accepts_exactly_the_maximum_and_refuses_one_more() {
    let mut set = RestOperationSet::new();
    for index in 0..RestOperationSet::MAX_OPERATIONS {
        set.insert(operation(HttpMethod::Get, &format!("/p{index}")))
            .unwrap();
    }

    assert_eq!(set.len(), RestOperationSet::MAX_OPERATIONS);
    assert_eq!(
        set.insert(operation(HttpMethod::Get, "/one-more")),
        Err(InvalidSpec::TooManyOperations {
            limit: RestOperationSet::MAX_OPERATIONS
        })
    );
    assert_eq!(set.len(), RestOperationSet::MAX_OPERATIONS);
}

#[test]
fn a_duplicate_is_reported_even_at_the_limit() {
    let mut set = RestOperationSet::new();
    for index in 0..RestOperationSet::MAX_OPERATIONS {
        set.insert(operation(HttpMethod::Get, &format!("/p{index}")))
            .unwrap();
    }

    assert_eq!(
        set.insert(operation(HttpMethod::Get, "/p0")),
        Err(InvalidSpec::DuplicateOperation {
            key: "GET /p0".to_owned()
        })
    );
}

#[test]
fn a_key_displays_as_the_method_and_the_template() {
    let key = RestOperationKey {
        method: HttpMethod::Delete,
        template: template("/a/{x}/b"),
    };

    assert_eq!(key.to_string(), "DELETE /a/{}/b");
}
