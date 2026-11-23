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

fn key(method: HttpMethod, path: &str) -> RestOperationKey {
    RestOperationKey {
        method,
        template: template(path),
    }
}

fn flagged(method: HttpMethod, path: &str, label: &str, flags: PermissionFlags) -> RestOperation {
    RestOperation {
        method,
        template: template(path),
        label: Some(label.to_owned()),
        flags,
    }
}

#[test]
fn contains_and_get_key_find_an_operation_by_its_key() {
    let mut set = RestOperationSet::new();
    set.insert(operation(HttpMethod::Get, "/roles")).unwrap();

    assert!(set.contains(&key(HttpMethod::Get, "/roles")));
    assert!(!set.contains(&key(HttpMethod::Post, "/roles")));
    assert_eq!(
        set.get_key(&key(HttpMethod::Get, "/roles"))
            .map(|details| details.flags),
        Some(PermissionFlags::NONE)
    );
    assert_eq!(set.get_key(&key(HttpMethod::Get, "/other")), None);
}

#[test]
fn the_union_keeps_every_operation_the_first_label_and_the_restrictive_flags() {
    let mut left = RestOperationSet::new();
    left.insert(flagged(
        HttpMethod::Get,
        "/a",
        "left",
        PermissionFlags::NONE.with_audit_always(),
    ))
    .unwrap();
    left.insert(operation(HttpMethod::Get, "/only-left"))
        .unwrap();
    let mut right = RestOperationSet::new();
    right
        .insert(flagged(
            HttpMethod::Get,
            "/a",
            "right",
            PermissionFlags::NONE.with_sensitive(),
        ))
        .unwrap();
    right
        .insert(operation(HttpMethod::Get, "/only-right"))
        .unwrap();

    let union = left.union(&right);

    assert_eq!(union.len(), 3);
    assert_eq!(
        union.get_key(&key(HttpMethod::Get, "/a")),
        Some(&RestOperationDetails {
            label: Some("left".to_owned()),
            flags: PermissionFlags::NONE.with_sensitive().with_audit_always(),
        })
    );
    assert!(union.contains(&key(HttpMethod::Get, "/only-left")));
    assert!(union.contains(&key(HttpMethod::Get, "/only-right")));
    assert_eq!(left.len(), 2);
}
