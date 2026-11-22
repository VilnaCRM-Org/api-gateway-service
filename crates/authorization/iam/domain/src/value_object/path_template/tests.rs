use rstest::rstest;

use super::PathTemplate;

#[rstest]
#[case("/", "/")]
#[case("/api/roles", "/api/roles")]
#[case("/api/roles/", "/api/roles")]
#[case("/api/roles/{id}", "/api/roles/{}")]
#[case("/api/roles/{roleId}/", "/api/roles/{}")]
#[case("/projects/{project}/members/{member}", "/projects/{}/members/{}")]
#[case("/files/{name}.json", "/files/{}.json")]
#[case("//", "/")]
fn replaces_parameter_names_and_drops_the_trailing_slash(
    #[case] path: &str,
    #[case] expected: &str,
) {
    let template = PathTemplate::from_openapi_path(path).unwrap();

    assert_eq!(template.as_str(), expected);
    assert_eq!(template.to_string(), expected);
    assert_eq!(template.as_rest_template().as_str(), expected);
}

#[test]
fn paths_that_differ_only_in_parameter_names_are_equal() {
    assert_eq!(
        PathTemplate::from_openapi_path("/users/{id}"),
        PathTemplate::from_openapi_path("/users/{userId}")
    );
}

#[rstest]
#[case("")]
#[case("users")]
#[case("/users/{}")]
#[case("/users/{id")]
#[case("/users/id}")]
#[case("/users/{a{b}}")]
#[case("/users/{id}}")]
#[case("/users/*")]
#[case("/users/{id} x")]
#[case("/usér")]
fn rejects_a_path_that_is_not_a_template(#[case] path: &str) {
    assert_eq!(PathTemplate::from_openapi_path(path), None);
}
