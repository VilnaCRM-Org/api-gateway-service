use rstest::rstest;

use super::{RestOperationMatcher, UnknownOperation};
use crate::policy::path_normalizer::PathNormalizer;
use crate::value_object::decision_reason::DecisionReason;
use crate::value_object::http_method::HttpMethod;
use crate::value_object::path_template::PathTemplate;
use crate::value_object::service_name::ServiceName;

fn templates(paths: &[&str]) -> Vec<PathTemplate> {
    paths
        .iter()
        .map(|path| PathTemplate::from_openapi_path(path).unwrap())
        .collect()
}

fn key(service: &str, method: HttpMethod, target: &str, paths: &[&str]) -> Option<String> {
    let service = ServiceName::new(service).unwrap();
    let path = PathNormalizer::normalize(target).unwrap();
    RestOperationMatcher::match_operation(&service, method, &path, &templates(paths))
        .ok()
        .map(|key| key.to_string())
}

#[test]
fn the_literal_template_wins_over_the_parameterised_one() {
    let paths = ["/api/roles/{id}", "/api/roles/batch"];

    assert_eq!(
        key("iam", HttpMethod::Post, "/api/roles/batch", &paths).as_deref(),
        Some("rest:iam:POST /api/roles/batch")
    );
    let reversed = ["/api/roles/batch", "/api/roles/{id}"];
    assert_eq!(
        key("iam", HttpMethod::Post, "/api/roles/batch", &reversed).as_deref(),
        Some("rest:iam:POST /api/roles/batch")
    );
}

#[test]
fn a_parameterised_match_uses_empty_braces_in_the_key() {
    let paths = ["/api/roles/{id}", "/api/roles/batch"];

    assert_eq!(
        key("iam", HttpMethod::Get, "/api/roles/0190", &paths).as_deref(),
        Some("rest:iam:GET /api/roles/{}")
    );
    assert_eq!(
        key(
            "user-service",
            HttpMethod::Delete,
            "/api/users/7/tokens/9?x=1",
            &["/api/users/{userId}/tokens/{tokenId}"]
        )
        .as_deref(),
        Some("rest:user-service:DELETE /api/users/{}/tokens/{}")
    );
}

#[test]
fn the_decoded_path_is_matched_and_a_trailing_slash_does_not_matter() {
    assert_eq!(
        key(
            "iam",
            HttpMethod::Get,
            "//api/ro%6Ces/batch/",
            &["/api/roles/batch"]
        )
        .as_deref(),
        Some("rest:iam:GET /api/roles/batch")
    );
}

#[test]
fn the_root_matches_the_root_template() {
    assert_eq!(
        key("iam", HttpMethod::Get, "/", &["/", "/api"]).as_deref(),
        Some("rest:iam:GET /")
    );
}

#[test]
fn the_first_differing_segment_decides_between_two_matching_templates() {
    let paths = ["/api/{group}/x", "/api/roles/{id}"];

    assert_eq!(
        key("iam", HttpMethod::Get, "/api/roles/x", &paths).as_deref(),
        Some("rest:iam:GET /api/roles/{}")
    );
}

#[rstest]
#[case("/api/roles/batch/extra")]
#[case("/api")]
#[case("/other/roles/1")]
#[case("/")]
fn a_path_without_a_matching_template_is_unknown(#[case] target: &str) {
    let service = ServiceName::new("iam").unwrap();
    let path = PathNormalizer::normalize(target).unwrap();

    let result = RestOperationMatcher::match_operation(
        &service,
        HttpMethod::Get,
        &path,
        &templates(&["/api/roles/{id}", "/api/roles/batch"]),
    );

    assert_eq!(result, Err(UnknownOperation));
    assert_eq!(
        DecisionReason::from(result.unwrap_err()),
        DecisionReason::UnknownOperation
    );
    assert_ne!(UnknownOperation.to_string(), "");
}

#[test]
fn a_service_without_templates_knows_no_operation() {
    assert_eq!(key("iam", HttpMethod::Get, "/api/roles", &[]), None);
}

#[rstest]
#[case("/files/report.json", "/files/{name}.json", true)]
#[case("/files/.json", "/files/{name}.json", false)]
#[case("/files/report.xml", "/files/{name}.json", false)]
#[case("/files/v2-beta", "/files/v{major}-{minor}", true)]
#[case("/files/v-beta", "/files/v{major}-{minor}", false)]
#[case("/files/v2-", "/files/v{major}-{minor}", false)]
#[case("/files/x2-beta", "/files/v{major}-{minor}", false)]
#[case("/files/v1-2-3", "/files/v{major}-{minor}", true)]
#[case("/files/ab", "/files/{a}{b}", true)]
#[case("/files/a", "/files/{a}{b}", false)]
#[case("/files/a.json.json", "/files/{name}.json", true)]
#[case("/files/x..json", "/files/{a}.{b}.json", false)]
#[case("/files/x.y.z.json", "/files/{a}.{b}.json", true)]
#[case("/files/%C3%A9-x", "/files/{a}-{b}", true)]
fn a_parameter_inside_a_segment_stands_for_at_least_one_character(
    #[case] target: &str,
    #[case] template: &str,
    #[case] matches: bool,
) {
    assert_eq!(
        key("iam", HttpMethod::Get, target, &[template]).is_some(),
        matches
    );
}

#[test]
fn a_literal_segment_beats_an_embedded_parameter_which_beats_a_bare_one() {
    let paths = ["/files/{name}", "/files/{stem}.json", "/files/report.json"];

    assert_eq!(
        key("iam", HttpMethod::Get, "/files/report.json", &paths).as_deref(),
        Some("rest:iam:GET /files/report.json")
    );
    assert_eq!(
        key("iam", HttpMethod::Get, "/files/data.json", &paths).as_deref(),
        Some("rest:iam:GET /files/{}.json")
    );
    assert_eq!(
        key("iam", HttpMethod::Get, "/files/data.xml", &paths).as_deref(),
        Some("rest:iam:GET /files/{}")
    );
}

/// A backtracking matcher would take exponential time on this case and hit the test timeout.
#[test]
fn many_embedded_parameters_are_matched_in_linear_time() {
    let names: Vec<String> = (0..20).map(|index| format!("{{p{index}}}")).collect();
    let template = format!("/files/v{}.json", names.join("-"));
    let target = format!("/files/v{}.xml", "-".repeat(60));

    assert_eq!(
        key("iam", HttpMethod::Get, &target, &[template.as_str()]),
        None
    );
}
