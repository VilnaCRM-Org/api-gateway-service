use rstest::rstest;

use super::RestTemplate;

#[rstest]
#[case("/")]
#[case("/api/roles")]
#[case("/api/roles/{}")]
#[case("/api/projects/{}/members/{}")]
#[case("/v1/a-b_c.d~e:f")]
fn accepts_a_path_template_with_anonymous_parameters(#[case] text: &str) {
    let template = RestTemplate::parse(text).unwrap();

    assert_eq!(template.as_str(), text);
    assert_eq!(template.to_string(), text);
}

#[test]
fn accepts_a_template_of_exactly_the_maximum_length() {
    let text = format!("/{}", "a".repeat(RestTemplate::MAX_LENGTH - 1));

    assert!(RestTemplate::parse(&text).is_some());
}

#[rstest]
#[case("")]
#[case("api/roles")]
#[case("/api roles")]
#[case("/api/*")]
#[case("/api/roles/{id}")]
#[case("/api/roles/{")]
#[case("/api/roles/}")]
#[case("/api/roles/}{")]
#[case("/api/rolé")]
#[case("/api/\u{7f}")]
fn rejects_anything_else(#[case] text: &str) {
    assert_eq!(RestTemplate::parse(text), None);
}

#[test]
fn rejects_a_template_over_the_maximum_length() {
    let text = format!("/{}", "a".repeat(RestTemplate::MAX_LENGTH));

    assert_eq!(RestTemplate::parse(&text), None);
}
