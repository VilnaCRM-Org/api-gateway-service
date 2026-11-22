use rstest::rstest;

use super::Credential;

const TOKEN: &str = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl";

#[test]
fn debug_prints_the_type_name_and_no_part_of_the_token() {
    let credential = Credential::new(TOKEN.to_owned());

    let printed = format!("{credential:?} {credential:#?}");

    assert_eq!(format!("{credential:?}"), "Credential");
    for part in TOKEN.split('.') {
        assert!(!printed.contains(part), "{printed}");
    }
}

#[test]
fn exposes_the_raw_text_to_the_verifier() {
    assert_eq!(Credential::new(TOKEN.to_owned()).expose(), TOKEN);
}

#[rstest]
#[case("", true)]
#[case("   ", true)]
#[case("\t\n", true)]
#[case("x", false)]
#[case(" token ", false)]
fn a_credential_of_blanks_is_blank(#[case] value: &str, #[case] blank: bool) {
    assert_eq!(Credential::new(value.to_owned()).is_blank(), blank);
}
