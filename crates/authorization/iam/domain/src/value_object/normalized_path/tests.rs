use super::NormalizedPath;

fn path(segments: &[&str]) -> NormalizedPath {
    NormalizedPath::from_segments(
        segments
            .iter()
            .map(|segment| (*segment).to_owned())
            .collect(),
    )
}

#[test]
fn the_root_has_no_segments_and_prints_as_a_slash() {
    let root = path(&[]);

    assert_eq!(root.segments(), Vec::<String>::new());
    assert_eq!(root.to_string(), "/");
    assert_eq!(root.canonical().as_str(), "/");
}

#[test]
fn segments_print_decoded_and_canonical_encodes_them() {
    let normalized = path(&["api", "a b"]);

    assert_eq!(normalized.segments(), ["api", "a b"]);
    assert_eq!(normalized.to_string(), "/api/a b");
    assert_eq!(normalized.canonical().as_str(), "/api/a%20b");
}
