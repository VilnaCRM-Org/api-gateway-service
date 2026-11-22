//! The approved allow-list change (ADR 0023) is a prerequisite of the token adapter.

const ARCHITECTURE: &str = include_str!("../../../../../../architecture.toml");

/// The text of the `[[layer]]` table named `name`.
fn layer(name: &str) -> &'static str {
    ARCHITECTURE
        .split("[[layer]]")
        .find(|table| table.contains(&format!("name = \"{name}\"")))
        .unwrap()
}

#[test]
fn the_infrastructure_layer_allows_jsonwebtoken_and_dev_aws_lc_rs() {
    let infrastructure = layer("infrastructure");
    let (external, dev_external) = infrastructure.split_once("dev_external").unwrap();

    assert!(external.contains("\"jsonwebtoken\""));
    assert!(dev_external.contains("\"aws-lc-rs\""));
}
