//! `GATEWAY_PROXY_PROTOCOL`: whether the public listener expects a Proxy Protocol v2 header.

use super::{gateway_problems, some, valid_gateway};
use crate::config::GatewayConfig;

#[test]
fn the_proxy_protocol_is_off_by_default() {
    let config = GatewayConfig::from_args(&valid_gateway()).unwrap();

    assert!(!config.proxy_protocol);
}

#[test]
fn the_proxy_protocol_can_be_switched_on_and_off() {
    for (raw, expected) in [("true", true), ("false", false)] {
        let mut args = valid_gateway();
        args.gateway_proxy_protocol = some(raw);

        let config = GatewayConfig::from_args(&args).unwrap();

        assert_eq!(config.proxy_protocol, expected, "{raw}");
    }
}

#[test]
fn a_proxy_protocol_that_is_no_boolean_names_the_variable_and_not_its_value() {
    let mut args = valid_gateway();
    args.gateway_proxy_protocol = some("sometimes");

    let problems = gateway_problems(&args);

    assert_eq!(
        problems,
        [("GATEWAY_PROXY_PROTOCOL", "must be true or false".to_owned())]
    );
}
