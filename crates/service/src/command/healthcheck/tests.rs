use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rstest::rstest;

use std::process::ExitCode;

use super::{gateway_target, run, target, target_host};
use crate::cli::{HealthcheckArgs, Mode};

#[rstest]
#[case::absent(None, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)))]
#[case::unspecified_v4(Some("0.0.0.0"), Some(IpAddr::V4(Ipv4Addr::LOCALHOST)))]
#[case::unspecified_v6(Some("::"), Some(IpAddr::V6(Ipv6Addr::LOCALHOST)))]
#[case::loopback_v4(Some("127.0.0.1"), Some(IpAddr::V4(Ipv4Addr::LOCALHOST)))]
#[case::loopback_v6(Some("::1"), Some(IpAddr::V6(Ipv6Addr::LOCALHOST)))]
#[case::specific_v4(Some("10.0.3.7"), Some(IpAddr::V4(Ipv4Addr::new(10, 0, 3, 7))))]
#[case::specific_v6(
    Some("2001:db8::7"),
    Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7)))
)]
#[case::not_an_address(Some("localhost"), None)]
#[case::empty(Some(""), None)]
fn the_probe_targets_the_address_the_service_listens_on(
    #[case] host: Option<&str>,
    #[case] expected: Option<IpAddr>,
) {
    assert_eq!(target_host(host), expected);
}

#[rstest]
#[case::absent(None, Some("127.0.0.1:9092"))]
#[case::unspecified_v4(Some("0.0.0.0:9100"), Some("127.0.0.1:9100"))]
#[case::unspecified_v6(Some("[::]:9100"), Some("[::1]:9100"))]
#[case::loopback(Some("127.0.0.1:9100"), Some("127.0.0.1:9100"))]
#[case::specific(Some("10.0.3.7:9100"), Some("10.0.3.7:9100"))]
#[case::no_port(Some("10.0.3.7"), None)]
#[case::not_an_address(Some("localhost:9092"), None)]
fn the_gateway_probe_targets_the_address_of_the_probe_listener(
    #[case] listen: Option<&str>,
    #[case] expected: Option<&str>,
) {
    let expected = expected.map(|text| text.parse::<std::net::SocketAddr>().unwrap());

    assert_eq!(gateway_target(listen), expected);
}

fn args(
    mode: Mode,
    port: Option<&str>,
    host: Option<&str>,
    listen: Option<&str>,
) -> HealthcheckArgs {
    HealthcheckArgs {
        mode,
        port: port.map(str::to_owned),
        host: host.map(str::to_owned),
        probe_listen: listen.map(str::to_owned),
    }
}

#[test]
fn the_mode_decides_which_settings_name_the_target() {
    let control = args(
        Mode::Control,
        Some("9100"),
        Some("10.0.3.7"),
        Some("0.0.0.0:9200"),
    );
    let gateway = args(
        Mode::Gateway,
        Some("9100"),
        Some("10.0.3.7"),
        Some("0.0.0.0:9200"),
    );

    assert_eq!(target(&control), Some("10.0.3.7:9100".parse().unwrap()));
    assert_eq!(target(&gateway), Some("127.0.0.1:9200".parse().unwrap()));
}

#[test]
fn the_control_defaults_are_the_service_port_on_loopback() {
    assert_eq!(
        target(&args(Mode::Control, None, None, None)),
        Some("127.0.0.1:8081".parse().unwrap())
    );
    assert_eq!(target(&args(Mode::Control, Some("x"), None, None)), None);
    assert_eq!(target(&args(Mode::Control, None, Some("name"), None)), None);
}

#[test]
fn an_unreachable_probe_listener_fails_the_check() {
    let silent = args(Mode::Gateway, None, None, Some("127.0.0.1:1"));
    let unparsable = args(Mode::Gateway, None, None, Some("nowhere"));

    assert_eq!(run(&silent), ExitCode::FAILURE);
    assert_eq!(run(&unparsable), ExitCode::FAILURE);
}
