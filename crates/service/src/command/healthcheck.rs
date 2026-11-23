//! `service healthcheck`: requests `/ping` on the address the service listens on.
//!
//! The probe uses the loopback interface when the service listens on every interface and makes no
//! dependency access. `--mode gateway` requests `/ping` on the probe listener of the gateway.

use std::io::{Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::process::ExitCode;
use std::time::Duration;

use crate::cli::{HealthcheckArgs, Mode};

/// Connect, write and read timeout of the probe.
const TIMEOUT: Duration = Duration::from_secs(2);

/// Port probed when neither `--port` nor `APP_PORT` is given.
const DEFAULT_PORT: u16 = 8081;

/// Port of the probe listener of the gateway when `GATEWAY_PROBE_LISTEN` is not given.
const DEFAULT_PROBE_PORT: u16 = 9092;

/// Sends `GET /ping` over a plain TCP connection and reports whether the status line is 200.
#[expect(
    clippy::disallowed_methods,
    reason = "the liveness probe owns this loopback connection"
)]
fn probe(address: SocketAddr) -> std::io::Result<bool> {
    let mut stream = TcpStream::connect_timeout(&address, TIMEOUT)?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    stream.write_all(b"GET /ping HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n")?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response.starts_with("HTTP/1.1 200"))
}

/// The address to probe for the configured `APP_HOST`: the loopback address when the variable is
/// absent or names an unspecified address (`0.0.0.0` or `::` accept connections on the loopback
/// interface of their family), the address itself otherwise. `None` when it is not an IP address.
fn target_host(host: Option<&str>) -> Option<IpAddr> {
    let Some(text) = host else {
        return Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
    };
    text.parse::<IpAddr>().ok().map(reachable)
}

/// The address to connect to for a service that listens on `address`: the loopback address of the
/// same family when it listens on every interface.
const fn reachable(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V4(_) if address.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(_) if address.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V4(_) | IpAddr::V6(_) => address,
    }
}

/// The address the probe listener of the gateway accepts connections on: `GATEWAY_PROBE_LISTEN`
/// (`0.0.0.0:9092` when absent) with an unspecified host replaced by the loopback address.
fn gateway_target(listen: Option<&str>) -> Option<SocketAddr> {
    let address = listen.map_or_else(
        || {
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                DEFAULT_PROBE_PORT,
            ))
        },
        |text| text.parse::<SocketAddr>().ok(),
    )?;
    Some(SocketAddr::new(reachable(address.ip()), address.port()))
}

/// The address to probe, or `None` when the settings do not name one.
fn target(args: &HealthcheckArgs) -> Option<SocketAddr> {
    match args.mode {
        Mode::Gateway => gateway_target(args.probe_listen.as_deref()),
        Mode::Control => {
            let port = args
                .port
                .as_deref()
                .map_or(Some(DEFAULT_PORT), |text| text.parse().ok())?;
            Some(SocketAddr::new(target_host(args.host.as_deref())?, port))
        }
    }
}

/// Requests `/ping` on the address the service listens on and the port.
///
/// The address is `--host` / `APP_HOST` (loopback by default) and the port `--port` / `APP_PORT`;
/// with `--mode gateway` it is `--gateway-probe-listen` / `GATEWAY_PROBE_LISTEN`. The exit status
/// is 0 when the answer is 200 and 1 otherwise, including an unparsable host, port or listen
/// address, a refused connection and a timeout. Prints nothing.
#[must_use]
pub fn run(args: &HealthcheckArgs) -> ExitCode {
    match target(args).map(probe) {
        Some(Ok(true)) => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}

#[cfg(test)]
mod tests;
