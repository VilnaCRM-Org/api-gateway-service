//! Proxy Protocol v2 (Story 10.9, FR-67): the header a load balancer writes before the first byte
//! of a connection, which names the client behind it.
//!
//! Only the binary header of version 2 is accepted; text headers (version 1) and anything else are
//! refused. A `LOCAL` command (the balancer's own health check) keeps the address of the socket.
//! The parser reads exactly the bytes of the header, so the stream continues at the first byte of
//! the connection proper.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt as _};

/// The twelve bytes every v2 header starts with.
pub const SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// The largest address block (with its TLV extensions) the gateway reads.
pub const MAX_PAYLOAD: usize = 1024;

const VERSION_2: u8 = 0x20;
const COMMAND_LOCAL: u8 = 0x00;
const COMMAND_PROXY: u8 = 0x01;
const FAMILY_UNSPEC: u8 = 0x00;
const TCP_OVER_IPV4: u8 = 0x11;
const TCP_OVER_IPV6: u8 = 0x21;

/// Why a connection has no valid Proxy Protocol header.
#[derive(Debug, thiserror::Error)]
pub enum ProxyHeaderError {
    /// The stream ended or failed before the header was complete.
    #[error("the Proxy Protocol header cannot be read: {0}")]
    Read(#[from] io::Error),
    /// The first bytes are not the v2 signature.
    #[error("the connection does not start with a Proxy Protocol v2 signature")]
    Signature,
    /// The version is not 2 or the command is neither `LOCAL` nor `PROXY`.
    #[error("the Proxy Protocol version or command is not supported")]
    Command,
    /// The address family or transport is not TCP over IPv4 or IPv6.
    #[error("the Proxy Protocol address family is not supported")]
    Family,
    /// The address block is longer than [`MAX_PAYLOAD`] or shorter than its family needs.
    #[error("the Proxy Protocol address block has an invalid length")]
    Length,
    /// The header did not arrive in time.
    #[error("the Proxy Protocol header did not arrive in time")]
    Timeout,
}

/// What the fixed 16 bytes announce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Prefix {
    command: u8,
    family: u8,
    length: usize,
}

fn parse_prefix(fixed: &[u8; 16]) -> Result<Prefix, ProxyHeaderError> {
    let (signature, rest) = fixed
        .split_first_chunk::<12>()
        .ok_or(ProxyHeaderError::Signature)?;
    if *signature != SIGNATURE {
        return Err(ProxyHeaderError::Signature);
    }
    let [version_command, family, high, low] =
        <[u8; 4]>::try_from(rest).map_err(|_short| ProxyHeaderError::Length)?;
    if version_command & 0xF0 != VERSION_2 {
        return Err(ProxyHeaderError::Command);
    }
    let command = version_command & 0x0F;
    if command != COMMAND_LOCAL && command != COMMAND_PROXY {
        return Err(ProxyHeaderError::Command);
    }
    let length = usize::from(u16::from_be_bytes([high, low]));
    if length > MAX_PAYLOAD {
        return Err(ProxyHeaderError::Length);
    }
    Ok(Prefix {
        command,
        family,
        length,
    })
}

fn take<const N: usize>(bytes: &[u8]) -> Result<([u8; N], &[u8]), ProxyHeaderError> {
    bytes
        .split_first_chunk::<N>()
        .map(|(head, tail)| (*head, tail))
        .ok_or(ProxyHeaderError::Length)
}

/// The source address of a `PROXY` block: the first address and the first port of the block.
fn source<const N: usize>(
    payload: &[u8],
    address: impl FnOnce([u8; N]) -> IpAddr,
) -> Result<SocketAddr, ProxyHeaderError> {
    let (source, rest) = take::<N>(payload)?;
    let (_destination, rest) = take::<N>(rest)?;
    let (port, _rest) = take::<2>(rest)?;
    Ok(SocketAddr::new(address(source), u16::from_be_bytes(port)))
}

fn parse_source(prefix: Prefix, payload: &[u8]) -> Result<Option<SocketAddr>, ProxyHeaderError> {
    if prefix.command == COMMAND_LOCAL {
        return Ok(None);
    }
    match prefix.family {
        TCP_OVER_IPV4 => source::<4>(payload, |bytes| IpAddr::V4(Ipv4Addr::from(bytes))).map(Some),
        TCP_OVER_IPV6 => source::<16>(payload, |bytes| IpAddr::V6(Ipv6Addr::from(bytes))).map(Some),
        FAMILY_UNSPEC => Ok(None),
        _ => Err(ProxyHeaderError::Family),
    }
}

/// Reads one header from `reader`: the client address it names, or `None` when the header asks to
/// keep the address of the socket (`LOCAL`, or an unspecified family).
///
/// # Errors
///
/// Returns why the bytes are not a valid v2 header.
pub async fn read_header<R>(reader: &mut R) -> Result<Option<SocketAddr>, ProxyHeaderError>
where
    R: AsyncRead + Unpin,
{
    let mut fixed = [0_u8; 16];
    reader.read_exact(&mut fixed).await?;
    let prefix = parse_prefix(&fixed)?;
    let mut payload = vec![0_u8; prefix.length];
    reader.read_exact(&mut payload).await?;
    parse_source(prefix, &payload)
}

/// [`read_header`] that gives up after `limit`.
///
/// # Errors
///
/// The errors of [`read_header`], or [`ProxyHeaderError::Timeout`].
pub async fn read_header_within<R>(
    reader: &mut R,
    limit: Duration,
) -> Result<Option<SocketAddr>, ProxyHeaderError>
where
    R: AsyncRead + Unpin,
{
    tokio::time::timeout(limit, read_header(reader))
        .await
        .unwrap_or(Err(ProxyHeaderError::Timeout))
}

#[cfg(test)]
mod tests;
