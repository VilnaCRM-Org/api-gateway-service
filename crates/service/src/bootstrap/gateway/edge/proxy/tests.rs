use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::AsyncWriteExt as _;

use super::{ProxyHeaderError, SIGNATURE, read_header, read_header_within};

fn header(version_command: u8, family: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = SIGNATURE.to_vec();
    bytes.push(version_command);
    bytes.push(family);
    bytes.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn ipv4_block(source: [u8; 4], port: u16) -> Vec<u8> {
    let mut block = source.to_vec();
    block.extend_from_slice(&[10, 0, 0, 1]);
    block.extend_from_slice(&port.to_be_bytes());
    block.extend_from_slice(&443_u16.to_be_bytes());
    block
}

async fn parse(bytes: Vec<u8>) -> Result<Option<SocketAddr>, ProxyHeaderError> {
    read_header(&mut bytes.as_slice()).await
}

#[tokio::test]
async fn a_proxy_header_over_ipv4_names_the_client() {
    let bytes = header(0x21, 0x11, &ipv4_block([203, 0, 113, 7], 51000));

    let client = parse(bytes).await.unwrap();

    assert_eq!(client, Some("203.0.113.7:51000".parse().unwrap()));
}

#[tokio::test]
async fn a_proxy_header_over_ipv6_names_the_client() {
    let mut block = "2001:db8::7"
        .parse::<std::net::Ipv6Addr>()
        .unwrap()
        .octets()
        .to_vec();
    block.extend_from_slice(&[0; 16]);
    block.extend_from_slice(&40000_u16.to_be_bytes());
    block.extend_from_slice(&443_u16.to_be_bytes());

    let client = parse(header(0x21, 0x21, &block)).await.unwrap();

    assert_eq!(client, Some("[2001:db8::7]:40000".parse().unwrap()));
}

#[tokio::test]
async fn a_local_command_keeps_the_address_of_the_socket() {
    assert_eq!(parse(header(0x20, 0x00, &[])).await.unwrap(), None);
    assert_eq!(
        parse(header(0x20, 0x11, &ipv4_block([1, 2, 3, 4], 1)))
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn an_unspecified_family_keeps_the_address_of_the_socket() {
    assert_eq!(parse(header(0x21, 0x00, &[1, 2, 3])).await.unwrap(), None);
}

#[tokio::test]
async fn tlv_extensions_after_the_addresses_are_skipped() {
    let mut block = ipv4_block([198, 51, 100, 9], 1234);
    block.extend_from_slice(&[0x04, 0x00, 0x01, 0xAA]);

    let client = parse(header(0x21, 0x11, &block)).await.unwrap();

    assert_eq!(client, Some("198.51.100.9:1234".parse().unwrap()));
}

#[tokio::test]
async fn the_bytes_after_the_header_stay_in_the_stream() {
    let mut bytes = header(0x21, 0x11, &ipv4_block([203, 0, 113, 7], 1));
    bytes.extend_from_slice(b"GET / HTTP/1.1");
    let mut reader = bytes.as_slice();

    read_header(&mut reader).await.unwrap();

    assert_eq!(reader, b"GET / HTTP/1.1");
}

#[tokio::test]
async fn a_connection_without_a_header_is_refused() {
    let plain = b"GET /api/users HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();

    assert!(matches!(
        parse(plain).await,
        Err(ProxyHeaderError::Signature)
    ));
}

#[tokio::test]
async fn a_version_1_text_header_is_refused() {
    let text = b"PROXY TCP4 203.0.113.7 10.0.0.1 51000 443\r\n".to_vec();

    assert!(matches!(
        parse(text).await,
        Err(ProxyHeaderError::Signature)
    ));
}

#[tokio::test]
async fn another_version_or_command_is_refused() {
    for version_command in [0x11, 0x22, 0x2F] {
        let bytes = header(version_command, 0x11, &ipv4_block([1, 1, 1, 1], 1));
        assert!(
            matches!(parse(bytes).await, Err(ProxyHeaderError::Command)),
            "{version_command:#x}"
        );
    }
}

#[tokio::test]
async fn a_unix_socket_family_is_refused() {
    let bytes = header(0x21, 0x31, &[0; 216]);

    assert!(matches!(parse(bytes).await, Err(ProxyHeaderError::Family)));
}

#[tokio::test]
async fn a_block_that_is_too_long_or_too_short_is_refused() {
    let long = header(0x21, 0x11, &vec![0; 2000]);
    let short = header(0x21, 0x11, &[1, 2, 3, 4]);

    assert!(matches!(parse(long).await, Err(ProxyHeaderError::Length)));
    assert!(matches!(parse(short).await, Err(ProxyHeaderError::Length)));
}

#[tokio::test]
async fn a_truncated_header_is_a_read_error() {
    let mut bytes = header(0x21, 0x11, &ipv4_block([1, 1, 1, 1], 1));
    bytes.truncate(20);

    assert!(matches!(parse(bytes).await, Err(ProxyHeaderError::Read(_))));
    assert!(matches!(
        parse(Vec::new()).await,
        Err(ProxyHeaderError::Read(_))
    ));
}

#[tokio::test(start_paused = true)]
async fn a_header_that_never_arrives_times_out() {
    let (mut client, mut server) = tokio::io::duplex(64);
    client.write_all(&SIGNATURE).await.unwrap();

    let outcome = read_header_within(&mut server, Duration::from_secs(10)).await;

    assert!(matches!(outcome, Err(ProxyHeaderError::Timeout)));
}

#[tokio::test(start_paused = true)]
async fn a_header_that_arrives_in_time_is_read() {
    let (mut client, mut server) = tokio::io::duplex(256);
    client
        .write_all(&header(0x21, 0x11, &ipv4_block([192, 0, 2, 1], 80)))
        .await
        .unwrap();

    let outcome = read_header_within(&mut server, Duration::from_secs(10)).await;

    assert_eq!(outcome.unwrap(), Some("192.0.2.1:80".parse().unwrap()));
}
