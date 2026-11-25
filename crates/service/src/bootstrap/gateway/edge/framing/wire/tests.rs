use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, duplex};

use super::Scanned;

/// What the scan makes of `bytes` written in `pieces` of the given size.
async fn conflicted(bytes: &[u8], piece: usize) -> bool {
    let (mut client, server) = duplex(4096);
    let (mut scanned, wire) = Scanned::new(server);
    for part in bytes.chunks(piece) {
        client.write_all(part).await.unwrap();
        let mut read = vec![0_u8; part.len()];
        scanned.read_exact(&mut read).await.unwrap();
    }
    wire.conflicted()
}

#[tokio::test]
async fn both_headers_in_one_block_are_a_conflict_in_either_order() {
    let length_first =
        b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n";
    let encoding_first =
        b"POST / HTTP/1.1\r\ntransfer-encoding: chunked\r\nCONTENT-LENGTH: 4\r\n\r\n";

    assert!(conflicted(length_first, 4096).await);
    assert!(conflicted(encoding_first, 4096).await);
}

#[tokio::test]
async fn a_block_cut_at_every_byte_is_still_a_conflict() {
    let request = b"POST / HTTP/1.1\r\ncontent-length: 4\r\ntransfer-encoding: chunked\r\n\r\n";

    assert!(conflicted(request, 1).await);
}

#[tokio::test]
async fn bare_line_feeds_end_the_lines_as_the_server_reads_them() {
    let request = b"POST / HTTP/1.1\ncontent-length: 4\ntransfer-encoding: chunked\n\n";

    assert!(conflicted(request, 4096).await);
}

#[tokio::test]
async fn one_header_per_block_is_no_conflict() {
    let requests = b"POST / HTTP/1.1\r\ncontent-length: 4\r\n\r\nabcdPOST / HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n";

    assert!(!conflicted(requests, 4096).await);
}

#[tokio::test]
async fn other_headers_and_long_lines_are_no_conflict() {
    let long = format!(
        "GET / HTTP/1.1\r\nx-padding: {}\r\ncontent-transfer-encoding: x\r\ncontent-length: 4\r\n\r\n",
        "a".repeat(200)
    );

    assert!(!conflicted(long.as_bytes(), 4096).await);
}

#[tokio::test]
async fn bytes_written_to_the_scanned_connection_reach_the_peer() {
    let (mut client, server) = duplex(64);
    let (mut scanned, wire) = Scanned::new(server);

    scanned.write_all(b"answer").await.unwrap();
    scanned.flush().await.unwrap();
    scanned.shutdown().await.unwrap();

    let mut received = String::new();
    client.read_to_string(&mut received).await.unwrap();
    assert_eq!(received, "answer");
    assert!(!wire.conflicted());
}
