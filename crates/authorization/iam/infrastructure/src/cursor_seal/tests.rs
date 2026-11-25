use std::fmt::Write as _;

use iam_domain::{AccessLogCursor, CursorSeal as _};

use super::{HmacCursorSeal, decode, encode, hmac_sha256, same_bytes};

const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";
const OTHER_KEY: &[u8] = b"fedcba9876543210fedcba9876543210";

#[test]
fn a_sealed_payload_opens_under_the_same_key() {
    let seal = HmacCursorSeal::new(KEY);

    let token = seal.seal("1a2b.3");

    assert_eq!(seal.open(&token).as_deref(), Some("1a2b.3"));
    assert!(
        token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    );
}

#[test]
fn a_replica_with_the_same_key_opens_the_token_of_another() {
    let token = HmacCursorSeal::new(KEY).seal("1a2b.3");

    assert_eq!(
        HmacCursorSeal::new(KEY).open(&token).as_deref(),
        Some("1a2b.3")
    );
}

#[test]
fn a_token_sealed_under_a_different_key_is_refused() {
    let token = HmacCursorSeal::new(OTHER_KEY).seal("1a2b.3");

    assert_eq!(HmacCursorSeal::new(KEY).open(&token), None);
}

#[test]
fn a_token_of_another_random_seal_is_refused() {
    let token = HmacCursorSeal::random().seal("1a2b.3");

    assert_eq!(HmacCursorSeal::random().open(&token), None);
}

#[test]
fn a_tampered_payload_is_refused() {
    let seal = HmacCursorSeal::new(KEY);
    let mut bytes = decode(&seal.seal("1a2b.3")).unwrap();
    bytes[0] = b'2';
    let forged = encode(&bytes);

    assert_eq!(seal.open(&forged), None);
}

#[test]
fn a_tampered_tag_is_refused() {
    let seal = HmacCursorSeal::new(KEY);
    let mut bytes = decode(&seal.seal("1a2b.3")).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;

    assert_eq!(seal.open(&encode(&bytes)), None);
}

#[test]
fn a_plain_cursor_without_a_tag_is_refused() {
    let seal = HmacCursorSeal::new(KEY);

    for forged in ["1a2b.3", "", "!!!", &encode(b"1a2b.3")] {
        assert_eq!(seal.open(forged), None, "{forged}");
    }
}

#[test]
fn a_cursor_pages_through_the_seal_and_a_forged_one_is_refused() {
    let seal = HmacCursorSeal::new(KEY);
    let cursor = AccessLogCursor {
        timestamp_nanos: 1_800_000_000_000_000_000,
        returned: 4,
    };

    let token = cursor.sealed(&seal);

    assert_eq!(AccessLogCursor::opened(&token, &seal), Some(cursor));
    assert_eq!(AccessLogCursor::opened(&cursor.encode(), &seal), None);
}

#[test]
fn the_debug_form_does_not_show_the_key() {
    let text = format!("{:?}", HmacCursorSeal::new(KEY));

    assert!(!text.contains("0123456789abcdef"));
    assert!(text.contains("redacted"));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        write!(text, "{byte:02x}").unwrap();
        text
    })
}

#[test]
fn the_hmac_matches_the_rfc_4231_vectors() {
    assert_eq!(
        hex(&hmac_sha256(&[0x0b; 20], b"Hi There")),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
    assert_eq!(
        hex(&hmac_sha256(
            &[0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First"
        )),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    );
}

#[test]
fn a_key_longer_than_a_block_seals_and_opens() {
    let seal = HmacCursorSeal::new(&[7; 200]);

    assert_eq!(seal.open(&seal.seal("1a2b.3")).as_deref(), Some("1a2b.3"));
}

#[test]
fn the_encoding_matches_the_rfc_4648_vectors_without_padding() {
    for (plain, text) in [
        ("", ""),
        ("f", "Zg"),
        ("fo", "Zm8"),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg"),
        ("fooba", "Zm9vYmE"),
        ("foobar", "Zm9vYmFy"),
    ] {
        assert_eq!(encode(plain.as_bytes()), text);
        assert_eq!(decode(text).unwrap(), plain.as_bytes());
    }
    assert_eq!(encode(&[0xfb, 0xff]), "-_8");
    assert_eq!(decode("-_8").unwrap(), [0xfb, 0xff]);
}

#[test]
fn a_text_outside_the_alphabet_or_of_an_impossible_length_does_not_decode() {
    for text in ["Z", "Zm9vY", "Zg==", "Z+8", "Zm 9"] {
        assert_eq!(decode(text), None, "{text}");
    }
}

#[test]
fn byte_strings_of_another_length_or_content_differ() {
    assert!(same_bytes(b"abc", b"abc"));
    assert!(!same_bytes(b"abc", b"abd"));
    assert!(!same_bytes(b"abc", b"ab"));
}

#[test]
fn a_token_with_a_non_utf8_payload_does_not_open() {
    let seal = HmacCursorSeal::new(KEY);
    let mut token = vec![0xff, 0xfe];
    token.extend_from_slice(&hmac_sha256(KEY, &[0xff, 0xfe]));

    assert_eq!(seal.open(&encode(&token)), None);
}
