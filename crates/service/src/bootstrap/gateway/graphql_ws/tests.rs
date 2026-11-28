use axum::http::header::{
    CONNECTION, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_PROTOCOL,
    SEC_WEBSOCKET_VERSION, UPGRADE,
};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use rstest::rstest;
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::Message;

use super::{
    ClientMessage, Handshake, Malformed, Protocol, ServerEvent, Unacceptable, accept,
    asks_for_websocket, close_frame, complete_message, decode_client, decode_server, error_message,
    pong_message, upstream_init,
};

/// The key and accept value of the example of RFC 6455, section 1.3.
const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

fn handshake_headers(protocols: &[&str]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(UPGRADE, HeaderValue::from_static("websocket"));
    headers.insert(CONNECTION, HeaderValue::from_static("keep-alive, Upgrade"));
    headers.insert(SEC_WEBSOCKET_VERSION, HeaderValue::from_static("13"));
    headers.insert(SEC_WEBSOCKET_KEY, HeaderValue::from_static(KEY));
    for protocol in protocols {
        headers.append(
            SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_str(protocol).unwrap(),
        );
    }
    headers
}

fn text(message: &Message) -> Value {
    match message {
        Message::Text(text) => serde_json::from_str(text.as_str()).unwrap(),
        Message::Binary(_)
        | Message::Ping(_)
        | Message::Pong(_)
        | Message::Close(_)
        | Message::Frame(_) => panic!("not a text message"),
    }
}

#[rstest]
#[case::transport(&["graphql-transport-ws"], Protocol::Transport)]
#[case::legacy(&["graphql-ws"], Protocol::Legacy)]
#[case::the_first_the_client_prefers(&["graphql-ws", "graphql-transport-ws"], Protocol::Legacy)]
#[case::skipping_what_it_does_not_speak(&["chat", "graphql-transport-ws"], Protocol::Transport)]
fn the_gateway_chooses_the_first_subprotocol_it_speaks(
    #[case] offered: &[&str],
    #[case] expected: Protocol,
) {
    let handshake = accept(&handshake_headers(offered)).unwrap();

    assert_eq!(handshake.protocol(), expected);
}

#[test]
fn several_subprotocols_in_one_header_are_read_in_order() {
    let mut headers = handshake_headers(&[]);
    headers.insert(
        SEC_WEBSOCKET_PROTOCOL,
        HeaderValue::from_static("chat , graphql-ws,graphql-transport-ws"),
    );

    assert_eq!(accept(&headers).unwrap().protocol(), Protocol::Legacy);
}

#[rstest]
#[case::another_subprotocol(&["chat"])]
#[case::none_at_all(&[])]
#[case::a_near_miss(&["graphql-transport-ws2", "GRAPHQL-WS"])]
fn a_client_that_offers_no_known_subprotocol_is_refused(#[case] offered: &[&str]) {
    let refused = accept(&handshake_headers(offered)).unwrap_err();

    assert_eq!(refused, Unacceptable::Subprotocol);
}

#[test]
fn the_answer_to_the_upgrade_names_the_protocol_and_proves_the_key() {
    let handshake = accept(&handshake_headers(&["graphql-transport-ws"])).unwrap();

    let response = handshake.response();

    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    assert_eq!(response.headers()[UPGRADE], "websocket");
    assert_eq!(response.headers()[SEC_WEBSOCKET_ACCEPT], ACCEPT);
    assert_eq!(
        response.headers()[SEC_WEBSOCKET_PROTOCOL],
        "graphql-transport-ws"
    );
}

#[rstest]
#[case::no_connection_header(CONNECTION)]
#[case::no_version(SEC_WEBSOCKET_VERSION)]
#[case::no_key(SEC_WEBSOCKET_KEY)]
fn a_handshake_that_lacks_a_header_is_refused(#[case] missing: axum::http::HeaderName) {
    let mut headers = handshake_headers(&["graphql-ws"]);
    headers.remove(missing);

    assert!(matches!(accept(&headers), Err(Unacceptable::Handshake(_))));
}

#[rstest]
#[case::an_old_version("8")]
#[case::a_word("thirteen")]
fn a_websocket_version_other_than_13_is_refused(#[case] version: &'static str) {
    let mut headers = handshake_headers(&["graphql-ws"]);
    headers.insert(SEC_WEBSOCKET_VERSION, HeaderValue::from_static(version));

    assert!(matches!(accept(&headers), Err(Unacceptable::Handshake(_))));
}

#[rstest]
#[case::too_short("dGhlIHNhbXBsZQ==")]
#[case::not_base64("dGhlIHNhbXBsZSBub25j!Q==")]
#[case::no_padding("dGhlIHNhbXBsZSBub25jZQAA")]
fn a_malformed_key_is_refused(#[case] key: &'static str) {
    let mut headers = handshake_headers(&["graphql-ws"]);
    headers.insert(SEC_WEBSOCKET_KEY, HeaderValue::from_static(key));

    assert!(matches!(accept(&headers), Err(Unacceptable::Handshake(_))));
}

#[test]
fn an_upgrade_request_is_recognised_without_regard_to_case() {
    let mut headers = HeaderMap::new();
    assert!(!asks_for_websocket(&headers));
    headers.insert(UPGRADE, HeaderValue::from_static("WebSocket"));

    assert!(asks_for_websocket(&headers));
}

fn decode(protocol: Protocol, value: &Value) -> Result<ClientMessage, Malformed> {
    decode_client(protocol, &value.to_string())
}

#[test]
fn connection_init_without_a_payload_carries_no_token() {
    let decoded = decode(Protocol::Transport, &json!({ "type": "connection_init" })).unwrap();

    assert_eq!(
        decoded,
        ClientMessage::Init {
            authorization: None,
            payload: None
        }
    );
}

#[test]
fn connection_init_splits_the_token_from_the_rest_of_its_payload() {
    let message = json!({
        "type": "connection_init",
        "payload": { "authorization": "Bearer abc", "tenant": "acme" },
    });

    let ClientMessage::Init {
        authorization,
        payload,
    } = decode(Protocol::Transport, &message).unwrap()
    else {
        panic!("not an init");
    };

    assert_eq!(authorization.as_deref(), Some("Bearer abc"));
    let payload = payload.unwrap();
    assert_eq!(payload.len(), 1);
    assert_eq!(payload["tenant"], "acme");
}

#[test]
fn an_authorization_that_is_not_a_string_is_no_token() {
    let message = json!({ "type": "connection_init", "payload": { "authorization": 7 } });

    let ClientMessage::Init { authorization, .. } = decode(Protocol::Legacy, &message).unwrap()
    else {
        panic!("not an init");
    };

    assert_eq!(authorization, None);
}

#[rstest]
#[case::an_array(json!({ "type": "connection_init", "payload": [1] }))]
#[case::a_string(json!({ "type": "connection_init", "payload": "token" }))]
fn a_payload_that_is_not_an_object_is_malformed(#[case] message: Value) {
    assert_eq!(decode(Protocol::Transport, &message), Err(Malformed));
}

#[test]
fn a_subscribe_carries_its_id_and_its_operation() {
    let message = json!({
        "id": "1",
        "type": "subscribe",
        "payload": { "query": "subscription { orderUpdated }", "operationName": "Watch" },
    });

    let ClientMessage::Operation { id, operation } = decode(Protocol::Transport, &message).unwrap()
    else {
        panic!("not an operation");
    };

    assert_eq!(id, "1");
    let operation = operation.unwrap();
    assert_eq!(operation.document, "subscription { orderUpdated }");
    assert_eq!(operation.operation_name.as_deref(), Some("Watch"));
}

#[test]
fn a_start_is_an_operation_of_the_legacy_protocol_only() {
    let message = json!({ "id": "1", "type": "start", "payload": { "query": "{ a }" } });

    assert!(matches!(
        decode(Protocol::Legacy, &message),
        Ok(ClientMessage::Operation { .. })
    ));
    assert_eq!(decode(Protocol::Transport, &message), Err(Malformed));
}

#[test]
fn a_subscribe_is_an_operation_of_the_transport_protocol_only() {
    let message = json!({ "id": "1", "type": "subscribe", "payload": { "query": "{ a }" } });

    assert_eq!(decode(Protocol::Legacy, &message), Err(Malformed));
}

#[rstest]
#[case::persisted_query(json!({ "extensions": { "persistedQuery": { "sha256Hash": "ab" } } }))]
#[case::an_empty_query(json!({ "query": "" }))]
#[case::no_query(json!({ "operationName": "Watch" }))]
#[case::a_document_id(json!({ "documentId": "abc", "query": "{ a }" }))]
fn a_payload_that_breaks_the_envelope_rules_is_refused_for_its_id(#[case] payload: Value) {
    let message = json!({ "id": "7", "type": "subscribe", "payload": payload });

    let ClientMessage::Operation { id, operation } = decode(Protocol::Transport, &message).unwrap()
    else {
        panic!("not an operation");
    };

    assert_eq!(id, "7");
    assert!(operation.is_err());
}

#[test]
fn a_subscribe_without_a_payload_is_refused_for_its_id() {
    let message = json!({ "id": "7", "type": "subscribe" });

    let ClientMessage::Operation { operation, .. } = decode(Protocol::Transport, &message).unwrap()
    else {
        panic!("not an operation");
    };

    assert!(operation.is_err());
}

#[test]
fn a_member_given_twice_in_a_payload_is_refused() {
    let text = r#"{"id":"1","type":"subscribe","payload":{"query":"{ a }","query":"{ b }"}}"#;

    let ClientMessage::Operation { operation, .. } =
        decode_client(Protocol::Transport, text).unwrap()
    else {
        panic!("not an operation");
    };

    assert!(operation.is_err());
}

#[test]
fn a_member_given_twice_in_a_message_is_malformed() {
    let text = r#"{"id":"1","id":"2","type":"complete"}"#;

    assert_eq!(decode_client(Protocol::Transport, text), Err(Malformed));
}

#[rstest]
#[case::transport(Protocol::Transport, "complete")]
#[case::legacy(Protocol::Legacy, "stop")]
fn the_client_ends_an_operation_with_the_message_of_its_protocol(
    #[case] protocol: Protocol,
    #[case] kind: &str,
) {
    let message = json!({ "id": "3", "type": kind });

    assert_eq!(
        decode(protocol, &message),
        Ok(ClientMessage::Stop { id: "3".to_owned() })
    );
}

#[rstest]
#[case::no_id(json!({ "type": "subscribe", "payload": { "query": "{ a }" } }))]
#[case::an_empty_id(json!({ "id": "", "type": "subscribe", "payload": { "query": "{ a }" } }))]
#[case::a_numeric_id(json!({ "id": 1, "type": "subscribe", "payload": { "query": "{ a }" } }))]
#[case::a_stop_without_id(json!({ "type": "complete" }))]
fn an_operation_message_needs_a_string_id(#[case] message: Value) {
    assert_eq!(decode(Protocol::Transport, &message), Err(Malformed));
}

#[rstest]
#[case::no_type(json!({ "id": "1" }))]
#[case::an_unknown_type(json!({ "type": "hello" }))]
#[case::a_numeric_type(json!({ "type": 4 }))]
#[case::not_an_object(json!([1, 2]))]
#[case::a_string(json!("connection_init"))]
fn a_frame_that_is_no_message_of_the_protocol_is_malformed(#[case] message: Value) {
    assert_eq!(decode(Protocol::Transport, &message), Err(Malformed));
}

#[test]
fn a_frame_that_is_not_json_is_malformed() {
    assert_eq!(decode_client(Protocol::Legacy, "not json"), Err(Malformed));
    assert_eq!(decode_client(Protocol::Legacy, ""), Err(Malformed));
}

#[test]
fn ping_and_pong_are_decoded() {
    assert_eq!(
        decode(Protocol::Transport, &json!({ "type": "ping" })),
        Ok(ClientMessage::Ping)
    );
    assert_eq!(
        decode(Protocol::Transport, &json!({ "type": "pong" })),
        Ok(ClientMessage::Pong)
    );
}

#[test]
fn connection_terminate_belongs_to_the_legacy_protocol() {
    let message = json!({ "type": "connection_terminate" });

    assert_eq!(
        decode(Protocol::Legacy, &message),
        Ok(ClientMessage::Terminate)
    );
    assert_eq!(decode(Protocol::Transport, &message), Err(Malformed));
}

#[rstest]
#[case::an_ack(json!({ "type": "connection_ack" }), ServerEvent::Ack)]
#[case::an_ack_with_a_payload(
    json!({ "type": "connection_ack", "payload": { "a": 1 } }),
    ServerEvent::Ack
)]
#[case::a_completion(
    json!({ "type": "complete", "id": "1" }),
    ServerEvent::Ended("1".to_owned())
)]
#[case::an_error_for_an_operation(
    json!({ "type": "error", "id": "2", "payload": [] }),
    ServerEvent::Ended("2".to_owned())
)]
#[case::a_next(json!({ "type": "next", "id": "1", "payload": {} }), ServerEvent::Other)]
#[case::a_data_message(json!({ "type": "data", "id": "1" }), ServerEvent::Other)]
#[case::a_completion_without_id(json!({ "type": "complete" }), ServerEvent::Other)]
fn a_message_of_the_upstream_is_read_only_for_its_type_and_id(
    #[case] message: Value,
    #[case] expected: ServerEvent,
) {
    assert_eq!(decode_server(&message.to_string()), expected);
}

#[test]
fn a_frame_of_the_upstream_that_does_not_decode_passes_as_other() {
    assert_eq!(decode_server("not json"), ServerEvent::Other);
    assert_eq!(decode_server("[]"), ServerEvent::Other);
}

#[test]
fn the_upstream_init_drops_the_token_of_the_payload() {
    let payload = serde_json::from_value(json!({ "tenant": "acme" })).unwrap();

    let init = upstream_init(Some(&payload), Some("secret"), false);

    assert_eq!(
        text(&init),
        json!({ "type": "connection_init", "payload": { "tenant": "acme" } })
    );
}

#[test]
fn the_upstream_init_carries_the_token_to_an_upstream_that_takes_credentials() {
    let payload = serde_json::from_value(json!({ "tenant": "acme" })).unwrap();

    let init = upstream_init(Some(&payload), Some("secret"), true);

    assert_eq!(
        text(&init),
        json!({
            "type": "connection_init",
            "payload": { "tenant": "acme", "authorization": "Bearer secret" },
        })
    );
}

#[test]
fn an_init_without_a_payload_stays_without_one_for_an_upstream_that_takes_no_credentials() {
    let init = upstream_init(None, Some("secret"), false);

    assert_eq!(text(&init), json!({ "type": "connection_init" }));
}

#[test]
fn an_init_without_a_payload_gets_the_token_for_an_upstream_that_takes_credentials() {
    let init = upstream_init(None, Some("secret"), true);

    assert_eq!(
        text(&init),
        json!({
            "type": "connection_init",
            "payload": { "authorization": "Bearer secret" },
        })
    );
}

#[test]
fn the_error_of_the_transport_protocol_is_a_list_of_errors() {
    let error = error_message(Protocol::Transport, "9", "FORBIDDEN", "no");

    assert_eq!(
        text(&error),
        json!({
            "type": "error",
            "id": "9",
            "payload": [{ "message": "no", "extensions": { "code": "FORBIDDEN" } }],
        })
    );
}

#[test]
fn the_error_of_the_legacy_protocol_is_one_error() {
    let error = error_message(Protocol::Legacy, "9", "FORBIDDEN", "no");

    assert_eq!(
        text(&error),
        json!({
            "type": "error",
            "id": "9",
            "payload": { "message": "no", "extensions": { "code": "FORBIDDEN" } },
        })
    );
}

#[test]
fn an_id_with_special_characters_is_escaped() {
    let error = error_message(Protocol::Transport, "a\"b\\c", "FORBIDDEN", "no");

    assert_eq!(text(&error)["id"], "a\"b\\c");
}

#[rstest]
#[case::transport(Protocol::Transport, "complete")]
#[case::legacy(Protocol::Legacy, "stop")]
fn the_gateway_ends_an_operation_upstream_with_the_message_of_the_protocol(
    #[case] protocol: Protocol,
    #[case] kind: &str,
) {
    assert_eq!(
        text(&complete_message(protocol, "4")),
        json!({ "type": kind, "id": "4" })
    );
}

#[test]
fn the_pong_answers_a_ping() {
    assert_eq!(text(&pong_message()), json!({ "type": "pong" }));
}

#[test]
fn a_close_frame_has_the_code_and_the_reason() {
    let frame = close_frame(4403, "forbidden");

    assert_eq!(u16::from(frame.code), 4403);
    assert_eq!(frame.reason.as_str(), "forbidden");
}

#[test]
fn the_protocols_are_named_as_their_subprotocols() {
    assert_eq!(Protocol::Transport.name(), "graphql-transport-ws");
    assert_eq!(Protocol::Legacy.name(), "graphql-ws");
}

#[test]
fn a_handshake_is_equal_to_the_handshake_of_the_same_request() {
    let first: Handshake = accept(&handshake_headers(&["graphql-ws"])).unwrap();
    let second = accept(&handshake_headers(&["graphql-ws"])).unwrap();

    assert_eq!(first, second);
}
