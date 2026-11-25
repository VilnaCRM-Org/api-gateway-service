use super::*;

#[test]
fn a_refused_stream_and_a_graceful_goaway_say_the_request_never_began() {
    assert!(refused_text(
        "stream error received: refused stream before processing any application logic"
    ));
    assert!(refused_text(
        "connection error received: not a result of an error"
    ));
    assert!(refused_text(
        "connection error received: not a result of an error (b\"max_age\")"
    ));
}

#[test]
fn any_other_http2_failure_may_have_reached_the_server() {
    assert!(!refused_text(
        "stream error received: unspecific protocol error detected"
    ));
    assert!(!refused_text(
        "connection error received: unexpected internal error encountered"
    ));
    assert!(!refused_text(
        "connection error detected: not a result of an error"
    ));
    assert!(!refused_text("connection reset"));
}

#[test]
fn a_plain_error_is_not_a_cancellation() {
    let error: Box<dyn StdError + 'static> = "boom".into();

    assert!(!never_began(error.as_ref()));
}
