use rstest::rstest;

use super::{DocumentRefusal, LimitKind};
use crate::value_object::decision_reason::DecisionReason;

#[rstest]
#[case(
    DocumentRefusal::LimitsExceeded(LimitKind::Depth),
    DecisionReason::LimitsExceeded
)]
#[case(
    DocumentRefusal::MalformedOperation,
    DecisionReason::MalformedOperation
)]
#[case(DocumentRefusal::UnknownOperation, DecisionReason::UnknownOperation)]
fn maps_to_its_reason_code(#[case] refusal: DocumentRefusal, #[case] reason: DecisionReason) {
    assert_eq!(refusal.reason(), reason);
}

#[rstest]
#[case(
    DocumentRefusal::LimitsExceeded(LimitKind::Bytes),
    "the document exceeds a limit"
)]
#[case(DocumentRefusal::MalformedOperation, "the operation cannot be read")]
#[case(
    DocumentRefusal::UnknownOperation,
    "the operation selects a field no active version has"
)]
fn displays_a_message(#[case] refusal: DocumentRefusal, #[case] message: &str) {
    assert_eq!(refusal.to_string(), message);
}
