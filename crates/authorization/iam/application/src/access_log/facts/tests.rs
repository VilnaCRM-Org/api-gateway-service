use iam_domain::{PermissionFlags, PermissionKey, RequiredKey};

use super::DecisionTrace;

fn required(text: &str, flags: PermissionFlags) -> RequiredKey {
    RequiredKey::new(PermissionKey::parse(text).unwrap(), flags)
}

#[test]
fn a_trace_without_keys_is_empty() {
    let trace = DecisionTrace::of_required(&[]);

    assert_eq!(trace, DecisionTrace::default());
    assert!(!trace.wildcard);
}

#[test]
fn a_trace_names_the_first_key_and_merges_the_flags_of_all() {
    let keys = [
        required("gql:orders:Query.order", PermissionFlags::NONE),
        required(
            "gql:orders:Mutation.cancelOrder",
            PermissionFlags::NONE.with_sensitive(),
        ),
        required(
            "gql:orders:Query.audit",
            PermissionFlags::NONE.with_audit_always(),
        ),
    ];

    let trace = DecisionTrace::of_required(&keys);

    assert_eq!(
        trace.permission_key.as_deref(),
        Some("gql:orders:Query.order")
    );
    assert!(trace.flags.is_sensitive());
    assert!(trace.flags.is_audit_always());
}

#[test]
fn a_trace_of_plain_keys_carries_no_flag() {
    let keys = [required("gql:orders:Query.order", PermissionFlags::NONE)];

    let trace = DecisionTrace::of_required(&keys);

    assert!(!trace.flags.is_sensitive());
    assert!(!trace.flags.is_audit_always());
}

#[test]
fn a_trace_notes_a_wildcard_allow() {
    let trace = DecisionTrace::default().with_wildcard(true);

    assert!(trace.wildcard);
    assert!(!trace.with_wildcard(false).wildcard);
}
