//! The caller rule of the decision API and of token resolution (FR-12) over the decision path.

use iam_domain::{PermissionKey, SubjectRef};

use super::{IamAccessGuard, Verdict, subject_of};
use crate::caller_rule::CallerRule;
use crate::operation_rules::VALIDATE_ALL;
use crate::principal::Principal;

/// Decides the caller rule: `iam:validate:*` admits the caller, and without it the caller must
/// hold `iam:validate:{service}` for every service the rule names. A service that is not a
/// service name has no key, so only the wildcard admits it.
pub(super) async fn caller_verdict(
    guard: &IamAccessGuard,
    principal: &Principal,
    rule: CallerRule,
    named: &[String],
) -> Verdict {
    let subject = subject_of(principal);
    let wildcard = holds(guard, &subject, VALIDATE_ALL).await;
    if wildcard != Verdict::Denied {
        return wildcard;
    }
    let Some(services) = rule.required_services(principal.subject(), named) else {
        return Verdict::Denied;
    };
    for service in services {
        let held = holds(guard, &subject, &format!("iam:validate:{service}")).await;
        if held != Verdict::Allowed {
            return held;
        }
    }
    Verdict::Allowed
}

/// Decides whether `subject` holds the reserved key `raw` at global scope; a text that is not a
/// key is held by nobody.
async fn holds(guard: &IamAccessGuard, subject: &SubjectRef, raw: &str) -> Verdict {
    let Ok(key) = PermissionKey::parse(raw) else {
        return Verdict::Denied;
    };
    let outcome = guard
        .decisions
        .decide_reserved(subject.clone(), vec![key])
        .await;
    Verdict::of(&outcome)
}
