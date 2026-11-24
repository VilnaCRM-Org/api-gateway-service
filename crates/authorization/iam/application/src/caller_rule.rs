//! The caller rule of the decision API and of token resolution (FR-12): a service validates only
//! for itself unless it holds a broader key.
//!
//! Validating for target service `s` requires `iam:validate:s` or `iam:validate:*`, and every item
//! of a batch is checked. Resolving a token requires `iam:validate:{caller's service name}` for a
//! service caller, or `iam:validate:*` for any caller. Neither operation requires a catalogue key.
//! The keys depend on the content of the request, so the guard decides them from the services that
//! the request names; this module holds the pure part: which services a request names and which
//! services a caller must hold a key for.

use async_graphql::Value;
use iam_domain::SubjectId;

/// The member of a check that names its target service.
const SERVICE_FIELD: &str = "service";

/// The member of a batch that lists its checks.
const CHECKS_FIELD: &str = "checks";

/// Which of the two caller rules a row of the rule table applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerRule {
    /// A decision request: a key for the target service of each check.
    Validate,
    /// Token resolution: a key for the caller's own service name.
    ResolveToken,
}

impl CallerRule {
    /// Whether the request must be read to learn the services it names.
    #[must_use]
    pub const fn names_services(self) -> bool {
        matches!(self, Self::Validate)
    }

    /// The services that the caller must hold `iam:validate:{service}` for when it does not hold
    /// `iam:validate:*`; `None` when only `iam:validate:*` admits the caller (a user resolving a
    /// token).
    #[must_use]
    pub fn required_services(self, caller: &SubjectId, named: &[String]) -> Option<Vec<String>> {
        match (self, caller) {
            (Self::Validate, _) if named.is_empty() => None,
            (Self::Validate, _) => {
                let mut services = named.to_vec();
                services.sort_unstable();
                services.dedup();
                Some(services)
            }
            (Self::ResolveToken, _) if named.iter().any(String::is_empty) => None,
            (Self::ResolveToken, SubjectId::Service(name)) => Some(vec![name.to_string()]),
            (Self::ResolveToken, SubjectId::User(_)) => None,
        }
    }
}

/// The name that stands for a check whose target service cannot be read.
///
/// It stands for an argument that does not resolve and for a check without a service as text. It
/// is no service name, so no key `iam:validate:{service}` covers it and only `iam:validate:*`
/// admits the request (fail closed).
pub const UNREADABLE_SERVICE: &str = "";

/// The target services that a value names, with [`UNREADABLE_SERVICE`] for each check that names
/// none.
///
/// An object that carries `service` as text names it, and so do the items of its `checks` and the
/// items of a list. A body of a decision request names its services this way, and so do the
/// arguments of the GraphQL decision fields. A check that names no service as text, and any value
/// that is neither an object nor a list, stands for [`UNREADABLE_SERVICE`], so that the guard
/// refuses it unless the caller holds `iam:validate:*`.
#[must_use]
pub fn target_services(value: &Value) -> Vec<String> {
    let mut services = Vec::new();
    collect(value, &mut services);
    services
}

fn collect(value: &Value, services: &mut Vec<String>) {
    match value {
        Value::List(items) => {
            for item in items {
                collect(item, services);
            }
        }
        Value::Object(members) => {
            let named = match members.get(SERVICE_FIELD) {
                Some(Value::String(service)) => {
                    services.push(service.clone());
                    true
                }
                _ => false,
            };
            match members.get(CHECKS_FIELD) {
                Some(checks) => collect(checks, services),
                None if !named => services.push(UNREADABLE_SERVICE.to_owned()),
                None => {}
            }
        }
        Value::Null
        | Value::Number(_)
        | Value::String(_)
        | Value::Boolean(_)
        | Value::Binary(_)
        | Value::Enum(_) => services.push(UNREADABLE_SERVICE.to_owned()),
    }
}

#[cfg(test)]
mod tests;
