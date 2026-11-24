use iam_domain::{EntityVersion, RateFallback, RateKeyKind, RatePolicyId};
use serde_json::json;
use validator::Validate as _;

use super::{
    CreateRatePolicyRequest, DeleteRatePolicyResponse, ListRatePoliciesParams,
    RatePolicyPageResponse, RatePolicyResponse, UpdateRatePolicyRequest,
    delete_rate_policy_canonical_form,
};
use crate::error::IamError;
use crate::query::list_rate_policies::RatePolicyPage;
use crate::rate_policy_fixtures::{POLICY, rate_policy, receipt_at};

fn create() -> CreateRatePolicyRequest {
    serde_json::from_value(json!({
        "name": "per-subject",
        "key": "subject_route",
        "limit": 100,
        "periodMs": 60_000,
        "burst": 20,
        "fallback": "divided",
    }))
    .unwrap()
}

fn paths(error: IamError) -> Vec<String> {
    let IamError::Invalid(violations) = error else {
        panic!("violations expected: {error:?}");
    };
    violations
        .into_iter()
        .map(|violation| violation.property_path)
        .collect()
}

#[test]
fn a_creation_body_becomes_the_values_of_a_policy() {
    let values = create().into_values().unwrap();

    assert_eq!(values.name, "per-subject");
    assert_eq!(values.key_kind, RateKeyKind::SubjectRoute);
    assert_eq!(values.limit, 100);
    assert_eq!(values.period_ms, 60_000);
    assert_eq!(values.burst, 20);
    assert_eq!(values.fallback, RateFallback::Divided);
    assert!(create().validate().is_ok());
}

#[test]
fn a_creation_body_misses_no_member_and_adds_none() {
    let missing = serde_json::from_value::<CreateRatePolicyRequest>(json!({ "name": "a" }));
    let extra = serde_json::from_value::<CreateRatePolicyRequest>(json!({
        "name": "a", "key": "ip", "limit": 1, "periodMs": 1000, "burst": 0,
        "fallback": "full", "other": 1,
    }));

    assert!(missing.is_err());
    assert!(extra.is_err());
}

#[test]
fn a_key_and_a_fallback_that_name_nothing_are_violations_of_their_members() {
    let request = CreateRatePolicyRequest {
        key: "everyone".to_owned(),
        fallback: "never".to_owned(),
        ..create()
    };

    assert_eq!(
        paths(request.into_values().unwrap_err()),
        ["key", "fallback"]
    );
}

#[test]
fn an_update_body_names_only_the_members_it_changes() {
    let request: UpdateRatePolicyRequest =
        serde_json::from_value(json!({ "limit": 5, "key": "ip" })).unwrap();

    let patch = request.into_patch().unwrap();

    assert_eq!(patch.limit, Some(5));
    assert_eq!(patch.key_kind, Some(RateKeyKind::Ip));
    assert_eq!(patch.name, None);
    assert_eq!(patch.period_ms, None);
    assert_eq!(patch.burst, None);
    assert_eq!(patch.fallback, None);
    assert!(UpdateRatePolicyRequest::default().validate().is_ok());
}

#[test]
fn an_update_body_with_an_unknown_key_or_fallback_is_refused() {
    let request = UpdateRatePolicyRequest {
        key: Some("everyone".to_owned()),
        fallback: Some("never".to_owned()),
        ..UpdateRatePolicyRequest::default()
    };

    assert_eq!(
        paths(request.into_patch().unwrap_err()),
        ["key", "fallback"]
    );
}

#[test]
fn the_canonical_forms_differ_by_operation_and_content() {
    let id = RatePolicyId::parse(POLICY).unwrap();
    let version = EntityVersion::new(2).unwrap();
    let other = CreateRatePolicyRequest {
        limit: 101,
        ..create()
    };
    let update = UpdateRatePolicyRequest {
        limit: Some(1),
        ..UpdateRatePolicyRequest::default()
    };

    assert_ne!(create().canonical_form(), other.canonical_form());
    assert_ne!(
        update.canonical_form(id, version),
        UpdateRatePolicyRequest::default().canonical_form(id, version)
    );
    assert_ne!(
        update.canonical_form(id, version),
        delete_rate_policy_canonical_form(id, version)
    );
    assert!(delete_rate_policy_canonical_form(id, version).starts_with("rate_policy.delete:"));
}

#[test]
fn a_rate_policy_is_answered_with_every_member_of_fr_64() {
    let response = RatePolicyResponse::from(rate_policy(3));

    assert_eq!(
        serde_json::to_value(response).unwrap(),
        json!({
            "id": POLICY,
            "name": "per-subject",
            "key": "subject_route",
            "limit": 100,
            "periodMs": 60_000,
            "burst": 20,
            "fallback": "divided",
            "version": 3,
            "createdAt": "2027-01-15T08:00:00.000000Z",
            "updatedAt": "2027-01-15T08:01:00.000000Z",
        })
    );
}

#[test]
fn a_page_names_its_cursor_only_when_another_page_follows() {
    let last = RatePolicyPageResponse::from(RatePolicyPage {
        rate_policies: vec![rate_policy(1)],
        next_after: None,
    });
    let more = RatePolicyPageResponse::from(RatePolicyPage {
        rate_policies: vec![rate_policy(1)],
        next_after: Some(RatePolicyId::parse(POLICY).unwrap()),
    });

    assert_eq!(last.items.len(), 1);
    assert_eq!(serde_json::to_value(&last).unwrap().get("nextCursor"), None);
    assert_eq!(more.next_cursor.as_deref(), Some(POLICY));
}

#[test]
fn a_deletion_is_answered_with_the_policy_and_its_final_version() {
    let response = DeleteRatePolicyResponse::from(&receipt_at(4, Some(9)));

    assert_eq!(
        serde_json::to_value(response).unwrap(),
        json!({ "id": POLICY, "version": 4 })
    );
}

#[test]
fn list_parameters_default_to_the_first_page_of_thirty_and_check_their_range() {
    let defaults = ListRatePoliciesParams::default();
    let zero = ListRatePoliciesParams {
        limit: 0,
        ..ListRatePoliciesParams::default()
    };

    assert_eq!(defaults.limit, 30);
    assert!(defaults.validate().is_ok());
    assert!(zero.validate().is_err());
}

#[test]
fn list_parameters_become_a_query_and_refuse_a_cursor_that_is_not_a_uuid() {
    let query = ListRatePoliciesParams {
        limit: 5,
        after: Some(POLICY.to_owned()),
    }
    .into_query()
    .unwrap();
    let refused = ListRatePoliciesParams {
        limit: 5,
        after: Some("not-a-uuid".to_owned()),
    }
    .into_query()
    .unwrap_err();

    assert_eq!(query.limit, 5);
    assert_eq!(query.after, Some(RatePolicyId::parse(POLICY).unwrap()));
    assert_eq!(paths(refused), ["after"]);
}
