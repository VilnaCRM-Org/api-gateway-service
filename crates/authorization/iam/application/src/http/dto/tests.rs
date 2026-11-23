use std::time::{Duration, SystemTime};

use iam_domain::{
    AccessToken, AccessTokenParts, EntityVersion, PermissionGrant, PermissionGrantSet,
    RoleDescription, RoleId, RoleKind, RoleName, RoleParts, ServiceName, SessionId, SubjectId,
    TokenId, TokenIdentity, TokenRejection,
};
use rstest::rstest;
use serde_json::json;
use shared_domain::Uuid;
use validator::Validate as _;

use super::{
    CreateRoleRequest, DeleteRoleResponse, DescriptionPatch, ListRolesParams, RolePageResponse,
    RoleResponse, TokenResolutionRequest, TokenResolutionResponse, UpdateRoleRequest,
    delete_role_canonical_form,
};
use crate::command::update_role::DescriptionUpdate;
use crate::error::IamError;
use crate::principal::Principal;
use crate::query::list_roles::{ListRolesQuery, RolePage};
use crate::query::resolve_subject_token::TokenResolution;

fn principal(subject: SubjectId, session: Option<&str>, expires_in: Duration) -> Principal {
    Principal::from(TokenIdentity::from(&AccessToken::new(AccessTokenParts {
        subject,
        session: session.map(|sid| SessionId::new(sid).unwrap()),
        token_id: TokenId::new("jti-9").unwrap(),
        roles: vec!["ROLE_USER".to_owned(), "ROLE_ADMIN".to_owned()],
        issued_at: SystemTime::UNIX_EPOCH,
        expires_at: SystemTime::UNIX_EPOCH.checked_add(expires_in).unwrap(),
    })))
}

fn user() -> SubjectId {
    SubjectId::User(Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap())
}

fn request(credential: &str) -> TokenResolutionRequest {
    TokenResolutionRequest {
        credential: credential.to_owned(),
    }
}

#[test]
fn a_resolved_user_token_is_answered_with_every_claim() {
    let user = principal(user(), Some("session-1"), Duration::from_hours(500_000));

    let response = TokenResolutionResponse::from(TokenResolution::Resolved(user));

    assert_eq!(
        serde_json::to_value(response).unwrap(),
        json!({
            "resolved": true,
            "subjectId": "0190f2a8-7b3c-7d4e-8f10-1234567890ab",
            "subjectKind": "user",
            "sessionId": "session-1",
            "roles": ["ROLE_USER", "ROLE_ADMIN"],
            "expiresAt": 1_800_000_000_i64,
        })
    );
}

#[test]
fn a_resolved_service_token_has_its_service_name_and_no_session() {
    let name = ServiceName::new("billing").unwrap();
    let service = principal(SubjectId::Service(name), None, Duration::from_secs(60));

    let response = TokenResolutionResponse::resolved(&service);

    assert_eq!(
        serde_json::to_value(response).unwrap(),
        json!({
            "resolved": true,
            "subjectId": "billing",
            "subjectKind": "service",
            "roles": ["ROLE_USER", "ROLE_ADMIN"],
            "expiresAt": 60,
        })
    );
}

#[rstest]
#[case::missing(TokenRejection::Missing, "token_missing")]
#[case::invalid(TokenRejection::Invalid, "token_invalid")]
#[case::expired(TokenRejection::Expired, "token_expired")]
#[case::revoked(TokenRejection::Revoked, "token_revoked")]
fn a_refused_credential_is_answered_with_its_reason_code_only(
    #[case] rejection: TokenRejection,
    #[case] code: &str,
) {
    let response = TokenResolutionResponse::from(TokenResolution::Unresolved(rejection));

    assert_eq!(
        serde_json::to_value(response).unwrap(),
        json!({ "resolved": false, "reason": code })
    );
}

fn principal_expiring_at(time: SystemTime) -> Principal {
    Principal::from(TokenIdentity::from(&AccessToken::new(AccessTokenParts {
        subject: user(),
        session: Some(SessionId::new("s").unwrap()),
        token_id: TokenId::new("jti-9").unwrap(),
        roles: Vec::new(),
        issued_at: SystemTime::UNIX_EPOCH,
        expires_at: time,
    })))
}

#[test]
fn an_expiry_before_1970_is_zero() {
    let before = SystemTime::UNIX_EPOCH
        .checked_sub(Duration::from_secs(10))
        .unwrap();

    let response = TokenResolutionResponse::resolved(&principal_expiring_at(before));

    assert_eq!(response.expires_at, Some(0));
}

#[test]
fn the_request_reads_its_credential_and_refuses_unknown_members() {
    let parsed: TokenResolutionRequest =
        serde_json::from_value(json!({ "credential": "abc" })).unwrap();

    assert_eq!(parsed.credential, "abc");
    assert!(
        serde_json::from_value::<TokenResolutionRequest>(json!({ "credential": "a", "x": 1 }))
            .is_err()
    );
    assert!(serde_json::from_value::<TokenResolutionRequest>(json!({})).is_err());
}

#[rstest]
#[case::empty("", true)]
#[case::at_the_limit(&"a".repeat(8192), true)]
#[case::above_the_limit(&"a".repeat(8193), false)]
fn the_credential_may_be_empty_but_not_longer_than_the_limit(
    #[case] credential: &str,
    #[case] valid: bool,
) {
    assert_eq!(request(credential).validate().is_ok(), valid);
}

#[test]
fn the_printed_request_never_shows_the_credential() {
    let printed = format!("{:?}", request("raw-secret-token"));

    assert!(printed.starts_with("TokenResolutionRequest"), "{printed}");
    assert!(!printed.contains("raw-secret-token"), "{printed}");
}

const ROLE: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890cd";

fn create(name: &str, description: Option<&str>) -> CreateRoleRequest {
    CreateRoleRequest {
        name: name.to_owned(),
        description: description.map(ToOwned::to_owned),
    }
}

#[rstest]
#[case::one_character("a", None, true)]
#[case::longest_name(&"a".repeat(100), None, true)]
#[case::empty_name("", None, false)]
#[case::name_above_the_limit(&"a".repeat(101), None, false)]
#[case::longest_description("a", Some("d".repeat(1000)), true)]
#[case::description_above_the_limit("a", Some("d".repeat(1001)), false)]
#[case::empty_description("a", Some(String::new()), true)]
fn the_name_and_the_description_keep_their_lengths(
    #[case] name: &str,
    #[case] description: Option<String>,
    #[case] valid: bool,
) {
    let request = create(name, description.as_deref());

    assert_eq!(request.validate().is_ok(), valid);
}

#[test]
fn the_create_request_reads_its_members_and_refuses_unknown_ones() {
    let parsed: CreateRoleRequest = serde_json::from_value(json!({ "name": "Billing" })).unwrap();

    assert_eq!(parsed.name, "Billing");
    assert_eq!(parsed.description, None);
    let described: CreateRoleRequest =
        serde_json::from_value(json!({ "name": "Billing", "description": "Invoices" })).unwrap();
    assert_eq!(described.description.as_deref(), Some("Invoices"));
    assert!(
        serde_json::from_value::<CreateRoleRequest>(json!({ "name": "a", "kind": "system" }))
            .is_err()
    );
    assert!(serde_json::from_value::<CreateRoleRequest>(json!({})).is_err());
}

#[test]
fn the_canonical_form_tells_one_request_from_another() {
    let forms = [
        create("a", None).canonical_form(),
        create("a", Some("")).canonical_form(),
        create("a", Some("b")).canonical_form(),
        create("ab", None).canonical_form(),
        create("a\\", Some("b")).canonical_form(),
    ];

    for (index, form) in forms.iter().enumerate() {
        assert!(form.starts_with("role.create:"), "{form}");
        assert_eq!(
            forms.iter().filter(|other| *other == form).count(),
            1,
            "{index}"
        );
    }
    assert_eq!(
        create("a", Some("b")).canonical_form(),
        create("a", Some("b")).canonical_form()
    );
}

fn role(description: Option<&str>, kind: RoleKind, grants: &[&str], version: i64) -> RoleParts {
    RoleParts {
        id: RoleId::parse(ROLE).unwrap(),
        name: RoleName::new("Billing".to_owned()).unwrap(),
        description: description.map(|text| RoleDescription::new(text.to_owned()).unwrap()),
        kind,
        grants: PermissionGrantSet::new(
            grants
                .iter()
                .map(|grant| PermissionGrant::parse(grant).unwrap()),
        )
        .unwrap(),
        version: EntityVersion::new(version).unwrap(),
        created_at: SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_micros(1_800_000_000_123_456))
            .unwrap(),
        updated_at: SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_mins(30_000_001))
            .unwrap(),
        deleted_at: None,
    }
}

#[test]
fn a_role_is_answered_with_every_field() {
    let stored = role(
        Some("Invoices"),
        RoleKind::Custom,
        &["gql:billing:Query.invoices", "rest:billing:GET /invoices"],
        3,
    );

    let response = RoleResponse::from(stored);

    assert_eq!(
        serde_json::to_value(response).unwrap(),
        json!({
            "id": ROLE,
            "name": "Billing",
            "description": "Invoices",
            "kind": "custom",
            "grantCount": 2,
            "version": 3,
            "createdAt": "2027-01-15T08:00:00.123456Z",
            "updatedAt": "2027-01-15T08:01:00.000000Z",
        })
    );
}

#[test]
fn a_role_without_a_description_or_grants_answers_null_and_zero() {
    let response = RoleResponse::from(role(None, RoleKind::System, &[], 1));

    let value = serde_json::to_value(response).unwrap();

    assert_eq!(value["description"], json!(null));
    assert_eq!(value["kind"], json!("system"));
    assert_eq!(value["grantCount"], json!(0));
    assert_eq!(value["version"], json!(1));
}

#[test]
fn a_page_of_roles_names_its_cursor_only_when_another_page_follows() {
    let first = role(None, RoleKind::Custom, &[], 1);
    let id = first.id;

    let with_cursor = RolePageResponse::from(RolePage {
        roles: vec![first.clone()],
        next_after: Some(id),
    });
    let last = RolePageResponse::from(RolePage {
        roles: vec![first],
        next_after: None,
    });

    assert_eq!(
        serde_json::to_value(&with_cursor).unwrap()["nextCursor"],
        json!(ROLE)
    );
    assert_eq!(with_cursor.items.len(), 1);
    assert!(
        serde_json::to_value(&last)
            .unwrap()
            .get("nextCursor")
            .is_none()
    );
}

fn params(
    limit: i32,
    after: Option<&str>,
    prefix: Option<&str>,
    kind: Option<&str>,
) -> ListRolesParams {
    ListRolesParams {
        limit,
        after: after.map(ToOwned::to_owned),
        name_prefix: prefix.map(ToOwned::to_owned),
        kind: kind.map(ToOwned::to_owned),
    }
}

#[test]
fn the_list_parameters_default_to_the_first_page_of_thirty() {
    let parsed: ListRolesParams = serde_json::from_value(json!({})).unwrap();

    assert_eq!(parsed.limit, 30);
    assert_eq!(parsed.after, None);
    assert_eq!(parsed.name_prefix, None);
    assert_eq!(parsed.kind, None);
    assert_eq!(ListRolesParams::default().limit, 30);
}

#[rstest]
#[case::lowest(1, true)]
#[case::highest(100, true)]
#[case::zero(0, false)]
#[case::negative(-1, false)]
#[case::above(101, false)]
fn the_limit_is_between_one_and_one_hundred(#[case] limit: i32, #[case] valid: bool) {
    assert_eq!(params(limit, None, None, None).validate().is_ok(), valid);
}

#[test]
fn the_name_prefix_has_at_most_one_hundred_characters() {
    assert!(
        params(5, None, Some(&"a".repeat(100)), None)
            .validate()
            .is_ok()
    );
    assert!(
        params(5, None, Some(&"a".repeat(101)), None)
            .validate()
            .is_err()
    );
}

#[test]
fn valid_parameters_become_the_query() {
    let query = params(7, Some(ROLE), Some("bill"), Some("system"))
        .into_query()
        .unwrap();

    assert_eq!(
        query,
        ListRolesQuery {
            limit: 7,
            after: Some(RoleId::parse(ROLE).unwrap()),
            name_prefix: Some("bill".to_owned()),
            kind: Some(RoleKind::System),
        }
    );
    let bare = params(30, None, None, None).into_query().unwrap();
    assert_eq!(
        (bare.after, bare.name_prefix, bare.kind),
        (None, None, None)
    );
}

#[rstest]
#[case::bad_cursor(Some("not-a-uuid"), None, &[("after", "uuid")])]
#[case::bad_kind(None, Some("owner"), &[("kind", "choice")])]
#[case::both(Some("x"), Some("y"), &[("after", "uuid"), ("kind", "choice")])]
fn an_invalid_cursor_or_kind_is_a_violation_each(
    #[case] after: Option<&str>,
    #[case] kind: Option<&str>,
    #[case] expected: &[(&str, &str)],
) {
    let error = params(5, after, None, kind).into_query().unwrap_err();

    let IamError::Invalid(violations) = error else {
        panic!("a validation error expected: {error:?}");
    };
    let found: Vec<(&str, &str)> = violations
        .iter()
        .map(|violation| (violation.property_path.as_str(), violation.code.as_str()))
        .collect();
    assert_eq!(found, expected);
}

fn update(name: Option<&str>, description: DescriptionUpdate) -> UpdateRoleRequest {
    UpdateRoleRequest {
        name: name.map(ToOwned::to_owned),
        description: DescriptionPatch(description),
    }
}

#[test]
fn the_update_request_tells_an_absent_description_from_a_null_and_a_text() {
    let absent: UpdateRoleRequest = serde_json::from_value(json!({ "name": "a" })).unwrap();
    let null: UpdateRoleRequest = serde_json::from_value(json!({ "description": null })).unwrap();
    let text: UpdateRoleRequest =
        serde_json::from_value(json!({ "description": "Invoices" })).unwrap();

    assert_eq!(absent.name.as_deref(), Some("a"));
    assert_eq!(
        absent.description,
        DescriptionPatch(DescriptionUpdate::Keep)
    );
    assert_eq!(null.name, None);
    assert_eq!(
        null.description,
        DescriptionPatch(DescriptionUpdate::Remove)
    );
    assert_eq!(
        text.description,
        DescriptionPatch(DescriptionUpdate::Set("Invoices".to_owned()))
    );
}

#[test]
fn the_update_request_accepts_an_empty_body_and_refuses_unknown_or_mistyped_members() {
    let empty: UpdateRoleRequest = serde_json::from_value(json!({})).unwrap();

    assert_eq!(empty.name, None);
    assert_eq!(empty.description, DescriptionPatch::default());
    assert!(serde_json::from_value::<UpdateRoleRequest>(json!({ "kind": "system" })).is_err());
    assert!(serde_json::from_value::<UpdateRoleRequest>(json!({ "description": 3 })).is_err());
}

#[rstest]
#[case::nothing(None, DescriptionUpdate::Keep, true)]
#[case::one_character(Some("a".to_owned()), DescriptionUpdate::Keep, true)]
#[case::longest_name(Some("a".repeat(100)), DescriptionUpdate::Keep, true)]
#[case::empty_name(Some(String::new()), DescriptionUpdate::Keep, false)]
#[case::name_above_the_limit(Some("a".repeat(101)), DescriptionUpdate::Keep, false)]
#[case::removal(None, DescriptionUpdate::Remove, true)]
#[case::longest_description(None, DescriptionUpdate::Set("d".repeat(1000)), true)]
#[case::description_above_the_limit(None, DescriptionUpdate::Set("d".repeat(1001)), false)]
#[case::empty_description(None, DescriptionUpdate::Set(String::new()), true)]
fn the_update_keeps_the_lengths_of_the_creation(
    #[case] name: Option<String>,
    #[case] description: DescriptionUpdate,
    #[case] valid: bool,
) {
    let request = update(name.as_deref(), description);

    assert_eq!(request.validate().is_ok(), valid);
}

#[test]
fn the_description_violation_names_its_property_and_keeps_its_message() {
    let errors = update(None, DescriptionUpdate::Set("d".repeat(1001)))
        .validate()
        .unwrap_err();

    let field = &errors.field_errors()["description"][0];
    assert_eq!(field.code, "length");
    assert_eq!(
        field.message.as_deref(),
        Some("This value must contain 1000 characters or fewer.")
    );
}

#[test]
fn the_update_canonical_form_tells_one_request_from_another() {
    let id = RoleId::parse(ROLE).unwrap();
    let other = RoleId::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ce").unwrap();
    let one = EntityVersion::INITIAL;
    let two = EntityVersion::new(2).unwrap();
    let forms = [
        update(Some("a"), DescriptionUpdate::Keep).canonical_form(id, one),
        update(Some("a"), DescriptionUpdate::Keep).canonical_form(id, two),
        update(Some("a"), DescriptionUpdate::Keep).canonical_form(other, one),
        update(Some("b"), DescriptionUpdate::Keep).canonical_form(id, one),
        update(Some("a"), DescriptionUpdate::Remove).canonical_form(id, one),
        update(Some("a"), DescriptionUpdate::Set(String::new())).canonical_form(id, one),
        update(None, DescriptionUpdate::Keep).canonical_form(id, one),
    ];

    for form in &forms {
        assert!(form.starts_with("role.update:"), "{form}");
        assert_eq!(forms.iter().filter(|other| *other == form).count(), 1);
    }
    assert_eq!(
        update(Some("a"), DescriptionUpdate::Keep).canonical_form(id, one),
        update(Some("a"), DescriptionUpdate::Keep).canonical_form(id, one)
    );
}

#[test]
fn the_description_patch_serializes_as_its_text_or_null() {
    let set = DescriptionPatch(DescriptionUpdate::Set("Invoices".to_owned()));

    assert_eq!(serde_json::to_value(&set).unwrap(), json!("Invoices"));
    assert_eq!(
        serde_json::to_value(DescriptionPatch(DescriptionUpdate::Keep)).unwrap(),
        json!(null)
    );
    assert_eq!(
        serde_json::to_value(DescriptionPatch(DescriptionUpdate::Remove)).unwrap(),
        json!(null)
    );
}

fn deletion_receipt(revoked: Option<u32>) -> iam_domain::ChangeReceipt {
    let receipt = iam_domain::ChangeReceipt::new(
        iam_domain::ChangeId::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ac").unwrap(),
        iam_domain::ActorRef::User(Uuid::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ab").unwrap()),
        iam_domain::AuditTarget::new("role", ROLE).unwrap(),
        EntityVersion::new(4).unwrap(),
        iam_domain::PolicyVersion::new(9).ok(),
    );
    match revoked {
        Some(count) => receipt.with_revoked_assignments(count),
        None => receipt,
    }
}

#[test]
fn the_deletion_response_names_the_role_and_the_revoked_assignments() {
    let response = DeleteRoleResponse::from(&deletion_receipt(Some(3)));

    assert_eq!(response.id, ROLE);
    assert_eq!(response.revoked_assignments, 3);
    assert_eq!(
        serde_json::to_value(&response).unwrap(),
        json!({ "id": ROLE, "revokedAssignments": 3 })
    );
}

#[test]
fn a_receipt_without_a_count_reports_no_revoked_assignments() {
    let response = DeleteRoleResponse::from(&deletion_receipt(None));

    assert_eq!(response.revoked_assignments, 0);
}

#[test]
fn the_deletion_canonical_form_tells_one_request_from_another() {
    let role = RoleId::parse(ROLE).unwrap();
    let other = RoleId::parse("0190f2a8-7b3c-7d4e-8f10-1234567890ce").unwrap();
    let forms = [
        delete_role_canonical_form(role, EntityVersion::new(1).unwrap()),
        delete_role_canonical_form(role, EntityVersion::new(2).unwrap()),
        delete_role_canonical_form(other, EntityVersion::new(1).unwrap()),
    ];

    assert_eq!(
        forms[0],
        delete_role_canonical_form(role, EntityVersion::new(1).unwrap())
    );
    assert_ne!(forms[0], forms[1]);
    assert_ne!(forms[0], forms[2]);
    assert!(forms[0].starts_with("role.delete:"));
}
