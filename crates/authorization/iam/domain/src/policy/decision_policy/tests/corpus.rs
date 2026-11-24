//! The maintained decision corpus of FR-10: every case names the policy, the check and the one
//! correct verdict. A new rule or a fixed defect adds a case here.

use super::{NOW, RoleSpec, at, decide, project, projects, required, role, role_sets, sensitive};
use crate::policy::decision_policy::{RequiredKey, RoleAssignment};
use crate::value_object::assignment_scope::AssignmentScope;
use crate::value_object::decision_outcome::DecisionVerdict;
use crate::value_object::decision_reason::DecisionReason;
use crate::value_object::scope_set::ScopeSet;

/// When an assignment of the corpus expires, relative to the decision instant.
#[derive(Debug, Clone, Copy)]
enum Expiry {
    Never,
    Passed,
    AtNow,
    Later,
}

/// One assignment: role, project (`None` for global) and expiry.
#[derive(Debug, Clone, Copy)]
struct Assign(u8, Option<u8>, Expiry);

/// The one correct verdict of a case.
#[derive(Debug, Clone, Copy)]
enum Expect {
    AllowAll,
    AllowIn(&'static [u8]),
    Deny(DecisionReason, &'static [&'static str]),
}

/// One corpus case.
#[derive(Debug, Clone, Copy)]
struct Case {
    name: &'static str,
    /// `(role, active grants, orphaned grants)`.
    roles: &'static [RoleSpec<'static>],
    assignments: &'static [Assign],
    /// `(key, sensitive)`.
    keys: &'static [(&'static str, bool)],
    project: Option<u8>,
    expect: Expect,
}

const ORDER: &str = "gql:orders:Query.order";
const CANCEL: &str = "gql:orders:Mutation.cancelOrder";
const LIST: &str = "rest:orders:GET /api/orders";
const CREATE: &str = "rest:orders:POST /api/orders";
const INTROSPECT: &str = "gql:orders:__introspection";
const INVOICE: &str = "rest:billing:GET /api/invoices";
const IAM_ROLES: &str = "rest:iam:POST /api/roles";
const IAM_CREATE_ROLE: &str = "gql:iam:Mutation.createRole";

const CORPUS: &[Case] = &[
    Case {
        name: "exact key, global assignment",
        roles: &[(1, &[LIST], &[])],
        assignments: &[Assign(1, None, Expiry::Never)],
        keys: &[(LIST, false)],
        project: None,
        expect: Expect::AllowAll,
    },
    Case {
        name: "exact key, global assignment, project given",
        roles: &[(1, &[LIST], &[])],
        assignments: &[Assign(1, None, Expiry::Never)],
        keys: &[(LIST, false)],
        project: Some(7),
        expect: Expect::AllowAll,
    },
    Case {
        name: "method wildcard covers the method",
        roles: &[(1, &["rest:orders:GET *"], &[])],
        assignments: &[Assign(1, None, Expiry::Never)],
        keys: &[(LIST, false)],
        project: None,
        expect: Expect::AllowAll,
    },
    Case {
        name: "method wildcard misses another method",
        roles: &[(1, &["rest:orders:GET *"], &[])],
        assignments: &[Assign(1, None, Expiry::Never)],
        keys: &[(CREATE, false)],
        project: None,
        expect: Expect::Deny(DecisionReason::PermissionMissing, &[CREATE]),
    },
    Case {
        name: "service wildcard covers every REST key of the service",
        roles: &[(1, &["rest:orders:*"], &[])],
        assignments: &[Assign(1, None, Expiry::Never)],
        keys: &[(LIST, false), (CREATE, false)],
        project: None,
        expect: Expect::AllowAll,
    },
    Case {
        name: "service wildcard misses another service",
        roles: &[(1, &["rest:orders:*"], &[])],
        assignments: &[Assign(1, None, Expiry::Never)],
        keys: &[(INVOICE, false)],
        project: None,
        expect: Expect::Deny(DecisionReason::PermissionMissing, &[INVOICE]),
    },
    Case {
        name: "REST wildcard misses GraphQL keys",
        roles: &[(1, &["rest:orders:*"], &[])],
        assignments: &[Assign(1, None, Expiry::Never)],
        keys: &[(ORDER, false)],
        project: None,
        expect: Expect::Deny(DecisionReason::PermissionMissing, &[ORDER]),
    },
    Case {
        name: "type wildcard covers a field of the type",
        roles: &[(1, &["gql:orders:Query.*"], &[])],
        assignments: &[Assign(1, None, Expiry::Never)],
        keys: &[(ORDER, false)],
        project: None,
        expect: Expect::AllowAll,
    },
    Case {
        name: "type wildcard misses another type",
        roles: &[(1, &["gql:orders:Query.*"], &[])],
        assignments: &[Assign(1, None, Expiry::Never)],
        keys: &[(CANCEL, false)],
        project: None,
        expect: Expect::Deny(DecisionReason::PermissionMissing, &[CANCEL]),
    },
    Case {
        name: "type wildcard misses introspection",
        roles: &[(1, &["gql:orders:Query.*"], &[])],
        assignments: &[Assign(1, None, Expiry::Never)],
        keys: &[(INTROSPECT, false)],
        project: None,
        expect: Expect::Deny(DecisionReason::PermissionMissing, &[INTROSPECT]),
    },
    Case {
        name: "GraphQL service wildcard covers introspection",
        roles: &[(1, &["gql:orders:*"], &[])],
        assignments: &[Assign(1, None, Expiry::Never)],
        keys: &[(INTROSPECT, false), (ORDER, false)],
        project: None,
        expect: Expect::AllowAll,
    },
    Case {
        name: "service wildcard never covers a sensitive REST key",
        roles: &[(1, &["rest:orders:*"], &[])],
        assignments: &[Assign(1, None, Expiry::Never)],
        keys: &[(CREATE, true)],
        project: None,
        expect: Expect::Deny(DecisionReason::PermissionMissing, &[CREATE]),
    },
    Case {
        name: "type wildcard never covers a sensitive field",
        roles: &[(1, &["gql:orders:Mutation.*", "gql:orders:*"], &[])],
        assignments: &[Assign(1, None, Expiry::Never)],
        keys: &[(CANCEL, true)],
        project: None,
        expect: Expect::Deny(DecisionReason::PermissionMissing, &[CANCEL]),
    },
    Case {
        name: "exact grant of a sensitive key allows",
        roles: &[(1, &[CANCEL], &[])],
        assignments: &[Assign(1, None, Expiry::Never)],
        keys: &[(CANCEL, true)],
        project: None,
        expect: Expect::AllowAll,
    },
    Case {
        name: "project assignment, matching project",
        roles: &[(1, &[ORDER], &[])],
        assignments: &[Assign(1, Some(1), Expiry::Never)],
        keys: &[(ORDER, false)],
        project: Some(1),
        expect: Expect::AllowIn(&[1]),
    },
    Case {
        name: "project assignment, other project",
        roles: &[(1, &[ORDER], &[])],
        assignments: &[Assign(1, Some(1), Expiry::Never)],
        keys: &[(ORDER, false)],
        project: Some(2),
        expect: Expect::Deny(DecisionReason::ScopeMissing, &[ORDER]),
    },
    Case {
        name: "project assignments, no project: scopes list the projects",
        roles: &[(1, &[ORDER], &[])],
        assignments: &[
            Assign(1, Some(1), Expiry::Never),
            Assign(1, Some(2), Expiry::Never),
        ],
        keys: &[(ORDER, false)],
        project: None,
        expect: Expect::AllowIn(&[1, 2]),
    },
    Case {
        name: "global beside project assignment reports all",
        roles: &[(1, &[ORDER], &[]), (2, &["gql:orders:*"], &[])],
        assignments: &[
            Assign(1, Some(1), Expiry::Never),
            Assign(2, None, Expiry::Never),
        ],
        keys: &[(ORDER, false)],
        project: None,
        expect: Expect::AllowAll,
    },
    Case {
        name: "assignment expired before now",
        roles: &[(1, &[ORDER], &[])],
        assignments: &[Assign(1, None, Expiry::Passed)],
        keys: &[(ORDER, false)],
        project: None,
        expect: Expect::Deny(DecisionReason::PermissionMissing, &[ORDER]),
    },
    Case {
        name: "assignment expiring exactly now",
        roles: &[(1, &[ORDER], &[])],
        assignments: &[Assign(1, None, Expiry::AtNow)],
        keys: &[(ORDER, false)],
        project: None,
        expect: Expect::Deny(DecisionReason::PermissionMissing, &[ORDER]),
    },
    Case {
        name: "assignment expiring later",
        roles: &[(1, &[ORDER], &[])],
        assignments: &[Assign(1, Some(3), Expiry::Later)],
        keys: &[(ORDER, false)],
        project: Some(3),
        expect: Expect::AllowIn(&[3]),
    },
    Case {
        name: "expired global assignment leaves the project one",
        roles: &[(1, &[ORDER], &[])],
        assignments: &[
            Assign(1, None, Expiry::Passed),
            Assign(1, Some(1), Expiry::Never),
        ],
        keys: &[(ORDER, false)],
        project: Some(2),
        expect: Expect::Deny(DecisionReason::ScopeMissing, &[ORDER]),
    },
    Case {
        name: "orphaned exact grant",
        roles: &[(1, &[], &[ORDER])],
        assignments: &[Assign(1, None, Expiry::Never)],
        keys: &[(ORDER, false)],
        project: None,
        expect: Expect::Deny(DecisionReason::PermissionMissing, &[ORDER]),
    },
    Case {
        name: "orphaned wildcard grant",
        roles: &[(1, &[], &["gql:orders:*"])],
        assignments: &[Assign(1, None, Expiry::Never)],
        keys: &[(ORDER, false)],
        project: None,
        expect: Expect::Deny(DecisionReason::PermissionMissing, &[ORDER]),
    },
    Case {
        name: "orphaned grant beside an active one of another role",
        roles: &[(1, &[], &[ORDER]), (2, &[ORDER], &[])],
        assignments: &[
            Assign(1, None, Expiry::Never),
            Assign(2, Some(5), Expiry::Never),
        ],
        keys: &[(ORDER, false)],
        project: None,
        expect: Expect::AllowIn(&[5]),
    },
    Case {
        name: "no assignment",
        roles: &[(1, &[ORDER], &[])],
        assignments: &[],
        keys: &[(ORDER, false)],
        project: None,
        expect: Expect::Deny(DecisionReason::PermissionMissing, &[ORDER]),
    },
    Case {
        name: "assignment of an unknown role",
        roles: &[],
        assignments: &[Assign(9, None, Expiry::Never)],
        keys: &[(ORDER, false)],
        project: None,
        expect: Expect::Deny(DecisionReason::PermissionMissing, &[ORDER]),
    },
    Case {
        name: "several keys, one missing",
        roles: &[(1, &[ORDER], &[])],
        assignments: &[Assign(1, None, Expiry::Never)],
        keys: &[(ORDER, false), (CANCEL, false)],
        project: None,
        expect: Expect::Deny(DecisionReason::PermissionMissing, &[CANCEL]),
    },
    Case {
        name: "several keys held in disjoint projects",
        roles: &[(1, &[ORDER], &[]), (2, &[CANCEL], &[])],
        assignments: &[
            Assign(1, Some(1), Expiry::Never),
            Assign(2, Some(2), Expiry::Never),
        ],
        keys: &[(ORDER, false), (CANCEL, false)],
        project: None,
        expect: Expect::Deny(DecisionReason::ScopeMissing, &[ORDER, CANCEL]),
    },
    Case {
        name: "several keys held together in one project",
        roles: &[(1, &[ORDER], &[]), (2, &[CANCEL], &[])],
        assignments: &[
            Assign(1, Some(1), Expiry::Never),
            Assign(1, Some(2), Expiry::Never),
            Assign(2, Some(2), Expiry::Never),
        ],
        keys: &[(ORDER, false), (CANCEL, false)],
        project: None,
        expect: Expect::AllowIn(&[2]),
    },
    Case {
        name: "several keys, project lacks one",
        roles: &[(1, &[ORDER], &[]), (2, &[CANCEL], &[])],
        assignments: &[
            Assign(1, None, Expiry::Never),
            Assign(2, Some(2), Expiry::Never),
        ],
        keys: &[(ORDER, false), (CANCEL, false)],
        project: Some(1),
        expect: Expect::Deny(DecisionReason::ScopeMissing, &[CANCEL]),
    },
    Case {
        name: "reserved wildcard-like key covers its family",
        roles: &[(1, &["iam:grant:*"], &[])],
        assignments: &[Assign(1, None, Expiry::Never)],
        keys: &[("iam:grant:orders", true)],
        project: None,
        expect: Expect::AllowAll,
    },
    Case {
        name: "reserved key misses another family",
        roles: &[(1, &["iam:grant:*"], &[])],
        assignments: &[Assign(1, None, Expiry::Never)],
        keys: &[("iam:grant:sensitive", true)],
        project: None,
        expect: Expect::Deny(DecisionReason::PermissionMissing, &["iam:grant:sensitive"]),
    },
    Case {
        name: "a project assignment never holds a reserved key",
        roles: &[(1, &["iam:grant:*"], &[])],
        assignments: &[Assign(1, Some(1), Expiry::Never)],
        keys: &[("iam:grant:orders", true)],
        project: None,
        expect: Expect::Deny(DecisionReason::PermissionMissing, &["iam:grant:orders"]),
    },
    Case {
        name: "a project assignment never holds an iam catalogue key",
        roles: &[(1, &[IAM_ROLES], &[])],
        assignments: &[Assign(1, Some(1), Expiry::Never)],
        keys: &[(IAM_ROLES, false)],
        project: Some(1),
        expect: Expect::Deny(DecisionReason::PermissionMissing, &[IAM_ROLES]),
    },
    Case {
        name: "a project assignment never holds an iam catalogue key without a project",
        roles: &[(1, &["rest:iam:*"], &[])],
        assignments: &[Assign(1, Some(1), Expiry::Never)],
        keys: &[(IAM_ROLES, false)],
        project: None,
        expect: Expect::Deny(DecisionReason::PermissionMissing, &[IAM_ROLES]),
    },
    Case {
        name: "a global assignment holds an iam catalogue key",
        roles: &[(1, &[IAM_ROLES], &[])],
        assignments: &[Assign(1, None, Expiry::Never)],
        keys: &[(IAM_ROLES, false)],
        project: Some(1),
        expect: Expect::AllowAll,
    },
    Case {
        name: "a global assignment holds an iam graphql key beside a project one",
        roles: &[(1, &["gql:iam:*"], &[])],
        assignments: &[
            Assign(1, Some(1), Expiry::Never),
            Assign(1, None, Expiry::Never),
        ],
        keys: &[(IAM_CREATE_ROLE, false)],
        project: Some(2),
        expect: Expect::AllowAll,
    },
    Case {
        name: "no wildcard covers a reserved key",
        roles: &[(1, &["gql:iam:*", "rest:iam:*"], &[])],
        assignments: &[Assign(1, None, Expiry::Never)],
        keys: &[("iam:audit:read", false)],
        project: None,
        expect: Expect::Deny(DecisionReason::PermissionMissing, &["iam:audit:read"]),
    },
];

fn assignment(case_assignment: Assign) -> RoleAssignment {
    let Assign(role_number, project_number, expiry) = case_assignment;
    let scope = project_number.map_or(AssignmentScope::Global, |number| {
        AssignmentScope::Project(project(number))
    });
    let expires_at = match expiry {
        Expiry::Never => None,
        Expiry::Passed => Some(at(NOW - 60)),
        Expiry::AtNow => Some(at(NOW)),
        Expiry::Later => Some(at(NOW + 60)),
    };
    RoleAssignment::new(role(role_number), scope, expires_at)
}

fn expected(expect: Expect) -> DecisionVerdict {
    match expect {
        Expect::AllowAll => DecisionVerdict::allow(ScopeSet::All),
        Expect::AllowIn(numbers) => DecisionVerdict::allow(projects(numbers)),
        Expect::Deny(reason, denied) => {
            DecisionVerdict::deny(reason, denied.iter().map(|key| (*key).to_owned()).collect())
        }
    }
}

fn run(case: &Case) -> DecisionVerdict {
    let roles = role_sets(case.roles);
    let assignments: Vec<RoleAssignment> =
        case.assignments.iter().copied().map(assignment).collect();
    let keys: Vec<RequiredKey> = case
        .keys
        .iter()
        .map(|(key, is_sensitive)| {
            if *is_sensitive {
                sensitive(key)
            } else {
                required(key)
            }
        })
        .collect();
    decide(&assignments, &roles, &keys, case.project.map(project))
}

#[test]
fn the_corpus_has_zero_false_allows_and_zero_false_denies() {
    let mut false_allows = Vec::new();
    let mut false_denies = Vec::new();
    let mut wrong_details = Vec::new();
    for case in CORPUS {
        let actual = run(case);
        let expected = expected(case.expect);
        match (actual.decision().is_allow(), expected.decision().is_allow()) {
            (true, false) => false_allows.push(case.name),
            (false, true) => false_denies.push(case.name),
            _ if actual != expected => wrong_details.push((case.name, actual)),
            _ => {}
        }
    }

    assert_eq!(false_allows, Vec::<&str>::new(), "false allows");
    assert_eq!(false_denies, Vec::<&str>::new(), "false denies");
    assert_eq!(
        wrong_details,
        Vec::new(),
        "wrong reason, denied list or scopes"
    );
}

#[test]
fn the_corpus_covers_every_reason_the_rule_produces() {
    let reasons: Vec<DecisionReason> = CORPUS
        .iter()
        .map(|case| expected(case.expect).reason())
        .collect();

    for reason in [
        DecisionReason::Allowed,
        DecisionReason::PermissionMissing,
        DecisionReason::ScopeMissing,
    ] {
        assert!(reasons.contains(&reason), "{reason}");
    }
}
