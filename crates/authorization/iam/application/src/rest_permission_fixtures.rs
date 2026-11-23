//! Values and doubles that the tests of the REST catalogue read operations of the REST and
//! GraphQL adapters share.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;

use iam_domain::{
    PermissionFlags, PermissionId, PermissionKey, RestPermissionParts, RoleId, SpecId,
};
use shared_domain::{CommandBus, QueryBus};
use test_support::bus::{FakeCommandBus, FakeQueryBus};
use test_support::clock::FixedClock;
use test_support::id::SequenceUuidGenerator;
use test_support::request_digester::FakeRequestDigester;

use crate::error::IamError;
use crate::http::IamState;
use crate::query::get_rest_permission::GetRestPermissionQuery;
use crate::query::get_rest_permissions::{
    GetRestPermissionsQuery, RestPermissionPage, RestPermissionView,
};

/// The entry that every answer names.
pub(crate) const PERMISSION: &str = "0190f2a8-7b3c-7d4e-8f12-1234567890ad";
/// The version that contains the key of the entry.
pub(crate) const VERSION: &str = "0190f2a8-7b3c-7d4e-8f10-1234567890ad";
/// The role that grants the key of the entry.
pub(crate) const ROLE: &str = "0190f2a8-7b3c-7d4e-8f11-1234567890ad";

/// A bus error that a test builds when it needs it.
pub(crate) type Refusal = fn() -> IamError;

/// The active, sensitive entry of `POST /api/invoices/{}/pay` of `billing`, in one version and one role.
pub(crate) fn view() -> RestPermissionView {
    view_of("rest:billing:POST /api/invoices/{}/pay")
}

/// The same entry for the key `key`.
pub(crate) fn view_of(key: &str) -> RestPermissionView {
    RestPermissionView {
        permission: RestPermissionParts {
            id: PermissionId::parse(PERMISSION).unwrap(),
            key: PermissionKey::parse(key).unwrap(),
            flags: PermissionFlags::NONE.with_sensitive(),
            active: true,
        },
        versions: vec![SpecId::parse(VERSION).unwrap()],
        roles: vec![RoleId::parse(ROLE).unwrap()],
    }
}

/// What the doubles answer.
pub(crate) struct Answers {
    /// The answer of the list query.
    pub page: Result<RestPermissionPage, Refusal>,
    /// The answer of the query of one entry.
    pub one: Result<Option<RestPermissionView>, Refusal>,
}

impl Default for Answers {
    fn default() -> Self {
        Self {
            page: Ok(RestPermissionPage {
                permissions: vec![view()],
                next_after: Some(PermissionId::parse(PERMISSION).unwrap()),
            }),
            one: Ok(Some(view())),
        }
    }
}

/// What the doubles were asked.
#[derive(Debug, Default)]
pub(crate) struct Asked {
    /// The list queries.
    pub pages: Arc<Mutex<Vec<GetRestPermissionsQuery>>>,
    /// The queries of one entry.
    pub ones: Arc<Mutex<Vec<GetRestPermissionQuery>>>,
}

/// The values a double recorded, in order.
pub(crate) fn recorded<T: Clone>(log: &Arc<Mutex<Vec<T>>>) -> Vec<T> {
    log.lock().unwrap_or_else(PoisonError::into_inner).clone()
}

fn record<T>(log: &Arc<Mutex<Vec<T>>>, value: T) {
    log.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(value);
}

/// The state over doubles that answer the read queries as `answers` say and record what they were
/// asked.
pub(crate) fn scenario(answers: Answers) -> (IamState, Asked) {
    let asked = Asked::default();
    let Answers { page, one } = answers;
    let pages = Arc::clone(&asked.pages);
    let ones = Arc::clone(&asked.ones);
    let query_bus: Arc<dyn QueryBus> = Arc::new(
        FakeQueryBus::answering(move |query: GetRestPermissionsQuery| {
            record(&pages, query);
            page.clone().map_err(|refusal| refusal())
        })
        .and_answering(move |query: GetRestPermissionQuery| {
            record(&ones, query);
            one.clone().map_err(|refusal| refusal())
        }),
    );
    let command_bus: Arc<dyn CommandBus> = Arc::new(FakeCommandBus::unregistered());
    let state = IamState {
        command_bus,
        query_bus,
        uuid_generator: Arc::new(SequenceUuidGenerator::starting_at(1)),
        clock: Arc::new(FixedClock::at(SystemTime::UNIX_EPOCH)),
        request_digester: Arc::new(FakeRequestDigester),
    };
    (state, asked)
}
