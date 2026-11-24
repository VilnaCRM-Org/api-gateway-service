//! The statements and guards that a change runs inside its transaction.

use crate::bulk_operation::statement::BulkProgressStatement;
use crate::catalogue_statement::CatalogueStatement;
use crate::gateway_statement::GatewayStatement;
use crate::graphql_spec::statement::GraphQlSpecStatement;
use crate::openapi_spec::statement::OpenApiSpecStatement;
use crate::resync::{EpochChange, Republication, ResyncStart};
use crate::role::statement::RoleStatement;
use crate::state::key::StateKey;
use crate::user_role::statement::UserRoleStatement;
use crate::value_object::policy_version::PolicyVersion;
use crate::value_object::service_name::ServiceName;

/// One aggregate statement or guard of a change, described for the unit of work to execute.
///
/// The unit of work runs it inside the transaction, after it has locked the policy version and
/// before it writes the outbox, the audit record, the change receipt and the idempotency record.
///
/// The aggregate stories add one variant per aggregate write (an insert, or an update with
/// `WHERE version = $expected`); a failing statement rolls the whole change back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeStatement {
    /// Refuse the change with a conflict when the policy version locked by the transaction differs
    /// from the version the change was decided against.
    ExpectPolicyVersion(PolicyVersion),
    /// Insert a new role, or update a stored role at the expected version; a duplicate name or id
    /// refuses the change as a duplicate and a stale or deleted stored role as a conflict.
    SaveRole(Box<RoleStatement>),
    /// Insert a new assignment, or update a stored assignment at the expected version.
    ///
    /// A duplicate id, or an assignment that is not revoked with the same subject, role and scope,
    /// refuses the change as a duplicate; a stale or revoked stored assignment refuses it as a
    /// conflict.
    SaveUserRole(Box<UserRoleStatement>),
    /// Insert a new specification version with its SDL; a duplicate id, or a version of the same
    /// service with the same content hash, refuses the change as a duplicate.
    SaveGraphQlSpec(Box<GraphQlSpecStatement>),
    /// Insert a new `OpenAPI` specification version with its document; a duplicate id, or a version
    /// of the same service with the same content hash, refuses the change as a duplicate.
    SaveOpenApiSpec(Box<OpenApiSpecStatement>),
    /// Activate or retire a specification version: move its status, create and update the
    /// catalogue entries, set `orphaned_at` on the grants that lose their key, apply the renames
    /// and take the next catalogue epoch; a version that is no longer in the expected status
    /// refuses the change as a conflict.
    ApplyCatalogue(Box<CatalogueStatement>),
    /// Insert a new upstream, route or rate policy, or update a stored one at the expected version;
    /// a duplicate id or name refuses the change as a duplicate, and a stale or deleted stored
    /// record or a missing upstream or rate policy of a route as a conflict.
    SaveGateway(Box<GatewayStatement>),
    /// Store the progress of a bulk operation after a committed chunk; stored progress that differs
    /// from the expected applied records refuses the change as a conflict.
    SaveBulkProgress(Box<BulkProgressStatement>),
    /// Start a resync: the stored log epoch must be the one the statement names, which becomes the
    /// next one, the policy version rises to the floor of the statement before the transaction
    /// takes the next version, and the pending bulk operation is stored; a stored log epoch that
    /// differs refuses the change as a conflict and a known operation as a duplicate.
    StartResync(Box<ResyncStart>),
    /// Publish the unchanged state of the named entities and catalogues again under the version of
    /// the change; no entity changes and the digest stays.
    RepublishState(Box<Republication>),
}

impl ChangeStatement {
    /// Whether the statement holds under `locked`, the policy version that the transaction locked
    /// before any increment. An aggregate write holds here: the storage checks it when it runs.
    #[must_use]
    pub fn holds(&self, locked: PolicyVersion) -> bool {
        match self {
            Self::ExpectPolicyVersion(expected) => *expected == locked,
            Self::SaveRole(_)
            | Self::SaveUserRole(_)
            | Self::SaveGraphQlSpec(_)
            | Self::SaveOpenApiSpec(_)
            | Self::ApplyCatalogue(_)
            | Self::SaveGateway(_)
            | Self::SaveBulkProgress(_)
            | Self::StartResync(_)
            | Self::RepublishState(_) => true,
        }
    }

    /// The keys of the state records that the statement changes directly: the role of a role write,
    /// the subject of an assignment write, the record of a gateway configuration write, and the
    /// roles whose grants an activation orphans or moves. The catalogue records of an activation are named by [`Self::catalogue_service`].
    #[must_use]
    pub fn state_keys(&self) -> Vec<StateKey> {
        match self {
            Self::ExpectPolicyVersion(_)
            | Self::SaveGraphQlSpec(_)
            | Self::SaveOpenApiSpec(_)
            | Self::SaveBulkProgress(_)
            | Self::StartResync(_) => Vec::new(),
            Self::RepublishState(republication) => republication.keys().to_vec(),
            Self::SaveRole(statement) => vec![StateKey::Role(statement.role().id)],
            Self::SaveUserRole(statement) => {
                vec![StateKey::Subject(statement.user_role().subject.clone())]
            }
            Self::SaveGateway(statement) => vec![statement.state_key()],
            Self::ApplyCatalogue(statement) => {
                let parts = statement.parts();
                parts
                    .orphaned
                    .iter()
                    .map(|grant| grant.role)
                    .chain(
                        parts
                            .renames
                            .iter()
                            .flat_map(|rename| rename.roles.iter().copied()),
                    )
                    .map(StateKey::Role)
                    .collect()
            }
        }
    }

    /// The service whose catalogue records the statement changes, when it is an activation or a
    /// retirement.
    #[must_use]
    pub fn catalogue_service(&self) -> Option<&ServiceName> {
        match self {
            Self::ApplyCatalogue(statement) => Some(&statement.parts().service),
            Self::ExpectPolicyVersion(_)
            | Self::SaveRole(_)
            | Self::SaveUserRole(_)
            | Self::SaveGraphQlSpec(_)
            | Self::SaveOpenApiSpec(_)
            | Self::SaveGateway(_)
            | Self::SaveBulkProgress(_)
            | Self::StartResync(_)
            | Self::RepublishState(_) => None,
        }
    }

    /// The services whose catalogue records the statement writes again without changing them.
    #[must_use]
    pub fn republished_services(&self) -> &[ServiceName] {
        match self {
            Self::RepublishState(republication) => republication.services(),
            Self::ExpectPolicyVersion(_)
            | Self::SaveRole(_)
            | Self::SaveUserRole(_)
            | Self::SaveGraphQlSpec(_)
            | Self::SaveOpenApiSpec(_)
            | Self::ApplyCatalogue(_)
            | Self::SaveGateway(_)
            | Self::SaveBulkProgress(_)
            | Self::StartResync(_) => &[],
        }
    }

    /// The log epoch change the statement makes, when it starts a new log epoch.
    #[must_use]
    pub fn epoch_change(&self) -> Option<&EpochChange> {
        match self {
            Self::StartResync(start) => Some(start.epoch()),
            Self::ExpectPolicyVersion(_)
            | Self::SaveRole(_)
            | Self::SaveUserRole(_)
            | Self::SaveGraphQlSpec(_)
            | Self::SaveOpenApiSpec(_)
            | Self::ApplyCatalogue(_)
            | Self::SaveGateway(_)
            | Self::SaveBulkProgress(_)
            | Self::RepublishState(_) => None,
        }
    }

    /// The keys of the entities the statement writes again without changing them.
    #[must_use]
    pub fn republished_keys(&self) -> &[StateKey] {
        if let Self::RepublishState(republication) = self {
            republication.keys()
        } else {
            &[]
        }
    }
}

#[cfg(test)]
mod tests;
