//! Verifies the security audit hash chain and audits the verification (FR-52).

use std::sync::Arc;

use iam_domain::{
    ActorRef, AuditChainHead, AuditSummary, ChainVerdict, ChainVerification, SecurityAuditLog,
};
use shared_domain::{Clock, Query, QueryHandler, UuidGenerator};

use crate::error::IamError;
use crate::security_audit_reads::{ReadAudit, ReadRecord};

/// The largest number of anchors that one verification accepts.
pub const MAX_ANCHORS: usize = 100;

/// The audited action of a verification.
pub const AUDIT_ACTION: &str = "security_audit.verify";

/// The target id of the record of a verification, which reads no single record.
const CHAIN_TARGET_ID: &str = "chain";

/// Asks whether the audit chain verifies, optionally against external anchors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifySecurityAuditChainQuery {
    /// Who asks; the verification is recorded in the log under this actor.
    pub actor: ActorRef,
    /// The `{seq, hash}` values published as `iam.security_audit.anchored`, if the caller has any.
    pub anchors: Vec<AuditChainHead>,
}

impl Query for VerifySecurityAuditChainQuery {
    type Output = ChainVerification;
    type Error = IamError;
    const NAME: &'static str = "VerifySecurityAuditChainQuery";
}

/// Handles [`VerifySecurityAuditChainQuery`].
///
/// The record of the verification is appended once the chain is verified, so that a verification
/// that cannot be audited is not served and a verification never checks its own record.
#[derive(Debug)]
pub struct VerifySecurityAuditChainQueryHandler {
    log: Arc<dyn SecurityAuditLog>,
    audit: ReadAudit,
}

impl VerifySecurityAuditChainQueryHandler {
    /// A handler over the audit log, with the `Clock` and `UuidGenerator` ports that stamp the
    /// record of the verification.
    #[must_use]
    pub fn new(
        log: Arc<dyn SecurityAuditLog>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn UuidGenerator>,
    ) -> Self {
        let audit = ReadAudit::new(Arc::clone(&log), clock, ids);
        Self { log, audit }
    }

    async fn verify(
        &self,
        query: VerifySecurityAuditChainQuery,
    ) -> Result<ChainVerification, IamError> {
        let verification = self.log.verify_chain(&query.anchors).await?;
        self.audit
            .record(ReadRecord {
                actor: &query.actor,
                action: AUDIT_ACTION,
                target_id: CHAIN_TARGET_ID,
                summary: summary(query.anchors.len(), &verification)?,
            })
            .await?;
        Ok(verification)
    }
}

/// The summary of a verification: how many anchors it used, how many records it checked and its
/// verdict.
fn summary(anchors: usize, verification: &ChainVerification) -> Result<AuditSummary, IamError> {
    let checked = verification.records_checked();
    let text = match verification.verdict() {
        ChainVerdict::Valid => format!("anchors={anchors};checked={checked};result=valid"),
        ChainVerdict::Invalid(broken) => format!(
            "anchors={anchors};checked={checked};result=invalid;seq={};cause={}",
            broken.seq(),
            broken.cause().as_str()
        ),
    };
    Ok(AuditSummary::new(&text)?)
}

#[async_trait::async_trait]
impl QueryHandler<VerifySecurityAuditChainQuery> for VerifySecurityAuditChainQueryHandler {
    async fn handle(
        &self,
        query: VerifySecurityAuditChainQuery,
    ) -> Result<ChainVerification, IamError> {
        self.verify(query).await
    }
}

#[cfg(test)]
mod tests;
