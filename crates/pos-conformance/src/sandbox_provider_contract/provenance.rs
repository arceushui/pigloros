use ed25519_dalek::VerifyingKey;

use super::{AdmissionGrantV1, SandboxContractErrorV1, SandboxProviderReceiptV1};
use crate::CaseOutcomeV1;

impl SandboxProviderReceiptV1 {
    /// Verify that this signed receipt is the exact provenance of one CNR1 case.
    ///
    /// The caller supplies the authenticated EVR1 identity. This method then
    /// verifies both signed provider records and the complete AGR1-to-SPR1-to-
    /// `CaseOutcomeV1` authority chain. Runtime acquisition of these records is
    /// owned by the trusted selector integration in Redmine #213.
    ///
    /// # Errors
    /// Returns a closed contract error when either signature is invalid or any
    /// request, attempt, authority, epoch, key, case, or provenance binding
    /// differs.
    pub fn verify_case_provenance(
        &self,
        grant: &AdmissionGrantV1,
        case: &CaseOutcomeV1,
        request_id: [u8; 16],
        evr1_digest: [u8; 32],
        key: &VerifyingKey,
    ) -> Result<(), SandboxContractErrorV1> {
        grant.verify_signature(key)?;
        self.verify_signature(key)?;

        let grant_authority = &grant.authority;
        let receipt_authority = &self.authority;
        let consistent = grant.request_id == request_id
            && grant.attempt_id == self.attempt_id
            && grant_authority.evr1_digest == evr1_digest
            && grant_authority.fixture_digest == case.fixture_digest
            && grant_authority.execution_profile_digest == case.execution_profile_digest
            && receipt_authority.agr1_digest == grant.grant_digest
            && receipt_authority.spm1_digest == grant_authority.spm1_digest
            && receipt_authority.lps1_digest == grant_authority.lps1_digest
            && receipt_authority.sim1_digest == grant_authority.sim1_digest
            && receipt_authority.apt1_digest == grant_authority.apt1_digest
            && receipt_authority.trs1_digest == grant_authority.trs1_digest
            && receipt_authority.rvs1_digest == grant_authority.rvs1_digest
            && self.trust_epoch == grant.trust_epoch
            && self.revocation_epoch == grant.revocation_epoch
            && self.policy_epoch == grant.policy_epoch
            && self.hcp1_digest == grant_authority.hcp1_digest
            && self.elm1_digest == grant.elm1_digest
            && self.runtime_attestation_key_id == grant.runtime_attestation_key_id
            && case.provenance_digest == self.receipt_digest;
        consistent
            .then_some(())
            .ok_or(SandboxContractErrorV1::InconsistentFields)
    }
}
