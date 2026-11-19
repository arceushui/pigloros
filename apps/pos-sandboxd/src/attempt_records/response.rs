//! The signed terminal response of one ended attempt (ADR-069 §4; R9 §4.7
//! steps 7 to 9 and §5).
//!
//! [`EndedAttempt::signed_response`] signs, once and only from the
//! attempt's own records, the SAU1 chain, then SPR1, then SPY1, each through
//! [`sign_verified`], so no signature leaves the provider before it verified
//! under the admitted runtime key. The chain is:
//!
//! * `11 LauncherReady` = `[agr1, ready1, koe1]` once a `ReadyV1` was
//!   accepted, then `12 ExecutionReleased` = `[agr1, ready1, rls1, koe1]`
//!   if `ReleaseV1` was sent, else `13 ExecutionReleaseDenied`;
//! * the terminal event `[agr1, elm1, tme1]`, whose code is TME1's, unless
//!   the attempt Completed.
//!
//! [`RetainedResponse`] keeps the exact bytes: AGR1, the chain, SPR1, SPY1
//! and the `ReleaseV1` sent, with the RQE1, KOE1 and TME1 they bind. The
//! output bytes stay fenced in the attempt's capture. When the output
//! transfer of a Completed response times out,
//! [`RetainedResponse::successor`] re-issues it once (R9 §4.7): a successor
//! TME1, SAU1 event 10 appended to the chain, and a new SPR1 and SPY1.

use pos_reference::sandbox_provider_protocol::{
    AdmissionGrant, AttemptResponse, ExecutionRelease, PayloadDescriptor, ReceiptAuthority,
    RuntimeSigned, SandboxAuditRecord, SandboxAuditRecordFields, SandboxProviderProtocolError,
    SandboxProviderReceipt, SandboxProviderReceiptFields, SandboxProviderResult,
    SandboxProviderResultFields, SandboxTerminalOutcome, SelfDigested, TransferRecord, Verified,
};

use super::{AttemptRecords, EvidenceFault};
use crate::{
    sign_verified, AdmittedRuntimeKey, AttemptProgress, EndedAttempt, IssuedGrant,
    RequestedConfiguration, RuntimeAttestationSigner, RuntimeSignerError,
};

/// SAU1 lifecycle event codes (ADR-069 §10).
const LAUNCHER_READY: u8 = 11;
const EXECUTION_RELEASED: u8 = 12;
const EXECUTION_RELEASE_DENIED: u8 = 13;

/// The complete signed response of one ended attempt, as it is retained
/// until the attempt is reconciled.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedResponse {
    grant: IssuedGrant,
    records: AttemptRecords,
    sent: Sent,
    chain: Vec<SandboxAuditRecord>,
    encoded: Encoded,
}

impl RetainedResponse {
    /// The self-digest of the AGR1 the response answers.
    #[must_use]
    pub const fn agr1_digest(&self) -> [u8; 32] {
        self.grant.digest()
    }

    /// The RQE1, KOE1 and TME1 the response binds, with TME1's
    /// classification.
    #[must_use]
    pub const fn records(&self) -> &AttemptRecords {
        &self.records
    }

    /// The exact AGR1, SAU1 chain, SPR1, SPY1 and `ReleaseV1` bytes.
    #[must_use]
    pub fn response(&self) -> AttemptResponse<'_> {
        let (audit, receipt, result, release) = &self.encoded;
        AttemptResponse {
            grant: self.grant.bytes(),
            audit,
            receipt,
            result,
            release: release.as_deref(),
        }
    }

    /// Re-issue this Completed response once its output transfer timed out
    /// (R9 §4.7): the successor TME1 records `transfer`, which is
    /// incomplete, and SAU1 event 10, SPR1 and SPY1 follow it. The earlier
    /// records stay in the chain.
    ///
    /// # Errors
    /// [`ResponseFault::Evidence`] when this response cannot be re-issued
    /// ([`EvidenceFault::NotReissuable`]) or the successor is refused, and
    /// [`ResponseFault::Sign`] when a record is refused or a signature does
    /// not verify under `admitted`.
    pub fn successor<R: RuntimeAttestationSigner>(
        &self,
        transfer: TransferRecord,
        signer: &R,
        admitted: AdmittedRuntimeKey<'_>,
    ) -> Result<Self, ResponseFault> {
        let records = self.records.successor(transfer)?;
        Ok(assemble(
            signer,
            admitted,
            &self.grant,
            records,
            self.sent.clone(),
            self.chain.clone(),
        )?)
    }
}

/// Why no signed response exists for an ended attempt.
///
/// Each is a provider fault: nothing is emitted, the lifecycle is
/// quarantined, and restart reconciliation (SIR1) recovers (R9 §5; owner
/// reading G2, Redmine #443 journal 22723).
#[derive(Debug, thiserror::Error)]
pub enum ResponseFault {
    /// The attempt's records could not be assembled.
    #[error(transparent)]
    Evidence(#[from] EvidenceFault),
    /// A record could not be signed, or its signature did not verify under
    /// the admitted key.
    #[error(transparent)]
    Sign(#[from] RuntimeSignerError),
}

/// What the attempt sent that the signed records name.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Sent {
    release: Option<ExecutionRelease>,
    transcripts: Vec<[u8; 32]>,
    output: Option<PayloadDescriptor>,
}

impl Sent {
    /// The `ReleaseV1` sent, the network transcripts and the output
    /// descriptor of an executed attempt; only the `ReleaseV1` of a failed
    /// one.
    fn of<S>(progress: &AttemptProgress<S>) -> Self {
        match progress {
            AttemptProgress::Executed {
                evidence,
                network,
                adapter,
                ..
            } => Self {
                release: evidence.release().release().cloned(),
                transcripts: network.transcript_digests(),
                output: Some(adapter.output().descriptor()),
            },
            AttemptProgress::Failed {
                evidence: Some(evidence),
                ..
            } => Self {
                release: evidence.release().release().cloned(),
                ..Self::default()
            },
            _ => Self::default(),
        }
    }

    fn release_digest(&self) -> Option<[u8; 32]> {
        self.release.as_ref().map(ExecutionRelease::digest)
    }
}

/// Sign `record` and return the record `new` builds from the verified
/// signature under the admitted key.
fn signed<R, M, T>(
    signer: &R,
    admitted: AdmittedRuntimeKey<'_>,
    record: Result<SelfDigested<M>, SandboxProviderProtocolError>,
    new: fn(Verified<M>, &ed25519_dalek::VerifyingKey) -> Result<T, SandboxProviderProtocolError>,
) -> Result<T, RuntimeSignerError>
where
    R: RuntimeAttestationSigner,
    M: RuntimeSigned,
{
    record
        .map_err(RuntimeSignerError::from)
        .and_then(|record| sign_verified(signer, admitted, record))
        .and_then(|verified| new(verified, admitted.key()).map_err(Into::into))
}

/// The SAU1 events of the attempt, in order, with their authority digests.
fn events(
    records: &AttemptRecords,
    grant: &AdmissionGrant,
    release: Option<[u8; 32]>,
) -> Vec<(u8, Vec<[u8; 32]>)> {
    let agr1 = grant.grant_digest();
    let koe1 = records.observed().digest();
    let lifecycle = records
        .observed()
        .fields()
        .status
        .ready1_digest()
        .map(|ready| {
            let released = release.map_or_else(
                || (EXECUTION_RELEASE_DENIED, vec![agr1, ready, koe1]),
                |rls1| (EXECUTION_RELEASED, vec![agr1, ready, rls1, koe1]),
            );
            [(LAUNCHER_READY, vec![agr1, ready, koe1]), released]
        });
    lifecycle
        .into_iter()
        .flatten()
        .chain(terminal_event(records, grant))
        .collect()
}

/// The terminal SAU1 event `[agr1, elm1, tme1]`, unless TME1 Completed.
fn terminal_event(records: &AttemptRecords, grant: &AdmissionGrant) -> Option<(u8, Vec<[u8; 32]>)> {
    records.classification().code().map(|code| {
        (
            code.code(),
            vec![
                grant.grant_digest(),
                grant.elm1_digest,
                records.termination().digest(),
            ],
        )
    })
}

/// Sign `events` onto the SAU1 chain `prefix`, each linked to the one
/// before.
fn chain<R: RuntimeAttestationSigner>(
    signer: &R,
    admitted: AdmittedRuntimeKey<'_>,
    attempt_id: [u8; 16],
    mut chain: Vec<SandboxAuditRecord>,
    events: Vec<(u8, Vec<[u8; 32]>)>,
) -> Result<Vec<SandboxAuditRecord>, RuntimeSignerError> {
    let first = u64::try_from(chain.len()).unwrap_or(u64::MAX);
    for ((event_code, authority_digests), sequence) in events.into_iter().zip(first..) {
        let fields = SandboxAuditRecordFields {
            attempt_id,
            sequence,
            event_code,
            authority_digests,
            previous_digest: chain.last().map(|previous| previous.record_digest),
            runtime_attestation_key_id: admitted.key_id().to_owned(),
        };
        chain.push(signed(
            signer,
            admitted,
            SandboxAuditRecord::self_digested(fields),
            SandboxAuditRecord::new,
        )?);
    }
    Ok(chain)
}

/// SPR1's authority: AGR1's, with the admitted provider binary digest.
fn receipt_authority(grant: &AdmissionGrant, issued: &IssuedGrant) -> ReceiptAuthority {
    let admitted = &grant.authority;
    ReceiptAuthority {
        agr1_digest: grant.grant_digest(),
        spm1_digest: admitted.spm1_digest,
        provider_binary_digest: issued.provider_binary_digest(),
        lps1_digest: admitted.lps1_digest,
        sim1_digest: admitted.sim1_digest,
        apt1_digest: admitted.apt1_digest,
        trs1_digest: admitted.trs1_digest,
        rvs1_digest: admitted.rvs1_digest,
    }
}

/// The SPR1 body: the grant's authority and epochs, the evidence digests
/// (ordinals 19 to 22) and the final SAU1 (R9 §4.7 step 8).
fn receipt_fields(
    grant: &AdmissionGrant,
    issued: &IssuedGrant,
    records: &AttemptRecords,
    sent: &Sent,
    sau1_digest: [u8; 32],
) -> SandboxProviderReceiptFields {
    SandboxProviderReceiptFields {
        attempt_id: grant.attempt_id,
        authority: receipt_authority(grant, issued),
        trust_epoch: grant.trust_epoch,
        revocation_epoch: grant.revocation_epoch,
        policy_epoch: grant.policy_epoch,
        hcp1_digest: grant.authority.hcp1_digest,
        elm1_digest: grant.elm1_digest,
        network_transcript_digests: sent.transcripts.clone(),
        ready1_digest: records.observed().fields().status.ready1_digest(),
        release1_digest: sent.release_digest(),
        requested_configuration_evidence: records.requested().digest(),
        kernel_observation_evidence: records.observed().digest(),
        negative_probe_evidence: issued.negative_probe_evidence(),
        termination_evidence: records.termination().digest(),
        sau1_digest,
        runtime_attestation_key_id: grant.runtime_attestation_key_id.clone(),
    }
}

/// The SPY1 body: TME1's outcome, the output descriptor only when
/// Completed, and the chain's event codes (R9 §6 rule 8).
fn result_fields(
    grant: &AdmissionGrant,
    records: &AttemptRecords,
    output: Option<PayloadDescriptor>,
    receipt: &SandboxProviderReceipt,
    chain: &[SandboxAuditRecord],
) -> SandboxProviderResultFields {
    let outcome = records.classification().outcome();
    SandboxProviderResultFields {
        request_id: grant.request_id,
        attempt_id: grant.attempt_id,
        outcome,
        output: output.filter(|_| outcome == SandboxTerminalOutcome::Completed),
        agr1_digest: Some(grant.grant_digest()),
        spr1_digest: Some(receipt.receipt_digest()),
        operational_events: chain.iter().map(|record| record.event_code).collect(),
        runtime_attestation_key_id: grant.runtime_attestation_key_id.clone(),
    }
}

/// The exact bytes of a signed response: the SAU1 chain, SPR1, SPY1 and
/// the `ReleaseV1` sent.
type Encoded = (Vec<Vec<u8>>, Vec<u8>, Vec<u8>, Option<Vec<u8>>);

/// Encode the signed records.
fn encoded(
    chain: &[SandboxAuditRecord],
    receipt: &SandboxProviderReceipt,
    result: &SandboxProviderResult,
    release: Option<&ExecutionRelease>,
) -> Result<Encoded, SandboxProviderProtocolError> {
    chain
        .iter()
        .map(SandboxAuditRecord::to_canonical_cbor)
        .collect::<Result<Vec<_>, _>>()
        .and_then(|audit| receipt.to_canonical_cbor().map(|bytes| (audit, bytes)))
        .and_then(|(audit, receipt)| {
            result
                .to_canonical_cbor()
                .map(|bytes| (audit, receipt, bytes))
        })
        .and_then(|(audit, receipt, result)| {
            release
                .map(ExecutionRelease::to_canonical_cbor)
                .transpose()
                .map(|release| (audit, receipt, result, release))
        })
}

/// The SAU1 events after `prefix`: a first response's lifecycle and
/// terminal events, or only the terminal event of a successor.
fn events_after(
    prefix: &[SandboxAuditRecord],
    records: &AttemptRecords,
    grant: &AdmissionGrant,
    sent: &Sent,
) -> Vec<(u8, Vec<[u8; 32]>)> {
    if prefix.is_empty() {
        events(records, grant, sent.release_digest())
    } else {
        terminal_event(records, grant).into_iter().collect()
    }
}

/// Sign the events after `prefix`, then SPR1 over the chain's last record
/// and SPY1 over SPR1, and retain them with what they bind.
fn assemble<R: RuntimeAttestationSigner>(
    signer: &R,
    admitted: AdmittedRuntimeKey<'_>,
    issued: &IssuedGrant,
    records: AttemptRecords,
    sent: Sent,
    prefix: Vec<SandboxAuditRecord>,
) -> Result<RetainedResponse, RuntimeSignerError> {
    let grant = AdmissionGrant::from_canonical_cbor(issued.bytes())?;
    let events = events_after(&prefix, &records, &grant, &sent);
    chain(signer, admitted, grant.attempt_id, prefix, events)
        .and_then(|chain| {
            let sau1 = chain.last().map_or([0; 32], |last| last.record_digest);
            let fields = receipt_fields(&grant, issued, &records, &sent, sau1);
            signed(
                signer,
                admitted,
                SandboxProviderReceipt::self_digested(fields),
                SandboxProviderReceipt::new,
            )
            .map(|receipt| (chain, receipt))
        })
        .and_then(|(chain, receipt)| {
            let fields = result_fields(&grant, &records, sent.output.clone(), &receipt, &chain);
            signed(
                signer,
                admitted,
                SandboxProviderResult::self_digested(fields),
                SandboxProviderResult::new,
            )
            .map(|result| (chain, receipt, result))
        })
        .and_then(|(chain, receipt, result)| {
            encoded(&chain, &receipt, &result, sent.release.as_ref())
                .map(|encoded| RetainedResponse {
                    grant: issued.clone(),
                    records,
                    sent,
                    chain,
                    encoded,
                })
                .map_err(Into::into)
        })
}

impl<S: RequestedConfiguration> EndedAttempt<S> {
    /// Assemble this attempt's records and sign its terminal response: the
    /// SAU1 chain, SPR1 and SPY1 (R9 §4.7 steps 7 to 9).
    ///
    /// # Errors
    /// [`ResponseFault::Evidence`] when the records cannot be assembled, and
    /// [`ResponseFault::Sign`] when the retained AGR1 does not decode, a
    /// record is refused, or a signature does not verify under `admitted`.
    /// Each is a provider fault: nothing is emitted.
    pub fn signed_response<R: RuntimeAttestationSigner>(
        &self,
        signer: &R,
        admitted: AdmittedRuntimeKey<'_>,
    ) -> Result<RetainedResponse, ResponseFault> {
        let records = self.records()?;
        Ok(assemble(
            signer,
            admitted,
            self.admission().grant(),
            records,
            Sent::of(self.progress()),
            Vec::new(),
        )?)
    }
}
