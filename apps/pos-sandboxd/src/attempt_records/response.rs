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
//! output bytes stay fenced in the attempt's capture.

use pos_reference::sandbox_provider_protocol::{
    AdmissionGrant, AttemptResponse, ExecutionRelease, PayloadDescriptor, ReceiptAuthority,
    RuntimeSigned, SandboxAuditRecord, SandboxAuditRecordFields, SandboxProviderProtocolError,
    SandboxProviderReceipt, SandboxProviderReceiptFields, SandboxProviderResult,
    SandboxProviderResultFields, SandboxTerminalOutcome, SelfDigested, Verified,
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
    audit: Vec<Vec<u8>>,
    receipt: Vec<u8>,
    result: Vec<u8>,
    release: Option<Vec<u8>>,
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
        AttemptResponse {
            grant: self.grant.bytes(),
            audit: &self.audit,
            receipt: &self.receipt,
            result: &self.result,
            release: self.release.as_deref(),
        }
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
#[derive(Default)]
struct Sent<'a> {
    release: Option<&'a ExecutionRelease>,
    transcripts: Vec<[u8; 32]>,
    output: Option<PayloadDescriptor>,
}

impl<'a> Sent<'a> {
    /// The `ReleaseV1` sent, the network transcripts and the output
    /// descriptor of an executed attempt; only the `ReleaseV1` of a failed
    /// one.
    fn of<S>(progress: &'a AttemptProgress<S>) -> Self {
        match progress {
            AttemptProgress::Executed {
                evidence,
                network,
                adapter,
                ..
            } => Self {
                release: evidence.release().release(),
                transcripts: network.transcript_digests(),
                output: Some(adapter.output().descriptor()),
            },
            AttemptProgress::Failed {
                evidence: Some(evidence),
                ..
            } => Self {
                release: evidence.release().release(),
                ..Self::default()
            },
            _ => Self::default(),
        }
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

/// One SAU1 event: its code and authority digests.
type Event = (u8, Vec<[u8; 32]>);

/// The SAU1 events to sign, never empty: a first event and the rest.
struct Events {
    first: Event,
    rest: Vec<Event>,
}

impl Events {
    /// The events in order; `None` when there are none.
    fn new(events: impl IntoIterator<Item = Event>) -> Option<Self> {
        let mut events = events.into_iter();
        events.next().map(|first| Self {
            first,
            rest: events.collect(),
        })
    }
}

/// The SAU1 events of the attempt, in order, with their authority digests.
///
/// Events 11 and 13 bind the KOE1 digest whatever its status, including a
/// status-2 KOE1 whose observation failed after `ReadyV1` (owner decision
/// 2026-11-19, Q3).
fn events(
    records: &AttemptRecords,
    grant: &AdmissionGrant,
    release: Option<[u8; 32]>,
) -> Vec<Event> {
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
    let terminal = records.classification().code().map(|code| {
        (
            code.code(),
            vec![agr1, grant.elm1_digest, records.termination().digest()],
        )
    });
    lifecycle.into_iter().flatten().chain(terminal).collect()
}

/// Where the next SAU1 record links: its sequence and the digest of the
/// record before it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Link {
    sequence: u64,
    previous: Option<[u8; 32]>,
}

impl Link {
    /// The start of a chain.
    const FIRST: Self = Self {
        sequence: 0,
        previous: None,
    };
}

/// Sign one SAU1 event at `link`.
fn sign_event<R: RuntimeAttestationSigner>(
    signer: &R,
    admitted: AdmittedRuntimeKey<'_>,
    attempt_id: [u8; 16],
    link: Link,
    (event_code, authority_digests): Event,
) -> Result<SandboxAuditRecord, RuntimeSignerError> {
    let fields = SandboxAuditRecordFields {
        attempt_id,
        sequence: link.sequence,
        event_code,
        authority_digests,
        previous_digest: link.previous,
        runtime_attestation_key_id: admitted.key_id().to_owned(),
    };
    signed(
        signer,
        admitted,
        SandboxAuditRecord::self_digested(fields),
        SandboxAuditRecord::new,
    )
}

/// The signed SAU1 records of `events` from `link`, and the digest of the
/// last one, which SPR1 binds.
fn chain<R: RuntimeAttestationSigner>(
    signer: &R,
    admitted: AdmittedRuntimeKey<'_>,
    attempt_id: [u8; 16],
    link: Link,
    events: Events,
) -> Result<(Vec<SandboxAuditRecord>, [u8; 32]), RuntimeSignerError> {
    let Events { first, rest } = events;
    sign_event(signer, admitted, attempt_id, link, first).and_then(|first| {
        let tip = (first.sequence, first.record_digest);
        rest.into_iter()
            .try_fold(
                (vec![first], tip),
                |(mut chain, (sequence, previous)), event| {
                    let next = Link {
                        sequence: sequence + 1,
                        previous: Some(previous),
                    };
                    sign_event(signer, admitted, attempt_id, next, event).map(|record| {
                        let tip = (record.sequence, record.record_digest);
                        chain.push(record);
                        (chain, tip)
                    })
                },
            )
            .map(|(chain, (_, sau1))| (chain, sau1))
    })
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
    sent: &Sent<'_>,
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
        release1_digest: sent.release.map(ExecutionRelease::digest),
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

/// Sign SPR1 over the chain whose last record is `sau1`.
fn sign_receipt<R: RuntimeAttestationSigner>(
    signer: &R,
    admitted: AdmittedRuntimeKey<'_>,
    grant: &AdmissionGrant,
    issued: &IssuedGrant,
    records: &AttemptRecords,
    sent: &Sent<'_>,
    sau1: [u8; 32],
) -> Result<SandboxProviderReceipt, RuntimeSignerError> {
    signed(
        signer,
        admitted,
        SandboxProviderReceipt::self_digested(receipt_fields(grant, issued, records, sent, sau1)),
        SandboxProviderReceipt::new,
    )
}

/// Sign SPY1 over `receipt` and `chain`.
fn sign_result<R: RuntimeAttestationSigner>(
    signer: &R,
    admitted: AdmittedRuntimeKey<'_>,
    grant: &AdmissionGrant,
    records: &AttemptRecords,
    sent: &Sent<'_>,
    (receipt, chain): (&SandboxProviderReceipt, &[SandboxAuditRecord]),
) -> Result<SandboxProviderResult, RuntimeSignerError> {
    let fields = result_fields(grant, records, sent.output.clone(), receipt, chain);
    signed(
        signer,
        admitted,
        SandboxProviderResult::self_digested(fields),
        SandboxProviderResult::new,
    )
}

/// Sign the chain, then SPR1 over its last record, then SPY1 over SPR1, and
/// encode them. An attempt with no event to sign is refused.
fn sign_response<R: RuntimeAttestationSigner>(
    signer: &R,
    admitted: AdmittedRuntimeKey<'_>,
    grant: &AdmissionGrant,
    issued: &IssuedGrant,
    records: &AttemptRecords,
    sent: &Sent<'_>,
) -> Result<Encoded, RuntimeSignerError> {
    let release = sent.release.map(ExecutionRelease::digest);
    Events::new(events(records, grant, release))
        .ok_or(RuntimeSignerError::Protocol(
            SandboxProviderProtocolError::InconsistentFields,
        ))
        .and_then(|events| chain(signer, admitted, grant.attempt_id, Link::FIRST, events))
        .and_then(|(chain, sau1)| {
            sign_receipt(signer, admitted, grant, issued, records, sent, sau1)
                .map(|receipt| (chain, receipt))
        })
        .and_then(|(chain, receipt)| {
            sign_result(signer, admitted, grant, records, sent, (&receipt, &chain))
                .map(|result| (chain, receipt, result))
        })
        .and_then(|(chain, receipt, result)| {
            encoded(&chain, &receipt, &result, sent.release).map_err(Into::into)
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
        let issued = self.admission().grant();
        let sent = Sent::of(self.progress());
        let (audit, receipt, result, release) = AdmissionGrant::from_canonical_cbor(issued.bytes())
            .map_err(RuntimeSignerError::from)
            .and_then(|grant| sign_response(signer, admitted, &grant, issued, &records, &sent))?;
        Ok(RetainedResponse {
            grant: issued.clone(),
            records,
            audit,
            receipt,
            result,
            release,
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{Event, Events};

    #[test]
    fn events_are_never_empty() {
        assert!(Events::new(Vec::<Event>::new()).is_none());
        let events = Events::new([(11, Vec::new()), (12, Vec::new())]);
        assert!(events.is_some_and(|events| events.first.0 == 11 && events.rest.len() == 1));
    }
}
