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
//! [`RetainedResponse`] keeps the exact bytes: AGR1, the chain, SPR1, the
//! output SBC1 records of a Completed response, SPY1 and the `ReleaseV1`
//! sent, with the RQE1, KOE1 and TME1 they bind. The output leaves its fence
//! only here, against the attempt's terminal evidence, and its records stay
//! under the output reservation, so the full response can be replayed byte
//! for byte until the attempt is reconciled (ADR-069 §4; the charge lifetime
//! is R11 Amendment 1, item P12). When the output
//! transfer of a Completed response times out,
//! [`RetainedResponse::successor`] re-issues it once (R9 §4.7): a successor
//! TME1, SAU1 event 10 appended to the chain, and a new SPR1 and SPY1. The
//! successor is not Completed, so it carries no output.

use pos_reference::sandbox_provider_protocol::{
    AdmissionGrant, AttemptResponse, ExecutionRelease, PayloadDescriptor, ReceiptAuthority,
    RuntimeSigned, SandboxAuditRecord, SandboxAuditRecordFields, SandboxProviderProtocolError,
    SandboxProviderReceipt, SandboxProviderReceiptFields, SandboxProviderResult,
    SandboxProviderResultFields, SandboxTerminalOutcome, SelfDigested, TransferRecord, Verified,
};

use super::{AttemptRecords, EvidenceFault};
use crate::adapter_stdio::RetainedOutput;
use crate::{
    sign_verified, AdmittedRuntimeKey, AttemptProgress, EndedAttempt, IssuedGrant, ReleasedOutput,
    RequestedConfiguration, RuntimeAttestationSigner, RuntimeSignerError,
};

/// SAU1 lifecycle event codes (ADR-069 §10).
const LAUNCHER_READY: u8 = 11;
const EXECUTION_RELEASED: u8 = 12;
const EXECUTION_RELEASE_DENIED: u8 = 13;

/// The complete signed response of one ended attempt, as it is retained
/// until the attempt is reconciled.
#[derive(Debug)]
pub struct RetainedResponse {
    grant: IssuedGrant,
    records: AttemptRecords,
    sent: Sent,
    chain: Vec<SandboxAuditRecord>,
    encoded: Encoded,
    output: Option<RetainedOutput>,
    // The SPY1 self-digest and the final SAU1 digest SPR1 binds, which the
    // reconciliation evidence and SCY1 bind (ADR-069 R15 §3.2).
    terminal: ([u8; 32], [u8; 32]),
    // Set, under the lifecycle's attempts lock, once a connection writes
    // its SPY1 or an SCY1 binds it: no re-issue may then replace it.
    delivered: std::sync::atomic::AtomicBool,
}

impl RetainedResponse {
    /// Record that this response is delivered whole: a connection writes
    /// its SPY1, or an SCY1 binds its digest. The lifecycle calls this
    /// under its attempts lock, while this is the stored response.
    pub(crate) fn mark_delivered(&self) {
        self.delivered
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// Whether this response was delivered whole, so a re-issue must keep it.
    pub(crate) fn delivered(&self) -> bool {
        self.delivered.load(std::sync::atomic::Ordering::Acquire)
    }

    /// The self-digest of its SPY1 and the digest of its last SAU1, which
    /// its SPR1 binds (ADR-069 R15 §3.2).
    #[must_use]
    pub const fn terminal_digests(&self) -> ([u8; 32], [u8; 32]) {
        self.terminal
    }

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

    /// The stored full response, frame by frame, exactly as every
    /// connection of the attempt receives it (ADR-069 §4): AGR1, the SAU1
    /// chain from sequence zero, SPR1, the output SBC1 records from index
    /// zero when Completed, and SPY1.
    pub fn frames(&self) -> impl Iterator<Item = &[u8]> {
        let (audit, receipt, result, _) = &self.encoded;
        let output = self
            .output
            .as_ref()
            .map_or(&[][..], RetainedOutput::records);
        std::iter::once(self.grant.bytes())
            .chain(audit.iter().map(Vec::as_slice))
            .chain(std::iter::once(receipt.as_slice()))
            .chain(output.iter().map(Vec::as_slice))
            .chain(std::iter::once(result.as_slice()))
    }

    /// The AGR1 the response answers, with its admitted ELM1 limits.
    #[must_use]
    pub const fn grant(&self) -> &IssuedGrant {
        &self.grant
    }

    /// The output SBC1 records of a Completed response, from index zero,
    /// and the payload bytes they carry: TME1 `output-capture.accepted-bytes`,
    /// which an output transfer must deliver (R9 §4.7). Empty, with zero
    /// bytes, for any other response.
    #[must_use]
    pub fn output(&self) -> (&[Vec<u8>], u64) {
        (
            self.output
                .as_ref()
                .map_or(&[][..], RetainedOutput::records),
            self.records
                .termination
                .fields()
                .output_capture
                .map_or(0, |capture| capture.accepted_bytes),
        )
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
    /// records stay in the chain. `transfer` is `None` when a time of the
    /// output transfer could not be read.
    ///
    /// # Errors
    /// [`ResponseFault::Evidence`] when this response cannot be re-issued
    /// ([`EvidenceFault::NotReissuable`]), a time of the output transfer
    /// could not be read ([`EvidenceFault::Clock`], R9 Amendment 1 change F)
    /// or the successor is refused, and [`ResponseFault::Sign`] when a
    /// record is refused or a signature does not verify under `admitted`.
    pub fn successor<R: RuntimeAttestationSigner>(
        &self,
        transfer: Option<TransferRecord>,
        signer: &R,
        admitted: AdmittedRuntimeKey<'_>,
    ) -> Result<Self, ResponseFault> {
        let records = self.records.successor(transfer)?;
        Ok(assemble(
            signer,
            admitted,
            &self.grant,
            (records, self.sent.clone()),
            self.chain.clone(),
            None,
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
    /// descriptor of an executed attempt. No other attempt sent anything a
    /// signed response names: one that failed after its `ReleaseV1` has no
    /// records, so it is never signed.
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
            _ => Self::default(),
        }
    }

    fn release_digest(&self) -> Option<[u8; 32]> {
        self.release.as_ref().map(ExecutionRelease::digest)
    }
}

/// The captured output of an executed attempt, released from its fence
/// against the terminal evidence read after exit and before teardown.
fn released<S>(progress: AttemptProgress<S>) -> Option<ReleasedOutput> {
    match progress {
        AttemptProgress::Executed {
            evidence, adapter, ..
        } => evidence
            .terminal()
            .map(|terminal| adapter.into_output().release(terminal)),
        _ => None,
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
    lifecycle
        .into_iter()
        .flatten()
        .chain(terminal_event(records, grant))
        .collect()
}

/// The terminal SAU1 event `[agr1, elm1, tme1]`, unless TME1 Completed.
fn terminal_event(records: &AttemptRecords, grant: &AdmissionGrant) -> Option<Event> {
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

/// Where the next SAU1 record links: its sequence and the digest of the
/// record before it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Link {
    sequence: u64,
    previous: Option<[u8; 32]>,
}

impl Link {
    /// The link after the last record of `prefix`, or the start of a chain.
    fn after(prefix: &[SandboxAuditRecord]) -> Self {
        prefix.last().map_or(
            Self {
                sequence: 0,
                previous: None,
            },
            |last| Self {
                sequence: last.sequence + 1,
                previous: Some(last.record_digest),
            },
        )
    }
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
) -> Vec<Event> {
    if prefix.is_empty() {
        events(records, grant, sent.release_digest())
    } else {
        terminal_event(records, grant).into_iter().collect()
    }
}

/// Sign SPR1 over the chain whose last record is `sau1`.
fn sign_receipt<R: RuntimeAttestationSigner>(
    signer: &R,
    admitted: AdmittedRuntimeKey<'_>,
    grant: &AdmissionGrant,
    issued: &IssuedGrant,
    records: &AttemptRecords,
    sent: &Sent,
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
    sent: &Sent,
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

/// The signed records after `prefix`: the SAU1 chain, then SPR1 over its
/// last record, then SPY1 over SPR1. A response with no event to sign is
/// refused.
fn sign_records<R: RuntimeAttestationSigner>(
    signer: &R,
    admitted: AdmittedRuntimeKey<'_>,
    (grant, issued): (&AdmissionGrant, &IssuedGrant),
    records: &AttemptRecords,
    sent: &Sent,
    prefix: Vec<SandboxAuditRecord>,
) -> Result<Signed, RuntimeSignerError> {
    let link = Link::after(&prefix);
    Events::new(events_after(&prefix, records, grant, sent))
        .ok_or(RuntimeSignerError::Protocol(
            SandboxProviderProtocolError::InconsistentFields,
        ))
        .and_then(|events| chain(signer, admitted, grant.attempt_id, link, events))
        .and_then(|(appended, sau1)| {
            let chain = [prefix, appended].concat();
            sign_receipt(signer, admitted, grant, issued, records, sent, sau1)
                .map(|receipt| (chain, receipt))
        })
        .and_then(|(chain, receipt)| {
            sign_result(signer, admitted, grant, records, sent, (&receipt, &chain))
                .map(|result| (chain, receipt, result))
        })
}

/// The signed SAU1 chain, SPR1 and SPY1 of one response.
type Signed = (
    Vec<SandboxAuditRecord>,
    SandboxProviderReceipt,
    SandboxProviderResult,
);

/// The output SBC1 records under `result` when it carries an output
/// descriptor, that is when it Completed; any other response retains none.
fn retained_output(
    output: Option<ReleasedOutput>,
    grant: &AdmissionGrant,
    result: &SandboxProviderResult,
) -> Result<Option<RetainedOutput>, SandboxProviderProtocolError> {
    output
        .filter(|_| result.output.is_some())
        .map(|output| {
            output.into_records(result.result_digest(), grant.request_id, grant.attempt_id)
        })
        .transpose()
}

/// Sign the events after `prefix`, then SPR1 and SPY1, and retain them with
/// what they bind. `output` becomes the SBC1 records under SPY1 only when
/// SPY1 carries an output descriptor, that is when it Completed.
fn assemble<R: RuntimeAttestationSigner>(
    signer: &R,
    admitted: AdmittedRuntimeKey<'_>,
    issued: &IssuedGrant,
    (records, sent): (AttemptRecords, Sent),
    prefix: Vec<SandboxAuditRecord>,
    output: Option<ReleasedOutput>,
) -> Result<RetainedResponse, RuntimeSignerError> {
    let grant = AdmissionGrant::from_canonical_cbor(issued.bytes())?;
    let (chain, receipt, result) =
        sign_records(signer, admitted, (&grant, issued), &records, &sent, prefix)?;
    retained_output(output, &grant, &result)
        .and_then(|output| {
            encoded(&chain, &receipt, &result, sent.release.as_ref())
                .map(|encoded| (encoded, output))
        })
        .map(|(encoded, output)| RetainedResponse {
            grant: issued.clone(),
            records,
            sent,
            chain,
            encoded,
            output,
            terminal: (result.result_digest(), receipt.sau1_digest),
            delivered: std::sync::atomic::AtomicBool::new(false),
        })
        .map_err(Into::into)
}

impl<S: RequestedConfiguration> EndedAttempt<S> {
    /// Assemble this attempt's records and sign its terminal response: the
    /// SAU1 chain, SPR1 and SPY1 (R9 §4.7 steps 7 to 9). A Completed
    /// response also takes the attempt's captured output, as the SBC1
    /// records SPY1 parents.
    ///
    /// # Errors
    /// [`ResponseFault::Evidence`] when the records cannot be assembled, and
    /// [`ResponseFault::Sign`] when the retained AGR1 does not decode, a
    /// record is refused, or a signature does not verify under `admitted`.
    /// Each is a provider fault: nothing is emitted.
    pub fn signed_response<R: RuntimeAttestationSigner>(
        self,
        signer: &R,
        admitted: AdmittedRuntimeKey<'_>,
    ) -> Result<RetainedResponse, ResponseFault> {
        let records = self.records()?;
        let sent = Sent::of(self.progress());
        let grant = self.admission().grant().clone();
        Ok(assemble(
            signer,
            admitted,
            &grant,
            (records, sent),
            Vec::new(),
            released(self.into_parts().0),
        )?)
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
