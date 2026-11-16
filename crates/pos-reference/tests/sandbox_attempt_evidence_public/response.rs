//! The SAU1, SPR1 and SPY1 encoders, and `AttemptEvidence::verify_response`:
//! R9 §6 rules 5, 6 (SAU1 and RLS1), 8 and 10 over one complete signed
//! response.
//!
//! Every response is built by the oracle: ciborium, BLAKE3 and Ed25519 over
//! the R9 §5 message, never the encoders under test. The encoders must then
//! reproduce those bytes exactly.

use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use pos_reference::sandbox_provider_protocol::{
    AdmissionGrant, AdmissionGrantFields, AttemptEvidence, AttemptProgressCode, AttemptResponse,
    RuntimeSigned, SandboxAuditRecord, SandboxAuditRecordFields,
    SandboxProviderProtocolError as ProtocolError, SandboxProviderReceipt,
    SandboxProviderReceiptFields, SandboxProviderResult, SandboxProviderResultFields,
    SandboxTerminalOutcome, SelfDigested, Verified,
};

use super::bundle::{elm1_digest, Fixture, APT1, LPS1, RUNTIME_KEY};
use super::oracle::{encode, integer, self_digest, text, unhex, TestResult};
use super::vectors::{
    KOE1_A_DIGEST, SAU1_EVENT_11_AUTHORITY, SAU1_EVENT_1_AUTHORITY, SAU1_EVENT_2_AUTHORITY, TME1_A,
    TME1_B_DIGEST, TME1_C, TME1_C_DIGEST,
};

/// The admitted runtime-attestation key of every response.
pub(super) fn runtime_key() -> SigningKey {
    SigningKey::from_bytes(&[42; 32])
}

fn foreign_key() -> SigningKey {
    SigningKey::from_bytes(&[43; 32])
}

/// Sign a sealed record and verify the signature, as the provider's
/// verify-before-emit signer does.
pub(super) fn sign<M: RuntimeSigned>(
    record: SelfDigested<M>,
    key: &SigningKey,
) -> TestResult<Verified<M>> {
    let signature = key.sign(&record.signature_message()).to_bytes();
    Ok(record.verify(signature, &key.verifying_key())?)
}

const ATTEMPT: [u8; 16] = [0x11; 16];
const REQUEST: [u8; 16] = [0x21; 16];
/// The admitted HCP1 ordinal 7 (R9 §7.7).
const NEGATIVE_PROBE: [u8; 32] = [0x55; 32];
const SPM1: [u8; 32] = [0x77; 32];
const SIM1: [u8; 32] = [0x74; 32];
const TRS1: [u8; 32] = [0x75; 32];
const RVS1: [u8; 32] = [0x76; 32];
const HCP1: [u8; 32] = [0x7a; 32];

fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}

/// `[unsigned, self_digest, signature]`, signed with `key` over
/// `PiglorOS.<magic>.Signature.v1\0 || self_digest`.
fn signed(magic: &str, unsigned: Vec<Value>, key: &SigningKey) -> TestResult<Vec<u8>> {
    let unsigned = Value::Array(unsigned);
    let digest = self_digest(magic, &unsigned)?;
    let mut message = format!("PiglorOS.{magic}.Signature.v1\0").into_bytes();
    message.extend(digest);
    let signature = key.sign(&message).to_bytes();
    encode(&Value::Array(vec![
        unsigned,
        bytes(&digest),
        bytes(&signature),
    ]))
}

/// `record` with an all-zero signature: an unsigned record.
fn zero_signature(record: &[u8]) -> TestResult<Vec<u8>> {
    match ciborium::from_reader::<Value, _>(record)? {
        Value::Array(mut parts) if parts.len() == 3 => {
            parts[2] = bytes(&[0; 64]);
            encode(&Value::Array(parts))
        }
        _ => Err("not a signed wrapper".into()),
    }
}

/// The self-digest a signed wrapper carries.
fn signed_digest(record: &[u8]) -> TestResult<[u8; 32]> {
    match ciborium::from_reader::<Value, _>(record)? {
        Value::Array(parts) => match parts.get(1) {
            Some(Value::Bytes(digest)) => Ok(digest.as_slice().try_into()?),
            _ => Err("no self-digest".into()),
        },
        _ => Err("not a signed wrapper".into()),
    }
}

type Change<'a> = &'a dyn Fn(&mut [Value]);

const fn unchanged(_: &mut [Value]) {}

/// How the oracle builds one response: the SAU1 events and SPY1 outcome,
/// changes to the signed records' fields, the records a foreign key signs,
/// the records left unsigned, and whether the `ReleaseV1` is presented.
struct Plan<'a> {
    events: &'a [u8],
    outcome: u64,
    grant: Change<'a>,
    release: Change<'a>,
    receipt: Change<'a>,
    result: Change<'a>,
    foreign: &'a [&'a str],
    zero: &'a [&'a str],
    present_release: Option<bool>,
}

impl<'a> Plan<'a> {
    const fn new(events: &'a [u8], outcome: u64) -> Self {
        Self {
            events,
            outcome,
            grant: &unchanged,
            release: &unchanged,
            receipt: &unchanged,
            result: &unchanged,
            foreign: &[],
            zero: &[],
            present_release: None,
        }
    }

    fn key(&self, magic: &str) -> SigningKey {
        if self.foreign.contains(&magic) {
            foreign_key()
        } else {
            runtime_key()
        }
    }

    /// The record `magic` signed by its key, or with a zero signature.
    fn signed(&self, magic: &str, unsigned: Vec<Value>) -> TestResult<Vec<u8>> {
        let record = signed(magic, unsigned, &self.key(magic))?;
        if self.zero.contains(&magic) {
            zero_signature(&record)
        } else {
            Ok(record)
        }
    }
}

/// One verified attempt and its oracle-built response.
struct Built {
    evidence: AttemptEvidence,
    grant: Vec<u8>,
    audit: Vec<Vec<u8>>,
    receipt: Vec<u8>,
    result: Vec<u8>,
    release: Option<Vec<u8>>,
}

impl Built {
    fn verify(&self) -> Result<(), ProtocolError> {
        self.evidence.verify_response(
            &AttemptResponse {
                grant: &self.grant,
                audit: &self.audit,
                receipt: &self.receipt,
                result: &self.result,
                release: self.release.as_deref(),
            },
            NEGATIVE_PROBE,
            &runtime_key().verifying_key(),
        )
    }

    fn rejects(&self, case: &str) {
        assert_eq!(
            self.verify(),
            Err(ProtocolError::InconsistentFields),
            "{case}"
        );
    }

    fn unsigned(&self, case: &str) {
        assert_eq!(
            self.verify(),
            Err(ProtocolError::SignatureInvalid),
            "{case}"
        );
    }
}

fn grant_fields(elm1: [u8; 32]) -> Vec<Value> {
    let mut fields = vec![text("AGR1"), integer(1), bytes(&REQUEST), bytes(&ATTEMPT)];
    fields.extend(
        [
            [0x70; 32], [0x71; 32], [0x72; 32], [0x73; 32], LPS1, SIM1, APT1, TRS1, RVS1, SPM1,
            [0x78; 32], [0x79; 32], HCP1,
        ]
        .iter()
        .map(|digest| bytes(digest.as_slice())),
    );
    fields.extend([
        integer(1),
        integer(2),
        integer(3),
        bytes(&elm1),
        bytes(&[0x7b; 32]),
        Value::Array(Vec::new()),
        bytes(&[0x7c; 32]),
        bytes(&[0x7d; 32]),
        text(RUNTIME_KEY),
    ]);
    fields
}

/// The digests of one attempt's records and what its response binds.
struct Bound {
    agr1: [u8; 32],
    elm1: [u8; 32],
    rqe1: [u8; 32],
    koe1: [u8; 32],
    tme1: [u8; 32],
    ready: Option<[u8; 32]>,
}

/// Build the attempt `fixture` and its response by `plan`: AGR1, then the
/// records rebound to it, `ReleaseV1`, the SAU1 chain, SPR1 and SPY1.
fn build(fixture: Fixture, plan: &Plan<'_>) -> TestResult<Built> {
    let elm1 = elm1_digest(&fixture.limits)?;
    let mut grant = grant_fields(elm1);
    (plan.grant)(grant.as_mut_slice());
    let grant = plan.signed("AGR1", grant)?;
    let agr1 = signed_digest(&grant)?;
    let mut fixture = fixture
        .rqe1(&[3], bytes(&agr1))?
        .koe1(&[3], bytes(&agr1))?
        .tme1(&[3], bytes(&agr1))?;
    fixture.grant.1 = agr1;
    let evidence = fixture.accepts()?;
    let (requested, observed, termination, _) = fixture.records()?;
    let bound = Bound {
        agr1,
        elm1,
        rqe1: requested.digest(),
        koe1: observed.digest(),
        tme1: termination.digest(),
        ready: fixture.ready.as_ref().map(|ready| ready.digest),
    };
    let released = termination.fields().progress == AttemptProgressCode::Released;
    let release = bound
        .ready
        .filter(|_| released)
        .map(|ready| release_record(&bound, ready, plan))
        .transpose()?;
    let rls1 = release.as_deref().map(signed_digest).transpose()?;
    let audit = audit_chain(&bound, rls1, plan)?;
    let receipt = receipt_record(
        &bound,
        rls1,
        signed_digest(audit.last().ok_or("no SAU1")?)?,
        plan,
    )?;
    let result = result_record(&bound, signed_digest(&receipt)?, plan)?;
    let release = match plan.present_release {
        Some(true) => Some(release.map_or_else(|| signed("RLS1", Vec::new(), &runtime_key()), Ok)?),
        Some(false) => None,
        None => release,
    };
    Ok(Built {
        evidence,
        grant,
        audit,
        receipt,
        result,
        release,
    })
}

fn release_record(bound: &Bound, ready: [u8; 32], plan: &Plan<'_>) -> TestResult<Vec<u8>> {
    let mut fields = vec![
        text("RLS1"),
        integer(1),
        bytes(&ATTEMPT),
        bytes(&[0x7e; 32]),
        bytes(&ready),
        bytes(&TRS1),
        bytes(&RVS1),
        bytes(&APT1),
        integer(1),
        integer(2),
        integer(3),
        bytes(&[0x7d; 32]),
        bytes(&bound.koe1),
        integer(9),
        text(RUNTIME_KEY),
    ];
    (plan.release)(fields.as_mut_slice());
    plan.signed("RLS1", fields)
}

fn audit_chain(bound: &Bound, rls1: Option<[u8; 32]>, plan: &Plan<'_>) -> TestResult<Vec<Vec<u8>>> {
    let mut audit = Vec::new();
    let mut previous: Option<[u8; 32]> = None;
    for (sequence, event) in plan.events.iter().enumerate() {
        let ready = bound.ready.ok_or("no ReadyV1");
        let authority: Vec<[u8; 32]> = match event {
            11 | 13 => vec![bound.agr1, ready?, bound.koe1],
            12 => vec![bound.agr1, ready?, rls1.ok_or("no ReleaseV1")?, bound.koe1],
            _ => vec![bound.agr1, bound.elm1, bound.tme1],
        };
        let record = plan.signed(
            "SAU1",
            vec![
                text("SAU1"),
                integer(1),
                bytes(&ATTEMPT),
                integer(u64::try_from(sequence)?),
                integer(u64::from(*event)),
                Value::Array(
                    authority
                        .iter()
                        .map(|digest| bytes(digest.as_slice()))
                        .collect(),
                ),
                previous.map_or(Value::Null, |digest| bytes(&digest)),
                text(RUNTIME_KEY),
            ],
        )?;
        previous = Some(signed_digest(&record)?);
        audit.push(record);
    }
    Ok(audit)
}

fn optional(digest: Option<[u8; 32]>) -> Value {
    digest.map_or(Value::Null, |digest| bytes(&digest))
}

fn receipt_record(
    bound: &Bound,
    rls1: Option<[u8; 32]>,
    sau1: [u8; 32],
    plan: &Plan<'_>,
) -> TestResult<Vec<u8>> {
    let mut fields = vec![
        text("SPR1"),
        integer(1),
        bytes(&ATTEMPT),
        bytes(&bound.agr1),
        bytes(&SPM1),
        bytes(&[0x7f; 32]),
        bytes(&LPS1),
        bytes(&SIM1),
        bytes(&APT1),
        bytes(&TRS1),
        bytes(&RVS1),
        integer(1),
        integer(2),
        integer(3),
        bytes(&HCP1),
        bytes(&bound.elm1),
        Value::Array(Vec::new()),
        optional(bound.ready),
        optional(rls1),
        bytes(&bound.rqe1),
        bytes(&bound.koe1),
        bytes(&NEGATIVE_PROBE),
        bytes(&bound.tme1),
        bytes(&sau1),
        text(RUNTIME_KEY),
    ];
    (plan.receipt)(fields.as_mut_slice());
    plan.signed("SPR1", fields)
}

fn result_record(bound: &Bound, spr1: [u8; 32], plan: &Plan<'_>) -> TestResult<Vec<u8>> {
    let mut fields = vec![
        text("SPY1"),
        integer(1),
        bytes(&REQUEST),
        bytes(&ATTEMPT),
        integer(plan.outcome),
        if plan.outcome == 0 {
            // TME1-A captured 70 bytes (R10 I6).
            Value::Array(vec![integer(70), bytes(&[0x99; 32])])
        } else {
            Value::Null
        },
        bytes(&bound.agr1),
        bytes(&spr1),
        Value::Array(
            plan.events
                .iter()
                .map(|event| integer(u64::from(*event)))
                .collect(),
        ),
        text(RUNTIME_KEY),
    ];
    (plan.result)(fields.as_mut_slice());
    plan.signed("SPY1", fields)
}

fn completed(plan: &Plan<'_>) -> TestResult<Built> {
    build(Fixture::released(TME1_A)?, plan)
}

fn unstarted(plan: &Plan<'_>) -> TestResult<Built> {
    build(Fixture::not_started()?, plan)
}

const COMPLETED: Plan<'static> = Plan::new(&[11, 12], 0);
/// TME1 progress 0 selects code 2 (missing evidence): one SAU1 event 2.
const UNSTARTED: Plan<'static> = Plan::new(&[2], 4);

#[test]
fn a_complete_signed_response_is_accepted() -> TestResult {
    completed(&COMPLETED)?.verify()?;
    unstarted(&UNSTARTED)?.verify()?;
    // TME1-C: cancelled after release (code 1), so SPY1 is Cancelled.
    build(Fixture::released(TME1_C)?, &Plan::new(&[11, 12, 1], 1))?.verify()?;
    Ok(())
}

#[test]
fn rule_8_the_outcome_and_terminal_event_are_the_tme1_code() -> TestResult {
    completed(&Plan::new(&[11, 12, 8], 4))?.rejects("Completed evidence reported unavailable");
    unstarted(&Plan::new(&[10], 4))?.rejects("code 2 reported as event 10");
    unstarted(&Plan::new(&[0], 4))?.rejects("code 0 BrokerDied (D6)");
    unstarted(&Plan::new(&[1], 1))?.rejects("code 2 reported as Cancelled");
    build(Fixture::released(TME1_C)?, &Plan::new(&[11, 12, 2], 4))?
        .rejects("Cancelled reported as unavailable");
    Ok(())
}

#[test]
fn rule_10_every_record_is_signed_by_the_admitted_key() -> TestResult {
    for magic in ["AGR1", "SAU1", "SPR1", "SPY1", "RLS1"] {
        let foreign = [magic];
        let mut plan = COMPLETED;
        plan.foreign = &foreign;
        completed(&plan)?.unsigned(magic);
        let mut plan = COMPLETED;
        plan.zero = &foreign;
        completed(&plan)?.unsigned(magic);
    }
    Ok(())
}

#[test]
fn rule_8_completed_output_is_the_captured_length() -> TestResult {
    let longer = |fields: &mut [Value]| {
        fields[5] = Value::Array(vec![integer(71), bytes(&[0x99; 32])]);
    };
    let mut plan = COMPLETED;
    plan.result = &longer;
    completed(&plan)?.rejects("an output descriptor longer than the capture");
    Ok(())
}

#[test]
fn rule_5_the_grant_is_the_one_spr1_and_spy1_name() -> TestResult {
    let cases: [(&str, usize, Value); 8] = [
        ("request", 2, bytes(&[0x22; 16])),
        ("attempt", 3, bytes(&[0x12; 16])),
        ("SIM1", 9, bytes(&[0x5a; 32])),
        ("HCP1", 16, bytes(&[0x5a; 32])),
        ("trust epoch", 17, integer(9)),
        ("ELM1", 20, bytes(&[0x5a; 32])),
        ("key", 25, text("other")),
        ("TRS1", 11, bytes(&[0x5a; 32])),
    ];
    for (case, index, value) in cases {
        let change = move |fields: &mut [Value]| fields[index] = value.clone();
        let mut plan = COMPLETED;
        plan.grant = &change;
        completed(&plan)?.rejects(case);
    }
    Ok(())
}

#[test]
fn rule_6_spr1_copies_the_admitted_negative_probe_and_binds_the_records() -> TestResult {
    for (case, index) in [("ordinal 21", 21), ("ordinal 22", 22)] {
        let change = move |fields: &mut [Value]| fields[index] = bytes(&[0x56; 32]);
        let mut plan = COMPLETED;
        plan.receipt = &change;
        completed(&plan)?.rejects(case);
    }
    let change = |fields: &mut [Value]| fields[7] = bytes(&[0x56; 32]);
    let mut plan = COMPLETED;
    plan.result = &change;
    completed(&plan)?.rejects("SPY1 naming another SPR1");
    Ok(())
}

#[test]
fn rule_6_the_release_binds_koe1_and_exists_exactly_when_spr1_names_it() -> TestResult {
    let mut withheld = COMPLETED;
    withheld.present_release = Some(false);
    completed(&withheld)?.rejects("a released attempt without its ReleaseV1");
    let mut extra = UNSTARTED;
    extra.present_release = Some(true);
    unstarted(&extra)?.rejects("a ReleaseV1 for an attempt never released");
    // KOE1 status 2: the observation failed, which selects code 2, so no
    // ReleaseV1 may bind it.
    let failed = Fixture::released(TME1_A)?
        .koe1(&[4], integer(2))?
        .koe1(&[7], Value::Null)?
        .tme1(&[26], integer(2))?;
    build(failed, &Plan::new(&[11, 12, 2], 4))?
        .rejects("a ReleaseV1 binding a KOE1 whose observation failed");

    let cases: [(&str, usize, Value); 5] = [
        ("attempt", 2, bytes(&[0x12; 16])),
        ("ReadyV1", 4, bytes(&[0x5a; 32])),
        ("RVS1", 6, bytes(&[0x5a; 32])),
        ("policy epoch", 10, integer(9)),
        ("observed readback", 12, bytes(&[0x5a; 32])),
    ];
    for (case, index, value) in cases {
        let change = move |fields: &mut [Value]| fields[index] = value.clone();
        let mut plan = COMPLETED;
        plan.release = &change;
        completed(&plan)?.rejects(case);
    }
    let other_key = |fields: &mut [Value]| fields[14] = text("other");
    let mut plan = COMPLETED;
    plan.release = &other_key;
    completed(&plan)?.rejects("key");

    // A valid ReleaseV1 that SPR1 does not name.
    let other_nonce = |fields: &mut [Value]| fields[3] = bytes(&[0x5a; 32]);
    let mut plan = COMPLETED;
    plan.release = &other_nonce;
    let mut substituted = completed(&COMPLETED)?;
    substituted.release = completed(&plan)?.release;
    substituted.rejects("a ReleaseV1 that SPR1 does not name");
    Ok(())
}

#[test]
fn an_incomplete_or_malformed_response_is_rejected() -> TestResult {
    let mut truncated = completed(&COMPLETED)?;
    truncated.audit.pop();
    truncated.rejects("a SAU1 chain without its last event");
    let mut malformed = completed(&COMPLETED)?;
    malformed.result = vec![0xff];
    assert!(malformed.verify().is_err());
    Ok(())
}

#[test]
fn the_encoders_reproduce_the_oracle_records() -> TestResult {
    let key = runtime_key();
    let public = key.verifying_key();
    for built in [
        completed(&COMPLETED)?,
        unstarted(&UNSTARTED)?,
        build(Fixture::released(TME1_C)?, &Plan::new(&[11, 12, 1], 1))?,
    ] {
        for oracle in &built.audit {
            let decoded = SandboxAuditRecord::from_canonical_cbor(oracle)?;
            let record = SandboxAuditRecord::self_digested(audit_fields(&decoded))?;
            assert_eq!(record.digest(), decoded.record_digest);
            let encoded = SandboxAuditRecord::new(sign(record, &key)?, &public)?;
            assert_eq!(&encoded.to_canonical_cbor()?, oracle);
        }
        let decoded = SandboxProviderReceipt::from_canonical_cbor(&built.receipt)?;
        let record = SandboxProviderReceipt::self_digested(receipt_fields(&decoded))?;
        let encoded = SandboxProviderReceipt::new(sign(record, &key)?, &public)?;
        assert_eq!(encoded.receipt_digest(), decoded.receipt_digest());
        assert_eq!(encoded.to_canonical_cbor()?, built.receipt);

        let decoded = SandboxProviderResult::from_canonical_cbor(&built.result)?;
        let record = SandboxProviderResult::self_digested(result_fields(&decoded))?;
        let encoded = SandboxProviderResult::new(sign(record, &key)?, &public)?;
        assert_eq!(encoded.result_digest(), decoded.result_digest());
        assert_eq!(encoded.to_canonical_cbor()?, built.result);
    }
    Ok(())
}

fn audit_fields(record: &SandboxAuditRecord) -> SandboxAuditRecordFields {
    SandboxAuditRecordFields {
        attempt_id: record.attempt_id,
        sequence: record.sequence,
        event_code: record.event_code,
        authority_digests: record.authority_digests.clone(),
        previous_digest: record.previous_digest,
        runtime_attestation_key_id: record.runtime_attestation_key_id.clone(),
    }
}

fn receipt_fields(receipt: &SandboxProviderReceipt) -> SandboxProviderReceiptFields {
    SandboxProviderReceiptFields {
        attempt_id: receipt.attempt_id,
        authority: receipt.authority.clone(),
        trust_epoch: receipt.trust_epoch,
        revocation_epoch: receipt.revocation_epoch,
        policy_epoch: receipt.policy_epoch,
        hcp1_digest: receipt.hcp1_digest,
        elm1_digest: receipt.elm1_digest,
        network_transcript_digests: receipt.network_transcript_digests.clone(),
        ready1_digest: receipt.ready1_digest,
        release1_digest: receipt.release1_digest,
        requested_configuration_evidence: receipt.requested_configuration_evidence,
        kernel_observation_evidence: receipt.kernel_observation_evidence,
        negative_probe_evidence: receipt.negative_probe_evidence,
        termination_evidence: receipt.termination_evidence,
        sau1_digest: receipt.sau1_digest,
        runtime_attestation_key_id: receipt.runtime_attestation_key_id.clone(),
    }
}

fn result_fields(result: &SandboxProviderResult) -> SandboxProviderResultFields {
    SandboxProviderResultFields {
        request_id: result.request_id,
        attempt_id: result.attempt_id,
        outcome: result.outcome,
        output: result.output.clone(),
        agr1_digest: result.agr1_digest,
        spr1_digest: result.spr1_digest,
        operational_events: result.operational_events.clone(),
        runtime_attestation_key_id: result.runtime_attestation_key_id.clone(),
    }
}

/// The digests of an R9 §7 SAU1 `authority_digests` vector.
fn authority(vector: &str) -> TestResult<Vec<[u8; 32]>> {
    match ciborium::from_reader::<Value, _>(unhex(vector)?.as_slice())? {
        Value::Array(digests) => digests
            .into_iter()
            .map(|digest| -> TestResult<[u8; 32]> {
                match digest {
                    Value::Bytes(digest) => Ok(digest.as_slice().try_into()?),
                    _ => Err("not a digest".into()),
                }
            })
            .collect(),
        _ => Err("not an array".into()),
    }
}

fn audit_record(event_code: u8, authority_digests: Vec<[u8; 32]>) -> SandboxAuditRecordFields {
    SandboxAuditRecordFields {
        attempt_id: ATTEMPT,
        sequence: 0,
        event_code,
        authority_digests,
        previous_digest: None,
        runtime_attestation_key_id: RUNTIME_KEY.to_owned(),
    }
}

#[test]
fn sau1_binds_the_r9_authority_vectors_and_signs_its_domain() -> TestResult {
    let key = runtime_key();
    for (event, vector, evidence) in [
        (11, SAU1_EVENT_11_AUTHORITY, KOE1_A_DIGEST),
        // R10 §8.3 replaced R9 §7.6 and §7.6a for these two (R10 D6).
        (2, SAU1_EVENT_2_AUTHORITY, TME1_B_DIGEST),
        (1, SAU1_EVENT_1_AUTHORITY, TME1_C_DIGEST),
    ] {
        let digests = authority(vector)?;
        // The last digest is the KOE1 or TME1 the event binds.
        assert_eq!(
            digests.last().map(|digest| digest.to_vec()),
            Some(unhex(evidence)?)
        );
        let record = SandboxAuditRecord::self_digested(audit_record(event, digests))?;
        // R9 §7.8: the SAU1 message is its domain followed by the digest.
        let mut message = b"PiglorOS.SAU1.Signature.v1\0".to_vec();
        message.extend(record.digest());
        assert_eq!(record.signature_message(), message);
        let encoded = SandboxAuditRecord::new(sign(record, &key)?, &key.verifying_key())?;
        let wrapper: Value = ciborium::from_reader(encoded.to_canonical_cbor()?.as_slice())?;
        let field = match wrapper {
            Value::Array(mut parts) => match parts.swap_remove(0) {
                Value::Array(mut fields) => fields.swap_remove(5),
                _ => return Err("no unsigned prefix".into()),
            },
            _ => return Err("not a wrapper".into()),
        };
        assert_eq!(encode(&field)?, unhex(vector)?);
    }
    Ok(())
}

#[test]
fn the_audit_encoder_refuses_invalid_fields() {
    let digests = vec![[0x22; 32], [0x44; 32], [0x20; 32]];
    let cases: [(SandboxAuditRecordFields, ProtocolError); 7] = [
        (
            audit_record(14, digests.clone()),
            ProtocolError::FieldOutOfBounds,
        ),
        (
            SandboxAuditRecordFields {
                attempt_id: [0; 16],
                ..audit_record(11, digests.clone())
            },
            ProtocolError::FieldOutOfBounds,
        ),
        (
            SandboxAuditRecordFields {
                runtime_attestation_key_id: String::new(),
                ..audit_record(11, digests.clone())
            },
            ProtocolError::FieldOutOfBounds,
        ),
        (
            audit_record(12, digests.clone()),
            ProtocolError::InconsistentFields,
        ),
        (
            audit_record(11, vec![[0x22; 32], [0; 32], [0x20; 32]]),
            ProtocolError::InconsistentFields,
        ),
        (
            SandboxAuditRecordFields {
                sequence: 1,
                ..audit_record(11, digests.clone())
            },
            ProtocolError::InconsistentFields,
        ),
        (
            SandboxAuditRecordFields {
                sequence: 1,
                previous_digest: Some([0; 32]),
                ..audit_record(11, digests)
            },
            ProtocolError::InconsistentFields,
        ),
    ];
    for (fields, error) in cases {
        assert_eq!(SandboxAuditRecord::self_digested(fields).err(), Some(error));
    }
}

#[test]
fn the_receipt_and_result_encoders_refuse_invalid_fields() -> TestResult {
    let built = completed(&COMPLETED)?;
    let receipt = receipt_fields(&SandboxProviderReceipt::from_canonical_cbor(
        &built.receipt,
    )?);
    assert_eq!(
        SandboxProviderReceipt::self_digested(SandboxProviderReceiptFields {
            hcp1_digest: [0; 32],
            ..receipt.clone()
        })
        .err(),
        Some(ProtocolError::FieldOutOfBounds)
    );
    assert_eq!(
        SandboxProviderReceipt::self_digested(SandboxProviderReceiptFields {
            ready1_digest: None,
            ..receipt
        })
        .err(),
        Some(ProtocolError::InconsistentFields)
    );
    let result = result_fields(&SandboxProviderResult::from_canonical_cbor(&built.result)?);
    for (fields, error) in [
        (
            SandboxProviderResultFields {
                request_id: [0; 16],
                ..result.clone()
            },
            ProtocolError::FieldOutOfBounds,
        ),
        (
            SandboxProviderResultFields {
                operational_events: vec![11],
                ..result.clone()
            },
            ProtocolError::InconsistentFields,
        ),
        (
            SandboxProviderResultFields {
                output: None,
                ..result
            },
            ProtocolError::InconsistentFields,
        ),
    ] {
        assert_eq!(
            SandboxProviderResult::self_digested(fields).err(),
            Some(error)
        );
    }
    Ok(())
}

#[test]
fn a_record_is_built_only_from_a_signature_under_the_admitted_key() -> TestResult {
    let foreign = foreign_key();
    let admitted = runtime_key().verifying_key();
    let built = completed(&COMPLETED)?;

    let audit = SandboxAuditRecord::from_canonical_cbor(&built.audit[0])?;
    let record = SandboxAuditRecord::self_digested(audit_fields(&audit))?;
    assert_eq!(
        SandboxAuditRecord::new(sign(record, &foreign)?, &admitted).err(),
        Some(ProtocolError::SignatureInvalid)
    );
    let receipt = SandboxProviderReceipt::from_canonical_cbor(&built.receipt)?;
    let record = SandboxProviderReceipt::self_digested(receipt_fields(&receipt))?;
    assert_eq!(
        SandboxProviderReceipt::new(sign(record, &foreign)?, &admitted).err(),
        Some(ProtocolError::SignatureInvalid)
    );
    let result = SandboxProviderResult::from_canonical_cbor(&built.result)?;
    let record = SandboxProviderResult::self_digested(result_fields(&result))?;
    assert_eq!(
        SandboxProviderResult::new(sign(record, &foreign)?, &admitted).err(),
        Some(ProtocolError::SignatureInvalid)
    );
    Ok(())
}

#[test]
fn a_changed_record_is_never_encoded_under_its_old_signature() -> TestResult {
    let built = completed(&COMPLETED)?;
    let mut audit = SandboxAuditRecord::from_canonical_cbor(&built.audit[0])?;
    audit.attempt_id = [0x12; 16];
    assert_eq!(
        audit.to_canonical_cbor().err(),
        Some(ProtocolError::DigestMismatch)
    );
    let mut receipt = SandboxProviderReceipt::from_canonical_cbor(&built.receipt)?;
    receipt.trust_epoch = 9;
    assert_eq!(
        receipt.to_canonical_cbor().err(),
        Some(ProtocolError::DigestMismatch)
    );
    let mut result = SandboxProviderResult::from_canonical_cbor(&built.result)?;
    result.outcome = SandboxTerminalOutcome::Cancelled;
    assert_eq!(
        result.to_canonical_cbor().err(),
        Some(ProtocolError::InconsistentFields)
    );
    result.outcome = SandboxTerminalOutcome::Completed;
    result.request_id = [0x22; 16];
    assert_eq!(
        result.to_canonical_cbor().err(),
        Some(ProtocolError::DigestMismatch)
    );
    Ok(())
}

fn grant_record_fields(grant: &AdmissionGrant) -> AdmissionGrantFields {
    AdmissionGrantFields {
        request_id: grant.request_id,
        attempt_id: grant.attempt_id,
        authority: grant.authority.clone(),
        trust_epoch: grant.trust_epoch,
        revocation_epoch: grant.revocation_epoch,
        policy_epoch: grant.policy_epoch,
        elm1_digest: grant.elm1_digest,
        input_digest: grant.input_digest,
        exchange_plan_digests: grant.exchange_plan_digests.clone(),
        expected_launch_policy_digest: grant.expected_launch_policy_digest,
        expected_readback_set_digest: grant.expected_readback_set_digest,
        runtime_attestation_key_id: grant.runtime_attestation_key_id.clone(),
    }
}

#[test]
fn the_grant_encoder_reproduces_the_oracle_agr1_and_signs_only_under_the_admitted_key() -> TestResult
{
    let key = runtime_key();
    let public = key.verifying_key();
    let built = completed(&COMPLETED)?;
    let decoded = AdmissionGrant::from_canonical_cbor(&built.grant)?;
    let fields = grant_record_fields(&decoded);
    let record = AdmissionGrant::self_digested(fields.clone())?;
    assert_eq!(record.digest(), decoded.grant_digest);
    // R9 §5: the AGR1 message is its domain followed by the self-digest.
    let mut message = b"PiglorOS.AGR1.Signature.v1\0".to_vec();
    message.extend(record.digest());
    assert_eq!(record.signature_message(), message);
    assert_eq!(record.key_id(), RUNTIME_KEY);
    let encoded = AdmissionGrant::new(sign(record.clone(), &key)?, &public)?;
    assert_eq!(encoded, decoded);
    assert_eq!(encoded.to_canonical_cbor()?, built.grant);
    // A signature that verified under another key is not the admitted one.
    assert_eq!(
        AdmissionGrant::new(sign(record, &foreign_key())?, &public).err(),
        Some(ProtocolError::SignatureInvalid)
    );
    // The encoder validates as the decoder does.
    for invalid in [
        AdmissionGrantFields {
            attempt_id: [0; 16],
            ..fields.clone()
        },
        AdmissionGrantFields {
            elm1_digest: [0; 32],
            ..fields.clone()
        },
        AdmissionGrantFields {
            exchange_plan_digests: vec![[0; 32]],
            ..fields.clone()
        },
        AdmissionGrantFields {
            runtime_attestation_key_id: String::new(),
            ..fields
        },
    ] {
        assert_eq!(
            AdmissionGrant::self_digested(invalid).err(),
            Some(ProtocolError::FieldOutOfBounds)
        );
    }
    // A changed grant is never encoded under its old signature.
    let mut changed = encoded;
    changed.policy_epoch += 1;
    assert_eq!(
        changed.to_canonical_cbor().err(),
        Some(ProtocolError::DigestMismatch)
    );
    changed.policy_epoch -= 1;
    changed.signature = [0; 64];
    assert_eq!(
        changed.to_canonical_cbor().err(),
        Some(ProtocolError::SignatureInvalid)
    );
    Ok(())
}
