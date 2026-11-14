//! `AttemptEvidence`: R9 §6 rules 4 to 7 and 9 across RQE1, KOE1, TME1,
//! the grant, ELM1, `ReadyV1` and SPR1.

use ciborium::value::Value;
use pos_reference::sandbox_provider_protocol::{
    AttemptEvidence, AttemptEvidenceContext, Contradiction, FdIdentity, KernelObservationEvidence,
    LauncherReady, LauncherReadyFields, NamespaceIdentity, ReceiptAuthority,
    RequestedConfigurationEvidence, SandboxExecutionMode, SandboxLimit,
    SandboxProviderProtocolError as ProtocolError, SandboxProviderReceipt, TerminalCode,
    TerminationEvidence,
};

use super::observed::provider_namespaces;
use super::oracle::{edit, filled, integer, set, unhex, with, wrapped_digest, TestResult};
use super::terminated::at_progress;
use super::vectors::{KOE1_A, KOE1_B, RQE1_A, RQE1_B, TME1_A, TME1_B, TME1_C};

const WORK_LIMIT: u64 = 1_048_576;

const fn ready_fields() -> LauncherReadyFields {
    LauncherReadyFields {
        attempt_id: [0x11; 16],
        nonce: [0x01; 32],
        launch_instance_id: [0x77; 16],
        launcher_digest: [0x02; 32],
        launcher_identity: FdIdentity {
            mount_id: 303,
            inode: 12,
        },
        sim1_digest: [0x03; 32],
        adapter_digest: [0x04; 32],
        adapter_identity: FdIdentity {
            mount_id: 301,
            inode: 57,
        },
        launch_parameter_digest: [0x05; 32],
        expected_fdl1_digest: [0x88; 32],
        observed_fdl1_digest: [0x88; 32],
    }
}

fn limits(output: u64, work: u64, live: u64, incomplete: u64) -> Vec<SandboxLimit> {
    [(8, output), (9, work), (13, live), (14, incomplete)]
        .into_iter()
        .map(|(limit_id, value)| SandboxLimit { limit_id, value })
        .collect()
}

/// The decoded RQE1, KOE1 and TME1, and the TME1 it succeeds.
type Records = (
    RequestedConfigurationEvidence,
    KernelObservationEvidence,
    TerminationEvidence,
    Option<TerminationEvidence>,
);

/// One attempt's records and what a verifier holds, with the records'
/// digest bindings kept intact as they are edited.
struct Fixture {
    rqe1: Vec<u8>,
    koe1: Vec<u8>,
    tme1: Vec<u8>,
    previous: Option<Vec<u8>>,
    ready: Option<LauncherReady>,
    limits: Vec<SandboxLimit>,
    mode: SandboxExecutionMode,
    provider: [NamespaceIdentity; 6],
    grant: ([u8; 16], [u8; 32], [u8; 32]),
}

impl Fixture {
    /// RQE1-A and KOE1-A, bound to a real `ReadyV1`, with `tme1`.
    fn observed(tme1: Vec<u8>) -> TestResult<Self> {
        let ready = LauncherReady::new(ready_fields())?;
        let koe1 = with(&unhex(KOE1_A)?, &[5], Value::Bytes(ready.digest.to_vec()))?;
        let mut fixture = Self {
            rqe1: unhex(RQE1_A)?,
            koe1,
            tme1,
            previous: None,
            ready: Some(ready),
            limits: limits(5, WORK_LIMIT, 1, 0),
            mode: SandboxExecutionMode::AirGapped,
            provider: provider_namespaces(),
            grant: ([0x11; 16], [0x22; 32], [0x33; 32]),
        };
        fixture.rebind()?;
        Ok(fixture)
    }

    fn released(vector: &str) -> TestResult<Self> {
        Self::observed(unhex(vector)?)
    }

    /// RQE1-B, KOE1-B and a progress-0 TME1: nothing was started.
    fn not_started() -> TestResult<Self> {
        let mut fixture = Self::observed(at_progress(0)?)?;
        fixture.rqe1 = unhex(RQE1_B)?;
        fixture.koe1 = unhex(KOE1_B)?;
        fixture.ready = None;
        fixture.rebind()?;
        Ok(fixture)
    }

    /// KOE1 binds RQE1, and TME1 binds KOE1.
    fn rebind(&mut self) -> TestResult {
        self.koe1 = with(
            &self.koe1,
            &[6],
            Value::Bytes(wrapped_digest(&self.rqe1)?.to_vec()),
        )?;
        self.tme1 = with(
            &self.tme1,
            &[5],
            Value::Bytes(wrapped_digest(&self.koe1)?.to_vec()),
        )?;
        Ok(())
    }

    fn rqe1(mut self, path: &[usize], value: Value) -> TestResult<Self> {
        self.rqe1 = with(&self.rqe1, path, value)?;
        self.rebind().map(|()| self)
    }

    fn koe1(mut self, path: &[usize], value: Value) -> TestResult<Self> {
        self.koe1 = with(&self.koe1, path, value)?;
        self.rebind().map(|()| self)
    }

    fn tme1(mut self, path: &[usize], value: Value) -> TestResult<Self> {
        self.tme1 = with(&self.tme1, path, value)?;
        Ok(self)
    }

    fn records(&self) -> TestResult<Records> {
        Ok((
            RequestedConfigurationEvidence::from_canonical_cbor(&self.rqe1)?,
            KernelObservationEvidence::from_canonical_cbor(&self.koe1)?,
            TerminationEvidence::from_canonical_cbor(&self.tme1)?,
            self.previous
                .as_deref()
                .map(TerminationEvidence::from_canonical_cbor)
                .transpose()?,
        ))
    }

    fn verify(&self) -> TestResult<Result<AttemptEvidence, ProtocolError>> {
        let (requested, observed, termination, previous) = self.records()?;
        let (attempt_id, agr1_digest, elm1_digest) = self.grant;
        Ok(AttemptEvidence::verify(
            requested,
            observed,
            termination,
            previous.as_ref(),
            &AttemptEvidenceContext {
                attempt_id,
                agr1_digest,
                elm1_digest,
                limits: &self.limits,
                mode: self.mode,
                ready: self.ready.as_ref(),
                provider_namespaces: &self.provider,
            },
        ))
    }

    fn accepts(&self) -> TestResult<AttemptEvidence> {
        Ok(self.verify()??)
    }

    fn rejects(&self, case: &str) -> TestResult {
        assert_eq!(
            self.verify()?.map(|_| ()),
            Err(ProtocolError::InconsistentFields),
            "{case}"
        );
        Ok(())
    }
}

#[test]
fn verify_accepts_the_vectors_and_every_progress() -> TestResult {
    for (fixture, contradiction, code) in [
        (Fixture::released(TME1_A)?, None, None),
        (
            Fixture::released(TME1_B)?,
            Some(Contradiction::CounterDecreased),
            Some(TerminalCode::CleanupFailed),
        ),
        (
            Fixture::released(TME1_C)?,
            None,
            Some(TerminalCode::Cancelled),
        ),
        (
            Fixture::observed(at_progress(1)?)?,
            None,
            Some(TerminalCode::ProtocolFailure),
        ),
        (
            Fixture::not_started()?,
            None,
            Some(TerminalCode::CleanupFailed),
        ),
    ] {
        let (requested, observed, termination, _) = fixture.records()?;
        let evidence = fixture.accepts()?;
        assert_eq!(evidence.requested(), &requested);
        assert_eq!(evidence.observed(), &observed);
        assert_eq!(evidence.termination(), &termination);
        let classification = termination.facts(&requested, &observed).classify();
        assert_eq!(classification.contradiction(), contradiction);
        assert_eq!(classification.code(), code);
    }
    Ok(())
}

#[test]
fn rule_5_one_attempt_and_grant_throughout() -> TestResult {
    let mut other_attempt = Fixture::released(TME1_A)?;
    other_attempt.grant.0 = [0x12; 16];
    other_attempt.rejects("context attempt")?;
    let mut other_grant = Fixture::released(TME1_A)?;
    other_grant.grant.1 = [0x23; 32];
    other_grant.rejects("context grant")?;
    let mut other_limits = Fixture::released(TME1_A)?;
    other_limits.grant.2 = [0x34; 32];
    other_limits.rejects("context ELM1")?;
    let attempt = filled(0x12, 16);
    let digest = filled(0x23, 32);
    Fixture::released(TME1_A)?
        .rqe1(&[2], attempt.clone())?
        .rejects("RQE1 attempt")?;
    Fixture::released(TME1_A)?
        .rqe1(&[3], digest.clone())?
        .rejects("RQE1 grant")?;
    Fixture::released(TME1_A)?
        .koe1(&[2], attempt.clone())?
        .rejects("KOE1 attempt")?;
    Fixture::released(TME1_A)?
        .koe1(&[3], digest.clone())?
        .rejects("KOE1 grant")?;
    Fixture::released(TME1_A)?
        .tme1(&[2], attempt)?
        .rejects("TME1 attempt")?;
    Fixture::released(TME1_A)?
        .tme1(&[3], digest.clone())?
        .rejects("TME1 grant")?;
    Fixture::released(TME1_A)?
        .tme1(&[4], digest.clone())?
        .rejects("TME1 ELM1")?;
    Fixture::released(TME1_A)?
        .tme1(&[5], digest.clone())?
        .rejects("TME1 KOE1")?;
    let mut unbound = Fixture::released(TME1_A)?;
    unbound.koe1 = with(&unbound.koe1, &[6], digest)?;
    unbound.tme1 = with(
        &unbound.tme1,
        &[5],
        Value::Bytes(wrapped_digest(&unbound.koe1)?.to_vec()),
    )?;
    unbound.rejects("KOE1 RQE1")
}

#[test]
fn rule_6_rqe1_is_not_requested_exactly_at_progress_0() -> TestResult {
    let mut requested = Fixture::not_started()?;
    requested.rqe1 = unhex(RQE1_A)?;
    requested.rebind()?;
    requested.rejects("verified RQE1 at progress 0")?;
    let mut unrequested = Fixture::released(TME1_A)?.tme1(&[26], integer(2))?;
    unrequested.rqe1 = unhex(RQE1_B)?;
    unrequested.rebind()?;
    unrequested.rejects("unrequested RQE1 at progress 2")
}

#[test]
fn rule_4_koe1_binds_the_accepted_ready_v1() -> TestResult {
    let mut missing = Fixture::released(TME1_A)?;
    missing.ready = None;
    missing.rejects("observed without ReadyV1")?;
    let mut unexpected = Fixture::not_started()?;
    unexpected.ready = Some(LauncherReady::new(ready_fields())?);
    unexpected.rejects("not reached with ReadyV1")?;
    let mut other = Fixture::released(TME1_A)?;
    other.ready = Some(LauncherReady::new(LauncherReadyFields {
        nonce: [0x09; 32],
        ..ready_fields()
    })?);
    other.rejects("another ReadyV1")?;

    let failed = Fixture::released(TME1_A)?
        .koe1(&[4], integer(2))?
        .koe1(&[7], Value::Null)?
        .tme1(&[26], integer(2))?;
    failed.accepts()?;
    let mut failed_other = failed;
    failed_other.ready = Some(LauncherReady::new(LauncherReadyFields {
        nonce: [0x09; 32],
        ..ready_fields()
    })?);
    failed_other.rejects("observation failed after another ReadyV1")?;

    for (case, fields) in [
        (
            "invocation",
            LauncherReadyFields {
                launch_instance_id: [0x78; 16],
                ..ready_fields()
            },
        ),
        (
            "launcher",
            LauncherReadyFields {
                launcher_identity: FdIdentity {
                    mount_id: 303,
                    inode: 13,
                },
                ..ready_fields()
            },
        ),
        (
            "adapter",
            LauncherReadyFields {
                adapter_identity: FdIdentity {
                    mount_id: 301,
                    inode: 58,
                },
                ..ready_fields()
            },
        ),
        (
            "expected FDL1",
            LauncherReadyFields {
                expected_fdl1_digest: [0x89; 32],
                ..ready_fields()
            },
        ),
        (
            "observed FDL1",
            LauncherReadyFields {
                observed_fdl1_digest: [0x89; 32],
                ..ready_fields()
            },
        ),
    ] {
        let ready = LauncherReady::new(fields)?;
        let mut fixture =
            Fixture::released(TME1_A)?.koe1(&[5], Value::Bytes(ready.digest.to_vec()))?;
        fixture.ready = Some(ready);
        fixture.rejects(case)?;
    }
    let mut runtime = Fixture::released(TME1_A)?;
    runtime.provider[1].inode += 100;
    runtime.rejects("provider namespaces of another runtime")
}

#[test]
fn rule_4_work_capacity_is_the_limit_rounded_up_to_a_block() -> TestResult {
    let with_limit = |work: u64| -> TestResult<Fixture> {
        let mut fixture = Fixture::released(TME1_A)?;
        fixture.limits = limits(5, work, 1, 0);
        Ok(fixture)
    };
    with_limit(WORK_LIMIT - 61_440)?.accepts()?;
    with_limit(WORK_LIMIT - 65_536)?.rejects("one block too much slack")?;
    with_limit(WORK_LIMIT + 1)?.rejects("capacity below the limit")?;
    let unaligned = with_limit(WORK_LIMIT)?
        .koe1(&[7, 11, 1], integer(WORK_LIMIT + 1))?
        .tme1(&[21, 1], integer(WORK_LIMIT + 1))?;
    unaligned.rejects("capacity off a block boundary")?;
    let unobserved = with_limit(WORK_LIMIT)?
        .koe1(&[7, 11], Value::Null)?
        .tme1(&[26], integer(2))?;
    unobserved.rejects("no KOE1 work with a nonzero limit")?;
    let none = with_limit(0)?
        .koe1(&[7, 11], Value::Null)?
        .tme1(&[21], Value::Null)?;
    none.accepts().map(|_| ())
}

#[test]
fn rule_2_local_network_and_work_after_follow_mode_and_elm1() -> TestResult {
    let network = Value::Array(vec![Value::Null, Value::Bool(false)]);
    let mut local = Fixture::released(TME1_A)?;
    local.mode = SandboxExecutionMode::Local;
    local.rejects("Local released without a proxy session")?;
    let mut proxied = Fixture::released(TME1_A)?.tme1(&[19], network.clone())?;
    proxied.mode = SandboxExecutionMode::Local;
    proxied.accepts()?;
    Fixture::released(TME1_A)?
        .tme1(&[19], network.clone())?
        .rejects("air-gapped with a proxy session")?;

    let mut unbound = Fixture::observed(at_progress(1)?)?;
    unbound.mode = SandboxExecutionMode::Local;
    unbound.accepts()?;
    let mut bound = Fixture::observed(with(&at_progress(1)?, &[19], network.clone())?)?;
    bound.mode = SandboxExecutionMode::Local;
    bound.accepts()?;
    Fixture::observed(with(&at_progress(1)?, &[19], network)?)?
        .rejects("air-gapped started with a proxy session")?;

    let mut unlimited = Fixture::released(TME1_A)?
        .koe1(&[7, 11], Value::Null)?
        .tme1(&[26], integer(2))?;
    unlimited.limits = limits(5, 0, 1, 0);
    unlimited.rejects("work-after without a /work limit")?;
    Fixture::observed(at_progress(1)?)?
        .tme1(&[21], Value::Null)?
        .tme1(&[26], integer(2))?
        .rejects("started with a unit and no work-after")?;
    let unbound = edit(&at_progress(1)?, |fields| {
        for index in [9, 10, 11, 21] {
            fields[index] = Value::Null;
        }
        set(fields, &[24, 1], Value::Null)?;
        fields[26] = integer(2);
        Ok(())
    })?;
    Fixture::observed(unbound)?.accepts().map(|_| ())
}

#[test]
fn rule_9_admission_ledger_and_output_ceiling_are_within_elm1() -> TestResult {
    let ledger = |output, live, incomplete| -> TestResult<Fixture> {
        let mut fixture = Fixture::released(TME1_A)?;
        fixture.limits = limits(output, WORK_LIMIT, live, incomplete);
        Ok(fixture)
    };
    ledger(5, 0, 0)?.rejects("live attempts above ELM1 13")?;
    ledger(5, 1, 0)?
        .tme1(&[20, 1], integer(1))?
        .rejects("incomplete inputs above ELM1 14")?;
    ledger(5, 1, 1)?.tme1(&[20, 1], integer(1))?.accepts()?;
    let ceiling = Value::Array(vec![integer(5), Value::Bool(true), Value::Bool(true)]);
    ledger(5, 1, 0)?
        .tme1(&[17], ceiling.clone())?
        .tme1(&[26], integer(7))?
        .accepts()?;
    ledger(6, 1, 0)?
        .tme1(&[17], ceiling)?
        .tme1(&[26], integer(7))?
        .rejects("ceiling reached below ELM1 8")?;
    for missing in [8, 9, 13, 14] {
        let mut fixture = Fixture::released(TME1_A)?;
        fixture.limits.retain(|limit| limit.limit_id != missing);
        fixture.rejects(&format!("ELM1 {missing} missing"))?;
    }
    Ok(())
}

#[test]
fn rule_7_contradiction_and_terminal_code_are_recomputed() -> TestResult {
    Fixture::released(TME1_A)?
        .tme1(&[26], integer(8))?
        .rejects("Completed recorded as a crash")?;
    Fixture::released(TME1_A)?
        .tme1(&[12], integer(0))?
        .rejects("a contradiction that does not hold")?;
    Fixture::released(TME1_B)?
        .tme1(&[12], Value::Null)?
        .rejects("an omitted contradiction")
}

/// TME1-A's successor: the output transfer timed out.
fn successor_of(previous: &[u8]) -> TestResult<Vec<u8>> {
    edit(previous, |fields| {
        fields[18] = Value::Array(vec![
            integer(1_001_000_000_000),
            integer(1_002_000_000_000),
            integer(1_003_000_000_000),
            integer(5),
            integer(3),
            Value::Bool(false),
        ]);
        fields[25] = Value::Bytes(wrapped_digest(previous)?.to_vec());
        fields[26] = integer(10);
        Ok(())
    })
}

#[test]
fn rule_7_a_successor_copies_its_one_predecessor() -> TestResult {
    let first = Fixture::released(TME1_A)?;
    let successor = |change: &dyn Fn(&mut Vec<Value>) -> TestResult| -> TestResult<Fixture> {
        let mut fixture = Fixture::released(TME1_A)?;
        fixture.tme1 = edit(&successor_of(&first.tme1)?, |fields| change(fields))?;
        fixture.previous = Some(first.tme1.clone());
        Ok(fixture)
    };
    successor(&|_| Ok(()))?.accepts()?;
    let mut orphan = successor(&|_| Ok(()))?;
    orphan.previous = None;
    orphan.rejects("a successor without its predecessor")?;
    let mut first_with_previous = Fixture::released(TME1_A)?;
    first_with_previous.previous = Some(first.tme1.clone());
    first_with_previous.rejects("a first TME1 given a predecessor")?;
    let mut wrong = successor(&|_| Ok(()))?;
    wrong.previous = Some(Fixture::released(TME1_C)?.tme1);
    wrong.rejects("another predecessor")?;
    successor(&|fields| set(fields, &[22], integer(1_005_000_000_001)))?
        .rejects("a changed field")?;
    successor(&|fields| {
        set(fields, &[18, 4], integer(5))?;
        set(fields, &[18, 2], integer(1_001_500_000_000))?;
        set(fields, &[18, 5], Value::Bool(true))?;
        set(fields, &[26], Value::Null)
    })?
    .rejects("a complete output transfer")?;
    successor(&|fields| {
        set(fields, &[18], Value::Null)?;
        set(fields, &[26], Value::Null)
    })?
    .rejects("no output transfer")?;

    let second = successor_of(&successor(&|_| Ok(()))?.tme1)?;
    let mut chained = Fixture::released(TME1_A)?;
    chained.previous = Some(successor(&|_| Ok(()))?.tme1);
    chained.tme1 = second;
    chained.rejects("a successor of a successor")
}

fn receipt(fixture: &Fixture) -> TestResult<SandboxProviderReceipt> {
    let (requested, observed, termination, _) = fixture.records()?;
    Ok(SandboxProviderReceipt {
        attempt_id: [0x11; 16],
        authority: ReceiptAuthority {
            agr1_digest: [0x22; 32],
            spm1_digest: [0x40; 32],
            provider_binary_digest: [0x41; 32],
            lps1_digest: [0x42; 32],
            sim1_digest: [0x43; 32],
            apt1_digest: [0x44; 32],
            trs1_digest: [0x45; 32],
            rvs1_digest: [0x46; 32],
        },
        trust_epoch: 1,
        revocation_epoch: 1,
        policy_epoch: 1,
        hcp1_digest: [0x47; 32],
        elm1_digest: [0x33; 32],
        network_transcript_digests: Vec::new(),
        ready1_digest: fixture.ready.as_ref().map(|ready| ready.digest),
        release1_digest: (termination.fields().progress
            == pos_reference::sandbox_provider_protocol::AttemptProgressCode::Released)
            .then_some([0x48; 32]),
        requested_configuration_evidence: requested.digest(),
        kernel_observation_evidence: observed.digest(),
        negative_probe_evidence: [0x49; 32],
        termination_evidence: termination.digest(),
        sau1_digest: [0x4a; 32],
        runtime_attestation_key_id: "runtime".to_owned(),
        receipt_digest: [0x4b; 32],
        signature: [0x4c; 64],
    })
}

#[test]
fn rules_5_and_6_spr1_binds_the_records() -> TestResult {
    for fixture in [Fixture::released(TME1_A)?, Fixture::not_started()?] {
        let evidence = fixture.accepts()?;
        let bound = receipt(&fixture)?;
        assert_eq!(evidence.verify_receipt(&bound), Ok(()));
        let released = bound.release1_digest.is_some();
        let changes: Vec<(&str, Box<dyn Fn(&mut SandboxProviderReceipt)>)> = vec![
            (
                "attempt",
                Box::new(|receipt| receipt.attempt_id = [0x12; 16]),
            ),
            (
                "grant",
                Box::new(|receipt| receipt.authority.agr1_digest = [0x23; 32]),
            ),
            ("ELM1", Box::new(|receipt| receipt.elm1_digest = [0x34; 32])),
            (
                "ordinal 19",
                Box::new(|receipt| receipt.requested_configuration_evidence = [0x5a; 32]),
            ),
            (
                "ordinal 20",
                Box::new(|receipt| receipt.kernel_observation_evidence = [0x5a; 32]),
            ),
            (
                "ordinal 22",
                Box::new(|receipt| receipt.termination_evidence = [0x5a; 32]),
            ),
            (
                "ReadyV1",
                Box::new(|receipt| {
                    receipt.ready1_digest = receipt.ready1_digest.xor(Some([0x5b; 32]));
                }),
            ),
            (
                "ReleaseV1",
                Box::new(move |receipt| {
                    receipt.release1_digest = (!released).then_some([0x48; 32]);
                }),
            ),
        ];
        for (case, mutate) in changes {
            let mut changed = bound.clone();
            mutate(&mut changed);
            assert_eq!(
                evidence.verify_receipt(&changed),
                Err(ProtocolError::InconsistentFields),
                "{case}"
            );
        }
    }
    Ok(())
}
