//! `AttemptEvidence`: R9 §6 rules 4 to 7 and 9 across RQE1, KOE1, TME1,
//! the grant, ELM1, `ReadyV1` and SPR1, with the R14 §3.5 additions to
//! rules 2 and 4.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use ciborium::value::Value;
use pos_reference::sandbox_provider_protocol::{
    AttemptEvidence, AttemptEvidenceContext, Contradiction, EffectiveLimitRecord, FdIdentity,
    KernelObservationEvidence, LauncherReady, LauncherReadyFields, NamespaceIdentity,
    ReceiptAuthority, RequestedConfigurationEvidence, SandboxArchitecture, SandboxExecutionMode,
    SandboxLimit, SandboxProviderProtocolError as ProtocolError, SandboxProviderReceipt,
    SandboxProviderReceiptFields, TerminalCode, TerminationEvidence,
};

use super::network_readback::{list_at, vector_d_endpoints, READBACK};
use super::observed::provider_namespaces;
use super::oracle::{
    edit, filled, integer, self_digest, set, text, unhex, with, wrapped_digest, TestResult,
};
use super::response::{runtime_key, sign};
use super::terminated::at_progress;
use super::vectors::{
    KOE1_A, KOE1_B, KOE1_C, KOE1_D, RQE1_A, RQE1_B, TME1_A, TME1_B, TME1_C, TME1_D, TME1_E, TME1_F,
    TME1_G, TME1_H,
};

const WORK_LIMIT: u64 = 1_048_576;
/// ELM1\[8\]: exactly the 70 bytes of `S` that TME1-A captures (R10 §8.3).
const OUTPUT_LIMIT: u64 = 70;

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

/// The decoded RQE1, KOE1 and TME1, and the TME1 they succeed.
pub(super) type Records = (
    RequestedConfigurationEvidence,
    KernelObservationEvidence,
    TerminationEvidence,
    Option<TerminationEvidence>,
);

/// The ELM1 fields besides its limits.
const BROKER_CAPS: [u8; 32] = [0x61; 32];
pub(super) const APT1: [u8; 32] = [0x62; 32];
pub(super) const LPS1: [u8; 32] = [0x63; 32];
const PROFILE: [u8; 32] = [0x64; 32];
const FIXTURE: [u8; 32] = [0x65; 32];
pub(super) const RUNTIME_KEY: &str = "runtime";

/// The ELM1 self-digest of `limits`, by the oracle.
pub(super) fn elm1_digest(limits: &[SandboxLimit]) -> TestResult<[u8; 32]> {
    let limits = limits
        .iter()
        .map(|limit| {
            Value::Array(vec![
                integer(u64::from(limit.limit_id)),
                integer(limit.value),
            ])
        })
        .collect();
    self_digest(
        "ELM1",
        &Value::Array(vec![
            text("ELM1"),
            integer(1),
            Value::Array(limits),
            Value::Bytes(BROKER_CAPS.to_vec()),
            Value::Bytes(APT1.to_vec()),
            Value::Bytes(LPS1.to_vec()),
            Value::Bytes(PROFILE.to_vec()),
            Value::Bytes(FIXTURE.to_vec()),
            text(RUNTIME_KEY),
        ]),
    )
}

/// One attempt's records and what a verifier holds, with the records'
/// digest bindings kept intact as they are edited.
pub(super) struct Fixture {
    rqe1: Vec<u8>,
    koe1: Vec<u8>,
    tme1: Vec<u8>,
    previous: Option<Vec<u8>>,
    pub(super) ready: Option<LauncherReady>,
    pub(super) limits: Vec<SandboxLimit>,
    broker_caps: [u8; 32],
    mode: SandboxExecutionMode,
    architecture: SandboxArchitecture,
    provider: [NamespaceIdentity; 6],
    pub(super) grant: ([u8; 16], [u8; 32]),
    elm1: Option<[u8; 32]>,
    endpoints: Vec<SocketAddr>,
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
            limits: limits(OUTPUT_LIMIT, WORK_LIMIT, 1, 0),
            broker_caps: BROKER_CAPS,
            mode: SandboxExecutionMode::AirGapped,
            architecture: SandboxArchitecture::X86_64,
            provider: provider_namespaces(),
            grant: ([0x11; 16], [0x22; 32]),
            elm1: None,
            endpoints: Vec::new(),
        };
        fixture.rebind()?;
        Ok(fixture)
    }

    pub(super) fn released(vector: &str) -> TestResult<Self> {
        Self::observed(unhex(vector)?)
    }

    /// The Local attempt of `fixture`, whose status-0 KOE1 holds the
    /// readback of `koe1` (R14 KOE1-C or -D) under `endpoints`.
    fn local(mut self, koe1: &str, endpoints: Vec<SocketAddr>) -> TestResult<Self> {
        let readback =
            super::oracle::at(&mut super::oracle::unsigned(&unhex(koe1)?)?, &READBACK)?.clone();
        self.mode = SandboxExecutionMode::Local;
        self.endpoints = endpoints;
        self.koe1(&READBACK, readback)
    }

    /// RQE1-B, KOE1-B and a progress-0 TME1: nothing was started.
    pub(super) fn not_started() -> TestResult<Self> {
        Self::unstarted(at_progress(0)?)
    }

    /// RQE1-B, KOE1-B and the progress-0 `tme1`.
    fn unstarted(tme1: Vec<u8>) -> TestResult<Self> {
        let mut fixture = Self::observed(tme1)?;
        fixture.rqe1 = unhex(RQE1_B)?;
        fixture.koe1 = unhex(KOE1_B)?;
        fixture.ready = None;
        fixture.rebind()?;
        Ok(fixture)
    }

    /// KOE1 binds RQE1, and TME1 binds KOE1 and ELM1.
    fn rebind(&mut self) -> TestResult {
        self.koe1 = with(
            &self.koe1,
            &[6],
            Value::Bytes(wrapped_digest(&self.rqe1)?.to_vec()),
        )?;
        let elm1 = elm1_digest(&self.limits)?;
        self.tme1 = edit(&self.tme1, |fields| {
            fields[4] = Value::Bytes(elm1.to_vec());
            fields[5] = Value::Bytes(wrapped_digest(&self.koe1)?.to_vec());
            Ok(())
        })?;
        Ok(())
    }

    fn with_limits(mut self, limits: Vec<SandboxLimit>) -> TestResult<Self> {
        self.limits = limits;
        self.rebind().map(|()| self)
    }

    pub(super) fn rqe1(mut self, path: &[usize], value: Value) -> TestResult<Self> {
        self.rqe1 = with(&self.rqe1, path, value)?;
        self.rebind().map(|()| self)
    }

    pub(super) fn koe1(mut self, path: &[usize], value: Value) -> TestResult<Self> {
        self.koe1 = with(&self.koe1, path, value)?;
        self.rebind().map(|()| self)
    }

    pub(super) fn tme1(mut self, path: &[usize], value: Value) -> TestResult<Self> {
        self.tme1 = with(&self.tme1, path, value)?;
        Ok(self)
    }

    pub(super) fn records(&self) -> TestResult<Records> {
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
        let (attempt_id, agr1_digest) = self.grant;
        let context = AttemptEvidenceContext {
            attempt_id,
            agr1_digest,
            elm1_digest: self.elm1.map_or_else(|| elm1_digest(&self.limits), Ok)?,
            limits: EffectiveLimitRecord {
                limits: &self.limits,
                broker_caps_digest: self.broker_caps,
                apt1_digest: APT1,
                lps1_digest: LPS1,
                execution_profile_digest: PROFILE,
                fixture_digest: FIXTURE,
                runtime_attestation_key_id: RUNTIME_KEY,
            },
            mode: self.mode,
            architecture: self.architecture,
            ready: self.ready.as_ref(),
            provider_namespaces: &self.provider,
            planned_endpoints: &self.endpoints,
        };
        // A predecessor is presented only as verified evidence.
        let previous = match previous {
            Some(termination) => match AttemptEvidence::verify(
                requested.clone(),
                observed.clone(),
                termination,
                None,
                &context,
            ) {
                Ok(previous) => Some(previous),
                Err(error) => return Ok(Err(error)),
            },
            None => None,
        };
        Ok(AttemptEvidence::verify(
            requested,
            observed,
            termination,
            previous.as_ref(),
            &context,
        ))
    }

    pub(super) fn accepts(&self) -> TestResult<AttemptEvidence> {
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
        (
            Fixture::released(TME1_D)?.with_limits(limits(OUTPUT_LIMIT - 1, WORK_LIMIT, 1, 0))?,
            None,
            Some(TerminalCode::FileOrOutputLimit),
        ),
        (
            Fixture::released(TME1_E)?,
            None,
            Some(TerminalCode::ProtocolFailure),
        ),
        (
            Fixture::unstarted(unhex(TME1_F)?)?,
            None,
            Some(TerminalCode::ProtocolFailure),
        ),
    ] {
        let (requested, observed, termination, _) = fixture.records()?;
        fixture.accepts()?;
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
    other_limits.elm1 = Some([0x34; 32]);
    other_limits.rejects("context ELM1")?;
    let mut unbound_limits = Fixture::released(TME1_A)?;
    unbound_limits.broker_caps = [0x66; 32];
    unbound_limits.rejects("ELM1 limits that do not digest to the grant's ELM1")?;
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

    // A failed KOE1 opened no `/work`, so `work-after` is null. Nothing
    // else is a candidate, so the cascade ends in the fail-closed fallback,
    // code 2 (R9 §4.6.5): a released attempt Completes only after a
    // status-0 KOE1.
    let failed = Fixture::released(TME1_A)?
        .koe1(&[4], integer(2))?
        .koe1(&[7], Value::Null)?
        .tme1(&[21], Value::Null)?
        .tme1(&[26], integer(2))?;
    let (requested, observed, termination, _) = failed.records()?;
    failed.accepts()?;
    let classification = termination.facts(&requested, &observed).classify();
    assert_eq!(classification.code(), Some(TerminalCode::CleanupFailed));
    assert!(!classification
        .candidates()
        .contains(TerminalCode::CleanupFailed));
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

/// TME1-A with `/work` capacity `capacity` in KOE1 and `work-after`,
/// verified against ELM1 limit 9 `limit`.
fn work(limit: u64, capacity: u64) -> TestResult<Fixture> {
    Fixture::released(TME1_A)?
        .with_limits(limits(OUTPUT_LIMIT, limit, 1, 0))?
        .koe1(&[7, 11, 1], integer(capacity))?
        .tme1(&[21, 1], integer(capacity))
}

#[test]
fn rule_4_work_capacity_is_exactly_the_limit_rounded_up_to_a_block() -> TestResult {
    work(WORK_LIMIT, WORK_LIMIT)?.accepts()?;
    work(WORK_LIMIT, WORK_LIMIT - 4096)?.rejects("one block below the exact capacity")?;
    work(WORK_LIMIT, WORK_LIMIT + 4096)?.rejects("one block above the exact capacity")?;
    // 1_000_000 rounds up to 1_003_520 (4 KiB), 1_015_808 (16 KiB) and
    // 1_048_576 (64 KiB) blocks. An x86_64 host has only 4 KiB pages.
    work(1_000_000, 1_003_520)?.accepts()?;
    for capacity in [1_015_808, 1_048_576] {
        work(1_000_000, capacity)?.rejects("an x86_64 capacity rounded to a larger page")?;
    }
    // An aarch64 host may use any of its three page sizes.
    for capacity in [1_003_520, 1_015_808, 1_048_576] {
        let mut arm = work(1_000_000, capacity)?;
        arm.architecture = SandboxArchitecture::Aarch64;
        arm.accepts()?;
    }
    let mut arm = work(1_000_000, 1_007_616)?;
    arm.architecture = SandboxArchitecture::Aarch64;
    arm.rejects("a multiple of no page size's rounding")?;
    work(1_000_000, 1_000_001)?.rejects("an unaligned capacity")?;
    // The rounding of a limit near `u64::MAX` overflows and is refused.
    work(u64::MAX - 1, u64::MAX)?.rejects("a rounding that overflows")?;
    let unobserved = Fixture::released(TME1_A)?
        .koe1(&[7, 11], Value::Null)?
        .tme1(&[26], integer(2))?;
    unobserved.rejects("no KOE1 work with a nonzero limit")?;
    let none = Fixture::released(TME1_A)?
        .with_limits(limits(OUTPUT_LIMIT, 0, 1, 0))?
        .koe1(&[7, 11], Value::Null)?
        .tme1(&[21], Value::Null)?;
    none.accepts().map(|_| ())
}

#[test]
fn rule_2_local_network_and_work_after_follow_mode_and_elm1() -> TestResult {
    let network = Value::Array(vec![Value::Null, Value::Bool(false)]);
    Fixture::released(TME1_A)?
        .local(KOE1_C, Vec::new())?
        .rejects("Local released without a proxy session")?;
    Fixture::released(TME1_A)?
        .tme1(&[19], network.clone())?
        .local(KOE1_C, Vec::new())?
        .accepts()?;
    Fixture::released(TME1_A)?
        .tme1(&[19], network.clone())?
        .rejects("air-gapped with a proxy session")?;

    Fixture::observed(at_progress(1)?)?
        .local(KOE1_C, Vec::new())?
        .accepts()?;
    Fixture::observed(with(&at_progress(1)?, &[19], network.clone())?)?
        .local(KOE1_C, Vec::new())?
        .accepts()?;
    Fixture::observed(with(&at_progress(1)?, &[19], network)?)?
        .rejects("air-gapped started with a proxy session")?;

    let unlimited = Fixture::released(TME1_A)?
        .with_limits(limits(OUTPUT_LIMIT, 0, 1, 0))?
        .koe1(&[7, 11], Value::Null)?
        .tme1(&[26], integer(2))?;
    unlimited.rejects("work-after without a /work limit")?;
    Fixture::observed(at_progress(1)?)?
        .tme1(&[21], Value::Null)?
        .rejects("a null work-after recorded as anything but code 2")?;
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
        Fixture::released(TME1_A)?.with_limits(limits(output, WORK_LIMIT, live, incomplete))
    };
    ledger(OUTPUT_LIMIT, 0, 0)?.rejects("live attempts above ELM1 13")?;
    ledger(OUTPUT_LIMIT, 1, 0)?
        .tme1(&[20, 1], integer(1))?
        .rejects("incomplete inputs above ELM1 14")?;
    ledger(OUTPUT_LIMIT, 1, 1)?
        .tme1(&[20, 1], integer(1))?
        .accepts()?;
    let ceiling = Value::Array(vec![
        integer(OUTPUT_LIMIT),
        Value::Bool(true),
        Value::Bool(false),
    ]);
    ledger(OUTPUT_LIMIT, 1, 0)?
        .tme1(&[17], ceiling.clone())?
        .tme1(&[26], integer(7))?
        .accepts()?;
    ledger(OUTPUT_LIMIT + 1, 1, 0)?
        .tme1(&[17], ceiling)?
        .tme1(&[26], integer(7))?
        .rejects("ceiling reached below ELM1 8")?;
    // Exactly ELM1[8] framed bytes, then end of stream, is Completed.
    ledger(OUTPUT_LIMIT, 1, 0)?.accepts()?;
    ledger(OUTPUT_LIMIT - 1, 1, 0)?.rejects("a capture above ELM1 8")?;
    // TME1-D: the ceiling at ELM1[8] = 69, and the same capture over 68.
    Fixture::released(TME1_D)?
        .with_limits(limits(OUTPUT_LIMIT - 1, WORK_LIMIT, 1, 0))?
        .accepts()?;
    Fixture::released(TME1_D)?
        .with_limits(limits(OUTPUT_LIMIT - 2, WORK_LIMIT, 1, 0))?
        .rejects("TME1-D over ELM1 8 = 68")?;
    for missing in [8, 9, 13, 14] {
        let mut remaining = limits(OUTPUT_LIMIT, WORK_LIMIT, 1, 0);
        remaining.retain(|limit| limit.limit_id != missing);
        Fixture::released(TME1_A)?
            .with_limits(remaining)?
            .rejects(&format!("ELM1 {missing} missing"))?;
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
    chained.rejects("a successor of a successor")?;

    // R9 §4.7: the output transfer is "now present", so a predecessor had
    // none.
    let transferred = Fixture::released(TME1_A)?.tme1(
        &[18],
        Value::Array(vec![
            integer(1_001_000_000_000),
            integer(1_002_000_000_000),
            integer(1_001_500_000_000),
            integer(5),
            integer(5),
            Value::Bool(true),
        ]),
    )?;
    transferred.accepts()?;
    let mut after_transfer = Fixture::released(TME1_A)?;
    after_transfer.tme1 = successor_of(&transferred.tme1)?;
    after_transfer.previous = Some(transferred.tme1);
    after_transfer.rejects("a predecessor whose output transfer had started")
}

/// One named change to an SPR1 that must break its binding.
type ReceiptChange = (&'static str, Box<dyn Fn(&mut SandboxProviderReceipt)>);

fn receipt(fixture: &Fixture) -> TestResult<SandboxProviderReceipt> {
    let (requested, observed, termination, _) = fixture.records()?;
    let record = SandboxProviderReceipt::self_digested(SandboxProviderReceiptFields {
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
        elm1_digest: elm1_digest(&fixture.limits)?,
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
    })?;
    let key = runtime_key();
    Ok(SandboxProviderReceipt::new(
        sign(record, &key)?,
        &key.verifying_key(),
    )?)
}

#[test]
fn rules_5_and_6_spr1_binds_the_records() -> TestResult {
    for fixture in [Fixture::released(TME1_A)?, Fixture::not_started()?] {
        let evidence = fixture.accepts()?;
        let bound = receipt(&fixture)?;
        assert_eq!(evidence.verify_receipt(&bound), Ok(()));
        let released = bound.release1_digest.is_some();
        let changes: Vec<ReceiptChange> = vec![
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
            let mut altered = bound.clone();
            mutate(&mut altered);
            assert_eq!(
                evidence.verify_receipt(&altered),
                Err(ProtocolError::InconsistentFields),
                "{case}"
            );
        }
    }
    Ok(())
}

#[test]
fn r10_rule_7_the_feed_and_launch_failures_select_their_codes() -> TestResult {
    // A released attempt without `adapter-input` lacks evidence: code 2.
    Fixture::released(TME1_A)?
        .tme1(&[27], Value::Null)?
        .tme1(&[26], integer(2))?
        .accepts()?;
    Fixture::released(TME1_A)?
        .tme1(&[27], Value::Null)?
        .rejects("Completed without the stdin feed")?;
    // A closed ledger quarantines (code 2); a channel failure is code 9.
    for (failure, code) in [(5, 2), (4, 9)] {
        let record = edit(&unhex(TME1_F)?, |fields| {
            set(fields, &[7], integer(failure))?;
            set(fields, &[26], integer(code))
        })?;
        Fixture::unstarted(record.clone())?.accepts()?;
        Fixture::unstarted(with(&record, &[26], integer(10))?)?
            .rejects(&format!("launch failure {failure} as code 10"))?;
    }
    Fixture::released(TME1_E)?
        .tme1(&[26], Value::Null)?
        .rejects("an incomplete feed recorded as Completed")
}

/// `work-after` is present only when ELM1 limit 9 is nonzero and KOE1 has
/// status 0 (owner decision 2026-11-19, R9 amendment review).
#[test]
fn rule_2_work_after_follows_a_status_0_koe1() -> TestResult {
    // Status 0 with `work-after`: unchanged.
    let present = Fixture::released(TME1_A)?;
    let (requested, observed, termination, _) = present.records()?;
    present.accepts()?;
    assert_eq!(
        termination.facts(&requested, &observed).classify().code(),
        None
    );
    // Status 0 with a null `work-after`: missing evidence, code 2 and
    // quarantine; the D5 `/work` identity check is skipped.
    let unread = Fixture::released(TME1_A)?
        .tme1(&[21], Value::Null)?
        .tme1(&[26], integer(2))?;
    let (requested, observed, termination, _) = unread.records()?;
    unread.accepts()?;
    let classification = termination.facts(&requested, &observed).classify();
    assert_eq!(classification.contradiction(), None);
    assert_eq!(classification.code(), Some(TerminalCode::CleanupFailed));
    assert!(classification.quarantined());
    // Status 2 (observation failed) and status 1 (not reached) with limit 9
    // nonzero: a null `work-after` is valid and the cascade code stands.
    let failed = Fixture::observed(with(&at_progress(1)?, &[21], Value::Null)?)?
        .koe1(&[4], integer(2))?
        .koe1(&[7], Value::Null)?;
    let not_reached = |work_after: bool| -> TestResult<Fixture> {
        let mut fixture = Fixture::observed(edit(&at_progress(1)?, |fields| {
            if !work_after {
                fields[21] = Value::Null;
            }
            fields[15] = integer(0);
            fields[26] = integer(9);
            Ok(())
        })?)?;
        fixture.koe1 = unhex(KOE1_B)?;
        fixture.ready = None;
        fixture.rebind()?;
        Ok(fixture)
    };
    for (fixture, code) in [
        (failed, TerminalCode::ProtocolFailure),
        (not_reached(false)?, TerminalCode::IpcFailure),
    ] {
        let (requested, observed, termination, _) = fixture.records()?;
        fixture.accepts()?;
        let classification = termination.facts(&requested, &observed).classify();
        assert_eq!(classification.code(), Some(code));
        assert!(!classification.quarantined());
    }
    // ... and a present one is refused after a not-reached or failed KOE1.
    not_reached(true)?.rejects("work-after after a not-reached KOE1")?;
    Fixture::observed(at_progress(1)?)?
        .koe1(&[4], integer(2))?
        .koe1(&[7], Value::Null)?
        .rejects("work-after after a failed KOE1")?;
    // Limit 9 zero with `work-after`: still refused.
    Fixture::released(TME1_A)?
        .with_limits(limits(OUTPUT_LIMIT, 0, 1, 0))?
        .koe1(&[7, 11], Value::Null)?
        .tme1(&[26], integer(2))?
        .rejects("work-after without a /work limit")
}

/// A released Local attempt whose KOE1 holds the readback of `koe1`.
fn local_released(koe1: &str, endpoints: Vec<SocketAddr>) -> TestResult<Fixture> {
    let network = Value::Array(vec![Value::Null, Value::Bool(false)]);
    Fixture::released(TME1_A)?
        .tme1(&[19], network)?
        .local(koe1, endpoints)
}

/// One `network-readback` field of a fixture's KOE1.
fn readback_path(path: &[usize]) -> Vec<usize> {
    READBACK.iter().chain(path).copied().collect()
}

/// R14 rule 2: a status-0 KOE1 has a `network-readback` exactly in Local
/// mode, and rule 4 accepts KOE1-C under a Local AGR1 with empty plans.
#[test]
fn r14_rule_2_the_network_readback_follows_the_mode() -> TestResult {
    local_released(KOE1_C, Vec::new())?.accepts()?;
    for mode in [
        SandboxExecutionMode::AirGapped,
        SandboxExecutionMode::Replay,
        SandboxExecutionMode::Fork,
    ] {
        // (e) a readback in KOE1-A, outside Local mode.
        let mut present = local_released(KOE1_C, Vec::new())?;
        present.mode = mode;
        present.rejects(&format!("a readback in {mode:?}"))?;
        let mut absent = Fixture::released(TME1_A)?;
        absent.mode = mode;
        absent.accepts()?;
    }
    // (f) null in a Local status-0 KOE1.
    local_released(KOE1_C, Vec::new())?
        .koe1(&READBACK, Value::Null)?
        .rejects("a Local status-0 KOE1 without a readback")?;
    // A status-1 or status-2 KOE1 has no observation, so no readback.
    let mut unstarted = Fixture::not_started()?;
    unstarted.mode = SandboxExecutionMode::Local;
    unstarted.accepts().map(|_| ())
}

fn ipv4_endpoint(octets: [u8; 4], port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port)
}

/// R14 rule 4: the routes, chains and egress lists follow the planned
/// endpoints, mapped and distinct, in any order.
#[test]
fn r14_rule_4_the_readback_follows_the_planned_endpoints() -> TestResult {
    let [web, ipv6_endpoint] = vector_d_endpoints();
    let mapped = SocketAddr::new(
        IpAddr::V6(Ipv4Addr::new(203, 0, 113, 10).to_ipv6_mapped()),
        443,
    );
    for endpoints in [
        vec![web, ipv6_endpoint],
        vec![ipv6_endpoint, web],
        vec![web, ipv6_endpoint, web],
        vec![mapped, ipv6_endpoint],
    ] {
        local_released(KOE1_D, endpoints)?.accepts()?;
    }
    for (koe1, endpoints, case) in [
        (KOE1_D, Vec::new(), "KOE1-D without plans"),
        (KOE1_D, vec![web], "KOE1-D without the IPv6 endpoint"),
        (
            KOE1_D,
            vec![ipv6_endpoint],
            "KOE1-D without the IPv4 endpoint",
        ),
        (
            KOE1_D,
            vec![ipv4_endpoint([203, 0, 113, 10], 444), ipv6_endpoint],
            "another port",
        ),
        (KOE1_C, vec![web], "KOE1-C with a planned endpoint"),
    ] {
        local_released(koe1, endpoints)?.rejects(case)?;
    }
    Ok(())
}

fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}

/// R14 rule 4: each route, chain and egress condition, one field at a
/// time, over KOE1-C and KOE1-D.
#[test]
fn r14_rule_4_routes_chains_and_egress_are_exact() -> TestResult {
    let endpoints = || vector_d_endpoints().to_vec();
    let web = Value::Array(vec![bytes(&[203, 0, 113, 10]), integer(443)]);
    let reject_d = |path: &[usize], value: Value, case: &str| -> TestResult {
        local_released(KOE1_D, endpoints())?
            .koe1(&readback_path(path), value)?
            .rejects(case)
    };
    // Routes: each gateway and each connected route.
    reject_d(
        &[8, 1, 1],
        bytes(&[10, 200, 0, 14]),
        "an IPv4 host route via N+2",
    )?;
    let ipv6_gateway = Ipv6Addr::new(0xfd70, 0x6967, 0x6c6f, 0, 0, 0, 0, 7);
    reject_d(
        &[8, 2, 1],
        bytes(&ipv6_gateway.octets()),
        "an IPv6 host route via M+1",
    )?;
    reject_d(&[8, 0, 0, 1], integer(29), "a /29 connected route")?;
    reject_d(
        &[8, 3, 1],
        bytes(&[0xfd; 16]),
        "a connected IPv6 route via a gateway",
    )?;
    // Chains: hook, priority, policy, regular chain, rules and names.
    reject_d(&[10, 0, 1, 0], integer(2), "input at the output hook")?;
    reject_d(&[10, 2, 1, 1], integer(1), "forward at priority 1")?;
    reject_d(&[10, 1, 1, 2], integer(0), "an accepting output chain")?;
    reject_d(&[10, 2, 1], Value::Null, "a regular forward chain")?;
    reject_d(
        &[10, 0, 2],
        Value::Array(vec![
            Value::Array(vec![integer(1)]),
            Value::Array(vec![integer(0)]),
        ]),
        "reordered input rules",
    )?;
    reject_d(
        &[10, 2, 2],
        Value::Array(vec![Value::Array(vec![integer(0)])]),
        "a forward rule",
    )?;
    reject_d(
        &[10, 1, 2, 1, 2],
        integer(127),
        "neighbour discovery to M/127",
    )?;
    reject_d(
        &[10, 0, 0],
        Value::Text("inputs".to_owned()),
        "a chain named inputs",
    )?;
    // (d) the output rules reordered.
    let reordered = local_released(KOE1_D, endpoints())?;
    let mut rules = list_at(&unhex(KOE1_D)?, &readback_path(&[10, 1, 2]))?;
    rules.swap(2, 3);
    reordered
        .koe1(&readback_path(&[10, 1, 2]), Value::Array(rules))?
        .rejects("reordered output rules")?;
    // Egress: each list is exactly the IPv4 endpoints.
    reject_d(&[11], Value::Array(Vec::new()), "nothing allowed")?;
    reject_d(&[12], Value::Array(Vec::new()), "nothing masqueraded")?;
    for index in [11, 12] {
        local_released(KOE1_C, Vec::new())?
            .koe1(&readback_path(&[index]), Value::Array(vec![web.clone()]))?
            .rejects(&format!("egress list {index} without a plan"))?;
    }
    Ok(())
}

/// R14 rule 2 and §4.6: launch failure 6 only in Local mode and 7 only in
/// Replay mode, both at progress 0; codes 9 and 10, never a quarantine.
#[test]
fn r14_launch_failures_6_and_7_follow_their_modes() -> TestResult {
    for (vector, mode, code) in [
        (
            TME1_G,
            SandboxExecutionMode::Local,
            TerminalCode::IpcFailure,
        ),
        (
            TME1_H,
            SandboxExecutionMode::Replay,
            TerminalCode::ProtocolFailure,
        ),
    ] {
        let mut fixture = Fixture::unstarted(unhex(vector)?)?;
        fixture.mode = mode;
        let (requested, observed, termination, _) = fixture.records()?;
        fixture.accepts()?;
        let classification = termination.facts(&requested, &observed).classify();
        assert_eq!(classification.code(), Some(code));
        assert!(!classification.quarantined());
    }
    for (vector, mode) in [
        (TME1_G, SandboxExecutionMode::Replay),
        (TME1_G, SandboxExecutionMode::AirGapped),
        (TME1_G, SandboxExecutionMode::Fork),
        (TME1_H, SandboxExecutionMode::Local),
        (TME1_H, SandboxExecutionMode::AirGapped),
        (TME1_H, SandboxExecutionMode::Fork),
    ] {
        let mut fixture = Fixture::unstarted(unhex(vector)?)?;
        fixture.mode = mode;
        fixture.rejects(&format!("{mode:?}"))?;
    }
    Ok(())
}
