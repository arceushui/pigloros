#![cfg(target_os = "linux")]

//! R8-S1 to R8-S11: the acceptance tests of the community Plugin conformance profile (ADR-061
//! revision 8, S5), on the real `pos-plugin-worker`, and R7-F2: the `downgrade` family through
//! the production rollback entry (ADR-103 revision 7 decision 4.6).
//!
//! The attempts are built from the checked-in files of `fixtures/conformance` and run through
//! the adapter library's `run_with` with a recording runner. The runner interprets each
//! sub-case over the real evaluation port (`EvaluationStepPortV1`, which launches the worker
//! binary of this package) and keeps the sub-case record and the committed Events and state
//! around every pass. Each family runs once per Execution Mode and the tests share the result.
//! The tests assert nothing about wall time; the per-launch watchdog of the supervisor is the
//! adapter's constant. Every result here is Local-relaxation engineering evidence.
//!
//! `worker_launches` of a sub-case record, and the launches the recording port captures around
//! each pass, are the supervisors' own count of launched workers (#660). R8-S9 checks that every
//! pass of a launching sub-case launched exactly one worker, so a reused worker fails it, and
//! the "baseline plus three launches" control of R8-S2 uses the same count. The evaluator-path
//! half of R8-S8 lives in `crates/pos-reference/tests/plugin_subject_public.rs`.
//!
//! The sharing of a family run between tests (`OnceLock`) assumes the single-process `cargo
//! test` runner; under nextest every test is its own process and recomputes the runs it uses.

pub mod support;

use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use pos_plugin_conformance_adapter::payload::{StepV1, SubCaseV1};
use pos_plugin_conformance_adapter::world::{
    interpret, outcome_bytes_of, BindArgsV1, InstallArgsV1, PassArgsV1, RefreshArgsV1,
    RollbackArgsV1, SetupArgsV1, StepPortV1, SubCaseRecordV1,
};
use pos_plugin_conformance_adapter::{
    run_with, AdapterRunErrorV1, EvaluationStepPortV1, PiecesV1, SubCaseRunnerV1,
    SupervisorRunnerV1,
};
use pos_plugin_supervisor::{
    CommunityPluginSubjectOutcomeV1 as Outcome, CommunityPluginSubjectResultV1 as Verdict,
    ContentValidationV1, WorkerProgramV1,
};
use pos_reference::adapter_transport::{read_observation, write_attempt};
use pos_reference::evaluator::{CaseAttempt, ResourceUsage, SubjectObservation, SubjectResult};
use pos_reference::evaluator_domain::{ExecutionMode, FixtureFamily};
use pos_reference::profile::DeterministicBudget;
use pos_runtime::community_plugin_host::{
    CommunityPluginHostErrorV1, CommunityPluginModeV1, ReleaseIdentityV1, RevocationBasisV1,
    TrustDenialBasisV1,
};
use serde_json::Value;
use support::attempts::{
    attempt_from_fixture_files, family_budget, oracle_bytes, rewrite_subcases,
};
use support::subcase::{
    assert_output_is_the_oracle, assert_within_budget, expecting, failure, observe_attempt,
    one_subcase, WORKER,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The committed Events (payload bytes) and the Driver's committed state.
#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    events: Vec<Vec<u8>>,
    state: Vec<u8>,
}

const MODES: [ExecutionMode; 2] = [ExecutionMode::Local, ExecutionMode::AirGapped];

/// The BLAKE3 of the public input of `ind.1`; `pos-reference`'s `plugin_subject_public.rs`
/// asserts the same literal.
const IND1_DIGEST: &str = "92adc8f0b327b091f85e847d3fa1f7cb46e16bdd74f389d79b2e61171c2715c3";

/// The first six bytes of a `PCW2` composite.
const COMPOSITE_HEADER: [u8; 6] = [0x83, 0x64, 0x50, 0x43, 0x57, 0x32];

/// The keys that would claim a safety property.
const FORBIDDEN_KEYS: [&str; 5] = ["signature", "verified", "safe", "safety", "quality"];

/// The Plugin ID of the compatibility prototype guests.
const PLUGIN_ID: &str = "pigloros.compatibility-prototype";

/// ADR-068 R4 test 8: the usage the real worker measures for `pos.3`, two committed passes of
/// the Rust guest (Simulation Time 42 then 43), each one 8-byte Event and an 8-byte next state,
/// and so for the `positive` case, the per-counter maximum over its sub-cases (ADR-068 R4 4.2).
/// The evaluator half, `crates/pos-reference/tests/plugin_subject_public.rs`, asserts the same
/// literal (`MEASURED_POSITIVE_USAGE`) at and one below its budget; keep the two in step.
const POSITIVE_USAGE: ResourceUsage = ResourceUsage {
    memory_bytes: 1_179_648,
    cpu_fuel: 42_604,
    host_calls: 6,
    event_count: 2,
    output_bytes: 16,
    storage_bytes: 16,
    execution_steps: 2,
    simulation_time_ns: 1,
};

/// The usage of `pos.1`, one committed pass of the Rust guest.
const RUST_ONE_PASS_USAGE: ResourceUsage = ResourceUsage {
    memory_bytes: 1_179_648,
    cpu_fuel: 21_238,
    host_calls: 3,
    event_count: 1,
    output_bytes: 8,
    storage_bytes: 8,
    execution_steps: 1,
    simulation_time_ns: 0,
};

/// The usage of `pos.2`, one committed pass of the C guest.
const C_ONE_PASS_USAGE: ResourceUsage = ResourceUsage {
    memory_bytes: 131_072,
    cpu_fuel: 20_841,
    host_calls: 3,
    event_count: 1,
    output_bytes: 8,
    storage_bytes: 8,
    execution_steps: 1,
    simulation_time_ns: 0,
};

/// The usage of a case none of whose sub-cases commits: 0 for all eight counters.
const NO_USAGE: ResourceUsage = ResourceUsage {
    memory_bytes: 0,
    cpu_fuel: 0,
    host_calls: 0,
    event_count: 0,
    output_bytes: 0,
    storage_bytes: 0,
    execution_steps: 0,
    simulation_time_ns: 0,
};

/// The usage of `deletion-redaction`: `del.1` and `del.2` are each one committed pass of the
/// Rust guest over the same `del.1` observation.
const DELETION_REDACTION_USAGE: ResourceUsage = RUST_ONE_PASS_USAGE;

/// The usage of `independent-evaluation`: `ind.3` is the pass of `pos.1`, and `ind.1`, `ind.2a`,
/// `ind.2b` and `ind.4` run no pass.
const INDEPENDENT_EVALUATION_USAGE: ResourceUsage = RUST_ONE_PASS_USAGE;

/// ADR-061 R11: the usage the real worker measures for each family in Local and Air-Gapped, the
/// per-counter maximum over its sub-cases (ADR-068 R4 4.2(2)). Only a committed sub-case reports
/// usage, so the four failure families report none. The evaluator half,
/// `crates/pos-reference/tests/plugin_subject_public.rs`, asserts the same literals
/// (`MEASURED_USAGE`) against the provider budgets; keep the two in step.
const MEASURED_USAGE: [(FixtureFamily, ResourceUsage); 7] = [
    (FixtureFamily::Positive, POSITIVE_USAGE),
    (FixtureFamily::Denied, NO_USAGE),
    (FixtureFamily::Malformed, NO_USAGE),
    (FixtureFamily::ResourceExhaustion, NO_USAGE),
    (FixtureFamily::DeletionRedaction, DELETION_REDACTION_USAGE),
    (FixtureFamily::Downgrade, NO_USAGE),
    (
        FixtureFamily::IndependentEvaluation,
        INDEPENDENT_EVALUATION_USAGE,
    ),
];

const fn is_refused_or_failed(outcome: &Outcome) -> bool {
    matches!(
        outcome.result,
        Verdict::Refused { .. } | Verdict::Failed { .. }
    )
}

const fn is_committed(outcome: &Outcome) -> bool {
    matches!(outcome.result, Verdict::Committed { .. })
}

/// The committed Events and state around one pass.
struct PassCapture {
    before: Snapshot,
    after: Snapshot,
    /// The pass could not run, or a member was refused or failed.
    unsuccessful: bool,
    /// The workers the pass launched: the port's launch count after it less the count before.
    launches: u64,
}

/// The result of a `rollback` step.
type RollbackResult = Result<(), CommunityPluginHostErrorV1>;

/// One sub-case: its record, the passes it ran and the result of each `rollback` step.
struct Capture {
    record: SubCaseRecordV1,
    passes: Vec<PassCapture>,
    rollbacks: Vec<RollbackResult>,
}

/// The real evaluation port, which also snapshots the world around every pass and records the
/// result of every rollback.
struct SpyPort {
    inner: EvaluationStepPortV1,
    passes: Vec<PassCapture>,
    rollbacks: Vec<RollbackResult>,
}

impl SpyPort {
    fn snapshot(&mut self) -> Snapshot {
        let events = self.inner.committed_event_payloads().unwrap_or_default();
        Snapshot {
            events,
            state: self.inner.committed_state(),
        }
    }
}

impl StepPortV1 for SpyPort {
    fn open(&mut self, setup: SetupArgsV1) -> Result<(), CommunityPluginHostErrorV1> {
        self.inner.open(setup)
    }

    fn install(&mut self, args: &InstallArgsV1) -> Result<(), CommunityPluginHostErrorV1> {
        self.inner.install(args)
    }

    fn rollback(&mut self, args: &RollbackArgsV1) -> RollbackResult {
        let result = self.inner.rollback(args);
        self.rollbacks.push(result);
        result
    }

    fn bind(&mut self, args: &BindArgsV1) -> Result<ReleaseIdentityV1, CommunityPluginHostErrorV1> {
        self.inner.bind(args)
    }

    fn refresh(&mut self, args: &RefreshArgsV1) -> Result<(), CommunityPluginHostErrorV1> {
        self.inner.refresh(args)
    }

    fn pass(&mut self, args: &PassArgsV1) -> Result<Vec<Outcome>, CommunityPluginHostErrorV1> {
        let before = self.snapshot();
        let launched_before = self.inner.worker_launches();
        let result = self.inner.pass(args);
        let launches = self.inner.worker_launches().saturating_sub(launched_before);
        let after = self.snapshot();
        let ended_well = result
            .as_ref()
            .is_ok_and(|outcomes| !outcomes.iter().any(is_refused_or_failed));
        self.passes.push(PassCapture {
            before,
            after,
            unsuccessful: !ended_well,
            launches,
        });
        result
    }

    fn committed_event_payloads(&mut self) -> Result<Vec<Vec<u8>>, CommunityPluginHostErrorV1> {
        self.inner.committed_event_payloads()
    }

    fn committed_state(&mut self) -> Vec<u8> {
        self.inner.committed_state()
    }

    fn outcome_bytes(&self) -> Vec<u8> {
        self.inner.outcome_bytes()
    }

    fn worker_launches(&self) -> u64 {
        self.inner.worker_launches()
    }
}

/// `subcase` with the instant of every `pass` step one second earlier.
fn lowered_by_a_second(subcase: &SubCaseV1) -> SubCaseV1 {
    let mut copy = subcase.clone();
    for step in &mut copy.steps {
        if let StepV1::Pass(pass) = step {
            pass.instant_micros.0 = pass.instant_micros.0.saturating_sub(1_000_000);
        }
    }
    copy
}

/// The recording decorator over the real runner: it records every sub-case and, for the IDs in
/// `lowered`, runs the sub-case with its pass instants one second earlier.
struct Spy {
    program: WorkerProgramV1,
    lowered: &'static [&'static str],
    captures: Mutex<Vec<Capture>>,
}

impl Spy {
    fn new(lowered: &'static [&'static str]) -> TestResult<Self> {
        let program =
            WorkerProgramV1::new(PathBuf::from(WORKER)).ok_or("an invalid worker path")?;
        Ok(Self {
            program,
            lowered,
            captures: Mutex::new(Vec::new()),
        })
    }

    fn into_captures(self) -> Vec<Capture> {
        self.captures
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

impl SubCaseRunnerV1 for Spy {
    fn run(
        &self,
        subcase: &SubCaseV1,
        pieces: &PiecesV1,
        mode: CommunityPluginModeV1,
    ) -> SubCaseRecordV1 {
        let edited = if self.lowered.contains(&subcase.id.as_str()) {
            lowered_by_a_second(subcase)
        } else {
            subcase.clone()
        };
        let mut port = SpyPort {
            inner: EvaluationStepPortV1::new(self.program.clone()),
            passes: Vec::new(),
            rollbacks: Vec::new(),
        };
        let record = interpret(&edited, pieces, &mut port, mode);
        let capture = Capture {
            record: record.clone(),
            passes: port.passes,
            rollbacks: port.rollbacks,
        };
        self.captures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(capture);
        record
    }
}

/// The observation of `attempt` from `run_with` over `runner`.
fn observe_through(
    runner: &dyn SubCaseRunnerV1,
    attempt: &CaseAttempt,
) -> TestResult<SubjectObservation> {
    let mut stream = Vec::new();
    write_attempt(&mut stream, attempt)?;
    let mut out = Vec::new();
    run_with(runner, stream.as_slice(), &mut out)?;
    Ok(read_observation(out.as_slice(), 1_048_576)?)
}

/// A family run once in one Execution Mode.
struct FamilyRun {
    observation: SubjectObservation,
    captures: Vec<Capture>,
}

impl FamilyRun {
    fn ids(&self) -> Vec<&str> {
        self.captures
            .iter()
            .map(|capture| capture.record.id.as_str())
            .collect()
    }

    fn launches(&self) -> u32 {
        self.captures
            .iter()
            .map(|capture| capture.record.worker_launches)
            .sum()
    }
}

fn compute(family: FixtureFamily, mode: ExecutionMode) -> TestResult<FamilyRun> {
    let attempt = attempt_from_fixture_files(family, mode)?;
    let spy = Spy::new(&[])?;
    let observation = observe_through(&spy, &attempt)?;
    Ok(FamilyRun {
        observation,
        captures: spy.into_captures(),
    })
}

/// One cell per family and mode.
const RUN_CELLS: usize = FixtureFamily::ALL.len() * 2;

/// The shared result of one run: the run, or the text of the error that stopped it.
type SharedRun = Result<Arc<FamilyRun>, String>;

static RUNS: [OnceLock<SharedRun>; RUN_CELLS] = [const { OnceLock::new() }; RUN_CELLS];

/// The run of `family` in `mode`, made once and shared by the tests.
fn family_run(family: FixtureFamily, mode: ExecutionMode) -> TestResult<Arc<FamilyRun>> {
    let position = FixtureFamily::ALL
        .iter()
        .position(|candidate| *candidate == family)
        .ok_or("an unknown family")?;
    let slot = position * 2 + usize::from(matches!(mode, ExecutionMode::AirGapped));
    let cell = RUNS.get(slot).ok_or("no cell for the family")?;
    cell.get_or_init(|| {
        compute(family, mode)
            .map(Arc::new)
            .map_err(|error| error.to_string())
    })
    .clone()
    .map_err(Into::into)
}

fn capture_of<'a>(captures: &'a [Capture], id: &str) -> TestResult<&'a Capture> {
    captures
        .iter()
        .find(|capture| capture.record.id == id)
        .ok_or_else(|| format!("no record for {id}").into())
}

/// The family fails with `code` after every sub-case in `ids` matched, in both modes.
fn assert_family_failure(family: FixtureFamily, code: &str, ids: &[&str]) -> TestResult {
    for mode in MODES {
        let run = family_run(family, mode)?;
        assert_eq!(run.observation.result, failure(code), "{family:?} {mode:?}");
        assert_eq!(run.ids(), ids, "{family:?} {mode:?}");
        assert!(
            run.captures.iter().all(|capture| capture.record.matched),
            "{family:?} {mode:?}"
        );
        assert_within_budget(family, &run.observation)?;
    }
    Ok(())
}

/// The family gives the oracle member byte for byte, in both modes.
fn assert_family_output(family: FixtureFamily) -> TestResult {
    for mode in MODES {
        let run = family_run(family, mode)?;
        assert_output_is_the_oracle(family, &run.observation)?;
    }
    Ok(())
}

/// The `pass` steps of a sub-case document.
fn pass_steps(subcase: &mut Value) -> impl Iterator<Item = &mut Value> {
    subcase["steps"]
        .as_array_mut()
        .into_iter()
        .flatten()
        .filter(|step| step["step"] == "pass")
}

/// The edit that sets the instant of every `pass` step.
fn at_instant(micros: u64) -> impl Fn(&mut Value) {
    move |subcase| {
        for step in pass_steps(subcase) {
            step["instant_micros"] = micros.into();
        }
    }
}

/// The hexadecimal text with its last digit changed, which changes the last byte.
fn with_last_digit_changed(text: &str) -> String {
    let mut changed = text.to_owned();
    let last = changed.pop();
    changed.push(if last == Some('0') { '1' } else { '0' });
    changed
}

/// The edit that changes the `observation` of every `pass` step by one byte.
fn changing_the_observation(subcase: &mut Value) {
    for step in pass_steps(subcase) {
        if let Some(text) = step["observation"].as_str() {
            step["observation"] = with_last_digit_changed(text).into();
        }
    }
}

/// The pass steps of sub-case `id` in the checked-in payload of `family`.
fn pass_count(family: FixtureFamily, id: &str) -> TestResult<u32> {
    let attempt = attempt_from_fixture_files(family, ExecutionMode::Local)?;
    let payload: Value = serde_json::from_slice(&attempt.payload.bytes)?;
    let subcases = payload["subcases"].as_array().ok_or("no sub-cases")?;
    let subcase = subcases
        .iter()
        .find(|subcase| subcase["id"] == id)
        .ok_or("no such sub-case")?;
    let steps = subcase["steps"].as_array().ok_or("no steps")?;
    let passes = steps.iter().filter(|step| step["step"] == "pass").count();
    Ok(u32::try_from(passes)?)
}

#[test]
fn r8_s1_positive_output_is_the_oracle_in_local_and_air_gapped() -> TestResult {
    assert_family_output(FixtureFamily::Positive)?;
    let local = family_run(FixtureFamily::Positive, ExecutionMode::Local)?;
    let air_gapped = family_run(FixtureFamily::Positive, ExecutionMode::AirGapped)?;
    assert_eq!(local.observation.usage, air_gapped.observation.usage);
    assert!(local.observation.usage.cpu_fuel > 0);
    Ok(())
}

/// ADR-068 R4 test 8, worker half: `positive` reports nonzero Event count, output bytes, storage
/// bytes and steps, and exactly the measured usage, in Local and Air-Gapped.
#[test]
fn adr068_r4_t8_positive_reports_the_measured_usage_in_local_and_air_gapped() -> TestResult {
    for mode in MODES {
        let run = family_run(FixtureFamily::Positive, mode)?;
        let usage = run.observation.usage;
        let measured = [
            usage.event_count,
            usage.output_bytes,
            usage.storage_bytes,
            usage.execution_steps,
        ];
        let records: Vec<(&str, ResourceUsage)> = run
            .captures
            .iter()
            .map(|capture| (capture.record.id.as_str(), capture.record.usage))
            .collect();
        assert_eq!(usage, POSITIVE_USAGE, "{mode:?} {records:?}");
        assert_eq!(
            records,
            [
                ("pos.1", RUST_ONE_PASS_USAGE),
                ("pos.2", C_ONE_PASS_USAGE),
                ("pos.3", POSITIVE_USAGE),
            ],
            "{mode:?}"
        );
        assert!(measured.iter().all(|counter| *counter > 0), "{mode:?}");
    }
    Ok(())
}

/// ADR-068 R4 open check of slice 3: no `res.*` sub-case commits, so each reports zero usage and
/// so does the `resource-exhaustion` case.
#[test]
fn adr068_r4_no_resource_exhaustion_subcase_commits_or_reports_usage() -> TestResult {
    for mode in MODES {
        let run = family_run(FixtureFamily::ResourceExhaustion, mode)?;
        for capture in &run.captures {
            let id = &capture.record.id;
            assert!(!capture.record.outcomes.is_empty(), "{mode:?} {id}");
            assert!(
                !capture.record.outcomes.iter().any(is_committed),
                "{mode:?} {id}"
            );
            assert_eq!(
                capture.record.usage,
                ResourceUsage::default(),
                "{mode:?} {id}"
            );
        }
        assert_eq!(run.captures.len(), 7, "{mode:?}");
        assert_eq!(run.observation.usage, ResourceUsage::default(), "{mode:?}");
    }
    Ok(())
}

/// ADR-061 R11: the lowest budget `usage` passes, per counter. A counter measured at 0 takes 1,
/// because a zero budget is rejected.
const fn measured_floor(usage: ResourceUsage) -> DeterministicBudget {
    const fn floor(counter: u64) -> u64 {
        if counter == 0 {
            1
        } else {
            counter
        }
    }
    DeterministicBudget {
        memory_bytes: floor(usage.memory_bytes),
        cpu_fuel: floor(usage.cpu_fuel),
        host_calls: floor(usage.host_calls),
        event_count: floor(usage.event_count),
        output_bytes: floor(usage.output_bytes),
        storage_bytes: floor(usage.storage_bytes),
        execution_steps: floor(usage.execution_steps),
        simulation_time_ns: floor(usage.simulation_time_ns),
    }
}

/// ADR-061 R11: every family reports exactly its measured usage on the real worker in Local and
/// Air-Gapped, and the Draft budget the provider declares for it is the lowest budget that usage
/// passes. A change in measured usage fails here until the literal and `provider.json` move
/// together.
#[test]
fn adr061_r11_every_family_budget_is_the_floor_of_its_measured_usage() -> TestResult {
    let families: Vec<FixtureFamily> = MEASURED_USAGE.iter().map(|(family, _)| *family).collect();
    assert_eq!(families, FixtureFamily::ALL);
    for (family, measured) in MEASURED_USAGE {
        assert_eq!(
            family_budget(family)?,
            measured_floor(measured),
            "{family:?}"
        );
        for mode in MODES {
            let run = family_run(family, mode)?;
            let records: Vec<(&str, ResourceUsage)> = run
                .captures
                .iter()
                .map(|capture| (capture.record.id.as_str(), capture.record.usage))
                .collect();
            assert_eq!(
                run.observation.usage, measured,
                "{family:?} {mode:?} {records:?}"
            );
            assert_within_budget(family, &run.observation)?;
        }
    }
    Ok(())
}

/// The Migration S5 form: `SupervisorRunnerV1::new` over the worker of this package, without
/// the recording runner.
#[test]
fn r8_s1_the_supervisor_runner_gives_the_positive_oracle() -> TestResult {
    let attempt = attempt_from_fixture_files(FixtureFamily::Positive, ExecutionMode::Local)?;
    let oracle = SubjectResult::Output(oracle_bytes(FixtureFamily::Positive)?);
    assert_eq!(observe_attempt(&attempt)?.result, oracle);
    Ok(())
}

#[test]
fn r8_s1_changing_the_observation_by_one_byte_changes_the_committed_digest() -> TestResult {
    let family = FixtureFamily::Positive;
    let run = family_run(family, ExecutionMode::Local)?;
    let original = capture_of(&run.captures, "pos.1")?.record.committed;
    let changed_attempt = one_subcase(family, "pos.1", changing_the_observation)?;
    let spy = Spy::new(&[])?;
    observe_through(&spy, &changed_attempt)?;
    let captures = spy.into_captures();
    let changed = capture_of(&captures, "pos.1")?.record.committed;
    assert!(original.is_some());
    assert!(changed.is_some());
    assert_ne!(original, changed);
    Ok(())
}

fn denied_ids() -> Vec<String> {
    (1..=22).map(|number| format!("den.{number:02}")).collect()
}

#[test]
fn r8_s2_denied_is_capability_denied_after_den_01_to_den_22_matched() -> TestResult {
    let ids = denied_ids();
    let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
    assert_family_failure(FixtureFamily::Denied, "capability-denied", &ids)
}

const EXPIRY_CONTROLS: [&str; 3] = ["den.16", "den.17", "den.18"];

#[test]
fn r8_s2_lowering_the_pass_instant_by_a_second_commits_den_16_to_den_18() -> TestResult {
    let baseline = family_run(FixtureFamily::Denied, ExecutionMode::Local)?.launches();
    let attempt = attempt_from_fixture_files(FixtureFamily::Denied, ExecutionMode::Local)?;
    let spy = Spy::new(&EXPIRY_CONTROLS)?;
    let observation = observe_through(&spy, &attempt)?;
    let lowered = FamilyRun {
        observation,
        captures: spy.into_captures(),
    };
    for id in EXPIRY_CONTROLS {
        let record = &capture_of(&lowered.captures, id)?.record;
        assert!(!record.outcomes.is_empty(), "{id}");
        assert!(record.outcomes.iter().all(is_committed), "{id}");
        assert!(!record.matched, "{id}");
    }
    // One extra launch for each sub-case that now commits.
    let extra = u32::try_from(EXPIRY_CONTROLS.len())?;
    assert_eq!(lowered.launches(), baseline + extra);
    assert_eq!(lowered.observation.result, failure("subcase-mismatch"));
    Ok(())
}

#[test]
fn r8_s3_malformed_is_malformed_payload_after_mal_1a_to_mal_6_matched() -> TestResult {
    let ids = [
        "mal.1a", "mal.1b", "mal.2", "mal.3a", "mal.3b", "mal.3c", "mal.4a", "mal.4b", "mal.5a",
        "mal.5b", "mal.6",
    ];
    assert_family_failure(FixtureFamily::Malformed, "malformed-payload", &ids)
}

#[test]
fn r8_s4_resource_exhaustion_is_resource_limit_within_the_budget() -> TestResult {
    let ids = [
        "res.1", "res.2", "res.3", "res.4", "res.5", "res.6", "res.7",
    ];
    assert_family_failure(FixtureFamily::ResourceExhaustion, "resource-limit", &ids)
}

#[test]
fn r8_s5_deletion_redaction_output_is_the_oracle() -> TestResult {
    assert_family_output(FixtureFamily::DeletionRedaction)
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

/// The committed Event payloads and states after every pass of the sub-case, and with
/// `with_outcome` the canonical bytes of its outcome records.
fn haystacks(capture: &Capture, with_outcome: bool) -> Vec<Vec<u8>> {
    let mut stacks = Vec::new();
    for pass in &capture.passes {
        stacks.extend(pass.after.events.iter().cloned());
        stacks.push(pass.after.state.clone());
    }
    if with_outcome {
        stacks.extend(capture.record.outcomes.iter().map(outcome_bytes_of));
    }
    stacks
}

/// The scanned records of the sub-case hold bytes, and the outcome record holds other text.
fn assert_scan_controls(capture: &Capture, id: &str) {
    let events = capture.passes.last().map(|pass| pass.after.events.len());
    assert!(events.is_some_and(|count| count > 0), "{id}");
    let stacks = haystacks(capture, false);
    assert!(stacks.iter().any(|stack| !stack.is_empty()), "{id}");
    let outcome_stacks = haystacks(capture, true);
    assert!(
        outcome_stacks
            .iter()
            .any(|stack| contains(stack, PLUGIN_ID)),
        "{id}"
    );
}

/// `del.2` excludes the outcome record: the guests' Event type `prototype.driven` contains its
/// marker `drive`.
const MARKERS: [(&str, &str, bool); 2] = [
    ("del.1", "synthetic-secret", true),
    ("del.2", "drive", false),
];

#[test]
fn r8_s5_the_marker_is_in_no_committed_event_state_or_outcome() -> TestResult {
    for mode in MODES {
        let run = family_run(FixtureFamily::DeletionRedaction, mode)?;
        for (id, marker, with_outcome) in MARKERS {
            let capture = capture_of(&run.captures, id)?;
            let stacks = haystacks(capture, with_outcome);
            assert!(
                stacks.iter().all(|stack| !contains(stack, marker)),
                "{id} {mode:?}"
            );
            let scan = capture.record.scan.as_ref().ok_or("no scan")?;
            assert!(scan.found.is_empty(), "{id} {mode:?}");
            assert!(scan.retained_ok, "{id} {mode:?}");
            assert_scan_controls(capture, id);
        }
    }
    Ok(())
}

#[test]
fn r8_s6_downgrade_is_incompatible_contract_after_dgr_1_to_dgr_6_matched() -> TestResult {
    let ids = [
        "dgr.1", "dgr.2", "dgr.3a", "dgr.3b", "dgr.4", "dgr.5", "dgr.6",
    ];
    assert_family_failure(FixtureFamily::Downgrade, "incompatible-contract", &ids)
}

const UNAVAILABLE: CommunityPluginHostErrorV1 = CommunityPluginHostErrorV1::ArtifactTrustDenied {
    basis: TrustDenialBasisV1::TrustStateUnavailable,
};

/// One `downgrade` sub-case: the refusal that decides it, the steps that ran (the refusing step
/// included) and the result of each `rollback` step.
struct Downgrade {
    id: &'static str,
    refusal: CommunityPluginHostErrorV1,
    steps_run: u32,
    rollbacks: Vec<RollbackResult>,
}

const fn downgrade(
    id: &'static str,
    refusal: CommunityPluginHostErrorV1,
    steps_run: u32,
    rollbacks: Vec<RollbackResult>,
) -> Downgrade {
    Downgrade {
        id,
        refusal,
        steps_run,
        rollbacks,
    }
}

/// The `downgrade` table of ADR-103 revision 7 decision 4.6.
fn downgrade_table() -> [Downgrade; 7] {
    let not_active = CommunityPluginHostErrorV1::ArtifactTrustDenied {
        basis: TrustDenialBasisV1::NotActive,
    };
    let revoked = CommunityPluginHostErrorV1::ArtifactRevoked {
        basis: RevocationBasisV1::PublisherKey,
    };
    let invalid = CommunityPluginHostErrorV1::InvalidManifest;
    let abi = CommunityPluginHostErrorV1::IncompatibleAbi;
    [
        // The rollback to R1 succeeds, then the bind of the replaced R2 is refused.
        downgrade("dgr.1", not_active, 4, vec![Ok(())]),
        // A revoked R1 is not silently restored.
        downgrade("dgr.2", revoked, 4, vec![Err(revoked)]),
        downgrade("dgr.3a", invalid, 1, Vec::new()),
        downgrade("dgr.3b", abi, 2, Vec::new()),
        downgrade("dgr.4", UNAVAILABLE, 2, Vec::new()),
        // `UnknownRollbackTarget`, then `RollbackTargetActive`.
        downgrade("dgr.5", UNAVAILABLE, 2, vec![Err(UNAVAILABLE)]),
        downgrade("dgr.6", UNAVAILABLE, 2, vec![Err(UNAVAILABLE)]),
    ]
}

#[test]
fn r7_f2_downgrade_rolls_back_through_the_production_entry() -> TestResult {
    for mode in MODES {
        let run = family_run(FixtureFamily::Downgrade, mode)?;
        for expected in downgrade_table() {
            let id = expected.id;
            let capture = capture_of(&run.captures, id)?;
            let record = &capture.record;
            assert_eq!(
                record.setup_refusal,
                Some(expected.refusal),
                "{id} {mode:?}"
            );
            assert_eq!(record.steps_run, expected.steps_run, "{id} {mode:?}");
            assert_eq!(capture.rollbacks, expected.rollbacks, "{id} {mode:?}");
            assert_eq!(capture.record.worker_launches, 0, "{id} {mode:?}");
            assert!(capture.passes.is_empty(), "{id} {mode:?}");
            assert!(capture.record.matched, "{id} {mode:?}");
        }
    }
    Ok(())
}

#[test]
fn r8_s7_independent_evaluation_output_is_the_oracle() -> TestResult {
    assert_family_output(FixtureFamily::IndependentEvaluation)
}

#[test]
fn r8_s7_ind_1_is_the_checked_in_literal() -> TestResult {
    let family = FixtureFamily::IndependentEvaluation;
    let run = family_run(family, ExecutionMode::Local)?;
    let computed = capture_of(&run.captures, "ind.1")?
        .record
        .computed
        .ok_or("no computed digest")?;
    assert_eq!(
        blake3::Hash::from_bytes(computed).to_hex().as_str(),
        IND1_DIGEST
    );
    let bytes = oracle_bytes(family)?;
    let oracle: Value = serde_json::from_slice(&bytes)?;
    let first = &oracle["output"]["subcases"][0];
    assert_eq!(first["id"], "ind.1");
    assert_eq!(first["value"], IND1_DIGEST);
    Ok(())
}

/// Assert that `run_with` does not execute `attempt`.
fn assert_not_executed(attempt: &CaseAttempt) -> TestResult {
    let runner = SupervisorRunnerV1::with_program(WORKER).ok_or("a relative program")?;
    let mut stream = Vec::new();
    write_attempt(&mut stream, attempt)?;
    let mut out = Vec::new();
    let result = run_with(&runner, stream.as_slice(), &mut out);
    assert_eq!(result, Err(AdapterRunErrorV1::NotExecuted));
    assert!(out.is_empty());
    Ok(())
}

/// Where in the composite bytes to change a byte.
type Position = fn(&[u8]) -> Option<usize>;

/// `attempt` with one byte of the composite changed at the position `position` finds; the
/// digest of the member follows the new bytes, as the evaluator delivers it.
fn mutating_the_composite(
    mut attempt: CaseAttempt,
    position: impl Fn(&[u8]) -> Option<usize>,
) -> TestResult<CaseAttempt> {
    let member = attempt
        .auxiliary
        .iter_mut()
        .find(|member| member.bytes.starts_with(&COMPOSITE_HEADER))
        .ok_or("no composite")?;
    let at = position(&member.bytes).ok_or("no position")?;
    member.bytes[at] ^= 1;
    member.digest = *blake3::hash(&member.bytes).as_bytes();
    Ok(attempt)
}

// R8-S8, evaluator path: that half lives in `crates/pos-reference/tests/plugin_subject_public.rs`
// on its hand-written fixtures. The real composite cannot be used there: `pos-reference` may not
// depend on the host, the adapter or the fixture files, which
// `check-reference-evaluator-independence.sh` enforces, so it builds its own signed corpus.
#[test]
fn r8_s8_one_byte_of_the_composite_is_not_executed() -> TestResult {
    let attempt = attempt_from_fixture_files(FixtureFamily::Malformed, ExecutionMode::Local)?;
    let positions: [Position; 3] = [
        |_| Some(6),
        |bytes| Some(bytes.len() / 2),
        |bytes| bytes.len().checked_sub(1),
    ];
    for position in positions {
        let mutated = mutating_the_composite(attempt.clone(), position)?;
        assert_not_executed(&mutated)?;
    }
    Ok(())
}

/// The position of the version bytes of the first Component in the composite.
fn after_the_component_magic(bytes: &[u8]) -> Option<usize> {
    let start = bytes.windows(4).position(|window| window == b"\0asm");
    start.map(|start| start + 4)
}

#[test]
fn r8_s8_a_component_piece_changed_without_its_digest_entry_is_not_executed() -> TestResult {
    let attempt = attempt_from_fixture_files(FixtureFamily::Positive, ExecutionMode::Local)?;
    let mutated = mutating_the_composite(attempt, after_the_component_magic)?;
    assert_not_executed(&mutated)
}

#[test]
fn r8_s8_changing_the_first_expectation_fails_the_case() -> TestResult {
    let family = FixtureFamily::Malformed;
    let unchanged = attempt_from_fixture_files(family, ExecutionMode::Local)?;
    assert_eq!(
        observe_attempt(&unchanged)?.result,
        failure("malformed-payload")
    );
    let mut first = true;
    let changed = rewrite_subcases(unchanged, move |subcase| {
        if std::mem::take(&mut first) {
            expecting("IncompatibleAbi")(subcase);
        }
        true
    })?;
    assert_eq!(
        observe_attempt(&changed)?.result,
        failure("subcase-mismatch")
    );
    Ok(())
}

#[test]
fn r8_s8_an_instant_across_the_validity_boundary_fails_the_case() -> TestResult {
    let attempt = one_subcase(FixtureFamily::Denied, "den.16", at_instant(59_000_000))?;
    assert_eq!(
        observe_attempt(&attempt)?.result,
        failure("subcase-mismatch")
    );
    Ok(())
}

#[test]
fn r8_s8_an_instant_inside_the_same_window_still_passes() -> TestResult {
    let attempt = one_subcase(FixtureFamily::Denied, "den.16", at_instant(61_000_000))?;
    assert_eq!(
        observe_attempt(&attempt)?.result,
        failure("capability-denied")
    );
    Ok(())
}

/// The sub-cases of `family` that launch a worker.
fn launching_ids(family: FixtureFamily, run: &FamilyRun) -> Vec<String> {
    match family {
        FixtureFamily::Denied => (3..=12).map(|number| format!("den.{number:02}")).collect(),
        FixtureFamily::IndependentEvaluation => vec!["ind.3".to_owned()],
        _ => run.ids().into_iter().map(str::to_owned).collect(),
    }
}

const LAUNCHING_FAMILIES: [FixtureFamily; 5] = [
    FixtureFamily::Positive,
    FixtureFamily::Denied,
    FixtureFamily::ResourceExhaustion,
    FixtureFamily::DeletionRedaction,
    FixtureFamily::IndependentEvaluation,
];

/// R8-S9: every pass step of a launching sub-case launched exactly one worker, by the
/// supervisors' own count (#660). A worker reused by a later pass would leave that pass at zero
/// launches and fail the test.
#[test]
fn r8_s9_every_pass_is_one_fresh_worker_launch() -> TestResult {
    for family in LAUNCHING_FAMILIES {
        for mode in MODES {
            let run = family_run(family, mode)?;
            for id in launching_ids(family, &run) {
                let capture = capture_of(&run.captures, &id)?;
                let passes = pass_count(family, &id)?;
                let per_pass: Vec<u64> = capture.passes.iter().map(|pass| pass.launches).collect();
                let one_each = vec![1; usize::try_from(passes)?];
                assert_eq!(per_pass, one_each, "{family:?} {mode:?} {id}");
                assert_eq!(
                    capture.record.worker_launches, passes,
                    "{family:?} {mode:?} {id}"
                );
                assert!(passes > 0, "{id}");
            }
        }
    }
    Ok(())
}

#[test]
fn r8_s9_a_launching_family_without_a_worker_is_unavailable() -> TestResult {
    // The ADR text names `/bin/false` as the worker; this test deliberately uses an absolute path
    // that holds no program, which is equivalent (R8-A6): the launch fails and the member is
    // `WorkerCrashed`, so the case is `Unavailable`.
    let missing = std::env::temp_dir().join(format!("pigloros-no-worker-{}", std::process::id()));
    let runner =
        SupervisorRunnerV1::with_program(missing).ok_or("the worker path must be absolute")?;
    for family in LAUNCHING_FAMILIES {
        let attempt = attempt_from_fixture_files(family, ExecutionMode::Local)?;
        let observation = observe_through(&runner, &attempt)?;
        assert_eq!(observation.result, SubjectResult::Unavailable, "{family:?}");
    }
    Ok(())
}

/// The names of the keys at every depth of the JSON document `bytes` that claim a safety
/// property, and the number of keys.
fn safety_keys(bytes: &[u8]) -> TestResult<(Vec<String>, usize)> {
    let mut keys = Vec::new();
    collect_keys(&serde_json::from_slice(bytes)?, &mut keys);
    let claims = keys
        .iter()
        .filter(|key| FORBIDDEN_KEYS.contains(&key.as_str()))
        .cloned()
        .collect();
    Ok((claims, keys.len()))
}

fn collect_keys(value: &Value, keys: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, member) in map {
                keys.push(key.clone());
                collect_keys(member, keys);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| collect_keys(item, keys)),
        _ => {}
    }
}

#[test]
fn r8_s10_no_oracle_or_output_key_claims_a_safety_property() -> TestResult {
    for family in FixtureFamily::ALL.iter().copied() {
        let oracle = oracle_bytes(family)?;
        let (claims, count) = safety_keys(&oracle)?;
        assert!(claims.is_empty(), "{family:?} oracle {claims:?}");
        assert!(count > 0, "{family:?} oracle");
    }
    for family in [
        FixtureFamily::Positive,
        FixtureFamily::DeletionRedaction,
        FixtureFamily::IndependentEvaluation,
    ] {
        let run = family_run(family, ExecutionMode::Local)?;
        let SubjectResult::Output(bytes) = &run.observation.result else {
            return Err(format!("{family:?} gave no output").into());
        };
        let (claims, count) = safety_keys(bytes)?;
        assert!(claims.is_empty(), "{family:?} output {claims:?}");
        assert!(count > 0, "{family:?} output");
    }
    Ok(())
}

#[test]
fn r8_s10_the_outcome_record_has_exactly_the_r7_h3_fields() -> TestResult {
    let run = family_run(FixtureFamily::Positive, ExecutionMode::Local)?;
    let outcome = run
        .captures
        .first()
        .and_then(|capture| capture.record.outcomes.first())
        .ok_or("no outcome")?;
    // The pattern names every field and has no `..`: a field added to the record, such as a
    // signature-validity claim, stops this test from compiling.
    let Outcome {
        plugin_id,
        pmf1_digest,
        release_digest,
        tps1_digest,
        execution_profile_digest,
        tick,
        mode,
        content_validation,
        result,
    } = outcome.clone();
    assert_eq!(plugin_id, PLUGIN_ID);
    let digests = [
        pmf1_digest,
        release_digest,
        tps1_digest,
        execution_profile_digest,
    ];
    assert!(digests.iter().all(Option::is_some));
    assert_eq!(tick, 5);
    assert!(matches!(mode, CommunityPluginModeV1::Local));
    assert!(matches!(
        content_validation,
        ContentValidationV1::NotPerformed
    ));
    assert!(matches!(result, Verdict::Committed { .. }));
    // The canonical record is CBOR with no key names; it also holds no such word.
    let bytes = outcome_bytes_of(outcome);
    assert!(FORBIDDEN_KEYS.iter().all(|key| !contains(&bytes, key)));
    Ok(())
}

/// Assert that every unsuccessful pass of the run left the Events and the state as they were,
/// and report the number of unsuccessful passes and of passes that changed them.
fn assert_unsuccessful_passes_changed_nothing(run: &FamilyRun) -> (usize, usize) {
    let passes = run.captures.iter().flat_map(|capture| &capture.passes);
    let (unsuccessful, successful): (Vec<_>, Vec<_>) = passes.partition(|pass| pass.unsuccessful);
    for pass in &unsuccessful {
        assert_eq!(pass.before, pass.after);
    }
    let changed = successful.iter().filter(|pass| pass.before != pass.after);
    (unsuccessful.len(), changed.count())
}

#[test]
fn r8_s11_a_refused_or_failed_pass_leaves_events_and_state_unchanged() -> TestResult {
    let (mut unsuccessful, mut changed) = (0, 0);
    for mode in MODES {
        for family in FixtureFamily::ALL.iter().copied() {
            let run = family_run(family, mode)?;
            let counts = assert_unsuccessful_passes_changed_nothing(&run);
            unsuccessful += counts.0;
            changed += counts.1;
        }
    }
    // The controls: the check saw refused and failed passes, and it sees a pass that commits.
    assert!(unsuccessful >= 20, "{unsuccessful}");
    assert!(changed >= 2, "{changed}");
    Ok(())
}
