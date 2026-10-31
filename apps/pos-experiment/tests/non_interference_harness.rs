#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Public-interface tests for the ADR-059 non-interference mode harness
//! (ADR-062 Revision 8 slice N0, #1227).
//!
//! The Local runner spawns the `pos-ni-local-probe` binary (or `/bin/sh` for
//! malformed frames) as a fresh process; the Replay and Fork runners drive a
//! probe subject through the Experiment host. Every executed case is signed
//! with the host executor key, published at its content address and checked
//! by the independent #181 verifier in `pos-reference`. The probe captures
//! prove the harness, not any ADR-059 row: they are not inventory evidence.

use std::fs;
use std::path::{Path, PathBuf};

use pos_conformance::{
    non_interference_capture_profiles_v1, non_interference_normalization_digest_v1,
    ExecutionModeV1, NonInterferenceExecutionArtifactBodyV1, NonInterferenceExecutionArtifactV1,
    NonInterferenceFixturePairV1, NonInterferenceHostRunV1, NonInterferenceRawCaptureV1,
    NonInterferenceReportErrorV1, NonInterferenceVariantV1, NON_INTERFERENCE_FIXTURE_IDS_V1,
};
use pos_core::{
    event::{CanonicalBytes, EventDraft, Kind},
    ids::{EntityId, PluginId, TimelineId},
    plugin::{Capability, Plugin},
    ErasureContainmentGateV1, Event, Reducer, State,
};
use pos_experiment::non_interference_harness::{
    build_non_interference_report_v1, non_interference_publication_path_v1,
    probe::{local_probe_subject_v1, serve_local_probe_v1, LOCAL_PROBE_FIXTURE_ID_V1},
    publish_non_interference_execution_v1, HostExecutorKeyV1, NonInterferenceAirGappedRunnerV1,
    NonInterferenceForkRunnerV1, NonInterferenceHarnessV1, NonInterferenceLocalProcessRunnerV1,
    NonInterferenceLocalRequestV1, NonInterferenceModeRunnerV1, NonInterferenceNonExecutedCauseV1,
    NonInterferencePreparationV1, NonInterferencePublicationErrorV1, NonInterferenceReplayRunnerV1,
    NonInterferenceRunOutcomeV1, NonInterferenceSessionObservationV1,
    NonInterferenceSessionSubjectV1, NonInterferenceSignedExecutionV1,
    NON_INTERFERENCE_LOCAL_CAPTURE_MAGIC_V1, NON_INTERFERENCE_LOCAL_REQUEST_MAGIC_V1,
    NON_INTERFERENCE_PUBLICATION_DIRECTORY_V1,
};
use pos_experiment::{Experiment, ExperimentConfig, StopCondition};
use pos_reference::{
    verify_non_interference_execution_artifact_v1, verify_non_interference_report_v1,
    IndependentNonInterferenceReportErrorV1,
};
use pos_runtime::{Driver, ObservationView, PluginRegistry, RuntimeError, StepOutput};
use pos_state::ProjectionRegistry;
use pos_store::StoreConfig;
use serde_json::{json, Value};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const PROBE: &str = env!("CARGO_BIN_EXE_pos-ni-local-probe");
const SECRET: [u8; 32] = [7; 32];
const OTHER_SECRET: [u8; 32] = [9; 32];
const CONTROL: &[u8] = b"control-unauthorized-0001";
const CANARY: &[u8] = b"canary-unauthorized-0002";
const VARIANTS: [NonInterferenceVariantV1; 4] = [
    NonInterferenceVariantV1::Success,
    NonInterferenceVariantV1::Denial,
    NonInterferenceVariantV1::WarmCache,
    NonInterferenceVariantV1::ColdCache,
];
const MODES: [ExecutionModeV1; 4] = [
    ExecutionModeV1::Local,
    ExecutionModeV1::AirGapped,
    ExecutionModeV1::Replay,
    ExecutionModeV1::Fork,
];
const EXECUTABLE_MODES: [ExecutionModeV1; 3] = [
    ExecutionModeV1::Local,
    ExecutionModeV1::Replay,
    ExecutionModeV1::Fork,
];
const EVENT_TYPE: &str = "ni-probe.tick.v1";
const REDUCER: &str = "ni-probe.count";

fn key() -> HostExecutorKeyV1 {
    HostExecutorKeyV1::from_secret_bytes(&SECRET)
}

fn fixture(
    fixture_id: &str,
    variant: NonInterferenceVariantV1,
    mode: ExecutionModeV1,
    permitted: &[u8],
) -> TestResult<NonInterferenceFixturePairV1> {
    Ok(NonInterferenceFixturePairV1::try_new(
        fixture_id,
        variant,
        mode,
        permitted.to_vec(),
        CONTROL.to_vec(),
        CANARY.to_vec(),
    )?)
}

fn probe_fixture(
    variant: NonInterferenceVariantV1,
    mode: ExecutionModeV1,
    permitted: &[u8],
) -> TestResult<NonInterferenceFixturePairV1> {
    fixture(LOCAL_PROBE_FIXTURE_ID_V1, variant, mode, permitted)
}

/// A Local runner of the probe binary. The coverage profile variable is the
/// one declared environment variable it passes on, when the run has one.
#[cfg_attr(coverage_nightly, coverage(off))]
fn probe_runner(work: &Path) -> TestResult<NonInterferenceLocalProcessRunnerV1> {
    let runner = NonInterferenceLocalProcessRunnerV1::new(PathBuf::from(PROBE), work.join("work"))?;
    Ok(match std::env::var("LLVM_PROFILE_FILE") {
        Ok(value) => runner.with_env("LLVM_PROFILE_FILE", value),
        Err(_) => runner,
    })
}

/// A Local runner of `/bin/sh -c script`, with `argument` as `$1`.
fn shell_runner(
    work: &Path,
    script: &str,
    argument: &Path,
) -> TestResult<NonInterferenceLocalProcessRunnerV1> {
    Ok(
        NonInterferenceLocalProcessRunnerV1::new(PathBuf::from("/bin/sh"), work.join("work"))?
            .with_env("PATH", "/usr/bin:/bin")
            .with_argument("-c")
            .with_argument(script)
            .with_argument("sh")
            .with_argument(argument.to_string_lossy().into_owned()),
    )
}

fn harness_with(runners: Vec<Box<dyn NonInterferenceModeRunnerV1>>) -> NonInterferenceHarnessV1 {
    runners.into_iter().fold(
        NonInterferenceHarnessV1::new(key(), vec![key().public_key()]),
        NonInterferenceHarnessV1::with_runner,
    )
}

fn all_runners(work: &Path) -> TestResult<NonInterferenceHarnessV1> {
    Ok(harness_with(vec![
        Box::new(probe_runner(work)?),
        Box::new(NonInterferenceReplayRunnerV1::new(SessionProbe::new())),
        Box::new(NonInterferenceForkRunnerV1::new(SessionProbe::new(), 1)),
    ]))
}

fn executed(
    outcome: &NonInterferenceRunOutcomeV1,
) -> TestResult<&NonInterferenceSignedExecutionV1> {
    outcome
        .execution()
        .ok_or_else(|| format!("not executed: {outcome:?}").into())
}

fn cause_of(
    harness: &mut NonInterferenceHarnessV1,
    fixture: &NonInterferenceFixturePairV1,
) -> Option<NonInterferenceNonExecutedCauseV1> {
    let outcome = harness.execute_case(fixture);
    assert_eq!(outcome.claim(), None, "{outcome:?}");
    assert!(outcome.execution().is_none(), "{outcome:?}");
    outcome.non_executed_cause()
}

// ---------------------------------------------------------------------------
// Probe subjects
// ---------------------------------------------------------------------------

/// What a test runner returns for every run.
#[derive(Clone)]
enum Behaviour {
    /// The probe subject's capture.
    Probe,
    /// The probe subject's capture, changed by `edit`.
    Edited(fn(&mut NonInterferenceRawCaptureV1)),
    /// This cause.
    Fail(NonInterferenceNonExecutedCauseV1),
}

/// A runner of any mode that runs the probe subject in-process.
struct TestRunner {
    mode: ExecutionModeV1,
    behaviour: Behaviour,
    directory: tempfile::TempDir,
}

impl TestRunner {
    fn boxed(
        mode: ExecutionModeV1,
        behaviour: Behaviour,
    ) -> TestResult<Box<dyn NonInterferenceModeRunnerV1>> {
        Ok(Box::new(Self {
            mode,
            behaviour,
            directory: tempfile::tempdir()?,
        }))
    }
}

fn request_of(
    run: &NonInterferenceHostRunV1<'_>,
    preparation: NonInterferencePreparationV1,
) -> NonInterferenceLocalRequestV1 {
    NonInterferenceLocalRequestV1 {
        magic: NON_INTERFERENCE_LOCAL_REQUEST_MAGIC_V1.to_owned(),
        version: 1,
        fixture_id: run.subject.fixture_id.to_owned(),
        variant: run.subject.variant,
        mode: run.subject.mode,
        preparation,
        permitted_input: run.subject.permitted_input.to_vec(),
        unauthorized_value: run.unauthorized_value.to_vec(),
    }
}

impl NonInterferenceModeRunnerV1 for TestRunner {
    fn mode(&self) -> ExecutionModeV1 {
        self.mode
    }

    fn prepare(
        &mut self,
        _preparation: NonInterferencePreparationV1,
    ) -> Result<(), NonInterferenceNonExecutedCauseV1> {
        Ok(())
    }

    fn execute(
        &mut self,
        run: &NonInterferenceHostRunV1<'_>,
        preparation: NonInterferencePreparationV1,
    ) -> Result<NonInterferenceRawCaptureV1, NonInterferenceNonExecutedCauseV1> {
        let captured = local_probe_subject_v1(&request_of(run, preparation), self.directory.path());
        match self.behaviour.clone() {
            Behaviour::Probe => captured,
            Behaviour::Edited(edit) => captured.map(|mut capture| {
                edit(&mut capture);
                capture
            }),
            Behaviour::Fail(cause) => Err(cause),
        }
    }
}

struct ProbePlugin {
    id: PluginId,
}

impl Plugin for ProbePlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "ni-probe"
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new(EVENT_TYPE)],
            owned_entity_kinds: Vec::new(),
            has_driver: true,
            has_reducer: false,
        }
    }
}

/// Emits the permitted input as one Event per Tick; the input `fail` fails
/// every Tick.
struct ProbeDriver {
    payload: Vec<u8>,
}

impl Driver for ProbeDriver {
    fn name(&self) -> &'static str {
        "ni-probe.driver"
    }

    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        if self.payload == b"fail" {
            return Err(RuntimeError::CapabilityMismatch {
                name: "ni-probe".to_owned(),
                reason: "probe failure".to_owned(),
            });
        }
        Ok(StepOutput::new(vec![EventDraft::new(
            EntityId::from_ulid(ulid::Ulid::from_parts(1, 7)),
            Kind::new(EVENT_TYPE),
            CanonicalBytes::from_vec(self.payload.clone()),
        )]))
    }
}

/// Counts the Events of each entity.
struct CountReducer;

impl Reducer for CountReducer {
    fn initial(&self) -> State {
        let mut state = State::new();
        state.set("count", json!(0_u64));
        state
    }

    fn apply(&self, state: &mut State, _event: &Event) {
        let next = state
            .get("count")
            .and_then(Value::as_u64)
            .map(|count| count + 1);
        state.set("count", json!(next));
    }
}

/// The session probe subject of the Replay and Fork runners. The
/// unauthorized value stays with the host; the Driver only sees the
/// permitted input. A warm run after priming reports a
/// cache hit on its operational surfaces.
struct SessionProbe {
    gate: bool,
    fork_factory: bool,
    primed: bool,
    hit: bool,
}

impl SessionProbe {
    const fn new() -> Self {
        Self {
            gate: true,
            fork_factory: true,
            primed: false,
            hit: false,
        }
    }
}

fn probe_registry(plugin: PluginId, payload: Vec<u8>) -> Result<PluginRegistry, RuntimeError> {
    let mut registry = PluginRegistry::new();
    registry
        .register_generated(
            &ProbePlugin { id: plugin },
            None,
            Some(Box::new(ProbeDriver { payload })),
        )
        .map(|()| registry)
}

impl NonInterferenceSessionSubjectV1 for SessionProbe {
    fn prepare(
        &mut self,
        _preparation: NonInterferencePreparationV1,
    ) -> Result<(), NonInterferenceNonExecutedCauseV1> {
        self.primed = false;
        Ok(())
    }

    fn compose(
        &mut self,
        run: &NonInterferenceHostRunV1<'_>,
        preparation: NonInterferencePreparationV1,
    ) -> Result<Experiment, NonInterferenceNonExecutedCauseV1> {
        if run.subject.fixture_id != LOCAL_PROBE_FIXTURE_ID_V1 {
            return Err(NonInterferenceNonExecutedCauseV1::Unsupported);
        }
        self.hit = preparation == NonInterferencePreparationV1::Warm && self.primed;
        self.primed = true;
        let plugin = PluginId::new();
        let payload = run.subject.permitted_input.to_vec();
        let mut experiment = Experiment::new(ExperimentConfig {
            name: "ni-session-probe".to_owned(),
            stop: StopCondition::MaxTicks(2),
            store_config: StoreConfig::Memory,
        });
        if self.fork_factory {
            let child_payload = payload.clone();
            experiment = experiment
                .with_fork_registry_factory(move |_| probe_registry(plugin, child_payload.clone()));
        }
        experiment
            .register_generated(
                &ProbePlugin { id: plugin },
                None,
                Some(Box::new(ProbeDriver { payload })),
            )
            .map(|()| experiment)
            .map_err(|_| NonInterferenceNonExecutedCauseV1::Unavailable)
    }

    fn projections(&self) -> ProjectionRegistry {
        let mut projections = if self.gate {
            ProjectionRegistry::new().with_erasure_gate(std::sync::Arc::new(
                ErasureContainmentGateV1::new_test_open(),
            ))
        } else {
            ProjectionRegistry::new()
        };
        projections.register(REDUCER, Box::new(CountReducer));
        projections
    }

    fn capture(
        &mut self,
        run: &NonInterferenceHostRunV1<'_>,
        observation: &NonInterferenceSessionObservationV1<'_>,
    ) -> Result<NonInterferenceRawCaptureV1, NonInterferenceNonExecutedCauseV1> {
        let state = pos_crypto::canonical::encode(observation.snapshot)
            .map_err(|_| NonInterferenceNonExecutedCauseV1::Unavailable)?;
        let payloads = observation
            .events
            .iter()
            .flat_map(|event| event.payload.as_slice().to_vec())
            .collect::<Vec<_>>();
        let names = pos_conformance::non_interference_surface_names_v1(run.subject.fixture_id)
            .ok_or(NonInterferenceNonExecutedCauseV1::Unsupported)?;
        let class: &[u8] = if self.hit {
            b"cache-hit"
        } else {
            b"cache-miss"
        };
        Ok(NonInterferenceRawCaptureV1 {
            surface_names: names.iter().map(|name| (*name).to_owned()).collect(),
            authoritative: names
                .iter()
                .map(|name| [name.as_bytes(), state.as_slice(), payloads.as_slice()].concat())
                .collect(),
            public: names
                .iter()
                .map(|name| format!("{name}:{}", observation.events.len()).into_bytes())
                .collect(),
            operational: names
                .iter()
                .map(|_| {
                    pos_conformance::NonInterferenceRawOperationalV1::ByteExact(class.to_vec())
                })
                .collect(),
            unexpected_network_accesses: 0,
            provenance_digest: [1; 32],
        })
    }
}

// ---------------------------------------------------------------------------
// Acceptance: each runner signs, publishes and passes the verifier
// ---------------------------------------------------------------------------

#[test]
fn each_runner_signs_a_published_nia1_the_independent_verifier_accepts() -> TestResult {
    let work = tempfile::tempdir()?;
    let root = tempfile::tempdir()?;
    let mut harness = all_runners(work.path())?;
    for mode in EXECUTABLE_MODES {
        let outcome = harness.execute_case(&probe_fixture(
            NonInterferenceVariantV1::Success,
            mode,
            b"probe-input",
        )?);
        let execution = executed(&outcome)?;
        assert_eq!(outcome.claim(), Some(true), "{mode:?}");
        assert_eq!(outcome.non_executed_cause(), None);
        assert_eq!(execution.artifact().mode, mode);
        assert_eq!(execution.artifact().executor_public_key, key().public_key());
        assert_eq!(execution.case().mode, mode);
        assert_eq!(execution.preparation(), NonInterferencePreparationV1::Cold);
        assert!(execution.canonical_bytes().len() <= 4 * 1024);
        assert_eq!(
            verify_non_interference_execution_artifact_v1(
                execution.canonical_bytes(),
                &[key().public_key()]
            ),
            Ok(execution.content_digest())
        );

        let path = publish_non_interference_execution_v1(root.path(), execution)?;
        assert_eq!(
            path,
            non_interference_publication_path_v1(root.path(), &execution.content_digest())
        );
        assert!(path.starts_with(root.path().join(NON_INTERFERENCE_PUBLICATION_DIRECTORY_V1)));
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        assert_eq!(name, format!("{}.nia1", hex(&execution.content_digest())));
        let published = fs::read(&path)?;
        assert_eq!(published, execution.canonical_bytes());
        assert_eq!(
            verify_non_interference_execution_artifact_v1(&published, &[key().public_key()]),
            Ok(execution.content_digest())
        );
        assert_eq!(
            NonInterferenceExecutionArtifactV1::from_canonical_cbor(&published)?,
            *execution.artifact()
        );
        assert_eq!(
            verify_non_interference_execution_artifact_v1(&published, &[[3; 32]]),
            Err(IndependentNonInterferenceReportErrorV1::InvalidShape)
        );
        // Publication is immutable and idempotent.
        assert_eq!(
            publish_non_interference_execution_v1(root.path(), execution)?,
            path
        );
    }
    Ok(())
}

#[test]
fn an_interfering_subject_is_signed_unequal_at_its_first_coordinate() -> TestResult {
    let work = tempfile::tempdir()?;
    let mut harness = all_runners(work.path())?;
    let outcome = harness.execute_case(&probe_fixture(
        NonInterferenceVariantV1::Denial,
        ExecutionModeV1::Local,
        b"leak:probe-input",
    )?);
    let execution = executed(&outcome)?;
    assert_eq!(outcome.claim(), Some(false));
    let divergence = execution
        .artifact()
        .divergence
        .clone()
        .ok_or("no divergence")?;
    assert_eq!(divergence.mode, ExecutionModeV1::Local);
    assert_eq!(divergence.surface_ordinal, 0);
    assert!(!execution.case().public_equal);
    assert!(execution.case().authoritative_equal);
    assert_eq!(
        verify_non_interference_execution_artifact_v1(
            execution.canonical_bytes(),
            &[key().public_key()]
        ),
        Ok(execution.content_digest())
    );
    Ok(())
}

#[test]
fn warm_and_cold_preparation_are_both_exercised_in_every_runner() -> TestResult {
    let work = tempfile::tempdir()?;
    let mut harness = all_runners(work.path())?;
    assert_eq!(
        NonInterferencePreparationV1::for_variant(NonInterferenceVariantV1::WarmCache),
        NonInterferencePreparationV1::Warm
    );
    for variant in [
        NonInterferenceVariantV1::Success,
        NonInterferenceVariantV1::Denial,
        NonInterferenceVariantV1::ColdCache,
    ] {
        assert_eq!(
            NonInterferencePreparationV1::for_variant(variant),
            NonInterferencePreparationV1::Cold
        );
    }
    for mode in EXECUTABLE_MODES {
        let warm_outcome = harness.execute_case(&probe_fixture(
            NonInterferenceVariantV1::WarmCache,
            mode,
            b"cache-input",
        )?);
        let cold_outcome = harness.execute_case(&probe_fixture(
            NonInterferenceVariantV1::ColdCache,
            mode,
            b"cache-input",
        )?);
        let warm = executed(&warm_outcome)?;
        let cold = executed(&cold_outcome)?;
        assert_eq!(
            warm.preparation(),
            NonInterferencePreparationV1::Warm,
            "{mode:?}"
        );
        assert_eq!(
            cold.preparation(),
            NonInterferencePreparationV1::Cold,
            "{mode:?}"
        );
        assert_eq!(warm_outcome.claim(), Some(true), "{mode:?}");
        assert_eq!(cold_outcome.claim(), Some(true), "{mode:?}");
        // The primed environment is observed only by the warm case.
        assert_eq!(
            warm.case().authoritative_digest,
            cold.case().authoritative_digest
        );
        assert_ne!(
            warm.case().operational_digest,
            cold.case().operational_digest,
            "{mode:?}"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Acceptance: Air-Gapped and every non-executed cause make no claim
// ---------------------------------------------------------------------------

#[test]
fn every_air_gapped_case_is_unavailable_and_never_a_pass_or_fail() -> TestResult {
    let work = tempfile::tempdir()?;
    let root = tempfile::tempdir()?;
    // A runner claiming the Air-Gapped mode is dropped: the mode is reserved.
    let mut harness = all_runners(work.path())?.with_runner(TestRunner::boxed(
        ExecutionModeV1::AirGapped,
        Behaviour::Probe,
    )?);
    for variant in VARIANTS {
        let fixture = probe_fixture(variant, ExecutionModeV1::AirGapped, b"probe-input")?;
        let outcome = harness.execute_case(&fixture);
        assert_eq!(
            outcome,
            NonInterferenceRunOutcomeV1::NonExecuted {
                fixture_id: LOCAL_PROBE_FIXTURE_ID_V1.to_owned(),
                variant,
                mode: ExecutionModeV1::AirGapped,
                cause: NonInterferenceNonExecutedCauseV1::Unavailable,
            }
        );
        assert_eq!(outcome.claim(), None);
    }
    let mut runner = NonInterferenceAirGappedRunnerV1;
    assert_eq!(runner.mode(), ExecutionModeV1::AirGapped);
    assert_eq!(runner.prepare(NonInterferencePreparationV1::Cold), Ok(()));
    assert!(!root
        .path()
        .join(NON_INTERFERENCE_PUBLICATION_DIRECTORY_V1)
        .exists());
    Ok(())
}

#[test]
fn every_runner_reported_cause_is_non_executed_with_no_claim() -> TestResult {
    for cause in [
        NonInterferenceNonExecutedCauseV1::Missing,
        NonInterferenceNonExecutedCauseV1::Skipped,
        NonInterferenceNonExecutedCauseV1::Unsupported,
        NonInterferenceNonExecutedCauseV1::Unavailable,
        NonInterferenceNonExecutedCauseV1::LiveCall,
        NonInterferenceNonExecutedCauseV1::UnknownField,
        NonInterferenceNonExecutedCauseV1::Budget,
        NonInterferenceNonExecutedCauseV1::SignatureFailure,
    ] {
        let mut harness = harness_with(vec![TestRunner::boxed(
            ExecutionModeV1::Local,
            Behaviour::Fail(cause),
        )?]);
        for variant in VARIANTS {
            let fixture = probe_fixture(variant, ExecutionModeV1::Local, b"probe-input")?;
            assert_eq!(cause_of(&mut harness, &fixture), Some(cause), "{cause}");
        }
    }
    Ok(())
}

#[test]
fn each_non_executed_cause_arises_at_its_harness_boundary() -> TestResult {
    let work = tempfile::tempdir()?;
    let local = |permitted: &[u8]| {
        probe_fixture(
            NonInterferenceVariantV1::Success,
            ExecutionModeV1::Local,
            permitted,
        )
    };

    // Missing: no runner for the mode, or a fixture whose content address is wrong.
    let mut empty = harness_with(Vec::new());
    assert_eq!(
        cause_of(
            &mut empty,
            &probe_fixture(
                NonInterferenceVariantV1::Success,
                ExecutionModeV1::Replay,
                b"x"
            )?
        ),
        Some(NonInterferenceNonExecutedCauseV1::Missing)
    );
    let mut harness = all_runners(work.path())?;
    let mut tampered = local(b"probe-input")?;
    tampered.fixture_digest = [1; 32];
    assert_eq!(
        cause_of(&mut harness, &tampered),
        Some(NonInterferenceNonExecutedCauseV1::Missing)
    );

    // Live call: the probe records one network attempt.
    assert_eq!(
        cause_of(&mut harness, &local(b"net:probe-input")?),
        Some(NonInterferenceNonExecutedCauseV1::LiveCall)
    );
    // Unavailable: the probe process refuses an unsupported row and exits non-zero.
    assert_eq!(
        cause_of(
            &mut harness,
            &fixture(
                "NI-TOOL-001",
                NonInterferenceVariantV1::Success,
                ExecutionModeV1::Local,
                b"x"
            )?
        ),
        Some(NonInterferenceNonExecutedCauseV1::Unavailable)
    );
    // Unsupported: the session subject does not serve the row.
    for mode in [ExecutionModeV1::Replay, ExecutionModeV1::Fork] {
        assert_eq!(
            cause_of(
                &mut harness,
                &fixture("NI-TOOL-001", NonInterferenceVariantV1::Success, mode, b"x")?
            ),
            Some(NonInterferenceNonExecutedCauseV1::Unsupported)
        );
    }
    // Signature failure: the harness does not trust its own executor key.
    let mut untrusted = NonInterferenceHarnessV1::new(key(), vec![[3; 32]])
        .with_runner(TestRunner::boxed(ExecutionModeV1::Local, Behaviour::Probe)?);
    assert_eq!(
        cause_of(&mut untrusted, &local(b"probe-input")?),
        Some(NonInterferenceNonExecutedCauseV1::SignatureFailure)
    );
    // The #181 normalizer's closed errors: an incomplete or out-of-bounds capture.
    for (edit, cause) in [
        (
            Behaviour::Edited(|capture| capture.surface_names.clear()),
            NonInterferenceNonExecutedCauseV1::Unavailable,
        ),
        (
            Behaviour::Edited(|capture| capture.authoritative[0].clear()),
            NonInterferenceNonExecutedCauseV1::Budget,
        ),
    ] {
        let mut edited = harness_with(vec![TestRunner::boxed(ExecutionModeV1::Local, edit)?]);
        assert_eq!(cause_of(&mut edited, &local(b"probe-input")?), Some(cause));
    }
    Ok(())
}

#[test]
fn the_local_runner_refuses_malformed_unknown_and_over_budget_frames() -> TestResult {
    let work = tempfile::tempdir()?;
    let frames = tempfile::tempdir()?;
    let fixture = probe_fixture(
        NonInterferenceVariantV1::Success,
        ExecutionModeV1::Local,
        b"probe-input",
    )?;
    let capture = local_probe_subject_v1(
        &NonInterferenceLocalRequestV1 {
            magic: NON_INTERFERENCE_LOCAL_REQUEST_MAGIC_V1.to_owned(),
            version: 1,
            fixture_id: LOCAL_PROBE_FIXTURE_ID_V1.to_owned(),
            variant: NonInterferenceVariantV1::Success,
            mode: ExecutionModeV1::Local,
            preparation: NonInterferencePreparationV1::Cold,
            permitted_input: b"probe-input".to_vec(),
            unauthorized_value: CONTROL.to_vec(),
        },
        frames.path(),
    )?;
    let frame = |magic: &str, extra: Option<(&str, Value)>| -> TestResult<Vec<u8>> {
        let mut value =
            json!({ "magic": magic, "version": 1, "capture": serde_json::to_value(&capture)? });
        if let (Some((name, field)), Some(object)) = (extra, value.as_object_mut()) {
            object.insert(name.to_owned(), field);
        }
        Ok(pos_crypto::canonical::encode(&value)?.as_slice().to_vec())
    };
    let echo = "cat >/dev/null; cat \"$1\"";
    for (name, bytes, cause) in [
        (
            "unknown",
            frame(
                NON_INTERFERENCE_LOCAL_CAPTURE_MAGIC_V1,
                Some(("extra", json!(1))),
            )?,
            NonInterferenceNonExecutedCauseV1::UnknownField,
        ),
        (
            "magic",
            frame("XXXX", None)?,
            NonInterferenceNonExecutedCauseV1::Unsupported,
        ),
        (
            "garbage",
            b"\xff\x00".to_vec(),
            NonInterferenceNonExecutedCauseV1::Unavailable,
        ),
    ] {
        let path = frames.path().join(name);
        fs::write(&path, bytes)?;
        let mut harness = harness_with(vec![Box::new(shell_runner(
            &work.path().join(name),
            echo,
            &path,
        )?)]);
        assert_eq!(cause_of(&mut harness, &fixture), Some(cause), "{name}");
    }
    // A well-formed frame from a process that then fails is unavailable.
    let valid = frames.path().join("valid");
    fs::write(
        &valid,
        frame(NON_INTERFERENCE_LOCAL_CAPTURE_MAGIC_V1, None)?,
    )?;
    let mut failing = harness_with(vec![Box::new(shell_runner(
        &work.path().join("failing"),
        "cat >/dev/null; cat \"$1\"; exit 3",
        &valid,
    )?)]);
    assert_eq!(
        cause_of(&mut failing, &fixture),
        Some(NonInterferenceNonExecutedCauseV1::Unavailable)
    );
    // The same frame from a process that succeeds executes.
    let mut echoing = harness_with(vec![Box::new(shell_runner(
        &work.path().join("echoing"),
        echo,
        &valid,
    )?)]);
    assert_eq!(echoing.execute_case(&fixture).claim(), Some(true));
    // Output over the budget is refused before it is decoded.
    let mut bounded = harness_with(vec![Box::new(
        probe_runner(&work.path().join("bounded"))?.with_output_budget(16),
    )]);
    assert_eq!(
        cause_of(&mut bounded, &fixture),
        Some(NonInterferenceNonExecutedCauseV1::Budget)
    );
    Ok(())
}

#[test]
fn the_local_runner_reports_host_failures_as_unavailable() -> TestResult {
    let work = tempfile::tempdir()?;
    assert!(NonInterferenceLocalProcessRunnerV1::new(
        work.path().join("absent"),
        work.path().to_path_buf()
    )
    .is_err());
    // A program that cannot be executed.
    let program = work.path().join("not-executable");
    fs::write(&program, b"#!/bin/sh\n")?;
    let mut harness = harness_with(vec![Box::new(NonInterferenceLocalProcessRunnerV1::new(
        program,
        work.path().join("work"),
    )?)]);
    let cold = probe_fixture(
        NonInterferenceVariantV1::Success,
        ExecutionModeV1::Local,
        b"probe-input",
    )?;
    let warm = probe_fixture(
        NonInterferenceVariantV1::WarmCache,
        ExecutionModeV1::Local,
        b"probe-input",
    )?;
    assert_eq!(
        cause_of(&mut harness, &cold),
        Some(NonInterferenceNonExecutedCauseV1::Unavailable)
    );
    // A work root that is a file: no run directory can be created.
    let file_root = work.path().join("file-root");
    fs::write(&file_root, b"file")?;
    let mut blocked = harness_with(vec![Box::new(NonInterferenceLocalProcessRunnerV1::new(
        PathBuf::from(PROBE),
        file_root,
    )?)]);
    for fixture in [&cold, &warm] {
        assert_eq!(
            cause_of(&mut blocked, fixture),
            Some(NonInterferenceNonExecutedCauseV1::Unavailable)
        );
    }
    Ok(())
}

#[test]
fn the_session_runners_report_host_failures_as_unavailable() -> TestResult {
    let fixture_in = |mode| probe_fixture(NonInterferenceVariantV1::Success, mode, b"probe-input");
    let failing = |mode| probe_fixture(NonInterferenceVariantV1::Success, mode, b"fail");
    let unavailable = Some(NonInterferenceNonExecutedCauseV1::Unavailable);
    // A failing Driver, in the recorded run and in the parent before the Fork Cut.
    let mut harness = harness_with(vec![
        Box::new(NonInterferenceReplayRunnerV1::new(SessionProbe::new())),
        Box::new(NonInterferenceForkRunnerV1::new(SessionProbe::new(), 1)),
    ]);
    for mode in [ExecutionModeV1::Replay, ExecutionModeV1::Fork] {
        assert_eq!(
            cause_of(&mut harness, &failing(mode)?),
            unavailable,
            "{mode:?}"
        );
    }
    // A Driver that fails only after the Fork Cut: the parent cuts at Tick 0.
    let mut uncut = harness_with(vec![Box::new(NonInterferenceForkRunnerV1::new(
        SessionProbe::new(),
        0,
    ))]);
    assert_eq!(
        cause_of(&mut uncut, &failing(ExecutionModeV1::Fork)?),
        unavailable
    );
    // No Fork registry factory.
    let mut no_factory = SessionProbe::new();
    no_factory.fork_factory = false;
    let mut unforkable = harness_with(vec![Box::new(NonInterferenceForkRunnerV1::new(
        no_factory, 1,
    ))]);
    assert_eq!(
        cause_of(&mut unforkable, &fixture_in(ExecutionModeV1::Fork)?),
        unavailable
    );
    // A Projection registry without an erasure gate cannot be read.
    let ungated = || {
        let mut subject = SessionProbe::new();
        subject.gate = false;
        subject
    };
    let ungated_runners: [(ExecutionModeV1, Box<dyn NonInterferenceModeRunnerV1>); 2] = [
        (
            ExecutionModeV1::Replay,
            Box::new(NonInterferenceReplayRunnerV1::new(ungated())),
        ),
        (
            ExecutionModeV1::Fork,
            Box::new(NonInterferenceForkRunnerV1::new(ungated(), 1)),
        ),
    ];
    for (mode, runner) in ungated_runners {
        let mut harness = harness_with(vec![runner]);
        assert_eq!(
            cause_of(&mut harness, &fixture_in(mode)?),
            unavailable,
            "{mode:?}"
        );
    }
    Ok(())
}

#[test]
fn the_local_probe_serves_its_request_in_process() -> TestResult {
    let directory = tempfile::tempdir()?;
    let request = |magic: &str| NonInterferenceLocalRequestV1 {
        magic: magic.to_owned(),
        version: 1,
        fixture_id: LOCAL_PROBE_FIXTURE_ID_V1.to_owned(),
        variant: NonInterferenceVariantV1::Success,
        mode: ExecutionModeV1::Local,
        preparation: NonInterferencePreparationV1::Cold,
        permitted_input: b"probe-input".to_vec(),
        unauthorized_value: CONTROL.to_vec(),
    };
    let encoded = |value: &Value| -> TestResult<Vec<u8>> {
        Ok(pos_crypto::canonical::encode(value)?.as_slice().to_vec())
    };
    let valid = encoded(&serde_json::to_value(request(
        NON_INTERFERENCE_LOCAL_REQUEST_MAGIC_V1,
    ))?)?;
    let mut output = Vec::new();
    serve_local_probe_v1(valid.as_slice(), &mut output, directory.path())?;
    assert!(!output.is_empty());
    assert_eq!(fs::read(directory.path().join("denied-channel"))?, CONTROL);

    let mut unknown = serde_json::to_value(request(NON_INTERFERENCE_LOCAL_REQUEST_MAGIC_V1))?;
    if let Some(object) = unknown.as_object_mut() {
        object.insert("extra".to_owned(), json!(true));
    }
    let wrong_magic = encoded(&serde_json::to_value(request("XXXX"))?)?;
    let mut other_row = request(NON_INTERFERENCE_LOCAL_REQUEST_MAGIC_V1);
    "NI-TOOL-001".clone_into(&mut other_row.fixture_id);
    for (bytes, cause) in [
        (
            encoded(&unknown)?,
            NonInterferenceNonExecutedCauseV1::UnknownField,
        ),
        (wrong_magic, NonInterferenceNonExecutedCauseV1::Unsupported),
        (
            b"\xff".to_vec(),
            NonInterferenceNonExecutedCauseV1::Unavailable,
        ),
        (
            encoded(&serde_json::to_value(other_row)?)?,
            NonInterferenceNonExecutedCauseV1::Unsupported,
        ),
    ] {
        let mut output = Vec::new();
        assert_eq!(
            serve_local_probe_v1(bytes.as_slice(), &mut output, directory.path()),
            Err(cause)
        );
        assert!(output.is_empty());
    }
    // A closed output stream.
    assert_eq!(
        serve_local_probe_v1(valid.as_slice(), ClosedWriter, directory.path()),
        Err(NonInterferenceNonExecutedCauseV1::Unavailable)
    );
    // A working directory that cannot be written.
    assert_eq!(
        local_probe_subject_v1(
            &request(NON_INTERFERENCE_LOCAL_REQUEST_MAGIC_V1),
            &directory.path().join("absent")
        ),
        Err(NonInterferenceNonExecutedCauseV1::Unavailable)
    );
    Ok(())
}

struct ClosedWriter;

impl std::io::Write for ClosedWriter {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Publication and inventory
// ---------------------------------------------------------------------------

#[test]
fn publication_is_immutable_and_changes_no_inventory() -> TestResult {
    let root = tempfile::tempdir()?;
    let repository_matrix = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/conformance/matrix/execution-matrix.json");
    let matrix_bytes = fs::read(&repository_matrix)?;
    let matrix: Value = serde_json::from_slice(&matrix_bytes)?;
    assert_eq!(matrix["executed_case_count"], json!(0));
    let cases = matrix["cases"].as_array().ok_or("no cases")?;
    assert_eq!(cases.len(), 192);
    assert!(cases.iter().all(|case| case["executed"] == json!(false)));
    let copied_matrix = root.path().join("matrix/execution-matrix.json");
    fs::create_dir_all(root.path().join("matrix"))?;
    fs::write(&copied_matrix, &matrix_bytes)?;

    let mut harness = harness_with(vec![TestRunner::boxed(
        ExecutionModeV1::Local,
        Behaviour::Probe,
    )?]);
    let mut published = Vec::new();
    for variant in VARIANTS {
        let outcome = harness.execute_case(&probe_fixture(
            variant,
            ExecutionModeV1::Local,
            b"probe-input",
        )?);
        published.push(publish_non_interference_execution_v1(
            root.path(),
            executed(&outcome)?,
        )?);
    }
    assert_eq!(fs::read(&copied_matrix)?, matrix_bytes);
    assert_eq!(
        fs::read_dir(root.path().join(NON_INTERFERENCE_PUBLICATION_DIRECTORY_V1))?.count(),
        VARIANTS.len()
    );

    let outcome = harness.execute_case(&probe_fixture(
        NonInterferenceVariantV1::Success,
        ExecutionModeV1::Local,
        b"other-input",
    )?);
    let execution = executed(&outcome)?;
    // Different bytes at the content address are a conflict, never a rewrite.
    let address = non_interference_publication_path_v1(root.path(), &execution.content_digest());
    fs::write(&address, b"other bytes")?;
    assert_eq!(
        publish_non_interference_execution_v1(root.path(), execution),
        Err(NonInterferencePublicationErrorV1::Conflict)
    );
    assert_eq!(fs::read(&address)?, b"other bytes");
    // A directory at the address cannot be read as the artifact.
    fs::remove_file(&address)?;
    fs::create_dir(&address)?;
    let unreadable = publish_non_interference_execution_v1(root.path(), execution);
    assert!(unreadable.is_err());
    assert_ne!(unreadable, Err(NonInterferencePublicationErrorV1::Conflict));
    // A root that is a file cannot hold the publication directory.
    let file_root = root.path().join("file-root");
    fs::write(&file_root, b"file")?;
    let unwritable = publish_non_interference_execution_v1(&file_root, execution);
    assert!(unwritable.is_err());
    assert_ne!(unwritable, Err(NonInterferencePublicationErrorV1::Conflict));
    assert_eq!(published.len(), VARIANTS.len());
    Ok(())
}

#[test]
fn keys_and_harness_debug_forms_show_only_public_material() {
    let rendered = format!("{:?}", key());
    assert!(rendered.contains(&hex(&key().public_key())));
    assert!(!rendered.contains(&hex(&SECRET)));
    let harness = harness_with(Vec::new());
    assert!(format!("{harness:?}").contains("NonInterferenceHarnessV1"));
    assert_ne!(
        HostExecutorKeyV1::from_secret_bytes(&OTHER_SECRET).public_key(),
        key().public_key()
    );
}

// ---------------------------------------------------------------------------
// NIR1: only 192 trusted NIA1 build a report
// ---------------------------------------------------------------------------

/// One test-signed NIA1 per coordinate (test-only data, not a claim).
fn synthetic_artifacts(secret: &[u8; 32]) -> TestResult<Vec<Vec<u8>>> {
    let signing = ed25519_dalek::SigningKey::from_bytes(secret);
    let profiles = non_interference_capture_profiles_v1();
    let mut artifacts = Vec::new();
    for (row, fixture_id) in NON_INTERFERENCE_FIXTURE_IDS_V1.iter().enumerate() {
        let profile = profiles
            .iter()
            .find(|profile| profile.fixture_id == *fixture_id)
            .ok_or("no profile")?;
        for (variant_index, variant) in VARIANTS.iter().enumerate() {
            for (mode_index, mode) in MODES.iter().enumerate() {
                let seed = [
                    u8::try_from(row)?,
                    u8::try_from(variant_index)?,
                    u8::try_from(mode_index)?,
                ];
                let artifact = NonInterferenceExecutionArtifactV1::sign(
                    NonInterferenceExecutionArtifactBodyV1 {
                        fixture_id: (*fixture_id).to_owned(),
                        variant: *variant,
                        mode: *mode,
                        fixture_digest: *blake3::hash(&seed[..2]).as_bytes(),
                        profile_digest: profile.profile_digest,
                        normalization_digest: non_interference_normalization_digest_v1(fixture_id)
                            .ok_or("no normalization")?,
                        result_digest: *blake3::hash(&[seed[0], seed[1], 0xff]).as_bytes(),
                        execution_provenance_digest: *blake3::hash(&seed).as_bytes(),
                        equal: true,
                        divergence: None,
                    },
                    &signing,
                )?;
                artifacts.push(artifact.to_canonical_cbor()?);
            }
        }
    }
    Ok(artifacts)
}

#[test]
fn fewer_than_192_nia1_build_no_report() -> TestResult {
    let artifacts = synthetic_artifacts(&SECRET)?;
    let trusted = [key().public_key()];
    for count in [0, 3, 144, 191] {
        assert_eq!(
            build_non_interference_report_v1(&artifacts[..count], &trusted, &key()).err(),
            Some(NonInterferenceReportErrorV1::InvalidShape),
            "{count}"
        );
    }
    // The harness's own executed cases are not a report either.
    let mut harness = harness_with(vec![TestRunner::boxed(
        ExecutionModeV1::Local,
        Behaviour::Probe,
    )?]);
    let mut executed_bytes = Vec::new();
    for variant in VARIANTS {
        let outcome = harness.execute_case(&probe_fixture(
            variant,
            ExecutionModeV1::Local,
            b"probe-input",
        )?);
        executed_bytes.push(executed(&outcome)?.canonical_bytes().to_vec());
    }
    assert_eq!(
        build_non_interference_report_v1(&executed_bytes, &trusted, &key()).err(),
        Some(NonInterferenceReportErrorV1::InvalidShape)
    );
    let mut over = artifacts;
    over.push(executed_bytes[0].clone());
    assert_eq!(
        build_non_interference_report_v1(&over, &trusted, &key()).err(),
        Some(NonInterferenceReportErrorV1::InvalidShape)
    );
    Ok(())
}

#[test]
fn exactly_192_trusted_nia1_build_a_report_the_independent_verifier_accepts() -> TestResult {
    let artifacts = synthetic_artifacts(&SECRET)?;
    let trusted = [key().public_key()];
    let report = build_non_interference_report_v1(&artifacts, &trusted, &key())?;
    assert!(report.is_conformant());
    let bytes = report.to_canonical_cbor()?;
    assert_eq!(
        verify_non_interference_report_v1(&bytes, &key().public_key(), &trusted, &artifacts),
        Ok(true)
    );

    // An untrusted executor.
    assert_eq!(
        build_non_interference_report_v1(&artifacts, &[[3; 32]], &key()).err(),
        Some(NonInterferenceReportErrorV1::SignatureInvalid)
    );
    // A repeated coordinate.
    let mut repeated = artifacts.clone();
    repeated[1] = repeated[0].clone();
    assert_eq!(
        build_non_interference_report_v1(&repeated, &trusted, &key()).err(),
        Some(NonInterferenceReportErrorV1::InvalidShape)
    );
    // A malformed artifact.
    let mut malformed = artifacts.clone();
    malformed[5] = b"\xff".to_vec();
    assert_eq!(
        build_non_interference_report_v1(&malformed, &trusted, &key()).err(),
        Some(NonInterferenceReportErrorV1::NonCanonical)
    );
    // One mode of a row/variant names another fixture: the artifacts do not
    // form one report.
    let other = synthetic_artifacts(&SECRET)?;
    let mut mixed = artifacts;
    let signing = ed25519_dalek::SigningKey::from_bytes(&SECRET);
    let mut moved = NonInterferenceExecutionArtifactV1::from_canonical_cbor(&other[1])?;
    moved.fixture_digest = [0xee; 32];
    let resigned = NonInterferenceExecutionArtifactV1::sign(
        NonInterferenceExecutionArtifactBodyV1 {
            fixture_id: moved.fixture_id.clone(),
            variant: moved.variant,
            mode: moved.mode,
            fixture_digest: moved.fixture_digest,
            profile_digest: moved.profile_digest,
            normalization_digest: moved.normalization_digest,
            result_digest: moved.result_digest,
            execution_provenance_digest: moved.execution_provenance_digest,
            equal: moved.equal,
            divergence: moved.divergence,
        },
        &signing,
    )?;
    mixed[1] = resigned.to_canonical_cbor()?;
    assert_eq!(
        build_non_interference_report_v1(&mixed, &trusted, &key()).err(),
        Some(NonInterferenceReportErrorV1::InvalidShape)
    );
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
