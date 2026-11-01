//! The ADR-059 non-interference mode harness (ADR-062 Revision 8 slice N0,
//! #1227).
//!
//! The harness feeds the #181 framework in `pos_conformance`: it runs one
//! admitted control/canary [`NonInterferenceFixturePairV1`] in the fixture's
//! Execution Mode, normalizes each raw capture with
//! [`normalize_non_interference_capture_v1`], compares the pair with
//! [`execute_non_interference_pair`] and signs the case as one `NIA1`
//! [`NonInterferenceExecutionArtifactV1`] with the [`HostExecutorKeyV1`].
//! [`publish_non_interference_execution_v1`] then writes the canonical
//! artifact bytes at their content address below `fixtures/conformance`.
//!
//! # Modes
//!
//! - Local: [`NonInterferenceLocalProcessRunnerV1`] spawns a fresh host
//!   process for every run, bounded by a host kill timeout.
//! - Replay: [`NonInterferenceReplayRunnerV1`] records the subject's run and
//!   rebuilds its Projection State from the recorded Events alone.
//! - Fork: [`NonInterferenceForkRunnerV1`] runs the subject in an ordinary
//!   Fork of its Timeline cut at a Tick Boundary (`ExperimentSession::fork`).
//!   Its F-mode evidence is engineering evidence (owner note
//!   `ADR-062_R8_NonInterference_Harness`, decision 4): it counts for every
//!   row except `NI-FORK-008`, which needs the ADR-064 records-form artifact
//!   path of slice R6 (#1225) in slice N4 (#1232), and every F case is re-run
//!   when Driver-declared provisional Ticks land (#1204).
//! - Air-Gapped: [`NonInterferenceAirGappedRunnerV1`] is the only runner the
//!   harness uses for this mode, and every run is the typed non-executed
//!   [`NonInterferenceNonExecutedCauseV1::Unavailable`] until the
//!   kernel-audited Sandbox Provider runs land (slice N7, owner answer Q8:
//!   M-B). No Local-relaxation run is counted as Air-Gapped.
//!
//! # Preparation
//!
//! [`NonInterferencePreparationV1::for_variant`] selects warm preparation for
//! the `WarmCache` variant and cold preparation for every other variant. A
//! runner resets its environment for each case
//! ([`NonInterferenceModeRunnerV1::prepare`]); for a warm case the harness then
//! primes that environment with one run of the permitted input and an empty
//! unauthorized value, whose capture is discarded, before the control and
//! canary runs. A cold run starts from a fresh environment every time.
//!
//! # Non-executed
//!
//! Missing, skipped, unsupported, unavailable, live-call, unknown-field,
//! budget and signature failures are
//! [`NonInterferenceRunOutcomeV1::NonExecuted`]: there is no artifact, nothing
//! to publish and [`NonInterferenceRunOutcomeV1::claim`] is `None`. Only an
//! executed case carries a pass/fail claim, and that claim is engineering
//! evidence for its one coordinate: it does not flip the ADR-059 inventory
//! (`execution-matrix.json`) and is not a report.
//!
//! # Report
//!
//! [`build_non_interference_report_v1`] builds an `NIR1` only from exactly
//! 192 trusted NIA1 artifacts, one per coordinate; with fewer it is
//! [`NonInterferenceReportErrorV1::InvalidShape`].

mod local_process;
#[cfg(feature = "test-support")]
pub mod probe;
mod session;

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use pos_conformance::{
    execute_non_interference_pair, non_interference_capture_profiles_v1,
    non_interference_normalization_digest_v1, normalize_non_interference_capture_v1,
    ExecutionModeV1, NonInterferenceCaseV1, NonInterferenceExecutionArtifactBodyV1,
    NonInterferenceExecutionArtifactV1, NonInterferenceExecutionErrorV1,
    NonInterferenceFixturePairV1, NonInterferenceHostRunV1, NonInterferenceInvocationV1,
    NonInterferenceMatrixMemberV1, NonInterferenceModeResultRefV1, NonInterferenceRawCaptureV1,
    NonInterferenceReportErrorV1, NonInterferenceReportOutcomeV1, NonInterferenceReportV1,
    NonInterferenceVariantV1, MAX_NON_INTERFERENCE_EXECUTION_ARTIFACT_BYTES_V1,
    NON_INTERFERENCE_CASE_COUNT_V1, NON_INTERFERENCE_FIXTURE_IDS_V1,
};
use serde::{Deserialize, Serialize};

pub use local_process::{
    serve_non_interference_local_subject_v1, NonInterferenceLocalProcessRunnerV1,
    NonInterferenceLocalRequestV1, DEFAULT_NON_INTERFERENCE_LOCAL_OUTPUT_BUDGET_V1,
    DEFAULT_NON_INTERFERENCE_LOCAL_TIMEOUT_V1, NON_INTERFERENCE_LOCAL_CAPTURE_MAGIC_V1,
    NON_INTERFERENCE_LOCAL_REQUEST_MAGIC_V1,
};
pub use session::{
    NonInterferenceForkRunnerV1, NonInterferenceReplayRunnerV1,
    NonInterferenceSessionObservationV1, NonInterferenceSessionSubjectV1,
};

/// The directory, relative to the `fixtures/conformance` root, that holds the
/// content-addressed NIA1 publications.
pub const NON_INTERFERENCE_PUBLICATION_DIRECTORY_V1: &str = "non-interference/executions";
/// The file extension of one published NIA1.
pub const NON_INTERFERENCE_PUBLICATION_EXTENSION_V1: &str = "nia1";

const RESULT_DOMAIN_V1: &[u8] = b"PiglorOS.NonInterference.HarnessResult.v1";
const ARTIFACT_DOMAIN_V1: &[u8] = b"PiglorOS.NonInterference.ExecutionArtifact.v1";

/// Distinguishes the staged files of concurrent publications in one process.
static STAGED_PUBLICATIONS: AtomicU64 = AtomicU64::new(0);

/// The host executor key that signs every NIA1 the harness produces.
///
/// Its public key is the executor key an NIR1 verifier must trust. The secret
/// never leaves this value; its `Debug` form shows only the public key.
pub struct HostExecutorKeyV1 {
    signing: ed25519_dalek::SigningKey,
}

impl HostExecutorKeyV1 {
    /// The executor key with the given Ed25519 secret.
    #[must_use]
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Self {
        Self {
            signing: ed25519_dalek::SigningKey::from_bytes(secret),
        }
    }

    /// The Ed25519 public key an NIA1 names as its executor.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }
}

impl fmt::Debug for HostExecutorKeyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostExecutorKeyV1")
            .field("public_key", &hex(&self.public_key()))
            .finish_non_exhaustive()
    }
}

/// How a runner's environment is prepared for one case.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NonInterferencePreparationV1 {
    /// The environment is primed by one discarded run before the pair runs.
    Warm,
    /// Every run starts from a fresh environment.
    Cold,
}

impl NonInterferencePreparationV1 {
    /// The preparation of an ADR-059 variant: warm for `WarmCache`, cold for
    /// every other variant.
    #[must_use]
    pub const fn for_variant(variant: NonInterferenceVariantV1) -> Self {
        match variant {
            NonInterferenceVariantV1::WarmCache => Self::Warm,
            NonInterferenceVariantV1::Success
            | NonInterferenceVariantV1::Denial
            | NonInterferenceVariantV1::ColdCache => Self::Cold,
        }
    }
}

/// Why a case was not executed. A non-executed case never carries a claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NonInterferenceNonExecutedCauseV1 {
    /// No runner, fixture or capture exists for the coordinate.
    #[error("non-interference case is missing")]
    Missing,
    /// The case was deliberately not run. Only a runner or its subject
    /// reports it: no harness source emits `Skipped`.
    #[error("non-interference case was skipped")]
    Skipped,
    /// The runner or its subject does not support the coordinate.
    #[error("non-interference case is unsupported")]
    Unsupported,
    /// The mode or a required host resource is unavailable.
    #[error("non-interference case is unavailable")]
    Unavailable,
    /// A deterministic run attempted live network access.
    #[error("non-interference case attempted a live call")]
    LiveCall,
    /// A host transport frame carried a field its schema does not declare.
    #[error("non-interference capture carried an unknown field")]
    UnknownField,
    /// A run exceeded its deterministic budget.
    #[error("non-interference case exceeded its budget")]
    Budget,
    /// The case could not be signed as an NIA1 the harness trusts.
    #[error("non-interference execution artifact failed its signature check")]
    SignatureFailure,
}

impl From<NonInterferenceExecutionErrorV1> for NonInterferenceNonExecutedCauseV1 {
    fn from(error: NonInterferenceExecutionErrorV1) -> Self {
        match error {
            NonInterferenceExecutionErrorV1::FixtureInvalid => Self::Missing,
            NonInterferenceExecutionErrorV1::CaptureUnavailable => Self::Unavailable,
            NonInterferenceExecutionErrorV1::CaptureOutOfBounds => Self::Budget,
            NonInterferenceExecutionErrorV1::UnexpectedNetworkAccess => Self::LiveCall,
        }
    }
}

/// A host I/O failure (spawning, piping or a working directory) leaves the
/// run unavailable.
impl From<std::io::Error> for NonInterferenceNonExecutedCauseV1 {
    fn from(_: std::io::Error) -> Self {
        Self::Unavailable
    }
}

/// One Execution Mode's runner.
///
/// A runner executes one host run of a subject and returns its raw capture;
/// the harness owns normalization, comparison and signing. A runner binds
/// its own execution provenance into the capture's `provenance_digest`.
pub trait NonInterferenceModeRunnerV1 {
    /// The Execution Mode this runner executes.
    fn mode(&self) -> ExecutionModeV1;

    /// Reset the runner's environment before one case.
    ///
    /// # Errors
    /// Returns the cause when the environment cannot be prepared.
    fn prepare(
        &mut self,
        preparation: NonInterferencePreparationV1,
    ) -> Result<(), NonInterferenceNonExecutedCauseV1>;

    /// Execute one host run in the prepared environment.
    ///
    /// # Errors
    /// Returns the cause when the run is not executed.
    fn execute(
        &mut self,
        run: &NonInterferenceHostRunV1<'_>,
        preparation: NonInterferencePreparationV1,
    ) -> Result<NonInterferenceRawCaptureV1, NonInterferenceNonExecutedCauseV1>;
}

/// The Air-Gapped runner until slice N7: every run is
/// [`NonInterferenceNonExecutedCauseV1::Unavailable`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NonInterferenceAirGappedRunnerV1;

impl NonInterferenceModeRunnerV1 for NonInterferenceAirGappedRunnerV1 {
    fn mode(&self) -> ExecutionModeV1 {
        ExecutionModeV1::AirGapped
    }

    fn prepare(
        &mut self,
        _preparation: NonInterferencePreparationV1,
    ) -> Result<(), NonInterferenceNonExecutedCauseV1> {
        Ok(())
    }

    fn execute(
        &mut self,
        _run: &NonInterferenceHostRunV1<'_>,
        _preparation: NonInterferencePreparationV1,
    ) -> Result<NonInterferenceRawCaptureV1, NonInterferenceNonExecutedCauseV1> {
        Err(NonInterferenceNonExecutedCauseV1::Unavailable)
    }
}

/// One executed case: the #181 case, its preparation and its signed NIA1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NonInterferenceSignedExecutionV1 {
    case: NonInterferenceCaseV1,
    preparation: NonInterferencePreparationV1,
    artifact: NonInterferenceExecutionArtifactV1,
    bytes: Vec<u8>,
    content_digest: [u8; 32],
}

impl NonInterferenceSignedExecutionV1 {
    /// The compared control/canary case.
    #[must_use]
    pub const fn case(&self) -> &NonInterferenceCaseV1 {
        &self.case
    }

    /// The preparation the case ran under.
    #[must_use]
    pub const fn preparation(&self) -> NonInterferencePreparationV1 {
        self.preparation
    }

    /// The signed NIA1.
    #[must_use]
    pub const fn artifact(&self) -> &NonInterferenceExecutionArtifactV1 {
        &self.artifact
    }

    /// The canonical NIA1 bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The NIA1 content address an NIR1 mode reference names.
    #[must_use]
    pub const fn content_digest(&self) -> [u8; 32] {
        self.content_digest
    }
}

/// The outcome of one case.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NonInterferenceRunOutcomeV1 {
    /// The case ran and is signed.
    Executed(Box<NonInterferenceSignedExecutionV1>),
    /// The case did not run; it has no artifact and no claim.
    NonExecuted {
        fixture_id: String,
        variant: NonInterferenceVariantV1,
        mode: ExecutionModeV1,
        cause: NonInterferenceNonExecutedCauseV1,
    },
}

impl NonInterferenceRunOutcomeV1 {
    /// Whether the control and canary runs were equal on every surface, for
    /// an executed case only. A non-executed case makes no claim.
    #[must_use]
    pub fn claim(&self) -> Option<bool> {
        self.execution().map(|execution| execution.artifact.equal)
    }

    /// The signed execution of an executed case.
    #[must_use]
    pub fn execution(&self) -> Option<&NonInterferenceSignedExecutionV1> {
        match self {
            Self::Executed(execution) => Some(execution.as_ref()),
            Self::NonExecuted { .. } => None,
        }
    }

    /// The cause of a non-executed case.
    #[must_use]
    pub const fn non_executed_cause(&self) -> Option<NonInterferenceNonExecutedCauseV1> {
        match self {
            Self::Executed(_) => None,
            Self::NonExecuted { cause, .. } => Some(*cause),
        }
    }
}

/// The mode harness: one runner per executable mode, the reserved Air-Gapped
/// runner and the host executor key.
pub struct NonInterferenceHarnessV1 {
    executor_key: HostExecutorKeyV1,
    trusted_executor_keys: Vec<[u8; 32]>,
    runners: BTreeMap<ExecutionModeV1, Box<dyn NonInterferenceModeRunnerV1>>,
    air_gapped: NonInterferenceAirGappedRunnerV1,
}

impl fmt::Debug for NonInterferenceHarnessV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NonInterferenceHarnessV1")
            .field("executor_key", &self.executor_key)
            .field("modes", &self.runners.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl NonInterferenceHarnessV1 {
    /// A harness that signs with `executor_key` and accepts an NIA1 only when
    /// its executor key is one of `trusted_executor_keys`.
    #[must_use]
    pub fn new(executor_key: HostExecutorKeyV1, trusted_executor_keys: Vec<[u8; 32]>) -> Self {
        Self {
            executor_key,
            trusted_executor_keys,
            runners: BTreeMap::new(),
            air_gapped: NonInterferenceAirGappedRunnerV1,
        }
    }

    /// Install the runner of its mode, replacing an earlier one.
    ///
    /// The Air-Gapped mode is reserved: a runner whose mode is Air-Gapped is
    /// dropped, and every Air-Gapped case stays
    /// [`NonInterferenceNonExecutedCauseV1::Unavailable`].
    #[must_use]
    pub fn with_runner(mut self, runner: Box<dyn NonInterferenceModeRunnerV1>) -> Self {
        let mode = runner.mode();
        if mode != ExecutionModeV1::AirGapped {
            self.runners.insert(mode, runner);
        }
        self
    }

    /// Run one case in its fixture's mode and sign it.
    #[must_use]
    pub fn execute_case(
        &mut self,
        fixture: &NonInterferenceFixturePairV1,
    ) -> NonInterferenceRunOutcomeV1 {
        let preparation = NonInterferencePreparationV1::for_variant(fixture.variant);
        let compared = self
            .runner(fixture.mode)
            .and_then(|runner| run_case(runner, fixture, preparation));
        match compared.and_then(|compared| self.sign(compared, preparation)) {
            Ok(execution) => NonInterferenceRunOutcomeV1::Executed(Box::new(execution)),
            Err(cause) => NonInterferenceRunOutcomeV1::NonExecuted {
                fixture_id: fixture.fixture_id.clone(),
                variant: fixture.variant,
                mode: fixture.mode,
                cause,
            },
        }
    }

    fn runner(
        &mut self,
        mode: ExecutionModeV1,
    ) -> Result<&mut dyn NonInterferenceModeRunnerV1, NonInterferenceNonExecutedCauseV1> {
        match mode {
            ExecutionModeV1::AirGapped => Ok(&mut self.air_gapped),
            ExecutionModeV1::Local | ExecutionModeV1::Replay | ExecutionModeV1::Fork => self
                .runners
                .get_mut(&mode)
                .map(|runner| &mut **runner as &mut dyn NonInterferenceModeRunnerV1)
                .ok_or(NonInterferenceNonExecutedCauseV1::Missing),
        }
    }

    fn sign(
        &self,
        case: NonInterferenceCaseV1,
        preparation: NonInterferencePreparationV1,
    ) -> Result<NonInterferenceSignedExecutionV1, NonInterferenceNonExecutedCauseV1> {
        let profile = non_interference_capture_profiles_v1()
            .into_iter()
            .find(|profile| profile.fixture_id == case.fixture_id);
        profile
            .zip(non_interference_normalization_digest_v1(&case.fixture_id))
            .and_then(|(profile, normalization_digest)| {
                NonInterferenceExecutionArtifactV1::sign(
                    NonInterferenceExecutionArtifactBodyV1 {
                        fixture_id: case.fixture_id.clone(),
                        variant: case.variant,
                        mode: case.mode,
                        fixture_digest: case.fixture_digest,
                        profile_digest: profile.profile_digest,
                        normalization_digest,
                        result_digest: result_digest(&case),
                        execution_provenance_digest: case.provenance_digest,
                        equal: case.authoritative_equal
                            && case.public_equal
                            && case.operational_equal,
                        divergence: case.first_divergence.clone(),
                    },
                    &self.executor_key.signing,
                )
                .ok()
            })
            .and_then(|artifact| {
                artifact
                    .to_canonical_cbor()
                    .ok()
                    .map(|bytes| (artifact, bytes))
            })
            .filter(|(artifact, bytes)| {
                bytes.len() <= MAX_NON_INTERFERENCE_EXECUTION_ARTIFACT_BYTES_V1
                    && self
                        .trusted_executor_keys
                        .contains(&artifact.executor_public_key)
            })
            .map(|(artifact, bytes)| NonInterferenceSignedExecutionV1 {
                content_digest: content_address(&bytes),
                case,
                preparation,
                artifact,
                bytes,
            })
            .ok_or(NonInterferenceNonExecutedCauseV1::SignatureFailure)
    }
}

/// Prepare the runner, prime a warm environment, then run and compare the
/// pair through the #181 framework.
fn run_case(
    runner: &mut dyn NonInterferenceModeRunnerV1,
    fixture: &NonInterferenceFixturePairV1,
    preparation: NonInterferencePreparationV1,
) -> Result<NonInterferenceCaseV1, NonInterferenceNonExecutedCauseV1> {
    fixture
        .validate()
        .map_err(NonInterferenceNonExecutedCauseV1::from)
        .and_then(|()| runner.prepare(preparation))
        .and_then(|()| prime(runner, fixture, preparation))?;
    let mut cause = None;
    let compared = execute_non_interference_pair(fixture, |run| {
        runner
            .execute(run, preparation)
            .map_err(|runner_cause| {
                cause = Some(runner_cause);
                NonInterferenceExecutionErrorV1::CaptureUnavailable
            })
            .and_then(|raw| normalize_non_interference_capture_v1(run.subject.fixture_id, raw))
    });
    compared.map_err(|error| cause.unwrap_or_else(|| error.into()))
}

/// For a warm case, one discarded run of the permitted input with an empty
/// unauthorized value.
fn prime(
    runner: &mut dyn NonInterferenceModeRunnerV1,
    fixture: &NonInterferenceFixturePairV1,
    preparation: NonInterferencePreparationV1,
) -> Result<(), NonInterferenceNonExecutedCauseV1> {
    match preparation {
        NonInterferencePreparationV1::Cold => Ok(()),
        NonInterferencePreparationV1::Warm => runner
            .execute(
                &NonInterferenceHostRunV1 {
                    member: NonInterferenceMatrixMemberV1::Control,
                    subject: NonInterferenceInvocationV1 {
                        fixture_id: &fixture.fixture_id,
                        variant: fixture.variant,
                        mode: fixture.mode,
                        permitted_input: &fixture.permitted_input,
                    },
                    unauthorized_value: &[],
                },
                preparation,
            )
            .map(drop),
    }
}

/// The mode-independent result an NIA1 binds: the control run's
/// authoritative and public capture digests.
fn result_digest(case: &NonInterferenceCaseV1) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(RESULT_DOMAIN_V1);
    hasher.update(&[0]);
    hasher.update(&case.authoritative_digest);
    hasher.update(&case.public_digest);
    *hasher.finalize().as_bytes()
}

/// A failure to publish one NIA1.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NonInterferencePublicationErrorV1 {
    /// The publication directory or file could not be written or read.
    #[error("non-interference publication failed: {0:?}")]
    Io(ErrorKind),
    /// Different bytes already exist at the artifact's content address.
    #[error("non-interference publication conflicts with existing bytes")]
    Conflict,
}

/// The path an NIA1 with `content_digest` is published at below the
/// `fixtures/conformance` root.
#[must_use]
pub fn non_interference_publication_path_v1(
    fixtures_root: &Path,
    content_digest: &[u8; 32],
) -> PathBuf {
    fixtures_root
        .join(NON_INTERFERENCE_PUBLICATION_DIRECTORY_V1)
        .join(format!(
            "{}.{NON_INTERFERENCE_PUBLICATION_EXTENSION_V1}",
            hex(content_digest)
        ))
}

/// Publish one executed case's canonical NIA1 at its content address below
/// the `fixtures/conformance` root and return the path.
///
/// Publication is atomic and immutable: the bytes are written and synced to
/// a staged file in the publication directory, which is then hard-linked to
/// the content address, so the address never holds a partial artifact, and
/// an existing file is never rewritten. The staged file is removed. When the
/// artifact cannot be linked, the bytes already at its address decide: the
/// same bytes are the same publication and return the same path, any other
/// bytes (a stray truncated file included) are a
/// [`NonInterferencePublicationErrorV1::Conflict`].
/// Only an executed case can be published; publication changes no
/// inventory.
///
/// # Errors
/// Returns the write's I/O error kind when the artifact can be neither
/// written nor read at its address, or `Conflict`.
pub fn publish_non_interference_execution_v1(
    fixtures_root: &Path,
    execution: &NonInterferenceSignedExecutionV1,
) -> Result<PathBuf, NonInterferencePublicationErrorV1> {
    let directory = fixtures_root.join(NON_INTERFERENCE_PUBLICATION_DIRECTORY_V1);
    let path = non_interference_publication_path_v1(fixtures_root, &execution.content_digest);
    let staged = directory.join(format!(
        ".{}.{}.{}.staged",
        hex(&execution.content_digest),
        std::process::id(),
        STAGED_PUBLICATIONS.fetch_add(1, Ordering::Relaxed)
    ));
    let written = fs::create_dir_all(&directory).and_then(|()| {
        let linked = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staged)
            .and_then(|mut file| {
                file.write_all(&execution.bytes)
                    .and_then(|()| file.sync_all())
            })
            .and_then(|()| fs::hard_link(&staged, &path));
        let removed = fs::remove_file(&staged);
        linked.and(removed)
    });
    written
        .or_else(|error| {
            fs::read(&path)
                .map_err(|_| NonInterferencePublicationErrorV1::Io(error.kind()))
                .and_then(|existing| {
                    if existing == execution.bytes {
                        Ok(())
                    } else {
                        Err(NonInterferencePublicationErrorV1::Conflict)
                    }
                })
        })
        .map(|()| path)
}

/// Build and host-sign an NIR1 from exactly 192 NIA1 artifacts, one per
/// ADR-059 coordinate, each signed by a trusted executor key.
///
/// The report is validated against the same artifacts before it is returned.
///
/// # Errors
/// Returns [`NonInterferenceReportErrorV1::InvalidShape`] for any count other
/// than 192 (so no report exists over fewer artifacts), a repeated
/// coordinate, or artifacts that do not form one report;
/// [`NonInterferenceReportErrorV1::SignatureInvalid`] for an untrusted
/// executor; and the NIA1 decode error of a malformed artifact.
pub fn build_non_interference_report_v1(
    artifacts: &[Vec<u8>],
    trusted_executor_keys: &[[u8; 32]],
    signer: &HostExecutorKeyV1,
) -> Result<NonInterferenceReportV1, NonInterferenceReportErrorV1> {
    if artifacts.len() != NON_INTERFERENCE_CASE_COUNT_V1 {
        return Err(NonInterferenceReportErrorV1::InvalidShape);
    }
    let mut resolved = BTreeMap::new();
    for bytes in artifacts {
        let (coordinate, entry) = NonInterferenceExecutionArtifactV1::from_canonical_cbor(bytes)
            .and_then(|artifact| {
                Some(artifact)
                    .filter(|artifact| {
                        trusted_executor_keys.contains(&artifact.executor_public_key)
                    })
                    .ok_or(NonInterferenceReportErrorV1::SignatureInvalid)
            })
            .map(|artifact| {
                (
                    (
                        row_of(&artifact.fixture_id),
                        artifact.variant,
                        artifact.mode,
                    ),
                    (content_address(bytes), artifact),
                )
            })?;
        if resolved.insert(coordinate, entry).is_some() {
            return Err(NonInterferenceReportErrorV1::InvalidShape);
        }
    }
    let executions = resolved.into_values().collect::<Vec<_>>();
    let outcomes = executions.chunks(4).map(report_outcome).collect();
    NonInterferenceReportV1::sign(outcomes, &signer.signing, &[]).and_then(|report| {
        report
            .validate(&signer.public_key(), trusted_executor_keys, artifacts)
            .map(|()| report)
    })
}

/// One row/variant outcome from its four mode artifacts, in mode order.
fn report_outcome(
    modes: &[([u8; 32], NonInterferenceExecutionArtifactV1)],
) -> NonInterferenceReportOutcomeV1 {
    let (_, first) = &modes[0];
    NonInterferenceReportOutcomeV1 {
        fixture_id: first.fixture_id.clone(),
        variant: first.variant,
        fixture_digest: first.fixture_digest,
        profile_digest: first.profile_digest,
        normalization_digest: first.normalization_digest,
        modes: modes
            .iter()
            .map(|(digest, artifact)| NonInterferenceModeResultRefV1 {
                mode: artifact.mode,
                result_digest: artifact.result_digest,
                artifact_digest: *digest,
                execution_provenance_digest: artifact.execution_provenance_digest,
                equal: artifact.equal,
            })
            .collect(),
        first_divergence: modes
            .iter()
            .find(|(_, artifact)| !artifact.equal)
            .and_then(|(_, artifact)| artifact.divergence.clone()),
    }
}

/// The matrix row of a fixture id an NIA1 decode has already admitted.
fn row_of(fixture_id: &str) -> usize {
    NON_INTERFERENCE_FIXTURE_IDS_V1
        .iter()
        .position(|row| *row == fixture_id)
        .unwrap_or(NON_INTERFERENCE_FIXTURE_IDS_V1.len())
}

/// The NIA1 content address: the digest an NIR1 mode reference names and the
/// independent verifier resolves.
fn content_address(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ARTIFACT_DOMAIN_V1);
    hasher.update(&[0]);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        text.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        text.push(char::from(b"0123456789abcdef"[usize::from(byte & 0x0f)]));
        text
    })
}
