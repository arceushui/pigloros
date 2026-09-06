//! Hosted measurements for the in-memory ADR-060 persistence path.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fs::File;
use std::hint::black_box;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Instant;

use pos_core::erasure::{target_closure_digest, ErasureAuthorizationDecisionV1};
use pos_core::{
    ErasureAcknowledgementOutcomeV1, ErasureAcknowledgementProvenanceV1, ErasureAcknowledgementV1,
    ErasureAtomicFreezeAdmissionInputV1, ErasureAtomicFreezeAdmissionV1,
    ErasureAtomicFreezeResultV1, ErasureAttemptQuotaReservationV1, ErasureCoordinatorPortV1,
    ErasureCoordinatorStateMachineV1, ErasureDestructionCommandV1, ErasureErrorV1,
    ErasureFreezeAdmissionEvidenceV1, ErasureFreezeAuthorizationEvidenceV1,
    ErasureFreezeAuthorizationVerifierV1, ErasureLifecycleV1, ErasureObligationSetInputV1,
    ErasureObligationSetV1, ErasureObligationV1, ErasurePersistencePortV1, ErasureReceiptInputV1,
    ErasureRecoveryAuthorizationVerifierV1, ErasureReferenceV1, ErasureRequestInputV1,
    ErasureRequestV1, ErasureRequiredTargetV1, ErasureRetryAdmissionV1,
    ErasureScopeCommitmentInputV1, ErasureScopeCommitmentV1, ErasureScopeExtensionV1,
    ErasureScopeV1, ErasureStateResolverV1, ErasureStateTransitionV1,
};
use pos_store::memory::MemoryStore;

#[path = "../../pos-core/tests/support/erasure.rs"]
pub mod erasure_support;

use erasure_support::{freeze_evidence_fixture, obligation, FreezeEvidenceFixtureInput};

const CAS_CARDINALITIES: [usize; 4] = [0, 32, 128, 512];
const ACKNOWLEDGEMENT_CARDINALITIES: [usize; 4] = [0, 8, 32, 63];
const RECOVERY_ERROR_CARDINALITIES: [usize; 3] = [0, 8, 24];
const DEFAULT_SAMPLES: usize = 10;

type SharedStore = Rc<RefCell<MemoryStore>>;
type ReadLog = Rc<RefCell<BTreeSet<ErasureReferenceV1>>>;

struct BenchmarkErasureHost {
    store: SharedStore,
    targets: Vec<ErasureRequiredTargetV1>,
    failed_object: Option<ErasureReferenceV1>,
    reads: ReadLog,
}

impl ErasureStateResolverV1 for BenchmarkErasureHost {
    fn resolve_state(
        &self,
        digest: ErasureReferenceV1,
    ) -> Result<Option<pos_core::ErasureStateV1>, ErasureErrorV1> {
        self.store.borrow().resolve_state(digest)
    }
}

impl ErasurePersistencePortV1 for BenchmarkErasureHost {
    fn read_manifest(
        &self,
        request: ErasureReferenceV1,
    ) -> Result<Option<pos_core::StoredErasureManifestV1>, ErasureErrorV1> {
        self.store.borrow().read_manifest(request)
    }

    fn read_object(&self, reference: ErasureReferenceV1) -> Result<Vec<u8>, ErasureErrorV1> {
        self.reads.borrow_mut().insert(reference);
        if self.failed_object == Some(reference) {
            Err(ErasureErrorV1::ProvenanceMissing)
        } else {
            self.store.borrow().read_object(reference)
        }
    }

    crate::impl_erasure_persistence_forwarding!();

    fn compare_and_swap(
        &mut self,
        mutation: pos_core::PreparedErasureCasV1,
    ) -> Result<pos_core::ErasureCasOutcomeV1, ErasureErrorV1> {
        self.store.borrow_mut().compare_and_swap(mutation)
    }
}

impl ErasureFreezeAuthorizationVerifierV1 for BenchmarkErasureHost {
    fn validate_freeze_authorization(
        &self,
        admission: &ErasureFreezeAdmissionEvidenceV1,
        authorization: &ErasureFreezeAuthorizationEvidenceV1,
    ) -> Result<(), ErasureErrorV1> {
        authorization.verify_admission_body_binding(admission)
    }
}

impl ErasureRecoveryAuthorizationVerifierV1 for BenchmarkErasureHost {
    fn validate_scope_extension(
        &self,
        _extension: &ErasureScopeExtensionV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn validate_administrative_resolution(
        &self,
        _resolution: &pos_core::ErasureAdministrativeResolutionV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }
}

impl ErasureCoordinatorPortV1 for BenchmarkErasureHost {
    fn authenticate(&self, _request: &ErasureRequestV1) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_authorization(
        &self,
        _request: ErasureReferenceV1,
        _provenance: ErasureReferenceV1,
        _decision: ErasureAuthorizationDecisionV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_corrected_submission(
        &self,
        _request: &ErasureRequestV1,
        _correction: &pos_core::ErasureCorrectionProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_atomic_freeze(
        &self,
        request: ErasureReferenceV1,
        requested: &ErasureStateTransitionV1,
    ) -> Result<ErasureAtomicFreezeResultV1, ErasureErrorV1> {
        let mut targets = self.targets.clone();
        targets.sort_unstable();
        let mut obligations = targets
            .iter()
            .copied()
            .map(|target| obligation(request, target))
            .collect::<Result<Vec<_>, _>>()?;
        obligations.sort_unstable_by_key(ErasureObligationV1::reference);
        let obligation_set = ErasureObligationSetV1::new(ErasureObligationSetInputV1 {
            request,
            obligations: obligations
                .iter()
                .map(ErasureObligationV1::reference)
                .collect(),
            policy: benchmark_reference(6, 0),
            trust: benchmark_reference(8, 0),
        })?;
        let scope = ErasureScopeCommitmentInputV1 {
            request,
            scope_members: vec![benchmark_reference(9, 0)],
            target_closure: target_closure_digest(&targets),
            lineage_rule: None,
        };
        let scope_reference = ErasureScopeCommitmentV1::new(scope.clone())?.reference();
        let freeze_position = requested.freeze_position.unwrap_or(10);
        let evidence = requested.provenance.digest();
        let (freeze_admission_evidence, freeze_authorization_evidence) =
            freeze_evidence_fixture(FreezeEvidenceFixtureInput {
                request,
                scope_commitment: scope_reference,
                obligation_set: &obligation_set,
                targets: &targets,
                obligations: &obligations,
                freeze_position,
                evidence: &evidence,
            })?;
        ErasureAtomicFreezeAdmissionV1::new(ErasureAtomicFreezeAdmissionInputV1 {
            targets,
            scope,
            obligations,
            obligation_set,
            freeze_position,
            freeze_admission_evidence,
            freeze_authorization_evidence,
        })
        .map(Box::new)
        .map(ErasureAtomicFreezeResultV1::Admitted)
    }

    fn admit_scope_extension(
        &self,
        _extension: &ErasureScopeExtensionV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_administrative_resolution(
        &self,
        _resolution: &pos_core::ErasureAdministrativeResolutionV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn dispatch_destruction(
        &self,
        _request: ErasureReferenceV1,
        _commands: &[ErasureDestructionCommandV1],
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_attempt(
        &self,
        admission: &ErasureRetryAdmissionV1,
    ) -> Result<ErasureAttemptQuotaReservationV1, ErasureErrorV1> {
        Ok(ErasureAttemptQuotaReservationV1::new(
            admission.reference(),
            admission.reference(),
        ))
    }

    fn admit_acknowledgement(
        &self,
        _acknowledgement: &ErasureAcknowledgementProvenanceV1,
    ) -> Result<(), ErasureErrorV1> {
        Ok(())
    }

    fn admit_receipt(&self, _input: &ErasureReceiptInputV1) -> Result<(), ErasureErrorV1> {
        Ok(())
    }
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
enum BenchmarkScenario {
    ManifestCas,
    AcknowledgementAdmission,
    RecoveryErrorAppend,
    RecoveryErrorRead,
}

impl BenchmarkScenario {
    const fn label(self) -> &'static str {
        match self {
            Self::ManifestCas => "manifest-cas",
            Self::AcknowledgementAdmission => "acknowledgement-admission",
            Self::RecoveryErrorAppend => "recovery-error-append",
            Self::RecoveryErrorRead => "recovery-error-read",
        }
    }
}

#[derive(Clone)]
struct Measurement {
    scenario: BenchmarkScenario,
    cardinality: usize,
    sample: usize,
    elapsed_nanos: u128,
}

struct AcknowledgementWorkload {
    store: SharedStore,
    state_machine: ErasureCoordinatorStateMachineV1<BenchmarkErasureHost>,
    request_reference: ErasureReferenceV1,
    entries: Vec<(ErasureRequiredTargetV1, ErasureReferenceV1)>,
}

fn benchmark_reference(namespace: u8, value: usize) -> ErasureReferenceV1 {
    let mut digest = [namespace; 32];
    let value = u64::try_from(value).unwrap_or(u64::MAX);
    digest[..8].copy_from_slice(&value.to_be_bytes());
    ErasureReferenceV1::from_digest(digest)
}

fn benchmark_request(value: usize) -> Result<ErasureRequestV1, ErasureErrorV1> {
    ErasureRequestV1::new(ErasureRequestInputV1 {
        request: benchmark_reference(1, value),
        subject: benchmark_reference(2, value),
        scope: ErasureScopeV1::PrivateSubjectData,
        selectors: vec![benchmark_reference(3, value)],
        requester: benchmark_reference(4, value),
        authorization: benchmark_reference(5, value),
        policy: benchmark_reference(6, 0),
        request_position: 9,
        horizon_position: 20,
        provenance: benchmark_reference(7, value),
    })
}

fn benchmark_target(value: usize) -> ErasureRequiredTargetV1 {
    ErasureRequiredTargetV1 {
        artifact_digest: benchmark_reference(20, value),
        key_digest: benchmark_reference(21, value),
        replica_set: benchmark_reference(22, value),
        replica_id: benchmark_reference(23, value),
        ..erasure_support::persistence_target()
    }
}

fn benchmark_coordinator(
    store: SharedStore,
    targets: Vec<ErasureRequiredTargetV1>,
    failed_object: Option<ErasureReferenceV1>,
    reads: ReadLog,
) -> ErasureCoordinatorStateMachineV1<BenchmarkErasureHost> {
    ErasureCoordinatorStateMachineV1::new(
        BenchmarkErasureHost {
            store,
            targets,
            failed_object,
            reads,
        },
        benchmark_reference(30, 0),
    )
}

fn access_frozen_transition() -> ErasureStateTransitionV1 {
    ErasureStateTransitionV1 {
        lifecycle: ErasureLifecycleV1::AccessFrozen,
        freeze_position: Some(10),
        pending_owners: Vec::new(),
        failed_owners: Vec::new(),
        acknowledged_targets: Vec::new(),
        replay_claim: pos_core::ErasureReplayClaimV1::Exact,
        provenance: benchmark_reference(31, 0),
    }
}

fn retry_admission(
    request: ErasureReferenceV1,
    targets: &[ErasureRequiredTargetV1],
) -> Result<(ErasureRetryAdmissionV1, Vec<ErasureObligationV1>), ErasureErrorV1> {
    let mut obligations = targets
        .iter()
        .copied()
        .map(|target| obligation(request, target))
        .collect::<Result<Vec<_>, _>>()?;
    obligations.sort_unstable_by_key(ErasureObligationV1::reference);
    let admission = erasure_support::retry_admission(erasure_support::RetryAdmissionFixture {
        request,
        attempt_ordinal: 0,
        source_receipt: None,
        obligations: &obligations,
        policy: benchmark_reference(6, 0),
        trust: benchmark_reference(8, 0),
        admitted_position: 11,
        deadline_position: 20,
        authorization_provenance: benchmark_reference(32, 0),
    })?;
    Ok((admission, obligations))
}

fn acknowledgement(
    target: ErasureRequiredTargetV1,
    obligation: ErasureReferenceV1,
    value: usize,
) -> ErasureAcknowledgementV1 {
    ErasureAcknowledgementV1 {
        obligation,
        target,
        owner: target.replica_id,
        evidence: benchmark_reference(40, value),
        outcome: ErasureAcknowledgementOutcomeV1::Acknowledged,
    }
}

fn acknowledgement_workload(
    acknowledged: usize,
) -> Result<AcknowledgementWorkload, ErasureErrorV1> {
    let targets = (0..=acknowledged).map(benchmark_target).collect::<Vec<_>>();
    let store = Rc::new(RefCell::new(MemoryStore::new()));
    let mut coordinator = benchmark_coordinator(
        Rc::clone(&store),
        targets.clone(),
        None,
        Rc::new(RefCell::new(BTreeSet::new())),
    );
    let request = benchmark_request(0)?;
    let request_reference = request.reference();
    coordinator.submit(request, benchmark_reference(7, 0))?;
    coordinator.authorize(request_reference, benchmark_reference(33, 0))?;
    coordinator.freeze_inventory(request_reference, &access_frozen_transition())?;
    let (admission, obligations) = retry_admission(request_reference, &targets)?;
    coordinator.dispatch_attempt(request_reference, &admission)?;
    let entries = obligations
        .iter()
        .map(|obligation| (obligation.target(), obligation.reference()))
        .collect::<Vec<_>>();
    for (index, (target, obligation)) in entries.iter().take(acknowledged).enumerate() {
        coordinator.acknowledge(
            request_reference,
            acknowledgement(*target, *obligation, index),
        )?;
    }
    Ok(AcknowledgementWorkload {
        store,
        state_machine: coordinator,
        request_reference,
        entries,
    })
}

fn measure_cas(samples: usize, measurements: &mut Vec<Measurement>) -> Result<(), ErasureErrorV1> {
    for cardinality in CAS_CARDINALITIES {
        for sample in 0..samples {
            let store = Rc::new(RefCell::new(MemoryStore::new()));
            let mut coordinator = benchmark_coordinator(
                store,
                Vec::new(),
                None,
                Rc::new(RefCell::new(BTreeSet::new())),
            );
            for value in 0..cardinality {
                coordinator.submit(benchmark_request(value)?, benchmark_reference(7, value))?;
            }
            let started = Instant::now();
            let state = coordinator.submit(
                benchmark_request(cardinality)?,
                benchmark_reference(7, cardinality),
            )?;
            let elapsed_nanos = started.elapsed().as_nanos();
            black_box(state);
            measurements.push(Measurement {
                scenario: BenchmarkScenario::ManifestCas,
                cardinality,
                sample,
                elapsed_nanos,
            });
        }
    }
    Ok(())
}

fn measure_acknowledgements(
    samples: usize,
    measurements: &mut Vec<Measurement>,
) -> Result<(), ErasureErrorV1> {
    for cardinality in ACKNOWLEDGEMENT_CARDINALITIES {
        for sample in 0..samples {
            let mut workload = acknowledgement_workload(cardinality)?;
            let (target, obligation) = workload.entries[cardinality];
            let started = Instant::now();
            let state = workload.state_machine.acknowledge(
                workload.request_reference,
                acknowledgement(target, obligation, cardinality),
            )?;
            let elapsed_nanos = started.elapsed().as_nanos();
            black_box(state);
            measurements.push(Measurement {
                scenario: BenchmarkScenario::AcknowledgementAdmission,
                cardinality,
                sample,
                elapsed_nanos,
            });
        }
    }
    Ok(())
}

fn recovery_read_set(
    store: &SharedStore,
    targets: &[ErasureRequiredTargetV1],
    request: ErasureReferenceV1,
) -> Result<Vec<ErasureReferenceV1>, ErasureErrorV1> {
    let reads = Rc::new(RefCell::new(BTreeSet::new()));
    benchmark_coordinator(Rc::clone(store), targets.to_vec(), None, Rc::clone(&reads))
        .verified_state(request)?;
    let result = reads.borrow().iter().copied().collect();
    Ok(result)
}

fn retain_recovery_error(
    store: &SharedStore,
    targets: &[ErasureRequiredTargetV1],
    request: ErasureReferenceV1,
    failed_object: ErasureReferenceV1,
) -> Result<(), ErasureErrorV1> {
    let result = benchmark_coordinator(
        Rc::clone(store),
        targets.to_vec(),
        Some(failed_object),
        Rc::new(RefCell::new(BTreeSet::new())),
    )
    .verified_state(request);
    match result {
        Err(ErasureErrorV1::ProvenanceMissing) => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(ErasureErrorV1::PolicyConflict),
    }
}

fn measure_recovery_errors(
    samples: usize,
    measurements: &mut Vec<Measurement>,
) -> Result<(), ErasureErrorV1> {
    for cardinality in RECOVERY_ERROR_CARDINALITIES {
        for sample in 0..samples {
            let workload = acknowledgement_workload(32)?;
            let targets = (0..=32).map(benchmark_target).collect::<Vec<_>>();
            let read_set =
                recovery_read_set(&workload.store, &targets, workload.request_reference)?;
            if read_set.len() <= cardinality {
                return Err(ErasureErrorV1::ScopeInvalid);
            }
            let measured_failure = *read_set.last().ok_or(ErasureErrorV1::ScopeInvalid)?;
            for failed_object in read_set.iter().take(cardinality) {
                retain_recovery_error(
                    &workload.store,
                    &targets,
                    workload.request_reference,
                    *failed_object,
                )?;
            }
            let started = Instant::now();
            retain_recovery_error(
                &workload.store,
                &targets,
                workload.request_reference,
                measured_failure,
            )?;
            let append_nanos = started.elapsed().as_nanos();
            measurements.push(Measurement {
                scenario: BenchmarkScenario::RecoveryErrorAppend,
                cardinality,
                sample,
                elapsed_nanos: append_nanos,
            });

            let observer = benchmark_coordinator(
                workload.store,
                targets,
                None,
                Rc::new(RefCell::new(BTreeSet::new())),
            );
            let started = Instant::now();
            let errors = observer.recovery_errors(workload.request_reference)?;
            let read_nanos = started.elapsed().as_nanos();
            black_box(errors);
            measurements.push(Measurement {
                scenario: BenchmarkScenario::RecoveryErrorRead,
                cardinality: cardinality + 1,
                sample,
                elapsed_nanos: read_nanos,
            });
        }
    }
    Ok(())
}

fn samples() -> Result<usize, Box<dyn std::error::Error>> {
    std::env::var("PIGLOROS_BENCH_SAMPLES").map_or(Ok(DEFAULT_SAMPLES), |value| {
        let parsed = value.parse::<usize>()?;
        if parsed == 0 {
            Err("PIGLOROS_BENCH_SAMPLES must be positive".into())
        } else {
            Ok(parsed)
        }
    })
}

fn output_path() -> PathBuf {
    std::env::var_os("PIGLOROS_BENCH_OUTPUT").map_or_else(
        || PathBuf::from("memory-erasure-benchmark.csv"),
        PathBuf::from,
    )
}

fn write_measurements(
    path: &Path,
    measurements: &[Measurement],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut output = BufWriter::new(File::create(path)?);
    writeln!(output, "scenario,cardinality,sample,elapsed_nanos")?;
    for measurement in measurements {
        writeln!(
            output,
            "{},{},{},{}",
            measurement.scenario.label(),
            measurement.cardinality,
            measurement.sample,
            measurement.elapsed_nanos
        )?;
    }
    output.flush()?;
    Ok(())
}

fn print_summaries(output: &mut impl Write, measurements: &[Measurement]) -> Result<(), io::Error> {
    let keys = measurements
        .iter()
        .map(|measurement| (measurement.scenario, measurement.cardinality))
        .collect::<BTreeSet<_>>();
    for (scenario, cardinality) in keys {
        let mut values = measurements
            .iter()
            .filter(|measurement| {
                measurement.scenario == scenario && measurement.cardinality == cardinality
            })
            .map(|measurement| measurement.elapsed_nanos)
            .collect::<Vec<_>>();
        values.sort_unstable();
        let median = values[values.len() / 2];
        let p95_index = (values.len() * 95).div_ceil(100).saturating_sub(1);
        writeln!(
            output,
            "scenario={} cardinality={cardinality} samples={} median_ns={median} p95_ns={}",
            scenario.label(),
            values.len(),
            values[p95_index]
        )?;
    }
    Ok(())
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let samples = samples()?;
    let mut measurements = Vec::new();
    measure_cas(samples, &mut measurements)?;
    measure_acknowledgements(samples, &mut measurements)?;
    measure_recovery_errors(samples, &mut measurements)?;
    let stdout = io::stdout();
    let mut output = stdout.lock();
    print_summaries(&mut output, &measurements)?;
    let path = output_path();
    write_measurements(&path, &measurements)?;
    writeln!(output, "measurements={}", path.display())?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        let stderr = io::stderr();
        if writeln!(stderr.lock(), "memory erasure benchmark failed: {error}").is_err() {
            std::process::exit(2);
        }
        std::process::exit(1);
    }
}
