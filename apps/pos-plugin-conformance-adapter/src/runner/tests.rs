//! R8-A6 and R8-A10: the real port and the S1c2 world with the fixture source, on releases of
//! the signed-release test world (no real worker: `/bin/false` stands in).

use pos_core::trusted_clock::{FixtureEvaluationInstantV1, FixtureWallSourceV1};
use pos_plugin_publisher::test_support::{encoding::TICK, release::Shape, world::World};
use pos_plugin_release::{BundleAddressV1, InMemoryReleaseEntryV1, ReleaseSourceV1};
use pos_plugin_supervisor::CommunityPluginSubjectResultV1;
use pos_reference::evaluator::SubjectResult;
use pos_reference::evaluator_domain::{ExecutionMode, FixtureFamily};
use pos_runtime::community_plugin_host::CommunityTrustAnchorBytesV1;
use serde_json::{json, Value};

use super::*;
use crate::map::{case_result, of_record, SubResultV1};
use crate::payload::ScanSource;
use crate::test_support::{
    attempt, composite, hex_of, observation, parsed, payload, stream, subcase, TestResult,
};
use crate::run_with;

type BoxError = Box<dyn std::error::Error>;

const EMPTY_CONFIG: &str =
    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";
const PLUGIN: &str = "plugin-a";
const INVOCATION_HEX: &str = "07070707070707070707070707070707";

const TRUST_UNAVAILABLE: HostError = HostError::ArtifactTrustDenied {
    basis: TrustDenialBasisV1::TrustStateUnavailable,
};

fn anchor_cbor(anchor: &CommunityTrustAnchorBytesV1) -> Result<Vec<u8>, BoxError> {
    use ciborium::value::Value as Cbor;
    let value = Cbor::Array(vec![
        Cbor::Text("PCA1".to_owned()),
        Cbor::Integer(1_u8.into()),
        Cbor::Text(anchor.scope.clone()),
        Cbor::Bytes(anchor.ptr1_genesis_digest.to_vec()),
        Cbor::Bytes(anchor.operator_key.to_vec()),
        Cbor::Bytes(anchor.genesis_tps1_digest.to_vec()),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&value, &mut out)?;
    Ok(out)
}

/// One release of the signed-release test world, as pieces.
struct Real {
    address: BundleAddressV1,
    source: InMemoryReleaseSourceV1,
    pieces: PiecesV1,
    all: Vec<Vec<u8>>,
    release: Value,
    material_json: Value,
    material: CommunityPluginTrustMaterialV1,
    pmf1_digest: [u8; 32],
}

impl Real {
    fn new() -> Result<Self, BoxError> {
        let mut publisher = World::build(None, false)?;
        let current = publisher.material()?;
        let shape = Shape::first().with_optional_capability().with_worker_abi();
        let address = publisher.publish(shape)?.address().clone();
        let bundle = publisher.store.read_verified(&address)?;
        let manifest = bundle.manifest().to_vec();
        let layers: Vec<Vec<u8>> = bundle
            .blobs()
            .iter()
            .filter(|blob| blob.digest() != EMPTY_CONFIG)
            .map(|blob| blob.bytes().to_vec())
            .collect();
        let anchor = CommunityTrustAnchorBytesV1 {
            scope: publisher.anchor.scope().to_owned(),
            ptr1_genesis_digest: publisher.anchor.ptr1_genesis_digest(),
            operator_key: publisher.anchor.operator_key(),
            genesis_tps1_digest: publisher.anchor.genesis_tps1_digest(),
        };
        let roots = vec![current.ptr1().to_vec()];
        let revocations = current.prv1_records().to_vec();
        let tps1 = current.tps1.clone();
        let material = CommunityPluginTrustMaterialV1::from_bytes_v1(
            &anchor,
            tps1.clone(),
            roots.clone(),
            revocations.clone(),
        )?;
        let anchor_bytes = anchor_cbor(&anchor)?;
        let mut all = vec![manifest.clone(), tps1.clone(), anchor_bytes.clone()];
        all.extend(layers.clone());
        all.extend(roots.clone());
        all.extend(revocations.clone());
        all.sort();
        all.dedup();
        let release = json!({
            "manifest": hex_of(&manifest),
            "blobs": layers.iter().map(|blob| hex_of(blob)).collect::<Vec<_>>(),
        });
        let material_json = json!({
            "anchor": hex_of(&anchor_bytes),
            "tps1": hex_of(&tps1),
            "ptr1": roots.iter().map(|record| hex_of(record)).collect::<Vec<_>>(),
            "prv1": revocations.iter().map(|record| hex_of(record)).collect::<Vec<_>>(),
        });
        let entry = InMemoryReleaseEntryV1::from_bytes(manifest, layers)?;
        Ok(Self {
            address,
            source: InMemoryReleaseSourceV1::new(vec![entry])?,
            pieces: PiecesV1::from_blobs(all.clone()),
            all,
            release,
            material_json,
            material,
            pmf1_digest: *blake3::hash(bundle.pmf1()).as_bytes(),
        })
    }

    fn install(&self, instant: u64) -> Value {
        json!({
            "step": "install", "release": self.release, "material": self.material_json,
            "instant_micros": instant, "tick": TICK,
        })
    }

    fn bind(&self, material: &Value) -> Value {
        json!({
            "step": "bind", "release": self.release, "material": material,
            "plugin_id": PLUGIN, "instant_micros": 50_000_000, "tick": TICK,
            "initial_state": {"schema": hex_of(b"schema"), "bytes": "696e6974"},
            "event_type": "prototype.driven",
        })
    }

    fn refresh(&self, material: &Value) -> Value {
        json!({
            "step": "refresh", "material": material, "instant_micros": 50_000_000, "tick": TICK,
        })
    }

    fn pass(&self, member: &Value) -> Value {
        json!({
            "step": "pass", "members": [member], "instant_micros": 50_000_000, "tick": TICK,
            "invocation_id": INVOCATION_HEX, "random_domain": hex_of(b"domain"),
            "timeline_seq": 0, "observation": "00", "simulation_time": 1,
        })
    }

    fn scan(&self, sources: &[&str], marker: &str) -> Value {
        json!({
            "step": "scan", "marker": marker, "in": sources,
            "retained": {"plugin_id": PLUGIN, "invocation_id_hex": INVOCATION_HEX},
        })
    }

    fn crash_steps(&self) -> Vec<Value> {
        vec![
            self.install(50_000_000),
            self.bind(&self.material_json),
            self.pass(&json!({"plugin_id": PLUGIN})),
        ]
    }

    fn run(&self, steps: Vec<Value>, expect: Value) -> Result<SubCaseRecordV1, BoxError> {
        let document = subcase("x", steps, expect);
        let runner = runner_for("/bin/false")?;
        Ok(runner.run(&parsed(&document)?, &self.pieces, CommunityPluginModeV1::Local))
    }
}

fn runner_for(program: &str) -> Result<SupervisorRunnerV1, BoxError> {
    Ok(SupervisorRunnerV1::with_program(program).ok_or("relative program")?)
}

fn refused_expect(basis: &str) -> Value {
    json!({"kind": "refused", "error": "ArtifactTrustDenied",
        "class": "PreExecutionRejection", "basis": basis})
}

fn crashed() -> Value {
    json!({"kind": "failed", "error": "WorkerCrashed", "class": "Operational"})
}

fn zeros() -> String {
    "00".repeat(32)
}

#[test]
fn a_worker_that_exits_without_a_reply_is_a_crash_and_the_case_is_unavailable() -> TestResult {
    let real = Real::new()?;
    for program in ["/bin/false", "/nonexistent/pos-plugin-worker"] {
        for mode in [CommunityPluginModeV1::Local, CommunityPluginModeV1::AirGapped] {
            let document = subcase("res.x", real.crash_steps(), crashed());
            let runner = runner_for(program)?;
            let record = runner.run(&parsed(&document)?, &real.pieces, mode);
            assert_eq!(record.setup_refusal, None, "{program}");
            assert_eq!(record.steps_run, 3);
            assert_eq!(record.outcomes.len(), 1);
            let failed = CommunityPluginSubjectResultV1::Failed {
                error: "WorkerCrashed",
                class: "Operational",
            };
            assert_eq!(record.outcomes[0].result, failed, "{program}");
            assert_eq!(record.outcomes[0].mode, mode);
            assert_eq!(record.worker_launches, 1);
            assert!(!record.matched, "an operational result matches nothing");
            assert_eq!(of_record(&record), Some(SubResultV1::Operational));
            let decided = case_result("c", FixtureFamily::ResourceExhaustion, &[record]);
            assert_eq!(decided.result, SubjectResult::Unavailable);
        }
    }
    Ok(())
}

#[test]
fn the_whole_attempt_through_run_with_is_unavailable_when_the_worker_crashes() -> TestResult {
    let real = Real::new()?;
    let document = payload(
        "resource-exhaustion",
        vec![subcase("res.x", real.crash_steps(), crashed())],
    );
    let pieces: Vec<&[u8]> = real.all.iter().map(Vec::as_slice).collect();
    let case = attempt(
        FixtureFamily::ResourceExhaustion,
        ExecutionMode::AirGapped,
        document.to_string().into_bytes(),
        vec![composite(&pieces)?],
    );
    let runner = runner_for("/bin/false")?;
    let mut out = Vec::new();
    run_with(&runner, stream(&case)?.as_slice(), &mut out)?;
    assert_eq!(observation(&out)?.result, SubjectResult::Unavailable);
    Ok(())
}

#[test]
fn a_relative_worker_path_is_refused() {
    assert!(SupervisorRunnerV1::with_program("pos-plugin-worker").is_none());
    assert!(SupervisorRunnerV1::with_program("/bin/false").is_some());
}

#[test]
fn bind_gates_the_release_and_reports_its_identity() -> TestResult {
    let real = Real::new()?;
    let steps = vec![real.install(50_000_000), real.bind(&real.material_json)];
    let pmf1 = json!({"what": "release_identity", "field": "pmf1"});
    let value = hex_of_digest(&real.pmf1_digest);
    let expect = json!({"kind": "digest", "compute": pmf1, "value": value});
    let record = real.run(steps.clone(), expect)?;
    assert_eq!(record.setup_refusal, None);
    assert_eq!(record.computed, Some(real.pmf1_digest));
    assert!(record.matched);
    let release = json!({"what": "release_identity", "field": "release"});
    let expect = json!({"kind": "digest", "compute": release, "value": zeros()});
    let record = real.run(steps, expect)?;
    assert!(record.computed.is_some_and(|digest| digest != real.pmf1_digest));
    Ok(())
}

fn hex_of_digest(digest: &[u8; 32]) -> String {
    crate::hex::encode(digest)
}

fn absent(marker: &str) -> Value {
    json!({"kind": "absent", "marker": marker,
        "retained": {"plugin_id": PLUGIN, "invocation_id_hex": INVOCATION_HEX}})
}

#[test]
fn a_scan_reads_the_drivers_state_the_events_and_the_outcome_from_the_world() -> TestResult {
    let real = Real::new()?;
    let steps = vec![
        real.install(50_000_000),
        real.bind(&real.material_json),
        real.scan(&["state"], "init"),
    ];
    let record = real.run(steps, absent("init"))?;
    let scan = record.scan.ok_or("no scan")?;
    assert_eq!(scan.found, [ScanSource::State], "the initial state of the Driver");
    assert_eq!(scan.observed_plugin_id, PLUGIN);

    let steps = vec![real.install(50_000_000), real.scan(&["events", "outcome", "state"], "init")];
    let record = real.run(steps, absent("init"))?;
    let scan = record.scan.ok_or("no scan")?;
    assert_eq!(scan.found, Vec::<ScanSource>::new(), "no Event, no Driver, no outcome");
    Ok(())
}

#[test]
fn a_refresh_runs_on_the_registry_of_the_world() -> TestResult {
    let real = Real::new()?;
    let steps = vec![real.install(50_000_000), real.refresh(&real.material_json)];
    let record = real.run(steps, crashed())?;
    assert_eq!(record.steps_run, 2);
    assert!(!record.matched);
    Ok(())
}

#[test]
fn a_step_without_material_or_a_world_without_genesis_is_trust_state_unavailable() -> TestResult {
    let real = Real::new()?;
    let mut install = real.install(50_000_000);
    install["material"] = Value::Null;
    let record = real.run(
        vec![real.refresh(&real.material_json), install.clone()],
        refused_expect("TrustStateUnavailable"),
    )?;
    assert_eq!(record.setup_refusal, Some(TRUST_UNAVAILABLE));
    assert_eq!(record.steps_run, 2);
    assert!(record.matched);

    let record = real.run(
        vec![real.install(50_000_000), real.refresh(&Value::Null)],
        refused_expect("TrustStateUnavailable"),
    )?;
    assert_eq!(record.setup_refusal, Some(TRUST_UNAVAILABLE));
    assert!(record.matched);

    // No step names a material: the registry cannot be provisioned.
    let record = real.run(vec![install], refused_expect("TrustStateUnavailable"))?;
    assert_eq!(record.setup_refusal, Some(TRUST_UNAVAILABLE));
    assert_eq!(record.steps_run, 0, "the world did not open");
    assert!(record.matched);
    Ok(())
}

#[test]
fn unreadable_material_and_an_empty_address_are_trust_state_unavailable() -> TestResult {
    let real = Real::new()?;
    // mal.5b: the material source of the bind is unreadable.
    let steps = vec![real.install(50_000_000), real.bind(&Value::Null)];
    let record = real.run(steps, refused_expect("TrustStateUnavailable"))?;
    assert_eq!(record.steps_run, 2);
    assert!(record.matched);

    // mal.5a: the address read at the pass holds nothing, so nothing launches.
    let member = json!({"plugin_id": PLUGIN, "at": "absent"});
    let steps = vec![
        real.install(50_000_000),
        real.bind(&real.material_json),
        real.pass(&member),
    ];
    let record = real.run(steps, refused_expect("TrustStateUnavailable"))?;
    assert_eq!(record.worker_launches, 0);
    assert!(record.matched, "{record:?}");

    // A member whose Plugin no bind registered cannot be built.
    let stranger = json!({"plugin_id": "plugin-b", "at": "absent"});
    let steps = vec![
        real.install(50_000_000),
        real.bind(&real.material_json),
        real.pass(&stranger),
    ];
    let record = real.run(steps, refused_expect("TrustStateUnavailable"))?;
    assert_eq!(record.setup_refusal, Some(TRUST_UNAVAILABLE));
    Ok(())
}

fn fixture_wall(second: u64) -> Result<FixtureWallSourceV1, BoxError> {
    let instant = FixtureEvaluationInstantV1::from_micros(second * 1_000_000);
    Ok(FixtureWallSourceV1::new(instant.map_err(|e| format!("{e:?}"))?))
}

const fn expired() -> HostError {
    HostError::ArtifactTrustDenied {
        basis: TrustDenialBasisV1::Expired,
    }
}

struct Gates {
    real: Real,
    world: CommunityEvaluationWorldV1,
}

impl Gates {
    fn new() -> Result<Self, BoxError> {
        let real = Real::new()?;
        let world = CommunityEvaluationWorldV1::open(&real.material).map_err(|e| format!("{e:?}"))?;
        Ok(Self { real, world })
    }

    fn install(&mut self, second: u64) -> Result<(), BoxError> {
        let mut wall = fixture_wall(second)?;
        let installed = self.world.install(
            &self.real.source,
            &self.real.address,
            &self.real.material,
            &mut wall,
            TICK,
        );
        installed.map(|_| ()).map_err(|e| format!("{e:?}").into())
    }

    fn gate(&mut self, second: u64) -> Result<Result<(), HostError>, BoxError> {
        let mut wall = fixture_wall(second)?;
        let expectation = CommunityPluginExpectationV1 {
            plugin_id: PLUGIN.to_owned(),
            release: None,
        };
        let material = FixedTrustMaterialSourceV1::new(self.real.material.clone());
        let gated = self.world.gate_for_driver(
            &expectation,
            &self.real.source,
            &self.real.address,
            &material,
            &mut wall,
            TICK,
        );
        Ok(gated.map(|_| ()))
    }
}

#[test]
fn the_gate_at_the_fixture_instant_honours_the_validity_window() -> TestResult {
    let mut gates = Gates::new()?;
    gates.install(50)?;
    assert_eq!(gates.gate(50)?, Ok(()));
    // The release is valid for the seconds [40, 60): the boundary pair.
    assert_eq!(gates.gate(59)?, Ok(()));
    assert_eq!(gates.gate(60)?, Err(expired()));
    Ok(())
}

#[test]
fn a_gate_below_the_second_the_installer_committed_is_trust_state_unavailable() -> TestResult {
    let mut gates = Gates::new()?;
    gates.install(55)?;
    assert_eq!(gates.gate(50)?, Err(TRUST_UNAVAILABLE));
    assert_eq!(gates.gate(55)?, Ok(()));
    Ok(())
}

#[test]
fn two_sources_for_two_steps_give_the_two_instants() -> TestResult {
    let mut gates = Gates::new()?;
    gates.install(50)?;
    assert_eq!(gates.gate(55)?, Ok(()), "a later source for the gate");
    assert_eq!(gates.gate(60)?, Err(expired()), "and an expired one");
    Ok(())
}

#[test]
fn the_fixture_source_is_accepted_by_a_pass_and_a_refresh() -> TestResult {
    let mut gates = Gates::new()?;
    gates.install(50)?;
    let mut host = CommunityPluginHostV1::<CommunityMemberV1>::new(Vec::new());
    let mut wall = fixture_wall(50)?;
    let pass = gates
        .world
        .run_pass(&mut host, &mut wall, TICK)
        .map_err(|e| format!("{e:?}"))?;
    assert_eq!(pass.utc, Some(50));
    let mut wall = fixture_wall(50)?;
    drop(gates.world.refresh(&mut host, &gates.real.material, &mut wall, TICK));
    Ok(())
}

#[test]
fn a_port_is_a_world_port_over_the_program_it_was_given() {
    let port = EvaluationWorldPortV1::new(
        WorkerProgramV1::new(PathBuf::from("/bin/false")).unwrap_or_else(|| {
            std::panic::resume_unwind(Box::new("relative"));
        }),
    );
    assert_eq!(port.outcome_bytes(), Vec::<u8>::new());
}
