//! R8-A6 and R8-A10: the real port and the S1c2 world with the fixture source, on releases of
//! the signed-release test world (no real worker: `/bin/false` stands in).

use pos_core::trusted_clock::{FixtureEvaluationInstantV1, FixtureWallSourceV1};
use pos_plugin_publisher::test_support::{encoding::TICK, release::Shape, world::World};
use pos_plugin_release::{
    BundleAddressV1, InMemoryReleaseEntryV1, ReleaseSourceV1, VerifiedReleaseBundleV1,
};
use pos_plugin_supervisor::CommunityPluginSubjectResultV1;
use pos_reference::evaluator::SubjectResult;
use pos_reference::evaluator_domain::{ExecutionMode, FixtureFamily};
use pos_runtime::community_plugin_host::CommunityTrustAnchorBytesV1;
use serde_json::{json, Value};

use super::*;
use crate::map::{case_result, of_record, SubResultV1};
use crate::payload::ScanSource;
use crate::run_with;
use crate::test_support::{
    attempt, composite, hex_of, observation, parsed, payload, stream, subcase, TestResult,
};

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

/// What the signed-release test world published, as bytes.
struct Published {
    address: BundleAddressV1,
    manifest: Vec<u8>,
    layers: Vec<Vec<u8>>,
    pmf1_digest: [u8; 32],
    anchor: CommunityTrustAnchorBytesV1,
    roots: Vec<Vec<u8>>,
    revocations: Vec<Vec<u8>>,
    tps1: Vec<u8>,
}

fn published() -> Result<Published, BoxError> {
    let mut publisher = World::build(None, false)?;
    let current = publisher.material()?;
    let shape = Shape::first().with_optional_capability().with_worker_abi();
    let address = publisher.publish(shape)?.address().clone();
    let bundle = publisher.store.read_verified(&address)?;
    Ok(Published {
        address,
        manifest: bundle.manifest().to_vec(),
        layers: layers_of(&bundle),
        pmf1_digest: *blake3::hash(bundle.pmf1()).as_bytes(),
        anchor: anchor_of(&publisher),
        roots: vec![current.ptr1().to_vec()],
        revocations: current.prv1_records().to_vec(),
        tps1: current.tps1,
    })
}

/// The layer pieces of a closure: every blob but the empty config.
fn layers_of(bundle: &VerifiedReleaseBundleV1) -> Vec<Vec<u8>> {
    let layers = bundle.blobs().iter();
    let layers = layers.filter(|blob| blob.digest() != EMPTY_CONFIG);
    layers.map(|blob| blob.bytes().to_vec()).collect()
}

fn anchor_of(publisher: &World) -> CommunityTrustAnchorBytesV1 {
    CommunityTrustAnchorBytesV1 {
        scope: publisher.anchor.scope().to_owned(),
        ptr1_genesis_digest: publisher.anchor.ptr1_genesis_digest(),
        operator_key: publisher.anchor.operator_key(),
        genesis_tps1_digest: publisher.anchor.genesis_tps1_digest(),
    }
}

fn hexes(records: &[Vec<u8>]) -> Vec<String> {
    records.iter().map(|record| hex_of(record)).collect()
}

/// Every piece of the release set, sorted and without duplicates.
fn piece_set(published: &Published, anchor_bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut all = vec![published.manifest.clone(), published.tps1.clone()];
    all.push(anchor_bytes.to_vec());
    all.extend(published.layers.clone());
    all.extend(published.roots.clone());
    all.extend(published.revocations.clone());
    all.sort();
    all.dedup();
    all
}

fn release_source(published: &Published) -> Result<InMemoryReleaseSourceV1, BoxError> {
    let entry =
        InMemoryReleaseEntryV1::from_bytes(published.manifest.clone(), published.layers.clone())?;
    Ok(InMemoryReleaseSourceV1::new(vec![entry])?)
}

impl Real {
    fn new() -> Result<Self, BoxError> {
        let published = published()?;
        let anchor_bytes = anchor_cbor(&published.anchor)?;
        let material = CommunityPluginTrustMaterialV1::from_bytes_v1(
            &published.anchor,
            published.tps1.clone(),
            published.roots.clone(),
            published.revocations.clone(),
        )?;
        let all = piece_set(&published, &anchor_bytes);
        Ok(Self {
            source: release_source(&published)?,
            pieces: PiecesV1::from_blobs(all.clone()),
            all,
            release: json!({
                "manifest": hex_of(&published.manifest),
                "blobs": hexes(&published.layers),
            }),
            material_json: json!({
                "anchor": hex_of(&anchor_bytes),
                "tps1": hex_of(&published.tps1),
                "ptr1": hexes(&published.roots),
                "prv1": hexes(&published.revocations),
            }),
            material,
            address: published.address,
            pmf1_digest: published.pmf1_digest,
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

    fn crash_steps(&self) -> Vec<Value> {
        vec![
            self.install(50_000_000),
            self.bind(&self.material_json),
            pass_step(&json!({"plugin_id": PLUGIN})),
        ]
    }

    fn run(&self, steps: Vec<Value>, expect: Value) -> Result<SubCaseRecordV1, BoxError> {
        let document = subcase("x", steps, expect);
        let runner = runner_for("/bin/false")?;
        Ok(runner.run(
            &parsed(&document)?,
            &self.pieces,
            CommunityPluginModeV1::Local,
        ))
    }
}

fn refresh_step(material: &Value) -> Value {
    json!({
        "step": "refresh", "material": material, "instant_micros": 50_000_000, "tick": TICK,
    })
}

fn pass_step(member: &Value) -> Value {
    json!({
        "step": "pass", "members": [member], "instant_micros": 50_000_000, "tick": TICK,
        "invocation_id": INVOCATION_HEX, "random_domain": hex_of(b"domain"),
        "timeline_seq": 0, "observation": "00", "simulation_time": 1,
    })
}

fn scan_step(sources: &[&str], marker: &str) -> Value {
    json!({
        "step": "scan", "marker": marker, "in": sources,
        "retained": {"plugin_id": PLUGIN, "invocation_id_hex": INVOCATION_HEX},
    })
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
        for mode in [
            CommunityPluginModeV1::Local,
            CommunityPluginModeV1::AirGapped,
        ] {
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
            // `/bin/false` starts and is confined, then exits: one launch. A path that holds no
            // program never starts, so nothing launched although the member crashed (#660).
            let launched = u32::from(program == "/bin/false");
            assert_eq!(record.worker_launches, launched, "{program}");
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
    assert!(record
        .computed
        .is_some_and(|digest| digest != real.pmf1_digest));
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
        scan_step(&["state"], "init"),
    ];
    let record = real.run(steps, absent("init"))?;
    let scan = record.scan.ok_or("no scan")?;
    assert_eq!(
        scan.found,
        [ScanSource::State],
        "the initial state of the Driver"
    );
    assert_eq!(scan.observed_plugin_id, PLUGIN);

    let steps = vec![
        real.install(50_000_000),
        scan_step(&["events", "outcome", "state"], "init"),
    ];
    let record = real.run(steps, absent("init"))?;
    let scan = record.scan.ok_or("no scan")?;
    assert_eq!(
        scan.found,
        Vec::<ScanSource>::new(),
        "no Event, no Driver, no outcome"
    );
    Ok(())
}

#[test]
fn a_refresh_runs_on_the_registry_of_the_world() -> TestResult {
    let real = Real::new()?;
    let steps = vec![real.install(50_000_000), refresh_step(&real.material_json)];
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
        vec![refresh_step(&real.material_json), install.clone()],
        refused_expect("TrustStateUnavailable"),
    )?;
    assert_eq!(record.setup_refusal, Some(TRUST_UNAVAILABLE));
    assert_eq!(record.steps_run, 2);
    assert!(record.matched);

    let record = real.run(
        vec![real.install(50_000_000), refresh_step(&Value::Null)],
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
        pass_step(&member),
    ];
    let record = real.run(steps, refused_expect("TrustStateUnavailable"))?;
    assert_eq!(record.worker_launches, 0);
    assert!(record.matched, "{record:?}");

    // A member whose Plugin no bind registered is payload-invalid: nothing runs.
    let stranger = json!({"plugin_id": "plugin-b", "at": "absent"});
    let steps = vec![
        real.install(50_000_000),
        real.bind(&real.material_json),
        pass_step(&stranger),
    ];
    let record = real.run(steps, refused_expect("TrustStateUnavailable"))?;
    assert_eq!(record, SubCaseRecordV1::empty("x"));
    Ok(())
}

fn fixture_wall(second: u64) -> Result<FixtureWallSourceV1, BoxError> {
    let instant = FixtureEvaluationInstantV1::from_micros(second * 1_000_000);
    Ok(FixtureWallSourceV1::new(
        instant.map_err(|e| format!("{e:?}"))?,
    ))
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
        let world =
            CommunityEvaluationWorldV1::open(&real.material).map_err(|e| format!("{e:?}"))?;
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
fn an_install_at_second_40_and_a_gate_at_second_50_is_ok() -> TestResult {
    let mut gates = Gates::new()?;
    gates.install(40)?;
    assert_eq!(gates.gate(50)?, Ok(()));
    Ok(())
}

#[test]
fn the_launch_watchdog_is_300_seconds() {
    assert_eq!(LAUNCH_WATCHDOG_MS, 300_000);
    assert_eq!(launch_watchdog(), Duration::from_mins(5));
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
    let refreshed = gates
        .world
        .refresh(&mut host, &gates.real.material, &mut wall, TICK);
    // The same material is adopted or refused by the registry, never an operational fault.
    let refused = matches!(refreshed, Err(HostError::ArtifactTrustDenied { .. }));
    assert!(refreshed.is_ok() || refused, "{refreshed:?}");
    Ok(())
}

#[test]
fn a_port_is_a_world_port_over_the_program_it_was_given() {
    let port = EvaluationStepPortV1::new(
        WorkerProgramV1::new(PathBuf::from("/bin/false")).unwrap_or_else(|| {
            std::panic::resume_unwind(Box::new("relative"));
        }),
    );
    assert_eq!(port.outcome_bytes(), Vec::<u8>::new());
    assert_eq!(port.worker_launches(), 0, "no world, no Driver, no launch");
}

#[test]
fn a_pass_that_reports_another_number_of_members_is_a_wiring_fault() {
    let gate = Err(TRUST_UNAVAILABLE);
    let entry = MemberPassV1 {
        plugin: pos_core::PluginId::new(),
        expected_plugin_id: PLUGIN.to_owned(),
        gate,
        invocation_id: None,
        launch_failure: None,
        sync: Ok(()),
    };
    let mode = CommunityPluginModeV1::Local;
    assert_eq!(assemble_all(&[], &[], 5, mode), Ok(Vec::new()));
    assert_eq!(assemble_all(&[entry], &[], 5, mode), Err(WIRING));
}
