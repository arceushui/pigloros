use std::sync::atomic::{AtomicUsize, Ordering};

use pos_core::{
    manifest_owner_admission_intent_digest_v1,
    output_policy::{OutputPolicyInputV1, OutputPolicyV1},
    prepare_manifest_owner_admission_v1, ArtifactDataClassV1, ArtifactOptionalityV1,
    ArtifactTransitionRuleV1, Hash, ManifestAdmissionCatalogInputV1, ManifestAdmissionCatalogRowV1,
    ManifestAdmissionCatalogV1, ManifestOwnerAdmissionCommitKindV1, ManifestOwnerAdmissionErrorV1,
    ManifestOwnerAdmissionOwnerStateV1, ManifestOwnerAdmissionRequestV1,
    ManifestOwnerAdmissionVerifierV1, ManifestOwnerPolicyCopiesV1,
    ManifestOwnerTimelineAdmissionRequestV1, ManifestSlotAdmissionReceiptDraftV1,
    ManifestSlotAdmissionReceiptV1, PluginId, TimelineId, WorldArtifactKindV1,
    WorldArtifactLeafInputV1, WorldArtifactLeafV1, WorldConsumerSetInputV1, WorldConsumerSetV1,
    WorldProducerV1, MAX_MANIFEST_OWNER_POLICY_COPY_BYTES_V1,
};
use pos_store::{memory::MemoryStore, ManifestOwnerAdmissionPersistencePortV1};

#[cfg(feature = "sqlite")]
use pos_store::sqlite::SqliteStore;

type FixtureResult<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = FixtureResult<()>;
type PolicySource = (OutputPolicyV1, Vec<u8>);
type CatalogFixture = (ManifestAdmissionCatalogV1, Vec<PolicySource>);

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

const fn plugin(byte: u8) -> PluginId {
    PluginId::from_ulid(ulid::Ulid::from_bytes([byte; 16]))
}

const fn timeline(byte: u8) -> TimelineId {
    TimelineId::from_ulid(ulid::Ulid::from_bytes([byte; 16]))
}

struct FixtureOwner {
    expected_timelines: Vec<TimelineId>,
    expected_operation: Hash,
    signatures_issued: AtomicUsize,
    coordinator_evidence: Hash,
    signature_byte: u8,
}

impl FixtureOwner {
    const fn new(expected_timelines: Vec<TimelineId>, expected_operation: Hash) -> Self {
        Self {
            expected_timelines,
            expected_operation,
            signatures_issued: AtomicUsize::new(0),
            coordinator_evidence: hash(90),
            signature_byte: 0x5a,
        }
    }

    const fn with_signing_identity(mut self, evidence: Hash, signature_byte: u8) -> Self {
        self.coordinator_evidence = evidence;
        self.signature_byte = signature_byte;
        self
    }
}

impl ManifestOwnerAdmissionVerifierV1 for FixtureOwner {
    fn verify_complete_composition(
        &self,
        catalog: &ManifestAdmissionCatalogV1,
    ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
        let rows = &catalog.as_input().rows;
        if rows.len() != 2
            || rows[0].plugin_name != rows[1].plugin_name
            || rows[0].plugin_id == rows[1].plugin_id
        {
            return Err(ManifestOwnerAdmissionErrorV1::OwnerRejected);
        }
        Ok(())
    }

    fn verify_complete_owned_scope_set(
        &self,
        _owner_id: [u8; 32],
        timelines: &[ManifestOwnerTimelineAdmissionRequestV1],
    ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
        let actual: Vec<_> = timelines.iter().map(|row| row.timeline_id).collect();
        if actual != self.expected_timelines
            || timelines.iter().any(|row| row.wcs1.scope() != row.scope)
        {
            return Err(ManifestOwnerAdmissionErrorV1::OwnerRejected);
        }
        Ok(())
    }

    fn verify_owner_prestate_and_allocation(
        &self,
        request: &ManifestOwnerAdmissionRequestV1,
        current_state: Option<&ManifestOwnerAdmissionOwnerStateV1>,
    ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
        let current_state_matches = match (request.expected_configuration_generation, current_state)
        {
            (None, None) => true,
            (Some(expected), Some(state)) => {
                state.configuration_generation == expected
                    && state.previous_visible_lcq1_hash == request.previous_visible_lcq1_hash
                    && Some(state.inventory_generation) == request.expected_inventory_generation
            }
            _ => false,
        };
        if request.operation_id != self.expected_operation
            || request.resulting_inventory_generation == Hash::zero()
            || !current_state_matches
        {
            return Err(ManifestOwnerAdmissionErrorV1::OwnerRejected);
        }
        Ok(())
    }

    fn sign_coordinator_receipt(
        &self,
        draft: ManifestSlotAdmissionReceiptDraftV1,
    ) -> Result<ManifestSlotAdmissionReceiptV1, ManifestOwnerAdmissionErrorV1> {
        self.signatures_issued.fetch_add(1, Ordering::SeqCst);
        draft
            .with_evidence_and_signature(self.coordinator_evidence, [self.signature_byte; 64])
            .map_err(|_| ManifestOwnerAdmissionErrorV1::OwnerRejected)
    }

    fn verify_coordinator_receipt(
        &self,
        receipt: &ManifestSlotAdmissionReceiptV1,
    ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
        if receipt.as_input().coordinator_key_evidence_hash != self.coordinator_evidence
            || receipt.as_input().signature != [self.signature_byte; 64]
        {
            return Err(ManifestOwnerAdmissionErrorV1::OwnerRejected);
        }
        Ok(())
    }

    fn verify_native_policy_copies(
        &self,
        _timeline_id: TimelineId,
        scope: Hash,
        copies: &ManifestOwnerPolicyCopiesV1,
    ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
        if !copies.eop1_bytes.starts_with(b"\x8a\x44EOP1")
            || !copies.opc1_bytes.starts_with(b"OPC1")
            || copies.eop1_leaf.as_input().scope != scope
            || copies.opc1_leaf.as_input().scope != scope
            || copies.eop1_leaf.as_input().optionality != ArtifactOptionalityV1::Required
            || copies.opc1_leaf.as_input().optionality != ArtifactOptionalityV1::Required
        {
            return Err(ManifestOwnerAdmissionErrorV1::OwnerRejected);
        }
        Ok(())
    }
}

fn policy_and_closure(
    plugin_id: PluginId,
    fixture_seed: u8,
) -> Result<(OutputPolicyV1, Vec<u8>), Box<dyn std::error::Error>> {
    let policy = OutputPolicyV1::new(OutputPolicyInputV1 {
        plugin_id,
        plugin_version: "1.0.0".to_owned(),
        implementation_hash: hash(fixture_seed + 30),
        base_configuration_digest: hash(fixture_seed + 40),
        executable_profile_hash: hash(fixture_seed + 50),
        retention_policy_hash: hash(fixture_seed + 60),
        policy_revision: 1,
        output_declarations: Vec::new(),
    })?;
    let members = [
        policy.to_canonical_cbor(),
        b"EBP1-fixture".to_vec(),
        b"implementation-fixture".to_vec(),
        b"CFG1-fixture".to_vec(),
        Vec::new(),
        b"RTP1-fixture".to_vec(),
    ];
    let mut closure = b"OPC1".to_vec();
    for member in members {
        closure.extend_from_slice(
            &u64::try_from(member.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        closure.extend_from_slice(&member);
    }
    Ok((policy, closure))
}

fn opc1_digest(bytes: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pigloros.manifest-plugin-closure.v1\0");
    hasher.update(bytes);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn catalog(owner_id: [u8; 32], generation: u64) -> FixtureResult<CatalogFixture> {
    let source = vec![
        policy_and_closure(plugin(1), 1)?,
        policy_and_closure(plugin(2), 2)?,
    ];
    let rows = source
        .iter()
        .enumerate()
        .map(|(index, (policy, closure))| ManifestAdmissionCatalogRowV1 {
            stable_slot: if index == 0 { "slot-a" } else { "slot-b" }.to_owned(),
            plugin_id: policy.fields().plugin_id,
            plugin_name: "same-name".to_owned(),
            plugin_version: policy.fields().plugin_version.clone(),
            implementation_hash: policy.fields().implementation_hash,
            eop1_native_digest: policy.digest(),
            closure_hash: opc1_digest(closure),
        })
        .collect();
    Ok((
        ManifestAdmissionCatalogV1::new(ManifestAdmissionCatalogInputV1 {
            owner_id,
            configuration_generation: generation,
            rows,
        })?,
        source,
    ))
}

fn policy_copies(
    scope: Hash,
    owner_id: [u8; 32],
    source: &[PolicySource],
    lease_hash: Hash,
) -> FixtureResult<Vec<ManifestOwnerPolicyCopiesV1>> {
    source
        .iter()
        .map(|(policy, closure)| {
            let eop1_bytes = policy.to_canonical_cbor();
            let eop1_leaf = WorldArtifactLeafV1::new(WorldArtifactLeafInputV1 {
                scope,
                kind: WorldArtifactKindV1::OutputPolicy,
                native_digest: policy.digest(),
                native_byte_length: u64::try_from(eop1_bytes.len()).unwrap_or(u64::MAX),
                owner: owner_id,
                data_class: ArtifactDataClassV1::StructuralAuditMetadata,
                optionality: ArtifactOptionalityV1::Required,
                transition: ArtifactTransitionRuleV1::PreserveExact,
                source_lease_hash: lease_hash,
                key_dependencies: Vec::new(),
                child_node_hashes: Vec::new(),
            })?;
            let opc1_leaf = WorldArtifactLeafV1::new(WorldArtifactLeafInputV1 {
                scope,
                kind: WorldArtifactKindV1::OutputPolicyClosure,
                native_digest: opc1_digest(closure),
                native_byte_length: u64::try_from(closure.len()).unwrap_or(u64::MAX),
                owner: owner_id,
                data_class: ArtifactDataClassV1::StructuralAuditMetadata,
                optionality: ArtifactOptionalityV1::Required,
                transition: ArtifactTransitionRuleV1::PreserveExact,
                source_lease_hash: lease_hash,
                key_dependencies: Vec::new(),
                child_node_hashes: Vec::new(),
            })?;
            Ok(ManifestOwnerPolicyCopiesV1 {
                plugin_id: policy.fields().plugin_id,
                eop1_bytes,
                eop1_leaf,
                opc1_bytes: closure.clone(),
                opc1_leaf,
            })
        })
        .collect()
}

#[derive(Clone, Copy)]
struct AdmissionTransition {
    owner_id: [u8; 32],
    generation: u64,
    expected_generation: Option<u64>,
    previous_receipt: Option<Hash>,
    expected_inventory: Option<Hash>,
    resulting_inventory: Hash,
    operation_id: Hash,
}

fn request(
    transition: AdmissionTransition,
    timeline_ids: &[TimelineId],
) -> Result<ManifestOwnerAdmissionRequestV1, Box<dyn std::error::Error>> {
    let (catalog, sources) = catalog(transition.owner_id, transition.generation)?;
    let timelines = timeline_ids
        .iter()
        .enumerate()
        .map(|(index, timeline_id)| {
            let scope = hash(70 + u8::try_from(index).unwrap_or(u8::MAX));
            let wcs1 = WorldConsumerSetV1::new(WorldConsumerSetInputV1 {
                scope,
                consumers: Vec::new(),
                // The second same-name Plugin is reducer-only and deliberately
                // absent from WCS1 while remaining in MCA1/MSB1 and the copies.
                producers: vec![WorldProducerV1::new(plugin(1), sources[0].0.digest())?],
                optional_view_roots: Vec::new(),
            })?;
            Ok(ManifestOwnerTimelineAdmissionRequestV1 {
                timeline_id: *timeline_id,
                scope,
                wcs1,
                policy_copies: policy_copies(
                    scope,
                    transition.owner_id,
                    &sources,
                    hash(80 + u8::try_from(index).unwrap_or(u8::MAX)),
                )?,
            })
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    Ok(ManifestOwnerAdmissionRequestV1 {
        operation_id: transition.operation_id,
        catalog,
        expected_configuration_generation: transition.expected_generation,
        previous_visible_lcq1_hash: transition.previous_receipt,
        expected_inventory_generation: transition.expected_inventory,
        resulting_inventory_generation: transition.resulting_inventory,
        timelines,
    })
}

#[test]
fn preparation_rejects_duplicate_timelines_and_missing_zero_output_copy() -> TestResult {
    let owner_id = [9; 32];
    let scope_timelines = vec![timeline(1), timeline(2)];
    let operation_id = hash(45);
    let duplicate = request(
        AdmissionTransition {
            owner_id,
            generation: 1,
            expected_generation: None,
            previous_receipt: None,
            expected_inventory: None,
            resulting_inventory: hash(44),
            operation_id,
        },
        &[timeline(1), timeline(1)],
    )?;
    assert_eq!(
        prepare_manifest_owner_admission_v1(
            duplicate,
            &FixtureOwner::new(vec![timeline(1), timeline(1)], operation_id),
            None,
        ),
        Err(ManifestOwnerAdmissionErrorV1::InvalidBatch)
    );

    let mut missing_copy = request(
        AdmissionTransition {
            owner_id,
            generation: 1,
            expected_generation: None,
            previous_receipt: None,
            expected_inventory: None,
            resulting_inventory: hash(44),
            operation_id,
        },
        &scope_timelines,
    )?;
    missing_copy.timelines[0].policy_copies.pop();
    let owner = FixtureOwner::new(scope_timelines, operation_id);
    assert_eq!(
        prepare_manifest_owner_admission_v1(missing_copy, &owner, None),
        Err(ManifestOwnerAdmissionErrorV1::InvalidBatch)
    );
    assert_eq!(owner.signatures_issued.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn preparation_bounds_total_native_copies() -> TestResult {
    let owner_id = [29; 32];
    let timeline_id = timeline(21);
    let operation_id = hash(121);
    let mut oversized = request(
        AdmissionTransition {
            owner_id,
            generation: 1,
            expected_generation: None,
            previous_receipt: None,
            expected_inventory: None,
            resulting_inventory: hash(120),
            operation_id,
        },
        &[timeline_id],
    )?;
    oversized.timelines[0].policy_copies[0].eop1_bytes =
        vec![0; MAX_MANIFEST_OWNER_POLICY_COPY_BYTES_V1];
    oversized.timelines[0].policy_copies[0].opc1_bytes =
        vec![0; MAX_MANIFEST_OWNER_POLICY_COPY_BYTES_V1];
    let owner = FixtureOwner::new(vec![timeline_id], operation_id);
    assert_eq!(
        prepare_manifest_owner_admission_v1(oversized, &owner, None),
        Err(ManifestOwnerAdmissionErrorV1::BoundExceeded)
    );
    assert_eq!(owner.signatures_issued.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn preparation_rejects_malformed_opc1_envelopes_before_signing() -> TestResult {
    let owner_id = [29; 32];
    let timeline_id = timeline(21);
    let operation_id = hash(121);
    let input = request(
        AdmissionTransition {
            owner_id,
            generation: 1,
            expected_generation: None,
            previous_receipt: None,
            expected_inventory: None,
            resulting_inventory: hash(120),
            operation_id,
        },
        &[timeline_id],
    )?;
    let valid = input.timelines[0].policy_copies[0].opc1_bytes.clone();
    let mut truncated_header = valid.clone();
    truncated_header.truncate(4);
    let mut mismatched_eop1 = valid.clone();
    mismatched_eop1[12] ^= 1;
    let mut oversized_member_length = valid.clone();
    oversized_member_length[4..12].fill(u8::MAX);
    let mut trailing_bytes = valid;
    trailing_bytes.push(0);

    for malformed in [
        truncated_header,
        mismatched_eop1,
        oversized_member_length,
        trailing_bytes,
    ] {
        let mut malformed_input = input.clone();
        malformed_input.timelines[0].policy_copies[0].opc1_bytes = malformed;
        let owner = FixtureOwner::new(vec![timeline_id], operation_id);
        assert_eq!(
            prepare_manifest_owner_admission_v1(malformed_input, &owner, None),
            Err(ManifestOwnerAdmissionErrorV1::InvalidBatch)
        );
        assert_eq!(owner.signatures_issued.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[test]
fn memory_owner_admission_resolves_retries_conflicts_and_historical_rows() -> TestResult {
    let owner_id = [9; 32];
    let first_timelines = vec![timeline(1), timeline(2)];
    let genesis_request = request(
        AdmissionTransition {
            owner_id,
            generation: 1,
            expected_generation: None,
            previous_receipt: None,
            expected_inventory: None,
            resulting_inventory: hash(40),
            operation_id: hash(41),
        },
        &first_timelines,
    )?;
    let genesis_owner = FixtureOwner::new(first_timelines.clone(), hash(41));
    let prepared =
        prepare_manifest_owner_admission_v1(genesis_request.clone(), &genesis_owner, None)?;
    assert_eq!(genesis_owner.signatures_issued.load(Ordering::SeqCst), 2);
    let mut store = MemoryStore::new();
    let applied = store.commit_manifest_owner_admission_v1(prepared)?;
    assert_eq!(applied.kind, ManifestOwnerAdmissionCommitKindV1::Applied);
    assert_eq!(applied.receipt_hashes.len(), 2);

    let retry_owner =
        FixtureOwner::new(first_timelines.clone(), hash(41)).with_signing_identity(hash(91), 0xa5);
    let retry_prepared =
        prepare_manifest_owner_admission_v1(genesis_request.clone(), &retry_owner, None)?;
    assert_ne!(
        retry_prepared.input().timelines[0].receipt.digest(),
        applied.receipt_hashes[0]
    );
    let exact = store.commit_manifest_owner_admission_v1(retry_prepared)?;
    assert_eq!(exact.kind, ManifestOwnerAdmissionCommitKindV1::ExactRetry);
    assert_eq!(exact.receipt_hashes, applied.receipt_hashes);

    let mut conflicting_operation = genesis_request;
    conflicting_operation.resulting_inventory_generation = hash(42);
    let conflicting =
        prepare_manifest_owner_admission_v1(conflicting_operation, &genesis_owner, None)?;
    assert_eq!(
        store.commit_manifest_owner_admission_v1(conflicting),
        Err(ManifestOwnerAdmissionErrorV1::Conflict)
    );

    let signatures_before_conflict = genesis_owner.signatures_issued.load(Ordering::SeqCst);
    let competing_genesis = request(
        AdmissionTransition {
            owner_id,
            generation: 1,
            expected_generation: None,
            previous_receipt: None,
            expected_inventory: None,
            resulting_inventory: hash(43),
            operation_id: hash(44),
        },
        &first_timelines,
    )?;
    let competing_owner = FixtureOwner::new(first_timelines.clone(), hash(44));
    assert_eq!(
        store.commit_manifest_owner_admission_v1(prepare_manifest_owner_admission_v1(
            competing_genesis,
            &competing_owner,
            None,
        )?),
        Err(ManifestOwnerAdmissionErrorV1::Conflict)
    );
    assert_eq!(
        genesis_owner.signatures_issued.load(Ordering::SeqCst),
        signatures_before_conflict
    );

    let current = store
        .read_manifest_owner_state_v1(owner_id)?
        .ok_or("missing genesis state")?;
    assert_eq!(current.configuration_generation, 1);
    assert_eq!(current.previous_visible_lcq1_hash, None);
    assert_eq!(current.inventory_generation, hash(40));
    assert_eq!(current.timelines, first_timelines);
    let historical = store
        .read_manifest_owner_admission_v1(owner_id, 1, timeline(1))?
        .ok_or("missing genesis admission row")?;
    assert_eq!(historical.timeline.policy_copies.len(), 2);
    assert_eq!(historical.timeline.wcs1.producers().len(), 1);
    assert_eq!(
        historical
            .timeline
            .receipt
            .as_input()
            .previous_visible_lcq1_hash,
        None
    );
    assert_eq!(
        historical
            .timeline
            .receipt
            .as_input()
            .expected_inventory_generation,
        None
    );

    Ok(())
}

#[test]
fn memory_owner_admission_replaces_the_complete_timeline_set() -> TestResult {
    let owner_id = [10; 32];
    let first_timelines = vec![timeline(1), timeline(2)];
    let genesis_request = request(
        AdmissionTransition {
            owner_id,
            generation: 1,
            expected_generation: None,
            previous_receipt: None,
            expected_inventory: None,
            resulting_inventory: hash(60),
            operation_id: hash(61),
        },
        &first_timelines,
    )?;
    let genesis_owner = FixtureOwner::new(first_timelines, hash(61));
    let mut store = MemoryStore::new();
    let genesis = prepare_manifest_owner_admission_v1(genesis_request, &genesis_owner, None)?;
    store.commit_manifest_owner_admission_v1(genesis)?;
    let previous = store
        .read_manifest_owner_state_v1(owner_id)?
        .ok_or("missing pre-replacement owner state")?;

    let replacement_timelines = vec![timeline(3), timeline(4)];
    let replacement_request = request(
        AdmissionTransition {
            owner_id,
            generation: 2,
            expected_generation: Some(1),
            previous_receipt: None,
            expected_inventory: Some(hash(60)),
            resulting_inventory: hash(50),
            operation_id: hash(51),
        },
        &replacement_timelines,
    )?;
    let replacement_owner = FixtureOwner::new(replacement_timelines.clone(), hash(51));
    let replacement =
        store.commit_manifest_owner_admission_v1(prepare_manifest_owner_admission_v1(
            replacement_request,
            &replacement_owner,
            Some(&previous),
        )?)?;
    assert_eq!(replacement.configuration_generation, 2);
    let current = store
        .read_manifest_owner_state_v1(owner_id)?
        .ok_or("missing replacement state")?;
    assert_eq!(current.timelines, replacement_timelines);
    assert_eq!(current.previous_visible_lcq1_hash, None);
    assert_eq!(current.inventory_generation, hash(50));
    let replacement_row = store
        .read_manifest_owner_admission_v1(owner_id, 2, timeline(3))?
        .ok_or("missing replacement scope row")?;
    assert_eq!(
        replacement_row
            .timeline
            .receipt
            .as_input()
            .expected_inventory_generation,
        Some(hash(60))
    );
    assert!(store
        .read_manifest_owner_admission_v1(owner_id, 1, timeline(1))?
        .is_some());
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_owner_admission_rolls_back_failed_transaction_and_recovers_after_reopen() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("owner-admission.sqlite");
    let owner_id = [19; 32];
    let timelines = vec![timeline(11), timeline(12)];
    let operation_id = hash(111);
    let input = request(
        AdmissionTransition {
            owner_id,
            generation: 1,
            expected_generation: None,
            previous_receipt: None,
            expected_inventory: None,
            resulting_inventory: hash(110),
            operation_id,
        },
        &timelines,
    )?;
    let owner = FixtureOwner::new(timelines.clone(), operation_id);
    let mut store = SqliteStore::open(path.to_str().ok_or("non-UTF8 test path")?)?;
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute_batch(
        "CREATE TRIGGER fail_manifest_policy_copy
         BEFORE INSERT ON manifest_owner_policy_copies
         BEGIN SELECT RAISE(ABORT, 'injected policy-copy failure'); END;",
    )?;
    assert_eq!(
        store.commit_manifest_owner_admission_v1(prepare_manifest_owner_admission_v1(
            input.clone(),
            &owner,
            None,
        )?),
        Err(ManifestOwnerAdmissionErrorV1::StorageFailure)
    );
    let partial_rows: i64 = connection.query_row(
        "SELECT COUNT(*) FROM manifest_owner_admissions WHERE owner_id = ?1",
        rusqlite::params![owner_id.as_slice()],
        |row| row.get(0),
    )?;
    assert_eq!(partial_rows, 0);
    let partial_operations: i64 = connection.query_row(
        "SELECT COUNT(*) FROM manifest_owner_admission_operations WHERE owner_id = ?1",
        rusqlite::params![owner_id.as_slice()],
        |row| row.get(0),
    )?;
    assert_eq!(partial_operations, 0);
    assert_eq!(store.read_manifest_owner_state_v1(owner_id)?, None);
    connection.execute_batch("DROP TRIGGER fail_manifest_policy_copy")?;
    drop(connection);

    let applied = store.commit_manifest_owner_admission_v1(prepare_manifest_owner_admission_v1(
        input.clone(),
        &owner,
        None,
    )?)?;
    assert_eq!(applied.kind, ManifestOwnerAdmissionCommitKindV1::Applied);
    drop(store);

    let reopened = SqliteStore::open(path.to_str().ok_or("non-UTF8 test path")?)?;
    let current = reopened
        .read_manifest_owner_state_v1(owner_id)?
        .ok_or("SQLite owner state is missing after reopen")?;
    assert_eq!(current.configuration_generation, 1);
    assert_eq!(current.timelines, timelines);
    let snapshot = reopened
        .read_manifest_owner_admission_v1(owner_id, 1, timeline(11))?
        .ok_or("SQLite native admission is missing after reopen")?;
    assert_eq!(snapshot.timeline.policy_copies.len(), 2);
    assert_eq!(snapshot.timeline.wcs1.producers().len(), 1);
    let signatures_before_retry = owner.signatures_issued.load(Ordering::SeqCst);
    let retry = reopened
        .resolve_manifest_owner_admission_retry_v1(
            owner_id,
            operation_id,
            manifest_owner_admission_intent_digest_v1(&input)?,
        )?
        .ok_or("SQLite should resolve the persisted operation before signing")?;
    assert_eq!(retry.kind, ManifestOwnerAdmissionCommitKindV1::ExactRetry);
    assert_eq!(retry.receipt_hashes, applied.receipt_hashes);
    assert_eq!(
        owner.signatures_issued.load(Ordering::SeqCst),
        signatures_before_retry
    );
    let mut conflicting_input = input;
    conflicting_input.resulting_inventory_generation = hash(112);
    assert_eq!(
        reopened.resolve_manifest_owner_admission_retry_v1(
            owner_id,
            operation_id,
            manifest_owner_admission_intent_digest_v1(&conflicting_input)?,
        ),
        Err(ManifestOwnerAdmissionErrorV1::Conflict)
    );
    let connection = rusqlite::Connection::open(&path)?;
    assert_sqlite_owner_receipt_corruption_is_rejected(
        &reopened,
        &connection,
        owner_id,
        operation_id,
    )?;
    Ok(())
}

#[cfg(feature = "sqlite")]
fn assert_competing_sqlite_owner_admission_conflicts(
    store: &mut SqliteStore,
    owner_id: [u8; 32],
    pre_replacement: &ManifestOwnerAdmissionOwnerStateV1,
) -> TestResult {
    let competing_timelines = vec![timeline(25), timeline(26)];
    let competing_operation = hash(155);
    let competing_request = request(
        AdmissionTransition {
            owner_id,
            generation: 2,
            expected_generation: Some(1),
            previous_receipt: None,
            expected_inventory: Some(hash(150)),
            resulting_inventory: hash(154),
            operation_id: competing_operation,
        },
        &competing_timelines,
    )?;
    let competing_owner = FixtureOwner::new(competing_timelines, competing_operation);
    let competing = prepare_manifest_owner_admission_v1(
        competing_request,
        &competing_owner,
        Some(pre_replacement),
    )?;
    assert_eq!(
        store.commit_manifest_owner_admission_v1(competing),
        Err(ManifestOwnerAdmissionErrorV1::Conflict)
    );
    Ok(())
}

#[cfg(feature = "sqlite")]
#[test]
fn sqlite_owner_admission_replaces_complete_generation_and_recovers_after_reopen() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("owner-admission-replacement.sqlite");
    let path = path.to_str().ok_or("non-UTF8 test path")?;
    let owner_id = [29; 32];
    let original_timelines = vec![timeline(21), timeline(22)];
    let genesis_operation = hash(151);
    let genesis_request = request(
        AdmissionTransition {
            owner_id,
            generation: 1,
            expected_generation: None,
            previous_receipt: None,
            expected_inventory: None,
            resulting_inventory: hash(150),
            operation_id: genesis_operation,
        },
        &original_timelines,
    )?;
    let genesis_owner = FixtureOwner::new(original_timelines, genesis_operation);
    let mut store = SqliteStore::open(path)?;
    let genesis = prepare_manifest_owner_admission_v1(genesis_request, &genesis_owner, None)?;
    let genesis_result = store.commit_manifest_owner_admission_v1(genesis)?;
    assert_eq!(
        genesis_result.kind,
        ManifestOwnerAdmissionCommitKindV1::Applied
    );
    let pre_replacement = store
        .read_manifest_owner_state_v1(owner_id)?
        .ok_or("SQLite owner state is missing before replacement")?;

    let replacement_timelines = vec![timeline(23), timeline(24)];
    let replacement_operation = hash(153);
    let replacement_request = request(
        AdmissionTransition {
            owner_id,
            generation: 2,
            expected_generation: Some(1),
            previous_receipt: None,
            expected_inventory: Some(hash(150)),
            resulting_inventory: hash(152),
            operation_id: replacement_operation,
        },
        &replacement_timelines,
    )?;
    let replacement_owner =
        FixtureOwner::new(replacement_timelines.clone(), replacement_operation);
    let replacement = prepare_manifest_owner_admission_v1(
        replacement_request.clone(),
        &replacement_owner,
        Some(&pre_replacement),
    )?;
    let replaced = store.commit_manifest_owner_admission_v1(replacement)?;
    assert_eq!(replaced.kind, ManifestOwnerAdmissionCommitKindV1::Applied);
    assert_eq!(replaced.configuration_generation, 2);
    assert_eq!(replaced.receipt_hashes.len(), replacement_timelines.len());

    assert_competing_sqlite_owner_admission_conflicts(
        &mut store,
        owner_id,
        &pre_replacement,
    )?;
    drop(store);

    let reopened = SqliteStore::open(path)?;
    let current = reopened
        .read_manifest_owner_state_v1(owner_id)?
        .ok_or("SQLite owner state is missing after replacement")?;
    assert_eq!(current.configuration_generation, 2);
    assert_eq!(current.timelines, replacement_timelines);
    assert_eq!(current.inventory_generation, hash(152));
    assert_eq!(current.previous_visible_lcq1_hash, None);
    assert!(reopened
        .read_manifest_owner_admission_v1(owner_id, 1, timeline(21))?
        .is_some());
    for timeline_id in [timeline(23), timeline(24)] {
        let historical = reopened
            .read_manifest_owner_admission_v1(owner_id, 2, timeline_id)?
            .ok_or("replacement generation scope row was lost after reopen")?;
        assert_eq!(historical.timeline.policy_copies.len(), 2);
        assert_eq!(
            historical
                .timeline
                .receipt
                .as_input()
                .expected_inventory_generation,
            Some(hash(150))
        );
    }
    let retry = reopened
        .resolve_manifest_owner_admission_retry_v1(
            owner_id,
            replacement_operation,
            manifest_owner_admission_intent_digest_v1(&replacement_request)?,
        )?
        .ok_or("SQLite did not recover the replacement operation")?;
    assert_eq!(retry.kind, ManifestOwnerAdmissionCommitKindV1::ExactRetry);
    assert_eq!(retry.receipt_hashes, replaced.receipt_hashes);
    let mut conflicting_retry = replacement_request;
    conflicting_retry.resulting_inventory_generation = hash(156);
    assert_eq!(
        reopened.resolve_manifest_owner_admission_retry_v1(
            owner_id,
            replacement_operation,
            manifest_owner_admission_intent_digest_v1(&conflicting_retry)?,
        ),
        Err(ManifestOwnerAdmissionErrorV1::Conflict)
    );
    Ok(())
}

fn assert_sqlite_owner_receipt_corruption_is_rejected(
    store: &SqliteStore,
    connection: &rusqlite::Connection,
    owner_id: [u8; 32],
    operation_id: Hash,
) -> TestResult {
    connection.execute(
        "UPDATE manifest_owner_admission_operations
         SET receipt_count = 1 WHERE owner_id = ?1 AND operation_id = ?2",
        rusqlite::params![owner_id.as_slice(), operation_id.as_bytes().as_slice()],
    )?;
    assert_eq!(
        store.read_manifest_owner_state_v1(owner_id),
        Err(ManifestOwnerAdmissionErrorV1::CorruptState)
    );
    assert_eq!(
        store.read_manifest_owner_admission_v1(owner_id, 1, timeline(11)),
        Err(ManifestOwnerAdmissionErrorV1::CorruptState)
    );
    connection.execute_batch("PRAGMA ignore_check_constraints = ON")?;
    connection.execute(
        "UPDATE manifest_owner_admission_operations
         SET receipt_count = 0 WHERE owner_id = ?1 AND operation_id = ?2",
        rusqlite::params![owner_id.as_slice(), operation_id.as_bytes().as_slice()],
    )?;
    assert_eq!(
        store.read_manifest_owner_state_v1(owner_id),
        Err(ManifestOwnerAdmissionErrorV1::CorruptState)
    );
    connection.execute(
        "UPDATE manifest_owner_admission_operations
         SET receipt_count = 2, receipt_set_digest = zeroblob(32)
         WHERE owner_id = ?1 AND operation_id = ?2",
        rusqlite::params![owner_id.as_slice(), operation_id.as_bytes().as_slice()],
    )?;
    assert_eq!(
        store.read_manifest_owner_state_v1(owner_id),
        Err(ManifestOwnerAdmissionErrorV1::CorruptState)
    );
    Ok(())
}
