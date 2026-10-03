use std::error::Error;

use pos_core::{
    local_cut_owner_intent_digest_v1, Hash, LocalCutCompositionBindingRowV1,
    LocalCutExpectedHeadRowV1, LocalCutHeadsTableV1, LocalCutManifestBindingRowV1,
    LocalCutManifestBindingTableV1, LocalCutOwnerErrorV1, LocalCutOwnerRequestV1,
    LocalCutOwnerStateV1, LocalCutRecordingContextRowV1, LocalCutResultHeadRowV1,
    LocalCutSealInputV2, LocalCutSealV2, LocalCutTableRefV1, PluginId, TimelineId,
};

type TestResult = Result<(), Box<dyn Error>>;

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

fn table(row_count: u64, byte: u8) -> Result<LocalCutTableRefV1, pos_core::LocalCutSealErrorV2> {
    LocalCutTableRefV1::new(row_count, (row_count != 0).then(|| hash(byte)))
}

const fn expected_head(timeline_id: TimelineId) -> LocalCutExpectedHeadRowV1 {
    LocalCutExpectedHeadRowV1 {
        timeline_id,
        logical_head: 0,
        stitched_chain_hash: hash(34),
        source_timeline_id: timeline_id,
        source_segment_head: 0,
        source_chain_hash: hash(34),
        logical_prefix: 0,
        lineage_proof_hash: None,
        predecessor_wcb_hash: None,
    }
}

const fn result_head(timeline_id: TimelineId) -> LocalCutResultHeadRowV1 {
    LocalCutResultHeadRowV1 {
        timeline_id,
        result_logical_head: 0,
        result_stitched_hash: hash(34),
        result_source_segment_head: 0,
        result_source_chain_hash: hash(34),
        successor_wcb_hash: hash(35),
        event_count: 0,
    }
}

fn request() -> Result<LocalCutOwnerRequestV1, Box<dyn Error>> {
    let timeline_id = TimelineId::new();
    request_with_heads(
        vec![expected_head(timeline_id)],
        vec![result_head(timeline_id)],
    )
}

fn request_with_heads(
    expected_head_rows: Vec<LocalCutExpectedHeadRowV1>,
    result_head_rows: Vec<LocalCutResultHeadRowV1>,
) -> Result<LocalCutOwnerRequestV1, Box<dyn Error>> {
    let owner_id = [1; 32];
    let timeline_id = expected_head_rows
        .first()
        .ok_or("missing expected head row")?
        .timeline_id;
    let plugin_id = PluginId::new();
    let expected_table = LocalCutHeadsTableV1::expected_heads(owner_id, 1, &expected_head_rows)?;
    let result_table = LocalCutHeadsTableV1::result_heads(owner_id, 1, &result_head_rows)?;
    let manifest_binding_table = LocalCutManifestBindingTableV1::new(
        owner_id,
        1,
        vec![LocalCutManifestBindingRowV1 {
            timeline_id,
            scope: hash(2),
            wcs_hash: hash(3),
            msr_hash: hash(4),
            msb_hash: hash(5),
        }],
    )?;
    let composition_table = table(1, 6)?;
    let recording_context_table = table(1, 7)?;
    let seal = LocalCutSealV2::new(LocalCutSealInputV2 {
        owner_id,
        cut_id: 1,
        tick: 1,
        membership_epoch: 0,
        configuration_generation: 1,
        schedule_ns: 0,
        previous_visible_receipt_hash: None,
        expected_inventory_generation: hash(8),
        membership_table: table(1, 9)?,
        composition_table,
        inbox_table: table(0, 10)?,
        invocation_table: table(0, 11)?,
        expected_heads_table: expected_table.table_ref(),
        ebp_native_hash: hash(13),
        execution_profile_native_hash: hash(14),
        recording_context_table,
        owner_operational_policy_hash: hash(15),
        explicit_attempt_hash: None,
        ingress_preallocation_native_hash: hash(16),
        manifest_binding_table: manifest_binding_table.table_ref(),
    })?;
    Ok(LocalCutOwnerRequestV1 {
        operation_id: hash(17),
        seal,
        manifest_hash: hash(18),
        manifest_binding_table,
        composition_rows: vec![LocalCutCompositionBindingRowV1 {
            plugin_id,
            timeline_id,
            plugin_version: "1.0.0".to_owned(),
            implementation_hash: hash(19),
            eop1_native_digest: hash(20),
            driver_interval_ns: Some(0),
            last_due_ns: None,
            event_cursor: 0,
            participant_native_state_hash: hash(21),
        }],
        recording_context_rows: vec![LocalCutRecordingContextRowV1 {
            timeline_id,
            wcs_hash: hash(3),
            retention_lease_hash: hash(22),
            predecessor_wcb_hash: None,
        }],
        expected_head_rows,
        result_head_rows,
        partition_ledger_seq: 1,
        result_heads_table: result_table.table_ref(),
        participant_successor_table: table(1, 24)?,
        cpu_completion_table: table(0, 25)?,
        action_disposition_table: table(1, 26)?,
        candidate_bases_table: table(0, 27)?,
        invocation_bridges_table: table(0, 28)?,
        result_inventory_generation: hash(29),
        release_fence_proof_digest: hash(30),
    })
}

#[test]
fn intent_binds_every_owner_selected_scalar_and_row() -> TestResult {
    let request = request()?;
    let digest = local_cut_owner_intent_digest_v1(&request)?;

    let mut changed_operation = request.clone();
    changed_operation.operation_id = hash(31);
    assert_ne!(
        local_cut_owner_intent_digest_v1(&changed_operation)?,
        digest
    );

    let mut changed_composition = request.clone();
    changed_composition.composition_rows[0].event_cursor = 1;
    assert_ne!(
        local_cut_owner_intent_digest_v1(&changed_composition)?,
        digest
    );

    let mut changed_context = request.clone();
    changed_context.recording_context_rows[0].retention_lease_hash = hash(32);
    assert_ne!(local_cut_owner_intent_digest_v1(&changed_context)?, digest);

    let mut changed_result = request;
    changed_result.release_fence_proof_digest = hash(33);
    assert_ne!(local_cut_owner_intent_digest_v1(&changed_result)?, digest);
    Ok(())
}

#[test]
fn intent_rejects_partial_or_invalid_kind_one_and_kind_eight_rows() -> TestResult {
    let mut missing_composition = request()?;
    missing_composition.composition_rows.clear();
    assert_eq!(
        local_cut_owner_intent_digest_v1(&missing_composition),
        Err(LocalCutOwnerErrorV1::BoundExceeded)
    );

    let mut missing_context = request()?;
    missing_context.recording_context_rows.clear();
    assert_eq!(
        local_cut_owner_intent_digest_v1(&missing_context),
        Err(LocalCutOwnerErrorV1::BoundExceeded)
    );

    let mut invalid_driver = request()?;
    invalid_driver.composition_rows[0].driver_interval_ns = None;
    invalid_driver.composition_rows[0].last_due_ns = Some(1);
    assert_eq!(
        local_cut_owner_intent_digest_v1(&invalid_driver),
        Err(LocalCutOwnerErrorV1::InvalidBatch)
    );

    let mut invalid_context = request()?;
    invalid_context.recording_context_rows[0].predecessor_wcb_hash = Some(Hash::zero());
    assert_eq!(
        local_cut_owner_intent_digest_v1(&invalid_context),
        Err(LocalCutOwnerErrorV1::InvalidBatch)
    );
    Ok(())
}

#[test]
fn intent_proves_kind_four_and_kind_five_rows_against_their_tables() -> TestResult {
    let request = request()?;
    let digest = local_cut_owner_intent_digest_v1(&request)?;
    let timeline_id = request.expected_head_rows[0].timeline_id;

    let mut expected = expected_head(timeline_id);
    expected.predecessor_wcb_hash = Some(hash(36));
    let rebuilt = request_with_heads(vec![expected], vec![result_head(timeline_id)])?;
    assert_ne!(local_cut_owner_intent_digest_v1(&rebuilt)?, digest);
    let mut result = result_head(timeline_id);
    result.successor_wcb_hash = hash(37);
    let rebuilt = request_with_heads(vec![expected_head(timeline_id)], vec![result])?;
    assert_ne!(local_cut_owner_intent_digest_v1(&rebuilt)?, digest);

    let mut unproven_expected = request.clone();
    unproven_expected.expected_head_rows[0].logical_head = 1;
    let mut unproven_result = request.clone();
    unproven_result.result_head_rows[0].event_count = 1;
    let mut missing_expected = request.clone();
    missing_expected.expected_head_rows.clear();
    let mut unsorted_result = request;
    unsorted_result
        .result_head_rows
        .push(result_head(TimelineId::from_ulid(ulid::Ulid::nil())));
    for invalid in [
        unproven_expected,
        unproven_result,
        missing_expected,
        unsorted_result,
    ] {
        assert_eq!(
            local_cut_owner_intent_digest_v1(&invalid),
            Err(LocalCutOwnerErrorV1::InvalidBatch)
        );
    }
    Ok(())
}

#[test]
fn owner_state_requires_one_complete_visible_or_genesis_shape() {
    let timeline_id = TimelineId::new();
    let genesis = LocalCutOwnerStateV1 {
        owner_id: [1; 32],
        last_visible_cut_id: 0,
        last_visible_tick: 0,
        membership_epoch: 0,
        configuration_generation: 1,
        previous_visible_lcq1_hash: None,
        inventory_generation: hash(1),
        timelines: vec![timeline_id],
    };
    assert_eq!(genesis.validate(), Ok(()));

    let visible = LocalCutOwnerStateV1 {
        last_visible_cut_id: 1,
        last_visible_tick: 1,
        previous_visible_lcq1_hash: Some(hash(2)),
        ..genesis.clone()
    };
    assert_eq!(visible.validate(), Ok(()));

    let missing_receipt = LocalCutOwnerStateV1 {
        last_visible_cut_id: 1,
        last_visible_tick: 1,
        ..genesis.clone()
    };
    assert_eq!(
        missing_receipt.validate(),
        Err(LocalCutOwnerErrorV1::CorruptState)
    );

    let repeated_timeline = LocalCutOwnerStateV1 {
        timelines: vec![timeline_id, timeline_id],
        ..genesis
    };
    assert_eq!(
        repeated_timeline.validate(),
        Err(LocalCutOwnerErrorV1::CorruptState)
    );
}

#[test]
fn owner_error_conversions_preserve_retryable_classes() {
    use pos_core::LocalCutOwnerErrorV1 as Local;
    use pos_core::ManifestOwnerAdmissionErrorV1 as Admission;

    for (local, admission) in [
        (Local::Conflict, Admission::Conflict),
        (Local::StorageFailure, Admission::StorageFailure),
        (Local::BoundExceeded, Admission::CorruptState),
        (Local::InvalidBatch, Admission::CorruptState),
        (Local::OwnerRejected, Admission::CorruptState),
        (Local::CorruptState, Admission::CorruptState),
    ] {
        assert_eq!(Admission::from(local), admission);
    }
    for (admission, local) in [
        (Admission::Conflict, Local::Conflict),
        (Admission::StorageFailure, Local::StorageFailure),
        (Admission::BoundExceeded, Local::CorruptState),
        (Admission::InvalidBatch, Local::CorruptState),
        (Admission::OwnerRejected, Local::CorruptState),
        (Admission::CorruptState, Local::CorruptState),
    ] {
        assert_eq!(Local::from(admission), local);
    }
}
