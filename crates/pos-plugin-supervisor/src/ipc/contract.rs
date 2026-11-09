//! Canonical CBOR of the guest contract types (ADR-061 `contract-v1`).
//!
//! Every record is an array of its fields in WIT order. `list<u8>`, including
//! `digest32` and the 16-byte IDs, is a byte string, and `bounded-text` is
//! text. A variant is `[case, payload]`, or `[case]` without a payload, and an
//! `option` is `null` or its value. The decoder enforces each WIT count bound;
//! semantic validation stays with the engine and the supervisor.

use pos_runtime::community_plugin_host::{
    ArtifactRefV1, EventDraftV1, FieldRefV1, GuestPluginErrorV1, MeteringV1, OperationalLogRecord,
    PluginDescriptorV1, PluginErrorCodeV1, PluginInvocationV1, PluginOutputV1, TimelinePositionV1,
    TraceAnnotationV1, MAX_OBSERVATION_BYTES_V1, MAX_STATE_BYTES_V1, MAX_TRACE_ANNOTATION_BYTES_V1,
};

use super::wire::{
    read_bytes, read_code, read_digests, read_list, read_text, read_u16, read_u32, Decoded,
    EnvelopeReader, Writer,
};
use super::{WorkerEnvelopeErrorV1, MAX_TEXT_BYTES};

/// WIT bound on one operational log message, in bytes.
const MAX_LOG_MESSAGE_BYTES: usize = 256;
/// WIT bound on `record-operational-log` calls.
const MAX_LOG_CALLS: usize = 64;
/// WIT bound on `EventDrafts` and on trace annotations.
const MAX_RECORDS: usize = 1_024;
/// WIT bound on dependency digests.
const MAX_DIGESTS: usize = 4_096;
/// WIT bound on descriptor lists: features and event schema digests.
const MAX_DESCRIPTOR_ITEMS: usize = 256;
/// PMF1 V1 bound on all `EventDraft` bytes (`event_bytes`).
const MAX_EVENT_PAYLOAD_BYTES: usize = 16_777_216;
/// WIT bound on a `canonical-coordinate`, in bytes.
const MAX_COORDINATE_BYTES: usize = 128;
/// Number of `plugin-error-code` cases.
const ERROR_CASES: usize = 8;

pub(super) fn write_invocation(writer: &mut Writer, invocation: &PluginInvocationV1) {
    let position = &invocation.timeline_position;
    writer.array(14).bytes(&invocation.invocation_id);
    writer
        .array(4)
        .bytes(&position.timeline_id)
        .unsigned(position.seq)
        .unsigned(position.tick)
        .unsigned(u64::from(position.scheduler_position));
    writer.unsigned(u64::from(invocation.output_base_ordinal));
    for artifact in [
        &invocation.principal_ref,
        &invocation.authorization_decision,
        &invocation.observation_snapshot,
    ] {
        writer
            .array(3)
            .unsigned(u64::from(artifact.schema_id))
            .unsigned(artifact.byte_length)
            .bytes(&artifact.digest);
    }
    writer
        .bytes(&invocation.observation_bytes)
        .bytes(&invocation.prior_state_schema)
        .bytes(&invocation.prior_state_bytes)
        .bytes(&invocation.execution_profile_digest)
        .bytes(&invocation.trust_policy_snapshot_digest)
        .text(&invocation.deterministic_budget_id)
        .bytes(&invocation.deterministic_random_domain)
        .bytes(&invocation.provenance_root);
}

pub(super) fn read_invocation(reader: &mut EnvelopeReader<'_>) -> Decoded<PluginInvocationV1> {
    reader.fixed_array(14)?;
    let invocation_id = reader.bytes()?;
    reader.fixed_array(4)?;
    let timeline_position = TimelinePositionV1 {
        timeline_id: reader.bytes()?,
        seq: reader.unsigned()?,
        tick: reader.unsigned()?,
        scheduler_position: read_u32(reader)?,
    };
    Ok(PluginInvocationV1 {
        invocation_id,
        timeline_position,
        output_base_ordinal: read_u32(reader)?,
        principal_ref: read_artifact(reader)?,
        authorization_decision: read_artifact(reader)?,
        observation_snapshot: read_artifact(reader)?,
        observation_bytes: read_bytes(reader, MAX_OBSERVATION_BYTES_V1)?,
        prior_state_schema: reader.bytes()?,
        prior_state_bytes: read_bytes(reader, MAX_STATE_BYTES_V1)?,
        execution_profile_digest: reader.bytes()?,
        trust_policy_snapshot_digest: reader.bytes()?,
        deterministic_budget_id: read_text(reader, MAX_TEXT_BYTES)?,
        deterministic_random_domain: reader.bytes()?,
        provenance_root: reader.bytes()?,
    })
}

fn read_artifact(reader: &mut EnvelopeReader<'_>) -> Decoded<ArtifactRefV1> {
    reader.fixed_array(3)?;
    Ok(ArtifactRefV1 {
        schema_id: read_u32(reader)?,
        byte_length: reader.unsigned()?,
        digest: reader.bytes()?,
    })
}

pub(super) fn write_descriptor(writer: &mut Writer, descriptor: &PluginDescriptorV1) {
    writer
        .array(11)
        .text(&descriptor.plugin_id)
        .text(&descriptor.release_semver)
        .text(&descriptor.world)
        .unsigned(u64::from(descriptor.abi_major))
        .unsigned(u64::from(descriptor.min_abi_minor))
        .unsigned(u64::from(descriptor.max_abi_minor))
        .list(&descriptor.required_features, |writer, feature| {
            writer.text(feature);
        })
        .digests(&descriptor.event_schema_digests)
        .bytes(&descriptor.state_schema_digest)
        .bytes(&descriptor.manifest_digest)
        .bytes(&descriptor.release_digest);
}

pub(super) fn read_descriptor(reader: &mut EnvelopeReader<'_>) -> Decoded<PluginDescriptorV1> {
    reader.fixed_array(11)?;
    Ok(PluginDescriptorV1 {
        plugin_id: read_text(reader, MAX_TEXT_BYTES)?,
        release_semver: read_text(reader, MAX_TEXT_BYTES)?,
        world: read_text(reader, MAX_TEXT_BYTES)?,
        abi_major: read_u16(reader)?,
        min_abi_minor: read_u16(reader)?,
        max_abi_minor: read_u16(reader)?,
        required_features: read_list(reader, MAX_DESCRIPTOR_ITEMS, |reader| {
            read_text(reader, MAX_TEXT_BYTES)
        })?,
        event_schema_digests: read_digests(reader, MAX_DESCRIPTOR_ITEMS)?,
        state_schema_digest: reader.bytes()?,
        manifest_digest: reader.bytes()?,
        release_digest: reader.bytes()?,
    })
}

pub(super) fn write_output(writer: &mut Writer, output: &PluginOutputV1) {
    writer
        .array(7)
        .bytes(&output.invocation_id)
        .list(&output.event_drafts, |writer, draft| {
            writer
                .array(5)
                .unsigned(u64::from(draft.event_schema_id))
                .bytes(&draft.entity_id)
                .text(&draft.event_type)
                .bytes(&draft.canonical_payload)
                .digests(&draft.dependency_digests);
        })
        .bytes(&output.next_state_schema)
        .bytes(&output.next_state_bytes)
        .list(&output.trace_annotations, |writer, annotation| {
            writer
                .array(3)
                .unsigned(u64::from(annotation.annotation_schema_id))
                .bytes(&annotation.canonical_bytes)
                .digests(&annotation.dependency_digests);
        })
        .digests(&output.consumed_dependencies)
        .bytes(&output.output_digest);
}

pub(super) fn read_output(reader: &mut EnvelopeReader<'_>) -> Decoded<PluginOutputV1> {
    reader.fixed_array(7)?;
    Ok(PluginOutputV1 {
        invocation_id: reader.bytes()?,
        event_drafts: read_list(reader, MAX_RECORDS, read_draft)?,
        next_state_schema: reader.bytes()?,
        next_state_bytes: read_bytes(reader, MAX_STATE_BYTES_V1)?,
        trace_annotations: read_list(reader, MAX_RECORDS, read_annotation)?,
        consumed_dependencies: read_digests(reader, MAX_DIGESTS)?,
        output_digest: reader.bytes()?,
    })
}

fn read_draft(reader: &mut EnvelopeReader<'_>) -> Decoded<EventDraftV1> {
    reader.fixed_array(5)?;
    Ok(EventDraftV1 {
        event_schema_id: read_u32(reader)?,
        entity_id: reader.bytes()?,
        event_type: read_text(reader, MAX_TEXT_BYTES)?,
        canonical_payload: read_bytes(reader, MAX_EVENT_PAYLOAD_BYTES)?,
        dependency_digests: read_digests(reader, MAX_DIGESTS)?,
    })
}

fn read_annotation(reader: &mut EnvelopeReader<'_>) -> Decoded<TraceAnnotationV1> {
    reader.fixed_array(3)?;
    Ok(TraceAnnotationV1 {
        annotation_schema_id: read_u32(reader)?,
        canonical_bytes: read_bytes(reader, MAX_TRACE_ANNOTATION_BYTES_V1)?,
        dependency_digests: read_digests(reader, MAX_DIGESTS)?,
    })
}

pub(super) fn write_guest_error(writer: &mut Writer, error: &GuestPluginErrorV1) {
    writer.array(3);
    write_error_code(writer, &error.code);
    match &error.canonical_coordinate {
        Some(coordinate) => writer.bytes(coordinate),
        None => writer.null(),
    };
    match &error.related_digest {
        Some(digest) => writer.bytes(digest),
        None => writer.null(),
    };
}

fn write_error_code(writer: &mut Writer, code: &PluginErrorCodeV1) {
    let field = |writer: &mut Writer, case: u64, field: &FieldRefV1| {
        writer
            .array(2)
            .unsigned(case)
            .array(2)
            .unsigned(u64::from(field.schema_id))
            .unsigned(u64::from(field.field_ordinal));
    };
    match code {
        PluginErrorCodeV1::InvalidInvocation(at) => field(writer, 0, at),
        PluginErrorCodeV1::UnsupportedSchema(schema) => {
            writer.array(2).unsigned(1).unsigned(u64::from(*schema));
        }
        PluginErrorCodeV1::CapabilityRequired(capability) => {
            writer.array(2).unsigned(2).text(capability);
        }
        PluginErrorCodeV1::DependencyMissing(digest) => {
            writer.array(2).unsigned(3).bytes(digest);
        }
        PluginErrorCodeV1::DeterministicBudgetExhausted => {
            writer.array(1).unsigned(4);
        }
        PluginErrorCodeV1::InvalidState(at) => field(writer, 5, at),
        PluginErrorCodeV1::MigrationRejected(at) => field(writer, 6, at),
        PluginErrorCodeV1::GuestDeclaredFailure(code) => {
            writer.array(2).unsigned(7).unsigned(u64::from(*code));
        }
    }
}

pub(super) fn read_guest_error(reader: &mut EnvelopeReader<'_>) -> Decoded<GuestPluginErrorV1> {
    reader.fixed_array(3)?;
    let code = read_error_code(reader)?;
    let canonical_coordinate = if reader.null() {
        None
    } else {
        Some(read_bytes(reader, MAX_COORDINATE_BYTES)?)
    };
    Ok(GuestPluginErrorV1 {
        code,
        canonical_coordinate,
        related_digest: reader.optional_bytes()?,
    })
}

fn read_error_code(reader: &mut EnvelopeReader<'_>) -> Decoded<PluginErrorCodeV1> {
    let members = reader.array(2)?;
    let case = read_code(reader, ERROR_CASES)?;
    let unit = case == 4;
    if members != if unit { 1 } else { 2 } {
        return Err(WorkerEnvelopeErrorV1);
    }
    Ok(match case {
        0 => PluginErrorCodeV1::InvalidInvocation(read_field(reader)?),
        1 => PluginErrorCodeV1::UnsupportedSchema(read_u32(reader)?),
        2 => PluginErrorCodeV1::CapabilityRequired(read_text(reader, MAX_TEXT_BYTES)?),
        3 => PluginErrorCodeV1::DependencyMissing(reader.bytes()?),
        4 => PluginErrorCodeV1::DeterministicBudgetExhausted,
        5 => PluginErrorCodeV1::InvalidState(read_field(reader)?),
        6 => PluginErrorCodeV1::MigrationRejected(read_field(reader)?),
        _ => PluginErrorCodeV1::GuestDeclaredFailure(read_u16(reader)?),
    })
}

fn read_field(reader: &mut EnvelopeReader<'_>) -> Decoded<FieldRefV1> {
    reader.fixed_array(2)?;
    Ok(FieldRefV1 {
        schema_id: read_u32(reader)?,
        field_ordinal: read_u16(reader)?,
    })
}

pub(super) fn write_metering(writer: &mut Writer, metering: &MeteringV1) {
    writer
        .array(4)
        .unsigned(metering.startup_fuel)
        .unsigned(metering.call_fuel)
        .unsigned(metering.memory_bytes)
        .unsigned(metering.host_calls);
}

pub(super) fn read_metering(reader: &mut EnvelopeReader<'_>) -> Decoded<MeteringV1> {
    reader.fixed_array(4)?;
    Ok(MeteringV1 {
        startup_fuel: reader.unsigned()?,
        call_fuel: reader.unsigned()?,
        memory_bytes: reader.unsigned()?,
        host_calls: reader.unsigned()?,
    })
}

pub(super) fn write_log(writer: &mut Writer, log: &[OperationalLogRecord]) {
    writer.list(log, |writer, record| {
        writer
            .array(2)
            .unsigned(u64::from(record.category))
            .text(&record.message);
    });
}

pub(super) fn read_log(reader: &mut EnvelopeReader<'_>) -> Decoded<Vec<OperationalLogRecord>> {
    read_list(reader, MAX_LOG_CALLS, |reader| {
        reader.fixed_array(2)?;
        Ok(OperationalLogRecord {
            category: read_u16(reader)?,
            message: read_text(reader, MAX_LOG_MESSAGE_BYTES)?,
        })
    })
}
