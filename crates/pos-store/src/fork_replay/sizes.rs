//! Allocation-free sizes of the existing canonical Fork records.
//!
//! These measure the accepted encoders' exact bytes, not a new wire format.
//! Public adapter tests compare them with the native encoders before budgeting.

use pos_core::{
    EventOriginRecordV1, ForkAdmissionRecordInputV1, ForkAdmissionRecordV1, ForkAppendOperationV1,
    ForkAppendSourceIdentityV1, ForkClassifierRegistrationV1, ForkClassifierSourceV1,
    ForkClassifierTableV1, ForkExternalInputRouteV1, ForkInterventionAdmissionV1,
    ForkPublicationArtifactV1, ForkPublicationBindingV1, ForkPublicationOperationV1,
    ImportedForkAdmissionRecordV1, ImportedForkPublicationOperationV1,
    ImportedKeyRecordV1, ImportedKeyTombstoneV1, ImportedPrincipalOwnerBindingV1,
    PrincipalOwnerBindingV1,
};

pub(crate) trait CanonicalSizeV1 {
    fn canonical_size(&self) -> usize;
}

/// One preferred CBOR length/integer head, without a payload.
const fn head(value: u64) -> usize {
    match value {
        0..=23 => 1,
        24..=255 => 2,
        256..=65_535 => 3,
        65_536..=4_294_967_295 => 5,
        _ => 9,
    }
}

fn string(length: usize) -> usize {
    head(length as u64) + length
}

/// Four-character marker, version 1 and the definite array head.
const RECORD_HEADER: usize = 7;
const HASH: usize = 34;
const ID: usize = 18;

fn routes(value: &[ForkExternalInputRouteV1]) -> usize {
    head(value.len() as u64) + value.iter()
        .map(|row| 1 + string(row.source().route().len()) + HASH + 1)
        .sum::<usize>()
}

impl CanonicalSizeV1 for ForkAdmissionRecordV1 {
    fn canonical_size(&self) -> usize {
        admission_size(self.input())
    }
}

fn admission_size(value: &ForkAdmissionRecordInputV1) -> usize {
    RECORD_HEADER + 5 * HASH + string(value.creator.as_str().len()) + 2 * ID
        + head(value.parent_logical_head) + head(value.completed_fold_cursor)
        + head(value.post_fold_tick_boundary) + 1 + 2
}

impl CanonicalSizeV1 for ImportedForkAdmissionRecordV1 {
    fn canonical_size(&self) -> usize {
        admission_size(self.fields()) + 34
    }
}

impl CanonicalSizeV1 for PrincipalOwnerBindingV1 {
    fn canonical_size(&self) -> usize {
        RECORD_HEADER + 2 * HASH + string(self.input().owner.as_str().len()) + 2
    }
}

impl CanonicalSizeV1 for ImportedPrincipalOwnerBindingV1 {
    fn canonical_size(&self) -> usize {
        RECORD_HEADER + 2 * HASH + string(self.input().owner.as_str().len()) + 36
    }
}

impl CanonicalSizeV1 for ForkClassifierSourceV1 {
    fn canonical_size(&self) -> usize {
        let value = self.input();
        RECORD_HEADER + HASH + string(value.registrar_identifier.len()) + routes(&value.routes)
    }
}

impl CanonicalSizeV1 for ForkClassifierTableV1 {
    fn canonical_size(&self) -> usize {
        let value = self.input();
        RECORD_HEADER + ID + 3 * HASH + string(value.registrar_identifier.len())
            + routes(&value.routes)
    }
}

impl CanonicalSizeV1 for ForkClassifierRegistrationV1 {
    fn canonical_size(&self) -> usize {
        RECORD_HEADER + ID + 4 * HASH
    }
}

impl CanonicalSizeV1 for EventOriginRecordV1 {
    fn canonical_size(&self) -> usize {
        RECORD_HEADER + 2 * ID + head(self.input().logical_seq) + 2 + 2 * HASH
    }
}

impl CanonicalSizeV1 for ForkInterventionAdmissionV1 {
    fn canonical_size(&self) -> usize {
        RECORD_HEADER + 2 * ID + head(self.input().logical_seq) + 5 * HASH
    }
}

impl CanonicalSizeV1 for ForkAppendOperationV1 {
    fn canonical_size(&self) -> usize {
        let value = self.input();
        let source = match &value.source {
            ForkAppendSourceIdentityV1::HostInternal => 2,
            ForkAppendSourceIdentityV1::ExternalInput { adapter_identifier, source } => {
                2 + string(adapter_identifier.len()) + string(source.route().len()) + HASH
            }
        };
        RECORD_HEADER + 2 * ID + head(value.logical_seq) + head(value.wall_time.as_micros())
            + 6 * HASH + source + value.intervention_admission_digest.map_or(1, |_| HASH)
    }
}

impl CanonicalSizeV1 for ForkPublicationOperationV1 {
    fn canonical_size(&self) -> usize {
        let value = self.input();
        RECORD_HEADER + ID + head(value.final_logical_head) + 6 * HASH
            + string(value.signing_identity.owner_id.as_str().len()) + 1
            + head(value.signing_identity.epoch) + 2
    }
}

impl CanonicalSizeV1 for ImportedForkPublicationOperationV1 {
    fn canonical_size(&self) -> usize {
        self.projection().canonical_size() + 34
    }
}

impl CanonicalSizeV1 for ImportedKeyRecordV1 {
    fn canonical_size(&self) -> usize {
        let identity = self.identity();
        RECORD_HEADER + string(identity.owner_id.as_str().len()) + 1 + head(identity.epoch)
            + self.private_material_digest().map_or(1, |_| HASH) + HASH
    }
}

impl CanonicalSizeV1 for ImportedKeyTombstoneV1 {
    fn canonical_size(&self) -> usize {
        let identity = self.identity();
        RECORD_HEADER + string(identity.owner_id.as_str().len()) + 1 + head(identity.epoch)
            + 3 * HASH
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::fae1_fixture::{Fallible, Shape, Spec, World};
    use pos_core::{ForkAttributionImportClosureV1, ForkPublicationOperationV1};

    #[test]
    fn sizes_match_native_encoders_across_imported_record_kinds() -> Fallible<()> {
        let world = World::new(Shape::Mixed, false)?;
        let built = world.build(&Spec::default())?;
        let closure = ForkAttributionImportClosureV1::validate(&built.envelope)?;
        let graph = closure.classifier().ok_or("missing classifier fixture")?;
        let sizes = [
            (closure.principal_owner_binding().canonical_size(), closure.principal_owner_binding().to_canonical_cbor().len()),
            (closure.fork_admission().canonical_size(), closure.fork_admission().to_canonical_cbor().len()),
            (graph.source.canonical_size(), graph.source.to_canonical_cbor().len()),
            (graph.table.canonical_size(), graph.table.to_canonical_cbor().len()),
            (graph.registration.canonical_size(), graph.registration.to_canonical_cbor().len()),
            (closure.publication_operation().canonical_size(), closure.publication_operation().to_canonical_cbor().len()),
            (closure.publication_binding().canonical_size(), closure.publication_binding().to_canonical_cbor().len()),
            (closure.publication_artifact().canonical_size(), closure.publication_artifact().to_canonical_cbor().len()),
        ];
        for (size, actual) in sizes {
            assert_eq!(size, actual);
        }
        for record in closure.append_operations() {
            assert_eq!(record.canonical_size(), record.to_canonical_cbor().len());
        }
        for record in closure.event_origins() {
            assert_eq!(record.canonical_size(), record.to_canonical_cbor().len());
        }
        for record in closure.intervention_admissions() {
            assert_eq!(record.canonical_size(), record.to_canonical_cbor().len());
        }
        let operation = closure.publication_operation().projection();
        for value in [0, 23, 24, 255, 256, 65_535, 65_536, u64::from(u32::MAX), u64::from(u32::MAX) + 1, u64::MAX] {
            let mut input = operation.input().clone();
            input.final_logical_head = value;
            let record = ForkPublicationOperationV1::new(input)?;
            assert_eq!(record.canonical_size(), record.to_canonical_cbor().len());
        }
        Ok(())
    }
}

impl CanonicalSizeV1 for ForkPublicationBindingV1 {
    fn canonical_size(&self) -> usize {
        RECORD_HEADER + ID + head(self.input().final_logical_head) + 2 * HASH
    }
}

impl CanonicalSizeV1 for ForkPublicationArtifactV1 {
    fn canonical_size(&self) -> usize {
        RECORD_HEADER + 2 * HASH + string(self.input().signed_manifest_bytes.len())
    }
}
