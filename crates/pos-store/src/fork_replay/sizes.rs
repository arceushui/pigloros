//! Private adapter dispatch to the native owners' checked length methods.
//!
//! There is no second CBOR schema or scalar size model in this module.

use super::CanonicalSizeV1;

macro_rules! native_lengths {
    ($($record:ty),+ $(,)?) => {
        $(impl CanonicalSizeV1 for $record {
            fn canonical_size(&self) -> Result<usize, pos_core::CanonicalLengthErrorV1> {
                self.canonical_cbor_len()
            }
        })+
    };
}

native_lengths!(
    pos_core::ForkAdmissionRecordV1,
    pos_core::ImportedForkAdmissionRecordV1,
    pos_core::PrincipalOwnerBindingV1,
    pos_core::ForkClassifierSourceV1,
    pos_core::ForkClassifierTableV1,
    pos_core::ForkClassifierRegistrationV1,
    pos_core::EventOriginRecordV1,
    pos_core::ForkInterventionAdmissionV1,
    pos_core::ForkAppendOperationV1,
    pos_core::ForkPublicationOperationV1,
    pos_core::ImportedForkPublicationOperationV1,
    pos_core::ImportedKeyRecordV1,
    pos_core::ImportedKeyTombstoneV1,
    pos_core::ForkPublicationBindingV1,
    pos_core::ForkPublicationArtifactV1,
);
