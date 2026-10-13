//! Allocation gates for the existing local and code-2 FAR1 decoders.
//!
//! Borrowed carriers identify only bounded allocation units; Core remains
//! the sole validator of native fields, origin, semantics and canonical bytes.

use pos_core::{
    ForkAdmissionRecordV1, ImportedForkAdmissionRecordV1,
    MAX_FORK_ADMISSION_RECORD_BYTES_V1,
};

use super::{imported_projection_length, AdmissionCarrierV1, NativeReadContextV1};
use crate::ForkManifestPublicationErrorV1 as Error;

type Result<T> = std::result::Result<T, Error>;

const CREATOR_FIELD: u64 = 4;
const TEXT_MAJOR: u8 = 3;
const OWNER_MAX_BYTES: usize = 128;

impl NativeReadContextV1<'_, '_> {
    fn admission_creator(&mut self, bytes: &[u8]) -> Result<()> {
        let creator = AdmissionCarrierV1::field(bytes, CREATOR_FIELD, TEXT_MAJOR)
            .filter(|value| value.len() <= OWNER_MAX_BYTES)
            .ok_or(Error::PublicationConflict)?;
        self.bytes(creator.len())
    }

    pub(crate) fn local_admission_record(&mut self, bytes: &[u8]) -> Result<ForkAdmissionRecordV1> {
        self.check()?;
        if self.budget.is_some() {
            if bytes.len() > MAX_FORK_ADMISSION_RECORD_BYTES_V1 {
                return Err(Error::PublicationConflict);
            }
            self.admission_creator(bytes)?;
            // A recognized code-2 tail rejects the local origin before Core
            // creates its equality buffer. Do not charge a phantom encoding.
            if imported_projection_length(bytes).is_none() {
                self.bytes(bytes.len())?;
            }
        }
        let record = ForkAdmissionRecordV1::from_canonical_cbor(bytes)
            .map_err(|_| Error::PublicationConflict);
        self.check()?;
        record
    }

    pub(crate) fn imported_admission_record(
        &mut self,
        bytes: &[u8],
    ) -> Result<ImportedForkAdmissionRecordV1> {
        self.check()?;
        if self.budget.is_some() {
            if bytes.len() > MAX_FORK_ADMISSION_RECORD_BYTES_V1 {
                return Err(Error::PublicationConflict);
            }
            if let Some(length) = imported_projection_length(bytes) {
                self.bytes(length)?; // Core's actual local-projection Vec.
                self.admission_creator(bytes)?; // Temporary creator String.
                self.bytes(length)?; // Local decoder's equality Vec.
            } else {
                // Erratum E9 runs the local decoder on the original input to
                // distinguish a valid local record from invalid encoding.
                self.admission_creator(bytes)?;
                self.bytes(bytes.len())?;
            }
        }
        let record = ImportedForkAdmissionRecordV1::from_canonical_cbor(bytes)
            .map_err(|_| Error::PublicationConflict);
        self.check()?;
        record
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::{
        fae1_fixture::{Fallible, Shape, Spec, World},
        ForkReplayReadBudgetV1, ForkReplayReadLimitsV1,
    };
    use pos_core::trusted_clock::{GuardMonotonicSourceV1, ScriptedGuardMonotonicSourceV1};
    use std::time::Duration;

    #[derive(Clone, Copy)]
    enum Codec { Local, Imported }

    impl Codec {
        fn accepts(self, bytes: &[u8]) -> bool {
            match self {
                Self::Local => ForkAdmissionRecordV1::from_canonical_cbor(bytes).is_ok(),
                Self::Imported => ImportedForkAdmissionRecordV1::from_canonical_cbor(bytes).is_ok(),
            }
        }

        fn decode(self, bytes: &[u8], context: &mut NativeReadContextV1<'_, '_>) -> Result<()> {
            match self {
                Self::Local => context.local_admission_record(bytes).map(|_| ()),
                Self::Imported => context.imported_admission_record(bytes).map(|_| ()),
            }
        }
    }

    fn records() -> Fallible<(ForkAdmissionRecordV1, ImportedForkAdmissionRecordV1)> {
        let world = World::new(Shape::Mixed, false)?;
        let built = world.build(&Spec::default())?;
        let imported = ImportedForkAdmissionRecordV1::from_canonical_cbor(
            &built.envelope.unsigned().input().records.fork_admission)?;
        let mut fields = imported.fields().clone();
        fields.creator = pos_core::OwnerIdV1::new("é".repeat(64))?;
        let local = ForkAdmissionRecordV1::new(fields)?;
        let imported = ImportedForkAdmissionRecordV1::from_local(local.clone(), imported.authority_origin_digest());
        Ok((local, imported))
    }

    fn assert_parity(codec: Codec, bytes: &[u8]) -> Fallible<()> {
        assert_eq!(codec.decode(bytes, &mut NativeReadContextV1::ordinary()).is_ok(), codec.accepts(bytes));
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(1, 1, 1, 8_192, 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        assert_eq!(codec.decode(bytes, &mut NativeReadContextV1::protected(&mut budget)).is_ok(), codec.accepts(bytes));
        assert!(budget.check_time().is_ok());
        Ok(())
    }

    #[test]
    fn admission_carriers_preserve_each_strict_native_decoder_on_current_bytes() -> Fallible<()> {
        let (local, imported) = records()?;
        for bytes in [local.to_canonical_cbor(), imported.to_canonical_cbor()] {
            for codec in [Codec::Local, Codec::Imported] {
                assert_parity(codec, &bytes)?;
                for end in 0..bytes.len() { assert_parity(codec, &bytes[..end])?; }
                for index in 0..bytes.len() {
                    for replacement in [0, 255] {
                        let mut changed = bytes.clone();
                        changed[index] = replacement;
                        assert_parity(codec, &changed)?;
                    }
                }
                let mut trailing = bytes.clone();
                trailing.push(0);
                assert_parity(codec, &trailing)?;
                let mut oversized = bytes.clone();
                oversized.resize(MAX_FORK_ADMISSION_RECORD_BYTES_V1 + 1, 0);
                assert_parity(codec, &oversized)?;
            }
        }
        Ok(())
    }

    #[test]
    fn admission_decoders_charge_owner_and_actual_projection_equality_buffers() -> Fallible<()> {
        let (local, imported) = records()?;
        let local_bytes = local.to_canonical_cbor();
        let imported_bytes = imported.to_canonical_cbor();
        let owner = local.input().creator.as_str().len();
        for (codec, bytes, expected) in [
            (Codec::Local, local_bytes.clone(), owner + local_bytes.len()),
            (Codec::Imported, imported_bytes.clone(), owner + local_bytes.len() * 2),
        ] {
            for limit in 1..=expected {
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, 1, limit, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                let result = codec.decode(&bytes, &mut NativeReadContextV1::protected(&mut budget));
                if limit == expected {
                    result?;
                    assert_eq!(budget.remaining_native_bytes(), 0);
                } else {
                    assert_eq!(result, Err(Error::PublicationConflict));
                    assert!(budget.check_time().is_err());
                }
            }
        }
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(1, 1, 1, owner, 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        assert_eq!(NativeReadContextV1::protected(&mut budget).local_admission_record(&imported_bytes),
            Err(Error::PublicationConflict));
        assert_eq!(budget.remaining_native_bytes(), 0);
        assert!(budget.check_time().is_ok(), "native origin rejection is not a fictitious equality debit");
        Ok(())
    }
}
