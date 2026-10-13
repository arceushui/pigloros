//! Allocation gates for existing FAH1, local POB1 and local/code-2 FAR1 decoders.
//!
//! Borrowed carriers identify only bounded allocation units; Core remains
//! the sole validator of native fields, origin, semantics and canonical bytes.

use pos_core::{
    ForkAdmissionRecordV1, ImportedForkAdmissionRecordV1, PrincipalOwnerBindingV1,
    MAX_FORK_ADMISSION_RECORD_BYTES_V1, MAX_PRINCIPAL_OWNER_BINDING_BYTES_V1,
};

use super::{imported_projection_length, AdmissionCarrierV1, NativeReadContextV1};
use crate::ForkManifestPublicationErrorV1 as Error;

type Result<T> = std::result::Result<T, Error>;

const CREATOR_FIELD: u64 = 4;
const BINDING_OWNER_FIELD: u64 = 4;
const TEXT_MAJOR: u8 = 3;
const OWNER_MAX_BYTES: usize = 128;

impl NativeReadContextV1<'_, '_> {
    pub(crate) fn host_record(&mut self, bytes: &[u8]) -> Result<pos_core::ForkAdmissionHostRecordV1> {
        const PREFIX: [u8; 7] = [0x85, 0x64, b'F', b'A', b'H', b'1', 0x01];
        const HASH_HEAD: [u8; 2] = [0x58, 0x20];
        self.check().and_then(|()| {
            // Only this exact transport reaches Core's allocation-free FAH1
            // path. Core still validates all three native nonzero fields.
            if self.is_protected()
                && (bytes.len() != pos_core::MAX_FORK_ADMISSION_HOST_RECORD_BYTES_V1
                    || bytes[..PREFIX.len()] != PREFIX
                    || [7, 41, 75]
                        .iter()
                        .any(|offset| bytes[*offset..*offset + HASH_HEAD.len()] != HASH_HEAD))
            {
                return Err(Error::PublicationConflict);
            }
            let host = pos_core::ForkAdmissionHostRecordV1::from_canonical_cbor(bytes)
                .map_err(|_| Error::PublicationConflict);
            self.check().and(host)
        })
    }

    pub(crate) fn local_principal_binding(
        &mut self,
        bytes: &[u8],
    ) -> Result<PrincipalOwnerBindingV1> {
        self.check()?;
        if self.budget.is_some() {
            if bytes.len() > MAX_PRINCIPAL_OWNER_BINDING_BYTES_V1 {
                return Err(Error::PublicationConflict);
            }
            let owner = AdmissionCarrierV1::field(bytes, BINDING_OWNER_FIELD, TEXT_MAJOR)
                .filter(|value| value.len() <= OWNER_MAX_BYTES)
                .ok_or(Error::PublicationConflict)?;
            self.bytes(owner.len())?;
            // The borrowed native POB1 decoder rejects a code-2 origin before
            // creating its equality Vec. No projection is built by this local
            // decoder; its temporary Owner String is still a real allocation.
            if imported_projection_length(bytes).is_none() {
                self.bytes(bytes.len())?;
            }
        }
        let binding = PrincipalOwnerBindingV1::from_canonical_cbor(bytes)
            .map_err(|_| Error::PublicationConflict);
        self.check()?;
        binding
    }

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
    enum Codec {
        Local,
        Imported,
    }

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
            &built.envelope.unsigned().input().records.fork_admission,
        )?;
        let mut fields = imported.fields().clone();
        fields.creator = pos_core::OwnerIdV1::new("é".repeat(64))?;
        let local = ForkAdmissionRecordV1::new(fields)?;
        let imported = ImportedForkAdmissionRecordV1::from_local(
            local.clone(),
            imported.authority_origin_digest(),
        );
        Ok((local, imported))
    }

    fn assert_parity(codec: Codec, bytes: &[u8]) -> Fallible<()> {
        assert_eq!(
            codec
                .decode(bytes, &mut NativeReadContextV1::ordinary())
                .is_ok(),
            codec.accepts(bytes)
        );
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(1, 1, 1, 8_192, 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        assert_eq!(
            codec
                .decode(bytes, &mut NativeReadContextV1::protected(&mut budget))
                .is_ok(),
            codec.accepts(bytes)
        );
        assert!(budget.check_time().is_ok());
        Ok(())
    }

    #[test]
    fn admission_carriers_preserve_each_strict_native_decoder_on_current_bytes() -> Fallible<()> {
        let (local, imported) = records()?;
        for bytes in [local.to_canonical_cbor(), imported.to_canonical_cbor()] {
            for codec in [Codec::Local, Codec::Imported] {
                assert_parity(codec, &bytes)?;
                for end in 0..bytes.len() {
                    assert_parity(codec, &bytes[..end])?;
                }
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
    fn principal_binding_carrier_preserves_native_local_rejection_and_allocation_units(
    ) -> Fallible<()> {
        use pos_core::{
            Hash, ImportedPrincipalOwnerBindingV1, OwnerIdV1, PrincipalOwnerBindingInputV1,
        };
        for owner in ["owner".to_owned(), "é".repeat(64)] {
            let binding = PrincipalOwnerBindingV1::new(PrincipalOwnerBindingInputV1 {
                operation_id: Hash::from_bytes([1; 32]),
                principal_digest: Hash::from_bytes([2; 32]),
                owner: OwnerIdV1::new(owner)?,
                origin: pos_core::ForkAuthorityOriginV1::Local,
            })?;
            let bytes = binding.to_canonical_cbor();
            let expected = bytes.len() + binding.input().owner.as_str().len();
            for limit in 1..=expected {
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, 1, limit, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                let result =
                    NativeReadContextV1::protected(&mut budget).local_principal_binding(&bytes);
                if limit == expected {
                    assert_eq!(result?, binding);
                    assert_eq!(budget.remaining_native_bytes(), 0);
                } else {
                    assert_eq!(result, Err(Error::PublicationConflict));
                    assert!(budget.check_time().is_err());
                }
            }
            let imported = ImportedPrincipalOwnerBindingV1::from_local(
                binding.clone(),
                Hash::from_bytes([3; 32]),
            )
            .to_canonical_cbor();
            let mut cases = vec![bytes.clone(), imported];
            cases.extend((0..bytes.len()).map(|end| bytes[..end].to_vec()));
            for index in 0..bytes.len() {
                for replacement in [0, 255] {
                    let mut changed = bytes.clone();
                    changed[index] = replacement;
                    cases.push(changed);
                }
            }
            let mut trailing = bytes.clone();
            trailing.push(0);
            cases.push(trailing);
            let mut oversized = bytes;
            oversized.resize(MAX_PRINCIPAL_OWNER_BINDING_BYTES_V1 + 1, 0);
            cases.push(oversized);
            for bytes in cases {
                let native = PrincipalOwnerBindingV1::from_canonical_cbor(&bytes).is_ok();
                assert_eq!(
                    NativeReadContextV1::ordinary()
                        .local_principal_binding(&bytes)
                        .is_ok(),
                    native
                );
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, 1, 1_024, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                assert_eq!(
                    NativeReadContextV1::protected(&mut budget)
                        .local_principal_binding(&bytes)
                        .is_ok(),
                    native
                );
                assert!(budget.check_time().is_ok());
            }
        }
        Ok(())
    }

    #[test]
    fn local_principal_binding_does_not_charge_a_code_two_equality_buffer() -> Fallible<()> {
        let binding = PrincipalOwnerBindingV1::new(pos_core::PrincipalOwnerBindingInputV1 {
            operation_id: pos_core::Hash::from_bytes([1; 32]),
            principal_digest: pos_core::Hash::from_bytes([2; 32]),
            owner: pos_core::OwnerIdV1::new("owner")?,
            origin: pos_core::ForkAuthorityOriginV1::Local,
        })?;
        let bytes = pos_core::ImportedPrincipalOwnerBindingV1::from_local(
            binding,
            pos_core::Hash::from_bytes([3; 32]),
        )
        .to_canonical_cbor();
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(1, 1, 1, "owner".len(), 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        assert_eq!(
            NativeReadContextV1::protected(&mut budget).local_principal_binding(&bytes),
            Err(Error::PublicationConflict)
        );
        assert_eq!(budget.remaining_native_bytes(), 0);
        assert!(budget.check_time().is_ok());
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
            (
                Codec::Imported,
                imported_bytes.clone(),
                owner + local_bytes.len() * 2,
            ),
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
        assert_eq!(
            NativeReadContextV1::protected(&mut budget).local_admission_record(&imported_bytes),
            Err(Error::PublicationConflict)
        );
        assert_eq!(budget.remaining_native_bytes(), 0);
        assert!(
            budget.check_time().is_ok(),
            "native origin rejection is not a fictitious equality debit"
        );
        Ok(())
    }
}
