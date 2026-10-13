//! Allocation gates for the existing verification-only imported-key decoders.

use pos_core::{
    ImportedKeyRecordV1, ImportedKeyTombstoneV1, MAX_IMPORTED_KEY_RECORD_BYTES_V1,
    MAX_IMPORTED_KEY_TOMBSTONE_BYTES_V1,
};

use super::{AdmissionCarrierV1, NativeReadContextV1};
use crate::ForkManifestPublicationErrorV1 as Error;

type Result<T> = std::result::Result<T, Error>;

const OWNER_FIELD: u64 = 2;
const TEXT_MAJOR: u8 = 3;
const OWNER_MAX_BYTES: usize = 128;

impl NativeReadContextV1<'_, '_> {
    fn imported_key_allocations(&mut self, bytes: &[u8], maximum: usize) -> Result<()> {
        if self.budget.is_some() {
            if bytes.len() > maximum {
                return Err(Error::PublicationConflict);
            }
            let owner = AdmissionCarrierV1::field(bytes, OWNER_FIELD, TEXT_MAJOR)
                .filter(|value| value.len() <= OWNER_MAX_BYTES)
                .ok_or(Error::PublicationConflict)?;
            // Reader::owner constructs a temporary String before OwnerIdV1.
            self.bytes(owner.len())?;
            // Each existing decoder creates one canonical comparison Vec.
            self.bytes(bytes.len())?;
        }
        Ok(())
    }

    pub(crate) fn imported_key_record(&mut self, bytes: &[u8]) -> Result<ImportedKeyRecordV1> {
        self.check()?;
        self.imported_key_allocations(bytes, MAX_IMPORTED_KEY_RECORD_BYTES_V1)?;
        let record = ImportedKeyRecordV1::from_canonical_cbor(bytes)
            .map_err(|_| Error::PublicationConflict);
        self.check()?;
        record
    }

    pub(crate) fn imported_key_tombstone(&mut self, bytes: &[u8]) -> Result<ImportedKeyTombstoneV1> {
        self.check()?;
        self.imported_key_allocations(bytes, MAX_IMPORTED_KEY_TOMBSTONE_BYTES_V1)?;
        let tombstone = ImportedKeyTombstoneV1::from_canonical_cbor(bytes)
            .map_err(|_| Error::PublicationConflict);
        self.check()?;
        tombstone
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::{ForkReplayReadBudgetV1, ForkReplayReadLimitsV1};
    use pos_core::{
        trusted_clock::{GuardMonotonicSourceV1, ScriptedGuardMonotonicSourceV1},
        Hash, KeyIdentityV1, KeyRoleV1, OwnerIdV1, PublicKey,
    };
    use std::time::Duration;

    type Fallible<T> = std::result::Result<T, Box<dyn std::error::Error>>;

    #[derive(Clone, Copy)]
    enum Codec { Record, Tombstone }

    impl Codec {
        fn native_accepts(self, bytes: &[u8]) -> bool {
            match self {
                Self::Record => ImportedKeyRecordV1::from_canonical_cbor(bytes).is_ok(),
                Self::Tombstone => ImportedKeyTombstoneV1::from_canonical_cbor(bytes).is_ok(),
            }
        }

        fn decode(self, bytes: &[u8], context: &mut NativeReadContextV1<'_, '_>) -> Result<()> {
            match self {
                Self::Record => context.imported_key_record(bytes).map(|_| ()),
                Self::Tombstone => context.imported_key_tombstone(bytes).map(|_| ()),
            }
        }
    }

    fn assert_parity(codec: Codec, bytes: &[u8]) -> Fallible<()> {
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(1, 1, 1, 4_096, 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        assert_eq!(codec.decode(bytes, &mut NativeReadContextV1::protected(&mut budget)).is_ok(),
            codec.native_accepts(bytes));
        assert!(budget.check_time().is_ok());
        Ok(())
    }

    #[test]
    fn imported_key_gates_preserve_native_parity_and_exact_owner_buffer_costs() -> Fallible<()> {
        let owner = OwnerIdV1::new("é".repeat(64))?;
        let identity = KeyIdentityV1::from_parts(owner, KeyRoleV1::SubjectAttributionSigning, 1);
        let record = ImportedKeyRecordV1::new(identity, None, PublicKey::from_bytes([7; 32]))?;
        let tombstone = ImportedKeyTombstoneV1::new(identity, Hash::from_bytes([1; 32]),
            Hash::from_bytes([2; 32]), Hash::from_bytes([3; 32]))?;
        for (codec, bytes) in [(Codec::Record, record.to_canonical_cbor()),
            (Codec::Tombstone, tombstone.to_canonical_cbor())] {
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
            let expected = owner.as_str().len() + bytes.len();
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
        Ok(())
    }
}
