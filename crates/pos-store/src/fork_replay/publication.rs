//! Borrowed allocation carriers for the existing publication decoders.
//!
//! This is not another native validator. Core still decides all magic,
//! preferred widths, semantics and exact canonical equality. Valid records
//! reconcile to actual buffers; malformed inputs receive bounded precharges.

use pos_core::{
    ForkPublicationArtifactV1, ForkPublicationBindingV1, ForkPublicationOperationV1,
    ImportedForkPublicationOperationV1, MAX_FORK_MANIFEST_INTERVENTIONS_V1,
    MAX_FORK_PUBLICATION_ARTIFACT_BYTES_V1, MAX_FORK_PUBLICATION_BINDING_BYTES_V1,
    MAX_FORK_PUBLICATION_OPERATION_BYTES_V1, MAX_FORK_REPRO_MANIFEST_BYTES_V1,
    MAX_SIGNED_FORK_REPRO_MANIFEST_BYTES_V1,
};

use super::{imported_projection_length, AdmissionCarrierV1, NativeReadContextV1};
use crate::{
    fork_event_authority::{AuthorityValidatorV1, ValidatedOriginV1},
    fork_manifest_publication::{charge_origin_copy, charge_publication_copy},
    ForkManifestPublicationErrorV1 as Error,
};

type Result<T> = std::result::Result<T, Error>;

const OWNER_FIELD: u64 = 7;
const OWNER_MAX_BYTES: usize = 128;

fn bounded_field(bytes: &[u8], field: u64, major: u8, maximum: usize) -> Result<&[u8]> {
    AdmissionCarrierV1::field(bytes, field, major)
        .filter(|value| value.len() <= maximum)
        .ok_or(Error::PublicationConflict)
}

impl NativeReadContextV1<'_, '_> {
    pub(crate) fn publication_binding(&mut self, bytes: &[u8]) -> Result<ForkPublicationBindingV1> {
        self.check()?;
        if self.budget.is_some() {
            if bytes.len() > MAX_FORK_PUBLICATION_BINDING_BYTES_V1 {
                return Err(Error::PublicationConflict);
            }
            // The fixed-field decoder's canonical comparison buffer.
            self.bytes(bytes.len())?;
        }
        let record = ForkPublicationBindingV1::from_canonical_cbor(bytes)
            .map_err(|_| Error::PublicationConflict);
        self.check()?;
        record
    }

    fn publication_owner(&mut self, bytes: &[u8]) -> Result<()> {
        let owner = bounded_field(bytes, OWNER_FIELD, 3, OWNER_MAX_BYTES)?;
        self.bytes(owner.len())
    }

    pub(crate) fn publication_operation(
        &mut self,
        bytes: &[u8],
        validator: AuthorityValidatorV1,
    ) -> Result<(ForkPublicationOperationV1, ValidatedOriginV1)> {
        self.check()?;
        let projected_length = imported_projection_length(bytes);
        if self.budget.is_some() {
            if bytes.len() > MAX_FORK_PUBLICATION_OPERATION_BYTES_V1 {
                return Err(Error::PublicationConflict);
            }
            self.publication_owner(bytes)?;
            // A recognized code-2 origin fails the local decoder before its
            // canonical comparison: no fictitious local encoding is charged.
            if projected_length.is_none() {
                self.bytes(bytes.len())?;
            }
        }
        let local = ForkPublicationOperationV1::from_canonical_cbor(bytes);
        self.check()?;
        if let Ok(operation) = local {
            charge_origin_copy(ValidatedOriginV1::Local, self)?;
            return self.check().map(|()| (operation, ValidatedOriginV1::Local));
        }
        if validator == AuthorityValidatorV1::LocalOnly {
            return Err(Error::PublicationConflict);
        }
        if self.budget.is_some() {
            if let Some(length) = projected_length {
                // Core's decode_imported creates this real local-projection
                // Vec, then its local decoder allocates owner and equality Vec.
                self.bytes(length)?;
                self.publication_owner(bytes)?;
                self.bytes(length)?;
            } else {
                // Erratum E9 deliberately retries the local decoder on the
                // original bytes; its conservative gates are charged again.
                self.publication_owner(bytes)?;
                self.bytes(bytes.len())?;
            }
        }
        let imported = ImportedForkPublicationOperationV1::from_canonical_cbor(bytes)
            .map_err(|_| Error::PublicationConflict)?;
        self.check()?;
        let origin = ValidatedOriginV1::Imported(imported.authority_origin_digest());
        charge_publication_copy(imported.projection(), origin, self)?;
        charge_origin_copy(origin, self)?;
        let operation = imported.projection().clone();
        self.check().map(|()| (operation, origin))
    }

    pub(crate) fn publication_artifact(
        &mut self,
        bytes: &[u8],
    ) -> Result<ForkPublicationArtifactV1> {
        self.check()?;
        if self.budget.is_some() {
            self.publication_artifact_allocations(bytes)?;
        }
        let record = ForkPublicationArtifactV1::from_canonical_cbor(bytes)
            .map_err(|_| Error::PublicationConflict);
        self.check()?;
        record
    }

    fn publication_artifact_allocations(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > MAX_FORK_PUBLICATION_ARTIFACT_BYTES_V1 {
            return Err(Error::PublicationConflict);
        }
        let signed = bounded_field(bytes, 4, 2, MAX_SIGNED_FORK_REPRO_MANIFEST_BYTES_V1)?;
        self.bytes(signed.len())?; // FPA1's owned nested FSM1 byte copy.
        let owner = bounded_field(signed, 2, 3, OWNER_MAX_BYTES)?;
        self.bytes(owner.len())?; // FSM1 decoder's temporary owner String.
        let manifest = bounded_field(signed, 5, 2, MAX_FORK_REPRO_MANIFEST_BYTES_V1)?;
        let (count, mut sequences) =
            AdmissionCarrierV1::array_field(manifest, 10).ok_or(Error::PublicationConflict)?;
        if count > MAX_FORK_MANIFEST_INTERVENTIONS_V1 as u64 {
            return Err(Error::PublicationConflict);
        }
        for _ in 0..count {
            if sequences.head().is_none_or(|(major, _)| major != 0) {
                return Err(Error::PublicationConflict);
            }
            self.bytes(8)?; // Logical u64 copied into the decoded FRM1 vector.
        }
        self.bytes(manifest.len())?; // FRM1 canonical comparison.
        self.bytes(signed.len())?; // FSM1 canonical comparison's outer Vec.
        self.bytes(manifest.len())?; // Its separate nested FRM1 Vec.
        self.bytes(signed.len())?; // FPA1::new's FSM1 record-id encoding.
        self.bytes(manifest.len())?; // Its separate nested FRM1 Vec.
        self.bytes(bytes.len()) // FPA1 canonical comparison, no nested encoding.
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::{
        fae1_fixture::{pin_policy, request_for, Fallible, Shape, Spec, World, PARENT_CUT},
        memory::MemoryStore,
        ForkAttributionAuthorityImportPortV1, ForkManifestPublicationPortV1,
        ForkReplayReadBudgetV1, ForkReplayReadLimitsV1,
    };
    use pos_core::trusted_clock::{GuardMonotonicSourceV1, ScriptedGuardMonotonicSourceV1};
    use std::time::Duration;

    #[derive(Clone, Copy)]
    enum Codec {
        Binding,
        Operation,
        Artifact,
    }

    impl Codec {
        fn native_accepts(self, bytes: &[u8]) -> bool {
            match self {
                Self::Binding => ForkPublicationBindingV1::from_canonical_cbor(bytes).is_ok(),
                Self::Operation => {
                    ForkPublicationOperationV1::from_canonical_cbor(bytes).is_ok()
                        || ImportedForkPublicationOperationV1::from_canonical_cbor(bytes).is_ok()
                }
                Self::Artifact => ForkPublicationArtifactV1::from_canonical_cbor(bytes).is_ok(),
            }
        }

        fn decode(self, bytes: &[u8], context: &mut NativeReadContextV1<'_, '_>) -> Result<()> {
            match self {
                Self::Binding => context.publication_binding(bytes).map(|_| ()),
                Self::Operation => context
                    .publication_operation(bytes, AuthorityValidatorV1::CodeTwoAware)
                    .map(|_| ()),
                Self::Artifact => context.publication_artifact(bytes).map(|_| ()),
            }
        }
    }

    fn committed() -> Fallible<crate::CommittedForkManifestV1> {
        let world = World::new(Shape::Mixed, false)?;
        let built = world.build(&Spec::default())?;
        let mut store = MemoryStore::new();
        world.seed_destination(&mut store)?;
        pin_policy(&mut store, &built.policy)?;
        store.import_verified(&request_for(&world, &built))?;
        Ok(store.read_committed(world.child_at(0)?.id, PARENT_CUT + Shape::Mixed.events())?)
    }

    fn artifact(committed: &crate::CommittedForkManifestV1) -> Fallible<ForkPublicationArtifactV1> {
        Ok(ForkPublicationArtifactV1::new(
            pos_core::ForkPublicationArtifactInputV1 {
                signed_manifest_record_id: committed.record_id,
                operation_id: committed.operation.input().operation_id,
                signed_manifest_bytes: committed.outer_bytes.clone(),
            },
        )?)
    }

    fn assert_parity(codec: Codec, bytes: &[u8]) -> Fallible<()> {
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(1, 1, 1, 8 * 1024 * 1024, 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        assert_eq!(
            codec
                .decode(bytes, &mut NativeReadContextV1::protected(&mut budget))
                .is_ok(),
            codec.native_accepts(bytes)
        );
        assert!(budget.check_time().is_ok());
        Ok(())
    }

    #[test]
    fn publication_carriers_preserve_strict_native_acceptance_on_current_bytes() -> Fallible<()> {
        let committed = committed()?;
        let imported = ImportedForkPublicationOperationV1::from_local(
            committed.operation.clone(),
            committed.authority_origin_digest.ok_or("no origin")?,
        );
        for (codec, bytes) in [
            (Codec::Binding, committed.binding.to_canonical_cbor()),
            (Codec::Operation, committed.operation.to_canonical_cbor()),
            (Codec::Operation, imported.to_canonical_cbor()),
            (Codec::Artifact, artifact(&committed)?.to_canonical_cbor()),
        ] {
            assert_parity(codec, &bytes)?;
            for end in 0..bytes.len() {
                assert_parity(codec, &bytes[..end])?;
            }
            for index in 0..bytes.len() {
                for value in [0, 255] {
                    let mut changed = bytes.clone();
                    changed[index] = value;
                    assert_parity(codec, &changed)?;
                }
            }
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert_parity(codec, &trailing)?;
        }
        Ok(())
    }

    #[test]
    fn publication_size_caps_refuse_before_owned_decoder_buffers() -> Fallible<()> {
        let committed = committed()?;
        let imported = ImportedForkPublicationOperationV1::from_local(
            committed.operation.clone(),
            committed.authority_origin_digest.ok_or("no origin")?,
        );
        for (codec, valid, maximum) in [
            (
                Codec::Binding,
                committed.binding.to_canonical_cbor(),
                MAX_FORK_PUBLICATION_BINDING_BYTES_V1,
            ),
            (
                Codec::Operation,
                committed.operation.to_canonical_cbor(),
                MAX_FORK_PUBLICATION_OPERATION_BYTES_V1,
            ),
            (
                Codec::Operation,
                imported.to_canonical_cbor(),
                MAX_FORK_PUBLICATION_OPERATION_BYTES_V1,
            ),
            (
                Codec::Artifact,
                artifact(&committed)?.to_canonical_cbor(),
                MAX_FORK_PUBLICATION_ARTIFACT_BYTES_V1,
            ),
        ] {
            assert!(valid.len() <= maximum);
            assert!(codec.native_accepts(&valid));
            codec.decode(&valid, &mut NativeReadContextV1::ordinary())?;
            // Raw corruption below typed construction, not admitted authority.
            let mut oversized = valid.clone();
            oversized.resize(maximum + 1, 0);
            assert!(!codec.native_accepts(&oversized));
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let started = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(1, 1, 1, 8 * 1024 * 1024, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, started, &mut clock)?;
            assert_eq!(
                codec.decode(&oversized, &mut NativeReadContextV1::protected(&mut budget)),
                Err(Error::PublicationConflict)
            );
            assert_eq!(budget.remaining_native_bytes(), limits.max_native_bytes());
            assert_eq!(budget.check_time(), Ok(()));
            // Semantic wire rejection does not fabricate a debit or latch an
            // exhausted budget; the valid decoder control uses that same ledger.
            codec.decode(&valid, &mut NativeReadContextV1::protected(&mut budget))?;
            assert!(budget.remaining_native_bytes() < limits.max_native_bytes());
        }
        Ok(())
    }

    #[test]
    fn publication_decoders_debit_actual_buffers_before_each_allocation() -> Fallible<()> {
        let committed = committed()?;
        let owner = committed
            .operation
            .input()
            .signing_identity
            .owner_id
            .as_str()
            .len();
        let local = committed.operation.to_canonical_cbor();
        let imported = ImportedForkPublicationOperationV1::from_local(
            committed.operation.clone(),
            committed.authority_origin_digest.ok_or("no origin")?,
        )
        .to_canonical_cbor();
        let artifact = artifact(&committed)?;
        let signed = artifact.signed_manifest();
        let artifact_bytes = artifact.to_canonical_cbor();
        let artifact_cost = committed.outer_bytes.len() * 3
            + signed.manifest_bytes().len() * 3
            + signed.identity().owner_id.as_str().len()
            + signed.manifest().input().intervention_sequences.len() * 8
            + artifact_bytes.len();
        let projection = 32 + 16 + 8 + 32 + 32 + owner + 1 + 8 + 32 + 32 + 32 + 1;
        for (codec, bytes, expected) in [
            (
                Codec::Binding,
                committed.binding.to_canonical_cbor(),
                committed.binding.to_canonical_cbor().len(),
            ),
            (Codec::Operation, local.clone(), owner + local.len() + 1),
            (
                Codec::Operation,
                imported,
                owner * 2 + local.len() * 2 + projection + 1 + 32,
            ),
            (Codec::Artifact, artifact_bytes, artifact_cost),
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
        Ok(())
    }

    #[test]
    fn imported_publication_fallback_funds_each_repeated_charge() -> Fallible<()> {
        let committed = committed()?;
        let operation = committed.operation;
        let owner = operation.input().signing_identity.owner_id.as_str().len();
        let mut bytes = operation.to_canonical_cbor();
        assert_eq!(
            ForkPublicationOperationV1::from_canonical_cbor(&bytes)?,
            operation
        );
        assert_eq!(&bytes[2..6], b"FPO1");
        // Keep the bounded owner and local-origin tail intact. Invalid magic
        // makes the first decoder refuse and forces the code-2 E9 fallback.
        bytes[2] = b'X';
        assert!(ForkPublicationOperationV1::from_canonical_cbor(&bytes).is_err());
        assert_eq!(
            ImportedForkPublicationOperationV1::from_canonical_cbor(&bytes).err(),
            Some(pos_core::ForkAttributionCodecErrorV1::InvalidEncoding)
        );
        let first_pass = owner + bytes.len();
        let second_owner = first_pass + owner;
        let total = first_pass * 2;
        for (limit, charged, healthy) in [
            (second_owner - 1, first_pass, false),
            (second_owner, second_owner, false),
            (total - 1, second_owner, false),
            (total, total, true),
        ] {
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(1, 1, 1, limit, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            assert_eq!(
                NativeReadContextV1::protected(&mut budget)
                    .publication_operation(&bytes, AuthorityValidatorV1::CodeTwoAware),
                Err(Error::PublicationConflict)
            );
            assert_eq!(budget.remaining_native_bytes(), limit - charged);
            assert_eq!(budget.check_time().is_ok(), healthy);
        }
        Ok(())
    }

    #[test]
    fn local_only_decoder_never_promotes_imported_publication_origin() -> Fallible<()> {
        let committed = committed()?;
        let bytes = ImportedForkPublicationOperationV1::from_local(
            committed.operation,
            committed.authority_origin_digest.ok_or("no origin")?,
        )
        .to_canonical_cbor();
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(1, 1, 1, 8 * 1024 * 1024, 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        assert_eq!(
            NativeReadContextV1::protected(&mut budget)
                .publication_operation(&bytes, AuthorityValidatorV1::LocalOnly),
            Err(Error::PublicationConflict)
        );
        assert!(budget.check_time().is_ok());
        Ok(())
    }

    #[test]
    fn artifact_gate_accounts_maximum_intervention_cardinality_and_owner_bytes() -> Fallible<()> {
        let committed = committed()?;
        let original = artifact(&committed)?;
        let mut fields = original.signed_manifest().manifest().input().clone();
        let count = u64::try_from(MAX_FORK_MANIFEST_INTERVENTIONS_V1)?;
        fields.intervention_sequences = (1..=count)
            .map(|seq| fields.parent_logical_head + seq)
            .collect();
        fields.final_fork_logical_head = fields.parent_logical_head + count;
        let manifest = pos_core::ForkReproManifestV1::new(fields)?;
        let identity = pos_core::KeyIdentityV1::from_parts(
            pos_core::OwnerIdV1::new("é".repeat(64))?,
            pos_core::KeyRoleV1::SubjectAttributionSigning,
            1,
        );
        let signed = pos_core::SignedForkReproManifestV1::new(
            identity,
            manifest,
            original.signed_manifest().signature(),
        )?;
        let artifact = ForkPublicationArtifactV1::new(pos_core::ForkPublicationArtifactInputV1 {
            signed_manifest_record_id: signed.record_id(),
            operation_id: committed.operation.input().operation_id,
            signed_manifest_bytes: signed.to_canonical_cbor(),
        })?;
        let bytes = artifact.to_canonical_cbor();
        let expected = signed.to_canonical_cbor().len() * 3
            + signed.manifest_bytes().len() * 3
            + identity.owner_id.as_str().len()
            + MAX_FORK_MANIFEST_INTERVENTIONS_V1 * 8
            + bytes.len();
        for (limit, succeeds) in [(expected, true), (expected - 1, false)] {
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let limits = ForkReplayReadLimitsV1::new(1, 1, 1, limit, 1_000_000)?;
            let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
            let decoded = NativeReadContextV1::protected(&mut budget).publication_artifact(&bytes);
            if succeeds {
                assert_eq!(decoded?, artifact);
                assert_eq!(budget.remaining_native_bytes(), 0);
            } else {
                assert_eq!(decoded, Err(Error::PublicationConflict));
                assert!(budget.check_time().is_err());
            }
        }
        Ok(())
    }

    #[test]
    fn oversized_raw_intervention_count_refuses_before_sequence_allocation() -> Fallible<()> {
        use ciborium::value::Value;

        fn replace(bytes: &[u8], index: usize, value: Value) -> Fallible<Vec<u8>> {
            let Value::Array(mut fields) = ciborium::from_reader(bytes)? else {
                return Err("expected native array".into());
            };
            *fields.get_mut(index).ok_or("missing native field")? = value;
            let mut bytes = Vec::new();
            ciborium::into_writer(&Value::Array(fields), &mut bytes)?;
            Ok(bytes)
        }

        let original = artifact(&committed()?)?;
        let signed = original.signed_manifest();
        let manifest = replace(
            &signed.manifest_bytes(),
            10,
            Value::Array(vec![
                Value::Integer(1.into());
                MAX_FORK_MANIFEST_INTERVENTIONS_V1 + 1
            ]),
        )?;
        let signed_bytes = replace(&signed.to_canonical_cbor(), 5, Value::Bytes(manifest))?;
        let expected_debit = signed_bytes.len() + signed.identity().owner_id.as_str().len();
        let bytes = replace(&original.to_canonical_cbor(), 4, Value::Bytes(signed_bytes))?;
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(1, 1, 1, 8 * 1024 * 1024, 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        assert_eq!(
            NativeReadContextV1::protected(&mut budget).publication_artifact(&bytes),
            Err(Error::PublicationConflict)
        );
        assert_eq!(
            budget.remaining_native_bytes(),
            limits.max_native_bytes() - expected_debit
        );
        budget.check_time()?;
        assert_eq!(
            NativeReadContextV1::protected(&mut budget)
                .publication_artifact(&original.to_canonical_cbor())?,
            original
        );
        Ok(())
    }
}
