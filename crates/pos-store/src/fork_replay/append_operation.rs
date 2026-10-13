//! Borrowed allocation carriers for the existing capped FOP1 decoder.

use pos_core::{
    ForkAppendOperationV1, MAX_FORK_EVENT_APPEND_OPERATION_BYTES_V1,
    MAX_FORK_EVENT_REGISTRAR_BYTES_V1, MAX_FORK_EVENT_SOURCE_ROUTE_BYTES_V1,
};

use super::{AdmissionCarrierV1, NativeReadContextV1};
use crate::ForkManifestPublicationErrorV1 as Error;

const SOURCE_FIELD: u64 = 7;

fn text_length(carrier: &mut AdmissionCarrierV1<'_>, maximum: usize) -> Option<usize> {
    let (major, length) = carrier.head()?;
    let length = usize::try_from(length).ok()?;
    if major != 3 || length == 0 || length > maximum {
        return None;
    }
    carrier.take(length).map(<[u8]>::len)
}

fn source_lengths(bytes: &[u8]) -> Option<[usize; 2]> {
    let (count, mut source) = AdmissionCarrierV1::array_field(bytes, SOURCE_FIELD)?;
    match (count, source.head()?) {
        (1, (0, 0)) => Some([0, 0]),
        (4, (0, 1)) => {
            let adapter = text_length(&mut source, MAX_FORK_EVENT_REGISTRAR_BYTES_V1)?;
            let route = text_length(&mut source, MAX_FORK_EVENT_SOURCE_ROUTE_BYTES_V1)?;
            Some([adapter, route])
        }
        _ => None,
    }
}

impl NativeReadContextV1<'_, '_> {
    pub(crate) fn append_operation(
        &mut self,
        bytes: &[u8],
    ) -> Result<ForkAppendOperationV1, Error> {
        self.check()
            .and_then(|()| {
                if self.budget.is_none() {
                    return Ok(());
                }
                if bytes.len() > MAX_FORK_EVENT_APPEND_OPERATION_BYTES_V1 {
                    return Err(Error::PublicationConflict);
                }
                source_lengths(bytes)
                    .ok_or(Error::PublicationConflict)
                    .and_then(|lengths| lengths.iter().try_for_each(|length| self.bytes(*length)))
                    // The borrowed reader owns no value tree or fixed-field
                    // Vec. Only external source Strings and this separate
                    // canonical equality Vec are allocated by core.
                    .and_then(|()| self.bytes(bytes.len()))
            })
            .and_then(|()| {
                let decoded = ForkAppendOperationV1::from_canonical_cbor(bytes)
                    .map_err(|_| Error::PublicationConflict);
                self.check().and(decoded)
            })
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
    use pos_core::{
        trusted_clock::{GuardMonotonicSourceV1, ScriptedGuardMonotonicSourceV1},
        ForkAppendSourceIdentityV1, ForkAttributionImportClosureV1,
    };
    use std::time::Duration;

    fn operations() -> Fallible<Vec<ForkAppendOperationV1>> {
        let world = World::new(Shape::Mixed, false)?;
        let built = world.build(&Spec::default())?;
        Ok(ForkAttributionImportClosureV1::validate(&built.envelope)?
            .append_operations()
            .to_vec())
    }

    fn cost(operation: &ForkAppendOperationV1) -> usize {
        operation.to_canonical_cbor().len()
            + match &operation.input().source {
                ForkAppendSourceIdentityV1::HostInternal => 0,
                ForkAppendSourceIdentityV1::ExternalInput {
                    adapter_identifier,
                    source,
                } => adapter_identifier.len() + source.route().len(),
            }
    }

    #[test]
    fn fop_native_decoder_charges_exact_external_strings_and_comparison_prefixes() -> Fallible<()> {
        let mut cases = operations()?;
        let mut input = cases.get(1).ok_or("external operation")?.input().clone();
        input.source = ForkAppendSourceIdentityV1::ExternalInput {
            adapter_identifier: "é".repeat(32),
            source: pos_core::ForkEventSourceDescriptorV1::new(
                "é".repeat(64),
                pos_core::Hash::from_bytes([9; 32]),
            )?,
        };
        input.logical_seq = u64::MAX;
        cases.push(ForkAppendOperationV1::new(input)?); // codec arithmetic witness, not admitted SQLite history
        for operation in cases {
            let bytes = operation.to_canonical_cbor();
            assert!(bytes.len() <= MAX_FORK_EVENT_APPEND_OPERATION_BYTES_V1);
            let expected = cost(&operation);
            assert_eq!(
                NativeReadContextV1::ordinary().append_operation(&bytes)?,
                operation
            );
            for limit in 1..=expected {
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, 1, limit, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                let decoded = NativeReadContextV1::protected(&mut budget).append_operation(&bytes);
                if limit == expected {
                    assert_eq!(decoded?, operation);
                    assert_eq!(budget.remaining_native_bytes(), 0);
                } else {
                    assert_eq!(decoded, Err(Error::PublicationConflict));
                    assert!(budget.check_time().is_err());
                }
            }
        }
        Ok(())
    }

    #[test]
    fn fop_native_carrier_preserves_core_rejection_and_repeated_budget() -> Fallible<()> {
        for operation in operations()? {
            let bytes = operation.to_canonical_cbor();
            for length in 0..bytes.len() {
                let truncated = &bytes[..length];
                assert!(ForkAppendOperationV1::from_canonical_cbor(truncated).is_err());
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, 1, 4096, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                assert_eq!(
                    NativeReadContextV1::protected(&mut budget).append_operation(truncated),
                    Err(Error::PublicationConflict)
                );
            }
            for limit in [cost(&operation) * 2 - 1, cost(&operation) * 2] {
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, 1, limit, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                assert_eq!(
                    NativeReadContextV1::protected(&mut budget).append_operation(&bytes)?,
                    operation
                );
                let result = NativeReadContextV1::protected(&mut budget).append_operation(&bytes);
                assert_eq!(result.is_ok(), limit == cost(&operation) * 2);
                assert_eq!(budget.check_time().is_ok(), result.is_ok());
            }
        }
        Ok(())
    }

    #[test]
    fn fop_native_batches_keep_original_guard_expiry_and_regression() -> Fallible<()> {
        let operation = operations()?.remove(1);
        let bytes = operation.to_canonical_cbor();
        for regression in [false, true] {
            let mut failed = 0;
            let mut completed = 0;
            for boundary in 2..=64 {
                let initial = if regression {
                    Duration::from_micros(1)
                } else {
                    Duration::ZERO
                };
                let later = if regression {
                    Duration::ZERO
                } else {
                    Duration::from_micros(11)
                };
                let mut clock = ScriptedGuardMonotonicSourceV1::new(
                    std::iter::repeat_n(initial, boundary).chain([later]),
                );
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, 1, cost(&operation), 10)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                let result = NativeReadContextV1::protected(&mut budget).append_operation(&bytes);
                if result.is_ok() {
                    completed += 1;
                } else {
                    failed += 1;
                    assert_eq!(result, Err(Error::PublicationConflict));
                    assert!(budget.check_time().is_err());
                }
            }
            assert!(failed > 0);
            assert!(completed > 0);
        }
        Ok(())
    }
}
