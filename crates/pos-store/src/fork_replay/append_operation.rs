//! Borrowed allocation carriers for the existing capped FOP1 decoder.

use pos_core::{
    ForkAppendOperationV1, MAX_FORK_EVENT_APPEND_OPERATION_BYTES_V1,
    MAX_FORK_EVENT_REGISTRAR_BYTES_V1, MAX_FORK_EVENT_SOURCE_ROUTE_BYTES_V1,
};

use super::{AdmissionCarrierV1, NativeReadContextV1};
use crate::ForkManifestPublicationErrorV1 as Error;

const SOURCE_FIELD: u64 = 7;

fn text_length(carrier: &mut AdmissionCarrierV1<'_>, maximum: u64) -> Option<usize> {
    let (major, length) = carrier.head()?;
    if major != 3 || length == 0 || length > maximum {
        return None;
    }
    carrier.take_encoded(length).map(<[u8]>::len)
}

fn source_lengths(bytes: &[u8]) -> Option<[usize; 2]> {
    let (count, mut source) = AdmissionCarrierV1::array_field(bytes, SOURCE_FIELD)?;
    match (count, source.head()?) {
        (1, (0, 0)) => Some([0, 0]),
        (4, (0, 1)) => {
            let adapter = text_length(&mut source, MAX_FORK_EVENT_REGISTRAR_BYTES_V1 as u64)?;
            let route = text_length(&mut source, MAX_FORK_EVENT_SOURCE_ROUTE_BYTES_V1 as u64)?;
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
    use ciborium::value::Value;
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

    fn assert_preallocation_refusal(bytes: &[u8], valid: &ForkAppendOperationV1) -> Fallible<()> {
        assert!(ForkAppendOperationV1::from_canonical_cbor(bytes).is_err());
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let started = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(1, 1, 1, 8 * 1024 * 1024, 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, started, &mut clock)?;
        assert_eq!(
            NativeReadContextV1::protected(&mut budget).append_operation(bytes),
            Err(Error::PublicationConflict)
        );
        assert_eq!(budget.remaining_native_bytes(), limits.max_native_bytes());
        assert_eq!(budget.check_time(), Ok(()));
        let control = NativeReadContextV1::protected(&mut budget)
            .append_operation(&valid.to_canonical_cbor())?;
        assert_eq!(&control, valid);
        assert!(budget.remaining_native_bytes() < limits.max_native_bytes());
        Ok(())
    }

    #[test]
    fn fop_transport_cap_is_inclusive_before_malformed_precharges() -> Fallible<()> {
        for operation in operations()? {
            let valid = operation.to_canonical_cbor();
            let fields = cost(&operation) - valid.len();
            let maximum = MAX_FORK_EVENT_APPEND_OPERATION_BYTES_V1;
            assert!(valid.len() < maximum);
            for (length, charge) in [
                (maximum - 1, maximum - 1 + fields),
                (maximum, maximum + fields),
                (maximum + 1, 0),
            ] {
                // Corrupt trailing bytes are not an admitted FOP1. Inside
                // the inclusive cap, its bounded precharges precede refusal.
                let mut malformed = valid.clone();
                malformed.resize(length, 0);
                assert!(ForkAppendOperationV1::from_canonical_cbor(&malformed).is_err());
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, 1, 8_192, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                assert_eq!(
                    NativeReadContextV1::protected(&mut budget).append_operation(&malformed),
                    Err(Error::PublicationConflict),
                );
                assert_eq!(
                    budget.remaining_native_bytes(),
                    limits.max_native_bytes() - charge,
                );
                assert_eq!(budget.check_time(), Ok(()));
                assert_eq!(
                    NativeReadContextV1::protected(&mut budget).append_operation(&valid)?,
                    operation,
                );
                assert_eq!(
                    budget.remaining_native_bytes(),
                    limits.max_native_bytes() - charge - cost(&operation),
                );
            }
        }
        Ok(())
    }

    #[test]
    fn fop_caps_and_malformed_source_carriers_refuse_before_owned_buffers() -> Fallible<()> {
        // These raw decoder faults cannot be constructed as typed FOP1 records.
        // They prove the native preallocation boundary, not an admitted import.
        let cases = operations()?;
        assert_eq!(cases.len(), 4);
        for operation in &cases {
            let mut oversized = operation.to_canonical_cbor();
            oversized.resize(MAX_FORK_EVENT_APPEND_OPERATION_BYTES_V1 + 1, 0);
            assert_preallocation_refusal(&oversized, operation)?;
        }
        let external = cases
            .iter()
            .find(|operation| {
                matches!(
                    &operation.input().source,
                    ForkAppendSourceIdentityV1::ExternalInput { .. }
                )
            })
            .ok_or("external operation")?;
        let valid = external.to_canonical_cbor();
        let decoded: Value = ciborium::de::from_reader(valid.as_slice())?;
        let Value::Array(fields) = decoded else {
            return Err("FOP1 array".into());
        };
        let Value::Array(source) = fields.get(7).ok_or("FOP1 source")? else {
            return Err("FOP1 source array".into());
        };
        let encode_source = |source: Vec<Value>| -> Fallible<Vec<u8>> {
            let mut fields = fields.clone();
            fields[7] = Value::Array(source);
            let mut bytes = Vec::new();
            ciborium::ser::into_writer(&Value::Array(fields), &mut bytes)?;
            Ok(bytes)
        };
        assert_eq!(encode_source(source.clone())?, valid);
        for (field, text) in [
            (1, String::new()),
            (2, String::new()),
            (1, "x".repeat(MAX_FORK_EVENT_REGISTRAR_BYTES_V1 + 1)),
            (2, "x".repeat(MAX_FORK_EVENT_SOURCE_ROUTE_BYTES_V1 + 1)),
        ] {
            let mut changed = source.clone();
            changed[field] = Value::Text(text);
            let bytes = encode_source(changed)?;
            assert!(bytes.len() <= MAX_FORK_EVENT_APPEND_OPERATION_BYTES_V1);
            assert_preallocation_refusal(&bytes, external)?;
        }
        let mut unknown_tag = source.clone();
        unknown_tag[0] = Value::Integer(2.into());
        for changed in [
            vec![Value::Integer(0.into()), Value::Integer(0.into())],
            unknown_tag,
        ] {
            let bytes = encode_source(changed)?;
            assert!(bytes.len() <= MAX_FORK_EVENT_APPEND_OPERATION_BYTES_V1);
            assert_preallocation_refusal(&bytes, external)?;
        }
        Ok(())
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
