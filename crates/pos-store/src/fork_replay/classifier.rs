//! Borrowed allocation gates for the existing FCS1, FCT1 and FCR1 decoders.

use pos_core::{
    ForkClassifierRegistrationV1, ForkClassifierSourceV1, ForkClassifierTableV1,
    MAX_FORK_EVENT_CLASSIFIER_REGISTRATION_BYTES_V1, MAX_FORK_EVENT_CLASSIFIER_ROUTES_V1,
    MAX_FORK_EVENT_CLASSIFIER_TABLE_BYTES_V1, MAX_FORK_EVENT_REGISTRAR_BYTES_V1,
    MAX_FORK_EVENT_SOURCE_ROUTE_BYTES_V1,
};

use super::{AdmissionCarrierV1, NativeReadContextV1};
use crate::ForkManifestPublicationErrorV1 as Error;

type Result<T> = std::result::Result<T, Error>;

const SOURCE_REGISTRAR_FIELD: u64 = 3;
const SOURCE_ROUTES_FIELD: u64 = 4;
const TABLE_REGISTRAR_FIELD: u64 = 5;
const TABLE_ROUTES_FIELD: u64 = 7;
// Logical route fields: one 32-byte schema digest and one intervention flag.
// The separately owned route text is charged by its actual UTF-8 length.
const ROUTE_FIXED_BYTES: usize = 32 + 1;

impl NativeReadContextV1<'_, '_> {
    /// `from_table` really encodes one table digest and clones each route.
    /// Charge those actual units, not the registrar it only borrows.
    pub(crate) fn classifier_from_table(
        &mut self,
        table: &ForkClassifierTableV1,
    ) -> Result<pos_core::ForkEventClassifierV1> {
        self.check()
            .and_then(|()| self.canonical(table.canonical_cbor_len()))
            .and_then(|()| {
                table.input().routes.iter().try_for_each(|route| {
                    self.bytes(route.source().route().len())
                        .and_then(|()| self.bytes(ROUTE_FIXED_BYTES))
                })
            })
            .and_then(|()| {
                let classifier = pos_core::ForkEventClassifierV1::from_table(table);
                self.check().map(|()| classifier)
            })
    }

    fn classifier_allocations(
        &mut self,
        bytes: &[u8],
        registrar_field: u64,
        routes_field: u64,
    ) -> Result<()> {
        if bytes.len() > MAX_FORK_EVENT_CLASSIFIER_TABLE_BYTES_V1 {
            return Err(Error::PublicationConflict);
        }
        let registrar = AdmissionCarrierV1::field(bytes, registrar_field, 3)
            .filter(|text| text.len() <= MAX_FORK_EVENT_REGISTRAR_BYTES_V1)
            .ok_or(Error::PublicationConflict)?;
        self.bytes(registrar.len())?;
        let (count, mut routes) = AdmissionCarrierV1::array_field(bytes, routes_field)
            .ok_or(Error::PublicationConflict)?;
        if count > MAX_FORK_EVENT_CLASSIFIER_ROUTES_V1 as u64 {
            return Err(Error::PublicationConflict);
        }
        for _ in 0..count {
            self.check()?;
            if routes.head() != Some((4, 3)) {
                return Err(Error::PublicationConflict);
            }
            let (major, length) = routes.head().ok_or(Error::PublicationConflict)?;
            if major != 3 || length > MAX_FORK_EVENT_SOURCE_ROUTE_BYTES_V1 as u64 {
                return Err(Error::PublicationConflict);
            }
            let text = routes
                .take_encoded(length)
                .ok_or(Error::PublicationConflict)?;
            self.bytes(text.len())?;
            if routes.head() != Some((2, 32)) {
                return Err(Error::PublicationConflict);
            }
            routes.take(32).ok_or(Error::PublicationConflict)?;
            // Native FCS1/FCT1 encode this logical flag as uint 0/1,
            // not CBOR's simple false/true values.
            if !matches!(routes.head(), Some((0, 0 | 1))) {
                return Err(Error::PublicationConflict);
            }
            self.bytes(ROUTE_FIXED_BYTES)?;
        }
        // Core's canonical equality buffer, independent of owned route fields.
        self.bytes(bytes.len())
    }

    pub(crate) fn classifier_source(&mut self, bytes: &[u8]) -> Result<ForkClassifierSourceV1> {
        self.check()?;
        if self.budget.is_some() {
            self.classifier_allocations(bytes, SOURCE_REGISTRAR_FIELD, SOURCE_ROUTES_FIELD)?;
        }
        let value = ForkClassifierSourceV1::from_canonical_cbor(bytes)
            .map_err(|_| Error::PublicationConflict);
        self.check()?;
        value
    }

    pub(crate) fn classifier_table(&mut self, bytes: &[u8]) -> Result<ForkClassifierTableV1> {
        self.check()?;
        if self.budget.is_some() {
            self.classifier_allocations(bytes, TABLE_REGISTRAR_FIELD, TABLE_ROUTES_FIELD)?;
        }
        let value = ForkClassifierTableV1::from_canonical_cbor(bytes)
            .map_err(|_| Error::PublicationConflict);
        self.check()?;
        value
    }

    pub(crate) fn classifier_registration(
        &mut self,
        bytes: &[u8],
    ) -> Result<ForkClassifierRegistrationV1> {
        self.check()?;
        if self.budget.is_some() {
            if bytes.len() > MAX_FORK_EVENT_CLASSIFIER_REGISTRATION_BYTES_V1 {
                return Err(Error::PublicationConflict);
            }
            self.bytes(bytes.len())?;
        }
        let value = ForkClassifierRegistrationV1::from_canonical_cbor(bytes)
            .map_err(|_| Error::PublicationConflict);
        self.check()?;
        value
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
        Source,
        Table,
        Registration,
    }

    impl Codec {
        fn accepts(self, bytes: &[u8]) -> bool {
            match self {
                Self::Source => ForkClassifierSourceV1::from_canonical_cbor(bytes).is_ok(),
                Self::Table => ForkClassifierTableV1::from_canonical_cbor(bytes).is_ok(),
                Self::Registration => {
                    ForkClassifierRegistrationV1::from_canonical_cbor(bytes).is_ok()
                }
            }
        }

        fn decode(self, bytes: &[u8], context: &mut NativeReadContextV1<'_, '_>) -> Result<()> {
            match self {
                Self::Source => context.classifier_source(bytes).map(|_| ()),
                Self::Table => context.classifier_table(bytes).map(|_| ()),
                Self::Registration => context.classifier_registration(bytes).map(|_| ()),
            }
        }

        const fn maximum(self) -> usize {
            match self {
                Self::Source | Self::Table => MAX_FORK_EVENT_CLASSIFIER_TABLE_BYTES_V1,
                Self::Registration => MAX_FORK_EVENT_CLASSIFIER_REGISTRATION_BYTES_V1,
            }
        }
    }

    fn records() -> Fallible<(
        ForkClassifierSourceV1,
        ForkClassifierTableV1,
        ForkClassifierRegistrationV1,
    )> {
        let world = World::new(Shape::Mixed, false)?;
        let built = world.build(&Spec::default())?;
        let records = built
            .envelope
            .unsigned()
            .input()
            .classifier
            .as_ref()
            .ok_or("classifier fixture")?;
        Ok((
            ForkClassifierSourceV1::from_canonical_cbor(&records.source)?,
            ForkClassifierTableV1::from_canonical_cbor(&records.table)?,
            ForkClassifierRegistrationV1::from_canonical_cbor(&records.registration)?,
        ))
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
        let limits = ForkReplayReadLimitsV1::new(1, 1, 1, 1_000_000, 1_000_000)?;
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
    fn classifier_caps_are_inclusive_before_malformed_precharges() -> Fallible<()> {
        let (source, table, registration) = records()?;
        assert_eq!(source.input().routes, table.input().routes);
        let route_bytes: usize = source
            .input()
            .routes
            .iter()
            .map(|route| route.source().route().len() + 32 + 1)
            .sum();
        for (codec, valid, fields) in [
            (
                Codec::Source,
                source.to_canonical_cbor(),
                source.input().registrar_identifier.len() + route_bytes,
            ),
            (
                Codec::Table,
                table.to_canonical_cbor(),
                table.input().registrar_identifier.len() + route_bytes,
            ),
            (Codec::Registration, registration.to_canonical_cbor(), 0),
        ] {
            let maximum = codec.maximum();
            assert!(valid.len() < maximum);
            for (length, charge) in [
                (maximum - 1, maximum - 1 + fields),
                (maximum, maximum + fields),
                (maximum + 1, 0),
            ] {
                // The carrier still exposes the original bounded fields;
                // Core independently rejects the corrupt trailing encoding.
                let mut malformed = valid.clone();
                malformed.resize(length, 0);
                assert!(!codec.accepts(&malformed));
                let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
                let start = clock.mark();
                let limits = ForkReplayReadLimitsV1::new(1, 1, 1, 1_000_000, 1_000_000)?;
                let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
                assert_eq!(
                    codec.decode(&malformed, &mut NativeReadContextV1::protected(&mut budget)),
                    Err(Error::PublicationConflict),
                );
                assert_eq!(
                    budget.remaining_native_bytes(),
                    limits.max_native_bytes() - charge,
                );
                assert_eq!(budget.check_time(), Ok(()));
                codec.decode(&valid, &mut NativeReadContextV1::protected(&mut budget))?;
                assert_eq!(
                    budget.remaining_native_bytes(),
                    limits.max_native_bytes() - charge - valid.len() - fields,
                );
            }
        }
        Ok(())
    }

    #[test]
    fn classifier_carriers_preserve_all_three_strict_native_decoders() -> Fallible<()> {
        let (source, table, registration) = records()?;
        for (codec, bytes) in [
            (Codec::Source, source.to_canonical_cbor()),
            (Codec::Table, table.to_canonical_cbor()),
            (Codec::Registration, registration.to_canonical_cbor()),
        ] {
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
            oversized.resize(codec.maximum() + 1, 0);
            assert_parity(codec, &oversized)?;
        }
        Ok(())
    }

    fn byte_boundary(codec: Codec, bytes: &[u8], expected: usize, limit: usize) -> Fallible<()> {
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let limits = ForkReplayReadLimitsV1::new(1, 1, 1, limit, 1_000_000)?;
        let mut budget = ForkReplayReadBudgetV1::new(limits, start, &mut clock)?;
        let value = codec.decode(bytes, &mut NativeReadContextV1::protected(&mut budget));
        if limit == expected {
            value?;
            assert_eq!(budget.remaining_native_bytes(), 0);
        } else {
            assert!(value.is_err());
            assert!(budget.check_time().is_err());
        }
        Ok(())
    }

    #[test]
    fn classifier_decoders_charge_independent_field_and_equality_units() -> Fallible<()> {
        let (source, table, registration) = records()?;
        let route_bytes: usize = source
            .input()
            .routes
            .iter()
            .map(|route| route.source().route().len() + 32 + 1)
            .sum();
        for (codec, bytes, fields) in [
            (
                Codec::Source,
                source.to_canonical_cbor(),
                source.input().registrar_identifier.len() + route_bytes,
            ),
            (
                Codec::Table,
                table.to_canonical_cbor(),
                table.input().registrar_identifier.len() + route_bytes,
            ),
            (Codec::Registration, registration.to_canonical_cbor(), 0),
        ] {
            let expected = bytes.len() + fields;
            for limit in 1..=expected {
                byte_boundary(codec, &bytes, expected, limit)?;
            }
        }
        Ok(())
    }

    #[test]
    fn classifier_intervention_flags_use_native_integer_encoding() -> Fallible<()> {
        let (source, table, _) = records()?;
        for intervention in [false, true] {
            let route = pos_core::ForkExternalInputRouteV1::new(
                pos_core::ForkEventSourceDescriptorV1::new(
                    "native-route".to_owned(),
                    pos_core::Hash::from_bytes([1; 32]),
                )?,
                intervention,
            );
            let mut source_fields = source.input().clone();
            source_fields.routes = vec![route.clone()];
            let source = ForkClassifierSourceV1::new(source_fields)?;
            let mut table_fields = table.input().clone();
            table_fields.routes = vec![route];
            let table = ForkClassifierTableV1::new(table_fields)?;
            for (codec, bytes, registrar) in [
                (
                    Codec::Source,
                    source.to_canonical_cbor(),
                    source.input().registrar_identifier.len(),
                ),
                (
                    Codec::Table,
                    table.to_canonical_cbor(),
                    table.input().registrar_identifier.len(),
                ),
            ] {
                assert_eq!(bytes.last(), Some(&u8::from(intervention)));
                assert_parity(codec, &bytes)?;
                let expected = bytes.len() + registrar + "native-route".len() + 32 + 1;
                byte_boundary(codec, &bytes, expected, expected)?;
                byte_boundary(codec, &bytes, expected, expected - 1)?;
                for nonnative_flag in [0xf4, 0xf5] {
                    let mut nonnative = bytes.clone();
                    *nonnative.last_mut().ok_or("native route flag")? = nonnative_flag;
                    assert!(!codec.accepts(&nonnative));
                    assert_parity(codec, &nonnative)?;
                }
            }
        }
        Ok(())
    }

    #[test]
    fn classifier_maximum_utf8_fields_and_route_cardinality_have_exact_gates() -> Fallible<()> {
        let (source, table, _) = records()?;
        let routes: Vec<_> = (0..MAX_FORK_EVENT_CLASSIFIER_ROUTES_V1)
            .map(|index| {
                pos_core::ForkEventSourceDescriptorV1::new(
                    format!("r{index:04}-{}", "é".repeat(61)),
                    pos_core::Hash::from_bytes([1; 32]),
                )
                .map(|source| pos_core::ForkExternalInputRouteV1::new(source, index % 2 == 0))
            })
            .collect::<std::result::Result<_, _>>()?;
        assert!(routes
            .iter()
            .all(|route| route.source().route().len() == MAX_FORK_EVENT_SOURCE_ROUTE_BYTES_V1));
        let mut source_fields = source.input().clone();
        source_fields.registrar_identifier = "é".repeat(32);
        source_fields.routes = routes.clone();
        let source = ForkClassifierSourceV1::new(source_fields)?;
        let mut table_fields = table.input().clone();
        table_fields.registrar_identifier = "é".repeat(32);
        table_fields.routes = routes;
        let table = ForkClassifierTableV1::new(table_fields)?;
        let fields = 64 + MAX_FORK_EVENT_CLASSIFIER_ROUTES_V1 * (128 + 32 + 1);
        for (codec, bytes) in [
            (Codec::Source, source.to_canonical_cbor()),
            (Codec::Table, table.to_canonical_cbor()),
        ] {
            assert_parity(codec, &bytes)?;
            let expected = bytes.len() + fields;
            byte_boundary(codec, &bytes, expected, expected)?;
            byte_boundary(codec, &bytes, expected, expected - 1)?;
            // Independently replace the definite routes head by count 1025.
            let mut too_many = bytes;
            // Fixed native field heads/payloads, independently of carriers:
            // array/magic/version, optional child/FAR, descriptor, registrar,
            // optional source digest, then the routes array.
            let head = match codec {
                Codec::Source => 1 + 5 + 1 + 34 + 66,
                Codec::Table => 1 + 5 + 1 + 17 + 34 + 34 + 66 + 34,
                Codec::Registration => return Err("no routes in FCR1".into()),
            };
            assert_eq!(&too_many[head..head + 3], &[0x99, 0x04, 0x00]);
            too_many[head + 2] = 1;
            assert_parity(codec, &too_many)?;
        }
        Ok(())
    }
}
