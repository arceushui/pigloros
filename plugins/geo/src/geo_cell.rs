#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::value::Value;
    use pos_core::CanonicalBytes;
    use std::io::Cursor;

    const KNOWN_INDEX: &str = "8928308280fffff";
    const KNOWN_BYTES: &[u8] =
        b"\xa4eindexo8928308280fffff\x66systemeh3-v4\x6aresolution\x09kcell_format\x01";

    fn resolution(value: u8) -> H3Resolution {
        H3Resolution::new(value).unwrap()
    }

    fn wgs84(latitude: f64, longitude: f64) -> Wgs84Point {
        Wgs84Point::new(latitude, longitude).unwrap()
    }

    fn map_bytes(entries: Vec<(Value, Value)>) -> CanonicalBytes {
        let mut bytes = Vec::new();
        ciborium::into_writer(&Value::Map(entries), &mut bytes).unwrap();
        CanonicalBytes::from_vec(bytes)
    }

    #[test]
    fn resolution_accepts_h3_range() {
        assert_eq!(H3Resolution::new(0).unwrap().value(), 0);
        assert_eq!(H3Resolution::new(15).unwrap().value(), 15);
        assert!(H3Resolution::new(16).is_err());
    }

    #[test]
    fn parses_and_exposes_a_canonical_cell() {
        let cell = H3ReferenceCloaker::new().parse(KNOWN_INDEX).unwrap();
        assert_eq!(cell.index(), KNOWN_INDEX);
        assert_eq!(cell.resolution().value(), 9);
    }

    #[test]
    fn rejects_noncanonical_or_invalid_h3_addresses() {
        let cloaker = H3ReferenceCloaker::new();
        for index in [
            "8928308280FFFFF",
            "0x8928308280fffff",
            "8928308280ffff",
            "8928308280ffffff",
            "ffffffffffffffff",
            "1828308280fffff",
        ] {
            assert!(cloaker.parse(index).is_err(), "accepted {index}");
        }
    }

    #[test]
    fn converts_wgs84_to_the_h3_core_known_answer() {
        let cell = H3ReferenceCloaker::new()
            .from_wgs84(wgs84(45.0, 40.0), resolution(2))
            .unwrap();
        assert_eq!(cell.index(), "822d57fffffffff");
    }

    #[test]
    fn normalizes_antimeridian_and_pole_inputs_for_h3() {
        let cloaker = H3ReferenceCloaker::new();
        let east = cloaker
            .from_wgs84(wgs84(0.0, 180.0), resolution(9))
            .unwrap();
        let west = cloaker
            .from_wgs84(wgs84(0.0, -180.0), resolution(9))
            .unwrap();
        assert_eq!(east, west);

        let north = cloaker
            .from_wgs84(wgs84(90.0, 180.0), resolution(9))
            .unwrap();
        let north_zero = cloaker.from_wgs84(wgs84(90.0, 0.0), resolution(9)).unwrap();
        assert_eq!(north, north_zero);
    }

    #[test]
    fn supports_every_h3_resolution() {
        let cloaker = H3ReferenceCloaker::new();
        for value in 0..=15 {
            let cell = cloaker
                .from_wgs84(wgs84(37.769377, -122.388903), resolution(value))
                .unwrap();
            assert_eq!(cell.resolution().value(), value);
            assert_eq!(cloaker.parse(cell.index()).unwrap(), cell);
        }
    }

    #[test]
    fn returns_coarser_parent_and_rejects_refinement() {
        let cloaker = H3ReferenceCloaker::new();
        let cell = cloaker.parse(KNOWN_INDEX).unwrap();
        let parent = cloaker.parent(cell, resolution(5)).unwrap();
        assert_eq!(parent.resolution().value(), 5);
        assert!(cloaker.parent(cell, resolution(10)).is_err());
    }

    #[test]
    fn encodes_the_exact_v1_fixture_and_round_trips() {
        let cell = H3ReferenceCloaker::new().parse(KNOWN_INDEX).unwrap();
        let bytes = cell.encode_v1().unwrap();
        assert_eq!(bytes.as_slice(), KNOWN_BYTES);
        assert_eq!(GeoCellV1::decode_v1(&bytes).unwrap(), cell);
        assert_eq!(cell.encode_v1().unwrap(), bytes);
    }

    #[test]
    fn decoder_rejects_wrong_size_and_trailing_data() {
        let mut trailing = KNOWN_BYTES.to_vec();
        trailing.push(0);
        assert!(GeoCellV1::decode_v1(&CanonicalBytes::from_vec(trailing)).is_err());
        assert!(
            GeoCellV1::decode_v1(&CanonicalBytes::from_vec(KNOWN_BYTES[..60].to_vec())).is_err()
        );
    }

    #[test]
    fn decoder_rejects_duplicate_unknown_and_wrong_fields() {
        let text = |value| Value::Text(value.to_owned());
        let valid = |key, value| (text(key), value);
        let duplicate = map_bytes(vec![
            valid("index", text(KNOWN_INDEX)),
            valid("index", text(KNOWN_INDEX)),
            valid("system", text("h3-v4")),
            valid("resolution", Value::Integer(9.into())),
            valid("cell_format", Value::Integer(1.into())),
        ]);
        assert!(GeoCellV1::decode_v1(&duplicate).is_err());

        let unknown = map_bytes(vec![
            valid("index", text(KNOWN_INDEX)),
            valid("system", text("h3-v4")),
            valid("resolution", Value::Integer(9.into())),
            valid("cell_format", Value::Integer(1.into())),
            valid("extra", text("nope")),
        ]);
        assert!(GeoCellV1::decode_v1(&unknown).is_err());

        let wrong_type = map_bytes(vec![
            valid("index", Value::Integer(1.into())),
            valid("system", text("h3-v4")),
            valid("resolution", Value::Integer(9.into())),
            valid("cell_format", Value::Integer(1.into())),
        ]);
        assert!(GeoCellV1::decode_v1(&wrong_type).is_err());
    }

    #[test]
    fn decoder_rejects_wrong_format_system_and_resolution() {
        let text = |value| Value::Text(value.to_owned());
        let make = |format, system, declared| {
            map_bytes(vec![
                (text("index"), text(KNOWN_INDEX)),
                (text("system"), text(system)),
                (text("resolution"), Value::Integer(declared.into())),
                (text("cell_format"), Value::Integer(format.into())),
            ])
        };
        assert!(GeoCellV1::decode_v1(&make(2, "h3-v4", 9)).is_err());
        assert!(GeoCellV1::decode_v1(&make(1, "s2-v1", 9)).is_err());
        assert!(GeoCellV1::decode_v1(&make(1, "h3-v4", 8)).is_err());
    }

    #[test]
    fn decoder_rejects_noncanonical_cbor_ordering() {
        let text = |value| Value::Text(value.to_owned());
        let noncanonical = map_bytes(vec![
            (text("system"), text("h3-v4")),
            (text("index"), text(KNOWN_INDEX)),
            (text("resolution"), Value::Integer(9.into())),
            (text("cell_format"), Value::Integer(1.into())),
        ]);
        let mut cursor = Cursor::new(noncanonical.as_slice());
        assert!(ciborium::from_reader::<Value, _>(&mut cursor).is_ok());
        assert!(GeoCellV1::decode_v1(&noncanonical).is_err());
    }
}
