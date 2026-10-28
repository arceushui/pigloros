//! Accepted ADR-110 E16 SNL1 at its public artifact seam.
//! Ciborium and a literal vector supply independent encoding oracles.

use ciborium::Value;
use pos_crypto::subject_key::SubjectKeyUseV1;
use pos_crypto::subject_nonce_ledger::{
    SubjectNonceLedgerErrorV1 as Error, SubjectNonceLedgerRowV1 as Row,
    SubjectNonceLedgerV1 as Ledger, EXHAUSTED_SUBJECT_NONCE_COUNTER,
    MAX_SUBJECT_NONCE_LEDGER_BYTES,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const OWNER: &str = "subject:000102030405060708090a0b0c0d0e0f";
const GOLDEN: &str = concat!(
    "8344534e4c3101818778287375626a6563743a303030313032303330343035303630",
    "373038303930613062306330643065306600015820111111111111111111111111",
    "1111111111111111111111111111111111111111830102030102",
);

fn row() -> Row {
    Row {
        owner_id: OWNER.to_owned(),
        epoch: 1,
        root_material_digest: [0x11; 32],
        store_file_id: [2, 3],
        data_next: 1,
        bootstrap_next: 2,
    }
}

fn hex(value: &str) -> TestResult<Vec<u8>> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect()
}

fn wire_row(row: &Row) -> Value {
    Value::Array(wire_fields(row))
}

fn wire_fields(row: &Row) -> Vec<Value> {
    vec![
        Value::Text(row.owner_id.clone()),
        Value::Integer(0.into()),
        Value::Integer(row.epoch.into()),
        Value::Bytes(row.root_material_digest.to_vec()),
        Value::Array(vec![
            Value::Integer(1.into()),
            Value::Integer(row.store_file_id[0].into()),
            Value::Integer(row.store_file_id[1].into()),
        ]),
        Value::Integer(row.data_next.into()),
        Value::Integer(row.bootstrap_next.into()),
    ]
}

fn document(rows: Vec<Value>) -> Vec<Value> {
    vec![
        Value::Bytes(b"SNL1".to_vec()),
        Value::Integer(1.into()),
        Value::Array(rows),
    ]
}

fn encode(value: &[Value]) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

fn independent(rows: &[Row]) -> TestResult<Vec<u8>> {
    encode(&document(rows.iter().map(wire_row).collect()))
}

#[test]
fn literal_vector_and_empty_ledger_round_trip() -> TestResult {
    let expected = hex(GOLDEN)?;
    let rows = vec![row()];
    assert_eq!(independent(&rows)?, expected);
    let ledger = Ledger::new(rows.clone())?;
    assert_eq!(ledger.as_bytes(), expected);
    assert_eq!(Ledger::from_bytes(&expected)?, ledger);
    assert_eq!(ledger.rows().len(), 1);
    assert_eq!(ledger.rows().cloned().collect::<Vec<_>>(), rows);
    assert_eq!(ledger.clone(), ledger);
    assert!(!format!("{ledger:?}").is_empty());
    assert_eq!(Ledger::new(Vec::new())?.as_bytes(), b"\x83\x44SNL1\x01\x80");
    let empty = Ledger::from_bytes(b"\x83\x44SNL1\x01\x80")?;
    assert_eq!(empty.rows().len(), 0);
    assert_eq!(empty, Ledger::new(Vec::new())?);
    Ok(())
}

#[test]
fn identities_follow_encoded_owner_then_epoch_and_preserve_all_metadata() -> TestResult {
    assert_eq!(EXHAUSTED_SUBJECT_NONCE_COUNTER, 0x1_0000_0000);
    let mut rows = Vec::new();
    for epoch in [1, 23, 24, 255, 256, 65_535, 65_536, u64::MAX] {
        rows.push(Row {
            epoch,
            store_file_id: [u64::MAX, 0],
            root_material_digest: [0; 32],
            data_next: 0xffff_ffff,
            bootstrap_next: 0x1_0000_0000,
            ..row()
        });
    }
    rows.push(Row {
        owner_id: "subject:ffffffffffffffffffffffffffffffff".to_owned(),
        epoch: 1,
        store_file_id: [0, u64::MAX],
        data_next: 0x1_0000_0000,
        bootstrap_next: 1,
        ..row()
    });
    let expected = independent(&rows)?;
    let ledger = Ledger::new(rows.clone())?;
    assert_eq!(ledger.as_bytes(), expected);
    assert_eq!(Ledger::from_bytes(&expected)?, ledger);
    assert_eq!(ledger.rows().cloned().collect::<Vec<_>>(), rows);
    Ok(())
}

#[test]
fn repeated_identity_cannot_change_its_digest_store_or_counters() -> TestResult {
    let first = row();
    for second in [
        first.clone(),
        Row {
            root_material_digest: [0x22; 32],
            ..first.clone()
        },
        Row {
            store_file_id: [9, 10],
            ..first.clone()
        },
        Row {
            data_next: 4,
            bootstrap_next: 5,
            ..first.clone()
        },
    ] {
        let rows = vec![first.clone(), second];
        assert_eq!(Ledger::new(rows.clone()), Err(Error::InvalidOrder));
        assert_eq!(
            Ledger::from_bytes(&independent(&rows)?),
            Err(Error::InvalidOrder)
        );
    }
    for second in [
        Row {
            owner_id: "subject:00000000000000000000000000000001".to_owned(),
            ..first.clone()
        },
        first.clone(),
    ] {
        let rows = vec![
            Row {
                epoch: 2,
                ..first.clone()
            },
            second,
        ];
        assert_eq!(Ledger::new(rows.clone()), Err(Error::InvalidOrder));
        assert_eq!(
            Ledger::from_bytes(&independent(&rows)?),
            Err(Error::InvalidOrder)
        );
    }
    Ok(())
}

#[test]
fn owner_epoch_and_each_counter_have_independent_validation() -> TestResult {
    for owner in [
        "",
        "person:000102030405060708090a0b0c0d0e0f",
        "subject:000102030405060708090A0B0C0D0E0F",
        "subject:00000000000000000000000000000000",
        "subject:000102030405060708090a0b0c0d0e0g",
        "subject:1",
    ] {
        let bad = Row {
            owner_id: owner.to_owned(),
            ..row()
        };
        assert_eq!(Ledger::new(vec![bad.clone()]), Err(Error::InvalidRow));
        assert_eq!(
            Ledger::from_bytes(&independent(&[bad])?),
            Err(Error::InvalidRow)
        );
    }
    let zero_epoch = Row { epoch: 0, ..row() };
    assert_eq!(
        Ledger::new(vec![zero_epoch.clone()]),
        Err(Error::InvalidRow)
    );
    assert_eq!(
        Ledger::from_bytes(&independent(&[zero_epoch])?),
        Err(Error::InvalidRow)
    );
    for counter in [0, 0x1_0000_0001, u64::MAX] {
        for bad in [
            Row {
                data_next: counter,
                ..row()
            },
            Row {
                bootstrap_next: counter,
                ..row()
            },
        ] {
            assert_eq!(Ledger::new(vec![bad.clone()]), Err(Error::InvalidRow));
            assert_eq!(
                Ledger::from_bytes(&independent(&[bad])?),
                Err(Error::InvalidRow)
            );
        }
    }
    let oversized_owner = Row {
        owner_id: "x".repeat(41),
        ..row()
    };
    assert_eq!(
        Ledger::new(vec![oversized_owner.clone()]),
        Err(Error::InvalidRow)
    );
    assert_eq!(
        Ledger::from_bytes(&independent(&[oversized_owner])?),
        Err(Error::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn every_row_field_requires_its_exact_wire_type_and_shape() -> TestResult {
    let original = wire_fields(&row());
    for field in 0..7 {
        let mut bad = original.clone();
        bad[field] = Value::Null;
        assert_eq!(
            Ledger::from_bytes(&encode(&document(vec![Value::Array(bad)]))?),
            Err(Error::InvalidEncoding)
        );
    }
    for (field, value, error) in [
        (1, Value::Integer(1.into()), Error::InvalidRow),
        (2, Value::Integer((-1).into()), Error::InvalidEncoding),
        (3, Value::Bytes(vec![0; 31]), Error::InvalidEncoding),
        (3, Value::Bytes(vec![0; 33]), Error::InvalidEncoding),
        (4, Value::Array(vec![]), Error::InvalidEncoding),
    ] {
        let mut bad = original.clone();
        bad[field] = value;
        assert_eq!(
            Ledger::from_bytes(&encode(&document(vec![Value::Array(bad)]))?),
            Err(error)
        );
    }
    for value in [
        Value::Array(vec![]),
        Value::Array(vec![Value::Null; 8]),
        Value::Null,
    ] {
        assert_eq!(
            Ledger::from_bytes(&encode(&document(vec![value]))?),
            Err(Error::InvalidEncoding)
        );
    }
    for (store, error) in [
        (
            vec![Value::Integer(1.into()), Value::Integer(2.into())],
            Error::InvalidEncoding,
        ),
        (vec![Value::Integer(1.into()); 4], Error::InvalidEncoding),
        (
            vec![
                Value::Integer(0.into()),
                Value::Integer(2.into()),
                Value::Integer(3.into()),
            ],
            Error::UnsupportedPlatform,
        ),
        (
            vec![
                Value::Integer(2.into()),
                Value::Integer(2.into()),
                Value::Integer(3.into()),
            ],
            Error::UnsupportedPlatform,
        ),
        (
            vec![
                Value::Null,
                Value::Integer(2.into()),
                Value::Integer(3.into()),
            ],
            Error::InvalidEncoding,
        ),
        (
            vec![
                Value::Integer(1.into()),
                Value::Null,
                Value::Integer(3.into()),
            ],
            Error::InvalidEncoding,
        ),
        (
            vec![
                Value::Integer(1.into()),
                Value::Integer(2.into()),
                Value::Null,
            ],
            Error::InvalidEncoding,
        ),
    ] {
        let mut bad = original.clone();
        bad[4] = Value::Array(store);
        assert_eq!(
            Ledger::from_bytes(&encode(&document(vec![Value::Array(bad)]))?),
            Err(error)
        );
    }
    Ok(())
}

#[test]
fn rejects_wrong_outer_format_and_untrusted_declared_counts() -> TestResult {
    let original = document(vec![wire_row(&row())]);
    for (field, value, error) in [
        (0, Value::Bytes(b"SNL2".to_vec()), Error::InvalidEncoding),
        (0, Value::Text("SNL1".to_owned()), Error::InvalidEncoding),
        (0, Value::Bytes(vec![0; 3]), Error::InvalidEncoding),
        (1, Value::Integer(0.into()), Error::UnsupportedVersion),
        (1, Value::Integer(2.into()), Error::UnsupportedVersion),
        (1, Value::Null, Error::InvalidEncoding),
        (2, Value::Null, Error::InvalidEncoding),
    ] {
        let mut bad = original.clone();
        bad[field] = value;
        assert_eq!(Ledger::from_bytes(&encode(&bad)?), Err(error));
    }
    for count in [1_048_576_u64, 1_048_577, u64::MAX] {
        let mut bytes = b"\x83\x44SNL1\x01\x9b".to_vec();
        bytes.extend_from_slice(&count.to_be_bytes());
        // The first two counts deliberately need a shortest-form u32 head.
        if count != u64::MAX {
            bytes.truncate(8);
            bytes[7] = 0x9a;
            bytes.extend_from_slice(&count.to_be_bytes()[4..]);
        }
        let error = if count == 1_048_576 {
            Error::InvalidEncoding
        } else {
            Error::BoundsExceeded
        };
        assert_eq!(Ledger::from_bytes(&bytes), Err(error));
    }
    Ok(())
}

#[test]
fn rejects_every_truncated_prefix_trailing_data_and_noncanonical_items() -> TestResult {
    let bytes = hex(GOLDEN)?;
    for end in 0..bytes.len() {
        assert!(Ledger::from_bytes(&bytes[..end]).is_err(), "prefix {end}");
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(Ledger::from_bytes(&trailing), Err(Error::InvalidEncoding));
    // Outer array, magic bstr, version, rows array, row array and owner text.
    for (offset, replacement) in [
        (0, 0x9f),
        (1, 0x5f),
        (6, 0x18),
        (7, 0x9f),
        (8, 0x9f),
        (9, 0x7f),
    ] {
        let mut bad = bytes.clone();
        bad[offset] = replacement;
        assert!(Ledger::from_bytes(&bad).is_err(), "offset {offset}");
    }
    // Replace each shortest-form header or unsigned scalar by an overlong form.
    for (offset, width, replacement) in [
        (0, 1, vec![0x98, 3]),
        (1, 1, vec![0x58, 4]),
        (6, 1, vec![0x18, 1]),
        (7, 1, vec![0x98, 1]),
        (8, 1, vec![0x98, 7]),
        (9, 2, vec![0x79, 0, 40]),
        (51, 1, vec![0x18, 0]),
        (52, 1, vec![0x18, 1]),
        (53, 2, vec![0x59, 0, 32]),
        (87, 1, vec![0x98, 3]),
        (88, 1, vec![0x18, 1]),
        (89, 1, vec![0x18, 2]),
        (90, 1, vec![0x18, 3]),
        (91, 1, vec![0x18, 1]),
        (92, 1, vec![0x18, 2]),
    ] {
        let mut bad = bytes.clone();
        bad.splice(offset..offset + width, replacement);
        assert_eq!(
            Ledger::from_bytes(&bad),
            Err(Error::InvalidEncoding),
            "offset {offset}"
        );
    }
    for cardinality in [0x82, 0x84, 0xa3, 0xc0] {
        let mut bad = bytes.clone();
        bad[0] = cardinality;
        assert_eq!(Ledger::from_bytes(&bad), Err(Error::InvalidEncoding));
    }
    Ok(())
}

#[test]
fn whole_file_bound_includes_every_header_and_accepts_exactly_one_mib() -> TestResult {
    assert_eq!(MAX_SUBJECT_NONCE_LEDGER_BYTES, 1_048_576);
    let mut rows = minimal_full_ledger_rows();
    let last = &mut rows[12_335];
    // Integer widths add exactly 2 + 4 bytes to reach the accepted byte bound.
    last.store_file_id = [256, 65_536];
    let exact = independent(&rows)?;
    assert_eq!(exact.len(), 1_048_576);
    let ledger = Ledger::new(rows.clone())?;
    assert_eq!(ledger.as_bytes(), exact);
    assert_eq!(Ledger::from_bytes(&exact)?, ledger);
    rows[12_335].bootstrap_next = 24;
    let one_over = independent(&rows)?;
    assert_eq!(one_over.len(), 1_048_577);
    assert_eq!(Ledger::new(rows), Err(Error::BoundsExceeded));
    assert_eq!(Ledger::from_bytes(&one_over), Err(Error::BoundsExceeded));
    Ok(())
}

#[test]
fn errors_are_closed_and_payload_free() {
    for error in [
        Error::InvalidEncoding,
        Error::BoundsExceeded,
        Error::InvalidRow,
        Error::InvalidOrder,
        Error::UnsupportedVersion,
        Error::UnsupportedPlatform,
        Error::RowMismatch,
        Error::CounterExhausted,
    ] {
        let copy = error;
        assert_eq!(copy, error);
        assert!(!format!("{error:?}").is_empty());
        assert!(!error.to_string().contains(OWNER));
    }
}

fn minimal_full_ledger_rows() -> Vec<Row> {
    // A minimal row is 85 bytes. The complete header for 12,336 rows is 10.
    (1..=12_336)
        .map(|id| Row {
            owner_id: format!("subject:{id:032x}"),
            store_file_id: [1, 1],
            data_next: 1,
            bootstrap_next: 1,
            ..row()
        })
        .collect()
}

#[test]
fn counter_candidates_preserve_other_domains_subjects_and_epochs() -> TestResult {
    let mut rows = vec![
        row(),
        Row { epoch: 2, ..row() },
        Row {
            owner_id: "subject:ffffffffffffffffffffffffffffffff".to_owned(),
            ..row()
        },
    ];
    for (index, key_use) in [
        (0, SubjectKeyUseV1::Data),
        (1, SubjectKeyUseV1::Bootstrap),
        (2, SubjectKeyUseV1::Data),
    ] {
        let ledger = Ledger::new(rows.clone())?;
        let original = ledger.clone();
        let expected = rows[index].clone();
        let candidate = ledger.advance_counter(&expected, key_use)?;
        assert_eq!(ledger, original);
        assert_eq!(ledger.advance_counter(&expected, key_use)?, candidate);
        match key_use {
            SubjectKeyUseV1::Data => rows[index].data_next += 1,
            SubjectKeyUseV1::Bootstrap => rows[index].bootstrap_next += 1,
        }
        assert_eq!(candidate.as_bytes(), independent(&rows)?);
        assert_eq!(candidate.rows().cloned().collect::<Vec<_>>(), rows);
        assert_eq!(Ledger::from_bytes(candidate.as_bytes())?, candidate);
        assert_eq!(
            candidate.advance_counter(&expected, key_use),
            Err(Error::RowMismatch)
        );
    }
    Ok(())
}

#[test]
fn each_counter_crosses_encoding_boundaries_then_stops_at_exhaustion() -> TestResult {
    for key_use in [SubjectKeyUseV1::Data, SubjectKeyUseV1::Bootstrap] {
        for counter in [
            1,
            22,
            23,
            24,
            254,
            255,
            256,
            65_534,
            65_535,
            65_536,
            0xffff_fffe,
            0xffff_ffff,
        ] {
            let mut expected = Row {
                data_next: EXHAUSTED_SUBJECT_NONCE_COUNTER,
                bootstrap_next: EXHAUSTED_SUBJECT_NONCE_COUNTER,
                ..row()
            };
            match key_use {
                SubjectKeyUseV1::Data => expected.data_next = counter,
                SubjectKeyUseV1::Bootstrap => expected.bootstrap_next = counter,
            }
            let ledger = Ledger::new([expected.clone()])?;
            let candidate = ledger.advance_counter(&expected, key_use)?;
            match key_use {
                SubjectKeyUseV1::Data => expected.data_next = counter + 1,
                SubjectKeyUseV1::Bootstrap => expected.bootstrap_next = counter + 1,
            }
            assert_eq!(candidate.as_bytes(), independent(&[expected.clone()])?);
            assert_eq!(Ledger::from_bytes(candidate.as_bytes())?, candidate);
            if counter == 0xffff_ffff {
                assert_eq!(
                    candidate.advance_counter(&expected, key_use),
                    Err(Error::CounterExhausted)
                );
                assert_eq!(candidate.as_bytes(), independent(&[expected])?);
            }
        }
    }
    Ok(())
}

#[test]
fn counter_candidates_require_the_entire_exact_existing_row() -> TestResult {
    let expected = row();
    let ledger = Ledger::new([expected.clone()])?;
    let original = ledger.clone();
    let mut mismatches = Vec::new();
    for replacement in ["subject:ffffffffffffffffffffffffffffffff", "invalid-owner"] {
        mismatches.push(Row {
            owner_id: replacement.to_owned(),
            ..expected.clone()
        });
    }
    mismatches.extend([
        Row {
            epoch: 2,
            ..expected.clone()
        },
        Row {
            epoch: 0,
            ..expected.clone()
        },
        Row {
            root_material_digest: [0x22; 32],
            ..expected.clone()
        },
        Row {
            store_file_id: [9, 3],
            ..expected.clone()
        },
        Row {
            store_file_id: [2, 9],
            ..expected.clone()
        },
        Row {
            data_next: 2,
            ..expected.clone()
        },
        Row {
            bootstrap_next: 3,
            ..expected.clone()
        },
    ]);
    for key_use in [SubjectKeyUseV1::Data, SubjectKeyUseV1::Bootstrap] {
        assert_eq!(
            Ledger::new([])?.advance_counter(&expected, key_use),
            Err(Error::RowMismatch)
        );
        for mismatch in &mismatches {
            assert_eq!(
                ledger.advance_counter(mismatch, key_use),
                Err(Error::RowMismatch)
            );
        }
    }
    assert_eq!(ledger, original);
    Ok(())
}

#[test]
fn counter_encoding_growth_cannot_exceed_the_complete_file_bound() -> TestResult {
    for key_use in [SubjectKeyUseV1::Data, SubjectKeyUseV1::Bootstrap] {
        for (counter, store_file_id, growth) in [
            (23, [256, 65_536], 1),
            (255, [24, 65_536], 1),
            (65_535, [1, 65_536], 2),
            (0xffff_ffff, [1, 256], 4),
        ] {
            let mut rows = minimal_full_ledger_rows();
            let last = &mut rows[12_335];
            last.store_file_id = store_file_id;
            match key_use {
                SubjectKeyUseV1::Data => last.data_next = counter,
                SubjectKeyUseV1::Bootstrap => last.bootstrap_next = counter,
            }
            let expected = last.clone();
            let ledger = Ledger::new(rows.clone())?;
            let original = independent(&rows)?;
            assert_eq!(original.len(), MAX_SUBJECT_NONCE_LEDGER_BYTES);
            assert_eq!(
                ledger.advance_counter(&expected, key_use),
                Err(Error::BoundsExceeded)
            );
            assert_eq!(ledger.as_bytes(), original);
            match key_use {
                SubjectKeyUseV1::Data => rows[12_335].data_next += 1,
                SubjectKeyUseV1::Bootstrap => rows[12_335].bootstrap_next += 1,
            }
            assert_eq!(
                independent(&rows)?.len(),
                MAX_SUBJECT_NONCE_LEDGER_BYTES + growth
            );
        }
    }
    Ok(())
}
