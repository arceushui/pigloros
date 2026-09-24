use ciborium::value::Value;
use pos_core::{
    Hash, ManifestAdmissionCatalogInputV1, ManifestAdmissionCatalogRowV1,
    ManifestAdmissionCatalogV1, ManifestOwnerLinkErrorV1, ManifestSlotAdmissionReceiptInputV1,
    ManifestSlotAdmissionReceiptV1, ManifestSlotBindingInputV1, ManifestSlotBindingRowV1,
    ManifestSlotBindingV1, PluginId, MAX_MANIFEST_ADMISSION_CATALOG_BYTES_V1,
    MAX_MANIFEST_OWNER_PLUGINS_V1, MAX_MANIFEST_SLOT_ADMISSION_RECEIPT_BYTES_V1,
    MAX_MANIFEST_SLOT_BINDING_BYTES_V1,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

const fn plugin(byte: u8) -> PluginId {
    PluginId::from_ulid(ulid::Ulid::from_bytes([byte; 16]))
}

fn catalog_row(slot: &str, id: u8) -> ManifestAdmissionCatalogRowV1 {
    ManifestAdmissionCatalogRowV1 {
        stable_slot: slot.to_owned(),
        plugin_id: plugin(id),
        plugin_name: "same-name".to_owned(),
        plugin_version: "1.0".to_owned(),
        implementation_hash: hash(10),
        eop1_native_digest: hash(11),
        closure_hash: hash(12),
    }
}

fn catalog_input() -> ManifestAdmissionCatalogInputV1 {
    ManifestAdmissionCatalogInputV1 {
        owner_id: [9; 32],
        configuration_generation: 7,
        rows: vec![catalog_row("first", 1), catalog_row("second", 2)],
    }
}

fn binding_row(slot: &str, id: u8) -> ManifestSlotBindingRowV1 {
    ManifestSlotBindingRowV1 {
        stable_slot: slot.to_owned(),
        plugin_id: plugin(id),
        eop1_wal1_hash: hash(11),
        closure_hash: hash(12),
    }
}

fn binding_input() -> ManifestSlotBindingInputV1 {
    ManifestSlotBindingInputV1 {
        scope: hash(2),
        wcs1_hash: hash(3),
        rows: vec![binding_row("first", 1), binding_row("second", 2)],
    }
}

const fn receipt_input() -> ManifestSlotAdmissionReceiptInputV1 {
    ManifestSlotAdmissionReceiptInputV1 {
        owner_id: [9; 32],
        configuration_generation: 7,
        scope: hash(2),
        wcs1_hash: hash(3),
        mca1_hash: hash(4),
        admission_operation_id: hash(5),
        previous_visible_lcq1_hash: None,
        expected_inventory_generation: None,
        msb1_hash: hash(6),
        coordinator_key_evidence_hash: hash(7),
        signature: [8; 64],
    }
}

fn encoded(value: &Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

fn changed_wire(
    bytes: &[u8],
    change: impl FnOnce(&mut Value),
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut value: Value = ciborium::from_reader(bytes)?;
    change(&mut value);
    encoded(&value)
}

fn replace_top(
    bytes: &[u8],
    index: usize,
    replacement: Value,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    changed_wire(bytes, |value| {
        if let Value::Array(fields) = value {
            fields[index] = replacement;
        }
    })
}

fn replace_first_row(
    bytes: &[u8],
    index: usize,
    replacement: Value,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    changed_wire(bytes, |value| {
        if let Value::Array(fields) = value {
            if let Value::Array(rows) = &mut fields[4] {
                if let Value::Array(row) = &mut rows[0] {
                    row[index] = replacement;
                }
            }
        }
    })
}

#[test]
fn literal_empty_catalog_and_binding_pin_exact_bytes_and_digest() -> TestResult {
    let catalog = ManifestAdmissionCatalogV1::new(ManifestAdmissionCatalogInputV1 {
        owner_id: [9; 32],
        configuration_generation: 7,
        rows: Vec::new(),
    })?;
    let mut catalog_bytes = vec![0x85, 0x44, b'M', b'C', b'A', b'1', 1, 0x58, 0x20];
    catalog_bytes.extend_from_slice(&[9; 32]);
    catalog_bytes.extend_from_slice(&[7, 0x80]);
    assert_eq!(catalog.to_canonical_cbor(), catalog_bytes);
    assert_eq!(
        ManifestAdmissionCatalogV1::from_canonical_cbor(&catalog_bytes)?,
        catalog
    );
    // Independently computed with b3sum over the literal domain/NUL/CBOR bytes.
    assert_eq!(
        catalog.digest().as_bytes(),
        &[
            0x56, 0x5b, 0x6f, 0x4b, 0x67, 0xe8, 0xba, 0xfe, 0x07, 0xa3, 0xcc, 0x34, 0x52, 0x79,
            0xea, 0xa4, 0x69, 0xb1, 0x8a, 0xc9, 0xb0, 0xe0, 0x02, 0xa0, 0x6a, 0x01, 0x67, 0xc7,
            0xac, 0xa4, 0x61, 0x22,
        ]
    );

    let binding = ManifestSlotBindingV1::new(ManifestSlotBindingInputV1 {
        scope: hash(2),
        wcs1_hash: hash(3),
        rows: Vec::new(),
    })?;
    let mut binding_bytes = vec![0x85, 0x44, b'M', b'S', b'B', b'1', 1, 0x58, 0x20];
    binding_bytes.extend_from_slice(&[2; 32]);
    binding_bytes.extend_from_slice(&[0x58, 0x20]);
    binding_bytes.extend_from_slice(&[3; 32]);
    binding_bytes.push(0x80);
    assert_eq!(binding.to_canonical_cbor(), binding_bytes);
    assert_eq!(
        ManifestSlotBindingV1::from_canonical_cbor(&binding_bytes)?,
        binding
    );
    assert_eq!(
        binding.digest().as_bytes(),
        &[
            0x28, 0x56, 0x42, 0xee, 0x21, 0xd8, 0xcd, 0xd7, 0x31, 0xe9, 0x2d, 0xb8, 0x87, 0x44,
            0xa8, 0x7c, 0x05, 0x43, 0x30, 0x29, 0x74, 0x00, 0x3b, 0x21, 0x84, 0xa8, 0x1f, 0xe2,
            0x11, 0xf1, 0x27, 0x84,
        ]
    );
    Ok(())
}

#[test]
fn complete_same_name_rows_roundtrip_without_key_collapse() -> TestResult {
    let catalog = ManifestAdmissionCatalogV1::new(catalog_input())?;
    let binding = ManifestSlotBindingV1::new(binding_input())?;
    assert_eq!(catalog.as_input().rows[0].plugin_name, "same-name");
    assert_eq!(catalog.as_input().rows[1].plugin_name, "same-name");
    assert_ne!(
        catalog.as_input().rows[0].plugin_id,
        catalog.as_input().rows[1].plugin_id
    );
    assert_eq!(
        ManifestAdmissionCatalogV1::from_canonical_cbor(&catalog.to_canonical_cbor())?,
        catalog
    );
    assert_eq!(
        ManifestSlotBindingV1::from_canonical_cbor(&binding.to_canonical_cbor())?,
        binding
    );
    assert_eq!(binding.as_input().rows.len(), catalog.as_input().rows.len());
    Ok(())
}

#[test]
fn catalog_row_bounds_order_slots_ids_and_hashes_fail_closed() {
    let mut catalog = catalog_input();
    catalog.rows[1].stable_slot = catalog.rows[0].stable_slot.clone();
    assert_eq!(
        ManifestAdmissionCatalogV1::new(catalog),
        Err(ManifestOwnerLinkErrorV1::InvalidRowOrder)
    );
    let mut catalog = catalog_input();
    catalog.rows[1].plugin_id = catalog.rows[0].plugin_id;
    assert_eq!(
        ManifestAdmissionCatalogV1::new(catalog),
        Err(ManifestOwnerLinkErrorV1::DuplicatePluginId)
    );
    let mut catalog = catalog_input();
    catalog.rows.swap(0, 1);
    assert_eq!(
        ManifestAdmissionCatalogV1::new(catalog),
        Err(ManifestOwnerLinkErrorV1::InvalidRowOrder)
    );
    for slot in [
        "",
        "a/b",
        "é",
        "a b",
        "x0123456789x0123456789x0123456789x0123456789x0123456789x0123456789",
    ] {
        let mut catalog = catalog_input();
        catalog.rows[0].stable_slot = slot.to_owned();
        assert_eq!(
            ManifestAdmissionCatalogV1::new(catalog),
            Err(ManifestOwnerLinkErrorV1::FieldOutOfBounds)
        );
    }
    let mut catalog = catalog_input();
    catalog.rows[0].plugin_name.clear();
    assert_eq!(
        ManifestAdmissionCatalogV1::new(catalog),
        Err(ManifestOwnerLinkErrorV1::FieldOutOfBounds)
    );
    let mut catalog = catalog_input();
    catalog.configuration_generation = 0;
    assert_eq!(
        ManifestAdmissionCatalogV1::new(catalog),
        Err(ManifestOwnerLinkErrorV1::FieldOutOfBounds)
    );
    let mut catalog = catalog_input();
    catalog.rows[0].plugin_name = "n".repeat(129);
    assert_eq!(
        ManifestAdmissionCatalogV1::new(catalog),
        Err(ManifestOwnerLinkErrorV1::FieldOutOfBounds)
    );
    let mut catalog = catalog_input();
    catalog.rows[0].plugin_version.clear();
    assert_eq!(
        ManifestAdmissionCatalogV1::new(catalog),
        Err(ManifestOwnerLinkErrorV1::FieldOutOfBounds)
    );
    let mut catalog = catalog_input();
    catalog.rows[0].plugin_version = "v".repeat(65);
    assert_eq!(
        ManifestAdmissionCatalogV1::new(catalog),
        Err(ManifestOwnerLinkErrorV1::FieldOutOfBounds)
    );
    let mut catalog = catalog_input();
    catalog.rows[0].closure_hash = Hash::zero();
    assert_eq!(
        ManifestAdmissionCatalogV1::new(catalog),
        Err(ManifestOwnerLinkErrorV1::FieldOutOfBounds)
    );
    let mut catalog = catalog_input();
    catalog.rows[0].implementation_hash = Hash::zero();
    assert_eq!(
        ManifestAdmissionCatalogV1::new(catalog),
        Err(ManifestOwnerLinkErrorV1::FieldOutOfBounds)
    );
    let mut catalog = catalog_input();
    catalog.rows[0].eop1_native_digest = Hash::zero();
    assert_eq!(
        ManifestAdmissionCatalogV1::new(catalog),
        Err(ManifestOwnerLinkErrorV1::FieldOutOfBounds)
    );
}

#[test]
fn binding_row_bounds_order_ids_and_hashes_fail_closed() {
    let mut binding = binding_input();
    binding.rows[1].plugin_id = binding.rows[0].plugin_id;
    assert_eq!(
        ManifestSlotBindingV1::new(binding),
        Err(ManifestOwnerLinkErrorV1::DuplicatePluginId)
    );
    let mut binding = binding_input();
    binding.rows[0].eop1_wal1_hash = Hash::zero();
    assert_eq!(
        ManifestSlotBindingV1::new(binding),
        Err(ManifestOwnerLinkErrorV1::FieldOutOfBounds)
    );
    let mut binding = binding_input();
    binding.scope = Hash::zero();
    assert_eq!(
        ManifestSlotBindingV1::new(binding),
        Err(ManifestOwnerLinkErrorV1::FieldOutOfBounds)
    );
    let mut binding = binding_input();
    binding.wcs1_hash = Hash::zero();
    assert_eq!(
        ManifestSlotBindingV1::new(binding),
        Err(ManifestOwnerLinkErrorV1::FieldOutOfBounds)
    );
    let mut binding = binding_input();
    binding.rows[0].closure_hash = Hash::zero();
    assert_eq!(
        ManifestSlotBindingV1::new(binding),
        Err(ManifestOwnerLinkErrorV1::FieldOutOfBounds)
    );
    let mut binding = binding_input();
    binding.rows[0].stable_slot = "a/b".to_owned();
    assert_eq!(
        ManifestSlotBindingV1::new(binding),
        Err(ManifestOwnerLinkErrorV1::FieldOutOfBounds)
    );
    let mut binding = binding_input();
    binding.rows.swap(0, 1);
    assert_eq!(
        ManifestSlotBindingV1::new(binding),
        Err(ManifestOwnerLinkErrorV1::InvalidRowOrder)
    );
}

#[test]
fn full_256_row_limit_is_preserved_without_truncation() -> TestResult {
    let mut catalog = ManifestAdmissionCatalogInputV1 {
        owner_id: [9; 32],
        configuration_generation: 1,
        rows: Vec::new(),
    };
    let mut binding = ManifestSlotBindingInputV1 {
        scope: hash(2),
        wcs1_hash: hash(3),
        rows: Vec::new(),
    };
    for index in 0..MAX_MANIFEST_OWNER_PLUGINS_V1 {
        let id = u8::try_from(index)?;
        let slot = format!("slot-{index:03}");
        catalog.rows.push(catalog_row(&slot, id));
        binding.rows.push(binding_row(&slot, id));
    }
    let catalog_record = ManifestAdmissionCatalogV1::new(catalog.clone())?;
    let binding_record = ManifestSlotBindingV1::new(binding.clone())?;
    assert_eq!(catalog_record.as_input().rows.len(), 256);
    assert_eq!(binding_record.as_input().rows.len(), 256);
    assert_eq!(
        ManifestAdmissionCatalogV1::from_canonical_cbor(&catalog_record.to_canonical_cbor())?,
        catalog_record
    );
    assert_eq!(
        ManifestSlotBindingV1::from_canonical_cbor(&binding_record.to_canonical_cbor())?,
        binding_record
    );
    catalog.rows.push(catalog_row("slot-256", 0));
    binding.rows.push(binding_row("slot-256", 0));
    assert_eq!(
        ManifestAdmissionCatalogV1::new(catalog),
        Err(ManifestOwnerLinkErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        ManifestSlotBindingV1::new(binding),
        Err(ManifestOwnerLinkErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn receipt_pins_signature_preimage_and_all_three_null_pairs() -> TestResult {
    for (previous, inventory) in [
        (None, None),
        (None, Some(hash(15))),
        (Some(hash(14)), Some(hash(15))),
    ] {
        let mut input = receipt_input();
        input.previous_visible_lcq1_hash = previous;
        input.expected_inventory_generation = inventory;
        let record = ManifestSlotAdmissionReceiptV1::new(input)?;
        let bytes = record.to_canonical_cbor();
        assert_eq!(bytes[0], 0x8d);
        assert_eq!(
            ManifestSlotAdmissionReceiptV1::from_canonical_cbor(&bytes)?,
            record
        );
        let mut expected = b"pigloros.manifest-slot-admission-signature.v1\0".to_vec();
        expected.push(0x8c);
        expected.extend_from_slice(&bytes[1..bytes.len() - 66]);
        assert_eq!(record.signature_preimage(), expected);
    }
    let record = ManifestSlotAdmissionReceiptV1::new(receipt_input())?;
    let bytes = record.to_canonical_cbor();
    assert_eq!(bytes.len(), 314);
    assert_eq!(
        record.digest().as_bytes(),
        &[
            0x17, 0x28, 0x45, 0xb7, 0xe7, 0x70, 0x0c, 0x28, 0x47, 0xb3, 0xed, 0xbd, 0x6a, 0x8f,
            0x75, 0xdd, 0x8a, 0x42, 0x15, 0xb4, 0xc3, 0x4a, 0xd6, 0x6c, 0xa1, 0x2c, 0x1e, 0xbd,
            0xe4, 0x7c, 0x5d, 0xe6,
        ]
    );
    let mut preimage_hasher = blake3::Hasher::new();
    preimage_hasher.update(&record.signature_preimage());
    assert_eq!(
        preimage_hasher.finalize().as_bytes(),
        &[
            0xcf, 0x77, 0x03, 0x9c, 0xa5, 0xab, 0x9f, 0x94, 0xd7, 0xf8, 0x7c, 0x09, 0xf3, 0x2f,
            0x2b, 0xa9, 0x02, 0x23, 0xb5, 0x9c, 0xf9, 0x10, 0xd1, 0x91, 0xdf, 0x6b, 0x4c, 0xf3,
            0xbb, 0x13, 0x4f, 0x89,
        ]
    );
    Ok(())
}

#[test]
fn impossible_receipt_pre_state_and_zero_references_reject() {
    let mut input = receipt_input();
    input.previous_visible_lcq1_hash = Some(hash(14));
    assert_eq!(
        ManifestSlotAdmissionReceiptV1::new(input),
        Err(ManifestOwnerLinkErrorV1::InvalidPreState)
    );
    let mut input = receipt_input();
    input.expected_inventory_generation = Some(Hash::zero());
    assert_eq!(
        ManifestSlotAdmissionReceiptV1::new(input),
        Err(ManifestOwnerLinkErrorV1::FieldOutOfBounds)
    );
    let mut input = receipt_input();
    input.configuration_generation = 0;
    assert_eq!(
        ManifestSlotAdmissionReceiptV1::new(input),
        Err(ManifestOwnerLinkErrorV1::FieldOutOfBounds)
    );
    let mut input = receipt_input();
    input.previous_visible_lcq1_hash = Some(Hash::zero());
    input.expected_inventory_generation = Some(hash(15));
    assert_eq!(
        ManifestSlotAdmissionReceiptV1::new(input),
        Err(ManifestOwnerLinkErrorV1::FieldOutOfBounds)
    );
    for field in 0..7 {
        let mut input = receipt_input();
        match field {
            0 => input.scope = Hash::zero(),
            1 => input.wcs1_hash = Hash::zero(),
            2 => input.mca1_hash = Hash::zero(),
            3 => input.admission_operation_id = Hash::zero(),
            4 => input.msb1_hash = Hash::zero(),
            5 => input.coordinator_key_evidence_hash = Hash::zero(),
            _ => input.expected_inventory_generation = Some(Hash::zero()),
        }
        assert_eq!(
            ManifestSlotAdmissionReceiptV1::new(input),
            Err(ManifestOwnerLinkErrorV1::FieldOutOfBounds)
        );
    }
}

#[test]
fn malformed_nonpreferred_trailing_and_oversized_wire_rejects() -> TestResult {
    let catalog = ManifestAdmissionCatalogV1::new(catalog_input())?;
    let bytes = catalog.to_canonical_cbor();
    let wrong_magic = changed_wire(&bytes, |value| {
        if let Value::Array(fields) = value {
            fields[0] = Value::Bytes(b"BAD1".to_vec());
        }
    })?;
    assert_eq!(
        ManifestAdmissionCatalogV1::from_canonical_cbor(&wrong_magic),
        Err(ManifestOwnerLinkErrorV1::InvalidEncoding)
    );
    let wrong_version = changed_wire(&bytes, |value| {
        if let Value::Array(fields) = value {
            fields[1] = Value::Integer(2.into());
        }
    })?;
    assert_eq!(
        ManifestAdmissionCatalogV1::from_canonical_cbor(&wrong_version),
        Err(ManifestOwnerLinkErrorV1::UnsupportedVersion)
    );
    let short_row = changed_wire(&bytes, |value| {
        if let Value::Array(fields) = value {
            if let Value::Array(rows) = &mut fields[4] {
                if let Value::Array(row) = &mut rows[0] {
                    row.pop();
                }
            }
        }
    })?;
    assert_eq!(
        ManifestAdmissionCatalogV1::from_canonical_cbor(&short_row),
        Err(ManifestOwnerLinkErrorV1::InvalidEncoding)
    );
    let mut nonpreferred = bytes.clone();
    nonpreferred.splice(6..7, [0x18, 1]);
    assert_eq!(
        ManifestAdmissionCatalogV1::from_canonical_cbor(&nonpreferred),
        Err(ManifestOwnerLinkErrorV1::NonCanonical)
    );
    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(
        ManifestAdmissionCatalogV1::from_canonical_cbor(&trailing),
        Err(ManifestOwnerLinkErrorV1::InvalidEncoding)
    );
    assert_eq!(
        ManifestAdmissionCatalogV1::from_canonical_cbor(&vec![
            0;
            MAX_MANIFEST_ADMISSION_CATALOG_BYTES_V1
                + 1
        ]),
        Err(ManifestOwnerLinkErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        ManifestSlotBindingV1::from_canonical_cbor(&vec![
            0;
            MAX_MANIFEST_SLOT_BINDING_BYTES_V1 + 1
        ]),
        Err(ManifestOwnerLinkErrorV1::FieldOutOfBounds)
    );
    assert_eq!(
        ManifestSlotAdmissionReceiptV1::from_canonical_cbor(&vec![
            0;
            MAX_MANIFEST_SLOT_ADMISSION_RECEIPT_BYTES_V1
                + 1
        ]),
        Err(ManifestOwnerLinkErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn catalog_preflights_lengths_counts_and_utf8_before_decoding() -> TestResult {
    let bytes = ManifestAdmissionCatalogV1::new(catalog_input())?.to_canonical_cbor();
    assert_eq!(&bytes[42..46], &[0x82, 0x87, 0x65, b'f']);

    for malformed in [&[][..], &[0x98][..], &[0x9f][..], &bytes[..10]] {
        assert_eq!(
            ManifestAdmissionCatalogV1::from_canonical_cbor(malformed),
            Err(ManifestOwnerLinkErrorV1::InvalidEncoding)
        );
    }

    let mut excessive_rows = bytes.clone();
    excessive_rows.splice(42..43, [0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    assert_eq!(
        ManifestAdmissionCatalogV1::from_canonical_cbor(&excessive_rows),
        Err(ManifestOwnerLinkErrorV1::FieldOutOfBounds)
    );

    let mut excessive_text = bytes.clone();
    excessive_text.splice(44..45, [0x78, 0xff]);
    assert_eq!(
        ManifestAdmissionCatalogV1::from_canonical_cbor(&excessive_text),
        Err(ManifestOwnerLinkErrorV1::FieldOutOfBounds)
    );

    let mut invalid_utf8 = bytes;
    invalid_utf8[45] = 0xff;
    assert_eq!(
        ManifestAdmissionCatalogV1::from_canonical_cbor(&invalid_utf8),
        Err(ManifestOwnerLinkErrorV1::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn wrong_catalog_cbor_shapes_and_field_widths_reject() -> TestResult {
    assert_eq!(
        ManifestAdmissionCatalogV1::from_canonical_cbor(&encoded(&Value::Map(Vec::new()))?),
        Err(ManifestOwnerLinkErrorV1::InvalidEncoding)
    );
    let catalog = ManifestAdmissionCatalogV1::new(catalog_input())?;
    let bytes = catalog.to_canonical_cbor();
    let wrong_generation = changed_wire(&bytes, |value| {
        if let Value::Array(fields) = value {
            fields[3] = Value::Text("seven".to_owned());
        }
    })?;
    assert_eq!(
        ManifestAdmissionCatalogV1::from_canonical_cbor(&wrong_generation),
        Err(ManifestOwnerLinkErrorV1::InvalidEncoding)
    );
    let wrong_plugin_id = changed_wire(&bytes, |value| {
        if let Value::Array(fields) = value {
            if let Value::Array(rows) = &mut fields[4] {
                if let Value::Array(row) = &mut rows[0] {
                    row[1] = Value::Bytes(vec![1; 15]);
                }
            }
        }
    })?;
    assert_eq!(
        ManifestAdmissionCatalogV1::from_canonical_cbor(&wrong_plugin_id),
        Err(ManifestOwnerLinkErrorV1::InvalidEncoding)
    );
    let wrong_slot_type = changed_wire(&bytes, |value| {
        if let Value::Array(fields) = value {
            if let Value::Array(rows) = &mut fields[4] {
                if let Value::Array(row) = &mut rows[0] {
                    row[0] = Value::Bytes(b"first".to_vec());
                }
            }
        }
    })?;
    assert_eq!(
        ManifestAdmissionCatalogV1::from_canonical_cbor(&wrong_slot_type),
        Err(ManifestOwnerLinkErrorV1::InvalidEncoding)
    );
    let wrong_hash = changed_wire(&bytes, |value| {
        if let Value::Array(fields) = value {
            if let Value::Array(rows) = &mut fields[4] {
                if let Value::Array(row) = &mut rows[0] {
                    row[6] = Value::Text("not-a-hash".to_owned());
                }
            }
        }
    })?;
    assert_eq!(
        ManifestAdmissionCatalogV1::from_canonical_cbor(&wrong_hash),
        Err(ManifestOwnerLinkErrorV1::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn wrong_binding_cbor_shapes_and_nonpreferred_integer_reject() -> TestResult {
    let binding = ManifestSlotBindingV1::new(binding_input())?;
    let bytes = binding.to_canonical_cbor();
    let wrong_rows = changed_wire(&bytes, |value| {
        if let Value::Array(fields) = value {
            fields[4] = Value::Text("not-rows".to_owned());
        }
    })?;
    assert_eq!(
        ManifestSlotBindingV1::from_canonical_cbor(&wrong_rows),
        Err(ManifestOwnerLinkErrorV1::InvalidEncoding)
    );
    let wrong_row = changed_wire(&bytes, |value| {
        if let Value::Array(fields) = value {
            if let Value::Array(rows) = &mut fields[4] {
                rows[0] = Value::Integer(0.into());
            }
        }
    })?;
    assert_eq!(
        ManifestSlotBindingV1::from_canonical_cbor(&wrong_row),
        Err(ManifestOwnerLinkErrorV1::InvalidEncoding)
    );
    let mut nonpreferred = bytes;
    nonpreferred.splice(6..7, [0x18, 1]);
    assert_eq!(
        ManifestSlotBindingV1::from_canonical_cbor(&nonpreferred),
        Err(ManifestOwnerLinkErrorV1::NonCanonical)
    );
    Ok(())
}

#[test]
fn wrong_receipt_cbor_shapes_and_pre_state_reject() -> TestResult {
    let receipt = ManifestSlotAdmissionReceiptV1::new(receipt_input())?;
    let bytes = receipt.to_canonical_cbor();
    let wrong_signature = changed_wire(&bytes, |value| {
        if let Value::Array(fields) = value {
            fields[12] = Value::Bytes(vec![8; 63]);
        }
    })?;
    assert_eq!(
        ManifestSlotAdmissionReceiptV1::from_canonical_cbor(&wrong_signature),
        Err(ManifestOwnerLinkErrorV1::InvalidEncoding)
    );
    let wrong_previous = changed_wire(&bytes, |value| {
        if let Value::Array(fields) = value {
            fields[8] = Value::Text("not-a-hash".to_owned());
        }
    })?;
    assert_eq!(
        ManifestSlotAdmissionReceiptV1::from_canonical_cbor(&wrong_previous),
        Err(ManifestOwnerLinkErrorV1::InvalidEncoding)
    );
    let impossible_pair = changed_wire(&bytes, |value| {
        if let Value::Array(fields) = value {
            fields[8] = Value::Bytes(vec![14; 32]);
        }
    })?;
    assert_eq!(
        ManifestSlotAdmissionReceiptV1::from_canonical_cbor(&impossible_pair),
        Err(ManifestOwnerLinkErrorV1::InvalidPreState)
    );
    Ok(())
}

#[test]
fn catalog_decode_rejects_every_untrusted_field_and_excess_rows() -> TestResult {
    let bytes = ManifestAdmissionCatalogV1::new(catalog_input())?.to_canonical_cbor();
    assert_eq!(
        ManifestAdmissionCatalogV1::from_canonical_cbor(&[0xff]),
        Err(ManifestOwnerLinkErrorV1::InvalidEncoding)
    );
    for (index, replacement) in [
        (2, Value::Text("owner".into())),
        (3, Value::Integer((-1).into())),
        (4, Value::Text("rows".into())),
    ] {
        let wrong = replace_top(&bytes, index, replacement)?;
        assert_eq!(
            ManifestAdmissionCatalogV1::from_canonical_cbor(&wrong),
            Err(ManifestOwnerLinkErrorV1::InvalidEncoding)
        );
    }
    for (index, replacement) in [
        (2, Value::Bytes(vec![1; 4])),
        (3, Value::Bytes(vec![1; 4])),
        (4, Value::Text("implementation".into())),
        (5, Value::Text("policy".into())),
        (6, Value::Integer(1.into())),
    ] {
        let wrong = replace_first_row(&bytes, index, replacement)?;
        assert_eq!(
            ManifestAdmissionCatalogV1::from_canonical_cbor(&wrong),
            Err(ManifestOwnerLinkErrorV1::InvalidEncoding)
        );
    }
    let excessive = replace_top(&bytes, 4, Value::Array(vec![Value::Null; 257]))?;
    assert_eq!(
        ManifestAdmissionCatalogV1::from_canonical_cbor(&excessive),
        Err(ManifestOwnerLinkErrorV1::FieldOutOfBounds)
    );
    let invalid_record = replace_top(&bytes, 3, Value::Integer(0.into()))?;
    assert_eq!(
        ManifestAdmissionCatalogV1::from_canonical_cbor(&invalid_record),
        Err(ManifestOwnerLinkErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn binding_decode_rejects_every_untrusted_field_and_excess_rows() -> TestResult {
    let bytes = ManifestSlotBindingV1::new(binding_input())?.to_canonical_cbor();
    for (index, replacement, expected) in [
        (
            0,
            Value::Bytes(b"BAD1".to_vec()),
            ManifestOwnerLinkErrorV1::InvalidEncoding,
        ),
        (
            1,
            Value::Integer(2.into()),
            ManifestOwnerLinkErrorV1::UnsupportedVersion,
        ),
        (
            2,
            Value::Text("scope".into()),
            ManifestOwnerLinkErrorV1::InvalidEncoding,
        ),
        (
            3,
            Value::Bytes(vec![1; 31]),
            ManifestOwnerLinkErrorV1::InvalidEncoding,
        ),
        (
            4,
            Value::Text("rows".into()),
            ManifestOwnerLinkErrorV1::InvalidEncoding,
        ),
    ] {
        let wrong = replace_top(&bytes, index, replacement)?;
        assert_eq!(
            ManifestSlotBindingV1::from_canonical_cbor(&wrong),
            Err(expected)
        );
    }
    for (index, replacement) in [
        (0, Value::Bytes(b"first".to_vec())),
        (1, Value::Bytes(vec![1; 15])),
        (2, Value::Text("policy".into())),
        (3, Value::Bool(true)),
    ] {
        let wrong = replace_first_row(&bytes, index, replacement)?;
        assert_eq!(
            ManifestSlotBindingV1::from_canonical_cbor(&wrong),
            Err(ManifestOwnerLinkErrorV1::InvalidEncoding)
        );
    }
    let excessive = replace_top(&bytes, 4, Value::Array(vec![Value::Null; 257]))?;
    assert_eq!(
        ManifestSlotBindingV1::from_canonical_cbor(&excessive),
        Err(ManifestOwnerLinkErrorV1::FieldOutOfBounds)
    );
    let invalid_record = replace_top(&bytes, 2, Value::Bytes(vec![0; 32]))?;
    assert_eq!(
        ManifestSlotBindingV1::from_canonical_cbor(&invalid_record),
        Err(ManifestOwnerLinkErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn receipt_decode_rejects_every_untrusted_field_and_nonpreferred_width() -> TestResult {
    let receipt = ManifestSlotAdmissionReceiptV1::new(receipt_input())?;
    assert_eq!(receipt.as_input().configuration_generation, 7);
    let bytes = receipt.to_canonical_cbor();
    for (index, replacement, expected) in [
        (
            0,
            Value::Bytes(b"BAD1".to_vec()),
            ManifestOwnerLinkErrorV1::InvalidEncoding,
        ),
        (
            1,
            Value::Integer(2.into()),
            ManifestOwnerLinkErrorV1::UnsupportedVersion,
        ),
        (
            2,
            Value::Text("owner".into()),
            ManifestOwnerLinkErrorV1::InvalidEncoding,
        ),
        (
            3,
            Value::Integer((-1).into()),
            ManifestOwnerLinkErrorV1::InvalidEncoding,
        ),
        (
            4,
            Value::Text("scope".into()),
            ManifestOwnerLinkErrorV1::InvalidEncoding,
        ),
        (
            5,
            Value::Text("wcs1".into()),
            ManifestOwnerLinkErrorV1::InvalidEncoding,
        ),
        (
            6,
            Value::Text("mca1".into()),
            ManifestOwnerLinkErrorV1::InvalidEncoding,
        ),
        (
            7,
            Value::Text("operation".into()),
            ManifestOwnerLinkErrorV1::InvalidEncoding,
        ),
        (
            9,
            Value::Text("inventory".into()),
            ManifestOwnerLinkErrorV1::InvalidEncoding,
        ),
        (
            10,
            Value::Text("msb1".into()),
            ManifestOwnerLinkErrorV1::InvalidEncoding,
        ),
        (
            11,
            Value::Text("key".into()),
            ManifestOwnerLinkErrorV1::InvalidEncoding,
        ),
    ] {
        let wrong = replace_top(&bytes, index, replacement)?;
        assert_eq!(
            ManifestSlotAdmissionReceiptV1::from_canonical_cbor(&wrong),
            Err(expected)
        );
    }
    let mut nonpreferred = bytes;
    nonpreferred.splice(6..7, [0x18, 1]);
    assert_eq!(
        ManifestSlotAdmissionReceiptV1::from_canonical_cbor(&nonpreferred),
        Err(ManifestOwnerLinkErrorV1::NonCanonical)
    );
    Ok(())
}

#[test]
fn large_generation_widths_roundtrip_canonically() -> TestResult {
    for generation in [256, 65_536, u64::MAX] {
        let mut catalog = catalog_input();
        catalog.configuration_generation = generation;
        let catalog = ManifestAdmissionCatalogV1::new(catalog)?;
        assert_eq!(
            ManifestAdmissionCatalogV1::from_canonical_cbor(&catalog.to_canonical_cbor())?,
            catalog
        );
        let mut receipt = receipt_input();
        receipt.configuration_generation = generation;
        let receipt = ManifestSlotAdmissionReceiptV1::new(receipt)?;
        assert_eq!(
            ManifestSlotAdmissionReceiptV1::from_canonical_cbor(&receipt.to_canonical_cbor())?,
            receipt
        );
    }
    Ok(())
}
