use super::*;

fn successor() -> Result<Vec<Value>, ProtocolError> {
    let mut fields = unsigned();
    fields[5] = bytes([250; 32]);
    fields[6] = bytes([251; 32]);
    let mut entries = vec![object(0), object(1)];
    entries.push(Value::Array(vec![
        integer(1),
        bytes([250; 32]),
        bytes([80; 32]),
        integer(64),
    ]));
    entries.push(object(2));
    entries.push(Value::Array(vec![
        integer(2),
        bytes([251; 32]),
        bytes([81; 32]),
        integer(96),
    ]));
    entries.extend((3..16).map(object));
    fields[10] = Value::Array(entries);
    // Exercise the public decoder before using this as transition input.
    InstallationManifest::from_cbor(&manifest_bytes(fields.clone())?)?;
    Ok(fields)
}

#[test]
fn revocation_transition_preserves_existing_objects_and_fixed_configuration() -> TestResult {
    let previous = InstallationManifest::from_cbor(&manifest_bytes(unsigned())?)?;
    let next = InstallationManifest::from_cbor(&manifest_bytes(successor()?)?)?;
    previous.validate_revocation_successor(&next)?;
    assert_eq!(next.objects().len(), previous.objects().len() + 2);
    assert!(previous.validate_revocation_successor(&previous).is_err());
    assert!(next.validate_revocation_successor(&previous).is_err());
    Ok(())
}

#[test]
fn revocation_transition_rejects_each_fixed_authority_change() -> TestResult {
    let previous = InstallationManifest::from_cbor(&manifest_bytes(unsigned())?)?;
    for (index, replacement) in [
        (2, Value::Text("another-root".to_owned())),
        (
            3,
            bytes(SigningKey::from_bytes(&[43; 32]).verifying_key().to_bytes()),
        ),
        (5, bytes([2; 32])),
        (6, bytes([3; 32])),
        (
            7,
            Value::Text("/run/pigloros/another-execute.sock".to_owned()),
        ),
        (
            8,
            Value::Text("/run/pigloros/another-control.sock".to_owned()),
        ),
        (9, Value::Array(vec![Value::Text("c".to_owned())])),
    ] {
        let mut fields = successor()?;
        fields[index] = replacement;
        let next = InstallationManifest::from_cbor(&manifest_bytes(fields)?)?;
        assert!(
            previous.validate_revocation_successor(&next).is_err(),
            "fixed field {index}"
        );
    }
    // A different valid indexed TRS1 still cannot replace the installed root registry.
    let mut fields = successor()?;
    fields[4] = bytes([200; 32]);
    let mut entries = array_values(&fields[10])?.to_vec();
    entries.insert(
        1,
        Value::Array(vec![
            integer(0),
            bytes([200; 32]),
            bytes([82; 32]),
            integer(64),
        ]),
    );
    fields[10] = Value::Array(entries);
    let next = InstallationManifest::from_cbor(&manifest_bytes(fields)?)?;
    assert!(previous.validate_revocation_successor(&next).is_err());
    Ok(())
}

#[test]
fn revocation_transition_rejects_removed_replaced_or_unrelated_added_objects() -> TestResult {
    let previous = InstallationManifest::from_cbor(&manifest_bytes(unsigned())?)?;
    for index in 0..16 {
        let kind = InstallationObjectKind::from_code(index)?;
        let original = &previous.objects()[usize::from(index)];
        let mut fields = successor()?;
        let mut entries = array_values(&fields[10])?.to_vec();
        let position = entries
            .iter()
            .position(|entry| {
                InstallationObject::decode(entry).is_ok_and(|entry| entry.kind() == kind)
            })
            .ok_or("original object missing")?;
        if index == 0 {
            // The TRS1 removal is already forbidden by the manifest decoder.
            entries.remove(position);
            fields[10] = Value::Array(entries);
            assert!(InstallationManifest::from_cbor(&manifest_bytes(fields)?).is_err());
            continue;
        }
        entries.remove(position);
        fields[10] = Value::Array(entries);
        let next = InstallationManifest::from_cbor(&manifest_bytes(fields)?)?;
        assert!(
            previous.validate_revocation_successor(&next).is_err(),
            "removed role {index}"
        );

        let mut fields = successor()?;
        let mut entries = array_values(&fields[10])?.to_vec();
        let mut changed = array(&entries[position], 4)?.to_vec();
        changed[3] = integer(original.length() + 1);
        entries[position] = Value::Array(changed);
        fields[10] = Value::Array(entries);
        let next = InstallationManifest::from_cbor(&manifest_bytes(fields)?)?;
        assert!(
            previous.validate_revocation_successor(&next).is_err(),
            "replaced role {index}"
        );
    }
    let mut fields = successor()?;
    let mut entries = array_values(&fields[10])?.to_vec();
    entries.push(Value::Array(vec![
        integer(15),
        bytes([255; 32]),
        bytes([255; 32]),
        integer(1),
    ]));
    fields[10] = Value::Array(entries);
    let next = InstallationManifest::from_cbor(&manifest_bytes(fields)?)?;
    assert!(previous.validate_revocation_successor(&next).is_err());
    Ok(())
}
