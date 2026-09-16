use std::error::Error;

use pos_conformance::SandboxSyscallSetV1;
use pos_reference::sandbox_provider_protocol::{SandboxArchitecture, SandboxProviderProtocolError};
use pos_sandboxd::{SystemCallFilter, SystemCallFilterError};
use zvariant::{serialized::Context, to_bytes, Value, LE};

const X86_64: &[u8] = include_bytes!(
    "../../../crates/pos-conformance/vectors/systemd-provider-v260.2/systemd-v260.2-x86_64.scs1.cbor"
);
const AARCH64: &[u8] = include_bytes!(
    "../../../crates/pos-conformance/vectors/systemd-provider-v260.2/systemd-v260.2-aarch64.scs1.cbor"
);

const fn production_systemd_scs1_records() -> [(SandboxArchitecture, &'static [u8]); 2] {
    [
        (SandboxArchitecture::X86_64, X86_64),
        (SandboxArchitecture::Aarch64, AARCH64),
    ]
}

#[test]
fn production_requests_have_exact_dbus_type_and_roundtrip() -> Result<(), Box<dyn Error>> {
    for (architecture, bytes) in production_systemd_scs1_records() {
        let authority = SandboxSyscallSetV1::from_canonical_cbor(bytes)?;
        let filter = SystemCallFilter::from_selected_record(
            bytes,
            authority.syscall_set_digest,
            architecture,
        )?;
        let request = filter.requested_property();
        assert_eq!(request, (true, authority.requested_names));
        assert_eq!(
            Value::from(request.clone()).value_signature().to_string(),
            "(bas)"
        );
        let encoded = to_bytes(Context::new_dbus(LE, 0), &request)?;
        let (decoded, consumed): ((bool, Vec<String>), usize) = encoded.deserialize()?;
        assert_eq!(decoded, request);
        assert_eq!(consumed, encoded.len());
        assert_eq!(
            filter.verify_readback(&(true, authority.expected_effective_names)),
            Ok(())
        );
        // Both selected production records have distinct requested/readback
        // arrays. Returning the sent property is not valid systemd readback.
        assert_eq!(
            filter.verify_readback(&request),
            Err(SystemCallFilterError::ReadbackMismatch)
        );
    }
    Ok(())
}

#[test]
fn selected_digest_and_architecture_are_checked_before_compilation() -> Result<(), Box<dyn Error>> {
    for (architecture, bytes) in production_systemd_scs1_records() {
        let authority = SandboxSyscallSetV1::from_canonical_cbor(bytes)?;
        assert!(matches!(
            SystemCallFilter::from_selected_record(bytes, [0; 32], architecture),
            Err(SystemCallFilterError::DigestMismatch)
        ));
        let wrong_architecture = if architecture == SandboxArchitecture::X86_64 {
            SandboxArchitecture::Aarch64
        } else {
            SandboxArchitecture::X86_64
        };
        assert!(matches!(
            SystemCallFilter::from_selected_record(
                bytes,
                authority.syscall_set_digest,
                wrong_architecture
            ),
            Err(SystemCallFilterError::ArchitectureMismatch)
        ));
    }
    Ok(())
}

#[test]
fn malformed_or_unbound_canonical_records_do_not_produce_properties() -> Result<(), Box<dyn Error>>
{
    for (architecture, bytes) in production_systemd_scs1_records() {
        let authority = SandboxSyscallSetV1::from_canonical_cbor(bytes)?;
        for malformed in [b"not canonical CBOR".to_vec(), [bytes, &[0]].concat()] {
            assert!(matches!(
                SystemCallFilter::from_selected_record(
                    &malformed,
                    authority.syscall_set_digest,
                    architecture
                ),
                Err(SystemCallFilterError::InvalidRecord(
                    SandboxProviderProtocolError::InvalidEncoding
                ))
            ));
        }
        let mut unbound = bytes.to_vec();
        let final_byte = unbound
            .last_mut()
            .ok_or("production record must not be empty")?;
        *final_byte ^= 1;
        assert!(matches!(
            SystemCallFilter::from_selected_record(
                &unbound,
                authority.syscall_set_digest,
                architecture
            ),
            Err(SystemCallFilterError::InvalidRecord(
                SandboxProviderProtocolError::DigestMismatch
            ))
        ));
    }
    Ok(())
}

#[test]
fn every_readback_deviation_fails_without_normalization() -> Result<(), Box<dyn Error>> {
    for (architecture, bytes) in production_systemd_scs1_records() {
        let authority = SandboxSyscallSetV1::from_canonical_cbor(bytes)?;
        let filter = SystemCallFilter::from_selected_record(
            bytes,
            authority.syscall_set_digest,
            architecture,
        )?;
        let expected = authority.expected_effective_names;
        let mut missing = expected.clone();
        missing.truncate(missing.len() - 1);
        let mut extra = expected.clone();
        extra.push("unknown_syscall".into());
        let mut duplicate = expected.clone();
        duplicate.push(expected[0].clone());
        let mut reordered = expected.clone();
        reordered.swap(0, 1);
        let mut group = expected.clone();
        group[0] = "@default".into();
        let mut uppercase = expected.clone();
        uppercase[0].make_ascii_uppercase();
        let mut whitespace = expected.clone();
        whitespace[0].push(' ');
        let opposite = SandboxSyscallSetV1::from_canonical_cbor(
            if architecture == SandboxArchitecture::X86_64 {
                AARCH64
            } else {
                X86_64
            },
        )?;
        for readback in [
            (false, expected),
            (true, Vec::new()),
            (true, missing),
            (true, extra),
            (true, duplicate),
            (true, reordered),
            (true, group),
            (true, uppercase),
            (true, whitespace),
            (true, opposite.expected_effective_names),
        ] {
            assert_eq!(
                filter.verify_readback(&readback),
                Err(SystemCallFilterError::ReadbackMismatch)
            );
        }
    }
    Ok(())
}

#[test]
fn public_errors_have_closed_diagnostic_messages() {
    assert_eq!(
        SystemCallFilterError::DigestMismatch.to_string(),
        "systemd syscall-filter record differs from selected digest"
    );
    assert_eq!(
        SystemCallFilterError::ArchitectureMismatch.to_string(),
        "systemd syscall-filter architecture differs from selected architecture"
    );
    assert_eq!(
        SystemCallFilterError::ReadbackMismatch.to_string(),
        "systemd syscall-filter readback differs from selected authority"
    );
    assert_eq!(
        SystemCallFilterError::from(SandboxProviderProtocolError::DigestMismatch).to_string(),
        "sandbox-provider self-digest does not match"
    );
}
