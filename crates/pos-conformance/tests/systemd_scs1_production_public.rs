use std::error::Error;

use pos_conformance::{SandboxArchitectureV1, SandboxSyscallSetV1};
use pos_reference::sandbox_provider_protocol::{
    SandboxArchitecture as IndependentArchitecture, SandboxSyscallSet as IndependentSyscallSet,
};

const REQUIRED_SYSCALLS: [&str; 6] = [
    "execveat",
    "getsockopt",
    "poll",
    "recvmsg",
    "sendto",
    "socket",
];
const EXPECTED_NAME_COUNT: usize = 392;
const X86_64_BYTES: &[u8] =
    include_bytes!("../vectors/systemd-provider-v260.2/systemd-v260.2-x86_64.scs1.cbor");
const AARCH64_BYTES: &[u8] =
    include_bytes!("../vectors/systemd-provider-v260.2/systemd-v260.2-aarch64.scs1.cbor");

#[test]
fn production_systemd_syscall_sets_match_both_public_decoders() -> Result<(), Box<dyn Error>> {
    let x86_64 = SandboxSyscallSetV1::from_canonical_cbor(X86_64_BYTES)?;
    let aarch64 = SandboxSyscallSetV1::from_canonical_cbor(AARCH64_BYTES)?;
    let independent_x86_64 = IndependentSyscallSet::from_canonical_cbor(X86_64_BYTES)?;
    let independent_aarch64 = IndependentSyscallSet::from_canonical_cbor(AARCH64_BYTES)?;

    assert_eq!(x86_64.architecture, SandboxArchitectureV1::X86_64);
    assert_eq!(aarch64.architecture, SandboxArchitectureV1::Aarch64);
    assert_eq!(
        independent_x86_64.architecture,
        IndependentArchitecture::X86_64
    );
    assert_eq!(
        independent_aarch64.architecture,
        IndependentArchitecture::Aarch64
    );

    assert_record(&x86_64);
    assert_record(&aarch64);
    assert_eq!(x86_64.requested_names, independent_x86_64.requested_names);
    assert_eq!(
        x86_64.expected_effective_names,
        independent_x86_64.expected_effective_names
    );
    assert_eq!(aarch64.requested_names, independent_aarch64.requested_names);
    assert_eq!(
        aarch64.expected_effective_names,
        independent_aarch64.expected_effective_names
    );
    assert_eq!(x86_64.requested_names, aarch64.requested_names);
    assert_ne!(x86_64.syscall_set_digest, aarch64.syscall_set_digest);
    Ok(())
}

#[test]
fn production_systemd_syscall_set_manifest_binds_exact_records() -> Result<(), Box<dyn Error>> {
    let manifest: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../vectors/systemd-provider-v260.2/manifest.json"
    ))?;
    let records = manifest["records"]
        .as_array()
        .ok_or("manifest records must be an array")?;
    assert_eq!(records.len(), 2);

    for (record, bytes) in records.iter().zip([X86_64_BYTES, AARCH64_BYTES]) {
        let byte_length = u64::try_from(bytes.len())?;
        let record_digest = blake3::hash(bytes).to_hex().to_string();
        assert_eq!(record["requested_count"].as_u64(), Some(392));
        assert_eq!(record["expected_effective_count"].as_u64(), Some(392));
        assert_eq!(record["byte_length"].as_u64(), Some(byte_length));
        assert_eq!(
            record["record_blake3"].as_str(),
            Some(record_digest.as_str())
        );

        let decoded = SandboxSyscallSetV1::from_canonical_cbor(bytes)?;
        let syscall_set_digest = blake3::Hash::from_bytes(decoded.syscall_set_digest)
            .to_hex()
            .to_string();
        assert_eq!(
            record["syscall_set_digest"].as_str(),
            Some(syscall_set_digest.as_str())
        );
    }
    Ok(())
}

fn assert_record(record: &SandboxSyscallSetV1) {
    assert_eq!(record.requested_names.len(), EXPECTED_NAME_COUNT);
    assert_eq!(record.expected_effective_names.len(), EXPECTED_NAME_COUNT);
    assert_eq!(record.requested_names, record.expected_effective_names);
    assert!(record
        .requested_names
        .windows(2)
        .all(|pair| pair[0] < pair[1]));
    assert!(record
        .requested_names
        .iter()
        .all(|name| !name.starts_with('@')));
    for required in REQUIRED_SYSCALLS {
        assert!(record
            .requested_names
            .binary_search_by(|candidate| candidate.as_str().cmp(required))
            .is_ok());
    }
}
