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
const X86_64_IMPLICIT_DEFAULTS: [&str; 18] = [
    "cacheflush",
    "clock_getres_time64",
    "clock_gettime64",
    "clock_nanosleep_time64",
    "futex_time64",
    "getegid32",
    "geteuid32",
    "getgid32",
    "getgroups32",
    "getresgid32",
    "getresuid32",
    "getuid32",
    "mmap2",
    "riscv_flush_icache",
    "riscv_hwprobe",
    "set_tls",
    "sigreturn",
    "ugetrlimit",
];
const AARCH64_IMPLICIT_DEFAULTS: [&str; 25] = [
    "arch_prctl",
    "cacheflush",
    "clock_getres_time64",
    "clock_gettime64",
    "clock_nanosleep_time64",
    "futex_time64",
    "get_thread_area",
    "getegid32",
    "geteuid32",
    "getgid32",
    "getgroups32",
    "getpgrp",
    "getresgid32",
    "getresuid32",
    "getuid32",
    "mmap2",
    "pause",
    "riscv_flush_icache",
    "riscv_hwprobe",
    "set_thread_area",
    "set_tls",
    "sigreturn",
    "time",
    "ugetrlimit",
    "uretprobe",
];
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

    assert_record(&x86_64, 315, &X86_64_IMPLICIT_DEFAULTS);
    assert_record(&aarch64, 275, &AARCH64_IMPLICIT_DEFAULTS);
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
    assert_ne!(x86_64.requested_names, aarch64.requested_names);
    for name in ["_llseek", "_newselect", "chown32", "mmap2", "socketcall"] {
        assert!(!x86_64
            .requested_names
            .iter()
            .any(|candidate| candidate == name));
    }
    for name in [
        "_llseek",
        "_newselect",
        "access",
        "arch_prctl",
        "open",
        "select",
        "socketcall",
    ] {
        assert!(!aarch64
            .requested_names
            .iter()
            .any(|candidate| candidate == name));
    }
    for name in ["access", "arch_prctl", "open", "select"] {
        assert!(x86_64
            .requested_names
            .iter()
            .any(|candidate| candidate == name));
    }
    assert_ne!(x86_64.syscall_set_digest, aarch64.syscall_set_digest);
    Ok(())
}

#[test]
fn production_systemd_syscall_set_manifest_binds_exact_records() -> Result<(), Box<dyn Error>> {
    let manifest: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../vectors/systemd-provider-v260.2/manifest.json"
    ))?;
    assert_eq!(
        manifest
            .as_object()
            .ok_or("manifest must be an object")?
            .len(),
        3
    );
    assert_eq!(
        manifest["systemd"],
        serde_json::json!({
            "revision": "f1d0952a125b96b7ab2f1ff29a87448ade8ac29b",
            "seccomp_util_sha256": "4242ae8aead8d2f0d9094449dfe039486edf0c0d8b32ba4cffc7991820590751",
            "version": "260.2",
        })
    );
    assert_eq!(
        manifest["libseccomp"],
        serde_json::json!({
            "source_archive_sha256": "501f66c667225d53791b97e1d7cf85ab764c297d04881f60f38f451c4b0ee1be",
            "syscalls_csv_sha256": "ab64e55719254d44bc279d967845568ab9940e81ed7800e9d1066f664a9f5231",
            "version": "2.6.1",
        })
    );
    let records = manifest["records"]
        .as_array()
        .ok_or("manifest records must be an array")?;
    assert_eq!(records.len(), 2);

    let expected_records = [
        (
            "x86_64",
            "systemd-v260.2-x86_64.scs1.cbor",
            SandboxArchitectureV1::X86_64,
            X86_64_BYTES,
        ),
        (
            "aarch64",
            "systemd-v260.2-aarch64.scs1.cbor",
            SandboxArchitectureV1::Aarch64,
            AARCH64_BYTES,
        ),
    ];
    for (record, (architecture, filename, expected_architecture, bytes)) in
        records.iter().zip(expected_records)
    {
        let byte_length = u64::try_from(bytes.len())?;
        let record_digest = blake3::hash(bytes).to_hex().to_string();
        let decoded = SandboxSyscallSetV1::from_canonical_cbor(bytes)?;
        assert_eq!(decoded.architecture, expected_architecture);
        let syscall_set_digest = blake3::Hash::from_bytes(decoded.syscall_set_digest)
            .to_hex()
            .to_string();
        assert_eq!(
            record,
            &serde_json::json!({
                "architecture": architecture,
                "file": filename,
                "requested_count": decoded.requested_names.len(),
                "expected_effective_count": decoded.expected_effective_names.len(),
                "byte_length": byte_length,
                "record_blake3": record_digest,
                "syscall_set_digest": syscall_set_digest,
            })
        );
    }
    Ok(())
}

fn assert_record(record: &SandboxSyscallSetV1, requested_count: usize, implicit_defaults: &[&str]) {
    assert_eq!(record.requested_names.len(), requested_count);
    assert_eq!(
        record.expected_effective_names.len(),
        requested_count + implicit_defaults.len()
    );
    for names in [&record.requested_names, &record.expected_effective_names] {
        assert!(names.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(names.iter().all(|name| !name.starts_with('@')));
    }
    assert!(record
        .requested_names
        .iter()
        .all(|name| record.expected_effective_names.binary_search(name).is_ok()));
    let additions: Vec<&str> = record
        .expected_effective_names
        .iter()
        .filter(|name| record.requested_names.binary_search(name).is_err())
        .map(String::as_str)
        .collect();
    assert_eq!(additions, implicit_defaults);
    for required in REQUIRED_SYSCALLS {
        assert!(record
            .requested_names
            .binary_search_by(|candidate| candidate.as_str().cmp(required))
            .is_ok());
    }
}
