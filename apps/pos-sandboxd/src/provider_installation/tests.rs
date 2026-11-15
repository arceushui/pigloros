//! SPI1 vectors, validation rules and file rules (ADR-069 R11 §4 and §11).
//!
//! The expected bytes are built by an oracle that encodes the CDDL fields
//! with `ciborium` and digests them with `blake3` directly, independently of
//! the decoder under test, and the §11 vectors are compared with it byte for
//! byte.

use std::error::Error;
use std::fs::{self, File};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::Path;

use ciborium::value::Value;
use ed25519_dalek::SigningKey;
use rustix::fs::{mknodat, FileType, Mode};

use super::{codec, ProviderInstallation, ProviderInstallationError, RuntimeKey};
use crate::{EgressProbe, InvalidEgressProbe, NetworkRange, StagingLimits};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const SPI1_A_UNSIGNED: &str = "8764535049310184440a5800001650fd7069676c6f72000000000000000000187782440a59fffc199c401a40000000851901f41903e81905dc190bb8191388781b72756e74696d652d6174746573746174696f6e2e65643235353139";
const SPI1_A_DIGEST: &str = "9d057c99cd949ef52cdcbeb13d26fd43f747d80ab26d539a11a31dd72e972003";
const SPI1_A_WRAPPER: &str = "828764535049310184440a5800001650fd7069676c6f72000000000000000000187782440a59fffc199c401a40000000851901f41903e81905dc190bb8191388781b72756e74696d652d6174746573746174696f6e2e6564323535313958209d057c99cd949ef52cdcbeb13d26fd43f747d80ab26d539a11a31dd72e972003";
const SPI1_B_UNSIGNED: &str = "8764535049310184440a5800001650fd7069676c6f72000000000000000000187782440a5803fc199c401a40000000851901f41903e81905dc190bb8191388781b72756e74696d652d6174746573746174696f6e2e65643235353139";
const SPI1_B_DIGEST: &str = "411542d90ce5c0915b95ebfa632395d8b1f295657000e94bba20aeadafd5d3dd";
const SPI1_C_UNSIGNED: &str = "8764535049310184440a5800001650fd7069676c6f72000000000000000000187782440a59fffc199c401a40000000851901f41903e81903e8190bb8191388781b72756e74696d652d6174746573746174696f6e2e65643235353139";
const SPI1_C_DIGEST: &str = "d2ca21d6bb1ce55688ac56d8ad58a608787252ad9c8af9fe1c6152892240d513";

const KEY_FILE: &str = "runtime-attestation.ed25519";
const SEED: [u8; 32] = [7; 32];

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap_or_default())
        .collect()
}

/// The SPI1 fields, one CDDL item each, as the oracle encodes them.
#[derive(Clone)]
struct Spec {
    magic: Value,
    version: Value,
    ipv4: Value,
    ipv4_length: Value,
    ipv6: Value,
    ipv6_length: Value,
    probe: Value,
    port: Value,
    cap: Value,
    budget: [u64; 5],
    key: Value,
}

fn bytes(slice: &[u8]) -> Value {
    Value::Bytes(slice.to_vec())
}

fn int(number: u64) -> Value {
    Value::Integer(number.into())
}

fn text(text: &str) -> Value {
    Value::Text(text.to_owned())
}

/// SPI1-A: the §11 common values with the probe `10.89.255.252/30:40000`.
fn spi1_a() -> Spec {
    Spec {
        magic: text("SPI1"),
        version: int(1),
        ipv4: bytes(&[10, 88, 0, 0]),
        ipv4_length: int(22),
        ipv6: bytes(&Ipv6Addr::new(0xfd70, 0x6967, 0x6c6f, 0x7200, 0, 0, 0, 0).octets()),
        ipv6_length: int(119),
        probe: bytes(&[10, 89, 255, 252]),
        port: int(40000),
        cap: int(1_073_741_824),
        budget: [500, 1000, 1500, 3000, 5000],
        key: text(KEY_FILE),
    }
}

impl Spec {
    fn unsigned(&self) -> Value {
        Value::Array(vec![
            self.magic.clone(),
            self.version.clone(),
            Value::Array(vec![
                self.ipv4.clone(),
                self.ipv4_length.clone(),
                self.ipv6.clone(),
                self.ipv6_length.clone(),
            ]),
            Value::Array(vec![self.probe.clone(), self.port.clone()]),
            self.cap.clone(),
            Value::Array(self.budget.iter().map(|phase| int(*phase)).collect()),
            self.key.clone(),
        ])
    }

    fn unsigned_bytes(&self) -> TestResult<Vec<u8>> {
        encode(&self.unsigned())
    }

    fn digest(&self) -> TestResult<[u8; 32]> {
        let mut preimage = b"PiglorOS.SPI1.v1\0".to_vec();
        preimage.extend(self.unsigned_bytes()?);
        Ok(*blake3::hash(&preimage).as_bytes())
    }

    /// The complete file, with its correct digest.
    fn document(&self) -> TestResult<Vec<u8>> {
        encode(&Value::Array(vec![self.unsigned(), bytes(&self.digest()?)]))
    }

    fn with(mut self, change: impl FnOnce(&mut Self)) -> Self {
        change(&mut self);
        self
    }
}

fn encode(value: &Value) -> TestResult<Vec<u8>> {
    let mut encoded = Vec::new();
    ciborium::into_writer(value, &mut encoded)?;
    Ok(encoded)
}

fn rejection(spec: &Spec) -> TestResult<ProviderInstallationError> {
    Ok(codec::decode(&spec.document()?)
        .err()
        .ok_or("the installation was accepted")?)
}

#[test]
fn the_vectors_regenerate_byte_for_byte() -> TestResult {
    let a = spi1_a();
    assert_eq!(a.unsigned_bytes()?, hex(SPI1_A_UNSIGNED));
    assert_eq!(a.unsigned_bytes()?.len(), 92);
    assert_eq!(a.digest()?.to_vec(), hex(SPI1_A_DIGEST));
    assert_eq!(a.document()?, hex(SPI1_A_WRAPPER));
    assert_eq!(a.document()?.len(), 127);
    let b = a.clone().with(|spec| spec.probe = bytes(&[10, 88, 3, 252]));
    assert_eq!(b.unsigned_bytes()?, hex(SPI1_B_UNSIGNED));
    assert_eq!(b.digest()?.to_vec(), hex(SPI1_B_DIGEST));
    let c = a.with(|spec| spec.budget = [500, 1000, 1000, 3000, 5000]);
    assert_eq!(c.unsigned_bytes()?, hex(SPI1_C_UNSIGNED));
    assert_eq!(c.digest()?.to_vec(), hex(SPI1_C_DIGEST));
    Ok(())
}

#[test]
fn spi1_a_decodes_to_its_values() -> TestResult {
    let fields = codec::decode(&hex(SPI1_A_WRAPPER))?;
    assert_eq!(
        fields.attempt_range,
        NetworkRange::new(
            Ipv4Addr::new(10, 88, 0, 0),
            22,
            Ipv6Addr::new(0xfd70, 0x6967, 0x6c6f, 0x7200, 0, 0, 0, 0),
            119
        )?
    );
    assert_eq!(fields.attempt_range.slots(), 256);
    assert_eq!(
        fields.egress_probe,
        EgressProbe::new(Ipv4Addr::new(10, 89, 255, 252), 40000)?
    );
    assert_eq!(fields.staging_aggregate_bytes, 1_073_741_824);
    assert_eq!(fields.runtime_key_file, KEY_FILE);
    Ok(())
}

#[test]
fn spi1_b_and_spi1_c_pass_the_digest_and_are_then_rejected() {
    let mut b = hex(SPI1_B_UNSIGNED);
    b.insert(0, 0x82);
    b.extend([0x58, 0x20]);
    b.extend(hex(SPI1_B_DIGEST));
    assert_eq!(
        codec::decode(&b).err(),
        Some(ProviderInstallationError::EgressProbeInAttemptRange)
    );
    let mut c = hex(SPI1_C_UNSIGNED);
    c.insert(0, 0x82);
    c.extend([0x58, 0x20]);
    c.extend(hex(SPI1_C_DIGEST));
    assert_eq!(
        codec::decode(&c).err(),
        Some(ProviderInstallationError::CleanupBudget)
    );
}

#[test]
fn rule_two_rejects_every_shape_and_bound_violation() -> TestResult {
    let ipv6 = Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0).octets();
    let cases: &[fn(&mut Spec)] = &[
        |spec| spec.magic = text("SPI2"),
        |spec| spec.magic = bytes(b"SPI1"),
        |spec| spec.version = int(0),
        |spec| spec.version = int(2),
        |spec| spec.version = text("1"),
        |spec| spec.ipv4 = bytes(&[10, 88, 0]),
        |spec| spec.ipv4 = bytes(&[10, 88, 0, 0, 0]),
        |spec| spec.ipv4 = int(10),
        |spec| spec.ipv4_length = int(7),
        |spec| spec.ipv4_length = int(31),
        |spec| spec.ipv6 = bytes(&[0xfd; 15]),
        |spec| spec.ipv6_length = int(6),
        |spec| spec.ipv6_length = int(128),
        |spec| spec.probe = bytes(&[10, 89, 255]),
        |spec| spec.port = int(0),
        |spec| spec.port = int(65536),
        |spec| spec.port = Value::Integer((-1).into()),
        |spec| spec.cap = int(0),
        |spec| spec.cap = Value::Bool(true),
        |spec| spec.budget = [0, 1000, 1500, 3000, 5000],
        |spec| spec.budget = [500, 1000, 1500, 3000, 5001],
        |spec| spec.key = text(".k"),
        |spec| spec.key = text("a/b"),
        |spec| spec.key = text("A"),
        |spec| spec.key = text(""),
        |spec| spec.key = text("k\0"),
        |spec| spec.key = text("k\u{e9}"),
        |spec| spec.key = text(&"k".repeat(65)),
        |spec| spec.key = bytes(b"k"),
    ];
    for change in cases {
        let spec = spi1_a().with(*change);
        assert_eq!(
            rejection(&spec)?,
            ProviderInstallationError::InvalidEncoding
        );
    }
    // A 64-character name and every allowed character pass rule 2.
    for name in ["k".repeat(64), "0a.b_c-9".to_owned(), "a.".to_owned()] {
        let spec = spi1_a().with(|spec| spec.key = text(&name));
        assert_eq!(codec::decode(&spec.document()?)?.runtime_key_file, name);
    }
    // The widest IPv6 prefix and the narrowest bounds also pass rule 2.
    let wide = spi1_a().with(|spec| {
        spec.ipv6 = bytes(&ipv6);
        spec.ipv6_length = int(7);
        spec.ipv4_length = int(8);
        spec.ipv4 = bytes(&[10, 0, 0, 0]);
        spec.probe = bytes(&[192, 168, 0, 0]);
        spec.port = int(65535);
        spec.cap = int(u64::MAX);
        spec.budget = [1, 2, 3, 4, 5];
    });
    let fields = codec::decode(&wide.document()?)?;
    assert_eq!(fields.staging_aggregate_bytes, u64::MAX);
    assert_eq!(fields.attempt_range.slots(), 1 << 22);
    Ok(())
}

#[test]
fn rule_two_rejects_non_canonical_and_malformed_documents() -> TestResult {
    let valid = spi1_a().document()?;
    let unsigned = spi1_a().unsigned();
    let digest = bytes(&spi1_a().digest()?);
    let mut trailing = valid.clone();
    trailing.push(0);
    // The version `1` in two bytes instead of one.
    let mut wide_integer = valid.clone();
    wide_integer.splice(7..8, [0x18, 0x01]);
    // The outer array with an indefinite length.
    let mut indefinite = valid.clone();
    indefinite[0] = 0x9f;
    indefinite.push(0xff);
    let documents = [
        trailing,
        wide_integer,
        indefinite,
        valid[..valid.len() - 1].to_vec(),
        Vec::new(),
        encode(&unsigned)?,
        encode(&Value::Array(vec![unsigned.clone()]))?,
        encode(&Value::Array(vec![
            unsigned.clone(),
            digest.clone(),
            digest.clone(),
        ]))?,
        encode(&Value::Array(vec![unsigned.clone(), bytes(&[0; 31])]))?,
        encode(&Value::Array(vec![digest, unsigned]))?,
        encode(&Value::Tag(24, Box::new(bytes(&valid))))?,
        encode(&Value::Map(Vec::new()))?,
    ];
    for document in documents {
        assert_eq!(
            codec::decode(&document).err(),
            Some(ProviderInstallationError::InvalidEncoding)
        );
    }
    // Each nested array with one item missing.
    for position in [2, 3, 5] {
        let Value::Array(mut items) = spi1_a().unsigned() else {
            return Err("the unsigned record is an array".into());
        };
        let Value::Array(nested) = &mut items[position] else {
            return Err("the item is an array".into());
        };
        nested.pop();
        let mut preimage = b"PiglorOS.SPI1.v1\0".to_vec();
        preimage.extend(encode(&Value::Array(items.clone()))?);
        let digest = bytes(blake3::hash(&preimage).as_bytes());
        let document = encode(&Value::Array(vec![Value::Array(items), digest]))?;
        assert_eq!(
            codec::decode(&document).err(),
            Some(ProviderInstallationError::InvalidEncoding)
        );
    }
    let short = encode(&Value::Array(vec![
        Value::Array(vec![text("SPI1"), int(1)]),
        bytes(&[0; 32]),
    ]))?;
    assert_eq!(
        codec::decode(&short).err(),
        Some(ProviderInstallationError::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn rule_three_rejects_a_digest_that_does_not_bind_the_record() -> TestResult {
    let spec = spi1_a();
    for flip in [0, 31] {
        let mut digest = spec.digest()?;
        digest[flip] ^= 1;
        let document = encode(&Value::Array(vec![spec.unsigned(), bytes(&digest)]))?;
        assert_eq!(
            codec::decode(&document).err(),
            Some(ProviderInstallationError::DigestMismatch)
        );
    }
    // A digest of the record without its domain does not bind it either.
    let undomained = blake3::hash(&spec.unsigned_bytes()?);
    let document = encode(&Value::Array(vec![
        spec.unsigned(),
        bytes(undomained.as_bytes()),
    ]))?;
    assert_eq!(
        codec::decode(&document).err(),
        Some(ProviderInstallationError::DigestMismatch)
    );
    Ok(())
}

#[test]
fn rules_four_and_five_reject_the_attempt_range() -> TestResult {
    for (network, length) in [
        ([11, 0, 0, 0], 8),
        ([10, 88, 0, 4], 22),
        ([172, 0, 0, 0], 10),
        ([192, 168, 0, 0], 15),
        ([100, 64, 0, 0], 22),
    ] {
        let spec = spi1_a().with(|spec| {
            spec.ipv4 = bytes(&network);
            spec.ipv4_length = int(length);
        });
        assert_eq!(
            rejection(&spec)?,
            ProviderInstallationError::AttemptIpv4Range
        );
    }
    let unaligned = Ipv6Addr::new(0xfd70, 0x6967, 0x6c6f, 0x7200, 0, 0, 0, 1);
    for (network, length) in [
        (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 64),
        (unaligned, 119),
        (Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 6),
    ] {
        let spec = spi1_a().with(|spec| {
            spec.ipv6 = bytes(&network.octets());
            spec.ipv6_length = int(length);
        });
        let expected = if length < 7 {
            ProviderInstallationError::InvalidEncoding
        } else {
            ProviderInstallationError::AttemptIpv6Range
        };
        assert_eq!(rejection(&spec)?, expected);
    }
    // Rule 5 is checked before rule 6.
    let v6_and_probe = spi1_a().with(|spec| {
        spec.ipv6 = bytes(&unaligned.octets());
        spec.probe = bytes(&[127, 0, 0, 0]);
    });
    assert_eq!(
        rejection(&v6_and_probe)?,
        ProviderInstallationError::AttemptIpv6Range
    );
    // Rule 4 is checked before rule 5.
    let both = spi1_a().with(|spec| {
        spec.ipv4 = bytes(&[11, 0, 0, 0]);
        spec.ipv6 = bytes(&unaligned.octets());
    });
    assert_eq!(
        rejection(&both)?,
        ProviderInstallationError::AttemptIpv4Range
    );
    Ok(())
}

#[test]
fn rules_six_and_six_b_reject_the_egress_probe() -> TestResult {
    for (network, expected) in [
        ([10, 89, 255, 254], InvalidEgressProbe::Misaligned),
        ([10, 89, 255, 249], InvalidEgressProbe::Misaligned),
        ([127, 0, 0, 0], InvalidEgressProbe::SpecialPurpose),
        ([0, 0, 0, 4], InvalidEgressProbe::SpecialPurpose),
        ([169, 254, 0, 0], InvalidEgressProbe::SpecialPurpose),
        ([224, 0, 0, 0], InvalidEgressProbe::SpecialPurpose),
    ] {
        let spec = spi1_a().with(|spec| spec.probe = bytes(&network));
        assert_eq!(
            rejection(&spec)?,
            ProviderInstallationError::EgressProbe(expected)
        );
    }
    // `EgressProbe::new` accepts these; only SPI1 rule 6b refuses them.
    for network in [
        [100, 64, 0, 0],
        [11, 0, 0, 0],
        [172, 32, 0, 0],
        [192, 169, 0, 0],
    ] {
        let address = Ipv4Addr::from(network);
        assert!(EgressProbe::new(address, 40000).is_ok());
        let spec = spi1_a().with(|spec| spec.probe = bytes(&network));
        assert_eq!(
            rejection(&spec)?,
            ProviderInstallationError::EgressProbeNotPrivate
        );
    }
    // Every RFC 1918 block passes rule 6b.
    for network in [[10, 0, 0, 0], [172, 31, 255, 252], [192, 168, 255, 252]] {
        let spec = spi1_a().with(|spec| spec.probe = bytes(&network));
        assert!(codec::decode(&spec.document()?).is_ok());
    }
    Ok(())
}

#[test]
fn rule_seven_rejects_a_probe_inside_the_attempt_range() -> TestResult {
    for network in [[10, 88, 0, 0], [10, 88, 1, 4], [10, 88, 3, 252]] {
        let spec = spi1_a().with(|spec| spec.probe = bytes(&network));
        assert_eq!(
            rejection(&spec)?,
            ProviderInstallationError::EgressProbeInAttemptRange
        );
    }
    // The /30s just outside the /22 share no address with it.
    for network in [[10, 87, 255, 252], [10, 88, 4, 0]] {
        let spec = spi1_a().with(|spec| spec.probe = bytes(&network));
        assert!(codec::decode(&spec.document()?).is_ok());
    }
    // A /30 range and a probe on the next /30.
    let narrow = spi1_a().with(|spec| {
        spec.ipv4_length = int(30);
        spec.probe = bytes(&[10, 88, 0, 4]);
    });
    assert!(codec::decode(&narrow.document()?).is_ok());
    let same = narrow.with(|spec| spec.probe = bytes(&[10, 88, 0, 0]));
    assert_eq!(
        rejection(&same)?,
        ProviderInstallationError::EgressProbeInAttemptRange
    );
    // Rule 6 is checked before rule 7.
    let private_inside = spi1_a().with(|spec| {
        spec.ipv4 = bytes(&[10, 0, 0, 0]);
        spec.ipv4_length = int(8);
        spec.probe = bytes(&[10, 0, 0, 3]);
    });
    assert_eq!(
        rejection(&private_inside)?,
        ProviderInstallationError::EgressProbe(InvalidEgressProbe::Misaligned)
    );
    Ok(())
}

#[test]
fn rule_nine_requires_strictly_increasing_phases() -> TestResult {
    for budget in [
        [500, 500, 1500, 3000, 5000],
        [1000, 500, 1500, 3000, 5000],
        [500, 1000, 1500, 1500, 5000],
        [500, 1000, 1500, 3000, 3000],
        [5000, 4000, 3000, 2000, 1000],
    ] {
        let spec = spi1_a().with(|spec| spec.budget = budget);
        assert_eq!(rejection(&spec)?, ProviderInstallationError::CleanupBudget);
    }
    // Rule 7 is checked before rule 9.
    let both = spi1_a().with(|spec| {
        spec.probe = bytes(&[10, 88, 3, 252]);
        spec.budget = [500, 500, 1500, 3000, 5000];
    });
    assert_eq!(
        rejection(&both)?,
        ProviderInstallationError::EgressProbeInAttemptRange
    );
    Ok(())
}

#[test]
fn the_digest_is_checked_before_the_value_rules() -> TestResult {
    let spec = spi1_a().with(|spec| spec.ipv4 = bytes(&[11, 0, 0, 0]));
    let mut digest = spec.digest()?;
    digest[0] ^= 1;
    let document = encode(&Value::Array(vec![spec.unsigned(), bytes(&digest)]))?;
    assert_eq!(
        codec::decode(&document).err(),
        Some(ProviderInstallationError::DigestMismatch)
    );
    Ok(())
}

/// An artifact root that this process's user owns, holding `document`.
fn artifact_root(document: &[u8], mode: u32) -> TestResult<(tempfile::TempDir, File, u32)> {
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755))?;
    let path = directory.path().join("provider-installation.cbor");
    fs::write(&path, document)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
    let root = File::open(directory.path())?;
    let owner = root.metadata()?.uid();
    Ok((directory, root, owner))
}

fn opened(
    document: &[u8],
    mode: u32,
) -> TestResult<Result<ProviderInstallation, ProviderInstallationError>> {
    let (_directory, root, owner) = artifact_root(document, mode)?;
    Ok(ProviderInstallation::open_beneath(root, owner))
}

#[test]
fn a_valid_file_yields_its_validated_values() -> TestResult {
    let installation = opened(&hex(SPI1_A_WRAPPER), 0o400)??;
    assert_eq!(installation.attempt_range().slots(), 256);
    assert_eq!(
        installation.egress_probe(),
        EgressProbe::new(Ipv4Addr::new(10, 89, 255, 252), 40000)?
    );
    assert_eq!(
        installation.staging_limits(),
        StagingLimits {
            aggregate_bytes: 1_073_741_824
        }
    );
    assert_eq!(installation.runtime_key_file(), KEY_FILE);
    // The budget is the one SPI1-A's phases built: the identical value.
    assert_eq!(
        format!("{:?}", installation.cleanup_budget()),
        format!("{:?}", installation.cleanup_budget)
    );
    Ok(())
}

#[test]
fn rule_one_refuses_every_unsafe_file() -> TestResult {
    let valid = hex(SPI1_A_WRAPPER);
    for mode in [0o600, 0o440, 0o404, 0o444, 0o500, 0o4400] {
        assert_eq!(
            opened(&valid, mode)?.err(),
            Some(ProviderInstallationError::UnsafeFile),
            "mode {mode:o}"
        );
    }
    assert_eq!(
        opened(&[], 0o400)?.err(),
        Some(ProviderInstallationError::UnsafeFile)
    );
    assert_eq!(
        opened(&[0; 4097], 0o400)?.err(),
        Some(ProviderInstallationError::UnsafeFile)
    );
    // Exactly 4096 bytes pass the file rules and fail the encoding.
    assert_eq!(
        opened(&[0; 4096], 0o400)?.err(),
        Some(ProviderInstallationError::InvalidEncoding)
    );
    assert_eq!(
        opened(&[0], 0o400)?.err(),
        Some(ProviderInstallationError::InvalidEncoding)
    );
    // Another owner.
    let (_directory, root, owner) = artifact_root(&valid, 0o400)?;
    assert_eq!(
        ProviderInstallation::open_beneath(root, owner + 1).err(),
        Some(ProviderInstallationError::UnsafeFile)
    );
    Ok(())
}

#[test]
fn rule_one_refuses_links_and_other_file_types() -> TestResult {
    let valid = hex(SPI1_A_WRAPPER);
    let refused = |prepare: &dyn Fn(&Path) -> TestResult| -> TestResult {
        let (directory, root, owner) = artifact_root(&valid, 0o400)?;
        let path = directory.path().join("provider-installation.cbor");
        let target = directory.path().join("target.cbor");
        fs::rename(&path, &target)?;
        prepare(directory.path())?;
        assert_eq!(
            ProviderInstallation::open_beneath(root, owner).err(),
            Some(ProviderInstallationError::UnsafeFile)
        );
        Ok(())
    };
    // Missing.
    refused(&|_| Ok(()))?;
    // A symlink to a valid file.
    refused(&|root| {
        Ok(symlink(
            "target.cbor",
            root.join("provider-installation.cbor"),
        )?)
    })?;
    // A second hard link to a valid file.
    refused(&|root| {
        Ok(fs::hard_link(
            root.join("target.cbor"),
            root.join("provider-installation.cbor"),
        )?)
    })?;
    // A directory.
    refused(&|root| Ok(fs::create_dir(root.join("provider-installation.cbor"))?))?;
    // A FIFO, which the non-blocking open cannot stall on.
    refused(&|root| {
        let directory = File::open(root)?;
        Ok(mknodat(
            &directory,
            "provider-installation.cbor",
            FileType::Fifo,
            Mode::from_raw_mode(0o400),
            0,
        )?)
    })?;
    Ok(())
}

#[test]
fn rule_one_refuses_an_unsafe_artifact_root() -> TestResult {
    let valid = hex(SPI1_A_WRAPPER);
    for mode in [0o775, 0o757, 0o777] {
        let (directory, root, owner) = artifact_root(&valid, 0o400)?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(mode))?;
        assert_eq!(
            ProviderInstallation::open_beneath(root, owner).err(),
            Some(ProviderInstallationError::UnsafeFile)
        );
    }
    // A root that is a file, not a directory.
    let (directory, _root, owner) = artifact_root(&valid, 0o400)?;
    let file = File::open(directory.path().join("provider-installation.cbor"))?;
    assert_eq!(
        ProviderInstallation::open_beneath(file, owner).err(),
        Some(ProviderInstallationError::UnsafeFile)
    );
    // A root without group or other write passes.
    let (directory, root, owner) = artifact_root(&valid, 0o400)?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    assert!(ProviderInstallation::open_beneath(root, owner).is_ok());
    Ok(())
}

/// A valid installation whose root holds `provider-keys/` in `mode`.
fn keyed(mode: u32) -> TestResult<(tempfile::TempDir, ProviderInstallation)> {
    let (directory, root, owner) = artifact_root(&hex(SPI1_A_WRAPPER), 0o400)?;
    let keys = directory.path().join("provider-keys");
    fs::create_dir(&keys)?;
    fs::set_permissions(&keys, fs::Permissions::from_mode(mode))?;
    let installation = ProviderInstallation::open_beneath(root, owner)?;
    Ok((directory, installation))
}

fn write_key(directory: &Path, seed: &[u8], mode: u32) -> TestResult {
    let keys = directory.join("provider-keys");
    let mode_before = fs::metadata(&keys)?.permissions().mode();
    fs::set_permissions(&keys, fs::Permissions::from_mode(0o700))?;
    let path = keys.join(KEY_FILE);
    fs::write(&path, seed)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
    fs::set_permissions(&keys, fs::Permissions::from_mode(mode_before))?;
    Ok(())
}

#[test]
fn a_private_key_file_loads_its_seed() -> TestResult {
    let expected = SigningKey::from_bytes(&SEED).verifying_key();
    for mode in [0o400, 0o600] {
        let (directory, installation) = keyed(0o700)?;
        write_key(directory.path(), &SEED, mode)?;
        let key = RuntimeKey::open(&installation)?;
        assert_eq!(key.verifying_key(), expected);
        assert_eq!(format!("{key:?}"), "RuntimeKey");
        let key = key.require_admitted(&expected)?;
        assert_eq!(key.verifying_key(), expected);
        let other = SigningKey::from_bytes(&[8; 32]).verifying_key();
        assert_eq!(
            key.require_admitted(&other).err(),
            Some(ProviderInstallationError::KeyMismatch)
        );
    }
    Ok(())
}

#[test]
fn an_unsafe_key_file_is_refused() -> TestResult {
    let refuse = |installation: &ProviderInstallation| {
        assert_eq!(
            RuntimeKey::open(installation).err(),
            Some(ProviderInstallationError::UnsafeKeyFile)
        );
    };
    for (mode, length) in [
        (0o640, 32),
        (0o604, 32),
        (0o700, 32),
        (0o644, 32),
        (0o4600, 32),
        (0o600, 31),
        (0o600, 33),
        (0o600, 0),
    ] {
        let (directory, installation) = keyed(0o700)?;
        write_key(directory.path(), &vec![7; length], mode)?;
        refuse(&installation);
    }
    let (directory, installation) = keyed(0o700)?;
    let keys = directory.path().join("provider-keys");
    // Missing.
    refuse(&installation);
    // A symlink to a valid key, a second hard link, a directory and a FIFO.
    fs::write(keys.join("target"), SEED)?;
    fs::set_permissions(keys.join("target"), fs::Permissions::from_mode(0o600))?;
    symlink("target", keys.join(KEY_FILE))?;
    refuse(&installation);
    fs::remove_file(keys.join(KEY_FILE))?;
    fs::hard_link(keys.join("target"), keys.join(KEY_FILE))?;
    refuse(&installation);
    fs::remove_file(keys.join(KEY_FILE))?;
    fs::create_dir(keys.join(KEY_FILE))?;
    refuse(&installation);
    fs::remove_dir(keys.join(KEY_FILE))?;
    mknodat(
        File::open(&keys)?,
        KEY_FILE,
        FileType::Fifo,
        Mode::from_raw_mode(0o600),
        0,
    )?;
    refuse(&installation);
    Ok(())
}

#[test]
fn an_unsafe_key_directory_is_refused() -> TestResult {
    let refuse = |installation: &ProviderInstallation| {
        assert_eq!(
            RuntimeKey::open(installation).err(),
            Some(ProviderInstallationError::UnsafeKeyDirectory)
        );
    };
    for mode in [0o750, 0o755, 0o705, 0o500, 0o1700] {
        let (directory, installation) = keyed(0o700)?;
        write_key(directory.path(), &SEED, 0o600)?;
        fs::set_permissions(
            directory.path().join("provider-keys"),
            fs::Permissions::from_mode(mode),
        )?;
        refuse(&installation);
    }
    // Missing, a symlink to a valid directory, and a file.
    let (directory, installation) = keyed(0o700)?;
    write_key(directory.path(), &SEED, 0o600)?;
    let keys = directory.path().join("provider-keys");
    fs::rename(&keys, directory.path().join("held"))?;
    refuse(&installation);
    symlink("held", &keys)?;
    refuse(&installation);
    fs::remove_file(&keys)?;
    fs::write(&keys, SEED)?;
    refuse(&installation);
    // Another owner of the directory and the file.
    let (directory, mut installation) = keyed(0o700)?;
    write_key(directory.path(), &SEED, 0o600)?;
    installation.owner += 1;
    refuse(&installation);
    Ok(())
}

/// The fixed path, as root, in the isolated container: `/var/lib` is a fresh
/// tmpfs there.
#[test]
fn the_fixed_path_opens_only_a_safe_artifact_root() -> TestResult {
    if std::env::var_os("PIGLOROS_PRIVILEGED_COMPOSITION_TEST").is_none() {
        let runner =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/run-isolated-test.sh");
        let output = std::process::Command::new(runner)
            .arg(std::env::current_exe()?)
            .arg("provider_installation::tests::the_fixed_path_opens_only_a_safe_artifact_root")
            .output()?;
        assert!(
            output.status.success(),
            "isolated provider installation test failed: {:?}\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return Ok(());
    }
    assert_eq!(fs::metadata("/var/lib")?.uid(), 0);
    let root = Path::new("/var/lib/pigloros/sandbox");
    assert_eq!(
        ProviderInstallation::open().err(),
        Some(ProviderInstallationError::UnsafeFile)
    );
    fs::create_dir_all(root)?;
    for directory in ["/var/lib/pigloros", "/var/lib/pigloros/sandbox"] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o755))?;
    }
    let path = root.join("provider-installation.cbor");
    fs::write(&path, hex(SPI1_A_WRAPPER))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400))?;
    fs::create_dir(root.join("provider-keys"))?;
    fs::set_permissions(
        root.join("provider-keys"),
        fs::Permissions::from_mode(0o700),
    )?;
    let key = root.join("provider-keys").join(KEY_FILE);
    fs::write(&key, SEED)?;
    fs::set_permissions(&key, fs::Permissions::from_mode(0o400))?;
    let installation = ProviderInstallation::open()?;
    assert_eq!(installation.runtime_key_file(), KEY_FILE);
    let expected = SigningKey::from_bytes(&SEED).verifying_key();
    assert_eq!(RuntimeKey::open(&installation)?.verifying_key(), expected);
    // A group-writable ancestor, then a symlinked one, are refused.
    for (directory, mode) in [
        ("/var/lib/pigloros", 0o775),
        ("/var/lib/pigloros/sandbox", 0o757),
    ] {
        fs::set_permissions(directory, fs::Permissions::from_mode(mode))?;
        assert_eq!(
            ProviderInstallation::open().err(),
            Some(ProviderInstallationError::UnsafeFile)
        );
        fs::set_permissions(directory, fs::Permissions::from_mode(0o755))?;
    }
    assert!(ProviderInstallation::open().is_ok());
    fs::rename(root, "/var/lib/pigloros/held")?;
    symlink("held", root)?;
    assert_eq!(
        ProviderInstallation::open().err(),
        Some(ProviderInstallationError::UnsafeFile)
    );
    Ok(())
}
