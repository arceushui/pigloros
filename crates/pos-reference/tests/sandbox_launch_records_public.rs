//! Golden-vector and mutation checks for the LPV1, `ReadyV1` and `ReleaseV1` launcher records.
//!
//! The vectors were produced by an independent Python CBOR/BLAKE3/Ed25519
//! encoder, not by the codec under test.

use std::error::Error;

use ciborium::value::Value;
use ed25519_dalek::{Signer, SigningKey};
use pos_reference::sandbox_provider_protocol::{
    ExecutionRelease, ExecutionReleaseFields, FdIdentity, LaunchParameters, LauncherReady,
    LauncherReadyFields, SandboxProviderProtocolError,
};

type TestResult = Result<(), Box<dyn Error>>;
type Rejects = fn(&[u8]) -> bool;
type Case<'a> = (&'a [u8], Rejects);
type PathCase<'a> = (&'a [u8], Rejects, Vec<Vec<usize>>);

const LPV1_FULL: &str = "8288644c5056310150010101010101010101010101010101015820020202020202020202020202020202020202020202020202020202020202020258200303030303030303030303030303030303030303030303030303030303030303702f7573722f62696e2f6164617074657282672d2d7365727665672d2d7175696574582004040404040404040404040404040404040404040404040404040404040404045820e139c1a90ed957711934f79d4706720242ef0f06c9cbb2e974ecbbe120582281";
const LPV1_DIGEST: &str = "e139c1a90ed957711934f79d4706720242ef0f06c9cbb2e974ecbbe120582281";
const RDY1_FULL: &str = "828d645244593101500101010101010101010101010101010158200202020202020202020202020202020202020202020202020202020202020202500505050505050505050505050505050558200606060606060606060606060606060606060606060606060606060606060606820718645820030303030303030303030303030303030303030303030303030303030303030358200707070707070707070707070707070707070707070707070707070707070707820718c85820e139c1a90ed957711934f79d4706720242ef0f06c9cbb2e974ecbbe120582281582004040404040404040404040404040404040404040404040404040404040404045820080808080808080808080808080808080808080808080808080808080808080858206348e47cb248ee8b32633b3f268606a8c7d5e85a22310e75bea5bbe43ed92140";
const RDY1_DIGEST: &str = "6348e47cb248ee8b32633b3f268606a8c7d5e85a22310e75bea5bbe43ed92140";
const RLS1_FULL: &str = "838f64524c53310150010101010101010101010101010101015820020202020202020202020202020202020202020202020202020202020202020258206348e47cb248ee8b32633b3f268606a8c7d5e85a22310e75bea5bbe43ed921405820090909090909090909090909090909090909090909090909090909090909090958200a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a58200b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b01020358200c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c58200d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d1a075bcd156b72756e74696d652d6b65795820533c96ca296f8ed9b29810932f3006584c4b8cfec660eaad85f82016eafd15a658407b48f0fd04bce7f20c5a7bfa26a40b482843cbb5ef3709b9ae5aefa771d11ce3f3c3b542e2b17818bd5af12084310c496121d87f75c7a461379627fe7e16ef0e";
const RLS1_DIGEST: &str = "533c96ca296f8ed9b29810932f3006584c4b8cfec660eaad85f82016eafd15a6";
const RLS1_PUBLIC_KEY: &str = "197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61";

/// A nonce built at run time, so the vector is not a literal key or nonce.
fn fill(value: u8) -> [u8; 32] {
    std::array::from_fn(|_| value)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .map(|nibble| char::from(DIGITS[usize::from(nibble)]))
        .collect()
}

fn unhex(text: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    (0..text.len())
        .step_by(2)
        .map(|index| Ok(u8::from_str_radix(&text[index..index + 2], 16)?))
        .collect()
}

fn launch() -> Result<LaunchParameters, Box<dyn Error>> {
    Ok(LaunchParameters::new(
        [1; 16],
        fill(2),
        [3; 32],
        "/usr/bin/adapter".to_owned(),
        vec!["--serve".to_owned(), "--quiet".to_owned()],
        [4; 32],
    )?)
}

fn ready_fields() -> Result<LauncherReadyFields, Box<dyn Error>> {
    Ok(LauncherReadyFields {
        attempt_id: [1; 16],
        nonce: [2; 32],
        launch_instance_id: [5; 16],
        launcher_digest: [6; 32],
        launcher_identity: FdIdentity {
            mount_id: 7,
            inode: 100,
        },
        sim1_digest: [3; 32],
        adapter_digest: [7; 32],
        adapter_identity: FdIdentity {
            mount_id: 7,
            inode: 200,
        },
        launch_parameter_digest: launch()?.digest,
        expected_fdl1_digest: [4; 32],
        observed_fdl1_digest: [8; 32],
    })
}

fn release_fields() -> Result<ExecutionReleaseFields, Box<dyn Error>> {
    Ok(ExecutionReleaseFields {
        attempt_id: [1; 16],
        nonce: [2; 32],
        ready1_digest: LauncherReady::new(ready_fields()?)?.digest,
        trs1_digest: [9; 32],
        rvs1_digest: [10; 32],
        apt1_digest: [11; 32],
        trust_epoch: 1,
        revocation_epoch: 2,
        policy_epoch: 3,
        expected_readback_digest: [12; 32],
        observed_readback_digest: [13; 32],
        deadline_monotonic_ns: 123_456_789,
        runtime_attestation_key_id: "runtime-key".to_owned(),
    })
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[42; 32])
}

fn release() -> Result<ExecutionRelease, Box<dyn Error>> {
    let key = signing_key();
    Ok(ExecutionRelease::sign(release_fields()?, |message| {
        key.sign(message).to_bytes()
    })?)
}

#[test]
fn lpv1_matches_the_golden_vector_and_round_trips() -> TestResult {
    let record = launch()?;
    assert_eq!(hex(&record.digest), LPV1_DIGEST);
    let bytes = record.to_canonical_cbor()?;
    assert_eq!(hex(&bytes), LPV1_FULL);
    assert_eq!(LaunchParameters::from_canonical_cbor(&bytes)?, record);
    Ok(())
}

#[test]
fn rdy1_matches_the_golden_vector_and_round_trips() -> TestResult {
    let record = LauncherReady::new(ready_fields()?)?;
    assert_eq!(hex(&record.digest), RDY1_DIGEST);
    let bytes = record.to_canonical_cbor()?;
    assert_eq!(hex(&bytes), RDY1_FULL);
    assert_eq!(LauncherReady::from_canonical_cbor(&bytes)?, record);
    Ok(())
}

#[test]
fn rls1_matches_the_golden_vector_verifies_and_round_trips() -> TestResult {
    let record = release()?;
    assert_eq!(hex(&record.digest), RLS1_DIGEST);
    let bytes = record.to_canonical_cbor()?;
    assert_eq!(hex(&bytes), RLS1_FULL);
    let decoded = ExecutionRelease::from_canonical_cbor(&bytes)?;
    assert_eq!(decoded, record);
    let public: [u8; 32] = unhex(RLS1_PUBLIC_KEY)?
        .try_into()
        .map_err(|_| "public key length")?;
    decoded.verify_signature(&ed25519_dalek::VerifyingKey::from_bytes(&public)?)?;
    let other = SigningKey::from_bytes(&[43; 32]).verifying_key();
    assert!(decoded.verify_signature(&other).is_err());
    Ok(())
}

#[test]
fn lpv1_constructor_rejects_every_invalid_field() {
    let build = |attempt: [u8; 16], nonce, sim1, path: &str, arguments: Vec<String>, fdl1| {
        LaunchParameters::new(attempt, nonce, sim1, path.to_owned(), arguments, fdl1)
    };
    let args = || vec!["a".to_owned()];
    assert!(build([0; 16], fill(2), [3; 32], "/a", args(), [4; 32]).is_err());
    assert!(build([1; 16], fill(0), [3; 32], "/a", args(), [4; 32]).is_err());
    assert!(build([1; 16], fill(2), [0; 32], "/a", args(), [4; 32]).is_err());
    assert!(build([1; 16], fill(2), [3; 32], "/a", args(), [0; 32]).is_err());
    for path in ["", "a", "/a//b", "/a/../b", "/a/./b", "/a\0b", "/", "/a/"] {
        assert!(build([1; 16], fill(2), [3; 32], path, args(), [4; 32]).is_err());
    }
    assert!(build(
        [1; 16],
        fill(2),
        [3; 32],
        "/a",
        vec![String::new()],
        [4; 32]
    )
    .is_err());
    assert!(build(
        [1; 16],
        fill(2),
        [3; 32],
        "/a",
        vec!["a\0".to_owned()],
        [4; 32]
    )
    .is_err());
    assert!(build(
        [1; 16],
        fill(2),
        [3; 32],
        "/a",
        vec!["a".repeat(257)],
        [4; 32]
    )
    .is_err());
    assert!(build(
        [1; 16],
        fill(2),
        [3; 32],
        "/a",
        vec!["a".repeat(256)],
        [4; 32]
    )
    .is_ok());
    assert!(build(
        [1; 16],
        fill(2),
        [3; 32],
        "/a",
        vec!["a".to_owned(); 257],
        [4; 32]
    )
    .is_err());
    assert!(build(
        [1; 16],
        fill(2),
        [3; 32],
        "/a",
        vec!["a".to_owned(); 256],
        [4; 32]
    )
    .is_ok());
}

#[test]
fn lpv1_enforces_the_64_kib_record_bound() {
    let build = |count: usize| {
        LaunchParameters::new(
            [1; 16],
            fill(2),
            [3; 32],
            "/a".to_owned(),
            vec!["a".repeat(256); count],
            [4; 32],
        )
    };
    assert!(build(250).is_ok());
    assert!(build(256).is_err());
}

#[test]
fn rdy1_constructor_rejects_every_zero_field() -> TestResult {
    let mutations: [fn(&mut LauncherReadyFields); 11] = [
        |f| f.attempt_id = [0; 16],
        |f| f.launch_instance_id = [0; 16],
        |f| f.nonce = [0; 32],
        |f| f.launcher_digest = [0; 32],
        |f| f.sim1_digest = [0; 32],
        |f| f.adapter_digest = [0; 32],
        |f| f.launch_parameter_digest = [0; 32],
        |f| f.expected_fdl1_digest = [0; 32],
        |f| f.observed_fdl1_digest = [0; 32],
        |f| f.launcher_identity.inode = 0,
        |f| f.adapter_identity.inode = 0,
    ];
    for mutate in mutations {
        let mut fields = ready_fields()?;
        mutate(&mut fields);
        assert!(LauncherReady::new(fields).is_err());
    }
    Ok(())
}

#[test]
fn rls1_signer_rejects_every_zero_field_and_a_zero_signature() -> TestResult {
    let mutations: [fn(&mut ExecutionReleaseFields); 11] = [
        |f| f.attempt_id = [0; 16],
        |f| f.nonce = [0; 32],
        |f| f.ready1_digest = [0; 32],
        |f| f.trs1_digest = [0; 32],
        |f| f.rvs1_digest = [0; 32],
        |f| f.apt1_digest = [0; 32],
        |f| f.expected_readback_digest = [0; 32],
        |f| f.observed_readback_digest = [0; 32],
        |f| f.deadline_monotonic_ns = 0,
        |f| f.runtime_attestation_key_id = String::new(),
        |f| f.runtime_attestation_key_id = "k".repeat(129),
    ];
    for mutate in mutations {
        let mut fields = release_fields()?;
        mutate(&mut fields);
        assert!(ExecutionRelease::sign(fields, |_| [1; 64]).is_err());
    }
    assert!(ExecutionRelease::sign(release_fields()?, |_| [0; 64]).is_err());
    Ok(())
}

fn mutated(bytes: &[u8], path: &[usize], replacement: Value) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut value: Value = ciborium::from_reader(bytes)?;
    let mut cursor = &mut value;
    for &index in path {
        let Value::Array(items) = cursor else {
            return Err("path is not an array".into());
        };
        cursor = items.get_mut(index).ok_or("path index")?;
    }
    *cursor = replacement;
    let mut encoded = Vec::new();
    ciborium::into_writer(&value, &mut encoded)?;
    Ok(encoded)
}

#[test]
fn decoders_reject_wrong_magic_version_digest_and_truncation() -> TestResult {
    let lpv = launch()?.to_canonical_cbor()?;
    let rdy = LauncherReady::new(ready_fields()?)?.to_canonical_cbor()?;
    let rls = release()?.to_canonical_cbor()?;
    let decoders: [Case<'_>; 3] = [
        (lpv.as_slice(), |b| {
            LaunchParameters::from_canonical_cbor(b).is_err()
        }),
        (rdy.as_slice(), |b| {
            LauncherReady::from_canonical_cbor(b).is_err()
        }),
        (rls.as_slice(), |b| {
            ExecutionRelease::from_canonical_cbor(b).is_err()
        }),
    ];
    for (bytes, rejects) in decoders {
        assert!(!rejects(bytes));
        assert!(rejects(&bytes[..bytes.len() - 1]));
        assert!(rejects(&[bytes, &[0]].concat()));
        assert!(rejects(&[]));
        assert!(rejects(&mutated(
            bytes,
            &[0, 0],
            Value::Text("XXXX".to_owned())
        )?));
        assert!(rejects(&mutated(bytes, &[0, 1], Value::Integer(2.into()))?));
        assert!(rejects(&mutated(bytes, &[1], Value::Bytes(vec![1; 32]))?));
        assert!(rejects(&mutated(
            bytes,
            &[0, 2],
            Value::Bytes(vec![1; 15])
        )?));
    }
    Ok(())
}

#[test]
fn decoders_reject_a_correctly_digested_record_with_a_zero_field() -> TestResult {
    // A zero nonce keeps the old digest, so this proves field validation
    // runs before and independently of the digest comparison.
    let lpv = launch()?.to_canonical_cbor()?;
    assert!(LaunchParameters::from_canonical_cbor(&mutated(
        &lpv,
        &[0, 3],
        Value::Bytes(vec![0; 32])
    )?)
    .is_err());
    let rls = release()?.to_canonical_cbor()?;
    assert!(ExecutionRelease::from_canonical_cbor(&mutated(
        &rls,
        &[0, 13],
        Value::Integer(0.into())
    )?)
    .is_err());
    let zero_signature = mutated(&rls, &[2], Value::Bytes(vec![0; 64]))?;
    assert!(ExecutionRelease::from_canonical_cbor(&zero_signature).is_err());
    Ok(())
}

#[test]
fn every_decoder_field_rejects_a_value_of_the_wrong_type() -> TestResult {
    let lpv = launch()?.to_canonical_cbor()?;
    let rdy = LauncherReady::new(ready_fields()?)?.to_canonical_cbor()?;
    let rls = release()?.to_canonical_cbor()?;
    let cases: [PathCase<'_>; 3] = [
        (
            lpv.as_slice(),
            |b| LaunchParameters::from_canonical_cbor(b).is_err(),
            (2..=7).map(|index| vec![0, index]).collect(),
        ),
        (
            rdy.as_slice(),
            |b| LauncherReady::from_canonical_cbor(b).is_err(),
            (2..=12)
                .map(|index| vec![0, index])
                .chain([vec![0, 6, 0], vec![0, 6, 1], vec![0, 9, 0], vec![0, 9, 1]])
                .collect(),
        ),
        (
            rls.as_slice(),
            |b| ExecutionRelease::from_canonical_cbor(b).is_err(),
            (2..=14).map(|index| vec![0, index]).collect(),
        ),
    ];
    for (bytes, rejects, paths) in cases {
        for path in paths {
            assert!(
                rejects(&mutated(bytes, &path, Value::Null)?),
                "{path:?} accepted a null"
            );
        }
        assert!(rejects(&mutated(bytes, &[1], Value::Null)?));
    }
    Ok(())
}

#[test]
fn decoders_reject_oversized_and_zero_field_records() -> TestResult {
    assert_eq!(
        LaunchParameters::from_canonical_cbor(&vec![0; 64 * 1024 + 1]),
        Err(SandboxProviderProtocolError::FieldOutOfBounds)
    );
    // Exactly 64 KiB passes the size gate and fails later, in decoding.
    assert_eq!(
        LaunchParameters::from_canonical_cbor(&vec![0; 64 * 1024]),
        Err(SandboxProviderProtocolError::InvalidEncoding)
    );
    let rdy = LauncherReady::new(ready_fields()?)?.to_canonical_cbor()?;
    assert!(LauncherReady::from_canonical_cbor(&mutated(
        &rdy,
        &[0, 3],
        Value::Bytes(vec![0; 32])
    )?)
    .is_err());
    Ok(())
}
