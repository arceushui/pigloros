//! Fail-closed verification of the evaluator package that authorizes CNR1 emission.

use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use flate2::read::MultiGzDecoder;
use serde::{Deserialize, Serialize};

use crate::evaluator_protocol::IndependenceEvidence;

const MAX_EVALUATOR_BINARY_BYTES: u64 = 256 * 1024 * 1024;
const MAX_EVALUATOR_SOURCE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_EVALUATOR_PROVENANCE_BYTES: u64 = 4 * 1024;
const MAX_DEPENDENCY_LOCK_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SBOM_BYTES: u64 = 64 * 1024 * 1024;
const MAX_LICENCES_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CHECKSUM_BYTES: u64 = 4 * 1024;
const MAX_TAR_METADATA_BYTES: u64 = 4 * 1024;
const MAX_SOURCE_TAR_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const PROVENANCE_SCHEMA: &str = "PiglorOS.EvaluatorBuildProvenance.v1";
const PROVENANCE_DOMAIN: &[u8] = b"PiglorOS.EvaluatorBuildProvenance.v1";
const EVIDENCE_FILES: [&str; 6] = [
    "Cargo.lock",
    "bin/pos-reference-evaluator",
    "licences.json",
    "provenance.json",
    "sbom.cdx.json",
    "source/pigloros-source.tar.gz",
];
const REQUIRED_SOURCE_ENTRIES: [&str; 4] = [
    "Cargo.lock",
    "Cargo.toml",
    "crates/pos-reference/Cargo.toml",
    "crates/pos-reference/src/bin/pos-reference-evaluator.rs",
];

/// The two declared paths that locate one complete evaluator evidence package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvaluatorBuildEvidence {
    source_archive: PathBuf,
    provenance: PathBuf,
}

impl EvaluatorBuildEvidence {
    /// Bind the source archive and provenance declaration for one evaluator package.
    #[must_use]
    pub fn new(source_archive: impl Into<PathBuf>, provenance: impl Into<PathBuf>) -> Self {
        Self {
            source_archive: source_archive.into(),
            provenance: provenance.into(),
        }
    }
}

/// A capability produced only after complete evaluator-package verification.
///
/// Its fields are deliberately private: report emission cannot be authorized by
/// caller-supplied source, binary, or provenance digests.
///
/// ```compile_fail
/// use pos_reference::evaluator_build_identity::VerifiedEvaluatorBuildIdentity;
///
/// let _ = VerifiedEvaluatorBuildIdentity { source_digest: [0; 32] };
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedEvaluatorBuildIdentity {
    source_digest: [u8; 32],
    binary_digest: [u8; 32],
    build_provenance_digest: [u8; 32],
    independence: IndependenceEvidence,
}

impl VerifiedEvaluatorBuildIdentity {
    pub(crate) const fn source_digest(&self) -> [u8; 32] {
        self.source_digest
    }

    pub(crate) const fn binary_digest(&self) -> [u8; 32] {
        self.binary_digest
    }

    pub(crate) const fn independence(&self) -> &IndependenceEvidence {
        &self.independence
    }

    pub(crate) const fn build_provenance_digest(&self) -> [u8; 32] {
        self.build_provenance_digest
    }
}

/// Closed reason why evaluator-package verification could not authorize CNR1 emission.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum EvaluatorBuildIdentityError {
    #[error("an evaluator evidence artifact cannot be read within its bound")]
    Input,
    #[error("the evaluator evidence package is invalid")]
    Invalid,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BuildProvenance {
    build_target: String,
    cargo_locked: bool,
    dependency_lock_blake3: String,
    evaluator_binary_blake3: String,
    evaluator_source_blake3: String,
    licences_blake3: String,
    rust_toolchain: String,
    sbom_blake3: String,
    schema: String,
    source_commit: String,
}

/// Verify the complete package, source archive, and running executable before
/// creating the only capability accepted by the report-emitting evaluator API.
///
/// # Errors
/// Returns [`EvaluatorBuildIdentityError::Input`] when an evidence artifact
/// cannot be read within its exact bound, or [`EvaluatorBuildIdentityError::Invalid`]
/// when any canonicality, digest, source-archive, checksum, or executable
/// binding check fails.
pub fn verify_evaluator_build_identity(
    evidence: &EvaluatorBuildEvidence,
    independence: IndependenceEvidence,
) -> Result<VerifiedEvaluatorBuildIdentity, EvaluatorBuildIdentityError> {
    let provenance_path =
        fs::canonicalize(&evidence.provenance).map_err(|_| EvaluatorBuildIdentityError::Input)?;
    if provenance_path.file_name().and_then(|name| name.to_str()) != Some("provenance.json") {
        return Err(EvaluatorBuildIdentityError::Invalid);
    }
    let evidence_root = provenance_path
        .parent()
        .ok_or(EvaluatorBuildIdentityError::Invalid)?;
    let source_path = evidence_root.join("source/pigloros-source.tar.gz");
    if fs::canonicalize(&evidence.source_archive).map_err(|_| EvaluatorBuildIdentityError::Input)?
        != fs::canonicalize(&source_path).map_err(|_| EvaluatorBuildIdentityError::Input)?
    {
        return Err(EvaluatorBuildIdentityError::Invalid);
    }

    let provenance_bytes = read_bounded(&provenance_path, MAX_EVALUATOR_PROVENANCE_BYTES)?;
    let provenance = parse_build_provenance(&provenance_bytes)?;
    let mut source_archive = snapshot_bounded(&source_path, MAX_EVALUATOR_SOURCE_BYTES)?;
    let source = verified_file_digest(
        &mut source_archive,
        MAX_EVALUATOR_SOURCE_BYTES,
        &provenance.evaluator_source_blake3,
    )?;
    source_archive
        .seek(SeekFrom::Start(0))
        .map_err(|_| EvaluatorBuildIdentityError::Input)?;
    if embedded_git_commit(&mut source_archive)? != provenance.source_commit {
        return Err(EvaluatorBuildIdentityError::Invalid);
    }
    let packaged_binary = verified_digest(
        &evidence_root.join("bin/pos-reference-evaluator"),
        MAX_EVALUATOR_BINARY_BYTES,
        &provenance.evaluator_binary_blake3,
    )?;
    let running_binary = running_binary_digest()?;
    if packaged_binary != running_binary {
        return Err(EvaluatorBuildIdentityError::Invalid);
    }
    let lock = verified_digest(
        &evidence_root.join("Cargo.lock"),
        MAX_DEPENDENCY_LOCK_BYTES,
        &provenance.dependency_lock_blake3,
    )?;
    let licences = verified_digest(
        &evidence_root.join("licences.json"),
        MAX_LICENCES_BYTES,
        &provenance.licences_blake3,
    )?;
    let sbom = verified_digest(
        &evidence_root.join("sbom.cdx.json"),
        MAX_SBOM_BYTES,
        &provenance.sbom_blake3,
    )?;
    verify_checksum_inventory(
        evidence_root,
        [
            lock,
            packaged_binary,
            licences,
            *blake3::hash(&provenance_bytes).as_bytes(),
            sbom,
            source,
        ],
    )?;
    Ok(VerifiedEvaluatorBuildIdentity {
        source_digest: source,
        binary_digest: running_binary,
        build_provenance_digest: domain_digest(PROVENANCE_DOMAIN, &provenance_bytes),
        independence,
    })
}

fn parse_build_provenance(bytes: &[u8]) -> Result<BuildProvenance, EvaluatorBuildIdentityError> {
    let provenance =
        serde_json::from_slice(bytes).map_err(|_| EvaluatorBuildIdentityError::Invalid)?;
    if canonical_provenance(&provenance)? != bytes
        || provenance.schema != PROVENANCE_SCHEMA
        || !valid_commit(&provenance.source_commit)
        || !valid_metadata(&provenance.build_target)
        || !valid_metadata(&provenance.rust_toolchain)
        || !provenance.cargo_locked
        || [
            &provenance.dependency_lock_blake3,
            &provenance.evaluator_binary_blake3,
            &provenance.evaluator_source_blake3,
            &provenance.licences_blake3,
            &provenance.sbom_blake3,
        ]
        .iter()
        .any(|digest| parse_digest(digest).is_err())
    {
        Err(EvaluatorBuildIdentityError::Invalid)
    } else {
        Ok(provenance)
    }
}

fn canonical_provenance(
    provenance: &BuildProvenance,
) -> Result<Vec<u8>, EvaluatorBuildIdentityError> {
    serde_json::to_vec(provenance)
        .map_err(|_| EvaluatorBuildIdentityError::Invalid)
        .map(|mut bytes| {
            bytes.push(b'\n');
            bytes
        })
}

fn valid_commit(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(is_lower_hexadecimal)
}

fn valid_metadata(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| matches!(byte, 0x20..=0x7e) && !matches!(byte, b'"' | b'\\'))
}

fn verified_digest(
    path: &Path,
    maximum: u64,
    expected: &str,
) -> Result<[u8; 32], EvaluatorBuildIdentityError> {
    verify_digest(parse_digest(expected)?, digest_bounded(path, maximum)?)
}

fn verified_file_digest(
    file: &mut File,
    maximum: u64,
    expected: &str,
) -> Result<[u8; 32], EvaluatorBuildIdentityError> {
    verify_digest(parse_digest(expected)?, digest_bounded_file(file, maximum)?)
}

fn verify_digest(
    expected: [u8; 32],
    actual: [u8; 32],
) -> Result<[u8; 32], EvaluatorBuildIdentityError> {
    if actual == expected {
        Ok(actual)
    } else {
        Err(EvaluatorBuildIdentityError::Invalid)
    }
}

#[cfg(target_os = "linux")]
fn running_binary_digest() -> Result<[u8; 32], EvaluatorBuildIdentityError> {
    digest_bounded(Path::new("/proc/self/exe"), MAX_EVALUATOR_BINARY_BYTES)
        .map_err(|_| EvaluatorBuildIdentityError::Invalid)
}

#[cfg(not(target_os = "linux"))]
fn running_binary_digest() -> Result<[u8; 32], EvaluatorBuildIdentityError> {
    Err(EvaluatorBuildIdentityError::Invalid)
}

fn verify_checksum_inventory(
    evidence_root: &Path,
    digests: [[u8; 32]; 6],
) -> Result<(), EvaluatorBuildIdentityError> {
    let mut expected = String::new();
    for (path, digest) in EVIDENCE_FILES.iter().zip(digests) {
        let encoded = blake3::Hash::from_bytes(digest).to_hex();
        expected.push_str(encoded.as_str());
        expected.push_str("  ");
        expected.push_str(path);
        expected.push('\n');
    }
    if read_bounded(&evidence_root.join("BLAKE3SUMS"), MAX_CHECKSUM_BYTES)? == expected.as_bytes() {
        Ok(())
    } else {
        Err(EvaluatorBuildIdentityError::Invalid)
    }
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[0]);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn embedded_git_commit(reader: &mut impl Read) -> Result<String, EvaluatorBuildIdentityError> {
    let mut archive = MultiGzDecoder::new(reader).take(MAX_SOURCE_TAR_BYTES + 1);
    let mut commit = None;
    let mut required_entries = [false; REQUIRED_SOURCE_ENTRIES.len()];
    let mut zero_headers = 0_u8;
    loop {
        let mut header = [0_u8; 512];
        archive
            .read_exact(&mut header)
            .map_err(|_| EvaluatorBuildIdentityError::Invalid)?;
        if header == [0; 512] {
            zero_headers += 1;
            if zero_headers == 2 {
                validate_tar_termination(&mut archive)?;
                if MAX_SOURCE_TAR_BYTES + 1 - archive.limit() > MAX_SOURCE_TAR_BYTES
                    || commit.is_none()
                    || required_entries.contains(&false)
                {
                    return Err(EvaluatorBuildIdentityError::Invalid);
                }
                return commit.ok_or(EvaluatorBuildIdentityError::Invalid);
            }
            continue;
        }
        if zero_headers != 0 || !valid_tar_checksum(&header) {
            return Err(EvaluatorBuildIdentityError::Invalid);
        }
        let size = tar_octal(&header[124..136])?;
        if header[156] == b'g' {
            if commit.is_some() || size > MAX_TAR_METADATA_BYTES {
                return Err(EvaluatorBuildIdentityError::Invalid);
            }
            let record_size =
                usize::try_from(size).map_err(|_| EvaluatorBuildIdentityError::Invalid)?;
            let mut records = vec![0_u8; record_size];
            archive
                .read_exact(&mut records)
                .map_err(|_| EvaluatorBuildIdentityError::Invalid)?;
            skip_tar_padding(&mut archive, size)?;
            commit = Some(pax_commit(&records)?);
            continue;
        }
        if !matches!(header[156], 0 | b'0' | b'2' | b'5') {
            return Err(EvaluatorBuildIdentityError::Invalid);
        }
        let path = tar_path(&header)?;
        if let Some(index) = REQUIRED_SOURCE_ENTRIES
            .iter()
            .position(|required| path == *required)
        {
            required_entries[index] = true;
        }
        skip_exact(&mut archive, size)?;
        skip_tar_padding(&mut archive, size)?;
    }
}

fn tar_path(header: &[u8; 512]) -> Result<String, EvaluatorBuildIdentityError> {
    let name = tar_text(&header[..100])?;
    if name.is_empty() {
        return Err(EvaluatorBuildIdentityError::Invalid);
    }
    let prefix = tar_text(&header[345..500])?;
    Ok(if prefix.is_empty() {
        name.to_owned()
    } else {
        format!("{prefix}/{name}")
    })
}

fn tar_text(field: &[u8]) -> Result<&str, EvaluatorBuildIdentityError> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    if field[end..].iter().any(|byte| *byte != 0) {
        return Err(EvaluatorBuildIdentityError::Invalid);
    }
    std::str::from_utf8(&field[..end]).map_err(|_| EvaluatorBuildIdentityError::Invalid)
}

fn validate_tar_termination(reader: &mut impl Read) -> Result<(), EvaluatorBuildIdentityError> {
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|_| EvaluatorBuildIdentityError::Invalid)?;
        if read == 0 {
            return Ok(());
        }
        if buffer[..read].iter().any(|byte| *byte != 0) {
            return Err(EvaluatorBuildIdentityError::Invalid);
        }
    }
}

fn valid_tar_checksum(header: &[u8; 512]) -> bool {
    let Ok(expected) = tar_octal(&header[148..156]) else {
        return false;
    };
    let actual = header.iter().enumerate().fold(0_u64, |sum, (index, byte)| {
        sum + if (148..156).contains(&index) {
            u64::from(b' ')
        } else {
            u64::from(*byte)
        }
    });
    actual == expected
}

fn tar_octal(bytes: &[u8]) -> Result<u64, EvaluatorBuildIdentityError> {
    let text = std::str::from_utf8(bytes).map_err(|_| EvaluatorBuildIdentityError::Invalid)?;
    let digits = text.trim_matches(['\0', ' ']);
    if digits.is_empty() || !digits.bytes().all(|byte| matches!(byte, b'0'..=b'7')) {
        return Err(EvaluatorBuildIdentityError::Invalid);
    }
    u64::from_str_radix(digits, 8).map_err(|_| EvaluatorBuildIdentityError::Invalid)
}

fn skip_tar_padding(reader: &mut impl Read, size: u64) -> Result<(), EvaluatorBuildIdentityError> {
    skip_exact(reader, (512 - size % 512) % 512)
}

fn skip_exact(reader: &mut impl Read, bytes: u64) -> Result<(), EvaluatorBuildIdentityError> {
    if io::copy(&mut reader.take(bytes), &mut io::sink())
        .map_err(|_| EvaluatorBuildIdentityError::Invalid)?
        == bytes
    {
        Ok(())
    } else {
        Err(EvaluatorBuildIdentityError::Invalid)
    }
}

fn pax_commit(records: &[u8]) -> Result<String, EvaluatorBuildIdentityError> {
    let mut offset = 0;
    let mut commit = None;
    while offset < records.len() {
        let separator = records[offset..]
            .iter()
            .position(|byte| *byte == b' ')
            .map(|position| offset + position)
            .ok_or(EvaluatorBuildIdentityError::Invalid)?;
        let length = std::str::from_utf8(&records[offset..separator])
            .map_err(|_| EvaluatorBuildIdentityError::Invalid)?
            .parse::<usize>()
            .map_err(|_| EvaluatorBuildIdentityError::Invalid)?;
        let end = offset
            .checked_add(length)
            .ok_or(EvaluatorBuildIdentityError::Invalid)?;
        let record = records
            .get(separator + 1..end)
            .filter(|record| !record.is_empty() && record.last() == Some(&b'\n'))
            .ok_or(EvaluatorBuildIdentityError::Invalid)?;
        if let Some(commit_bytes) = record
            .strip_suffix(b"\n")
            .and_then(|record| record.strip_prefix(b"comment="))
        {
            if commit_bytes.is_empty() {
                return Err(EvaluatorBuildIdentityError::Invalid);
            }
            let parsed = std::str::from_utf8(commit_bytes)
                .map_err(|_| EvaluatorBuildIdentityError::Invalid)?;
            if !valid_commit(parsed) || commit.replace(parsed.to_owned()).is_some() {
                return Err(EvaluatorBuildIdentityError::Invalid);
            }
        }
        offset = end;
    }
    commit.ok_or(EvaluatorBuildIdentityError::Invalid)
}

const fn is_lower_hexadecimal(value: u8) -> bool {
    value.is_ascii_digit() || matches!(value, b'a'..=b'f')
}

fn parse_digest(value: &str) -> Result<[u8; 32], EvaluatorBuildIdentityError> {
    if value.len() != 64 {
        return Err(EvaluatorBuildIdentityError::Invalid);
    }
    let mut digest = [0_u8; 32];
    for (target, pair) in digest.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let high = hexadecimal_nibble(pair[0]).ok_or(EvaluatorBuildIdentityError::Invalid)?;
        let low = hexadecimal_nibble(pair[1]).ok_or(EvaluatorBuildIdentityError::Invalid)?;
        *target = high << 4 | low;
    }
    if digest == [0; 32] {
        Err(EvaluatorBuildIdentityError::Invalid)
    } else {
        Ok(digest)
    }
}

const fn hexadecimal_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn digest_bounded(path: &Path, maximum: u64) -> Result<[u8; 32], EvaluatorBuildIdentityError> {
    let mut file = File::open(path).map_err(|_| EvaluatorBuildIdentityError::Input)?;
    digest_bounded_file(&mut file, maximum)
}

fn digest_bounded_file(
    file: &mut File,
    maximum: u64,
) -> Result<[u8; 32], EvaluatorBuildIdentityError> {
    if file
        .metadata()
        .map_err(|_| EvaluatorBuildIdentityError::Input)?
        .len()
        > maximum
    {
        return Err(EvaluatorBuildIdentityError::Input);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| EvaluatorBuildIdentityError::Input)?;
    let mut bounded = file.take(maximum.saturating_add(1));
    let mut hasher = blake3::Hasher::new();
    let byte_length =
        io::copy(&mut bounded, &mut hasher).map_err(|_| EvaluatorBuildIdentityError::Input)?;
    if byte_length > maximum {
        Err(EvaluatorBuildIdentityError::Input)
    } else {
        Ok(*hasher.finalize().as_bytes())
    }
}

fn snapshot_bounded(path: &Path, maximum: u64) -> Result<File, EvaluatorBuildIdentityError> {
    let source = File::open(path).map_err(|_| EvaluatorBuildIdentityError::Input)?;
    let mut snapshot = tempfile::tempfile().map_err(|_| EvaluatorBuildIdentityError::Input)?;
    let copied = io::copy(&mut source.take(maximum.saturating_add(1)), &mut snapshot)
        .map_err(|_| EvaluatorBuildIdentityError::Input)?;
    if copied > maximum {
        return Err(EvaluatorBuildIdentityError::Input);
    }
    snapshot
        .seek(SeekFrom::Start(0))
        .map_err(|_| EvaluatorBuildIdentityError::Input)?;
    Ok(snapshot)
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, EvaluatorBuildIdentityError> {
    let file = File::open(path).map_err(|_| EvaluatorBuildIdentityError::Input)?;
    let capacity = usize::try_from(maximum.min(16 * 1024 * 1024))
        .map_err(|_| EvaluatorBuildIdentityError::Input)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| EvaluatorBuildIdentityError::Input)?;
    if bytes.len() as u64 > maximum {
        Err(EvaluatorBuildIdentityError::Input)
    } else {
        Ok(bytes)
    }
}
