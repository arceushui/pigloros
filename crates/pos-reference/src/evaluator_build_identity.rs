//! Fail-closed verification of the evaluator package that authorizes CNR1 emission.

use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use flate2::read::MultiGzDecoder;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::bounded_input::{
    open_regular_file, parse_nonzero_digest, read_bounded, snapshot_bounded, BoundedInputError,
};
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
const REQUIRED_SOURCE_ENTRIES: [&str; 4] = [
    "Cargo.lock",
    "Cargo.toml",
    "crates/pos-reference/Cargo.toml",
    "crates/pos-reference/src/bin/pos-reference-evaluator.rs",
];

/// One value per file of an evaluator evidence package, named by the file's role.
///
/// [`EvidenceFiles::ordered`] is the single definition of the checksum-inventory order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceFiles<T> {
    /// The dependency lock file.
    pub lock: T,
    /// The evaluator executable.
    pub binary: T,
    /// The licence inventory.
    pub licences: T,
    /// The build provenance declaration.
    pub provenance: T,
    /// The software bill of materials.
    pub sbom: T,
    /// The source archive.
    pub source: T,
}

/// The only accepted package-relative path of each evidence file.
pub const PACKAGE_EVIDENCE_FILES: EvidenceFiles<&str> = EvidenceFiles {
    lock: "Cargo.lock",
    binary: "bin/pos-reference-evaluator",
    licences: "licences.json",
    provenance: "provenance.json",
    sbom: "sbom.cdx.json",
    source: "source/pigloros-source.tar.gz",
};

impl<T: Copy> EvidenceFiles<T> {
    /// Return the values in checksum-inventory order.
    #[must_use]
    pub const fn ordered(&self) -> [T; 6] {
        [
            self.lock,
            self.binary,
            self.licences,
            self.provenance,
            self.sbom,
            self.source,
        ]
    }
}

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
    source_archive_bytes: u64,
    source_expanded_bytes: u64,
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

    pub(crate) const fn admits_compression_expansion(&self, maximum: u64) -> bool {
        maximum != 0
            && self.source_expanded_bytes <= self.source_archive_bytes.saturating_mul(maximum)
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

impl From<BoundedInputError> for EvaluatorBuildIdentityError {
    fn from(_: BoundedInputError) -> Self {
        Self::Input
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BuildProvenance {
    build_target: String,
    cargo_locked: bool,
    dependency_lock_blake3: BuildDigest,
    evaluator_binary_blake3: BuildDigest,
    evaluator_source_blake3: BuildDigest,
    licences_blake3: BuildDigest,
    rust_toolchain: String,
    sbom_blake3: BuildDigest,
    schema: String,
    source_commit: String,
}

#[derive(Debug, Eq, PartialEq)]
struct BuildDigest([u8; 32]);

impl<'de> Deserialize<'de> for BuildDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)
            .and_then(|encoded| {
                parse_nonzero_digest(&encoded)
                    .ok_or_else(|| serde::de::Error::custom("invalid digest"))
            })
            .map(Self)
    }
}

impl Serialize for BuildDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(blake3::Hash::from_bytes(self.0).to_hex().as_str())
    }
}

/// Verify the complete package, source archive, and running executable before
/// creating the only capability accepted by the report-emitting evaluator API.
///
/// # Errors
/// Returns [`EvaluatorBuildIdentityError::Input`] when an evidence artifact
/// cannot be read within its exact bound, or [`EvaluatorBuildIdentityError::Invalid`]
/// when any canonicality, digest, source-archive, checksum, or executable
/// binding check fails, including when source expansion exceeds the authenticated
/// `max_compression_expansion` ratio.
pub fn verify_evaluator_build_identity(
    evidence: &EvaluatorBuildEvidence,
    independence: IndependenceEvidence,
    max_compression_expansion: u64,
) -> Result<VerifiedEvaluatorBuildIdentity, EvaluatorBuildIdentityError> {
    let provenance_path =
        fs::canonicalize(&evidence.provenance).map_err(|_| EvaluatorBuildIdentityError::Input)?;
    if provenance_path.file_name().and_then(|name| name.to_str())
        != Some(PACKAGE_EVIDENCE_FILES.provenance)
    {
        return Err(EvaluatorBuildIdentityError::Invalid);
    }
    let evidence_root = provenance_path.with_file_name("");
    let source_path = evidence_root.join(PACKAGE_EVIDENCE_FILES.source);
    if fs::canonicalize(&evidence.source_archive).map_err(|_| EvaluatorBuildIdentityError::Input)?
        != fs::canonicalize(&source_path).map_err(|_| EvaluatorBuildIdentityError::Input)?
    {
        return Err(EvaluatorBuildIdentityError::Invalid);
    }

    let provenance_bytes = read_bounded(&provenance_path, MAX_EVALUATOR_PROVENANCE_BYTES)?;
    let provenance = parse_build_provenance(&provenance_bytes)?;
    let mut source_archive = snapshot_bounded(&source_path, MAX_EVALUATOR_SOURCE_BYTES)?;
    let source_archive_bytes = source_archive
        .metadata()
        .map_err(|_| EvaluatorBuildIdentityError::Input)?
        .len();
    let source = verified_file_digest(
        &mut source_archive,
        MAX_EVALUATOR_SOURCE_BYTES,
        &provenance.evaluator_source_blake3,
    )?;
    source_archive
        .seek(SeekFrom::Start(0))
        .map_err(|_| EvaluatorBuildIdentityError::Input)?;
    let source_identity = embedded_git_commit(
        &mut source_archive,
        source_archive_bytes,
        max_compression_expansion,
    )?;
    if source_identity.commit != provenance.source_commit {
        return Err(EvaluatorBuildIdentityError::Invalid);
    }
    let packaged_binary = verified_digest(
        &evidence_root.join(PACKAGE_EVIDENCE_FILES.binary),
        MAX_EVALUATOR_BINARY_BYTES,
        &provenance.evaluator_binary_blake3,
    )?;
    let running_binary = running_binary_digest()?;
    if packaged_binary != running_binary {
        return Err(EvaluatorBuildIdentityError::Invalid);
    }
    let lock = verified_digest(
        &evidence_root.join(PACKAGE_EVIDENCE_FILES.lock),
        MAX_DEPENDENCY_LOCK_BYTES,
        &provenance.dependency_lock_blake3,
    )?;
    let licences = verified_digest(
        &evidence_root.join(PACKAGE_EVIDENCE_FILES.licences),
        MAX_LICENCES_BYTES,
        &provenance.licences_blake3,
    )?;
    let sbom = verified_digest(
        &evidence_root.join(PACKAGE_EVIDENCE_FILES.sbom),
        MAX_SBOM_BYTES,
        &provenance.sbom_blake3,
    )?;
    verify_checksum_inventory(
        &evidence_root,
        EvidenceFiles {
            lock,
            binary: packaged_binary,
            licences,
            provenance: *blake3::hash(&provenance_bytes).as_bytes(),
            sbom,
            source,
        },
    )?;
    Ok(VerifiedEvaluatorBuildIdentity {
        source_digest: source,
        source_archive_bytes,
        source_expanded_bytes: source_identity.expanded_bytes,
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
    expected: &BuildDigest,
) -> Result<[u8; 32], EvaluatorBuildIdentityError> {
    verify_digest(expected.0, digest_bounded(path, maximum)?)
}

fn verified_file_digest(
    file: &mut File,
    maximum: u64,
    expected: &BuildDigest,
) -> Result<[u8; 32], EvaluatorBuildIdentityError> {
    digest_bounded_file(file, maximum).and_then(|actual| verify_digest(expected.0, actual))
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
    let mut executable =
        File::open("/proc/self/exe").map_err(|_| EvaluatorBuildIdentityError::Invalid)?;
    digest_bounded_file(&mut executable, MAX_EVALUATOR_BINARY_BYTES)
        .map_err(|_| EvaluatorBuildIdentityError::Invalid)
}

#[cfg(not(target_os = "linux"))]
fn running_binary_digest() -> Result<[u8; 32], EvaluatorBuildIdentityError> {
    Err(EvaluatorBuildIdentityError::Invalid)
}

fn verify_checksum_inventory(
    evidence_root: &Path,
    digests: EvidenceFiles<[u8; 32]>,
) -> Result<(), EvaluatorBuildIdentityError> {
    let mut expected = String::new();
    for (path, digest) in PACKAGE_EVIDENCE_FILES
        .ordered()
        .into_iter()
        .zip(digests.ordered())
    {
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

struct SourceArchiveIdentity {
    commit: String,
    expanded_bytes: u64,
}

fn embedded_git_commit(
    reader: &mut impl Read,
    compressed_bytes: u64,
    max_compression_expansion: u64,
) -> Result<SourceArchiveIdentity, EvaluatorBuildIdentityError> {
    if compressed_bytes == 0 || max_compression_expansion == 0 {
        return Err(EvaluatorBuildIdentityError::Invalid);
    }
    let selected_limit = compressed_bytes
        .saturating_mul(max_compression_expansion)
        .min(MAX_SOURCE_TAR_BYTES);
    let read_limit = selected_limit + 1;
    let mut archive = MultiGzDecoder::new(reader).take(read_limit);
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
                let expanded_bytes = read_limit - archive.limit();
                if expanded_bytes > selected_limit
                    || commit.is_none()
                    || required_entries.contains(&false)
                {
                    return Err(EvaluatorBuildIdentityError::Invalid);
                }
                return Ok(SourceArchiveIdentity {
                    commit: commit.ok_or(EvaluatorBuildIdentityError::Invalid)?,
                    expanded_bytes,
                });
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
            if required_entries[index] || !matches!(header[156], 0 | b'0') {
                return Err(EvaluatorBuildIdentityError::Invalid);
            }
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

fn digest_bounded(path: &Path, maximum: u64) -> Result<[u8; 32], EvaluatorBuildIdentityError> {
    let mut file = open_regular_file(path)?;
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
