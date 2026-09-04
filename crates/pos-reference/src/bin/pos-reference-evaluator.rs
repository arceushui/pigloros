//! Standalone, bounded entry point for independent black-box evaluation.

use std::env;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use flate2::read::GzDecoder;
use pos_reference::evaluator::{evaluate, EvaluatorIdentity};
use pos_reference::evaluator_protocol::{EvaluationRequest, IndependenceEvidence, ProtocolError};
use pos_reference::process_adapter::ProcessAdapter;
use pos_reference::profile::Profile;
use pos_reference::signed_bundle::{preflight_signed_bundle, SelectedBundleCaps};
use serde::{Deserialize, Serialize};

const MAX_REQUEST_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_TRUST_POLICY_BYTES: u64 = 16 * 1024 * 1024;
const MAX_EVALUATOR_BINARY_BYTES: u64 = 256 * 1024 * 1024;
const MAX_EVALUATOR_SOURCE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_EVALUATOR_PROVENANCE_BYTES: u64 = 4 * 1024;
const MAX_DEPENDENCY_LOCK_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SBOM_BYTES: u64 = 64 * 1024 * 1024;
const MAX_LICENCES_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CHECKSUM_BYTES: u64 = 4 * 1024;
const MAX_TAR_METADATA_BYTES: u64 = 4 * 1024 * 1024;
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

struct VerifiedEvaluatorDigests {
    source: [u8; 32],
    binary: [u8; 32],
    provenance: [u8; 32],
}

#[derive(Debug, thiserror::Error)]
enum CommandError {
    #[error("command arguments are invalid")]
    Arguments,
    #[error("an input artifact cannot be read within its bound")]
    Input,
    #[error("the evaluator protocol version is unsupported")]
    UnsupportedVersion,
    #[error("the evaluator identity is invalid")]
    Identity,
    #[error("the subject adapter configuration is invalid")]
    Adapter,
    #[error("independent evaluation failed")]
    Evaluation,
    #[error("bounded output failed")]
    Output,
}

struct Options {
    request: PathBuf,
    archive: PathBuf,
    trust_policy: PathBuf,
    evaluator_evidence: EvaluatorEvidence,
    declaration_digest: [u8; 32],
    shared_code_audit_digest: [u8; 32],
    reviewer_ids: Vec<String>,
    authorship_independent: bool,
    organizational_independent: bool,
    adapter: PathBuf,
    adapter_arguments: Vec<OsString>,
}

#[derive(Default)]
struct OptionsBuilder {
    request: Option<PathBuf>,
    archive: Option<PathBuf>,
    trust_policy: Option<PathBuf>,
    evaluator_evidence: EvaluatorEvidenceBuilder,
    declaration_digest: Option<[u8; 32]>,
    shared_code_audit_digest: Option<[u8; 32]>,
    reviewer_ids: Vec<String>,
    authorship_independent: bool,
    organizational_independent: bool,
    adapter: Option<PathBuf>,
    adapter_arguments: Vec<OsString>,
}

struct EvaluatorEvidence {
    source: PathBuf,
    provenance: PathBuf,
}

#[derive(Default)]
struct EvaluatorEvidenceBuilder {
    source: Option<PathBuf>,
    provenance: Option<PathBuf>,
}

fn main() -> Result<(), CommandError> {
    run()
}

fn run() -> Result<(), CommandError> {
    let options = parse_options(env::args_os())?;
    let request_bytes = read_bounded(&options.request, MAX_REQUEST_BYTES)?;
    let request = EvaluationRequest::from_canonical_cbor(&request_bytes).map_err(|error| {
        if error == ProtocolError::UnsupportedVersion {
            CommandError::UnsupportedVersion
        } else {
            CommandError::Input
        }
    })?;
    let evaluator_digests = verified_evaluator_digests(&options)?;
    let trust_policy_bytes = read_bounded(&options.trust_policy, MAX_TRUST_POLICY_BYTES)?;
    let mut archive = File::open(&options.archive).map_err(|_| CommandError::Input)?;
    let preflight = preflight_signed_bundle(&mut archive, &trust_policy_bytes, &request)
        .map_err(|_| CommandError::Evaluation)?;
    let caps = Profile::authenticated_hard_caps(preflight.profile_bytes(), &request)
        .map_err(|_| CommandError::Evaluation)?;
    preflight
        .enforce_selected_caps(SelectedBundleCaps {
            max_profile_bytes: caps.max_profile_bytes,
            max_bundle_members: caps.max_bundle_members,
            max_member_path_bytes: caps.max_member_path_bytes,
            max_member_bytes: caps.max_member_bytes,
            max_total_bundle_bytes: caps.max_total_bundle_bytes,
        })
        .map_err(|_| CommandError::Evaluation)?;
    let archive_bytes = read_bounded(&options.archive, MAX_ARCHIVE_BYTES)?;
    let identity = EvaluatorIdentity {
        source_digest: evaluator_digests.source,
        binary_digest: evaluator_digests.binary,
        build_provenance_digest: evaluator_digests.provenance,
        independence: IndependenceEvidence {
            technical_independent: true,
            authorship_independent: options.authorship_independent,
            organizational_independent: options.organizational_independent,
            declaration_digest: options.declaration_digest,
            shared_code_audit_digest: options.shared_code_audit_digest,
            reviewer_ids: options.reviewer_ids,
        },
    };
    let mut adapter = ProcessAdapter::new(
        request.subject_adapter,
        request.subject_artifact_digest,
        options.adapter,
        options.adapter_arguments,
    )
    .map_err(|_| CommandError::Adapter)?;
    let artifacts = evaluate(
        &request_bytes,
        &archive_bytes,
        &trust_policy_bytes,
        &identity,
        &mut adapter,
    )
    .map_err(|_| CommandError::Evaluation)?;
    io::stdout()
        .lock()
        .write_all(&artifacts.report_bytes)
        .map_err(|_| CommandError::Output)?;
    if let Some(diagnostics) = artifacts.diagnostic_bytes {
        io::stderr()
            .lock()
            .write_all(&diagnostics)
            .map_err(|_| CommandError::Output)?;
    }
    Ok(())
}

fn parse_options(arguments: impl Iterator<Item = OsString>) -> Result<Options, CommandError> {
    let mut arguments = arguments.skip(1);
    let mut builder = OptionsBuilder::default();
    while let Some(argument) = arguments.next() {
        parse_option(&mut builder, &mut arguments, &argument)?;
    }
    builder.finish()
}

fn parse_option(
    builder: &mut OptionsBuilder,
    arguments: &mut impl Iterator<Item = OsString>,
    argument: &OsString,
) -> Result<(), CommandError> {
    if parse_evaluator_evidence_option(&mut builder.evaluator_evidence, arguments, argument)? {
        return Ok(());
    }
    match argument.to_str().ok_or(CommandError::Arguments)? {
        "--request" => set_once(&mut builder.request, next_path(arguments)?)?,
        "--bundle" => set_once(&mut builder.archive, next_path(arguments)?)?,
        "--trust-policy" => set_once(&mut builder.trust_policy, next_path(arguments)?)?,
        "--declaration-digest" => {
            set_once(&mut builder.declaration_digest, next_digest(arguments)?)?;
        }
        "--shared-code-audit-digest" => {
            set_once(
                &mut builder.shared_code_audit_digest,
                next_digest(arguments)?,
            )?;
        }
        "--reviewer" => builder.reviewer_ids.push(next_text(arguments)?),
        "--authorship-independent" if !builder.authorship_independent => {
            builder.authorship_independent = true;
        }
        "--organizational-independent" if !builder.organizational_independent => {
            builder.organizational_independent = true;
        }
        "--adapter" => set_once(&mut builder.adapter, next_path(arguments)?)?,
        "--adapter-arg" => builder.adapter_arguments.push(next_argument(arguments)?),
        _ => return Err(CommandError::Arguments),
    }
    Ok(())
}

fn parse_evaluator_evidence_option(
    builder: &mut EvaluatorEvidenceBuilder,
    arguments: &mut impl Iterator<Item = OsString>,
    argument: &OsString,
) -> Result<bool, CommandError> {
    match argument.to_str().ok_or(CommandError::Arguments)? {
        "--evaluator-source" => {
            set_once(&mut builder.source, next_path(arguments)?)?;
            Ok(true)
        }
        "--evaluator-provenance" => {
            set_once(&mut builder.provenance, next_path(arguments)?)?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

impl OptionsBuilder {
    fn finish(self) -> Result<Options, CommandError> {
        if self.reviewer_ids.is_empty()
            || self
                .reviewer_ids
                .windows(2)
                .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
        {
            return Err(CommandError::Identity);
        }
        Ok(Options {
            request: self.request.ok_or(CommandError::Arguments)?,
            archive: self.archive.ok_or(CommandError::Arguments)?,
            trust_policy: self.trust_policy.ok_or(CommandError::Arguments)?,
            evaluator_evidence: self.evaluator_evidence.finish()?,
            declaration_digest: self.declaration_digest.ok_or(CommandError::Arguments)?,
            shared_code_audit_digest: self
                .shared_code_audit_digest
                .ok_or(CommandError::Arguments)?,
            reviewer_ids: self.reviewer_ids,
            authorship_independent: self.authorship_independent,
            organizational_independent: self.organizational_independent,
            adapter: self.adapter.ok_or(CommandError::Arguments)?,
            adapter_arguments: self.adapter_arguments,
        })
    }
}

impl EvaluatorEvidenceBuilder {
    fn finish(self) -> Result<EvaluatorEvidence, CommandError> {
        Ok(EvaluatorEvidence {
            source: self.source.ok_or(CommandError::Arguments)?,
            provenance: self.provenance.ok_or(CommandError::Arguments)?,
        })
    }
}

fn verified_evaluator_digests(options: &Options) -> Result<VerifiedEvaluatorDigests, CommandError> {
    let provenance_path = fs::canonicalize(&options.evaluator_evidence.provenance)
        .map_err(|_| CommandError::Input)?;
    if provenance_path.file_name().and_then(|name| name.to_str()) != Some("provenance.json") {
        return Err(CommandError::Identity);
    }
    let evidence_root = provenance_path.parent().ok_or(CommandError::Identity)?;
    let source_path = evidence_root.join("source/pigloros-source.tar.gz");
    if fs::canonicalize(&options.evaluator_evidence.source).map_err(|_| CommandError::Input)?
        != fs::canonicalize(&source_path).map_err(|_| CommandError::Input)?
    {
        return Err(CommandError::Identity);
    }

    let provenance_bytes = read_bounded(&provenance_path, MAX_EVALUATOR_PROVENANCE_BYTES)?;
    let provenance = parse_build_provenance(&provenance_bytes)?;
    let source = verified_digest(
        &source_path,
        MAX_EVALUATOR_SOURCE_BYTES,
        &provenance.evaluator_source_blake3,
    )?;
    if embedded_git_commit(&source_path)? != provenance.source_commit {
        return Err(CommandError::Identity);
    }
    let packaged_binary = verified_digest(
        &evidence_root.join("bin/pos-reference-evaluator"),
        MAX_EVALUATOR_BINARY_BYTES,
        &provenance.evaluator_binary_blake3,
    )?;
    let running_binary = digest_bounded(
        &env::current_exe().map_err(|_| CommandError::Identity)?,
        MAX_EVALUATOR_BINARY_BYTES,
    )?;
    if packaged_binary != running_binary {
        return Err(CommandError::Identity);
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
    Ok(VerifiedEvaluatorDigests {
        source,
        binary: running_binary,
        provenance: domain_digest(PROVENANCE_DOMAIN, &provenance_bytes),
    })
}

fn parse_build_provenance(bytes: &[u8]) -> Result<BuildProvenance, CommandError> {
    let provenance: BuildProvenance =
        serde_json::from_slice(bytes).map_err(|_| CommandError::Identity)?;
    if canonical_provenance(&provenance)? != bytes
        || provenance.schema != PROVENANCE_SCHEMA
        || !valid_commit(&provenance.source_commit)
        || !valid_metadata(&provenance.build_target)
        || !valid_metadata(&provenance.rust_toolchain)
        || !provenance.cargo_locked
    {
        return Err(CommandError::Identity);
    }
    for digest in [
        &provenance.dependency_lock_blake3,
        &provenance.evaluator_binary_blake3,
        &provenance.evaluator_source_blake3,
        &provenance.licences_blake3,
        &provenance.sbom_blake3,
    ] {
        parse_digest(digest)?;
    }
    Ok(provenance)
}

fn canonical_provenance(provenance: &BuildProvenance) -> Result<Vec<u8>, CommandError> {
    let mut bytes = serde_json::to_vec(provenance).map_err(|_| CommandError::Identity)?;
    bytes.push(b'\n');
    Ok(bytes)
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

fn verified_digest(path: &Path, maximum: u64, expected: &str) -> Result<[u8; 32], CommandError> {
    let expected = parse_digest(expected)?;
    let actual = digest_bounded(path, maximum)?;
    if actual == expected {
        Ok(actual)
    } else {
        Err(CommandError::Identity)
    }
}

fn verify_checksum_inventory(
    evidence_root: &Path,
    digests: [[u8; 32]; 6],
) -> Result<(), CommandError> {
    let mut expected = String::new();
    for (path, digest) in EVIDENCE_FILES.iter().zip(digests) {
        let encoded = blake3::Hash::from_bytes(digest).to_hex();
        expected.push_str(encoded.as_str());
        expected.push_str("  ");
        expected.push_str(path);
        expected.push('\n');
    }
    let actual = read_bounded(&evidence_root.join("BLAKE3SUMS"), MAX_CHECKSUM_BYTES)?;
    if actual == expected.as_bytes() {
        Ok(())
    } else {
        Err(CommandError::Identity)
    }
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[0]);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn embedded_git_commit(path: &Path) -> Result<String, CommandError> {
    let file = File::open(path).map_err(|_| CommandError::Input)?;
    let mut archive = GzDecoder::new(file).take(MAX_TAR_METADATA_BYTES);
    loop {
        let mut header = [0_u8; 512];
        archive
            .read_exact(&mut header)
            .map_err(|_| CommandError::Identity)?;
        if header == [0; 512] || !valid_tar_checksum(&header) {
            return Err(CommandError::Identity);
        }
        let size = tar_octal(&header[124..136])?;
        if header[156] == b'g' {
            if size > MAX_EVALUATOR_PROVENANCE_BYTES {
                return Err(CommandError::Identity);
            }
            let record_size = usize::try_from(size).map_err(|_| CommandError::Identity)?;
            let mut records = vec![0_u8; record_size];
            archive
                .read_exact(&mut records)
                .map_err(|_| CommandError::Identity)?;
            skip_tar_padding(&mut archive, size as u64)?;
            return pax_commit(&records);
        }
        skip_exact(&mut archive, size)?;
        skip_tar_padding(&mut archive, size)?;
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

fn tar_octal(bytes: &[u8]) -> Result<u64, CommandError> {
    let text = std::str::from_utf8(bytes).map_err(|_| CommandError::Identity)?;
    let digits = text.trim_matches(['\0', ' ']);
    if digits.is_empty() || !digits.bytes().all(|byte| matches!(byte, b'0'..=b'7')) {
        return Err(CommandError::Identity);
    }
    u64::from_str_radix(digits, 8).map_err(|_| CommandError::Identity)
}

fn skip_tar_padding(reader: &mut impl Read, size: u64) -> Result<(), CommandError> {
    skip_exact(reader, (512 - size % 512) % 512)
}

fn skip_exact(reader: &mut impl Read, bytes: u64) -> Result<(), CommandError> {
    let copied =
        io::copy(&mut reader.take(bytes), &mut io::sink()).map_err(|_| CommandError::Identity)?;
    if copied == bytes {
        Ok(())
    } else {
        Err(CommandError::Identity)
    }
}

fn pax_commit(records: &[u8]) -> Result<String, CommandError> {
    let mut offset = 0;
    while offset < records.len() {
        let separator = records[offset..]
            .iter()
            .position(|byte| *byte == b' ')
            .map(|position| offset + position)
            .ok_or(CommandError::Identity)?;
        let length = std::str::from_utf8(&records[offset..separator])
            .map_err(|_| CommandError::Identity)?
            .parse::<usize>()
            .map_err(|_| CommandError::Identity)?;
        let end = offset.checked_add(length).ok_or(CommandError::Identity)?;
        let record = records
            .get(separator + 1..end)
            .filter(|record| record.last() == Some(&b'\n'))
            .ok_or(CommandError::Identity)?;
        if let Some(commit) = record
            .strip_suffix(b"\n")
            .and_then(|record| record.strip_prefix(b"comment="))
        {
            let commit = std::str::from_utf8(commit).map_err(|_| CommandError::Identity)?;
            return valid_commit(commit)
                .then(|| commit.to_owned())
                .ok_or(CommandError::Identity);
        }
        offset = end;
    }
    Err(CommandError::Identity)
}

const fn is_lower_hexadecimal(value: u8) -> bool {
    value.is_ascii_digit() || matches!(value, b'a'..=b'f')
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), CommandError> {
    if slot.replace(value).is_some() {
        Err(CommandError::Arguments)
    } else {
        Ok(())
    }
}

fn next_path(arguments: &mut impl Iterator<Item = OsString>) -> Result<PathBuf, CommandError> {
    next_argument(arguments).map(PathBuf::from)
}

fn next_text(arguments: &mut impl Iterator<Item = OsString>) -> Result<String, CommandError> {
    next_argument(arguments)?
        .into_string()
        .map_err(|_| CommandError::Arguments)
}

fn next_digest(arguments: &mut impl Iterator<Item = OsString>) -> Result<[u8; 32], CommandError> {
    parse_digest(&next_text(arguments)?)
}

fn next_argument(arguments: &mut impl Iterator<Item = OsString>) -> Result<OsString, CommandError> {
    arguments.next().ok_or(CommandError::Arguments)
}

fn parse_digest(value: &str) -> Result<[u8; 32], CommandError> {
    if value.len() != 64 {
        return Err(CommandError::Identity);
    }
    let mut digest = [0_u8; 32];
    for (target, pair) in digest.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let high = hexadecimal_nibble(pair[0]).ok_or(CommandError::Identity)?;
        let low = hexadecimal_nibble(pair[1]).ok_or(CommandError::Identity)?;
        *target = high << 4 | low;
    }
    if digest == [0; 32] {
        Err(CommandError::Identity)
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

fn digest_bounded(path: &Path, maximum: u64) -> Result<[u8; 32], CommandError> {
    let file = File::open(path).map_err(|_| CommandError::Input)?;
    if file.metadata().map_err(|_| CommandError::Input)?.len() > maximum {
        return Err(CommandError::Input);
    }
    let mut bounded = file.take(maximum.saturating_add(1));
    let mut hasher = blake3::Hasher::new();
    let byte_length = io::copy(&mut bounded, &mut hasher).map_err(|_| CommandError::Input)?;
    if byte_length > maximum {
        Err(CommandError::Input)
    } else {
        Ok(*hasher.finalize().as_bytes())
    }
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, CommandError> {
    let file = File::open(path).map_err(|_| CommandError::Input)?;
    if file.metadata().map_err(|_| CommandError::Input)?.len() > maximum {
        return Err(CommandError::Input);
    }
    let capacity =
        usize::try_from(maximum.min(16 * 1024 * 1024)).map_err(|_| CommandError::Input)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| CommandError::Input)?;
    if bytes.len() as u64 > maximum {
        Err(CommandError::Input)
    } else {
        Ok(bytes)
    }
}
