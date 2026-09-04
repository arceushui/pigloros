//! Standalone, bounded entry point for independent black-box evaluation.

use std::env;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use pos_reference::evaluator::{evaluate, EvaluatorIdentity};
use pos_reference::evaluator_protocol::{EvaluationRequest, IndependenceEvidence, ProtocolError};
use pos_reference::process_adapter::ProcessAdapter;

const MAX_REQUEST_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_TRUST_POLICY_BYTES: u64 = 16 * 1024 * 1024;
const MAX_EVALUATOR_BINARY_BYTES: u64 = 256 * 1024 * 1024;
const MAX_EVALUATOR_SOURCE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_EVALUATOR_PROVENANCE_BYTES: u64 = 64 * 1024;
const PROVENANCE_SCHEMA: &str = "PiglorOS.EvaluatorBuildProvenance.v1";
const PROVENANCE_FIELDS: [&str; 10] = [
    "schema",
    "source_commit",
    "build_target",
    "rust_toolchain",
    "cargo_locked",
    "evaluator_source_blake3",
    "evaluator_binary_blake3",
    "dependency_lock_blake3",
    "sbom_blake3",
    "licences_blake3",
];

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
    let (source_digest, binary_digest) = verified_evaluator_digests(&options)?;
    let archive_bytes = read_bounded(&options.archive, MAX_ARCHIVE_BYTES)?;
    let trust_policy_bytes = read_bounded(&options.trust_policy, MAX_TRUST_POLICY_BYTES)?;
    let identity = EvaluatorIdentity {
        source_digest,
        binary_digest,
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

fn verified_evaluator_digests(options: &Options) -> Result<([u8; 32], [u8; 32]), CommandError> {
    let source_digest = digest_bounded(
        &options.evaluator_evidence.source,
        MAX_EVALUATOR_SOURCE_BYTES,
    )?;
    let executable = env::current_exe().map_err(|_| CommandError::Identity)?;
    let binary_digest = digest_bounded(&executable, MAX_EVALUATOR_BINARY_BYTES)?;
    let provenance_bytes = read_bounded(
        &options.evaluator_evidence.provenance,
        MAX_EVALUATOR_PROVENANCE_BYTES,
    )?;
    let (bound_source, bound_binary) = parse_build_provenance(&provenance_bytes)?;
    if source_digest == bound_source && binary_digest == bound_binary {
        Ok((source_digest, binary_digest))
    } else {
        Err(CommandError::Identity)
    }
}

fn parse_build_provenance(bytes: &[u8]) -> Result<([u8; 32], [u8; 32]), CommandError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| CommandError::Identity)?;
    let object = value.as_object().ok_or(CommandError::Identity)?;
    if object.len() != PROVENANCE_FIELDS.len()
        || !PROVENANCE_FIELDS
            .iter()
            .all(|field| object.contains_key(*field))
        || provenance_text(object, "schema")? != PROVENANCE_SCHEMA
        || !valid_commit(provenance_text(object, "source_commit")?)
        || !valid_metadata(provenance_text(object, "build_target")?)
        || !valid_metadata(provenance_text(object, "rust_toolchain")?)
        || object.get("cargo_locked") != Some(&serde_json::Value::Bool(true))
    {
        return Err(CommandError::Identity);
    }
    let source = parse_digest(provenance_text(object, "evaluator_source_blake3")?)?;
    let binary = parse_digest(provenance_text(object, "evaluator_binary_blake3")?)?;
    for field in ["dependency_lock_blake3", "sbom_blake3", "licences_blake3"] {
        parse_digest(provenance_text(object, field)?)?;
    }
    Ok((source, binary))
}

fn provenance_text<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<&'a str, CommandError> {
    object
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or(CommandError::Identity)
}

fn valid_commit(value: &str) -> bool {
    (40..=64).contains(&value.len()) && value.bytes().all(is_lower_hexadecimal)
}

fn valid_metadata(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().any(|byte| byte.is_ascii_graphic())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
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
