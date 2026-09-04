//! Standalone, bounded entry point for independent black-box evaluation.

use std::env;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use pos_reference::evaluator::evaluate;
use pos_reference::evaluator_build_identity::{
    verify_evaluator_build_identity, EvaluatorBuildEvidence, EvaluatorBuildIdentityError,
};
use pos_reference::evaluator_protocol::{EvaluationRequest, IndependenceEvidence, ProtocolError};
use pos_reference::process_adapter::ProcessAdapter;
use pos_reference::profile::{EvaluatorHardCaps, Profile};
use pos_reference::signed_bundle::preflight_signed_bundle;

const MAX_REQUEST_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_TRUST_POLICY_BYTES: u64 = 16 * 1024 * 1024;

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

trait CommandResult<T> {
    fn map_input_error(self) -> Result<T, CommandError>;
    fn map_evaluation_error(self) -> Result<T, CommandError>;
}

impl<T, E> CommandResult<T> for Result<T, E> {
    fn map_input_error(self) -> Result<T, CommandError> {
        self.map_err(|_| CommandError::Input)
    }

    fn map_evaluation_error(self) -> Result<T, CommandError> {
        self.map_err(|_| CommandError::Evaluation)
    }
}

struct Options {
    request: PathBuf,
    archive: PathBuf,
    trust_policy: PathBuf,
    evaluator_evidence: EvaluatorBuildEvidence,
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
    let trust_policy_bytes = read_bounded(&options.trust_policy, MAX_TRUST_POLICY_BYTES)?;
    let (mut archive, caps) =
        preflight_authenticated_archive(&options, &trust_policy_bytes, &request)?;
    let identity = verify_evaluator_build_identity(
        &options.evaluator_evidence,
        IndependenceEvidence {
            technical_independent: true,
            authorship_independent: options.authorship_independent,
            organizational_independent: options.organizational_independent,
            declaration_digest: options.declaration_digest,
            shared_code_audit_digest: options.shared_code_audit_digest,
            reviewer_ids: options.reviewer_ids.clone(),
        },
        caps.max_compression_expansion,
    )
    .map_err(|error| match error {
        EvaluatorBuildIdentityError::Input => CommandError::Input,
        EvaluatorBuildIdentityError::Invalid => CommandError::Identity,
    })?;
    let archive_bytes = read_bounded_file(&mut archive, MAX_ARCHIVE_BYTES)?;
    let mut adapter = ProcessAdapter::new(
        request.subject_adapter,
        request.subject_artifact_digest,
        options.adapter,
        options.adapter_arguments,
    )
    .map_err(|_| CommandError::Adapter)?;
    evaluate(
        &request_bytes,
        &archive_bytes,
        &trust_policy_bytes,
        &identity,
        &mut adapter,
    )
    .map_evaluation_error()
    .and_then(write_artifacts)
}

fn write_artifacts(
    artifacts: pos_reference::evaluator::EvaluationArtifacts,
) -> Result<(), CommandError> {
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

fn preflight_authenticated_archive(
    options: &Options,
    trust_policy_bytes: &[u8],
    request: &EvaluationRequest,
) -> Result<(File, EvaluatorHardCaps), CommandError> {
    let mut archive = snapshot_bounded(&options.archive, MAX_ARCHIVE_BYTES)?;
    let preflight = preflight_signed_bundle(&mut archive, trust_policy_bytes, request)
        .map_evaluation_error()?;
    let caps = Profile::authenticated_hard_caps(preflight.profile_bytes(), request)
        .map_evaluation_error()?;
    preflight
        .enforce_selected_caps(caps.into())
        .map_evaluation_error()?;
    Ok((archive, caps))
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
    let argument = argument.to_str().ok_or(CommandError::Arguments)?;
    if parse_evaluator_evidence_option(&mut builder.evaluator_evidence, arguments, argument)? {
        return Ok(());
    }
    match argument {
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
    argument: &str,
) -> Result<bool, CommandError> {
    match argument {
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
    fn finish(self) -> Result<EvaluatorBuildEvidence, CommandError> {
        Ok(EvaluatorBuildEvidence::new(
            self.source.ok_or(CommandError::Arguments)?,
            self.provenance.ok_or(CommandError::Arguments)?,
        ))
    }
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

fn snapshot_bounded(path: &Path, maximum: u64) -> Result<File, CommandError> {
    File::open(path)
        .map_input_error()
        .and_then(|source| snapshot_source(source, maximum))
}

fn snapshot_source(source: File, maximum: u64) -> Result<File, CommandError> {
    tempfile::tempfile()
        .map_input_error()
        .and_then(|snapshot| copy_snapshot(source, snapshot, maximum))
}

fn copy_snapshot(source: File, mut snapshot: File, maximum: u64) -> Result<File, CommandError> {
    io::copy(&mut source.take(maximum.saturating_add(1)), &mut snapshot)
        .map_input_error()
        .and_then(|copied| {
            if copied > maximum {
                Err(CommandError::Input)
            } else {
                snapshot
                    .seek(SeekFrom::Start(0))
                    .map_input_error()
                    .map(|_| snapshot)
            }
        })
}

fn read_bounded_file(file: &mut File, maximum: u64) -> Result<Vec<u8>, CommandError> {
    file.seek(SeekFrom::Start(0))
        .map_input_error()
        .and_then(|_| {
            usize::try_from(maximum.min(16 * 1024 * 1024))
                .map_input_error()
                .and_then(|capacity| read_bounded_contents(file, maximum, capacity))
        })
}

fn read_bounded_contents(
    reader: impl Read,
    maximum: u64,
    capacity: usize,
) -> Result<Vec<u8>, CommandError> {
    let mut bytes = Vec::with_capacity(capacity);
    reader
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_input_error()
        .and({
            if bytes.len() as u64 > maximum {
                Err(CommandError::Input)
            } else {
                Ok(bytes)
            }
        })
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, CommandError> {
    File::open(path).map_input_error().and_then(|file| {
        usize::try_from(maximum.min(16 * 1024 * 1024))
            .map_input_error()
            .and_then(|capacity| read_bounded_contents(file, maximum, capacity))
    })
}
