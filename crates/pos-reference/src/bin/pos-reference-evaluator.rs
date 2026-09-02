//! Standalone, bounded entry point for independent black-box evaluation.

use std::env;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use pos_reference::evaluator::{evaluate, EvaluatorIdentity};
use pos_reference::evaluator_protocol::{EvaluationRequest, IndependenceEvidence};
use pos_reference::process_adapter::ProcessAdapter;

const MAX_REQUEST_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_TRUST_POLICY_BYTES: u64 = 16 * 1024 * 1024;
const MAX_EVALUATOR_BINARY_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
enum CommandError {
    #[error("command arguments are invalid")]
    Arguments,
    #[error("an input artifact cannot be read within its bound")]
    Input,
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
    source_digest: [u8; 32],
    declaration_digest: [u8; 32],
    shared_code_audit_digest: [u8; 32],
    reviewer_ids: Vec<String>,
    authorship_independent: bool,
    organizational_independent: bool,
    adapter: PathBuf,
    adapter_arguments: Vec<OsString>,
}

fn main() -> Result<(), CommandError> {
    run()
}

fn run() -> Result<(), CommandError> {
    let options = parse_options(env::args_os())?;
    let request_bytes = read_bounded(&options.request, MAX_REQUEST_BYTES)?;
    let archive_bytes = read_bounded(&options.archive, MAX_ARCHIVE_BYTES)?;
    let trust_policy_bytes = read_bounded(&options.trust_policy, MAX_TRUST_POLICY_BYTES)?;
    let request =
        EvaluationRequest::from_canonical_cbor(&request_bytes).map_err(|_| CommandError::Input)?;
    let executable = env::current_exe().map_err(|_| CommandError::Identity)?;
    let binary_digest = digest_bounded(&executable, MAX_EVALUATOR_BINARY_BYTES)?;
    let identity = EvaluatorIdentity {
        source_digest: options.source_digest,
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
    let mut request = None;
    let mut archive = None;
    let mut trust_policy = None;
    let mut source_digest = None;
    let mut declaration_digest = None;
    let mut shared_code_audit_digest = None;
    let mut reviewer_ids = Vec::new();
    let mut authorship_independent = false;
    let mut organizational_independent = false;
    let mut adapter = None;
    let mut adapter_arguments = Vec::new();
    while let Some(argument) = arguments.next() {
        match argument.to_str().ok_or(CommandError::Arguments)? {
            "--request" => set_once(&mut request, next_path(&mut arguments)?)?,
            "--bundle" => set_once(&mut archive, next_path(&mut arguments)?)?,
            "--trust-policy" => set_once(&mut trust_policy, next_path(&mut arguments)?)?,
            "--source-digest" => set_once(&mut source_digest, next_digest(&mut arguments)?)?,
            "--declaration-digest" => {
                set_once(&mut declaration_digest, next_digest(&mut arguments)?)?;
            }
            "--shared-code-audit-digest" => {
                set_once(&mut shared_code_audit_digest, next_digest(&mut arguments)?)?;
            }
            "--reviewer" => reviewer_ids.push(next_text(&mut arguments)?),
            "--authorship-independent" if !authorship_independent => {
                authorship_independent = true;
            }
            "--organizational-independent" if !organizational_independent => {
                organizational_independent = true;
            }
            "--adapter" => set_once(&mut adapter, next_path(&mut arguments)?)?,
            "--adapter-arg" => adapter_arguments.push(next_argument(&mut arguments)?),
            _ => return Err(CommandError::Arguments),
        }
    }
    if reviewer_ids.is_empty()
        || reviewer_ids
            .windows(2)
            .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
    {
        return Err(CommandError::Identity);
    }
    Ok(Options {
        request: request.ok_or(CommandError::Arguments)?,
        archive: archive.ok_or(CommandError::Arguments)?,
        trust_policy: trust_policy.ok_or(CommandError::Arguments)?,
        source_digest: source_digest.ok_or(CommandError::Arguments)?,
        declaration_digest: declaration_digest.ok_or(CommandError::Arguments)?,
        shared_code_audit_digest: shared_code_audit_digest.ok_or(CommandError::Arguments)?,
        reviewer_ids,
        authorship_independent,
        organizational_independent,
        adapter: adapter.ok_or(CommandError::Arguments)?,
        adapter_arguments,
    })
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
    read_bounded(path, maximum).map(|bytes| *blake3::hash(&bytes).as_bytes())
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
