//! Durable evidence of denied Gateway authority decisions (Redmine #1359).
//!
//! Owner decision D9 on #302: every denied authority decision is recorded as a
//! durable record before the Gateway answers. A record holds the AUD1 request
//! digest of the exact evaluated request, the AUD1 outcome and safe-error
//! codes, and the Gateway operation binding. It holds no request payload,
//! Principal, Entity, credential or wall time, so a record never discloses
//! what was requested or by whom.
//!
//! [`GatewayDenialEvidencePort`] is the seam the Gateway authorizer persists
//! through; [`FileDenialEvidenceLog`] is its durable append-only adapter.

use pos_core::{AuthorityErrorV1, AuthorizationOutcomeV1, Hash};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::PathBuf,
    sync::{Mutex, PoisonError},
};
use thiserror::Error;

const RECORD_MAGIC: [u8; 4] = *b"GDR1";
const REQUEST_DIGEST_AT: usize = 4;
const OPERATION_BINDING_AT: usize = REQUEST_DIGEST_AT + 32;
const OUTCOME_AT: usize = OPERATION_BINDING_AT + 32;
const ERROR_AT: usize = OUTCOME_AT + 1;
const CHECKSUM_AT: usize = ERROR_AT + 1;
/// The safe-error byte of a decision that carries no AUD1 safe-error code.
const NO_ERROR_CODE: u8 = u8::MAX;

/// Exact encoded size of one denial record: magic, AUD1 request digest,
/// operation binding, AUD1 outcome code, AUD1 safe-error code and a BLAKE3
/// checksum of the preceding bytes.
pub const DENIAL_RECORD_BYTES: usize = CHECKSUM_AT + 32;

/// Closed failures of the denial evidence seam. Neither carries a host path
/// or I/O description, because both can cross the public Gateway boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum GatewayDenialEvidenceError {
    #[error("denial evidence store unavailable")]
    Unavailable,
    #[error("denial evidence record is corrupt")]
    Corrupt,
}

/// One durable, payload-free record of a denied authority decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GatewayDenialRecordV1 {
    request_digest: Hash,
    operation_binding: Hash,
    outcome: AuthorizationOutcomeV1,
    error: Option<AuthorityErrorV1>,
}

impl GatewayDenialRecordV1 {
    /// Bind one denied decision; only the Gateway authorizer records one.
    pub(crate) const fn new(
        request_digest: Hash,
        operation_binding: Hash,
        outcome: AuthorizationOutcomeV1,
        error: Option<AuthorityErrorV1>,
    ) -> Self {
        Self {
            request_digest,
            operation_binding,
            outcome,
            error,
        }
    }

    /// The AUD1 request digest of the exact evaluated request.
    #[must_use]
    pub const fn request_digest(&self) -> Hash {
        self.request_digest
    }

    /// The Gateway operation binding the decision answered.
    #[must_use]
    pub const fn operation_binding(&self) -> Hash {
        self.operation_binding
    }

    /// The AUD1 outcome of the denied decision; never `Active`.
    #[must_use]
    pub const fn outcome(&self) -> AuthorizationOutcomeV1 {
        self.outcome
    }

    /// The AUD1 safe-error code of the denied decision, if it carries one.
    #[must_use]
    pub const fn error(&self) -> Option<AuthorityErrorV1> {
        self.error
    }

    /// Encode the exact fixed-size record.
    #[must_use]
    pub fn encode(&self) -> [u8; DENIAL_RECORD_BYTES] {
        let mut bytes = [0; DENIAL_RECORD_BYTES];
        bytes[..REQUEST_DIGEST_AT].copy_from_slice(&RECORD_MAGIC);
        bytes[REQUEST_DIGEST_AT..OPERATION_BINDING_AT]
            .copy_from_slice(self.request_digest.as_bytes());
        bytes[OPERATION_BINDING_AT..OUTCOME_AT].copy_from_slice(self.operation_binding.as_bytes());
        bytes[OUTCOME_AT] = self.outcome.code();
        bytes[ERROR_AT] = self.error.map_or(NO_ERROR_CODE, AuthorityErrorV1::code);
        let checksum = blake3::hash(&bytes[..CHECKSUM_AT]);
        bytes[CHECKSUM_AT..].copy_from_slice(checksum.as_bytes());
        bytes
    }

    /// Decode and verify one exact record.
    ///
    /// # Errors
    /// Returns [`GatewayDenialEvidenceError::Corrupt`] for a record of another
    /// length, magic or checksum, an unknown code, or an `Active` outcome.
    pub fn decode(bytes: &[u8]) -> Result<Self, GatewayDenialEvidenceError> {
        <[u8; DENIAL_RECORD_BYTES]>::try_from(bytes)
            .ok()
            .filter(|record| {
                record[..REQUEST_DIGEST_AT] == RECORD_MAGIC
                    && record[CHECKSUM_AT..] == *blake3::hash(&record[..CHECKSUM_AT]).as_bytes()
            })
            .and_then(|record| {
                AuthorizationOutcomeV1::from_code(record[OUTCOME_AT])
                    .ok()
                    .filter(|outcome| !outcome.is_allowed())
                    .zip(decode_error_code(record[ERROR_AT]))
                    .map(|(outcome, error)| Self {
                        request_digest: hash_at(&record, REQUEST_DIGEST_AT),
                        operation_binding: hash_at(&record, OPERATION_BINDING_AT),
                        outcome,
                        error,
                    })
            })
            .ok_or(GatewayDenialEvidenceError::Corrupt)
    }
}

/// `Some(None)` for a decision without a safe-error code, `Some(Some(_))` for
/// a known AUD1 code and `None` for an unknown one.
fn decode_error_code(code: u8) -> Option<Option<AuthorityErrorV1>> {
    match code {
        NO_ERROR_CODE => Some(None),
        known => AuthorityErrorV1::from_code(known).ok().map(Some),
    }
}

fn hash_at(record: &[u8; DENIAL_RECORD_BYTES], at: usize) -> Hash {
    Hash::from_bytes(std::array::from_fn(|index| record[at + index]))
}

/// Host seam that durably records one denied authority decision.
///
/// `persist` returns only after the record is durable, so the Gateway answers
/// a denial only once its evidence survives a restart. An implementation must
/// not retain anything beyond the record it is given.
pub trait GatewayDenialEvidencePort: Send + Sync {
    /// Durably persist one denial record.
    ///
    /// # Errors
    /// Returns [`GatewayDenialEvidenceError::Unavailable`] when the record
    /// cannot be made durable; the Gateway then fails closed without
    /// answering the denial.
    fn persist(&self, record: &GatewayDenialRecordV1) -> Result<(), GatewayDenialEvidenceError>;
}

/// Durable append-only log of fixed-size denial records with one writer.
///
/// Every append is synced to storage before `persist` returns. Opening the
/// log verifies every existing record, so a corrupt or torn log fails closed
/// instead of being silently extended.
#[derive(Debug)]
pub struct FileDenialEvidenceLog {
    path: PathBuf,
    file: Mutex<File>,
}

impl FileDenialEvidenceLog {
    /// Open or create the log at `path` and verify its existing records.
    ///
    /// # Errors
    /// Returns [`GatewayDenialEvidenceError::Unavailable`] when the file
    /// cannot be opened or read, and [`GatewayDenialEvidenceError::Corrupt`]
    /// when an existing record does not verify.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, GatewayDenialEvidenceError> {
        let path = path.into();
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .or(Err(GatewayDenialEvidenceError::Unavailable))
            .map(|file| Self {
                path,
                file: Mutex::new(file),
            })
            .and_then(|log| log.records().map(|_| log))
    }

    /// Read back every persisted record in append order.
    ///
    /// # Errors
    /// Returns [`GatewayDenialEvidenceError::Unavailable`] when the log cannot
    /// be read, and [`GatewayDenialEvidenceError::Corrupt`] when a record does
    /// not verify.
    pub fn records(&self) -> Result<Vec<GatewayDenialRecordV1>, GatewayDenialEvidenceError> {
        std::fs::read(&self.path)
            .or(Err(GatewayDenialEvidenceError::Unavailable))
            .and_then(|bytes| {
                bytes
                    .chunks(DENIAL_RECORD_BYTES)
                    .map(GatewayDenialRecordV1::decode)
                    .collect()
            })
    }
}

impl GatewayDenialEvidencePort for FileDenialEvidenceLog {
    fn persist(&self, record: &GatewayDenialRecordV1) -> Result<(), GatewayDenialEvidenceError> {
        let mut file = self.file.lock().unwrap_or_else(PoisonError::into_inner);
        file.write_all(&record.encode())
            .and_then(|()| file.sync_data())
            .or(Err(GatewayDenialEvidenceError::Unavailable))
    }
}

/// Non-durable denial evidence for tests and the nonproduction fixture
/// composition. No deployable graph enables it.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Default)]
pub struct VolatileDenialEvidence {
    records: Mutex<Vec<GatewayDenialRecordV1>>,
}

#[cfg(any(test, feature = "test-support"))]
impl VolatileDenialEvidence {
    /// The records persisted so far, in order.
    #[must_use]
    pub fn records(&self) -> Vec<GatewayDenialRecordV1> {
        self.records
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

#[cfg(any(test, feature = "test-support"))]
impl GatewayDenialEvidencePort for VolatileDenialEvidence {
    fn persist(&self, record: &GatewayDenialRecordV1) -> Result<(), GatewayDenialEvidenceError> {
        self.records
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(*record);
        Ok(())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn record(error: Option<AuthorityErrorV1>) -> GatewayDenialRecordV1 {
        GatewayDenialRecordV1::new(
            Hash::from_bytes([1; 32]),
            Hash::from_bytes([2; 32]),
            AuthorizationOutcomeV1::RevokedAtFence,
            error,
        )
    }

    /// Re-seal a hand-edited record so only the edited field is invalid.
    fn sealed(mut bytes: [u8; DENIAL_RECORD_BYTES]) -> [u8; DENIAL_RECORD_BYTES] {
        let checksum = blake3::hash(&bytes[..CHECKSUM_AT]);
        bytes[CHECKSUM_AT..].copy_from_slice(checksum.as_bytes());
        bytes
    }

    #[test]
    fn a_record_round_trips_with_and_without_a_safe_error_code() -> TestResult {
        for error in [Some(AuthorityErrorV1::RevokedAtFence), None] {
            let original = record(error);
            let decoded = GatewayDenialRecordV1::decode(&original.encode())?;
            assert_eq!(decoded, original);
            assert_eq!(decoded.request_digest(), Hash::from_bytes([1; 32]));
            assert_eq!(decoded.operation_binding(), Hash::from_bytes([2; 32]));
            assert_eq!(decoded.outcome(), AuthorizationOutcomeV1::RevokedAtFence);
            assert_eq!(decoded.error(), error);
        }
        Ok(())
    }

    #[test]
    fn a_malformed_record_is_corrupt() {
        let valid = record(None).encode();
        let mut magic = valid;
        magic[0] = b'X';
        let mut checksum = valid;
        checksum[CHECKSUM_AT] ^= 1;
        let mut unknown_outcome = valid;
        unknown_outcome[OUTCOME_AT] = 200;
        let mut active = valid;
        active[OUTCOME_AT] = AuthorizationOutcomeV1::Active.code();
        let mut unknown_error = valid;
        unknown_error[ERROR_AT] = 200;
        let cases: [&[u8]; 6] = [
            &valid[..DENIAL_RECORD_BYTES - 1],
            &sealed(magic),
            &checksum,
            &sealed(unknown_outcome),
            &sealed(active),
            &sealed(unknown_error),
        ];
        for bytes in cases {
            assert_eq!(
                GatewayDenialRecordV1::decode(bytes),
                Err(GatewayDenialEvidenceError::Corrupt)
            );
        }
    }

    #[test]
    fn the_file_log_survives_a_reopen_in_append_order() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("denials.log");
        let log = FileDenialEvidenceLog::open(&path)?;
        assert!(log.records()?.is_empty());
        log.persist(&record(None))?;
        log.persist(&record(Some(AuthorityErrorV1::RevokedAtFence)))?;
        drop(log);

        let reopened = FileDenialEvidenceLog::open(&path)?;
        assert_eq!(
            reopened.records()?,
            vec![record(None), record(Some(AuthorityErrorV1::RevokedAtFence))]
        );
        Ok(())
    }

    #[test]
    fn a_torn_or_unreadable_log_fails_closed() -> TestResult {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("torn.log");
        std::fs::write(&path, &record(None).encode()[..10])?;
        assert_eq!(
            FileDenialEvidenceLog::open(&path).err(),
            Some(GatewayDenialEvidenceError::Corrupt)
        );

        assert_eq!(
            FileDenialEvidenceLog::open(directory.path().join("missing").join("x.log")).err(),
            Some(GatewayDenialEvidenceError::Unavailable)
        );

        let removed = directory.path().join("removed.log");
        let log = FileDenialEvidenceLog::open(&removed)?;
        std::fs::remove_file(&removed)?;
        assert_eq!(log.records(), Err(GatewayDenialEvidenceError::Unavailable));
        Ok(())
    }

    #[test]
    fn volatile_evidence_keeps_records_in_order() -> TestResult {
        let evidence = VolatileDenialEvidence::default();
        evidence.persist(&record(None))?;
        evidence.persist(&record(Some(AuthorityErrorV1::CapabilityMissing)))?;
        assert_eq!(
            evidence.records(),
            vec![
                record(None),
                record(Some(AuthorityErrorV1::CapabilityMissing))
            ]
        );
        Ok(())
    }
}
