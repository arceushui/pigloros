//! Owner-verified preparation and persistence contracts for immutable ARD1 rows.

use super::{
    extract_adapter_admission_registration_v1, extract_adapter_transcript_registration_v1,
    extract_repro_manifest_root_registration_v1, inspect_artifact_registration_graph_v1,
    ArtifactRegistrationGraphErrorV1, ArtifactRegistrationGraphNodeV1, ArtifactRegistrationV1,
    ErasureArtifactClassV1, ReproManifestRootRegistrationInputV1,
    MAX_ARTIFACT_GRAPH_REGISTRATIONS_V1, MAX_ARTIFACT_GRAPH_REGISTRATION_BYTES_V1,
};
use crate::{
    AdapterAdmissionV1, AdapterTranscriptV1, Hash, OwnerIdV1, ReproManifestRootV1,
    WorldRecordingReceiptV1,
};

/// Maximum retained artifact bytes in one prepared registration closure.
pub const MAX_ARTIFACT_REGISTRATION_BATCH_BYTES_V1: usize =
    256 * 1024 * 1024 + MAX_ARTIFACT_GRAPH_REGISTRATION_BYTES_V1;

/// Untrusted exact artifact and ARD1 bytes submitted for owner verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactRegistrationInputV1 {
    /// Owner identity for these exact bytes; child owners may differ from the root.
    pub owner_id: OwnerIdV1,
    /// Exact bytes retained for this owner-specific artifact identity.
    pub artifact_bytes: Vec<u8>,
    /// Exact canonical ARD1 bytes derived for this artifact.
    pub registration_cbor: Vec<u8>,
}

/// Closed owner-side rejection while checking native commit provenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ArtifactRegistrationOwnerVerificationErrorV1 {
    /// The installed local owner cannot confirm the native commit facts.
    #[error("local artifact owner rejected the native commit facts")]
    Rejected,
}

/// Trusted local-owner seam for native commit and recorder facts.
///
/// Core derives the exact MAA1, MAT1, and MRM1 fields from retained bytes. The
/// installed local owner derives complete class-0/native child registrations
/// and authenticates the admission, receipt, recorder, and roster facts it
/// owns. Applications must not forward an untrusted remote client's
/// implementation of this trait.
pub trait ArtifactRegistrationOwnerVerifierV1 {
    /// Derive one complete accepted native registration outside the exact
    /// MAA1/MAT1/MRM1 extractors in core. This includes the class-0 WCR1
    /// registration and all native records in its ADR-100 closure.
    ///
    /// # Errors
    /// Returns [`ArtifactRegistrationOwnerVerificationErrorV1::Rejected`]
    /// when the installed owner has no complete extractor for this class.
    fn derive_native_registration(
        &self,
        owner_id: &OwnerIdV1,
        artifact_class: ErasureArtifactClassV1,
        artifact_bytes: &[u8],
    ) -> Result<ArtifactRegistrationV1, ArtifactRegistrationOwnerVerificationErrorV1>;

    /// Confirm that this exact native artifact was committed by `owner_id`.
    ///
    /// # Errors
    /// Returns [`ArtifactRegistrationOwnerVerificationErrorV1::Rejected`] if
    /// the owner's current or retained native facts do not authenticate the
    /// supplied immutable artifact and its derived ARD1 record.
    fn verify_committed_artifact(
        &self,
        owner_id: &OwnerIdV1,
        artifact_bytes: &[u8],
        registration: &ArtifactRegistrationV1,
    ) -> Result<(), ArtifactRegistrationOwnerVerificationErrorV1>;
}

/// Closed failures while deriving an owner-verified registration closure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ArtifactRegistrationPreparationErrorV1 {
    /// The input closure is empty or exceeds an accepted graph/byte bound.
    #[error("artifact registration closure exceeds its accepted bound")]
    BoundExceeded,
    /// An input ARD1 is malformed or does not identify its exact artifact bytes.
    #[error("artifact registration does not match its exact bytes")]
    InvalidRegistration,
    /// A native artifact is malformed, noncanonical, or not supported here.
    #[error("artifact format is invalid or not yet supported")]
    UnsupportedArtifact,
    /// A supported artifact's supplied ARD1 differs from exact extraction.
    #[error("artifact registration differs from native extraction")]
    ExtractionMismatch,
    /// The complete child graph is invalid or contains rows outside the root closure.
    #[error("artifact registration graph is invalid")]
    InvalidGraph,
    /// The trusted local owner rejected its native commit facts.
    #[error("local artifact owner rejected the commit")]
    OwnerRejected,
}

/// A validated immutable artifact/registration pair read from the owner catalog.
///
/// This row is data, not a release capability. Protected use still requires
/// current owner verification at its own boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactRegistrationCatalogRowV1 {
    owner_id: OwnerIdV1,
    artifact_class: ErasureArtifactClassV1,
    artifact_digest: Hash,
    registration_address: Hash,
    artifact_bytes: Vec<u8>,
    registration: ArtifactRegistrationV1,
}

impl ArtifactRegistrationCatalogRowV1 {
    /// Validate a persisted row against all of its stored identity columns.
    ///
    /// # Errors
    /// Returns [`ArtifactRegistrationPersistenceErrorV1::CorruptCatalog`] if
    /// any column, exact artifact bytes, owner reference, or ARD1 bytes disagree.
    pub fn from_persisted(
        owner_id: OwnerIdV1,
        artifact_class: ErasureArtifactClassV1,
        artifact_digest: Hash,
        registration_address: Hash,
        artifact_bytes: Vec<u8>,
        registration_cbor: &[u8],
    ) -> Result<Self, ArtifactRegistrationPersistenceErrorV1> {
        let registration = ArtifactRegistrationV1::from_canonical_cbor(registration_cbor)
            .map_err(|_| ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)?;
        if registration.address() != registration_address
            || registration.fields().artifact_class != artifact_class
            || registration.fields().artifact_digest != artifact_digest
            || registration.fields().owner_reference
                != ArtifactRegistrationV1::owner_reference(&owner_id)
            || ArtifactRegistrationV1::artifact_digest(artifact_class, &artifact_bytes)
                != artifact_digest
        {
            return Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog);
        }
        Ok(Self {
            owner_id,
            artifact_class,
            artifact_digest,
            registration_address,
            artifact_bytes,
            registration,
        })
    }

    /// Return the exact catalog owner identity.
    #[must_use]
    pub const fn owner_id(&self) -> &OwnerIdV1 {
        &self.owner_id
    }

    /// Return the closed artifact class.
    #[must_use]
    pub const fn artifact_class(&self) -> ErasureArtifactClassV1 {
        self.artifact_class
    }

    /// Return the content address of the exact artifact bytes.
    #[must_use]
    pub const fn artifact_digest(&self) -> Hash {
        self.artifact_digest
    }

    /// Return the content address of the exact canonical ARD1 bytes.
    #[must_use]
    pub const fn registration_address(&self) -> Hash {
        self.registration_address
    }

    /// Borrow the exact retained artifact bytes.
    #[must_use]
    pub fn artifact_bytes(&self) -> &[u8] {
        &self.artifact_bytes
    }

    /// Borrow the exact parsed ARD1 record.
    #[must_use]
    pub const fn registration(&self) -> &ArtifactRegistrationV1 {
        &self.registration
    }
}

/// Revalidate a persisted registration closure and its built-in native formats.
///
/// This checks exact retained bytes, known MAA1/MAT1/MRM1 extractor output,
/// and the complete ARD1 graph. It does not repeat local-owner verification
/// for native World records; callers must still consult that owner before
/// protected use.
///
/// # Errors
/// Returns `CorruptCatalog` if a stored row, native binding, or graph differs
/// from the exact format-specific registration derived from retained bytes.
pub fn validate_artifact_registration_catalog_graph_v1(
    root: Hash,
    rows: &[ArtifactRegistrationCatalogRowV1],
) -> Result<(), ArtifactRegistrationPersistenceErrorV1> {
    let nodes: Vec<_> = rows
        .iter()
        .map(|row| ArtifactRegistrationGraphNodeV1 {
            address: row.registration_address(),
            owner_id: *row.owner_id(),
            artifact_class: row.artifact_class(),
            artifact_digest: row.artifact_digest(),
            registration: row.registration().clone(),
        })
        .collect();
    inspect_artifact_registration_graph_v1(root, &nodes)
        .map_err(|_| ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)?;

    for row in rows {
        if row.artifact_class() == ErasureArtifactClassV1::ReproManifest {
            validate_repro_manifest_catalog_row(row, rows)?;
        }
    }
    Ok(())
}

fn validate_repro_manifest_catalog_row(
    row: &ArtifactRegistrationCatalogRowV1,
    rows: &[ArtifactRegistrationCatalogRowV1],
) -> Result<(), ArtifactRegistrationPersistenceErrorV1> {
    match row.artifact_bytes().get(2..6) {
        Some(b"MAA1") => validate_admission_catalog_row(row),
        Some(b"MAT1") => validate_transcript_catalog_row(row, rows),
        Some(b"MRM1") => validate_root_catalog_row(row, rows),
        _ => Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog),
    }
}

fn validate_admission_catalog_row(
    row: &ArtifactRegistrationCatalogRowV1,
) -> Result<(), ArtifactRegistrationPersistenceErrorV1> {
    let expected = extract_adapter_admission_registration_v1(row.artifact_bytes())
        .map_err(|_| ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)?;
    if &expected == row.registration() {
        Ok(())
    } else {
        Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
    }
}

fn validate_transcript_catalog_row(
    row: &ArtifactRegistrationCatalogRowV1,
    rows: &[ArtifactRegistrationCatalogRowV1],
) -> Result<(), ArtifactRegistrationPersistenceErrorV1> {
    let transcript = AdapterTranscriptV1::from_canonical_cbor(row.artifact_bytes())
        .map_err(|_| ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)?;
    let admission = find_catalog_native_row(
        rows,
        ErasureArtifactClassV1::ReproManifest,
        transcript.as_input().adapter_admission_digest,
        |bytes| {
            AdapterAdmissionV1::from_canonical_cbor(bytes)
                .ok()
                .map(|value| value.digest())
        },
    )?;
    let admission_registration =
        extract_adapter_admission_registration_v1(admission.artifact_bytes())
            .map_err(|_| ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)?;
    if admission_registration != *admission.registration() {
        return Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog);
    }
    let expected = extract_adapter_transcript_registration_v1(
        row.artifact_bytes(),
        admission.artifact_bytes(),
        &admission_registration,
    )
    .map_err(|_| ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)?;
    if &expected == row.registration() {
        Ok(())
    } else {
        Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
    }
}

fn validate_root_catalog_row(
    row: &ArtifactRegistrationCatalogRowV1,
    rows: &[ArtifactRegistrationCatalogRowV1],
) -> Result<(), ArtifactRegistrationPersistenceErrorV1> {
    let root = ReproManifestRootV1::from_canonical_cbor(row.artifact_bytes())
        .map_err(|_| ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)?;
    let recording = find_catalog_native_row(
        rows,
        ErasureArtifactClassV1::TimelineReplay,
        root.as_input()
            .world_handle
            .as_input()
            .recording_receipt_digest,
        |bytes| {
            WorldRecordingReceiptV1::from_canonical_cbor(bytes)
                .ok()
                .map(|value| value.digest())
        },
    )?;
    let transcript = find_catalog_native_row(
        rows,
        ErasureArtifactClassV1::ReproManifest,
        root.as_input().adapter_transcript_digest,
        |bytes| {
            AdapterTranscriptV1::from_canonical_cbor(bytes)
                .ok()
                .map(|value| value.digest())
        },
    )?;
    let transcript_record = AdapterTranscriptV1::from_canonical_cbor(transcript.artifact_bytes())
        .map_err(|_| ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)?;
    let admission = find_catalog_native_row(
        rows,
        ErasureArtifactClassV1::ReproManifest,
        transcript_record.as_input().adapter_admission_digest,
        |bytes| {
            AdapterAdmissionV1::from_canonical_cbor(bytes)
                .ok()
                .map(|value| value.digest())
        },
    )?;
    let admission_registration =
        extract_adapter_admission_registration_v1(admission.artifact_bytes())
            .map_err(|_| ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)?;
    if admission_registration != *admission.registration() {
        return Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog);
    }
    let transcript_registration = extract_adapter_transcript_registration_v1(
        transcript.artifact_bytes(),
        admission.artifact_bytes(),
        &admission_registration,
    )
    .map_err(|_| ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)?;
    if transcript_registration != *transcript.registration() {
        return Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog);
    }
    let expected =
        extract_repro_manifest_root_registration_v1(ReproManifestRootRegistrationInputV1 {
            root_bytes: row.artifact_bytes(),
            recording_receipt_bytes: recording.artifact_bytes(),
            recording_registration: recording.registration(),
            transcript_bytes: transcript.artifact_bytes(),
            admission_bytes: admission.artifact_bytes(),
            admission_registration: &admission_registration,
            transcript_registration: &transcript_registration,
            owner_id: row.owner_id(),
        })
        .map_err(|_| ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)?;
    if &expected == row.registration() {
        Ok(())
    } else {
        Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
    }
}

fn find_catalog_native_row(
    rows: &[ArtifactRegistrationCatalogRowV1],
    artifact_class: ErasureArtifactClassV1,
    native_digest: Hash,
    digest: impl Fn(&[u8]) -> Option<Hash>,
) -> Result<&ArtifactRegistrationCatalogRowV1, ArtifactRegistrationPersistenceErrorV1> {
    let mut found = None;
    for row in rows {
        if row.artifact_class() == artifact_class
            && digest(row.artifact_bytes()) == Some(native_digest)
        {
            if found.is_some() {
                return Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog);
            }
            found = Some(row);
        }
    }
    found.ok_or(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
}

/// One owner-verified, complete registration closure ready for an atomic store commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedArtifactRegistrationBatchV1 {
    owner_id: OwnerIdV1,
    root_registration_address: Hash,
    root_operation_id: Hash,
    records: Vec<PreparedArtifactRegistrationRecordV1>,
}

impl PreparedArtifactRegistrationBatchV1 {
    /// Return the owner whose authoritative catalog receives this closure.
    #[must_use]
    pub const fn owner_id(&self) -> &OwnerIdV1 {
        &self.owner_id
    }

    /// Return the required root registration address.
    #[must_use]
    pub const fn root_registration_address(&self) -> Hash {
        self.root_registration_address
    }

    /// Return the immutable MRM1 run operation identity bound to this root.
    #[must_use]
    pub const fn root_operation_id(&self) -> Hash {
        self.root_operation_id
    }

    /// Borrow every exact artifact/ARD1 pair in the root's complete closure.
    #[must_use]
    pub fn records(&self) -> &[PreparedArtifactRegistrationRecordV1] {
        &self.records
    }
}

/// One exact record in a prepared batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedArtifactRegistrationRecordV1 {
    owner_id: OwnerIdV1,
    artifact_class: ErasureArtifactClassV1,
    artifact_digest: Hash,
    registration_address: Hash,
    artifact_bytes: Vec<u8>,
    registration: ArtifactRegistrationV1,
}

impl PreparedArtifactRegistrationRecordV1 {
    /// Return the owner identity that commits this exact native artifact.
    #[must_use]
    pub const fn owner_id(&self) -> &OwnerIdV1 {
        &self.owner_id
    }

    /// Return the closed artifact class.
    #[must_use]
    pub const fn artifact_class(&self) -> ErasureArtifactClassV1 {
        self.artifact_class
    }

    /// Return the content address of the exact artifact bytes.
    #[must_use]
    pub const fn artifact_digest(&self) -> Hash {
        self.artifact_digest
    }

    /// Return the content address of the exact canonical ARD1 bytes.
    #[must_use]
    pub const fn registration_address(&self) -> Hash {
        self.registration_address
    }

    /// Borrow the exact artifact bytes to be committed with its ARD1 row.
    #[must_use]
    pub fn artifact_bytes(&self) -> &[u8] {
        &self.artifact_bytes
    }

    /// Borrow the exact registration derived for these bytes.
    #[must_use]
    pub const fn registration(&self) -> &ArtifactRegistrationV1 {
        &self.registration
    }
}

/// Closed failures while storing or reading immutable owner-catalog rows.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ArtifactRegistrationPersistenceErrorV1 {
    /// A different immutable row already occupies an owner-specific identity.
    #[error("artifact registration conflicts with an immutable catalog identity")]
    Conflict,
    /// A persisted catalog row failed exact identity or canonical-byte checks.
    #[error("artifact registration catalog row is corrupt")]
    CorruptCatalog,
    /// The adapter could not complete or determine the persistence operation.
    #[error("artifact registration storage operation failed")]
    StorageFailure,
}

/// Outcome of one atomic immutable artifact and ARD1 catalog commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactRegistrationCommitOutcomeV1 {
    /// At least one row in the complete closure was newly committed.
    Applied,
    /// Every row already existed byte-for-byte under the same owner identity.
    ExactRetry,
}

/// Same-store persistence seam for exact artifacts, ARD1 rows, and catalog visibility.
pub trait ArtifactRegistrationPersistencePortV1 {
    /// Atomically commit the entire owner-verified root closure.
    ///
    /// The adapter must commit each exact artifact byte string and its ARD1
    /// row together. A catalog identity may be repeated only with the exact
    /// same bytes and registration. The returned root is visible only when
    /// its complete child closure is visible in the same store.
    ///
    /// # Errors
    /// Returns a closed conflict, corruption, or storage failure. A failure
    /// must leave no newly visible row from this batch.
    fn commit_artifact_registration_batch(
        &mut self,
        batch: PreparedArtifactRegistrationBatchV1,
    ) -> Result<ArtifactRegistrationCommitOutcomeV1, ArtifactRegistrationPersistenceErrorV1>;

    /// Read one exact owner-specific row, including its bytes and ARD1 record.
    ///
    /// # Errors
    /// Returns a closed corruption or storage failure if the row is not
    /// internally consistent.
    fn read_artifact_registration(
        &self,
        owner_id: &OwnerIdV1,
        registration_address: Hash,
    ) -> Result<Option<ArtifactRegistrationCatalogRowV1>, ArtifactRegistrationPersistenceErrorV1>;
}

/// Derive, owner-verify, and prepare one complete MRM1 registration closure.
///
/// Wave 8 currently admits the ADR-101 `ReproManifest` root profile. The local
/// owner derives and authenticates the complete `class-0` `WCR1` closure. Other
/// root classes remain unavailable until they have accepted complete native
/// extractors; structural `TimelineReplay` bytes alone cannot be committed as
/// an authoritative root.
///
/// # Errors
/// Rejects unsupported formats/classes, incomplete or invalid child graphs,
/// mismatched ARD1 bytes, excessive input, and local-owner verification failure.
pub fn prepare_artifact_registration_batch_v1(
    owner_id: OwnerIdV1,
    root_registration_address: Hash,
    inputs: Vec<ArtifactRegistrationInputV1>,
    owner_verifier: &dyn ArtifactRegistrationOwnerVerifierV1,
) -> Result<PreparedArtifactRegistrationBatchV1, ArtifactRegistrationPreparationErrorV1> {
    let parsed = parse_artifact_inputs(inputs)?;
    let records = derive_records(root_registration_address, &owner_id, parsed, owner_verifier)?;
    let root_operation_id = records
        .iter()
        .find(|record| record.registration_address() == root_registration_address)
        .and_then(|record| ReproManifestRootV1::from_canonical_cbor(record.artifact_bytes()).ok())
        .map(|root| root.as_input().run_operation_id)
        .ok_or(ArtifactRegistrationPreparationErrorV1::InvalidGraph)?;
    let graph_nodes: Vec<_> = records
        .iter()
        .map(|record| ArtifactRegistrationGraphNodeV1 {
            address: record.registration_address,
            artifact_class: record.artifact_class,
            artifact_digest: record.artifact_digest,
            owner_id: *record.owner_id(),
            registration: record.registration.clone(),
        })
        .collect();
    inspect_artifact_registration_graph_v1(root_registration_address, &graph_nodes)
        .map_err(map_graph_error)?;
    for record in &records {
        owner_verifier
            .verify_committed_artifact(
                record.owner_id(),
                &record.artifact_bytes,
                &record.registration,
            )
            .map_err(|_| ArtifactRegistrationPreparationErrorV1::OwnerRejected)?;
    }
    Ok(PreparedArtifactRegistrationBatchV1 {
        owner_id,
        root_registration_address,
        root_operation_id,
        records,
    })
}

fn parse_artifact_inputs(
    inputs: Vec<ArtifactRegistrationInputV1>,
) -> Result<Vec<ParsedArtifact>, ArtifactRegistrationPreparationErrorV1> {
    if inputs.is_empty() || inputs.len() > MAX_ARTIFACT_GRAPH_REGISTRATIONS_V1 {
        return Err(ArtifactRegistrationPreparationErrorV1::BoundExceeded);
    }
    let mut artifact_bytes = 0_usize;
    let mut registration_bytes = 0_usize;
    let mut parsed = Vec::with_capacity(inputs.len());
    for input in inputs {
        artifact_bytes = artifact_bytes
            .checked_add(input.artifact_bytes.len())
            .ok_or(ArtifactRegistrationPreparationErrorV1::BoundExceeded)?;
        registration_bytes = registration_bytes
            .checked_add(input.registration_cbor.len())
            .ok_or(ArtifactRegistrationPreparationErrorV1::BoundExceeded)?;
        if artifact_bytes > MAX_ARTIFACT_REGISTRATION_BATCH_BYTES_V1 {
            return Err(ArtifactRegistrationPreparationErrorV1::BoundExceeded);
        }
        if registration_bytes > MAX_ARTIFACT_GRAPH_REGISTRATION_BYTES_V1 {
            return Err(ArtifactRegistrationPreparationErrorV1::BoundExceeded);
        }
        let registration = ArtifactRegistrationV1::from_canonical_cbor(&input.registration_cbor)
            .map_err(|_| ArtifactRegistrationPreparationErrorV1::InvalidRegistration)?;
        if registration.fields().owner_reference
            != ArtifactRegistrationV1::owner_reference(&input.owner_id)
            || ArtifactRegistrationV1::artifact_digest(
                registration.fields().artifact_class,
                &input.artifact_bytes,
            ) != registration.fields().artifact_digest
        {
            return Err(ArtifactRegistrationPreparationErrorV1::InvalidRegistration);
        }
        let native =
            parse_native_artifact(registration.fields().artifact_class, &input.artifact_bytes)?;
        parsed.push(ParsedArtifact {
            owner_id: input.owner_id,
            artifact_bytes: input.artifact_bytes,
            registration,
            native,
        });
    }
    Ok(parsed)
}

fn derive_records(
    root_registration_address: Hash,
    owner_id: &OwnerIdV1,
    parsed: Vec<ParsedArtifact>,
    owner_verifier: &dyn ArtifactRegistrationOwnerVerifierV1,
) -> Result<Vec<PreparedArtifactRegistrationRecordV1>, ArtifactRegistrationPreparationErrorV1> {
    let mut expected_registrations = Vec::with_capacity(parsed.len());
    for candidate in &parsed {
        let expected = derive_expected_registration(candidate, &parsed, owner_id, owner_verifier)?;
        if candidate.registration != expected {
            return Err(ArtifactRegistrationPreparationErrorV1::ExtractionMismatch);
        }
        expected_registrations.push(expected);
    }

    let root_is_manifest =
        parsed
            .iter()
            .zip(&expected_registrations)
            .any(|(candidate, registration)| {
                registration.address() == root_registration_address
                    && candidate.owner_id == *owner_id
                    && matches!(&candidate.native, NativeArtifactV1::ReproManifestRoot(_))
            });
    if !root_is_manifest {
        return Err(ArtifactRegistrationPreparationErrorV1::InvalidGraph);
    }
    Ok(parsed
        .into_iter()
        .zip(expected_registrations)
        .map(
            |(candidate, expected)| PreparedArtifactRegistrationRecordV1 {
                owner_id: candidate.owner_id,
                artifact_class: expected.fields().artifact_class,
                artifact_digest: expected.fields().artifact_digest,
                registration_address: expected.address(),
                artifact_bytes: candidate.artifact_bytes,
                registration: expected,
            },
        )
        .collect())
}

enum NativeArtifactV1 {
    AdapterAdmission(AdapterAdmissionV1),
    AdapterTranscript(AdapterTranscriptV1),
    WorldRecordingReceipt(WorldRecordingReceiptV1),
    ReproManifestRoot(ReproManifestRootV1),
    OwnerNative,
}

struct ParsedArtifact {
    owner_id: OwnerIdV1,
    artifact_bytes: Vec<u8>,
    registration: ArtifactRegistrationV1,
    native: NativeArtifactV1,
}

fn parse_native_artifact(
    artifact_class: ErasureArtifactClassV1,
    bytes: &[u8],
) -> Result<NativeArtifactV1, ArtifactRegistrationPreparationErrorV1> {
    let magic = bytes.get(2..6);
    if artifact_class == ErasureArtifactClassV1::ReproManifest && magic == Some(b"MAA1") {
        AdapterAdmissionV1::from_canonical_cbor(bytes)
            .map(NativeArtifactV1::AdapterAdmission)
            .map_err(|_| ArtifactRegistrationPreparationErrorV1::UnsupportedArtifact)
    } else if artifact_class == ErasureArtifactClassV1::ReproManifest && magic == Some(b"MAT1") {
        AdapterTranscriptV1::from_canonical_cbor(bytes)
            .map(NativeArtifactV1::AdapterTranscript)
            .map_err(|_| ArtifactRegistrationPreparationErrorV1::UnsupportedArtifact)
    } else if artifact_class == ErasureArtifactClassV1::TimelineReplay && magic == Some(b"WCR1") {
        WorldRecordingReceiptV1::from_canonical_cbor(bytes)
            .map(NativeArtifactV1::WorldRecordingReceipt)
            .map_err(|_| ArtifactRegistrationPreparationErrorV1::UnsupportedArtifact)
    } else if artifact_class == ErasureArtifactClassV1::ReproManifest && magic == Some(b"MRM1") {
        ReproManifestRootV1::from_canonical_cbor(bytes)
            .map(NativeArtifactV1::ReproManifestRoot)
            .map_err(|_| ArtifactRegistrationPreparationErrorV1::UnsupportedArtifact)
    } else if artifact_class == ErasureArtifactClassV1::ReproManifest {
        Err(ArtifactRegistrationPreparationErrorV1::UnsupportedArtifact)
    } else {
        Ok(NativeArtifactV1::OwnerNative)
    }
}

fn derive_expected_registration(
    candidate: &ParsedArtifact,
    closure: &[ParsedArtifact],
    owner_id: &OwnerIdV1,
    owner_verifier: &dyn ArtifactRegistrationOwnerVerifierV1,
) -> Result<ArtifactRegistrationV1, ArtifactRegistrationPreparationErrorV1> {
    match &candidate.native {
        NativeArtifactV1::AdapterAdmission(_) => {
            extract_adapter_admission_registration_v1(&candidate.artifact_bytes)
                .map_err(|_| ArtifactRegistrationPreparationErrorV1::UnsupportedArtifact)
        }
        NativeArtifactV1::AdapterTranscript(transcript) => {
            let admission =
                find_admission(closure, transcript.as_input().adapter_admission_digest)?;
            let admission_registration =
                extract_adapter_admission_registration_v1(&admission.artifact_bytes)
                    .map_err(|_| ArtifactRegistrationPreparationErrorV1::UnsupportedArtifact)?;
            extract_adapter_transcript_registration_v1(
                &candidate.artifact_bytes,
                &admission.artifact_bytes,
                &admission_registration,
            )
            .map_err(|_| ArtifactRegistrationPreparationErrorV1::UnsupportedArtifact)
        }
        NativeArtifactV1::WorldRecordingReceipt(_) | NativeArtifactV1::OwnerNative => {
            owner_verifier
                .derive_native_registration(
                    &candidate.owner_id,
                    candidate.registration.fields().artifact_class,
                    &candidate.artifact_bytes,
                )
                .map_err(|_| ArtifactRegistrationPreparationErrorV1::OwnerRejected)
        }
        NativeArtifactV1::ReproManifestRoot(root) => {
            let root_input = root.as_input();
            let recording = find_recording_receipt(
                closure,
                root_input.world_handle.as_input().recording_receipt_digest,
            )?;
            let transcript = find_transcript(closure, root_input.adapter_transcript_digest)?;
            let transcript_native = match &transcript.native {
                NativeArtifactV1::AdapterTranscript(value) => value,
                NativeArtifactV1::AdapterAdmission(_)
                | NativeArtifactV1::WorldRecordingReceipt(_)
                | NativeArtifactV1::ReproManifestRoot(_)
                | NativeArtifactV1::OwnerNative => {
                    return Err(ArtifactRegistrationPreparationErrorV1::UnsupportedArtifact);
                }
            };
            let admission = find_admission(
                closure,
                transcript_native.as_input().adapter_admission_digest,
            )?;
            let recording_registration = owner_verifier
                .derive_native_registration(
                    &recording.owner_id,
                    ErasureArtifactClassV1::TimelineReplay,
                    &recording.artifact_bytes,
                )
                .map_err(|_| ArtifactRegistrationPreparationErrorV1::OwnerRejected)?;
            let admission_registration =
                extract_adapter_admission_registration_v1(&admission.artifact_bytes)
                    .map_err(|_| ArtifactRegistrationPreparationErrorV1::UnsupportedArtifact)?;
            let transcript_registration = extract_adapter_transcript_registration_v1(
                &transcript.artifact_bytes,
                &admission.artifact_bytes,
                &admission_registration,
            )
            .map_err(|_| ArtifactRegistrationPreparationErrorV1::UnsupportedArtifact)?;
            extract_repro_manifest_root_registration_v1(ReproManifestRootRegistrationInputV1 {
                root_bytes: &candidate.artifact_bytes,
                recording_receipt_bytes: &recording.artifact_bytes,
                recording_registration: &recording_registration,
                transcript_bytes: &transcript.artifact_bytes,
                admission_bytes: &admission.artifact_bytes,
                admission_registration: &admission_registration,
                transcript_registration: &transcript_registration,
                owner_id,
            })
            .map_err(|_| ArtifactRegistrationPreparationErrorV1::UnsupportedArtifact)
        }
    }
}

fn find_admission(
    closure: &[ParsedArtifact],
    native_digest: Hash,
) -> Result<&ParsedArtifact, ArtifactRegistrationPreparationErrorV1> {
    find_unique_native(
        closure,
        |native| match native {
            NativeArtifactV1::AdapterAdmission(value) => Some(value.digest()),
            NativeArtifactV1::AdapterTranscript(_)
            | NativeArtifactV1::WorldRecordingReceipt(_)
            | NativeArtifactV1::ReproManifestRoot(_)
            | NativeArtifactV1::OwnerNative => None,
        },
        native_digest,
    )
}

fn find_transcript(
    closure: &[ParsedArtifact],
    native_digest: Hash,
) -> Result<&ParsedArtifact, ArtifactRegistrationPreparationErrorV1> {
    find_unique_native(
        closure,
        |native| match native {
            NativeArtifactV1::AdapterTranscript(value) => Some(value.digest()),
            NativeArtifactV1::AdapterAdmission(_)
            | NativeArtifactV1::WorldRecordingReceipt(_)
            | NativeArtifactV1::ReproManifestRoot(_)
            | NativeArtifactV1::OwnerNative => None,
        },
        native_digest,
    )
}

fn find_recording_receipt(
    closure: &[ParsedArtifact],
    native_digest: Hash,
) -> Result<&ParsedArtifact, ArtifactRegistrationPreparationErrorV1> {
    find_unique_native(
        closure,
        |native| match native {
            NativeArtifactV1::WorldRecordingReceipt(value) => Some(value.digest()),
            NativeArtifactV1::AdapterAdmission(_)
            | NativeArtifactV1::AdapterTranscript(_)
            | NativeArtifactV1::ReproManifestRoot(_)
            | NativeArtifactV1::OwnerNative => None,
        },
        native_digest,
    )
}

fn find_unique_native(
    closure: &[ParsedArtifact],
    identity: impl Fn(&NativeArtifactV1) -> Option<Hash>,
    expected: Hash,
) -> Result<&ParsedArtifact, ArtifactRegistrationPreparationErrorV1> {
    let mut found = None;
    for candidate in closure {
        if identity(&candidate.native) == Some(expected) {
            if found.is_some() {
                return Err(ArtifactRegistrationPreparationErrorV1::InvalidGraph);
            }
            found = Some(candidate);
        }
    }
    found.ok_or(ArtifactRegistrationPreparationErrorV1::InvalidGraph)
}

const fn map_graph_error(
    error: ArtifactRegistrationGraphErrorV1,
) -> ArtifactRegistrationPreparationErrorV1 {
    match error {
        ArtifactRegistrationGraphErrorV1::BoundExceeded => {
            ArtifactRegistrationPreparationErrorV1::BoundExceeded
        }
        ArtifactRegistrationGraphErrorV1::InvalidRoot
        | ArtifactRegistrationGraphErrorV1::DuplicateAddress
        | ArtifactRegistrationGraphErrorV1::MissingChild
        | ArtifactRegistrationGraphErrorV1::OwnerMismatch
        | ArtifactRegistrationGraphErrorV1::IdentityMismatch
        | ArtifactRegistrationGraphErrorV1::Cycle
        | ArtifactRegistrationGraphErrorV1::ExtraRegistration => {
            ArtifactRegistrationPreparationErrorV1::InvalidGraph
        }
    }
}

const _: () = assert!(MAX_ARTIFACT_REGISTRATION_BATCH_BYTES_V1 >= 256 * 1024 * 1024);
