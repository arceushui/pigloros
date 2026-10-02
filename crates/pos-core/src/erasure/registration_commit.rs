//! Owner-verified preparation and persistence contracts for immutable ARD1 rows.

use super::{
    extract_adapter_admission_registration_v1, extract_adapter_transcript_registration_v1,
    extract_repro_manifest_root_registration_v1, inspect_artifact_registration_graph_v1,
    ArtifactDataClassV1, ArtifactRegistrationGraphErrorV1, ArtifactRegistrationGraphNodeV1,
    ArtifactRegistrationV1, ErasureArtifactClassV1, ReproManifestArtifactRegistrationErrorV1,
    ReproManifestRootRegistrationInputV1, MAX_ARTIFACT_GRAPH_REGISTRATIONS_V1,
    MAX_ARTIFACT_GRAPH_REGISTRATION_BYTES_V1,
};
use crate::{
    AdapterAdmissionV1, AdapterTranscriptV1, Hash, OwnerIdV1, ReproManifestRootV1,
    WorldRecordingReceiptV1,
};

/// Maximum exact artifact bytes in one prepared registration closure.
///
/// Canonical ARD1 registration bytes use their separate 64 MiB graph bound.
pub const MAX_ARTIFACT_REGISTRATION_BATCH_BYTES_V1: usize = 256 * 1024 * 1024;

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

    /// Classify an optional MRM1 label using the installed owner's record policy.
    ///
    /// The returned class is accepted only when it is `PublicRecord` or
    /// `StructuralAuditMetadata`. An implementation must derive the result
    /// from the actual owner policy, not from the caller's label text.
    ///
    /// # Errors
    /// Returns `Rejected` when the owner cannot classify this exact label.
    fn classify_repro_manifest_label(
        &self,
        _owner_id: &OwnerIdV1,
        _label: &str,
    ) -> Result<ArtifactDataClassV1, ArtifactRegistrationOwnerVerificationErrorV1> {
        Err(ArtifactRegistrationOwnerVerificationErrorV1::Rejected)
    }

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
    let (admission, _) = find_catalog_native_row(
        rows,
        ErasureArtifactClassV1::ReproManifest,
        transcript.as_input().adapter_admission_digest,
        |bytes| {
            AdapterAdmissionV1::from_canonical_cbor(bytes)
                .ok()
                .map(|value| (value.digest(), value))
        },
    )?;
    // MAT1 extraction rejects an admission row whose ARD1 differs from MAA1 extraction.
    let expected = extract_adapter_transcript_registration_v1(
        row.artifact_bytes(),
        admission.artifact_bytes(),
        admission.registration(),
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
    let (recording, _) = find_catalog_native_row(
        rows,
        ErasureArtifactClassV1::TimelineReplay,
        root.as_input()
            .world_handle
            .as_input()
            .recording_receipt_digest,
        |bytes| {
            WorldRecordingReceiptV1::from_canonical_cbor(bytes)
                .ok()
                .map(|value| (value.digest(), value))
        },
    )?;
    let (transcript, transcript_record) = find_catalog_native_row(
        rows,
        ErasureArtifactClassV1::ReproManifest,
        root.as_input().adapter_transcript_digest,
        |bytes| {
            AdapterTranscriptV1::from_canonical_cbor(bytes)
                .ok()
                .map(|value| (value.digest(), value))
        },
    )?;
    let (admission, _) = find_catalog_native_row(
        rows,
        ErasureArtifactClassV1::ReproManifest,
        transcript_record.as_input().adapter_admission_digest,
        |bytes| {
            AdapterAdmissionV1::from_canonical_cbor(bytes)
                .ok()
                .map(|value| (value.digest(), value))
        },
    )?;
    // MRM1 extraction rejects stored MAA1 and MAT1 rows whose ARD1 differs
    // from their exact extraction.
    let expected =
        extract_repro_manifest_root_registration_v1(ReproManifestRootRegistrationInputV1 {
            root_bytes: row.artifact_bytes(),
            recording_receipt_bytes: recording.artifact_bytes(),
            recording_registration: recording.registration(),
            transcript_bytes: transcript.artifact_bytes(),
            admission_bytes: admission.artifact_bytes(),
            admission_registration: admission.registration(),
            transcript_registration: transcript.registration(),
            owner_id: row.owner_id(),
            label_data_class: None,
        })
        .map_err(|_| ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)?;
    if &expected == row.registration() {
        Ok(())
    } else {
        Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
    }
}

fn find_catalog_native_row<T>(
    rows: &[ArtifactRegistrationCatalogRowV1],
    artifact_class: ErasureArtifactClassV1,
    native_digest: Hash,
    parse: impl Fn(&[u8]) -> Option<(Hash, T)>,
) -> Result<(&ArtifactRegistrationCatalogRowV1, T), ArtifactRegistrationPersistenceErrorV1> {
    let mut found = None;
    for (row, (_, value)) in rows
        .iter()
        .filter(|row| row.artifact_class() == artifact_class)
        .filter_map(|row| parse(row.artifact_bytes()).map(|parsed| (row, parsed)))
        .filter(|(_, (digest, _))| *digest == native_digest)
    {
        if found.is_some() {
            return Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog);
        }
        found = Some((row, value));
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
impl PreparedArtifactRegistrationBatchV1 {
    pub(crate) fn empty_for_test() -> Self {
        Self {
            owner_id: OwnerIdV1::from_static("unsupported-event-store-test"),
            root_registration_address: Hash::zero(),
            root_operation_id: Hash::zero(),
            records: Vec::new(),
        }
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
    let (records, root_operation_id) =
        derive_records(root_registration_address, &owner_id, parsed, owner_verifier)?;
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
        artifact_bytes = artifact_bytes.saturating_add(input.artifact_bytes.len());
        registration_bytes = registration_bytes.saturating_add(input.registration_cbor.len());
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

/// Prepared records with the root MRM1 run operation identity.
type DerivedArtifactRecordsV1 = (Vec<PreparedArtifactRegistrationRecordV1>, Hash);

fn derive_records(
    root_registration_address: Hash,
    owner_id: &OwnerIdV1,
    parsed: Vec<ParsedArtifact>,
    owner_verifier: &dyn ArtifactRegistrationOwnerVerifierV1,
) -> Result<DerivedArtifactRecordsV1, ArtifactRegistrationPreparationErrorV1> {
    let mut expected_registrations = Vec::with_capacity(parsed.len());
    for candidate in &parsed {
        let expected = derive_expected_registration(candidate, &parsed, owner_id, owner_verifier)?;
        if candidate.registration != expected {
            return Err(ArtifactRegistrationPreparationErrorV1::ExtractionMismatch);
        }
        expected_registrations.push(expected);
    }

    let root_operation_id = parsed
        .iter()
        .zip(&expected_registrations)
        .find_map(|(candidate, registration)| match &candidate.native {
            NativeArtifactV1::ReproManifestRoot(root)
                if registration.address() == root_registration_address
                    && candidate.owner_id == *owner_id =>
            {
                Some(root.as_input().run_operation_id)
            }
            _ => None,
        })
        .ok_or(ArtifactRegistrationPreparationErrorV1::InvalidGraph)?;
    let records = parsed
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
        .collect();
    Ok((records, root_operation_id))
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
            extract_adapter_registrations(&candidate.artifact_bytes, &admission.artifact_bytes)
                .map(|(_, transcript_registration)| transcript_registration)
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
            let (transcript, transcript_native) =
                find_transcript(closure, root_input.adapter_transcript_digest)?;
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
            let (admission_registration, transcript_registration) = extract_adapter_registrations(
                &transcript.artifact_bytes,
                &admission.artifact_bytes,
            )?;
            let label_data_class = root
                .as_input()
                .label
                .as_deref()
                .map(|label| {
                    owner_verifier
                        .classify_repro_manifest_label(&candidate.owner_id, label)
                        .map_err(|_| ArtifactRegistrationPreparationErrorV1::OwnerRejected)
                })
                .transpose()?;
            extract_repro_manifest_root_registration_v1(ReproManifestRootRegistrationInputV1 {
                root_bytes: &candidate.artifact_bytes,
                recording_receipt_bytes: &recording.artifact_bytes,
                recording_registration: &recording_registration,
                transcript_bytes: &transcript.artifact_bytes,
                admission_bytes: &admission.artifact_bytes,
                admission_registration: &admission_registration,
                transcript_registration: &transcript_registration,
                owner_id,
                label_data_class,
            })
            .map_err(|error| match error {
                ReproManifestArtifactRegistrationErrorV1::InvalidLabelClassification => {
                    ArtifactRegistrationPreparationErrorV1::OwnerRejected
                }
                ReproManifestArtifactRegistrationErrorV1::InvalidManifestRoot
                | ReproManifestArtifactRegistrationErrorV1::InvalidRecordingReceipt
                | ReproManifestArtifactRegistrationErrorV1::InvalidTranscript
                | ReproManifestArtifactRegistrationErrorV1::InvalidAdmission
                | ReproManifestArtifactRegistrationErrorV1::RecordingRegistrationMismatch
                | ReproManifestArtifactRegistrationErrorV1::TranscriptRegistrationMismatch
                | ReproManifestArtifactRegistrationErrorV1::ManifestBindingMismatch => {
                    ArtifactRegistrationPreparationErrorV1::UnsupportedArtifact
                }
            })
        }
    }
}

/// Exact MAA1 registration and the MAT1 registration that names it.
type AdapterRegistrationsV1 = (ArtifactRegistrationV1, ArtifactRegistrationV1);

fn extract_adapter_registrations(
    transcript_bytes: &[u8],
    admission_bytes: &[u8],
) -> Result<AdapterRegistrationsV1, ArtifactRegistrationPreparationErrorV1> {
    extract_adapter_admission_registration_v1(admission_bytes)
        .and_then(|admission_registration| {
            extract_adapter_transcript_registration_v1(
                transcript_bytes,
                admission_bytes,
                &admission_registration,
            )
            .map(|transcript_registration| (admission_registration, transcript_registration))
        })
        .map_err(|_| ArtifactRegistrationPreparationErrorV1::UnsupportedArtifact)
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
) -> Result<(&ParsedArtifact, &AdapterTranscriptV1), ArtifactRegistrationPreparationErrorV1> {
    let mut found = None;
    for candidate in closure {
        if let NativeArtifactV1::AdapterTranscript(transcript) = &candidate.native {
            if transcript.digest() == native_digest {
                if found.is_some() {
                    return Err(ArtifactRegistrationPreparationErrorV1::InvalidGraph);
                }
                found = Some((candidate, transcript));
            }
        }
    }
    found.ok_or(ArtifactRegistrationPreparationErrorV1::InvalidGraph)
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
        _ => ArtifactRegistrationPreparationErrorV1::InvalidGraph,
    }
}

const _: () = assert!(MAX_ARTIFACT_REGISTRATION_BATCH_BYTES_V1 == 256 * 1024 * 1024);

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::{
        AdapterAdmissionInputV1, AdapterTranscriptInputV1, ArtifactOptionalityV1,
        ArtifactRegistrationErrorV1, ArtifactRegistrationFieldsV1, ArtifactTransitionRuleV1,
        ReproManifestRootInputV1, TimelineId, WorldRecordingReceiptInputV1,
        WorldReplayHandleInputV1, WorldReplayHandleV1,
    };
    use ulid::Ulid;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const RUN_OPERATION_ID: [u8; 32] = [0x51; 32];

    struct StructuralOwner;

    impl ArtifactRegistrationOwnerVerifierV1 for StructuralOwner {
        fn derive_native_registration(
            &self,
            owner_id: &OwnerIdV1,
            artifact_class: ErasureArtifactClassV1,
            artifact_bytes: &[u8],
        ) -> Result<ArtifactRegistrationV1, ArtifactRegistrationOwnerVerificationErrorV1> {
            loose_registration(owner_id, artifact_class, artifact_bytes)
                .map_err(|_| ArtifactRegistrationOwnerVerificationErrorV1::Rejected)
        }

        fn verify_committed_artifact(
            &self,
            _owner_id: &OwnerIdV1,
            _artifact_bytes: &[u8],
            _registration: &ArtifactRegistrationV1,
        ) -> Result<(), ArtifactRegistrationOwnerVerificationErrorV1> {
            Ok(())
        }
    }

    struct NativeRecords {
        admission: AdapterAdmissionV1,
        transcript: AdapterTranscriptV1,
        recording: WorldRecordingReceiptV1,
        root: ReproManifestRootV1,
    }

    struct ManifestClosure {
        owner_id: OwnerIdV1,
        root: Hash,
        admission: ArtifactRegistrationInputV1,
        transcript: ArtifactRegistrationInputV1,
        recording: ArtifactRegistrationInputV1,
        manifest: ArtifactRegistrationInputV1,
    }

    impl ManifestClosure {
        fn inputs(&self) -> Vec<ArtifactRegistrationInputV1> {
            vec![
                self.admission.clone(),
                self.transcript.clone(),
                self.recording.clone(),
                self.manifest.clone(),
            ]
        }
    }

    struct CatalogRows {
        admission: ArtifactRegistrationCatalogRowV1,
        transcript: ArtifactRegistrationCatalogRowV1,
        recording: ArtifactRegistrationCatalogRowV1,
        manifest: ArtifactRegistrationCatalogRowV1,
    }

    impl CatalogRows {
        fn all(&self) -> Vec<ArtifactRegistrationCatalogRowV1> {
            vec![
                self.admission.clone(),
                self.transcript.clone(),
                self.recording.clone(),
                self.manifest.clone(),
            ]
        }

        fn without(&self, magic: &[u8]) -> Vec<ArtifactRegistrationCatalogRowV1> {
            self.all()
                .into_iter()
                .filter(|row| row.artifact_bytes().get(2..6) != Some(magic))
                .collect()
        }
    }

    fn loose_registration(
        owner_id: &OwnerIdV1,
        artifact_class: ErasureArtifactClassV1,
        artifact_bytes: &[u8],
    ) -> Result<ArtifactRegistrationV1, ArtifactRegistrationErrorV1> {
        ArtifactRegistrationV1::new(ArtifactRegistrationFieldsV1 {
            artifact_class,
            artifact_digest: ArtifactRegistrationV1::artifact_digest(
                artifact_class,
                artifact_bytes,
            ),
            owner_reference: ArtifactRegistrationV1::owner_reference(owner_id),
            data_class: ArtifactDataClassV1::StructuralAuditMetadata,
            optionality: ArtifactOptionalityV1::Required,
            transition_rule: ArtifactTransitionRuleV1::PreserveExact,
            required_key_roles: Vec::new(),
            key_dependencies: Vec::new(),
            child_artifacts: Vec::new(),
        })
    }

    fn native_records(
        owner_id: &OwnerIdV1,
        admission_owner_id: &OwnerIdV1,
    ) -> Result<NativeRecords, Box<dyn std::error::Error>> {
        let owner_reference = ArtifactRegistrationV1::owner_reference(owner_id);
        let run_operation_id = Hash::from_bytes(RUN_OPERATION_ID);
        let commit_receipt_digest = Hash::from_bytes([0x52; 32]);
        let recording = WorldRecordingReceiptV1::new(WorldRecordingReceiptInputV1 {
            binding_hash: Hash::from_bytes([0x53; 32]),
            operation_id: run_operation_id,
            actual_commit_receipt_digest: commit_receipt_digest,
            installed_inventory_generation: Hash::from_bytes([0x54; 32]),
        })?;
        let world_handle = WorldReplayHandleV1::new(WorldReplayHandleInputV1 {
            owner_reference,
            timeline_id: TimelineId::from_ulid(Ulid::from(1_u128)),
            cut_id: 1,
            commit_receipt_digest,
            recording_receipt_digest: recording.digest(),
            logical_head: 0,
            stitched_head_hash: Hash::from_bytes([0x55; 32]),
        })?;
        let admission = AdapterAdmissionV1::new(AdapterAdmissionInputV1 {
            owner_reference: ArtifactRegistrationV1::owner_reference(admission_owner_id),
            configuration_generation: 1,
            scope_digest: Hash::from_bytes([0x56; 32]),
            entries: Vec::new(),
        })?;
        let transcript = AdapterTranscriptV1::new(AdapterTranscriptInputV1 {
            owner_reference,
            world_handle,
            run_operation_id,
            adapter_admission_digest: admission.digest(),
            calls: Vec::new(),
        })?;
        let root = ReproManifestRootV1::new(ReproManifestRootInputV1 {
            owner_reference,
            world_handle,
            run_operation_id,
            plugin_roster_digest: Hash::from_bytes([0x57; 32]),
            adapter_transcript_digest: transcript.digest(),
            created_at_micros: 1,
            label: None,
        })?;
        Ok(NativeRecords {
            admission,
            transcript,
            recording,
            root,
        })
    }

    fn registration_input(
        owner_id: OwnerIdV1,
        artifact_bytes: Vec<u8>,
        registration: &ArtifactRegistrationV1,
    ) -> ArtifactRegistrationInputV1 {
        ArtifactRegistrationInputV1 {
            owner_id,
            artifact_bytes,
            registration_cbor: registration.canonical_cbor().to_vec(),
        }
    }

    fn complete_closure() -> Result<ManifestClosure, Box<dyn std::error::Error>> {
        let owner_id = OwnerIdV1::from_static("registration-commit-unit-owner");
        let records = native_records(&owner_id, &owner_id)?;
        let admission_bytes = records.admission.to_canonical_cbor();
        let transcript_bytes = records.transcript.to_canonical_cbor();
        let recording_bytes = records.recording.to_canonical_cbor();
        let manifest_bytes = records.root.to_canonical_cbor();
        let admission_registration = extract_adapter_admission_registration_v1(&admission_bytes)?;
        let transcript_registration = extract_adapter_transcript_registration_v1(
            &transcript_bytes,
            &admission_bytes,
            &admission_registration,
        )?;
        let recording_registration = loose_registration(
            &owner_id,
            ErasureArtifactClassV1::TimelineReplay,
            &recording_bytes,
        )?;
        let manifest_registration =
            extract_repro_manifest_root_registration_v1(ReproManifestRootRegistrationInputV1 {
                root_bytes: &manifest_bytes,
                recording_receipt_bytes: &recording_bytes,
                recording_registration: &recording_registration,
                transcript_bytes: &transcript_bytes,
                admission_bytes: &admission_bytes,
                admission_registration: &admission_registration,
                transcript_registration: &transcript_registration,
                owner_id: &owner_id,
                label_data_class: None,
            })?;
        Ok(ManifestClosure {
            owner_id,
            root: manifest_registration.address(),
            admission: registration_input(owner_id, admission_bytes, &admission_registration),
            transcript: registration_input(owner_id, transcript_bytes, &transcript_registration),
            recording: registration_input(owner_id, recording_bytes, &recording_registration),
            manifest: registration_input(owner_id, manifest_bytes, &manifest_registration),
        })
    }

    fn prepare(
        owner_id: OwnerIdV1,
        root: Hash,
        inputs: Vec<ArtifactRegistrationInputV1>,
    ) -> Result<PreparedArtifactRegistrationBatchV1, ArtifactRegistrationPreparationErrorV1> {
        prepare_artifact_registration_batch_v1(owner_id, root, inputs, &StructuralOwner)
    }

    fn catalog_row(
        owner_id: OwnerIdV1,
        artifact_bytes: &[u8],
        registration: ArtifactRegistrationV1,
    ) -> ArtifactRegistrationCatalogRowV1 {
        ArtifactRegistrationCatalogRowV1 {
            owner_id,
            artifact_class: registration.fields().artifact_class,
            artifact_digest: registration.fields().artifact_digest,
            registration_address: registration.address(),
            artifact_bytes: artifact_bytes.to_vec(),
            registration,
        }
    }

    fn input_row(
        input: &ArtifactRegistrationInputV1,
    ) -> Result<ArtifactRegistrationCatalogRowV1, ArtifactRegistrationErrorV1> {
        let registration = ArtifactRegistrationV1::from_canonical_cbor(&input.registration_cbor)?;
        Ok(catalog_row(input.owner_id, &input.artifact_bytes, registration))
    }

    fn catalog_rows() -> Result<CatalogRows, Box<dyn std::error::Error>> {
        let closure = complete_closure()?;
        Ok(CatalogRows {
            admission: input_row(&closure.admission)?,
            transcript: input_row(&closure.transcript)?,
            recording: input_row(&closure.recording)?,
            manifest: input_row(&closure.manifest)?,
        })
    }

    fn malformed_row(
        magic: &[u8],
    ) -> Result<ArtifactRegistrationCatalogRowV1, ArtifactRegistrationErrorV1> {
        let owner_id = OwnerIdV1::from_static("registration-commit-unit-owner");
        let mut artifact_bytes = b"\x84\x44".to_vec();
        artifact_bytes.extend_from_slice(magic);
        artifact_bytes.extend_from_slice(b" is not a canonical record");
        let registration =
            loose_registration(&owner_id, ErasureArtifactClassV1::ReproManifest, &artifact_bytes)?;
        Ok(catalog_row(owner_id, &artifact_bytes, registration))
    }

    #[test]
    fn prepared_batch_carries_the_root_run_operation() -> TestResult {
        let closure = complete_closure()?;
        let prepared = prepare(closure.owner_id, closure.root, closure.inputs())?;
        assert_eq!(prepared.root_registration_address(), closure.root);
        assert_eq!(prepared.root_operation_id(), Hash::from_bytes(RUN_OPERATION_ID));
        assert_eq!(prepared.records().len(), 4);
        Ok(())
    }

    #[test]
    fn preparation_rejects_a_root_address_that_names_a_child() -> TestResult {
        let closure = complete_closure()?;
        let admission =
            ArtifactRegistrationV1::from_canonical_cbor(&closure.admission.registration_cbor)?;
        assert_eq!(
            prepare(closure.owner_id, admission.address(), closure.inputs()),
            Err(ArtifactRegistrationPreparationErrorV1::InvalidGraph)
        );
        Ok(())
    }

    #[test]
    fn preparation_rejects_a_root_bound_to_another_batch_owner() -> TestResult {
        let closure = complete_closure()?;
        assert_eq!(
            prepare(
                OwnerIdV1::from_static("registration-commit-other-owner"),
                closure.root,
                closure.inputs(),
            ),
            Err(ArtifactRegistrationPreparationErrorV1::UnsupportedArtifact)
        );
        Ok(())
    }

    #[test]
    fn preparation_rejects_a_leading_root_without_its_admission() -> TestResult {
        let ManifestClosure {
            owner_id,
            root,
            transcript,
            recording,
            manifest,
            ..
        } = complete_closure()?;
        assert_eq!(
            prepare(owner_id, root, vec![manifest, transcript, recording]),
            Err(ArtifactRegistrationPreparationErrorV1::InvalidGraph)
        );
        Ok(())
    }

    #[test]
    fn preparation_skips_an_unrelated_transcript_and_rejects_the_extra_row() -> TestResult {
        let closure = complete_closure()?;
        let transcript =
            AdapterTranscriptV1::from_canonical_cbor(&closure.transcript.artifact_bytes)?;
        let mut other_run = transcript.as_input().clone();
        other_run.run_operation_id = Hash::from_bytes([0x5f; 32]);
        let other_bytes = AdapterTranscriptV1::new(other_run)?.to_canonical_cbor();
        let admission_registration =
            ArtifactRegistrationV1::from_canonical_cbor(&closure.admission.registration_cbor)?;
        let other_registration = extract_adapter_transcript_registration_v1(
            &other_bytes,
            &closure.admission.artifact_bytes,
            &admission_registration,
        )?;
        let mut inputs = closure.inputs();
        inputs.push(registration_input(closure.owner_id, other_bytes, &other_registration));
        assert_eq!(
            prepare(closure.owner_id, closure.root, inputs),
            Err(ArtifactRegistrationPreparationErrorV1::InvalidGraph)
        );
        Ok(())
    }

    #[test]
    fn transcript_naming_another_owners_admission_is_rejected() -> TestResult {
        let owner_id = OwnerIdV1::from_static("registration-commit-unit-owner");
        let foreign_owner_id = OwnerIdV1::from_static("registration-commit-foreign-owner");
        let records = native_records(&owner_id, &foreign_owner_id)?;
        let admission_bytes = records.admission.to_canonical_cbor();
        let transcript_bytes = records.transcript.to_canonical_cbor();
        let recording_bytes = records.recording.to_canonical_cbor();
        let manifest_bytes = records.root.to_canonical_cbor();
        let admission_registration = extract_adapter_admission_registration_v1(&admission_bytes)?;
        let recording_registration = loose_registration(
            &owner_id,
            ErasureArtifactClassV1::TimelineReplay,
            &recording_bytes,
        )?;
        // MAT1 extraction fails before the supplied MAT1 registration is compared.
        assert_eq!(
            extract_repro_manifest_root_registration_v1(ReproManifestRootRegistrationInputV1 {
                root_bytes: &manifest_bytes,
                recording_receipt_bytes: &recording_bytes,
                recording_registration: &recording_registration,
                transcript_bytes: &transcript_bytes,
                admission_bytes: &admission_bytes,
                admission_registration: &admission_registration,
                transcript_registration: &admission_registration,
                owner_id: &owner_id,
                label_data_class: None,
            }),
            Err(ReproManifestArtifactRegistrationErrorV1::InvalidTranscript)
        );

        let transcript_registration = loose_registration(
            &owner_id,
            ErasureArtifactClassV1::ReproManifest,
            &transcript_bytes,
        )?;
        let manifest_registration =
            loose_registration(&owner_id, ErasureArtifactClassV1::ReproManifest, &manifest_bytes)?;
        let root = manifest_registration.address();
        // The root is derived first, so its own MAT1 extraction reports the foreign MAA1.
        let inputs = vec![
            registration_input(owner_id, manifest_bytes, &manifest_registration),
            registration_input(owner_id, transcript_bytes, &transcript_registration),
            registration_input(owner_id, recording_bytes, &recording_registration),
            registration_input(foreign_owner_id, admission_bytes, &admission_registration),
        ];
        assert_eq!(
            prepare(owner_id, root, inputs),
            Err(ArtifactRegistrationPreparationErrorV1::UnsupportedArtifact)
        );
        Ok(())
    }

    #[test]
    fn graph_bound_failures_keep_their_bound_classification() {
        assert_eq!(
            map_graph_error(ArtifactRegistrationGraphErrorV1::BoundExceeded),
            ArtifactRegistrationPreparationErrorV1::BoundExceeded
        );
        assert_eq!(
            map_graph_error(ArtifactRegistrationGraphErrorV1::Cycle),
            ArtifactRegistrationPreparationErrorV1::InvalidGraph
        );
    }

    #[test]
    fn catalog_rows_reject_malformed_native_bytes() -> TestResult {
        let rows = catalog_rows()?.all();
        assert_eq!(
            validate_admission_catalog_row(&malformed_row(b"MAA1")?),
            Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
        );
        assert_eq!(
            validate_transcript_catalog_row(&malformed_row(b"MAT1")?, &rows),
            Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
        );
        assert_eq!(
            validate_root_catalog_row(&malformed_row(b"MRM1")?, &rows),
            Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
        );
        Ok(())
    }

    #[test]
    fn catalog_rows_reject_missing_native_dependencies() -> TestResult {
        let rows = catalog_rows()?;
        assert_eq!(validate_transcript_catalog_row(&rows.transcript, &rows.all()), Ok(()));
        assert_eq!(validate_root_catalog_row(&rows.manifest, &rows.all()), Ok(()));
        assert_eq!(
            validate_transcript_catalog_row(&rows.transcript, &rows.without(b"MAA1")),
            Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
        );
        for magic in [b"WCR1", b"MAT1", b"MAA1"] {
            assert_eq!(
                validate_root_catalog_row(&rows.manifest, &rows.without(magic)),
                Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
            );
        }
        Ok(())
    }

    #[test]
    fn catalog_rows_reject_a_duplicate_native_dependency() -> TestResult {
        let rows = catalog_rows()?;
        let mut duplicated = rows.all();
        duplicated.extend(rows.all());
        assert_eq!(
            validate_transcript_catalog_row(&rows.transcript, &duplicated),
            Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
        );
        Ok(())
    }

    #[test]
    fn catalog_rows_reject_a_stored_admission_registration_unlike_extraction() -> TestResult {
        let mut rows = catalog_rows()?;
        let owner_id = *rows.admission.owner_id();
        let changed = loose_registration(
            &owner_id,
            ErasureArtifactClassV1::ReproManifest,
            rows.admission.artifact_bytes(),
        )?;
        rows.admission = catalog_row(owner_id, rows.admission.artifact_bytes(), changed);
        assert_eq!(
            validate_transcript_catalog_row(&rows.transcript, &rows.all()),
            Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
        );
        assert_eq!(
            validate_root_catalog_row(&rows.manifest, &rows.all()),
            Err(ArtifactRegistrationPersistenceErrorV1::CorruptCatalog)
        );
        Ok(())
    }
}
