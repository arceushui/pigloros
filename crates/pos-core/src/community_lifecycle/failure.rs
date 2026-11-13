//! Retained CFI1/CFO1 failures. Neither decoding nor a code proves its source.

use super::{
    bounded_bytes, bounded_text, canonical_end, digest, fixed_bytes, is_valid_community_id_v1,
    read_hash, read_head, read_optional_hash, read_pass_key, record_cursor, record_prefix,
    validate_horizon, AtomicCommitFailureV1, BundleContentReasonV1, CommunityDigestListV1,
    CommunityGuestErrorCodeV1, CommunityGuestErrorV1, CommunityLifecycleErrorV1 as Error,
    CommunityPassKeyV1, CommunityPluginHostErrorV1 as Host, ComponentTrapClassV1, FieldRefV1,
    Result, RevocationBasisV1, TrapReproductionV1, TrustDenialBasisV1,
};
use crate::{encode_bytes, encode_hash, encode_head, CborCursor, Hash};
use zeroize::Zeroizing;

/// Untrusted exact CFI1 fields. Operational errors never become guest outcomes.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityInvocationFailureInputV1<'a> {
    /// Original reserved pass when there is one, never fabricated for rejection.
    pub pass_key: Option<CommunityPassKeyV1>,
    /// Exact admitted member binding.
    pub member_binding_digest: Hash,
    /// Original prepared invocation when one exists.
    pub invocation_id: Option<[u8; 16]>,
    /// Exact original CIN1 when one exists.
    pub prepared_invocation_digest: Option<Hash>,
    /// Exact closed host failure, not its display/debug string or discriminant.
    pub host_failure: Host,
    /// Present exactly for the actual guest-declared failure host variant.
    pub guest_error: Option<CommunityGuestErrorV1<'a>>,
    /// Earlier independently verified host failure/decision provenance.
    pub decision_provenance_digest: Hash,
    /// Original admitted horizon, bounded by actual source evidence.
    pub evidence_not_after_micros: u64,
}

/// Borrowed CFI1 historical data, not a failure-source or execution certificate.
pub struct CommunityInvocationFailureV1<'a>(CommunityInvocationFailureInputV1<'a>);

impl<'a> CommunityInvocationFailureV1<'a> {
    /// Validate local identities, closed payload bounds and guest-error presence.
    ///
    /// # Errors
    /// Rejects zero required/present identities, invalid guest payload or horizon,
    /// out-of-profile PMF1 indices or guest data attached to another host error.
    /// Actual phase, exact PMF1 list membership, failure source, reproduction and
    /// current authority remain independently checked by the qualified owner.
    pub fn new(input: CommunityInvocationFailureInputV1<'a>) -> Result<Self> {
        if [
            input.member_binding_digest,
            input.decision_provenance_digest,
        ]
        .contains(&Hash::zero())
            || input.invocation_id == Some([0; 16])
            || input.prepared_invocation_digest == Some(Hash::zero())
            || (input.host_failure == Host::GuestDeclaredFailure) != input.guest_error.is_some()
        {
            return Err(Error::InvalidBinding);
        }
        validate_host(input.host_failure)
            .and_then(|()| input.guest_error.map_or(Ok(()), validate_guest))
            .and_then(|()| validate_horizon(input.evidence_not_after_micros))
            .map(|()| Self(input))
    }

    /// Borrow exact historical data; it cannot choose a new pass or clear failure.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityInvocationFailureInputV1<'a> {
        &self.0
    }

    /// Encode exact ten-field CFI1 into one pre-sized zeroizing output.
    /// Capability and coordinate bytes are copied into that owned output range.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(4096));
        record_prefix(&mut out, 10, *b"CFI1");
        encode_optional_pass(&mut out, input.pass_key);
        encode_hash(&mut out, input.member_binding_digest);
        match input.invocation_id {
            None => out.push(0xf6),
            Some(id) => encode_bytes(&mut out, &id, 2),
        }
        super::encode_optional_hash(&mut out, input.prepared_invocation_digest);
        encode_host(&mut out, input.host_failure);
        match input.guest_error {
            None => out.push(0xf6),
            Some(error) => encode_guest(&mut out, error),
        }
        encode_hash(&mut out, input.decision_provenance_digest);
        encode_head(&mut out, 0, input.evidence_not_after_micros);
        out
    }

    /// Protected original invocation-failure identity, never a State producer.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(b"PiglorOS.Community.CFI1.v1\0", &self.to_canonical_cbor())
    }

    /// Decode CFI1 while borrowing private guest coordinate/capability bytes.
    ///
    /// # Errors
    /// Rejects malformed/nonpreferred/trailing/versioned/oversized records,
    /// unknown host/guest code or associated value and invalid local bindings.
    pub fn from_canonical_cbor(bytes: &'a [u8]) -> Result<Self> {
        record_cursor(bytes, 4096, 10, *b"CFI1").and_then(|mut cursor| {
            read_failure_identity(&mut cursor).and_then(|identity| {
                read_host(&mut cursor).and_then(|host_failure| {
                    read_optional_guest(&mut cursor).and_then(|guest_error| {
                        read_hash(&mut cursor).and_then(|decision_provenance_digest| {
                            read_head(&mut cursor, 0).and_then(|evidence_not_after_micros| {
                                canonical_end(&cursor).and_then(|()| {
                                    Self::new(CommunityInvocationFailureInputV1 {
                                        pass_key: identity.pass,
                                        member_binding_digest: identity.member,
                                        invocation_id: identity.invocation,
                                        prepared_invocation_digest: identity.prepared,
                                        host_failure,
                                        guest_error,
                                        decision_provenance_digest,
                                        evidence_not_after_micros,
                                    })
                                })
                            })
                        })
                    })
                })
            })
        })
    }
}

/// Untrusted CFO1 data; exact CFI1 membership and original source are owner work.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityPassFailureInputV1<'a> {
    /// Original reserved pass or null for an independently admitted preflight.
    pub pass_key: Option<CommunityPassKeyV1>,
    /// Exact earlier CFI1 identities, in the actual complete invocation order.
    pub invocation_evidence_digests: CommunityDigestListV1<'a>,
    /// Exact closed host failure, retaining its associated fields.
    pub host_failure: Host,
    /// Exact earlier host decision/source commitment.
    pub host_decision_provenance_digest: Hash,
    /// Original admitted horizon, never reset by a repeated failure.
    pub evidence_not_after_micros: u64,
}

/// Historical CFO1; unavailable evidence cannot authorize another invocation.
pub struct CommunityPassFailureV1<'a>(CommunityPassFailureInputV1<'a>);

impl<'a> CommunityPassFailureV1<'a> {
    /// Check identities, invocation-list bound and finite source horizon.
    ///
    /// # Errors
    /// Rejects zero links, over64 invocations, out-of-profile PMF1 indices and an
    /// invalid horizon. No encoded failure is an authenticated failure producer.
    pub fn new(input: CommunityPassFailureInputV1<'a>) -> Result<Self> {
        if input.invocation_evidence_digests.len() > 64 {
            return Err(Error::BoundsExceeded);
        }
        if input.host_decision_provenance_digest == Hash::zero()
            || input
                .invocation_evidence_digests
                .iter()
                .any(|hash| hash == Hash::zero())
        {
            return Err(Error::InvalidBinding);
        }
        validate_host(input.host_failure)
            .and_then(|()| validate_horizon(input.evidence_not_after_micros))
            .map(|()| Self(input))
    }

    /// Borrow historical failure data, without authenticating any dependency.
    #[must_use]
    pub const fn as_input(&self) -> &CommunityPassFailureInputV1<'a> {
        &self.0
    }

    /// Encode exact seven-field CFO1 in fully reserved zeroizing staging.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Zeroizing<Vec<u8>> {
        let input = self.as_input();
        let mut out = Zeroizing::new(Vec::with_capacity(16_384));
        record_prefix(&mut out, 7, *b"CFO1");
        encode_optional_pass(&mut out, input.pass_key);
        encode_head(&mut out, 4, input.invocation_evidence_digests.len() as u64);
        for evidence in input.invocation_evidence_digests.iter() {
            encode_hash(&mut out, evidence);
        }
        encode_host(&mut out, input.host_failure);
        encode_hash(&mut out, input.host_decision_provenance_digest);
        encode_head(&mut out, 0, input.evidence_not_after_micros);
        out
    }

    /// Protected CFO1 identity, excluding the later control/outcome using it.
    #[must_use]
    pub fn digest(&self) -> Hash {
        digest(b"PiglorOS.Community.CFO1.v1\0", &self.to_canonical_cbor())
    }

    /// Decode exact CFO1, borrowing its potentially personal invocation list.
    ///
    /// # Errors
    /// Rejects malformed/nonpreferred/trailing/versioned/oversized data,
    /// unknown failure codes/payloads or locally invalid links/bounds/horizon.
    pub fn from_canonical_cbor(bytes: &'a [u8]) -> Result<Self> {
        record_cursor(bytes, 16_384, 7, *b"CFO1").and_then(|mut cursor| {
            read_optional_pass(&mut cursor).and_then(|pass_key| {
                super::seal::read_list(&mut cursor).and_then(|invocation_evidence_digests| {
                    read_host(&mut cursor).and_then(|host_failure| {
                        read_hash(&mut cursor).and_then(|host_decision_provenance_digest| {
                            read_head(&mut cursor, 0).and_then(|evidence_not_after_micros| {
                                canonical_end(&cursor).and_then(|()| {
                                    Self::new(CommunityPassFailureInputV1 {
                                        pass_key,
                                        invocation_evidence_digests,
                                        host_failure,
                                        host_decision_provenance_digest,
                                        evidence_not_after_micros,
                                    })
                                })
                            })
                        })
                    })
                })
            })
        })
    }
}

const fn validate_host(error: Host) -> Result<()> {
    match error {
        Host::MissingFeature { index } | Host::CapabilityDenied { index } if index >= 256 => {
            Err(Error::BoundsExceeded)
        }
        _ => Ok(()),
    }
}

fn validate_guest(error: CommunityGuestErrorV1<'_>) -> Result<()> {
    if error
        .canonical_coordinate
        .is_some_and(|bytes| bytes.len() > 128)
    {
        return Err(Error::BoundsExceeded);
    }
    if let CommunityGuestErrorCodeV1::CapabilityRequired(id) = error.code {
        if !is_valid_community_id_v1(id) {
            return Err(Error::InvalidBinding);
        }
    }
    Ok(())
}

fn encode_optional_pass(out: &mut Vec<u8>, pass: Option<CommunityPassKeyV1>) {
    match pass {
        None => out.push(0xf6),
        Some(pass) => {
            let bytes = Zeroizing::new(pass.to_canonical_cbor());
            encode_bytes(out, &bytes, 2);
        }
    }
}

fn read_optional_pass(cursor: &mut CborCursor<'_>) -> Result<Option<CommunityPassKeyV1>> {
    if cursor.consume_if(0xf6) {
        Ok(None)
    } else {
        read_pass_key(cursor).map(Some)
    }
}

struct FailureIdentity {
    pass: Option<CommunityPassKeyV1>,
    member: Hash,
    invocation: Option<[u8; 16]>,
    prepared: Option<Hash>,
}

fn read_failure_identity(cursor: &mut CborCursor<'_>) -> Result<FailureIdentity> {
    read_optional_pass(cursor).and_then(|pass| {
        read_hash(cursor).and_then(|member| {
            let invocation = if cursor.consume_if(0xf6) {
                Ok(None)
            } else {
                fixed_bytes(cursor).map(Some)
            };
            invocation.and_then(|invocation| {
                read_optional_hash(cursor).map(|prepared| FailureIdentity {
                    pass,
                    member,
                    invocation,
                    prepared,
                })
            })
        })
    })
}

fn encode_scalar_failure(out: &mut Vec<u8>, code: u8, value: u64) {
    out.extend_from_slice(&[0x82, code]);
    encode_head(out, 0, value);
}

/// The closed ADR-129 host-failure code of every host error.
const fn host_code(error: Host) -> u8 {
    match error {
        Host::InvalidManifest => 0,
        Host::ArtifactTrustDenied { .. } => 1,
        Host::ArtifactRevoked { .. } => 2,
        Host::IncompatibleAbi => 3,
        Host::MissingFeature { .. } => 4,
        Host::CapabilityDenied { .. } => 5,
        Host::InvalidInvocation => 6,
        Host::InvalidGuestOutput => 7,
        Host::UnsupportedSchema => 8,
        Host::StateMigrationFailed => 9,
        Host::GuestDeclaredFailure => 10,
        Host::ComponentTrap { .. } => 11,
        Host::WorkerCrashed => 12,
        Host::FuelExhausted => 13,
        Host::MemoryLimitExceeded => 14,
        Host::HostCallLimitExceeded => 15,
        Host::OutputLimitExceeded => 16,
        Host::DeterministicDeadlineExceeded => 17,
        Host::OperationalWatchdogStop => 18,
        Host::AtomicCommitFailed { .. } => 19,
        Host::InvalidBundleContent { .. } => 20,
    }
}

fn encode_host(out: &mut Vec<u8>, error: Host) {
    let code = host_code(error);
    match error {
        Host::ArtifactTrustDenied { basis } => {
            encode_scalar_failure(out, code, u64::from(denial_code(basis)));
        }
        Host::ArtifactRevoked { basis } => {
            encode_scalar_failure(out, code, u64::from(revocation_code(basis)));
        }
        Host::MissingFeature { index } | Host::CapabilityDenied { index } => {
            encode_scalar_failure(out, code, index as u64);
        }
        Host::ComponentTrap {
            class,
            reproduction,
        } => out.extend_from_slice(&[
            0x83,
            code,
            trap_code(class),
            reproduction_code(reproduction),
        ]),
        Host::AtomicCommitFailed { failure } => {
            encode_scalar_failure(out, code, u64::from(atomic_code(failure)));
        }
        Host::InvalidBundleContent { reason } => {
            encode_scalar_failure(out, code, u64::from(content_reason_code(reason)));
        }
        Host::InvalidManifest
        | Host::IncompatibleAbi
        | Host::InvalidInvocation
        | Host::InvalidGuestOutput
        | Host::UnsupportedSchema
        | Host::StateMigrationFailed
        | Host::GuestDeclaredFailure
        | Host::WorkerCrashed
        | Host::FuelExhausted
        | Host::MemoryLimitExceeded
        | Host::HostCallLimitExceeded
        | Host::OutputLimitExceeded
        | Host::DeterministicDeadlineExceeded
        | Host::OperationalWatchdogStop => out.extend_from_slice(&[0x81, code]),
    }
}

fn read_host(cursor: &mut CborCursor<'_>) -> Result<Host> {
    read_head(cursor, 4).and_then(|count| {
        read_head(cursor, 0).and_then(|code| match (count, code) {
            (1, 0) => Ok(Host::InvalidManifest),
            (2, 1) => read_denial(cursor).map(|basis| Host::ArtifactTrustDenied { basis }),
            (2, 2) => read_revocation(cursor).map(|basis| Host::ArtifactRevoked { basis }),
            (1, 3) => Ok(Host::IncompatibleAbi),
            (2, 4) => read_index(cursor).map(|index| Host::MissingFeature { index }),
            (2, 5) => read_index(cursor).map(|index| Host::CapabilityDenied { index }),
            (1, 6) => Ok(Host::InvalidInvocation),
            (1, 7) => Ok(Host::InvalidGuestOutput),
            (1, 8) => Ok(Host::UnsupportedSchema),
            (1, 9) => Ok(Host::StateMigrationFailed),
            (1, 10) => Ok(Host::GuestDeclaredFailure),
            (3, 11) => read_trap(cursor).and_then(|class| {
                read_reproduction(cursor).map(|reproduction| Host::ComponentTrap {
                    class,
                    reproduction,
                })
            }),
            (1, 12) => Ok(Host::WorkerCrashed),
            (1, 13) => Ok(Host::FuelExhausted),
            (1, 14) => Ok(Host::MemoryLimitExceeded),
            (1, 15) => Ok(Host::HostCallLimitExceeded),
            (1, 16) => Ok(Host::OutputLimitExceeded),
            (1, 17) => Ok(Host::DeterministicDeadlineExceeded),
            (1, 18) => Ok(Host::OperationalWatchdogStop),
            (2, 19) => read_atomic(cursor).map(|failure| Host::AtomicCommitFailed { failure }),
            (2, 20) => {
                read_content_reason(cursor).map(|reason| Host::InvalidBundleContent { reason })
            }
            _ => Err(Error::InvalidEncoding),
        })
    })
}

fn read_index(cursor: &mut CborCursor<'_>) -> Result<usize> {
    read_head(cursor, 0).and_then(|index| {
        if index < 256 {
            Ok(usize::try_from(index).unwrap_or(usize::MAX))
        } else {
            Err(Error::BoundsExceeded)
        }
    })
}

const fn denial_code(basis: TrustDenialBasisV1) -> u8 {
    match basis {
        TrustDenialBasisV1::Expired => 0,
        TrustDenialBasisV1::NotActive => 1,
        TrustDenialBasisV1::Untrusted => 2,
        TrustDenialBasisV1::PolicyMismatch => 3,
        TrustDenialBasisV1::TrustStateUnavailable => 4,
    }
}
const fn revocation_code(basis: RevocationBasisV1) -> u8 {
    match basis {
        RevocationBasisV1::PublisherKey => 0,
        RevocationBasisV1::Artifact => 1,
        RevocationBasisV1::OperatorDenial => 2,
    }
}
const fn trap_code(class: ComponentTrapClassV1) -> u8 {
    match class {
        ComponentTrapClassV1::Unreachable => 0,
        ComponentTrapClassV1::MemoryOutOfBounds => 1,
        ComponentTrapClassV1::TableOutOfBounds => 2,
        ComponentTrapClassV1::IndirectCall => 3,
        ComponentTrapClassV1::IntegerArithmetic => 4,
        ComponentTrapClassV1::StackExhausted => 5,
        ComponentTrapClassV1::Other => 6,
    }
}
const fn reproduction_code(value: TrapReproductionV1) -> u8 {
    match value {
        TrapReproductionV1::ReproducedByConformance => 0,
        TrapReproductionV1::Unverified => 1,
    }
}
const fn atomic_code(value: AtomicCommitFailureV1) -> u8 {
    match value {
        AtomicCommitFailureV1::DeterministicTypedResult => 0,
        AtomicCommitFailureV1::Operational => 1,
    }
}
const fn content_reason_code(value: BundleContentReasonV1) -> u8 {
    match value {
        BundleContentReasonV1::BoundsExceeded => 0,
        BundleContentReasonV1::UnsupportedFormat => 1,
        BundleContentReasonV1::Malformed => 2,
        BundleContentReasonV1::ReferenceMismatch => 3,
    }
}

fn read_denial(cursor: &mut CborCursor<'_>) -> Result<TrustDenialBasisV1> {
    read_head(cursor, 0).and_then(|code| match code {
        0 => Ok(TrustDenialBasisV1::Expired),
        1 => Ok(TrustDenialBasisV1::NotActive),
        2 => Ok(TrustDenialBasisV1::Untrusted),
        3 => Ok(TrustDenialBasisV1::PolicyMismatch),
        4 => Ok(TrustDenialBasisV1::TrustStateUnavailable),
        _ => Err(Error::InvalidEncoding),
    })
}
fn read_revocation(cursor: &mut CborCursor<'_>) -> Result<RevocationBasisV1> {
    read_head(cursor, 0).and_then(|code| match code {
        0 => Ok(RevocationBasisV1::PublisherKey),
        1 => Ok(RevocationBasisV1::Artifact),
        2 => Ok(RevocationBasisV1::OperatorDenial),
        _ => Err(Error::InvalidEncoding),
    })
}
fn read_trap(cursor: &mut CborCursor<'_>) -> Result<ComponentTrapClassV1> {
    read_head(cursor, 0).and_then(|code| match code {
        0 => Ok(ComponentTrapClassV1::Unreachable),
        1 => Ok(ComponentTrapClassV1::MemoryOutOfBounds),
        2 => Ok(ComponentTrapClassV1::TableOutOfBounds),
        3 => Ok(ComponentTrapClassV1::IndirectCall),
        4 => Ok(ComponentTrapClassV1::IntegerArithmetic),
        5 => Ok(ComponentTrapClassV1::StackExhausted),
        6 => Ok(ComponentTrapClassV1::Other),
        _ => Err(Error::InvalidEncoding),
    })
}
fn read_reproduction(cursor: &mut CborCursor<'_>) -> Result<TrapReproductionV1> {
    read_head(cursor, 0).and_then(|code| match code {
        0 => Ok(TrapReproductionV1::ReproducedByConformance),
        1 => Ok(TrapReproductionV1::Unverified),
        _ => Err(Error::InvalidEncoding),
    })
}
fn read_atomic(cursor: &mut CborCursor<'_>) -> Result<AtomicCommitFailureV1> {
    read_head(cursor, 0).and_then(|code| match code {
        0 => Ok(AtomicCommitFailureV1::DeterministicTypedResult),
        1 => Ok(AtomicCommitFailureV1::Operational),
        _ => Err(Error::InvalidEncoding),
    })
}
fn read_content_reason(cursor: &mut CborCursor<'_>) -> Result<BundleContentReasonV1> {
    read_head(cursor, 0).and_then(|code| match code {
        0 => Ok(BundleContentReasonV1::BoundsExceeded),
        1 => Ok(BundleContentReasonV1::UnsupportedFormat),
        2 => Ok(BundleContentReasonV1::Malformed),
        3 => Ok(BundleContentReasonV1::ReferenceMismatch),
        _ => Err(Error::InvalidEncoding),
    })
}

fn encode_guest(out: &mut Vec<u8>, error: CommunityGuestErrorV1<'_>) {
    out.push(0x83);
    encode_guest_code(out, error.code);
    match error.canonical_coordinate {
        None => out.push(0xf6),
        Some(bytes) => encode_bytes(out, bytes, 2),
    }
    match error.related_digest {
        None => out.push(0xf6),
        Some(bytes) => encode_bytes(out, &bytes, 2),
    }
}

fn encode_field(out: &mut Vec<u8>, code: u8, field: FieldRefV1) {
    out.extend_from_slice(&[0x83, code]);
    encode_head(out, 0, u64::from(field.schema_id));
    encode_head(out, 0, u64::from(field.field_ordinal));
}

fn encode_guest_code(out: &mut Vec<u8>, code: CommunityGuestErrorCodeV1<'_>) {
    match code {
        CommunityGuestErrorCodeV1::InvalidInvocation(field) => encode_field(out, 0, field),
        CommunityGuestErrorCodeV1::UnsupportedSchema(schema) => {
            encode_scalar_failure(out, 1, u64::from(schema));
        }
        CommunityGuestErrorCodeV1::CapabilityRequired(id) => {
            out.extend_from_slice(&[0x82, 2]);
            encode_bytes(out, id.as_bytes(), 3);
        }
        CommunityGuestErrorCodeV1::DependencyMissing(hash) => {
            out.extend_from_slice(&[0x82, 3]);
            encode_bytes(out, &hash, 2);
        }
        CommunityGuestErrorCodeV1::DeterministicBudgetExhausted => {
            out.extend_from_slice(&[0x81, 4]);
        }
        CommunityGuestErrorCodeV1::InvalidState(field) => encode_field(out, 5, field),
        CommunityGuestErrorCodeV1::MigrationRejected(field) => encode_field(out, 6, field),
        CommunityGuestErrorCodeV1::GuestDeclaredFailure(code) => {
            encode_scalar_failure(out, 7, u64::from(code));
        }
    }
}

fn read_optional_guest<'a>(
    cursor: &mut CborCursor<'a>,
) -> Result<Option<CommunityGuestErrorV1<'a>>> {
    if cursor.consume_if(0xf6) {
        return Ok(None);
    }
    cursor
        .fixed(&[0x83])
        .map_err(Error::from)
        .and_then(|()| read_guest_code(cursor))
        .and_then(|code| {
            let coordinate = if cursor.consume_if(0xf6) {
                Ok(None)
            } else {
                bounded_bytes(cursor, 128).map(Some)
            };
            coordinate.and_then(|canonical_coordinate| {
                let related = if cursor.consume_if(0xf6) {
                    Ok(None)
                } else {
                    fixed_bytes(cursor).map(Some)
                };
                related.map(|related_digest| {
                    Some(CommunityGuestErrorV1 {
                        code,
                        canonical_coordinate,
                        related_digest,
                    })
                })
            })
        })
}

fn read_guest_code<'a>(cursor: &mut CborCursor<'a>) -> Result<CommunityGuestErrorCodeV1<'a>> {
    read_head(cursor, 4).and_then(|count| {
        read_head(cursor, 0).and_then(|code| match (count, code) {
            (3, 0) => read_field(cursor).map(CommunityGuestErrorCodeV1::InvalidInvocation),
            (2, 1) => read_u32(cursor).map(CommunityGuestErrorCodeV1::UnsupportedSchema),
            (2, 2) => bounded_text(cursor, 128).map(CommunityGuestErrorCodeV1::CapabilityRequired),
            (2, 3) => fixed_bytes(cursor).map(CommunityGuestErrorCodeV1::DependencyMissing),
            (1, 4) => Ok(CommunityGuestErrorCodeV1::DeterministicBudgetExhausted),
            (3, 5) => read_field(cursor).map(CommunityGuestErrorCodeV1::InvalidState),
            (3, 6) => read_field(cursor).map(CommunityGuestErrorCodeV1::MigrationRejected),
            (2, 7) => read_u16(cursor).map(CommunityGuestErrorCodeV1::GuestDeclaredFailure),
            _ => Err(Error::InvalidEncoding),
        })
    })
}

fn read_u32(cursor: &mut CborCursor<'_>) -> Result<u32> {
    read_head(cursor, 0).and_then(|value| u32::try_from(value).map_err(|_| Error::BoundsExceeded))
}
fn read_u16(cursor: &mut CborCursor<'_>) -> Result<u16> {
    read_head(cursor, 0).and_then(|value| u16::try_from(value).map_err(|_| Error::BoundsExceeded))
}
fn read_field(cursor: &mut CborCursor<'_>) -> Result<FieldRefV1> {
    read_u32(cursor).and_then(|schema_id| {
        read_u16(cursor).map(|field_ordinal| FieldRefV1 {
            schema_id,
            field_ordinal,
        })
    })
}
