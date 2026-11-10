//! Shared guest failure vocabulary and borrowed durable failure views.

/// Exact ADR-061/PMF1 ID grammar, shared with the manifest and Runtime validators.
#[must_use]
pub fn is_valid_community_id_v1(value: &str) -> bool {
    let mut bytes = value.bytes();
    value.len() <= 128
        && bytes
            .next()
            .is_some_and(|first| first.is_ascii_lowercase() || first.is_ascii_digit())
        && bytes.all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'/' | b'-')
        })
}

/// `contract-v1.field-ref`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FieldRefV1 {
    /// Schema ID.
    pub schema_id: u32,
    /// Field ordinal.
    pub field_ordinal: u16,
}

/// `contract-v1.plugin-error-code`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PluginErrorCodeV1 {
    /// `invalid-invocation`.
    InvalidInvocation(FieldRefV1),
    /// `unsupported-schema`.
    UnsupportedSchema(u32),
    /// `capability-required`, with an ADR-061 capability ID.
    CapabilityRequired(String),
    /// `dependency-missing`.
    DependencyMissing([u8; 32]),
    /// `deterministic-budget-exhausted`.
    DeterministicBudgetExhausted,
    /// `invalid-state`.
    InvalidState(FieldRefV1),
    /// `migration-rejected`.
    MigrationRejected(FieldRefV1),
    /// `guest-declared-failure`.
    GuestDeclaredFailure(u16),
}

/// `contract-v1.plugin-error`: the guest's own typed failure, validated.
///
/// ADR-061 records the exact variant, ordinal, coordinate and digest as the
/// outcome. No `EventDraft` or state accompanies it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestPluginErrorV1 {
    /// The error code.
    pub code: PluginErrorCodeV1,
    /// Canonical coordinate, at most 128 bytes.
    pub canonical_coordinate: Option<Vec<u8>>,
    /// Related digest.
    pub related_digest: Option<[u8; 32]>,
}

/// Borrowed typed guest-error code. Decoding never clones a capability label.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CommunityGuestErrorCodeV1<'a> {
    /// Code0, exact schema/field coordinate.
    InvalidInvocation(FieldRefV1),
    /// Code1.
    UnsupportedSchema(u32),
    /// Code2, actual ADR-061 capability ID text.
    CapabilityRequired(&'a str),
    /// Code3, exact guest payload; no new nonzero-digest rule is imposed.
    DependencyMissing([u8; 32]),
    /// Code4.
    DeterministicBudgetExhausted,
    /// Code5.
    InvalidState(FieldRefV1),
    /// Code6.
    MigrationRejected(FieldRefV1),
    /// Code7, exact u16 guest code.
    GuestDeclaredFailure(u16),
}

/// Borrowed complete guest-error data, not diagnostic text or a source proof.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CommunityGuestErrorV1<'a> {
    /// Exact closed code and associated payload.
    pub code: CommunityGuestErrorCodeV1<'a>,
    /// Original 0..128-byte coordinate when present, never decoded as free text.
    pub canonical_coordinate: Option<&'a [u8]>,
    /// Original optional 32-byte payload, including zero if the guest schema allows.
    pub related_digest: Option<[u8; 32]>,
}

impl<'a> CommunityGuestErrorV1<'a> {
    /// Borrow the live Runtime capability and coordinate byte ranges.
    /// Fixed-size code and identity values are copied into this view.
    #[must_use]
    pub fn from_guest_error(error: &'a GuestPluginErrorV1) -> Self {
        let code = match &error.code {
            PluginErrorCodeV1::InvalidInvocation(field) => {
                CommunityGuestErrorCodeV1::InvalidInvocation(*field)
            }
            PluginErrorCodeV1::UnsupportedSchema(schema) => {
                CommunityGuestErrorCodeV1::UnsupportedSchema(*schema)
            }
            PluginErrorCodeV1::CapabilityRequired(id) => {
                CommunityGuestErrorCodeV1::CapabilityRequired(id)
            }
            PluginErrorCodeV1::DependencyMissing(digest) => {
                CommunityGuestErrorCodeV1::DependencyMissing(*digest)
            }
            PluginErrorCodeV1::DeterministicBudgetExhausted => {
                CommunityGuestErrorCodeV1::DeterministicBudgetExhausted
            }
            PluginErrorCodeV1::InvalidState(field) => {
                CommunityGuestErrorCodeV1::InvalidState(*field)
            }
            PluginErrorCodeV1::MigrationRejected(field) => {
                CommunityGuestErrorCodeV1::MigrationRejected(*field)
            }
            PluginErrorCodeV1::GuestDeclaredFailure(code) => {
                CommunityGuestErrorCodeV1::GuestDeclaredFailure(*code)
            }
        };
        Self {
            code,
            canonical_coordinate: error.canonical_coordinate.as_deref(),
            related_digest: error.related_digest,
        }
    }
}
