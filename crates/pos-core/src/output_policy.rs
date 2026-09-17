//! Structural EOP1 declarations. These values grant no execution or read authority.

use crate::{Hash, PluginId};

/// Maximum canonical EOP1 bytes.
pub const MAX_OUTPUT_POLICY_BYTES_V1: usize = 65_536;
/// Maximum declarations in one policy.
pub const MAX_OUTPUT_DECLARATIONS_V1: usize = 256;

/// Replay obligation of an output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputAuthorityV1 {
    /// Required authoritative input.
    Authoritative,
    /// Reproducible view of retained authoritative inputs.
    ReproducibleDerived,
    /// Disposable output that cannot affect authoritative State.
    Ephemeral,
}

/// Fidelity is independent of replay obligation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFidelityV1 {
    /// Full per-entity output.
    L0,
    /// Strided or delta output.
    L1,
    /// Aggregate output.
    L2,
}

/// Closed structural errors, without guest-controlled diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OutputPolicyErrorV1 {
    /// Wrong CBOR shape, type, magic or incomplete input.
    #[error("invalid output policy encoding")]
    InvalidEncoding,
    /// Unknown format version or enum.
    #[error("unsupported output policy value")]
    UnsupportedValue,
    /// A structural admissibility bound was exceeded.
    #[error("output policy field out of bounds")]
    FieldOutOfBounds,
    /// Integer widths, ordering or trailing bytes are not canonical.
    #[error("noncanonical output policy")]
    NonCanonical,
    /// Authority, fidelity and nullable metadata disagree.
    #[error("incompatible output declaration")]
    IncompatibleDeclaration,
}

/// Immutable, structurally validated declaration; not an emission permit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputDeclarationV1 {
    event_type: String,
    authority: OutputAuthorityV1,
    fidelity: OutputFidelityV1,
    max_bytes: u32,
    stride_ticks: Option<u32>,
    aggregate_min_group: Option<u32>,
}

impl OutputDeclarationV1 {
    /// Validate declaration metadata. Host ownership, profile and population
    /// limits must additionally be verified by the production admission owner.
    ///
    /// # Errors
    /// Rejects invalid text, zero size, authoritative non-L0 output, and invalid
    /// fidelity-specific stride/group metadata.
    pub fn new(
        event_type: String,
        authority: OutputAuthorityV1,
        fidelity: OutputFidelityV1,
        max_bytes: u32,
        stride_ticks: Option<u32>,
        aggregate_min_group: Option<u32>,
    ) -> Result<Self, OutputPolicyErrorV1> {
        if event_type.is_empty() || event_type.len() > 128 || max_bytes == 0 {
            return Err(OutputPolicyErrorV1::FieldOutOfBounds);
        }
        let valid_fidelity = match fidelity {
            OutputFidelityV1::L0 => stride_ticks.is_none() && aggregate_min_group.is_none(),
            OutputFidelityV1::L1 => {
                stride_ticks.is_some_and(|stride| (1..=32).contains(&stride))
                    && aggregate_min_group.is_none()
            }
            OutputFidelityV1::L2 => {
                stride_ticks.is_none() && aggregate_min_group.is_some_and(|group| group >= 10)
            }
        };
        if !valid_fidelity
            || (authority == OutputAuthorityV1::Authoritative && fidelity != OutputFidelityV1::L0)
        {
            return Err(OutputPolicyErrorV1::IncompatibleDeclaration);
        }
        Ok(Self {
            event_type,
            authority,
            fidelity,
            max_bytes,
            stride_ticks,
            aggregate_min_group,
        })
    }

    /// Owned output type requiring separate host registration verification.
    #[must_use]
    pub fn event_type(&self) -> &str { &self.event_type }
    /// Declared replay obligation.
    #[must_use]
    pub const fn authority(&self) -> OutputAuthorityV1 { self.authority }
    /// Declared fidelity.
    #[must_use]
    pub const fn fidelity(&self) -> OutputFidelityV1 { self.fidelity }
    /// Declared per-output ceiling.
    #[must_use]
    pub const fn max_bytes(&self) -> u32 { self.max_bytes }
    /// Stride for L1, absent otherwise.
    #[must_use]
    pub const fn stride_ticks(&self) -> Option<u32> { self.stride_ticks }
    /// Minimum group for L2, absent otherwise.
    #[must_use]
    pub const fn aggregate_min_group(&self) -> Option<u32> { self.aggregate_min_group }
}

/// Untrusted construction input. Hashes are references, not proof of trust,
/// retention, registered ownership or execution-profile support.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputPolicyInputV1 {
    /// Declared Plugin identity.
    pub plugin_id: PluginId,
    /// Exact declared Plugin version.
    pub plugin_version: String,
    /// Referenced implementation identity.
    pub implementation_hash: Hash,
    /// Original configuration identity, before policy binding.
    pub base_configuration_digest: Hash,
    /// Referenced executable budget policy identity.
    pub executable_profile_hash: Hash,
    /// Referenced retention policy identity.
    pub retention_policy_hash: Hash,
    /// Positive policy revision.
    pub policy_revision: u32,
    /// Declarations in strictly increasing UTF-8 Event-type order.
    pub output_declarations: Vec<OutputDeclarationV1>,
}

/// Immutable structural policy; decoding cannot mint a pinned runtime policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputPolicyV1(OutputPolicyInputV1);

impl OutputPolicyV1 {
    /// Validate structural construction input without sorting or defaulting it.
    ///
    /// # Errors
    /// Rejects invalid bounds, zero identity references and unsorted/duplicate kinds.
    pub fn new(input: OutputPolicyInputV1) -> Result<Self, OutputPolicyErrorV1> {
        if input.plugin_version.is_empty() || input.plugin_version.len() > 64
            || input.policy_revision == 0 || input.output_declarations.len() > MAX_OUTPUT_DECLARATIONS_V1
            || [input.implementation_hash, input.base_configuration_digest,
                input.executable_profile_hash, input.retention_policy_hash].contains(&Hash::zero())
        {
            return Err(OutputPolicyErrorV1::FieldOutOfBounds);
        }
        if input.output_declarations.windows(2).any(|pair| pair[0].event_type >= pair[1].event_type) {
            return Err(OutputPolicyErrorV1::NonCanonical);
        }
        Ok(Self(input))
    }

    /// Immutable validated fields. No mutable reference is exposed.
    #[must_use]
    pub const fn fields(&self) -> &OutputPolicyInputV1 { &self.0 }

    /// Exact deterministic EOP1 representation, without an allocation-time decoder.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let mut out = vec![0x8a, 0x44, b'E', b'O', b'P', b'1', 1, 0x50];
        out.extend_from_slice(&self.0.plugin_id.inner().to_bytes());
        encode_text(&mut out, &self.0.plugin_version);
        for hash in [self.0.implementation_hash, self.0.base_configuration_digest,
            self.0.executable_profile_hash, self.0.retention_policy_hash] {
            out.extend_from_slice(&[0x58, 32]);
            out.extend_from_slice(hash.as_bytes());
        }
        encode_uint(&mut out, self.0.policy_revision);
        let count = self.0.output_declarations.len();
        match count {
            0..=23 => out.push(0x80 | count.to_le_bytes()[0]),
            24..=255 => out.extend_from_slice(&[0x98, count.to_le_bytes()[0]]),
            _ => out.extend_from_slice(&[0x99, 1, 0]),
        }
        for declaration in &self.0.output_declarations {
            out.push(0x86);
            encode_text(&mut out, &declaration.event_type);
            out.push(match declaration.authority {
                OutputAuthorityV1::Authoritative => 0,
                OutputAuthorityV1::ReproducibleDerived => 1,
                OutputAuthorityV1::Ephemeral => 2,
            });
            out.push(match declaration.fidelity {
                OutputFidelityV1::L0 => 0,
                OutputFidelityV1::L1 => 1,
                OutputFidelityV1::L2 => 2,
            });
            encode_uint(&mut out, declaration.max_bytes);
            for optional in [declaration.stride_ticks, declaration.aggregate_min_group] {
                if let Some(value) = optional { encode_uint(&mut out, value); }
                else { out.push(0xf6); }
            }
        }
        out
    }

    /// Ordinary BLAKE3 of the fixed ASCII domain, zero separator and EOP1 bytes.
    #[must_use]
    pub fn digest(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"pigloros.output-policy.v1\0");
        hasher.update(&self.to_canonical_cbor());
        Hash::from_bytes(*hasher.finalize().as_bytes())
    }

    /// Decode only the bounded, definite EOP1 shape. Length/type checks happen
    /// before allocating strings or declaration arrays.
    ///
    /// # Errors
    /// Rejects malformed, oversized, unsupported, incompatible or noncanonical input.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, OutputPolicyErrorV1> {
        if bytes.len() > MAX_OUTPUT_POLICY_BYTES_V1 { return Err(OutputPolicyErrorV1::FieldOutOfBounds); }
        let mut reader = Reader { bytes, offset: 0 };
        reader.exact_array(10)?;
        if reader.blob::<4>()? != *b"EOP1" { return Err(OutputPolicyErrorV1::InvalidEncoding); }
        if reader.head(0, u32::MAX)? != 1 { return Err(OutputPolicyErrorV1::UnsupportedValue); }
        let plugin_id = PluginId::from_ulid(ulid::Ulid::from(u128::from_be_bytes(reader.blob::<16>()?)));
        let plugin_version = reader.text(64)?;
        let implementation_hash = Hash::from_bytes(reader.blob()?);
        let base_configuration_digest = Hash::from_bytes(reader.blob()?);
        let executable_profile_hash = Hash::from_bytes(reader.blob()?);
        let retention_policy_hash = Hash::from_bytes(reader.blob()?);
        let policy_revision = reader.head(0, u32::MAX)?;
        let count = reader.head(4, 256)?;
        let mut output_declarations = Vec::new();
        for _ in 0..count { output_declarations.push(reader.declaration()?); }
        let policy = Self::new(OutputPolicyInputV1 { plugin_id, plugin_version, implementation_hash,
            base_configuration_digest, executable_profile_hash, retention_policy_hash,
            policy_revision, output_declarations })?;
        if policy.to_canonical_cbor() != bytes { return Err(OutputPolicyErrorV1::NonCanonical); }
        Ok(policy)
    }
}

fn encode_text(out: &mut Vec<u8>, text: &str) {
    let length = text.len().to_le_bytes()[0];
    if length <= 23 { out.push(0x60 | length); }
    else { out.extend_from_slice(&[0x78, length]); }
    out.extend_from_slice(text.as_bytes());
}

fn encode_uint(out: &mut Vec<u8>, value: u32) {
    let bytes = value.to_be_bytes();
    match value {
        0..=23 => out.push(bytes[3]),
        24..=255 => out.extend_from_slice(&[0x18, bytes[3]]),
        256..=65_535 => { out.push(0x19); out.extend_from_slice(&bytes[2..]); }
        _ => { out.push(0x1a); out.extend_from_slice(&bytes); }
    }
}

struct Reader<'a> { bytes: &'a [u8], offset: usize }

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], OutputPolicyErrorV1> {
        let end = self.offset + length;
        self.bytes.get(self.offset..end).ok_or(OutputPolicyErrorV1::InvalidEncoding)
            .inspect(|_| self.offset = end)
    }

    fn head(&mut self, major: u8, maximum: u32) -> Result<u32, OutputPolicyErrorV1> {
        let initial = self.take(1)?[0];
        if initial >> 5 != major { return Err(OutputPolicyErrorV1::InvalidEncoding); }
        let argument = initial & 31;
        let (value, minimum) = match argument {
            0..=23 => (u64::from(argument), 0),
            24..=27 => {
                let length = 1usize << (argument - 24);
                let data = self.take(length)?;
                let value = data.iter().fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte));
                let minimum = match length { 1 => 24, 2 => 256, 4 => 65_536, _ => 4_294_967_296 };
                (value, minimum)
            }
            _ => return Err(OutputPolicyErrorV1::InvalidEncoding),
        };
        if value < minimum { return Err(OutputPolicyErrorV1::NonCanonical); }
        u32::try_from(value).map_err(|_| OutputPolicyErrorV1::FieldOutOfBounds)
            .and_then(|value| if value <= maximum { Ok(value) } else { Err(OutputPolicyErrorV1::FieldOutOfBounds) })
    }

    fn exact_array(&mut self, count: u32) -> Result<(), OutputPolicyErrorV1> {
        self.head(4, u32::MAX).and_then(|actual| if actual == count { Ok(()) }
            else { Err(OutputPolicyErrorV1::InvalidEncoding) })
    }

    fn blob<const N: usize>(&mut self) -> Result<[u8; N], OutputPolicyErrorV1> {
        let length = self.head(2, 32)?;
        let data = self.take(usize::try_from(length).map_err(|_| OutputPolicyErrorV1::FieldOutOfBounds)?)?;
        data.try_into().map_err(|_| OutputPolicyErrorV1::InvalidEncoding)
    }

    fn text(&mut self, maximum: u32) -> Result<String, OutputPolicyErrorV1> {
        let length = self.head(3, maximum)?;
        let data = self.take(usize::try_from(length).map_err(|_| OutputPolicyErrorV1::FieldOutOfBounds)?)?;
        std::str::from_utf8(data).map(str::to_owned).map_err(|_| OutputPolicyErrorV1::InvalidEncoding)
    }

    fn optional_uint(&mut self) -> Result<Option<u32>, OutputPolicyErrorV1> {
        if self.bytes.get(self.offset) == Some(&0xf6) { self.offset += 1; Ok(None) }
        else { self.head(0, u32::MAX).map(Some) }
    }

    fn declaration(&mut self) -> Result<OutputDeclarationV1, OutputPolicyErrorV1> {
        self.exact_array(6)?;
        let event_type = self.text(128)?;
        let authority = match self.head(0, u32::MAX)? {
            0 => OutputAuthorityV1::Authoritative, 1 => OutputAuthorityV1::ReproducibleDerived,
            2 => OutputAuthorityV1::Ephemeral, _ => return Err(OutputPolicyErrorV1::UnsupportedValue),
        };
        let fidelity = match self.head(0, u32::MAX)? {
            0 => OutputFidelityV1::L0, 1 => OutputFidelityV1::L1,
            2 => OutputFidelityV1::L2, _ => return Err(OutputPolicyErrorV1::UnsupportedValue),
        };
        OutputDeclarationV1::new(event_type, authority, fidelity, self.head(0, u32::MAX)?,
            self.optional_uint()?, self.optional_uint()?)
    }
}
