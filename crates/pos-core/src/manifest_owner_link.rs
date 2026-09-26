//! Portable ADR-088/089 owner-link records, without native admission authority.
//!
//! A matching digest or decoded receipt cannot establish that an actual owner
//! admitted, retained, or selected these bytes for a committed `WorldCut`.

use std::collections::HashSet;

use crate::{Hash, PluginId};

/// Maximum complete MCA1 admission-catalog bytes.
pub const MAX_MANIFEST_ADMISSION_CATALOG_BYTES_V1: usize = 131_072;
/// Maximum complete MSB1 slot-binding bytes.
pub const MAX_MANIFEST_SLOT_BINDING_BYTES_V1: usize = 65_536;
/// Maximum complete MSR1 admission-receipt bytes.
pub const MAX_MANIFEST_SLOT_ADMISSION_RECEIPT_BYTES_V1: usize = 16_384;
/// Maximum admitted Plugin rows in each complete catalog or binding.
pub const MAX_MANIFEST_OWNER_PLUGINS_V1: usize = 256;

/// Closed structural errors; none grants or denies native owner authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ManifestOwnerLinkErrorV1 {
    #[error("invalid manifest owner-link encoding")]
    InvalidEncoding,
    #[error("noncanonical manifest owner-link encoding")]
    NonCanonical,
    #[error("unsupported manifest owner-link version")]
    UnsupportedVersion,
    #[error("manifest owner-link field out of bounds")]
    FieldOutOfBounds,
    #[error("manifest owner-link rows are not strictly ordered")]
    InvalidRowOrder,
    #[error("duplicate manifest owner-link PluginId")]
    DuplicatePluginId,
    #[error("invalid manifest owner-link pre-state")]
    InvalidPreState,
}

/// One catalog row from the owner's complete admitted Plugin recipe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestAdmissionCatalogRowV1 {
    pub stable_slot: String,
    pub plugin_id: PluginId,
    pub plugin_name: String,
    pub plugin_version: String,
    pub implementation_hash: Hash,
    pub eop1_native_digest: Hash,
    pub closure_hash: Hash,
}

/// Untrusted MCA1 input; the actual owner must check it against its registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestAdmissionCatalogInputV1 {
    pub owner_id: [u8; 32],
    pub configuration_generation: u64,
    pub rows: Vec<ManifestAdmissionCatalogRowV1>,
}

/// Immutable structurally valid MCA1, not proof of complete admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestAdmissionCatalogV1(ManifestAdmissionCatalogInputV1);

impl ManifestAdmissionCatalogV1 {
    /// Validate the bounded, strictly ordered portable catalog.
    ///
    /// # Errors
    /// Rejects invalid slots, identities, metadata, order or cardinality.
    pub fn new(input: ManifestAdmissionCatalogInputV1) -> Result<Self, ManifestOwnerLinkErrorV1> {
        if input.configuration_generation == 0 || input.rows.len() > MAX_MANIFEST_OWNER_PLUGINS_V1 {
            return Err(ManifestOwnerLinkErrorV1::FieldOutOfBounds);
        }
        let mut ids = HashSet::with_capacity(input.rows.len());
        for row in &input.rows {
            if !valid_slot(&row.stable_slot)
                || row.plugin_name.is_empty()
                || row.plugin_name.len() > 128
                || row.plugin_version.is_empty()
                || row.plugin_version.len() > 64
                || row.implementation_hash == Hash::zero()
                || row.eop1_native_digest == Hash::zero()
                || row.closure_hash == Hash::zero()
            {
                return Err(ManifestOwnerLinkErrorV1::FieldOutOfBounds);
            }
            if !ids.insert(row.plugin_id) {
                return Err(ManifestOwnerLinkErrorV1::DuplicatePluginId);
            }
        }
        if input
            .rows
            .windows(2)
            .any(|pair| pair[0].stable_slot >= pair[1].stable_slot)
        {
            return Err(ManifestOwnerLinkErrorV1::InvalidRowOrder);
        }
        // The 256 bounded rows cannot reach the whole-input decode cap.
        Ok(Self(input))
    }

    #[must_use]
    pub const fn as_input(&self) -> &ManifestAdmissionCatalogInputV1 {
        &self.0
    }

    /// Encode exact preferred five-field MCA1 bytes.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_head(&mut out, 4, 5);
        encode_bytes(&mut out, b"MCA1");
        encode_head(&mut out, 0, 1);
        encode_bytes(&mut out, &self.0.owner_id);
        encode_head(&mut out, 0, self.0.configuration_generation);
        encode_head(&mut out, 4, self.0.rows.len() as u64);
        for row in &self.0.rows {
            encode_head(&mut out, 4, 7);
            encode_text(&mut out, &row.stable_slot);
            encode_bytes(&mut out, &row.plugin_id.inner().to_bytes());
            encode_text(&mut out, &row.plugin_name);
            encode_text(&mut out, &row.plugin_version);
            encode_bytes(&mut out, row.implementation_hash.as_bytes());
            encode_bytes(&mut out, row.eop1_native_digest.as_bytes());
            encode_bytes(&mut out, row.closure_hash.as_bytes());
        }
        out
    }

    /// Ordinary BLAKE3 over the approved domain, NUL and exact MCA1 bytes.
    #[must_use]
    pub fn digest(&self) -> Hash {
        domain_digest(
            b"pigloros.manifest-owner-admission-catalog.v1\0",
            &self.to_canonical_cbor(),
        )
    }

    /// Decode one complete bounded preferred MCA1 record.
    ///
    /// # Errors
    /// Rejects malformed, noncanonical, oversized or duplicate inputs.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ManifestOwnerLinkErrorV1> {
        let mut wire = preflight(bytes, MAX_MANIFEST_ADMISSION_CATALOG_BYTES_V1)?;
        wire.array(5)?;
        wire.fixed_bytes(4)
            .and_then(|magic| check_magic(magic, *b"MCA1"))?;
        wire.head(0).and_then(check_version)?;
        let owner_id = wire.bytes()?;
        let configuration_generation = wire.head(0)?;
        // Each fixed stack block stays below the 16 KiB local-array limit.
        let mut rows_0 = [None; 64];
        let mut rows_1 = [None; 64];
        let mut rows_2 = [None; 64];
        let mut rows_3 = [None; 64];
        for row in rows_0
            .iter_mut()
            .chain(rows_1.iter_mut())
            .chain(rows_2.iter_mut())
            .chain(rows_3.iter_mut())
            .take(wire.row_count()?)
        {
            wire.array(7)?;
            *row = Some(CatalogRowView {
                slot: wire.text(64)?,
                plugin_id: wire.bytes()?,
                name: wire.text(128)?,
                version: wire.text(64)?,
                implementation: wire.bytes()?,
                eop1: wire.bytes()?,
                closure: wire.bytes()?,
            });
        }
        wire.finish()?;
        let rows = rows_0
            .into_iter()
            .chain(rows_1)
            .chain(rows_2)
            .chain(rows_3)
            .flatten()
            .map(|row| ManifestAdmissionCatalogRowV1 {
                stable_slot: row.slot.to_owned(),
                plugin_id: PluginId::from_ulid(ulid::Ulid::from_bytes(row.plugin_id)),
                plugin_name: row.name.to_owned(),
                plugin_version: row.version.to_owned(),
                implementation_hash: Hash::from_bytes(row.implementation),
                eop1_native_digest: Hash::from_bytes(row.eop1),
                closure_hash: Hash::from_bytes(row.closure),
            })
            .collect();
        let record = Self::new(ManifestAdmissionCatalogInputV1 {
            owner_id,
            configuration_generation,
            rows,
        })?;
        check_canonical(bytes, &record.to_canonical_cbor())?;
        Ok(record)
    }
}

/// One scoped MSB1 slot-to-policy/closure binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestSlotBindingRowV1 {
    pub stable_slot: String,
    pub plugin_id: PluginId,
    pub eop1_wal1_hash: Hash,
    pub closure_hash: Hash,
}

/// Untrusted MSB1 input; matching MCA1 and WCS1 requires the real owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestSlotBindingInputV1 {
    pub scope: Hash,
    pub wcs1_hash: Hash,
    pub rows: Vec<ManifestSlotBindingRowV1>,
}

/// Immutable structurally valid MSB1; it cannot authenticate a cut by itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestSlotBindingV1(ManifestSlotBindingInputV1);

impl ManifestSlotBindingV1 {
    /// Validate one bounded slot-binding record.
    ///
    /// # Errors
    /// Rejects zero addresses, bad slots, duplicate IDs or row order.
    pub fn new(input: ManifestSlotBindingInputV1) -> Result<Self, ManifestOwnerLinkErrorV1> {
        if input.scope == Hash::zero()
            || input.wcs1_hash == Hash::zero()
            || input.rows.len() > MAX_MANIFEST_OWNER_PLUGINS_V1
            || input.rows.iter().any(|row| {
                !valid_slot(&row.stable_slot)
                    || row.eop1_wal1_hash == Hash::zero()
                    || row.closure_hash == Hash::zero()
            })
        {
            return Err(ManifestOwnerLinkErrorV1::FieldOutOfBounds);
        }
        if input
            .rows
            .windows(2)
            .any(|pair| pair[0].stable_slot >= pair[1].stable_slot)
        {
            return Err(ManifestOwnerLinkErrorV1::InvalidRowOrder);
        }
        let mut ids = HashSet::with_capacity(input.rows.len());
        if input.rows.iter().any(|row| !ids.insert(row.plugin_id)) {
            return Err(ManifestOwnerLinkErrorV1::DuplicatePluginId);
        }
        // The 256 bounded rows cannot reach the whole-input decode cap.
        Ok(Self(input))
    }

    #[must_use]
    pub const fn as_input(&self) -> &ManifestSlotBindingInputV1 {
        &self.0
    }

    /// Encode exact preferred five-field MSB1 bytes.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let mut out = Vec::new();
        encode_head(&mut out, 4, 5);
        encode_bytes(&mut out, b"MSB1");
        encode_head(&mut out, 0, 1);
        encode_bytes(&mut out, self.0.scope.as_bytes());
        encode_bytes(&mut out, self.0.wcs1_hash.as_bytes());
        encode_head(&mut out, 4, self.0.rows.len() as u64);
        for row in &self.0.rows {
            encode_head(&mut out, 4, 4);
            encode_text(&mut out, &row.stable_slot);
            encode_bytes(&mut out, &row.plugin_id.inner().to_bytes());
            encode_bytes(&mut out, row.eop1_wal1_hash.as_bytes());
            encode_bytes(&mut out, row.closure_hash.as_bytes());
        }
        out
    }

    /// Ordinary BLAKE3 over the approved domain, NUL and exact MSB1 bytes.
    #[must_use]
    pub fn digest(&self) -> Hash {
        domain_digest(
            b"pigloros.manifest-slot-binding.v1\0",
            &self.to_canonical_cbor(),
        )
    }

    /// Decode one complete bounded preferred MSB1 record.
    ///
    /// # Errors
    /// Rejects malformed, noncanonical, oversized or duplicate inputs.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ManifestOwnerLinkErrorV1> {
        let mut wire = preflight(bytes, MAX_MANIFEST_SLOT_BINDING_BYTES_V1)?;
        wire.array(5)?;
        wire.fixed_bytes(4)
            .and_then(|magic| check_magic(magic, *b"MSB1"))?;
        wire.head(0).and_then(check_version)?;
        let scope = Hash::from_bytes(wire.bytes()?);
        let wcs1_hash = Hash::from_bytes(wire.bytes()?);
        let mut rows_0 = [None; 128];
        let mut rows_1 = [None; 128];
        for row in rows_0
            .iter_mut()
            .chain(rows_1.iter_mut())
            .take(wire.row_count()?)
        {
            wire.array(4)?;
            *row = Some(BindingRowView {
                slot: wire.text(64)?,
                plugin_id: wire.bytes()?,
                eop1: wire.bytes()?,
                closure: wire.bytes()?,
            });
        }
        wire.finish()?;
        let rows = rows_0
            .into_iter()
            .chain(rows_1)
            .flatten()
            .map(|row| ManifestSlotBindingRowV1 {
                stable_slot: row.slot.to_owned(),
                plugin_id: PluginId::from_ulid(ulid::Ulid::from_bytes(row.plugin_id)),
                eop1_wal1_hash: Hash::from_bytes(row.eop1),
                closure_hash: Hash::from_bytes(row.closure),
            })
            .collect();
        let record = Self::new(ManifestSlotBindingInputV1 {
            scope,
            wcs1_hash,
            rows,
        })?;
        check_canonical(bytes, &record.to_canonical_cbor())?;
        Ok(record)
    }
}

/// Untrusted signed MSR1 fields; only the actual owner can authenticate them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestSlotAdmissionReceiptInputV1 {
    pub owner_id: [u8; 32],
    pub configuration_generation: u64,
    pub scope: Hash,
    pub wcs1_hash: Hash,
    pub mca1_hash: Hash,
    pub admission_operation_id: Hash,
    pub previous_visible_lcq1_hash: Option<Hash>,
    pub expected_inventory_generation: Option<Hash>,
    pub msb1_hash: Hash,
    pub coordinator_key_evidence_hash: Hash,
    pub signature: [u8; 64],
}

/// Immutable structurally valid MSR1, not a verified owner receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestSlotAdmissionReceiptV1(ManifestSlotAdmissionReceiptInputV1);

impl ManifestSlotAdmissionReceiptV1 {
    /// Check the portable receipt shape, not its actual owner pre-state or key.
    ///
    /// # Errors
    /// Rejects zero addresses, generation zero and the impossible `(some, null)` pair.
    pub fn new(
        input: ManifestSlotAdmissionReceiptInputV1,
    ) -> Result<Self, ManifestOwnerLinkErrorV1> {
        if input.configuration_generation == 0
            || input.scope == Hash::zero()
            || input.wcs1_hash == Hash::zero()
            || input.mca1_hash == Hash::zero()
            || input.admission_operation_id == Hash::zero()
            || input.msb1_hash == Hash::zero()
            || input.coordinator_key_evidence_hash == Hash::zero()
            || input
                .previous_visible_lcq1_hash
                .is_some_and(|hash| hash == Hash::zero())
            || input
                .expected_inventory_generation
                .is_some_and(|hash| hash == Hash::zero())
        {
            return Err(ManifestOwnerLinkErrorV1::FieldOutOfBounds);
        }
        if input.previous_visible_lcq1_hash.is_some()
            && input.expected_inventory_generation.is_none()
        {
            return Err(ManifestOwnerLinkErrorV1::InvalidPreState);
        }
        // The fixed-width record is far below the whole-input decode cap.
        Ok(Self(input))
    }

    #[must_use]
    pub const fn as_input(&self) -> &ManifestSlotAdmissionReceiptInputV1 {
        &self.0
    }

    fn write_fields(&self, out: &mut Vec<u8>, field_count: u64) {
        encode_head(out, 4, field_count);
        encode_bytes(out, b"MSR1");
        encode_head(out, 0, 1);
        encode_bytes(out, &self.0.owner_id);
        encode_head(out, 0, self.0.configuration_generation);
        encode_bytes(out, self.0.scope.as_bytes());
        encode_bytes(out, self.0.wcs1_hash.as_bytes());
        encode_bytes(out, self.0.mca1_hash.as_bytes());
        encode_bytes(out, self.0.admission_operation_id.as_bytes());
        encode_optional_hash(out, self.0.previous_visible_lcq1_hash);
        encode_optional_hash(out, self.0.expected_inventory_generation);
        encode_bytes(out, self.0.msb1_hash.as_bytes());
        encode_bytes(out, self.0.coordinator_key_evidence_hash.as_bytes());
    }

    /// Encode exact preferred thirteen-field MSR1 bytes.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write_fields(&mut out, 13);
        encode_bytes(&mut out, &self.0.signature);
        out
    }

    /// Exact domain/NUL and twelve-field CBOR message for the owner signer.
    ///
    /// A signature over this message still requires installed key-role and
    /// native owner-operation verification before any protected use.
    #[must_use]
    pub fn signature_preimage(&self) -> Vec<u8> {
        let mut out = b"pigloros.manifest-slot-admission-signature.v1\0".to_vec();
        self.write_fields(&mut out, 12);
        out
    }

    /// Ordinary BLAKE3 over the approved domain, NUL and exact MSR1 bytes.
    #[must_use]
    pub fn digest(&self) -> Hash {
        domain_digest(
            b"pigloros.manifest-slot-admission.v1\0",
            &self.to_canonical_cbor(),
        )
    }

    /// Decode one bounded, preferred thirteen-field MSR1 record.
    ///
    /// # Errors
    /// Rejects malformed, noncanonical, oversized or impossible nullable inputs.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ManifestOwnerLinkErrorV1> {
        let mut wire = preflight(bytes, MAX_MANIFEST_SLOT_ADMISSION_RECEIPT_BYTES_V1)?;
        wire.array(13)?;
        wire.fixed_bytes(4)
            .and_then(|magic| check_magic(magic, *b"MSR1"))?;
        wire.head(0).and_then(check_version)?;
        let input = ManifestSlotAdmissionReceiptInputV1 {
            owner_id: wire.bytes()?,
            configuration_generation: wire.head(0)?,
            scope: Hash::from_bytes(wire.bytes()?),
            wcs1_hash: Hash::from_bytes(wire.bytes()?),
            mca1_hash: Hash::from_bytes(wire.bytes()?),
            admission_operation_id: Hash::from_bytes(wire.bytes()?),
            previous_visible_lcq1_hash: wire.optional_hash()?,
            expected_inventory_generation: wire.optional_hash()?,
            msb1_hash: Hash::from_bytes(wire.bytes()?),
            coordinator_key_evidence_hash: Hash::from_bytes(wire.bytes()?),
            signature: wire.bytes()?,
        };
        wire.finish()?;
        let record = Self::new(input)?;
        check_canonical(bytes, &record.to_canonical_cbor())?;
        Ok(record)
    }
}

fn valid_slot(slot: &str) -> bool {
    (1..=64).contains(&slot.len())
        && slot
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn domain_digest(domain_with_nul: &[u8], bytes: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain_with_nul);
    hasher.update(bytes);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn encode_head(out: &mut Vec<u8>, major: u8, value: u64) {
    let bytes = value.to_be_bytes();
    let tag = major << 5;
    match value {
        0..=23 => out.push(tag | bytes[7]),
        24..=255 => out.extend_from_slice(&[tag | 0x18, bytes[7]]),
        256..=65_535 => {
            out.push(tag | 0x19);
            out.extend_from_slice(&bytes[6..]);
        }
        65_536..=4_294_967_295 => {
            out.push(tag | 0x1a);
            out.extend_from_slice(&bytes[4..]);
        }
        _ => {
            out.push(tag | 0x1b);
            out.extend_from_slice(&bytes);
        }
    }
}

fn encode_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    encode_head(out, 2, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn encode_text(out: &mut Vec<u8>, text: &str) {
    encode_head(out, 3, text.len() as u64);
    out.extend_from_slice(text.as_bytes());
}

fn encode_optional_hash(out: &mut Vec<u8>, value: Option<Hash>) {
    if let Some(hash) = value {
        encode_bytes(out, hash.as_bytes());
    } else {
        out.push(0xf6);
    }
}

#[derive(Clone, Copy)]
struct CatalogRowView<'a> {
    slot: &'a str,
    plugin_id: [u8; 16],
    name: &'a str,
    version: &'a str,
    implementation: [u8; 32],
    eop1: [u8; 32],
    closure: [u8; 32],
}

#[derive(Clone, Copy)]
struct BindingRowView<'a> {
    slot: &'a str,
    plugin_id: [u8; 16],
    eop1: [u8; 32],
    closure: [u8; 32],
}

// Borrow and validate the closed wire shape without heap allocation. Catalog
// and binding rows stay in fixed stack arrays until every field has passed.
struct WirePreflight<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> WirePreflight<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn byte(&mut self) -> Result<u8, ManifestOwnerLinkErrorV1> {
        let byte = self
            .bytes
            .get(self.offset)
            .copied()
            .ok_or(ManifestOwnerLinkErrorV1::InvalidEncoding)?;
        self.offset += 1;
        Ok(byte)
    }

    fn head(&mut self, major: u8) -> Result<u64, ManifestOwnerLinkErrorV1> {
        let first = self.byte()?;
        if first >> 5 != major {
            return Err(ManifestOwnerLinkErrorV1::InvalidEncoding);
        }
        let additional = first & 0x1f;
        if additional < 24 {
            return Ok(u64::from(additional));
        }
        let width = match additional {
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            _ => return Err(ManifestOwnerLinkErrorV1::InvalidEncoding),
        };
        let mut value = 0_u64;
        for _ in 0..width {
            value = (value << 8) | u64::from(self.byte()?);
        }
        Ok(value)
    }

    fn array(&mut self, expected: u64) -> Result<(), ManifestOwnerLinkErrorV1> {
        if self.head(4)? == expected {
            Ok(())
        } else {
            Err(ManifestOwnerLinkErrorV1::InvalidEncoding)
        }
    }

    fn row_count(&mut self) -> Result<usize, ManifestOwnerLinkErrorV1> {
        let count = usize::try_from(self.head(4)?)
            .map_err(|_| ManifestOwnerLinkErrorV1::FieldOutOfBounds)?;
        if count > MAX_MANIFEST_OWNER_PLUGINS_V1 {
            Err(ManifestOwnerLinkErrorV1::FieldOutOfBounds)
        } else {
            Ok(count)
        }
    }

    fn slice(&mut self, length: u64) -> Result<&'a [u8], ManifestOwnerLinkErrorV1> {
        let length =
            usize::try_from(length).map_err(|_| ManifestOwnerLinkErrorV1::FieldOutOfBounds)?;
        if length > self.bytes.len() - self.offset {
            return Err(ManifestOwnerLinkErrorV1::InvalidEncoding);
        }
        let start = self.offset;
        self.offset += length;
        Ok(&self.bytes[start..self.offset])
    }

    fn fixed_bytes(&mut self, expected: u64) -> Result<&'a [u8], ManifestOwnerLinkErrorV1> {
        let length = self.head(2)?;
        if length != expected {
            return Err(ManifestOwnerLinkErrorV1::InvalidEncoding);
        }
        self.slice(length)
    }

    fn bytes<const N: usize>(&mut self) -> Result<[u8; N], ManifestOwnerLinkErrorV1> {
        let mut bytes = [0; N];
        bytes.copy_from_slice(self.fixed_bytes(N as u64)?);
        Ok(bytes)
    }

    fn text(&mut self, maximum: u64) -> Result<&'a str, ManifestOwnerLinkErrorV1> {
        let length = self.head(3)?;
        if length == 0 || length > maximum {
            return Err(ManifestOwnerLinkErrorV1::FieldOutOfBounds);
        }
        self.slice(length).and_then(|bytes| {
            std::str::from_utf8(bytes).map_err(|_| ManifestOwnerLinkErrorV1::InvalidEncoding)
        })
    }

    fn optional_hash(&mut self) -> Result<Option<Hash>, ManifestOwnerLinkErrorV1> {
        if self.bytes.get(self.offset) == Some(&0xf6) {
            self.offset += 1;
            Ok(None)
        } else {
            self.bytes().map(Hash::from_bytes).map(Some)
        }
    }

    const fn finish(&self) -> Result<(), ManifestOwnerLinkErrorV1> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(ManifestOwnerLinkErrorV1::InvalidEncoding)
        }
    }
}

const fn preflight(
    bytes: &[u8],
    maximum: usize,
) -> Result<WirePreflight<'_>, ManifestOwnerLinkErrorV1> {
    if bytes.len() > maximum {
        return Err(ManifestOwnerLinkErrorV1::FieldOutOfBounds);
    }
    Ok(WirePreflight::new(bytes))
}

fn check_magic(value: &[u8], expected: [u8; 4]) -> Result<(), ManifestOwnerLinkErrorV1> {
    if value == expected {
        Ok(())
    } else {
        Err(ManifestOwnerLinkErrorV1::InvalidEncoding)
    }
}

const fn check_version(value: u64) -> Result<(), ManifestOwnerLinkErrorV1> {
    if value == 1 {
        Ok(())
    } else {
        Err(ManifestOwnerLinkErrorV1::UnsupportedVersion)
    }
}

fn check_canonical(bytes: &[u8], canonical: &[u8]) -> Result<(), ManifestOwnerLinkErrorV1> {
    if bytes == canonical {
        Ok(())
    } else {
        Err(ManifestOwnerLinkErrorV1::NonCanonical)
    }
}
