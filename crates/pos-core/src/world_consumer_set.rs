//! Immutable structural WCS1 consumer and producer selectors.
//!
//! This module records an explicit selector only. It does not establish that a
//! producer roster is authenticated, that referenced native records are exact,
//! or that any requested read is authorized.

use crate::{CanonicalBytes, Hash, PluginId};
use std::fmt;
use ulid::Ulid;

/// Maximum size of one encoded WCS1 record.
pub const WORLD_CONSUMER_SET_MAX_BYTES: usize = 65_536;
/// Maximum number of consumer rows in WCS1.
pub const WORLD_CONSUMER_SET_MAX_CONSUMERS: usize = 64;
/// Maximum number of producer rows or optional view roots in WCS1.
pub const WORLD_CONSUMER_SET_MAX_PRODUCERS_OR_VIEWS: usize = 256;
/// Maximum UTF-8 byte length of a consumer identifier.
pub const WORLD_CONSUMER_SET_MAX_CONSUMER_ID_BYTES: usize = 128;

const MAGIC: &[u8; 4] = b"WCS1";
const VERSION: u8 = 1;
const DOMAIN: &[u8] = b"pigloros.world-evidence.consumer-set.v1\0";

/// Closed errors returned by the structural WCS1 codec.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorldConsumerSetErrorV1 {
    /// The CBOR item is malformed or has a field with the wrong type or width.
    InvalidEncoding,
    /// The record does not carry the WCS1 magic byte string.
    WrongMagic,
    /// The record has an unsupported version.
    WrongVersion,
    /// A bounded cardinality or text length is outside the WCS1 contract.
    FieldOutOfBounds,
    /// A scope or content address is all zeroes.
    ZeroContentAddress,
    /// A sequence is not strictly sorted by its required raw-byte key.
    NonCanonicalOrder,
    /// The input is valid CBOR but not its unique preferred WCS1 encoding.
    NonCanonicalEncoding,
}

impl fmt::Display for WorldConsumerSetErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidEncoding => "invalid WCS1 encoding",
            Self::WrongMagic => "wrong WCS1 magic",
            Self::WrongVersion => "wrong WCS1 version",
            Self::FieldOutOfBounds => "WCS1 field is out of bounds",
            Self::ZeroContentAddress => "WCS1 content address is zero",
            Self::NonCanonicalOrder => "WCS1 rows are not in canonical order",
            Self::NonCanonicalEncoding => "WCS1 encoding is not preferred",
        })
    }
}

impl std::error::Error for WorldConsumerSetErrorV1 {}

/// One immutable WCS1 consumer row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorldConsumerV1 {
    consumer_id: String,
    reducer_hash: Hash,
    schema_hash: Hash,
    runtime_hash: Hash,
}

impl WorldConsumerV1 {
    /// Construct one row. Set-level construction validates ordering.
    ///
    /// # Errors
    /// Returns a closed error when an identifier is outside its byte bound or
    /// one of the three content addresses is zero.
    pub fn new(
        consumer_id: String,
        reducer_hash: Hash,
        schema_hash: Hash,
        runtime_hash: Hash,
    ) -> Result<Self, WorldConsumerSetErrorV1> {
        validate_consumer_id(&consumer_id).and_then(|()| {
            validate_address(reducer_hash).and_then(|()| {
                validate_address(schema_hash).and_then(|()| {
                    validate_address(runtime_hash).map(|()| Self {
                        consumer_id,
                        reducer_hash,
                        schema_hash,
                        runtime_hash,
                    })
                })
            })
        })
    }

    /// Return the UTF-8 consumer identifier.
    #[must_use]
    pub fn consumer_id(&self) -> &str {
        &self.consumer_id
    }
    /// Return the reducer leaf address.
    #[must_use]
    pub const fn reducer_hash(&self) -> Hash {
        self.reducer_hash
    }
    /// Return the schema leaf address.
    #[must_use]
    pub const fn schema_hash(&self) -> Hash {
        self.schema_hash
    }
    /// Return the runtime leaf address.
    #[must_use]
    pub const fn runtime_hash(&self) -> Hash {
        self.runtime_hash
    }
}

/// One immutable WCS1 producer row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorldProducerV1 {
    plugin_id: PluginId,
    output_policy_hash: Hash,
}

impl WorldProducerV1 {
    /// Construct one producer row. A zero opaque `PluginId` is permitted.
    ///
    /// # Errors
    /// Returns a closed error when the EOP1 content address is zero.
    pub fn new(
        plugin_id: PluginId,
        output_policy_hash: Hash,
    ) -> Result<Self, WorldConsumerSetErrorV1> {
        validate_address(output_policy_hash).map(|()| Self {
            plugin_id,
            output_policy_hash,
        })
    }

    /// Return the opaque producer plugin identifier.
    #[must_use]
    pub const fn plugin_id(&self) -> PluginId {
        self.plugin_id
    }
    /// Return the EOP1 leaf address.
    #[must_use]
    pub const fn output_policy_hash(&self) -> Hash {
        self.output_policy_hash
    }
}

/// Unvalidated fields supplied to construct an immutable WCS1 selector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorldConsumerSetInputV1 {
    pub scope: Hash,
    pub consumers: Vec<WorldConsumerV1>,
    pub producers: Vec<WorldProducerV1>,
    pub optional_view_roots: Vec<Hash>,
}

/// Immutable validated WCS1 selector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorldConsumerSetV1 {
    scope: Hash,
    consumers: Vec<WorldConsumerV1>,
    producers: Vec<WorldProducerV1>,
    optional_view_roots: Vec<Hash>,
}

impl WorldConsumerSetV1 {
    /// Validate and retain one structural WCS1 selector.
    ///
    /// # Errors
    /// Returns a closed error when a scope/content address, cardinality, or
    /// required raw-byte ordering is outside the WCS1 contract.
    pub fn new(input: WorldConsumerSetInputV1) -> Result<Self, WorldConsumerSetErrorV1> {
        validate_address(input.scope).and_then(|()| {
            validate_consumers(&input.consumers).and_then(|()| {
                validate_producers(&input.producers).and_then(|()| {
                    validate_views(&input.optional_view_roots).map(|()| Self {
                        scope: input.scope,
                        consumers: input.consumers,
                        producers: input.producers,
                        optional_view_roots: input.optional_view_roots,
                    })
                })
            })
        })
    }

    /// Encode the unique preferred WCS1 CBOR representation.
    pub fn encode(&self) -> CanonicalBytes {
        let mut bytes = Vec::with_capacity(WORLD_CONSUMER_SET_MAX_BYTES.min(256));
        array(&mut bytes, 6);
        bytes_value(&mut bytes, MAGIC);
        unsigned(&mut bytes, u64::from(VERSION));
        bytes_value(&mut bytes, self.scope.as_bytes());
        array(&mut bytes, self.consumers.len());
        for consumer in &self.consumers {
            array(&mut bytes, 4);
            text_value(&mut bytes, &consumer.consumer_id);
            bytes_value(&mut bytes, consumer.reducer_hash.as_bytes());
            bytes_value(&mut bytes, consumer.schema_hash.as_bytes());
            bytes_value(&mut bytes, consumer.runtime_hash.as_bytes());
        }
        array(&mut bytes, self.producers.len());
        for producer in &self.producers {
            array(&mut bytes, 2);
            bytes_value(&mut bytes, &plugin_id_bytes(producer.plugin_id));
            bytes_value(&mut bytes, producer.output_policy_hash.as_bytes());
        }
        array(&mut bytes, self.optional_view_roots.len());
        for root in &self.optional_view_roots {
            bytes_value(&mut bytes, root.as_bytes());
        }
        CanonicalBytes::from_vec(bytes)
    }

    /// Decode and validate only the preferred complete WCS1 CBOR representation.
    ///
    /// # Errors
    /// Returns a closed error for malformed, non-preferred, out-of-bounds, or
    /// semantically invalid WCS1 bytes.
    pub fn decode(bytes: &CanonicalBytes) -> Result<Self, WorldConsumerSetErrorV1> {
        if bytes.len() > WORLD_CONSUMER_SET_MAX_BYTES {
            return Err(WorldConsumerSetErrorV1::FieldOutOfBounds);
        }
        let mut parser = Parser::new(bytes.as_slice());
        parser.record().and_then(|input| {
            if !parser.finished() {
                return Err(WorldConsumerSetErrorV1::InvalidEncoding);
            }
            Self::new(input).and_then(|record| {
                if record.encode().as_slice() != bytes.as_slice() {
                    Err(WorldConsumerSetErrorV1::NonCanonicalEncoding)
                } else {
                    Ok(record)
                }
            })
        })
    }

    /// Return the domain-separated WCS1 content address.
    #[must_use]
    pub fn digest(&self) -> Hash {
        let encoded = self.encode();
        let mut hasher = blake3::Hasher::new();
        hasher.update(DOMAIN);
        hasher.update(encoded.as_slice());
        Hash::from_bytes(*hasher.finalize().as_bytes())
    }

    /// Return the scope address.
    #[must_use]
    pub const fn scope(&self) -> Hash {
        self.scope
    }
    /// Return the ordered consumer rows.
    #[must_use]
    pub fn consumers(&self) -> &[WorldConsumerV1] {
        &self.consumers
    }
    /// Return the ordered producer rows.
    #[must_use]
    pub fn producers(&self) -> &[WorldProducerV1] {
        &self.producers
    }
    /// Return the ordered optional-view root addresses.
    #[must_use]
    pub fn optional_view_roots(&self) -> &[Hash] {
        &self.optional_view_roots
    }
}

fn validate_address(address: Hash) -> Result<(), WorldConsumerSetErrorV1> {
    if address == Hash::zero() {
        Err(WorldConsumerSetErrorV1::ZeroContentAddress)
    } else {
        Ok(())
    }
}

fn validate_consumer_id(id: &str) -> Result<(), WorldConsumerSetErrorV1> {
    if id.is_empty() || id.len() > WORLD_CONSUMER_SET_MAX_CONSUMER_ID_BYTES {
        Err(WorldConsumerSetErrorV1::FieldOutOfBounds)
    } else {
        Ok(())
    }
}

fn validate_consumers(consumers: &[WorldConsumerV1]) -> Result<(), WorldConsumerSetErrorV1> {
    if consumers.is_empty() || consumers.len() > WORLD_CONSUMER_SET_MAX_CONSUMERS {
        return Err(WorldConsumerSetErrorV1::FieldOutOfBounds);
    }
    for pair in consumers.windows(2) {
        if pair[0].consumer_id.as_bytes() >= pair[1].consumer_id.as_bytes() {
            return Err(WorldConsumerSetErrorV1::NonCanonicalOrder);
        }
    }
    Ok(())
}

fn validate_producers(producers: &[WorldProducerV1]) -> Result<(), WorldConsumerSetErrorV1> {
    if producers.is_empty() || producers.len() > WORLD_CONSUMER_SET_MAX_PRODUCERS_OR_VIEWS {
        return Err(WorldConsumerSetErrorV1::FieldOutOfBounds);
    }
    for pair in producers.windows(2) {
        if plugin_id_bytes(pair[0].plugin_id) >= plugin_id_bytes(pair[1].plugin_id) {
            return Err(WorldConsumerSetErrorV1::NonCanonicalOrder);
        }
    }
    Ok(())
}

fn validate_views(roots: &[Hash]) -> Result<(), WorldConsumerSetErrorV1> {
    if roots.len() > WORLD_CONSUMER_SET_MAX_PRODUCERS_OR_VIEWS {
        return Err(WorldConsumerSetErrorV1::FieldOutOfBounds);
    }
    for root in roots {
        if let Err(error) = validate_address(*root) {
            return Err(error);
        }
    }
    for pair in roots.windows(2) {
        if pair[0].as_bytes() >= pair[1].as_bytes() {
            return Err(WorldConsumerSetErrorV1::NonCanonicalOrder);
        }
    }
    Ok(())
}

fn plugin_id_bytes(id: PluginId) -> [u8; 16] {
    u128::from(id.inner()).to_be_bytes()
}

fn plugin_id_from_bytes(bytes: [u8; 16]) -> PluginId {
    PluginId::from_ulid(Ulid::from(u128::from_be_bytes(bytes)))
}

fn array(bytes: &mut Vec<u8>, length: usize) {
    major(bytes, 4, length as u64);
}

fn bytes_value(bytes: &mut Vec<u8>, value: &[u8]) {
    major(bytes, 2, value.len() as u64);
    bytes.extend_from_slice(value);
}

fn text_value(bytes: &mut Vec<u8>, value: &str) {
    major(bytes, 3, value.len() as u64);
    bytes.extend_from_slice(value.as_bytes());
}

fn unsigned(bytes: &mut Vec<u8>, value: u64) {
    major(bytes, 0, value);
}

fn major(bytes: &mut Vec<u8>, kind: u8, value: u64) {
    let prefix = kind << 5;
    let encoded = value.to_be_bytes();
    match value {
        0..=23 => bytes.push(prefix | encoded[7]),
        24..=0xff => bytes.extend_from_slice(&[prefix | 0x18, encoded[7]]),
        // Validated WCS1 values have a maximum cardinality of256; neither
        // four-byte nor eight-byte integer payloads can be emitted.
        _ => {
            bytes.push(prefix | 0x19);
            bytes.extend_from_slice(&encoded[6..]);
        }
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Parser<'a> {
    fn record(&mut self) -> Result<WorldConsumerSetInputV1, WorldConsumerSetErrorV1> {
        self.array_exact(6)
            .and_then(|()| self.magic())
            .and_then(|()| {
                self.unsigned().and_then(|version| {
                    if version != u64::from(VERSION) {
                        Err(WorldConsumerSetErrorV1::WrongVersion)
                    } else {
                        Ok(())
                    }
                })
            })
            .and_then(|()| self.hash())
            .and_then(|scope| {
                self.consumers().and_then(|consumers| {
                    self.producers().and_then(|producers| {
                        self.views()
                            .map(|optional_view_roots| WorldConsumerSetInputV1 {
                                scope: Hash::from_bytes(scope),
                                consumers,
                                producers,
                                optional_view_roots,
                            })
                    })
                })
            })
    }

    fn magic(&mut self) -> Result<(), WorldConsumerSetErrorV1> {
        self.bytes_exact(MAGIC).map_err(|error| match error {
            WorldConsumerSetErrorV1::InvalidEncoding => WorldConsumerSetErrorV1::WrongMagic,
            other => other,
        })
    }

    fn consumers(&mut self) -> Result<Vec<WorldConsumerV1>, WorldConsumerSetErrorV1> {
        self.array_bounded(1, WORLD_CONSUMER_SET_MAX_CONSUMERS)
            .and_then(|count| (0..count).map(|_| self.consumer()).collect())
    }

    fn consumer(&mut self) -> Result<WorldConsumerV1, WorldConsumerSetErrorV1> {
        self.array_exact(4)
            .and_then(|()| self.text_bounded(WORLD_CONSUMER_SET_MAX_CONSUMER_ID_BYTES))
            .and_then(|id| {
                self.hash().and_then(|reducer| {
                    self.hash().and_then(|schema| {
                        self.hash().and_then(|runtime| {
                            WorldConsumerV1::new(
                                id,
                                Hash::from_bytes(reducer),
                                Hash::from_bytes(schema),
                                Hash::from_bytes(runtime),
                            )
                        })
                    })
                })
            })
    }

    fn producers(&mut self) -> Result<Vec<WorldProducerV1>, WorldConsumerSetErrorV1> {
        self.array_bounded(1, WORLD_CONSUMER_SET_MAX_PRODUCERS_OR_VIEWS)
            .and_then(|count| (0..count).map(|_| self.producer()).collect())
    }

    fn producer(&mut self) -> Result<WorldProducerV1, WorldConsumerSetErrorV1> {
        self.array_exact(2)
            .and_then(|()| self.fixed::<16>(2, 16))
            .and_then(|plugin| {
                self.hash().and_then(|policy| {
                    WorldProducerV1::new(plugin_id_from_bytes(plugin), Hash::from_bytes(policy))
                })
            })
    }

    fn views(&mut self) -> Result<Vec<Hash>, WorldConsumerSetErrorV1> {
        self.array_bounded(0, WORLD_CONSUMER_SET_MAX_PRODUCERS_OR_VIEWS)
            .and_then(|count| {
                (0..count)
                    .map(|_| self.hash().map(Hash::from_bytes))
                    .collect()
            })
    }

    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    const fn finished(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn array_exact(&mut self, expected: usize) -> Result<(), WorldConsumerSetErrorV1> {
        match self.header(4) {
            Ok(length) if length == expected as u64 => Ok(()),
            Ok(_) => Err(WorldConsumerSetErrorV1::InvalidEncoding),
            Err(error) => Err(error),
        }
    }

    fn array_bounded(
        &mut self,
        minimum: usize,
        maximum: usize,
    ) -> Result<usize, WorldConsumerSetErrorV1> {
        match self.header(4) {
            Ok(length) => match usize::try_from(length) {
                Ok(length) if (minimum..=maximum).contains(&length) => Ok(length),
                _ => Err(WorldConsumerSetErrorV1::FieldOutOfBounds),
            },
            Err(error) => Err(error),
        }
    }

    fn unsigned(&mut self) -> Result<u64, WorldConsumerSetErrorV1> {
        self.header(0)
    }

    fn bytes_exact(&mut self, expected: &[u8]) -> Result<(), WorldConsumerSetErrorV1> {
        match self.fixed::<4>(2, expected.len()) {
            Ok(value) if value == expected => Ok(()),
            Ok(_) => Err(WorldConsumerSetErrorV1::InvalidEncoding),
            Err(error) => Err(error),
        }
    }

    fn hash(&mut self) -> Result<[u8; 32], WorldConsumerSetErrorV1> {
        self.fixed(2, 32)
    }

    fn fixed<const N: usize>(
        &mut self,
        kind: u8,
        expected: usize,
    ) -> Result<[u8; N], WorldConsumerSetErrorV1> {
        match self.header(kind) {
            Ok(length) if length == expected as u64 => match self.take(expected) {
                Ok(slice) => slice
                    .try_into()
                    .map_err(|_| WorldConsumerSetErrorV1::InvalidEncoding),
                Err(error) => Err(error),
            },
            Ok(_) => Err(WorldConsumerSetErrorV1::InvalidEncoding),
            Err(error) => Err(error),
        }
    }
    fn text_bounded(&mut self, maximum: usize) -> Result<String, WorldConsumerSetErrorV1> {
        match self.header(3) {
            Ok(length) => match usize::try_from(length) {
                Ok(length) if length != 0 && length <= maximum => match self.take(length) {
                    Ok(value) => std::str::from_utf8(value)
                        .map(str::to_owned)
                        .map_err(|_| WorldConsumerSetErrorV1::InvalidEncoding),
                    Err(error) => Err(error),
                },
                _ => Err(WorldConsumerSetErrorV1::FieldOutOfBounds),
            },
            Err(error) => Err(error),
        }
    }
    fn header(&mut self, expected_kind: u8) -> Result<u64, WorldConsumerSetErrorV1> {
        self.take(1).and_then(|value| {
            let first = value[0];
            if first >> 5 != expected_kind {
                return Err(WorldConsumerSetErrorV1::InvalidEncoding);
            }
            self.additional(first & 0x1f)
        })
    }

    fn additional(&mut self, code: u8) -> Result<u64, WorldConsumerSetErrorV1> {
        let decoded = match code {
            0..=23 => Ok((u64::from(code), 0)),
            24 => self.take(1).map(|value| (u64::from(value[0]), 1)),
            25 => self
                .fixed_raw::<2>()
                .map(|value| (u64::from(u16::from_be_bytes(value)), 2)),
            26 => self
                .fixed_raw::<4>()
                .map(|value| (u64::from(u32::from_be_bytes(value)), 4)),
            27 => self
                .fixed_raw::<8>()
                .map(|value| (u64::from_be_bytes(value), 8)),
            _ => Err(WorldConsumerSetErrorV1::InvalidEncoding),
        };
        decoded.and_then(|(length, width)| {
            if (width == 1 && length < 24)
                || (width == 2 && length <= 0xff)
                || (width == 4 && length <= 0xffff)
                || (width == 8 && length <= 0xffff_ffff)
            {
                Err(WorldConsumerSetErrorV1::NonCanonicalEncoding)
            } else {
                Ok(length)
            }
        })
    }

    fn fixed_raw<const N: usize>(&mut self) -> Result<[u8; N], WorldConsumerSetErrorV1> {
        match self.take(N) {
            Ok(value) => value
                .try_into()
                .map_err(|_| WorldConsumerSetErrorV1::InvalidEncoding),
            Err(error) => Err(error),
        }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], WorldConsumerSetErrorV1> {
        match self.position.checked_add(length) {
            Some(end) => match self.bytes.get(self.position..end) {
                Some(value) => {
                    self.position = end;
                    Ok(value)
                }
                None => Err(WorldConsumerSetErrorV1::InvalidEncoding),
            },
            None => Err(WorldConsumerSetErrorV1::InvalidEncoding),
        }
    }
}
