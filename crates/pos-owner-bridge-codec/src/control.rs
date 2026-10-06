use core::convert::TryFrom;

use crate::{CeremonyId, OwnerBridgeCodecError};

/// Exact byte width of an [`OwnerBridgeControlV1`] header.
pub const CONTROL_HEADER_BYTES: usize = 64;

/// Exact total capacity of every request buffer.
pub const REQUEST_BUFFER_CAPACITY: u32 = 4_096;

/// Exact total capacity of a Create reply buffer.
pub const CREATE_REPLY_BUFFER_CAPACITY: u32 = 73_728;

/// Exact total capacity of a Get reply buffer.
pub const GET_REPLY_BUFFER_CAPACITY: u32 = 8_192;

const HEADER_MAGIC: [u8; 4] = *b"PWB1";
const HEADER_VERSION: u16 = 1;
const CONTROL_HEADER_BYTES_U16: u16 = 64;
const CONTROL_HEADER_BYTES_U32: u32 = 64;

/// The direction assigned to a control buffer by its owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ControlRole {
    /// A host-written request, shared read-only with the packaged page.
    Request = 0,
    /// A page-written reply, shared read-write with the packaged page.
    Reply = 1,
}

impl ControlRole {
    const fn code(self) -> u8 {
        match self {
            Self::Request => 0,
            Self::Reply => 1,
        }
    }
}

impl TryFrom<u8> for ControlRole {
    type Error = OwnerBridgeCodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Request),
            1 => Ok(Self::Reply),
            _ => Err(OwnerBridgeCodecError::InvalidControlValue),
        }
    }
}

/// The one `WebAuthn` ceremony shape accepted by the owner bridge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CeremonyKind {
    /// A `WebAuthn` Create ceremony.
    Create = 0,
    /// A `WebAuthn` Get ceremony.
    Get = 1,
}

impl CeremonyKind {
    const fn code(self) -> u8 {
        match self {
            Self::Create => 0,
            Self::Get => 1,
        }
    }
}

impl TryFrom<u8> for CeremonyKind {
    type Error = OwnerBridgeCodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Create),
            1 => Ok(Self::Get),
            _ => Err(OwnerBridgeCodecError::InvalidControlValue),
        }
    }
}

/// The closed state word values for an owner-bridge reply buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ControlState {
    /// The reply buffer was initialized by the host and has no page receipt.
    Empty = 0,
    /// The page has received a reply buffer and is writing its payload.
    Writing = 1,
    /// A complete request or reply payload is available for consumption.
    Ready = 2,
    /// The host owns a published reply while it copies its fixed-capacity image.
    Consuming = 3,
    /// The host has retired the pair and requested the page release both buffers.
    ReleaseRequested = 4,
    /// The page has started its release sequence.
    Releasing = 5,
    /// The page failed or cancelled its `WebAuthn` call without a payload.
    Failed = 6,
    /// The page has received a complete pair before it begins its `WebAuthn` call.
    Received = 7,
}

impl ControlState {
    const fn code(self) -> u32 {
        match self {
            Self::Empty => 0,
            Self::Writing => 1,
            Self::Ready => 2,
            Self::Consuming => 3,
            Self::ReleaseRequested => 4,
            Self::Releasing => 5,
            Self::Failed => 6,
            Self::Received => 7,
        }
    }
}

impl TryFrom<u32> for ControlState {
    type Error = OwnerBridgeCodecError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Empty),
            1 => Ok(Self::Writing),
            2 => Ok(Self::Ready),
            3 => Ok(Self::Consuming),
            4 => Ok(Self::ReleaseRequested),
            5 => Ok(Self::Releasing),
            6 => Ok(Self::Failed),
            7 => Ok(Self::Received),
            _ => Err(OwnerBridgeCodecError::InvalidControlValue),
        }
    }
}

/// One validated ADR-110 §5.3 owner-bridge control header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnerBridgeControlV1 {
    role: ControlRole,
    kind: CeremonyKind,
    generation: u32,
    ceremony_id: CeremonyId,
    total_capacity: u32,
    payload_len: u32,
    state: ControlState,
}

impl OwnerBridgeControlV1 {
    /// Construct the host's complete, ready-to-read request header.
    ///
    /// # Errors
    ///
    /// Returns [`OwnerBridgeCodecError::InvalidControlBounds`] if `generation`
    /// is zero or `payload_len` is outside the fixed request payload capacity.
    pub fn new_request(
        kind: CeremonyKind,
        generation: u32,
        ceremony_id: CeremonyId,
        payload_len: u32,
    ) -> Result<Self, OwnerBridgeCodecError> {
        let header = Self {
            role: ControlRole::Request,
            kind,
            generation,
            ceremony_id,
            total_capacity: REQUEST_BUFFER_CAPACITY,
            payload_len,
            state: ControlState::Ready,
        };
        header.validate()?;
        Ok(header)
    }

    /// Construct the host's empty reply header for `kind`.
    ///
    /// # Errors
    ///
    /// Returns [`OwnerBridgeCodecError::InvalidControlBounds`] if `generation`
    /// is zero.
    pub fn new_reply(
        kind: CeremonyKind,
        generation: u32,
        ceremony_id: CeremonyId,
    ) -> Result<Self, OwnerBridgeCodecError> {
        let header = Self {
            role: ControlRole::Reply,
            kind,
            generation,
            ceremony_id,
            total_capacity: reply_capacity(kind),
            payload_len: 0,
            state: ControlState::Empty,
        };
        header.validate()?;
        Ok(header)
    }

    /// Return a reply-header image after a page or host state transition.
    ///
    /// # Errors
    ///
    /// Returns [`OwnerBridgeCodecError::InvalidPayload`] when this is not a
    /// reply header or the resulting state/payload combination is invalid.
    pub fn with_reply_state(
        self,
        payload_len: u32,
        state: ControlState,
    ) -> Result<Self, OwnerBridgeCodecError> {
        if self.role != ControlRole::Reply {
            return Err(OwnerBridgeCodecError::InvalidPayload);
        }
        let reply = Self {
            payload_len,
            state,
            ..self
        };
        reply.validate()?;
        Ok(reply)
    }

    /// Decode and validate one exact 64-byte control header.
    ///
    /// # Errors
    ///
    /// Returns a closed [`OwnerBridgeCodecError`] for a malformed, unknown, or
    /// internally inconsistent header.
    pub fn decode(input: &[u8]) -> Result<Self, OwnerBridgeCodecError> {
        let header: &[u8; CONTROL_HEADER_BYTES] = input
            .try_into()
            .map_err(|_| OwnerBridgeCodecError::InvalidControlHeaderLength)?;
        if header[..4] != HEADER_MAGIC {
            return Err(OwnerBridgeCodecError::InvalidControlMagic);
        }
        if read_u16(header, 4) != HEADER_VERSION || read_u16(header, 6) != CONTROL_HEADER_BYTES_U16
        {
            return Err(OwnerBridgeCodecError::InvalidControlVersion);
        }
        if header[10..12] != [0; 2] || header[44..48] != [0; 4] || header[48..64] != [0; 16] {
            return Err(OwnerBridgeCodecError::NonzeroReserved);
        }

        let mut ceremony_id = [0; 16];
        ceremony_id.copy_from_slice(&header[16..32]);
        let decoded = Self {
            role: ControlRole::try_from(header[8])?,
            kind: CeremonyKind::try_from(header[9])?,
            generation: read_u32(header, 12),
            ceremony_id: CeremonyId::from_bytes(ceremony_id),
            total_capacity: read_u32(header, 32),
            payload_len: read_u32(header, 36),
            state: ControlState::try_from(read_u32(header, 40))?,
        };
        decoded.validate()?;
        Ok(decoded)
    }

    /// Encode this validated header into its exact 64-byte binary form.
    #[must_use]
    pub fn encode(self) -> [u8; CONTROL_HEADER_BYTES] {
        let mut output = [0; CONTROL_HEADER_BYTES];
        output[..4].copy_from_slice(&HEADER_MAGIC);
        write_u16(&mut output, 4, HEADER_VERSION);
        write_u16(&mut output, 6, CONTROL_HEADER_BYTES_U16);
        output[8] = self.role.code();
        output[9] = self.kind.code();
        write_u32(&mut output, 12, self.generation);
        output[16..32].copy_from_slice(self.ceremony_id.as_bytes());
        write_u32(&mut output, 32, self.total_capacity);
        write_u32(&mut output, 36, self.payload_len);
        write_u32(&mut output, 40, self.state.code());
        output
    }

    /// Return the fixed role declared by this header.
    #[must_use]
    pub const fn role(self) -> ControlRole {
        self.role
    }

    /// Return the closed `WebAuthn` ceremony kind declared by this header.
    #[must_use]
    pub const fn kind(self) -> CeremonyKind {
        self.kind
    }

    /// Return the nonzero buffer generation declared by this header.
    #[must_use]
    pub const fn generation(self) -> u32 {
        self.generation
    }

    /// Return the exact 16-byte ceremony identifier declared by this header.
    #[must_use]
    pub const fn ceremony_id(self) -> CeremonyId {
        self.ceremony_id
    }

    /// Return the exact fixed total buffer capacity declared by this header.
    #[must_use]
    pub const fn total_capacity(self) -> u32 {
        self.total_capacity
    }

    /// Return the currently published payload length.
    #[must_use]
    pub const fn payload_len(self) -> u32 {
        self.payload_len
    }

    /// Return the closed state-word value declared by this header.
    #[must_use]
    pub const fn state(self) -> ControlState {
        self.state
    }

    fn validate(self) -> Result<(), OwnerBridgeCodecError> {
        if self.generation == 0 || self.total_capacity != capacity_for(self.role, self.kind) {
            return Err(OwnerBridgeCodecError::InvalidControlBounds);
        }

        // The exact capacity check above establishes that every accepted
        // control buffer includes its fixed header.
        let maximum_payload = self.total_capacity - CONTROL_HEADER_BYTES_U32;
        if self.payload_len > maximum_payload {
            return Err(OwnerBridgeCodecError::InvalidControlBounds);
        }

        match self.role {
            ControlRole::Request => {
                if self.state != ControlState::Ready || self.payload_len == 0 {
                    return Err(OwnerBridgeCodecError::InvalidPayload);
                }
            }
            ControlRole::Reply => match self.state {
                ControlState::Empty | ControlState::Received | ControlState::Failed
                    if self.payload_len != 0 =>
                {
                    return Err(OwnerBridgeCodecError::InvalidPayload);
                }
                ControlState::Ready if self.payload_len == 0 => {
                    return Err(OwnerBridgeCodecError::InvalidPayload);
                }
                _ => {}
            },
        }
        Ok(())
    }
}

const fn capacity_for(role: ControlRole, kind: CeremonyKind) -> u32 {
    match role {
        ControlRole::Request => REQUEST_BUFFER_CAPACITY,
        ControlRole::Reply => reply_capacity(kind),
    }
}

const fn reply_capacity(kind: CeremonyKind) -> u32 {
    match kind {
        CeremonyKind::Create => CREATE_REPLY_BUFFER_CAPACITY,
        CeremonyKind::Get => GET_REPLY_BUFFER_CAPACITY,
    }
}

const fn read_u16(input: &[u8; CONTROL_HEADER_BYTES], offset: usize) -> u16 {
    u16::from_le_bytes([input[offset], input[offset + 1]])
}

const fn read_u32(input: &[u8; CONTROL_HEADER_BYTES], offset: usize) -> u32 {
    u32::from_le_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
    ])
}

fn write_u16(output: &mut [u8; CONTROL_HEADER_BYTES], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(output: &mut [u8; CONTROL_HEADER_BYTES], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
