use crate::OwnerBridgeCodecError;

pub(crate) const MAX_TRANSPORT_CODES: usize = 6;

/// Closed transport-code list persisted as hints in an owner credential binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportCodes {
    codes: [u8; MAX_TRANSPORT_CODES],
    length: usize,
}

impl TransportCodes {
    /// Construct sorted, unique ADR-097 transport codes.
    ///
    /// # Errors
    ///
    /// Returns [`OwnerBridgeCodecError::BoundsExceeded`] when the list is too
    /// long, or [`OwnerBridgeCodecError::InvalidPayload`] when it contains an
    /// unknown code or is not strictly sorted and unique.
    pub fn new(codes: &[u8]) -> Result<Self, OwnerBridgeCodecError> {
        if codes.len() > MAX_TRANSPORT_CODES {
            return Err(OwnerBridgeCodecError::BoundsExceeded);
        }
        let mut output = [0; MAX_TRANSPORT_CODES];
        for (index, &code) in codes.iter().enumerate() {
            if code > 5 || (index > 0 && codes[index - 1] >= code) {
                return Err(OwnerBridgeCodecError::InvalidPayload);
            }
            output[index] = code;
        }
        Ok(Self {
            codes: output,
            length: codes.len(),
        })
    }

    /// Return the ordered transport-code slice.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.codes[..self.length]
    }
}
