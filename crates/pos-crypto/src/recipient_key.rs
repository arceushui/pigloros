//! X25519 primitives used by the recipient-custody adapter.

use curve25519_dalek::{constants::X25519_BASEPOINT, montgomery::MontgomeryPoint};

/// Derive the X25519 public key for exactly 32 bytes of private material.
///
/// The caller owns and zeroizes the private bytes. This primitive never stores
/// or exposes them beyond the duration of the calculation.
#[must_use]
pub fn x25519_public_key(private_material: [u8; 32]) -> [u8; 32] {
    X25519_BASEPOINT.mul_clamped(private_material).0
}

/// Perform one X25519 scalar multiplication.
#[must_use]
pub fn x25519_shared_secret(private_material: [u8; 32], peer_public_key: [u8; 32]) -> [u8; 32] {
    MontgomeryPoint(peer_public_key)
        .mul_clamped(private_material)
        .0
}

#[cfg(test)]
mod tests {
    use super::{x25519_public_key, x25519_shared_secret};

    #[test]
    fn x25519_matches_rfc_7748_basepoint_vector() {
        let private = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        assert_eq!(
            x25519_public_key(private),
            [
                0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e,
                0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e,
                0xaa, 0x9b, 0x4e, 0x6a,
            ]
        );
        assert_ne!(x25519_shared_secret(private, [9; 32]), [0; 32]);
    }
}
