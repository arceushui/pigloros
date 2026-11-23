//! PIN/UV auth protocol 2 (CTAP 2.1 PS §6.5.7; ADR-110 E20 LP1).
//!
//! The platform draws an ephemeral P-256 key, computes `Z = x(d·Q)` with the authenticator key
//! `Q`, and derives the 64-byte shared secret `HKDF(Z, "CTAP2 HMAC key") ‖ HKDF(Z, "CTAP2 AES
//! key")`. `encrypt` is `IV ‖ AES-256-CBC(aesKey, IV, m)` with a random IV and no padding, and
//! `authenticate` is the full 32-byte HMAC-SHA-256. Protocol 1 is never used.
//!
//! The ephemeral key, `Z`, the shared secret and every plaintext block are wiped. Three things
//! are not: the HKDF pseudorandom key inside the `hkdf` state, which offers no wipe; the
//! `ProjectivePoint` product `d·Q`, which `p256` does not zeroize; and the SHA-256 block buffers
//! inside the `sha2` state, because enabling `sha2`'s `zeroize` feature would change the
//! lockfile (it adds `zeroize` to `digest`).

use hkdf::{Hkdf, HmacImpl};
use hmac::Hmac;
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::elliptic_curve::point::AffineCoordinates;
use p256::ProjectivePoint;
use pos_owner_bridge::{BridgeError, LifecycleCode, SecureRandom, UnavailableCode};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::cbc::{self, CbcBlock};

/// The CTAP2 identifier of PIN/UV auth protocol 2.
pub const PROTOCOL: u64 = 2;

/// How many draws may fail to be a valid P-256 scalar before the random source is distrusted.
const SCALAR_DRAWS: usize = 4;

const CLIENT_FAILED: BridgeError = BridgeError::Lifecycle(LifecycleCode::ClientFailed);

/// One uncompressed P-256 point, as its two coordinates.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Point {
    /// The x-coordinate, big-endian.
    pub x: [u8; 32],
    /// The y-coordinate, big-endian.
    pub y: [u8; 32],
}

impl Point {
    fn sec1(self) -> [u8; 65] {
        let mut encoded = [4; 65];
        encoded[1..33].copy_from_slice(&self.x);
        encoded[33..].copy_from_slice(&self.y);
        encoded
    }
}

/// The 64-byte protocol 2 shared secret: the HMAC key, then the AES key. Wiped on drop.
pub struct SharedSecret {
    hmac: Zeroizing<[u8; 32]>,
    aes: Zeroizing<[u8; 32]>,
}

impl SharedSecret {
    /// The first half: the key `authenticate` uses.
    #[must_use]
    pub fn hmac_key(&self) -> &[u8; 32] {
        &self.hmac
    }

    /// The second half: the key `encrypt` and `decrypt` use.
    #[must_use]
    pub fn aes_key(&self) -> &[u8; 32] {
        &self.aes
    }
}

/// The protocol 2 `kdf(Z)` of CTAP 2.1 PS §6.5.7.
///
/// The HKDF salt is 32 zero bytes. RFC 5869 §2.2 defines an absent salt as exactly that, so
/// the salt is passed as absent.
///
/// # Errors
///
/// Returns `Lifecycle(ClientFailed)` if HKDF refuses a 32-byte output, which it never does.
pub fn kdf(z: &[u8; 32]) -> Result<SharedSecret, BridgeError> {
    let hkdf = Hkdf::<Sha256>::new(None, z);
    let mut hmac = Zeroizing::<[u8; 32]>::default();
    let mut aes = Zeroizing::<[u8; 32]>::default();
    hkdf.expand(b"CTAP2 HMAC key", hmac.as_mut_slice())
        .and_then(|()| hkdf.expand(b"CTAP2 AES key", aes.as_mut_slice()))
        .map(|()| SharedSecret { hmac, aes })
        .or(Err(CLIENT_FAILED))
}

/// The x-coordinate of `scalar · peer`.
fn shared_x(scalar: &SigningKey, peer: &VerifyingKey) -> Zeroizing<[u8; 32]> {
    let product = ProjectivePoint::from(*peer.as_affine()).mul(scalar.as_nonzero_scalar());
    let mut x = product.to_affine().x();
    let mut z = Zeroizing::<[u8; 32]>::default();
    z.copy_from_slice(&x);
    x.zeroize();
    z
}

fn verifying_key(point: Point) -> Result<VerifyingKey, BridgeError> {
    VerifyingKey::from_sec1_bytes(&point.sec1()).or(Err(CLIENT_FAILED))
}

/// The coordinates of `key`'s public point.
#[must_use]
pub fn public_point(key: &SigningKey) -> Point {
    let affine = key.verifying_key().as_affine();
    let mut point = Point::default();
    point.x.copy_from_slice(&affine.x());
    point.y.copy_from_slice(&affine.y());
    point
}

/// Draw an ephemeral P-256 key, redrawing an invalid scalar.
///
/// # Errors
///
/// Returns `Unavailable(RngUnavailable)` when the source fails or yields no valid scalar in a
/// few draws.
pub fn ephemeral_key(random: &mut dyn SecureRandom) -> Result<SigningKey, BridgeError> {
    let mut scalar = Zeroizing::<[u8; 32]>::default();
    for _ in 0..SCALAR_DRAWS {
        random
            .fill(scalar.as_mut_slice())
            .map_err(BridgeError::Unavailable)?;
        if let Ok(key) = SigningKey::from_slice(scalar.as_slice()) {
            return Ok(key);
        }
    }
    Err(BridgeError::Unavailable(UnavailableCode::RngUnavailable))
}

/// The shared secret between the key `scalar` and the peer point `peer`.
///
/// # Errors
///
/// Returns `Lifecycle(ClientFailed)` when `peer` is not a valid P-256 point.
pub fn agree(scalar: &SigningKey, peer: Point) -> Result<SharedSecret, BridgeError> {
    let peer = verifying_key(peer)?;
    kdf(&shared_x(scalar, &peer))
}

/// `encapsulate(peer)`: a fresh platform key and the shared secret it agrees with `peer`.
///
/// # Errors
///
/// Returns `Lifecycle(ClientFailed)` for an invalid authenticator key, and
/// `Unavailable(RngUnavailable)` when no ephemeral key can be drawn.
pub fn encapsulate(
    peer: Point,
    random: &mut dyn SecureRandom,
) -> Result<(Point, SharedSecret), BridgeError> {
    let peer = verifying_key(peer)?;
    let scalar = ephemeral_key(random)?;
    let z = shared_x(&scalar, &peer);
    kdf(&z).map(|secret| (public_point(&scalar), secret))
}

/// `encrypt(key, demPlaintext)`: a random IV, then the CBC ciphertext of `plaintext`.
///
/// # Errors
///
/// Returns `Unavailable(RngUnavailable)` when no IV can be drawn.
pub fn encrypt(
    secret: &SharedSecret,
    plaintext: &[CbcBlock],
    random: &mut dyn SecureRandom,
) -> Result<Vec<u8>, BridgeError> {
    let mut iv = CbcBlock::default();
    random.fill(&mut iv).map_err(BridgeError::Unavailable)?;
    let mut blocks = Zeroizing::new(plaintext.to_vec());
    cbc::encrypt(secret.aes_key(), &iv, &mut blocks);
    let mut output = iv.to_vec();
    output.extend(blocks.iter().flatten());
    Ok(output)
}

/// `decrypt(key, demCiphertext)`: the plaintext blocks after the IV.
///
/// It returns none when the input is shorter than one IV or not a whole number of blocks.
#[must_use]
pub fn decrypt(secret: &SharedSecret, ciphertext: &[u8]) -> Option<Zeroizing<Vec<CbcBlock>>> {
    let (iv, rest) = ciphertext.split_first_chunk::<16>()?;
    let (blocks, remainder) = rest.as_chunks::<16>();
    if !remainder.is_empty() {
        return None;
    }
    let mut plaintext = Zeroizing::new(blocks.to_vec());
    cbc::decrypt(secret.aes_key(), iv, &mut plaintext);
    Some(plaintext)
}

/// `authenticate(key, message)`: HMAC-SHA-256 of the concatenated `parts`, all 32 bytes.
///
/// `key` is the 32-byte HMAC half of a shared secret or a 32-byte `pinUvAuthToken`. The HMAC
/// is set up through `hkdf::HmacImpl`, whose key setup cannot fail.
#[must_use]
pub fn authenticate(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as HmacImpl>::new_from_slice(key);
    for part in parts {
        HmacImpl::update(&mut mac, part);
    }
    HmacImpl::finalize(mac).into()
}

#[cfg(test)]
mod tests;
