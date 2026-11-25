//! AES-256-CBC without padding over `aes =0.9.4` (ADR-110 E20 LP1, AM-110g).
//!
//! PIN/UV auth protocol 2 encrypts whole blocks only, so the functions take blocks, not bytes,
//! and there is no padding to get wrong. They are checked against the NIST SP 800-38A CBC
//! vectors.

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, Key, KeyInit};
use aes::{Aes256, Block};

/// One AES block.
pub type CbcBlock = [u8; 16];

fn xor(block: &mut CbcBlock, with: &CbcBlock) {
    block
        .iter_mut()
        .zip(with)
        .for_each(|(byte, other)| *byte ^= other);
}

/// Encrypt `blocks` in place under `key`, chaining from `iv`.
pub fn encrypt(key: &[u8; 32], iv: &CbcBlock, blocks: &mut [CbcBlock]) {
    let cipher = Aes256::new(Key::<Aes256>::cast_from_core(key));
    let mut chain = *iv;
    for block in blocks {
        xor(block, &chain);
        cipher.encrypt_block(Block::cast_from_core_mut(block));
        chain = *block;
    }
}

/// Decrypt `blocks` in place under `key`, chaining from `iv`.
pub fn decrypt(key: &[u8; 32], iv: &CbcBlock, blocks: &mut [CbcBlock]) {
    let cipher = Aes256::new(Key::<Aes256>::cast_from_core(key));
    let mut chain = *iv;
    for block in blocks {
        let ciphertext = *block;
        cipher.decrypt_block(Block::cast_from_core_mut(block));
        xor(block, &chain);
        chain = ciphertext;
    }
}

#[cfg(test)]
mod tests;
