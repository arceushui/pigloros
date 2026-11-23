use super::{decrypt, encrypt, CbcBlock};
use crate::vectors::{array32, vector};

const VECTORS: &str = include_str!("../../tests/vectors/cbc-sp800-38a.txt");

fn blocks(bytes: &[u8]) -> Vec<CbcBlock> {
    bytes.as_chunks::<16>().0.to_vec()
}

#[test]
fn aes_256_cbc_matches_nist_sp_800_38a() {
    let key = array32(&vector(VECTORS, "key"));
    let iv = blocks(&vector(VECTORS, "iv"))[0];
    let plaintext = blocks(&vector(VECTORS, "plaintext"));
    let ciphertext = blocks(&vector(VECTORS, "ciphertext"));
    assert_eq!(plaintext.len(), 4);
    let mut encrypted = plaintext.clone();
    encrypt(&key, &iv, &mut encrypted);
    assert_eq!(encrypted, ciphertext);
    let mut decrypted = ciphertext;
    decrypt(&key, &iv, &mut decrypted);
    assert_eq!(decrypted, plaintext);
}

#[test]
fn each_block_chains_from_the_previous_ciphertext() {
    let key = array32(&vector(VECTORS, "key"));
    let iv = blocks(&vector(VECTORS, "iv"))[0];
    let plaintext = blocks(&vector(VECTORS, "plaintext"));
    let ciphertext = blocks(&vector(VECTORS, "ciphertext"));
    let mut second = vec![plaintext[1]];
    encrypt(&key, &ciphertext[0], &mut second);
    assert_eq!(second, [ciphertext[1]]);
    let mut first = vec![plaintext[0]];
    encrypt(&key, &iv, &mut first);
    assert_eq!(first, [ciphertext[0]]);
}
