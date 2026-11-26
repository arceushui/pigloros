#![cfg(any(test, feature = "test-support"))]
//! A tampered wrap or tag never authenticates: unlock releases no root and
//! leaves the binding alone (ADR-091: any changed field fails authentication).

use super::{binding_name, inverted, page, wrap_name, Fixture, TestResult, SUBJECT, WRAP_REFUSED};

#[test]
fn a_tampered_tag_ciphertext_or_authenticated_field_releases_no_root() -> TestResult {
    let mut fixture = Fixture::enrolled(&[SUBJECT])?;
    let original = fixture.read(&wrap_name(SUBJECT, 1))?;
    let binding = fixture.read(&binding_name(SUBJECT, 1))?;
    let wrap = fixture.wrap(SUBJECT, 1)?;
    let (ciphertext, tag) = wrap.wrapped_root().split_at(32);
    let params = wrap.params();
    let fields: [(&str, &[u8]); 6] = [
        ("tag", tag),
        ("wrapped root", ciphertext),
        ("wrap salt", &params.wrap_salt),
        ("subkey salt", &params.subkey_salt),
        ("wrap nonce", &params.wrap_nonce),
        ("prf input", &params.prf_input),
    ];
    for (name, field) in fields {
        let tampered = inverted(&original, field)?;
        assert_ne!(tampered, original, "{name}");
        fixture.put(&wrap_name(SUBJECT, 1), &tampered)?;
        let outcome = fixture.unlock(SUBJECT, 1, page(SUBJECT))?;
        assert_eq!(outcome.err(), Some(WRAP_REFUSED), "{name}");
        assert_eq!(fixture.read(&binding_name(SUBJECT, 1))?, binding, "{name}");
    }
    // The untampered wrap unlocks: only the changed field was refused.
    fixture.put(&wrap_name(SUBJECT, 1), &original)?;
    let entry = fixture.unlock(SUBJECT, 1, page(SUBJECT))??;
    assert_eq!(entry.root_material_digest(), fixture.digest(SUBJECT, 1)?);
    Ok(())
}

#[test]
fn a_single_flipped_tag_bit_is_refused() -> TestResult {
    let mut fixture = Fixture::enrolled(&[SUBJECT])?;
    let original = fixture.read(&wrap_name(SUBJECT, 1))?;
    // The wrap ends with its 16-byte tag.
    let mut tampered = original.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    fixture.put(&wrap_name(SUBJECT, 1), &tampered)?;
    let outcome = fixture.unlock(SUBJECT, 1, page(SUBJECT))?;
    assert_eq!(outcome.err(), Some(WRAP_REFUSED));
    fixture.put(&wrap_name(SUBJECT, 1), &original)?;
    assert!(fixture.unlock(SUBJECT, 1, page(SUBJECT))?.is_ok());
    Ok(())
}
