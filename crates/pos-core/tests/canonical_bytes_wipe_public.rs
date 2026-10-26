//! Public ownership/refusal contracts; freed storage is never inspected.
//! The overwrite guarantee is audited at the existing live-slice `zeroize` call.

use pos_core::CanonicalBytes;

fn refused(value: CanonicalBytes) -> CanonicalBytes {
    value.try_zeroize_owned().err().unwrap_or_else(|| {
        std::panic::resume_unwind(Box::new("expected unchanged ownership refusal"))
    })
}

#[test]
fn unique_owned_logical_ranges_can_be_consumed() {
    let mut bytes = Vec::with_capacity(128);
    bytes.extend_from_slice(b"owned plaintext");
    assert_eq!(CanonicalBytes::from_vec(bytes).try_zeroize_owned(), Ok(()));
}

#[test]
fn static_nonempty_refusal_preserves_bytes_and_backing() {
    let original = CanonicalBytes::from_static(b"static plaintext");
    let pointer = original.as_slice().as_ptr();
    let returned = refused(original);
    assert_eq!(returned.as_slice(), b"static plaintext");
    assert_eq!(returned.as_slice().as_ptr(), pointer);
    let returned = refused(returned);
    assert_eq!(returned.as_slice(), b"static plaintext");
    assert_eq!(returned.as_slice().as_ptr(), pointer);
}

#[test]
fn shared_refusal_preserves_all_aliases_and_retry_waits_for_the_last() {
    let original = CanonicalBytes::from_vec(b"shared plaintext".to_vec());
    let first = original.clone();
    let last = original.clone();
    let pointer = original.as_slice().as_ptr();
    let returned = refused(original);
    assert_eq!(returned.as_slice(), b"shared plaintext");
    assert_eq!(returned.as_slice().as_ptr(), pointer);
    assert_eq!(first.as_slice(), b"shared plaintext");
    assert_eq!(last.as_slice(), b"shared plaintext");
    drop(first);
    let returned = refused(returned);
    assert_eq!(returned.as_slice(), b"shared plaintext");
    assert_eq!(returned.as_slice().as_ptr(), pointer);
    assert_eq!(last.as_slice(), b"shared plaintext");
    drop(last);
    assert_eq!(returned.try_zeroize_owned(), Ok(()));
}

#[test]
fn owned_static_and_shared_empty_values_succeed_vacuously() {
    let empty = CanonicalBytes::from_vec(Vec::new());
    let alias = empty.clone();
    for value in [empty, alias, CanonicalBytes::from_static(b"")] {
        assert_eq!(value.try_zeroize_owned(), Ok(()));
    }
}
