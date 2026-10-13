use super::*;

#[test]
fn every_family_has_its_own_pinned_digest() {
    let digests: Vec<[u8; 32]> = FixtureFamily::ALL
        .iter()
        .map(|f| pinned_digest(*f))
        .collect();
    assert_eq!(digests.len(), 7);
    for (index, digest) in digests.iter().enumerate() {
        assert_eq!(
            digest,
            blake3::hash(placeholder_schema(FixtureFamily::ALL[index])).as_bytes()
        );
        assert!(!digests[..index].contains(digest), "digest {index} repeats");
    }
}
