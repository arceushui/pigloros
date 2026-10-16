use super::*;
use crate::test_support::schema_member;

#[test]
fn every_family_has_the_digest_of_its_own_schema_member() {
    let digests: Vec<[u8; 32]> = FixtureFamily::ALL
        .iter()
        .map(|f| pinned_digest(*f))
        .collect();
    assert_eq!(digests.len(), 7);
    for (index, digest) in digests.iter().enumerate() {
        let member = schema_member(FixtureFamily::ALL[index]);
        assert_eq!(digest, blake3::hash(member).as_bytes());
        assert!(!digests[..index].contains(digest), "digest {index} repeats");
    }
}
