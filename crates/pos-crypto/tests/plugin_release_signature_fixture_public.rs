//! ADR-103 R7 slice 1: the `test-support` release-signature token fixture.
//!
//! The fixture exists only with the `test-support` feature, so this target
//! declares `required-features = ["test-support"]` in `Cargo.toml`; a build
//! without the feature cannot name the type.

use pos_core::OwnerIdV1;
use pos_crypto::plugin_manifest::{
    PluginReleaseSignatureFixtureV1, VerifiedPluginReleaseSignatureV1,
};

#[test]
fn r7_t1_the_fixture_converts_to_a_token_with_its_five_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = PluginReleaseSignatureFixtureV1 {
        pmf1_digest: [0x11; 32],
        release_digest: [0x22; 32],
        owner: OwnerIdV1::new("publisher")?,
        epoch: 7,
        public_key: [0x33; 32],
    };

    let token = VerifiedPluginReleaseSignatureV1::from(fixture);

    assert_eq!(token.pmf1_digest(), [0x11; 32]);
    assert_eq!(token.release_digest(), [0x22; 32]);
    assert_eq!(token.owner(), OwnerIdV1::new("publisher")?);
    assert_eq!(token.epoch(), 7);
    assert_eq!(token.public_key(), [0x33; 32]);
    Ok(())
}
