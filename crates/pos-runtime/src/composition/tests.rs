//! R8-W4 (pos-runtime half): the production community pin.

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn the_community_pin_is_a_governed_community_plugin_pin() -> TestResult {
    let digest = Hash::from_bytes([7; 32]);
    let pin = community_pin_v1(digest, vec!["world".to_owned(), "guest".to_owned()])?;
    let kind = DomainImplementationKindV1::Plugin;
    assert_eq!(pin.implementation_kind(), kind);
    let isolation = PluginIsolationV1::GovernedCommunity;
    assert_eq!(pin.isolation(), isolation);
    assert_eq!(pin.configuration_digest(), digest);
    assert_eq!(pin.roles(), ["world".to_owned(), "guest".to_owned()]);
    Ok(())
}

#[test]
fn the_community_pin_refuses_what_the_pin_constructor_refuses() {
    let digest = Hash::from_bytes([7; 32]);
    let refused = [
        community_pin_v1(Hash::zero(), vec!["world".to_owned()]),
        community_pin_v1(digest, Vec::new()),
        community_pin_v1(digest, vec![String::new()]),
        community_pin_v1(digest, vec!["world".to_owned(), "world".to_owned()]),
    ];
    for result in refused {
        assert_eq!(result, Err(PluginCompositionErrorV1::InvalidMetadata));
    }
}
