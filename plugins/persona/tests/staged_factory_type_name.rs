//! The reviewed staged-catalogue name of this Plugin's factory.
//!
//! `pos-runtime` admits a reviewed staged Reducer factory by comparing
//! `std::any::type_name` of the real factory type with a fixed list of
//! reviewed names. `type_name` output is not stable across compiler
//! versions, so the comparison only holds within one compiler build; this
//! test pins the name that build produces for this crate's factory.

#[test]
fn reviewed_staged_factory_name_is_the_real_type_name() {
    assert_eq!(
        std::any::type_name::<pos_plugin_persona::PersonaPlugin>(),
        "pos_plugin_persona::PersonaPlugin"
    );
}
