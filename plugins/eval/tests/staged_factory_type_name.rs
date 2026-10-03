//! This Plugin's factory is on the reviewed staged-catalogue list.
//!
//! `pos-runtime` recognises a reviewed staged Reducer factory by
//! `std::any::type_name` of the real factory type. That output is not stable
//! across compiler versions, so recognition only holds within one compiler
//! build; this test checks the name this build produces against the actual
//! reviewed list. The recorded reducer identity hashes the list's stable
//! reviewed identifier instead, so it does not depend on the compiler.
//!
//! The second test proves the name belongs to a real factory: reviewed
//! admission of it reaches the conformance-evidence check, which refuses it
//! until that evidence is recorded.

#[test]
fn factory_type_name_is_on_the_reviewed_staged_list() {
    assert!(pos_runtime::is_reviewed_staged_factory(
        std::any::type_name::<pos_plugin_eval::EvalPlugin>()
    ));
}

#[test]
fn reviewed_admission_of_the_factory_needs_conformance_evidence() {
    let mut provider = pos_runtime::HostProjectionProviderV1::default();
    assert_eq!(
        provider.admit::<pos_plugin_eval::EvalPlugin>(std::sync::Arc::new(())),
        Err(pos_runtime::StagedReducerAdmissionErrorV1::ConformanceEvidenceMissing)
    );
}
