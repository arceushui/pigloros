use super::*;

#[test]
fn export_installed_selector_fixtures() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let export = std::env::var_os("SELECTOR_FIXTURE_EXPORT");
    let destination = export
        .as_ref()
        .map_or_else(|| temporary.path().to_path_buf(), std::path::PathBuf::from);
    std::fs::create_dir_all(&destination)?;
    let corpora = [
        ("valid", support::corpus()?),
        (
            "mode",
            support::corpus_with_bundle_mutation(BundleMutation::Mode)?,
        ),
        (
            "signature",
            support::corpus_with_bundle_mutation(BundleMutation::Signature)?,
        ),
        (
            "profile",
            support::corpus_with_profile_mutation(ProfileMutation::FixtureAdapter)?,
        ),
        (
            "caps",
            support::corpus_with_profile_mutation(ProfileMutation::SelectedClosureCapBoundary(0))?,
        ),
    ];
    for (name, corpus) in corpora {
        let directory = destination.join(name);
        std::fs::create_dir_all(&directory)?;
        let committed = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/installed-selector")
            .join(name);
        for (file, bytes) in [
            ("request.cbor", corpus.request),
            ("archive.cbor", corpus.archive),
            ("trust-policy.cbor", corpus.trust_policy),
        ] {
            if export.is_none() {
                assert_eq!(std::fs::read(committed.join(file))?, bytes, "{name}/{file}");
            }
            std::fs::write(directory.join(file), bytes)?;
        }
    }
    Ok(())
}
