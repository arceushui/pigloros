use super::*;

#[test]
fn export_installed_selector_fixtures() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let destination = std::env::var_os("SELECTOR_FIXTURE_EXPORT")
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
        std::fs::write(directory.join("request.cbor"), corpus.request)?;
        std::fs::write(directory.join("archive.cbor"), corpus.archive)?;
        std::fs::write(directory.join("trust-policy.cbor"), corpus.trust_policy)?;
    }
    Ok(())
}
