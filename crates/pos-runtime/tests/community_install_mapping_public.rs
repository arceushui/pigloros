//! R8-M3: the total mapping of a community release install failure (ADR-061 revision 8
//! decision 5), at the public seam.
//!
//! Every variant of `CommunityInstallErrorV1` and of `PluginReleaseInstallErrorV1` has a row,
//! and the wrapped source, trust, signature and registry errors are listed row by row. The
//! totality of the wrapped enums is enforced at compile time by the exhaustive matches without a
//! wildcard arm in `gate/mapping.rs` and `install.rs`; `index` below is an exhaustive `match`
//! over both install enums, so a variant added later fails to compile there until it is given a
//! row. The run-time check only proves that today's rows cover every arm of `index`.
#![cfg(target_os = "linux")]

use pos_crypto::plugin_manifest::{PluginManifestErrorV1, PluginReleaseSignatureErrorV1 as Sig};
use pos_crypto::plugin_trust::PluginTrustErrorV1 as Trust;
use pos_plugin_publisher::PluginReleaseInstallErrorV1 as Installer;
use pos_plugin_release::ReleaseSourceErrorV1 as S;
use pos_runtime::community_plugin_host::{
    host_error_for_install_v1, host_error_for_release_source_v1, CommunityInstallErrorV1 as Install,
};
use pos_store::plugin_trust_registry::PluginTrustPolicyRegistryErrorV1 as Reg;

#[path = "common/host_errors.rs"]
pub mod host_errors;

use host_errors::{
    Error as Host, ARTIFACT, EXPIRED, INVALID, KEY, MISMATCH, NOT_ACTIVE, TSU, UNTRUSTED,
};

/// The number of arms `index` distinguishes: two outer ones and five wrapped ones.
const ARMS: usize = 7;
const MANIFEST: PluginManifestErrorV1 = PluginManifestErrorV1::InvalidEncoding { ordinal: 3 };
/// Every variant of the source error, which the mapping sends to two answers.
const SOURCES: [S; 13] = [
    S::InvalidAddress,
    S::NotFound,
    S::BoundsExceeded,
    S::InvalidLayout,
    S::InvalidDescriptor,
    S::DigestMismatch,
    S::SizeMismatch,
    S::DuplicateMember,
    S::UnsupportedMediaType,
    S::Uncommitted,
    S::Io,
    S::LockUnavailable,
    S::RecoveryRequired,
];

/// The failure of the signed installer, wrapped as the community install entry wraps it.
const fn wrapped(error: Installer) -> Install {
    Install::Install(error)
}

const fn src(error: S) -> Install {
    wrapped(Installer::Source(error))
}

const fn auth(error: Trust) -> Install {
    wrapped(Installer::Authorization(error))
}

const fn sig(error: Sig) -> Install {
    wrapped(Installer::Signature(error))
}

const fn reg(error: Reg) -> Install {
    wrapped(Installer::Registry(error))
}

/// The arm of one input in the two enums: `0` and `1` for the outer `Source` and `Manifest`,
/// `2` for the wrapped `Install`.
const fn index(error: &Install) -> usize {
    match error {
        Install::Source(_) => 0,
        Install::Manifest(_) => 1,
        Install::Install(inner) => 2 + installer_index(inner),
    }
}

const fn installer_index(error: &Installer) -> usize {
    match error {
        Installer::Source(_) => 0,
        Installer::Manifest(_) => 1,
        Installer::Authorization(_) => 2,
        Installer::Signature(_) => 3,
        Installer::Registry(_) => 4,
    }
}

fn assert_rows(rows: &[(Install, Host)]) {
    for (input, expected) in rows {
        let got = host_error_for_install_v1(input.clone());
        assert_eq!(got, *expected, "{input:?}");
    }
}

#[test]
fn every_variant_of_both_install_errors_has_a_row() {
    let rows = [
        (Install::Source(S::NotFound), TSU),
        (Install::Manifest(MANIFEST), INVALID),
        (src(S::Io), TSU),
        (wrapped(Installer::Manifest(MANIFEST)), INVALID),
        (auth(Trust::ManifestExpired), EXPIRED),
        (sig(Sig::InvalidSignature), UNTRUSTED),
        (reg(Reg::ReleaseNotActive), NOT_ACTIVE),
    ];
    assert_rows(&rows);
    let mut listed = Vec::new();
    for (input, _) in &rows {
        listed.push(index(input));
    }
    listed.sort_unstable();
    assert_eq!(listed, (0..ARMS).collect::<Vec<_>>());
}

#[test]
fn a_manifest_failure_is_invalid_manifest_whichever_layer_raised_it() {
    let rows = [
        (Install::Manifest(MANIFEST), INVALID),
        (wrapped(Installer::Manifest(MANIFEST)), INVALID),
        (sig(Sig::Manifest(MANIFEST)), INVALID),
        (sig(Sig::AuthorizationMismatch), INVALID),
    ];
    assert_rows(&rows);
}

#[test]
fn source_failures_use_the_source_rows_whether_wrapped_or_not() {
    for source in SOURCES {
        let expected = host_error_for_release_source_v1(source);
        assert!(expected == TSU || expected == INVALID, "{source:?}");
        let outer = host_error_for_install_v1(Install::Source(source));
        let inner = host_error_for_install_v1(src(source));
        assert_eq!(outer, expected, "{source:?}");
        assert_eq!(inner, expected, "{source:?}");
    }
    assert_eq!(host_error_for_release_source_v1(S::NotFound), TSU);
    assert_eq!(host_error_for_release_source_v1(S::DigestMismatch), INVALID);
}

#[test]
fn installer_trust_failures_use_the_authorization_rows() {
    let rows = [
        (auth(Trust::ManifestExpired), EXPIRED),
        (auth(Trust::PublisherKeyRevoked), KEY),
        (auth(Trust::ArtifactRevoked), ARTIFACT),
        (auth(Trust::UnknownPublisherKey), UNTRUSTED),
        (auth(Trust::PluginIdNotGranted), UNTRUSTED),
        // The verifier would call this `Expired`; the authorization rows do not.
        (auth(Trust::Expired), TSU),
        (auth(Trust::InvalidSignature), TSU),
    ];
    assert_rows(&rows);
}

#[test]
fn registry_failures_use_the_registry_rows() {
    let rows = [
        (reg(Reg::ReleaseNotActive), NOT_ACTIVE),
        (reg(Reg::AnchorMismatch), MISMATCH),
        (reg(Reg::PolicyNotAdvanced), MISMATCH),
        // dgr.4: a release that breaks the release chain.
        (reg(Reg::ReleaseChainViolation), TSU),
        (reg(Reg::StorageFailed), TSU),
        (reg(Reg::TrustedTimeRegressed), TSU),
        (reg(Reg::Trust(Trust::ArtifactRevoked)), ARTIFACT),
        (reg(Reg::Trust(Trust::ManifestExpired)), EXPIRED),
    ];
    assert_rows(&rows);
}
