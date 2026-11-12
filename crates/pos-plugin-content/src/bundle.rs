//! A bound result exists only after every required artifact passes.

mod checks;
mod json;
mod provenance;
mod sbom;
mod schema;

use pos_crypto::plugin_execution::PluginExecutionProjectionV1;
use pos_crypto::plugin_manifest::PluginManifestErrorV1;
use pos_plugin_release::VerifiedReleaseBundleV1;
use thiserror::Error;

/// The artifact's role and index in the verified closure's semantic order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PluginBundleContentArtifactV1 {
    /// The sole WIT archive.
    Wit,
    /// A declared schema, indexed among schema members only.
    Schema { index: u16 },
    /// The in-toto/SLSA provenance statement.
    Provenance,
    /// The SPDX document.
    Sbom,
    /// A licence text, indexed among licence members only.
    Licence { index: u16 },
}

/// Closed refusals, without artifact text, paths or parser diagnostics.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PluginBundleContentErrorV1 {
    /// Complete PMF1/closure validation failed before content interpretation.
    #[error("invalid content manifest: {0}")]
    Manifest(PluginManifestErrorV1),
    /// A fixed decoding or indexing budget was exhausted.
    #[error("content bound exceeded: {artifact:?}")]
    BoundsExceeded {
        artifact: PluginBundleContentArtifactV1,
    },
    /// The artifact uses a format outside the fixed profile.
    #[error("unsupported content format: {artifact:?}")]
    UnsupportedFormat {
        artifact: PluginBundleContentArtifactV1,
    },
    /// Content syntax or a required field is malformed.
    #[error("malformed content: {artifact:?}")]
    Malformed {
        artifact: PluginBundleContentArtifactV1,
    },
    /// A required identity or reference does not resolve.
    #[error("content reference differs: {artifact:?}")]
    ReferenceMismatch {
        artifact: PluginBundleContentArtifactV1,
    },
}

#[derive(Clone, Copy)]
enum Refusal {
    BoundsExceeded,
    UnsupportedFormat,
    Malformed,
    ReferenceMismatch,
}

impl Refusal {
    const fn at(self, artifact: PluginBundleContentArtifactV1) -> PluginBundleContentErrorV1 {
        match self {
            Self::BoundsExceeded => PluginBundleContentErrorV1::BoundsExceeded { artifact },
            Self::UnsupportedFormat => PluginBundleContentErrorV1::UnsupportedFormat { artifact },
            Self::Malformed => PluginBundleContentErrorV1::Malformed { artifact },
            Self::ReferenceMismatch => PluginBundleContentErrorV1::ReferenceMismatch { artifact },
        }
    }
}

/// Complete basic package checks bound to one exact verified release closure.
///
/// This is content evidence, not publisher trust, signature verification,
/// legal clearance, Component execution or an installation/launch authority.
/// There is no public constructor or deserializer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedPluginBundleContentV1 {
    pmf1_digest: [u8; 32],
    release_digest: [u8; 32],
    rule: &'static str,
}

impl ValidatedPluginBundleContentV1 {
    /// The complete canonical PMF1 digest.
    #[must_use]
    pub const fn pmf1_digest(&self) -> [u8; 32] {
        self.pmf1_digest
    }

    /// The PMF1 release digest.
    #[must_use]
    pub const fn release_digest(&self) -> [u8; 32] {
        self.release_digest
    }

    /// The fixed interpretation rule applied by this evidence.
    #[must_use]
    pub const fn rule(&self) -> &'static str {
        self.rule
    }
}

/// Check every required artifact using the fixed offline `BasicPackageV1` rule.
///
/// Complete PMF1 validation precedes WIT, schemas in closure order, provenance,
/// SBOM and licences in closure order. No retrieval, extraction, clock, guest
/// execution, registry mutation or configurable policy is involved.
///
/// # Errors
/// Returns the first closed content refusal and no bound evidence.
pub fn validate_plugin_bundle_content_v1(
    bundle: &VerifiedReleaseBundleV1,
) -> Result<ValidatedPluginBundleContentV1, PluginBundleContentErrorV1> {
    let projection = PluginExecutionProjectionV1::from_verified_bundle(bundle)
        .map_err(PluginBundleContentErrorV1::Manifest)?;
    checks::validate(bundle)?;
    Ok(ValidatedPluginBundleContentV1 {
        pmf1_digest: projection.pmf1_digest(),
        release_digest: projection.release_digest(),
        rule: "BasicPackageV1",
    })
}
