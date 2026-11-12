//! Fixed artifact traversal after the existing complete-PMF1 validation.

use pos_plugin_release::VerifiedReleaseBundleV1;

use crate::bundle::{
    PluginBundleContentArtifactV1 as Artifact, PluginBundleContentErrorV1 as Error, Refusal,
};
use crate::{validate_plugin_wit_v1, PluginWitContentErrorV1};

impl From<PluginWitContentErrorV1> for Refusal {
    fn from(error: PluginWitContentErrorV1) -> Self {
        match error {
            PluginWitContentErrorV1::BoundsExceeded => Self::BoundsExceeded,
            PluginWitContentErrorV1::UnsupportedFormat => Self::UnsupportedFormat,
            PluginWitContentErrorV1::Malformed => Self::Malformed,
            PluginWitContentErrorV1::ReferenceMismatch => Self::ReferenceMismatch,
        }
    }
}

pub(super) fn validate(bundle: &VerifiedReleaseBundleV1) -> Result<(), Error> {
    // Complete PMF1 validation has established the exact semantic member order,
    // required member presence, list bounds, dual digests and content sizes.
    let component = &bundle.members()[1].digest()[7..];
    for (member, bytes) in bundle.members().iter().zip(bundle.member_bytes()) {
        if member.member() == "wit" {
            validate_plugin_wit_v1(bytes)
                .map_err(|error| Refusal::from(error).at(Artifact::Wit))?;
        }
    }

    let mut documents = Vec::new();
    let mut index = 0_u16;
    for (member, bytes) in bundle.members().iter().zip(bundle.member_bytes()) {
        if member.member().starts_with("schema/") {
            documents.push((index, &member.digest()[7..], bytes));
            index += 1;
        }
    }
    super::schema::validate(&documents)
        .map_err(|(index, error)| error.at(Artifact::Schema { index }))?;

    let mut index = 0_u16;
    for (member, bytes) in bundle.members().iter().zip(bundle.member_bytes()) {
        match member.member() {
            "provenance" => super::json::read(bytes)
                .and_then(|value| super::provenance::validate(&value, component))
                .map_err(|error| error.at(Artifact::Provenance))?,
            "sbom" => super::json::read(bytes)
                .and_then(|value| super::sbom::validate(&value, component))
                .map_err(|error| error.at(Artifact::Sbom))?,
            name if name.starts_with("licence/") => {
                let artifact = Artifact::Licence { index };
                let text =
                    std::str::from_utf8(bytes).map_err(|_| Refusal::Malformed.at(artifact))?;
                if text.contains('\0') || text.trim().is_empty() {
                    return Err(Refusal::Malformed.at(artifact));
                }
                index += 1;
            }
            _ => {}
        }
    }
    Ok(())
}
