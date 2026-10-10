#![cfg(any(test, feature = "test-support"))]
//! Release drafts, the OCI closure of a draft, and a private local OCI store root.
//!
//! A [`Shape`] says who publishes which Plugin at which version with which
//! Component bytes, validity interval, and signing key epoch. [`make_draft()`]
//! turns one into a complete valid release draft.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use pos_core::OwnerIdV1;
use pos_crypto::plugin_execution::{
    DeterministicBudgetV1, PluginAbiRequirementV1, PluginCapabilityDescriptorV1,
};
use pos_crypto::plugin_manifest::{
    PluginArtifactInputV1, PluginDependencyInputV1, PluginReleaseDraftV1, PluginSchemaInputV1,
};
use pos_plugin_release::{
    build_oci_closure_v1, BundleAddressV1, LocalOciPublisherV1, PublishOutcomeV1,
    ReleaseClosureInputV1, VerifiedReleaseBundleV1,
};
use sha2::{Digest as _, Sha256};

use super::encoding::OWNER;
use super::BoxResult;

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

/// The default Component bytes of a release: a fake that is not a valid WebAssembly Component.
pub const COMPONENT_BYTES: &[u8] = b"\0asm component";
/// A real WebAssembly Component: the compatibility prototype's Rust guest fixture.
pub const REAL_COMPONENT_BYTES: &[u8] = include_bytes!(
    "../../../../plugins/community/examples/compatibility-prototype/fixtures/rust-guest.wasm"
);
const WIT_BYTES: &[u8] = b"wit archive";
const EVENT_SCHEMA: &[u8] = br#"{"$id":"event"}"#;
const STATE_SCHEMA: &[u8] = br#"{"$id":"state"}"#;
const PROVENANCE_BYTES: &[u8] = b"in-toto provenance";
const SBOM_BYTES: &[u8] = b"spdx sbom";
const LICENCE_BYTES: &[u8] = b"licence text";

/// A private temporary directory that holds one local OCI store and is removed
/// on drop.
pub struct PrivateRoot(PathBuf);

impl PrivateRoot {
    /// Create a fresh `0700` directory under the system temporary directory.
    ///
    /// # Errors
    /// Returns the filesystem error.
    pub fn new() -> BoxResult<Self> {
        let root = std::env::temp_dir().join(format!(
            "pigloros-signed-release-world-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        Ok(Self(root))
    }

    /// Open the local OCI store rooted here.
    ///
    /// # Errors
    /// Returns the store open error.
    pub fn store(&self) -> BoxResult<LocalOciPublisherV1> {
        Ok(LocalOciPublisherV1::open(&self.0)?)
    }

    /// The directory path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for PrivateRoot {
    fn drop(&mut self) {
        drop(fs::set_permissions(
            &self.0,
            fs::Permissions::from_mode(0o700),
        ));
        drop(fs::remove_dir_all(&self.0));
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut digest = [0; 32];
    digest.copy_from_slice(&Sha256::digest(bytes));
    digest
}

fn input(bytes: &[u8]) -> PluginArtifactInputV1<'_> {
    PluginArtifactInputV1 {
        bytes,
        sha256: sha256(bytes),
    }
}

fn schema(id: u32, document: &[u8]) -> PluginSchemaInputV1<'_> {
    PluginSchemaInputV1 {
        id,
        version: 1,
        artifact: input(document),
        max_bytes: 65_536,
    }
}

/// One release shape: who publishes which Plugin version, linked to which
/// release, with which Component bytes, validity interval, and key epoch.
#[derive(Clone, Copy)]
pub struct Shape {
    /// The Plugin ID.
    pub plugin_id: &'static str,
    /// The publisher owner.
    pub owner: &'static str,
    /// The release version string.
    pub version: &'static str,
    /// The release digest of the direct predecessor, if any.
    pub previous: Option<[u8; 32]>,
    /// The Component artifact bytes.
    pub component: &'static [u8],
    /// The first UTC second the release is valid.
    pub not_before: i64,
    /// The first UTC second the release is no longer valid.
    pub not_after: i64,
    /// The publisher key epoch that signs the release.
    pub epoch: u64,
    /// Whether the one declared capability is required. A required capability is denied by
    /// negotiation, so a release that a Driver is built from declares it optional.
    pub required_capability: bool,
    /// The deterministic memory budget of the release, in bytes. The default is one page; a
    /// real Component needs more than its initial memory.
    pub memory_bytes: u64,
    /// The highest ABI minor the release declares.
    pub abi_max_minor: u16,
    /// Whether the release requires the `clock` host feature.
    pub clock: bool,
}

impl Shape {
    /// The default first release of `plugin-a`: valid for UTC seconds
    /// `[40, 60)`, signed at epoch 1.
    #[must_use]
    pub const fn first() -> Self {
        Self {
            plugin_id: "plugin-a",
            owner: OWNER,
            version: "1.0.0",
            previous: None,
            component: COMPONENT_BYTES,
            not_before: 40,
            not_after: 60,
            epoch: 1,
            required_capability: true,
            memory_bytes: 65_536,
            abi_max_minor: 1,
            clock: true,
        }
    }

    /// This shape declaring its one capability as optional, so negotiation records it as not
    /// granted instead of denying the release.
    #[must_use]
    pub const fn with_optional_capability(self) -> Self {
        Self {
            required_capability: false,
            ..self
        }
    }

    /// This shape with a deterministic memory budget of `memory_bytes`, a whole number of pages.
    #[must_use]
    pub const fn with_memory_bytes(self, memory_bytes: u64) -> Self {
        Self {
            memory_bytes,
            ..self
        }
    }

    /// This shape declaring only what the V1 host ABI of the real worker provides: ABI 0.0 and
    /// no required feature. The real worker rejects a record negotiated under any wider ABI.
    #[must_use]
    pub const fn with_worker_abi(self) -> Self {
        Self {
            abi_max_minor: 0,
            clock: false,
            ..self
        }
    }

    /// This shape carrying the real WebAssembly Component instead of the fake bytes.
    #[must_use]
    pub const fn with_real_component(self) -> Self {
        Self {
            component: REAL_COMPONENT_BYTES,
            ..self
        }
    }
}

/// A valid draft for `shape`.
///
/// # Errors
/// Returns the owner identifier error.
pub fn make_draft<'a>(shape: Shape) -> BoxResult<PluginReleaseDraftV1<'a>> {
    Ok(PluginReleaseDraftV1 {
        plugin_id: shape.plugin_id.to_owned(),
        release_version: shape.version.to_owned(),
        abi: PluginAbiRequirementV1 {
            major: 0,
            min_minor: 0,
            max_minor: shape.abi_max_minor,
            required_features: if shape.clock {
                vec!["clock".to_owned()]
            } else {
                Vec::new()
            },
        },
        component: input(shape.component),
        wit: input(WIT_BYTES),
        event_schemas: vec![schema(1, EVENT_SCHEMA)],
        state_schema: schema(2, STATE_SCHEMA),
        configuration_schema: None,
        capabilities: vec![PluginCapabilityDescriptorV1 {
            capability_id: "kv".to_owned(),
            operation: "read".to_owned(),
            resource_pattern: "state/*".to_owned(),
            purpose: "Read Plugin state".to_owned(),
            audience: "plugin".to_owned(),
            required: shape.required_capability,
            max_calls: 10,
            max_request_bytes: 1_024,
            max_response_bytes: 2_048,
        }],
        budget: DeterministicBudgetV1 {
            memory_bytes: shape.memory_bytes,
            fuel: 1 << 40,
            host_calls: 256,
            event_count: 24,
            event_bytes: 4_096,
            state_bytes: 4_096,
            log_calls: 24,
            log_bytes: 256,
        },
        dependencies: vec![PluginDependencyInputV1 {
            dependency_id: "dep".to_owned(),
            release_digest: [0x42; 32],
            min_minor: 0,
            max_minor: 0,
            required_features: vec!["clock".to_owned()],
            capability_ids: Vec::new(),
            class: 0,
        }],
        provenance: input(PROVENANCE_BYTES),
        sbom: input(SBOM_BYTES),
        licences: vec![input(LICENCE_BYTES)],
        owner: OwnerIdV1::new(shape.owner)?,
        not_before: shape.not_before,
        not_after: shape.not_after,
        previous_release_digest: shape.previous,
    })
}

/// The OCI closure of `pmf1` and the draft's artifacts, with an explicit
/// component layer so a test can bind a PMF1 to the wrong component bytes.
///
/// # Errors
/// Returns the closure construction error.
pub fn closure(
    draft: &PluginReleaseDraftV1<'_>,
    pmf1: &[u8],
    component: &[u8],
) -> BoxResult<VerifiedReleaseBundleV1> {
    let mut schemas = draft
        .event_schemas
        .iter()
        .map(|schema| schema.artifact.bytes)
        .collect::<Vec<_>>();
    schemas.push(draft.state_schema.artifact.bytes);
    Ok(build_oci_closure_v1(&ReleaseClosureInputV1 {
        pmf1,
        component,
        wit: draft.wit.bytes,
        schemas,
        provenance: draft.provenance.bytes,
        sbom: draft.sbom.bytes,
        licences: draft.licences.iter().map(|item| item.bytes).collect(),
        migration_fixtures: Vec::new(),
    })?)
}

/// The address of a published bundle, whether it was new or already there.
#[must_use]
pub fn address_of(outcome: PublishOutcomeV1) -> BundleAddressV1 {
    match outcome {
        PublishOutcomeV1::Published(address) | PublishOutcomeV1::AlreadyPublished(address) => {
            address
        }
    }
}

/// The BLAKE3 digest of the bundle's PMF1 bytes.
#[must_use]
pub fn pmf1_digest(bundle: &VerifiedReleaseBundleV1) -> [u8; 32] {
    *blake3::hash(bundle.pmf1()).as_bytes()
}
