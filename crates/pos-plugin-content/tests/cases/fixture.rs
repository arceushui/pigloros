use pos_core::OwnerIdV1;
use pos_crypto::plugin_execution::{DeterministicBudgetV1, PluginAbiRequirementV1};
use pos_crypto::plugin_manifest::{
    PluginArtifactInputV1, PluginReleaseDraftV1, PluginSchemaInputV1,
};
use pos_plugin_release::{build_oci_closure_v1, ReleaseClosureInputV1, VerifiedReleaseBundleV1};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

pub(super) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const COMPONENT: &[u8] = b"\0asm\x0d\0\x01\0";

pub(super) struct Fixture {
    pub(super) wit: Vec<u8>,
    pub(super) schemas: Vec<Vec<u8>>,
    pub(super) provenance: Vec<u8>,
    pub(super) sbom: Vec<u8>,
    pub(super) licences: Vec<Vec<u8>>,
}

pub(super) fn bytes(value: &Value) -> Vec<u8> {
    value.to_string().into_bytes()
}

pub(super) fn component_digest() -> String {
    hex(&Sha256::digest(COMPONENT))
}

pub(super) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|&byte| {
            [
                char::from(DIGITS[usize::from(byte >> 4)]),
                char::from(DIGITS[usize::from(byte & 15)]),
            ]
        })
        .collect()
}

impl Fixture {
    pub(super) fn new() -> Self {
        Self {
            wit: archive(),
            schemas: vec![b"true".to_vec()],
            provenance: bytes(&json!({
                "_type": "https://in-toto.io/Statement/v1",
                "predicateType": "https://slsa.dev/provenance/v1",
                "subject": [{"digest": {"sha256": component_digest()}}],
                "predicate": {
                    "buildDefinition": {"buildType": "https://example.invalid/build/v1", "externalParameters": {}},
                    "runDetails": {"builder": {"id": "https://example.invalid/self-hosted-builder"}}
                }
            })),
            sbom: bytes(&json!({
                "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
                "name": "test component", "documentNamespace": "https://example.invalid/spdx/test-v1",
                "creationInfo": {"creators": ["Tool: PiglorOS test fixture"], "created": "2026-11-01T00:00:00Z"},
                "documentDescribes": ["SPDXRef-component"],
                "packages": [{
                    "SPDXID": "SPDXRef-component", "name": "test-component", "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": false, "licenseConcluded": "MIT", "licenseDeclared": "MIT",
                    "copyrightText": "NOASSERTION", "checksums": [{"algorithm": "SHA256", "checksumValue": component_digest()}]
                }]
            })),
            licences: vec![b"MIT licence text fixture\n".to_vec()],
        }
    }

    pub(super) fn bundle(&self) -> TestResult<VerifiedReleaseBundleV1> {
        let event_schemas = self
            .schemas
            .iter()
            .enumerate()
            .skip(1)
            .map(|(index, value)| schema(index, value))
            .collect::<Result<_, _>>()?;
        let draft = PluginReleaseDraftV1 {
            plugin_id: "content-fixture".to_owned(),
            release_version: "1.0.0".to_owned(),
            abi: PluginAbiRequirementV1 {
                major: 0,
                min_minor: 0,
                max_minor: 0,
                required_features: Vec::new(),
            },
            component: artifact(COMPONENT),
            wit: artifact(&self.wit),
            event_schemas,
            state_schema: schema(0, &self.schemas[0])?,
            configuration_schema: None,
            capabilities: Vec::new(),
            budget: DeterministicBudgetV1::MINIMA,
            dependencies: Vec::new(),
            provenance: artifact(&self.provenance),
            sbom: artifact(&self.sbom),
            licences: self.licences.iter().map(|data| artifact(data)).collect(),
            owner: OwnerIdV1::new("publisher")?,
            not_before: 40,
            not_after: 60,
            previous_release_digest: None,
        };
        let pmf1 = draft.unsigned()?.with_signature(1, [0; 64])?;
        build_oci_closure_v1(&ReleaseClosureInputV1 {
            pmf1: &pmf1,
            component: COMPONENT,
            wit: &self.wit,
            schemas: self.schemas.iter().map(Vec::as_slice).collect(),
            provenance: &self.provenance,
            sbom: &self.sbom,
            licences: self.licences.iter().map(Vec::as_slice).collect(),
            migration_fixtures: Vec::new(),
        })
        .map_err(Into::into)
    }

    pub(super) fn bundle_with_invalid_manifest(&self) -> TestResult<VerifiedReleaseBundleV1> {
        Ok(build_oci_closure_v1(&ReleaseClosureInputV1 {
            pmf1: b"not a PMF1",
            component: COMPONENT,
            wit: &self.wit,
            schemas: self.schemas.iter().map(Vec::as_slice).collect(),
            provenance: &self.provenance,
            sbom: &self.sbom,
            licences: self.licences.iter().map(Vec::as_slice).collect(),
            migration_fixtures: Vec::new(),
        })?)
    }

    pub(super) fn provenance(&mut self, change: impl FnOnce(&mut Value)) -> TestResult {
        let mut value = serde_json::from_slice(&self.provenance)?;
        change(&mut value);
        self.provenance = bytes(&value);
        Ok(())
    }

    pub(super) fn sbom(&mut self, change: impl FnOnce(&mut Value)) -> TestResult {
        let mut value = serde_json::from_slice(&self.sbom)?;
        change(&mut value);
        self.sbom = bytes(&value);
        Ok(())
    }
}

fn artifact(bytes: &[u8]) -> PluginArtifactInputV1<'_> {
    PluginArtifactInputV1 {
        bytes,
        sha256: Sha256::digest(bytes).into(),
    }
}

fn schema(index: usize, data: &[u8]) -> TestResult<PluginSchemaInputV1<'_>> {
    Ok(PluginSchemaInputV1 {
        id: u32::try_from(index + 1)?,
        version: 1,
        artifact: artifact(data),
        max_bytes: 1_048_576,
    })
}

fn archive() -> Vec<u8> {
    let source = b"package pigloros:plugin@0.1.0; world community-plugin {}";
    let mut header = [0; 512];
    header[..8].copy_from_slice(b"main.wit");
    header[100..108].copy_from_slice(b"0000644\0");
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
    header[124..136].copy_from_slice(format!("{:011o}\0", source.len()).as_bytes());
    header[136..148].copy_from_slice(b"00000000000\0");
    header[148..156].fill(b' ');
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum: usize = header.iter().map(|byte| usize::from(*byte)).sum();
    header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
    let mut result = header.to_vec();
    result.extend_from_slice(source);
    result.resize(2048, 0);
    result
}
