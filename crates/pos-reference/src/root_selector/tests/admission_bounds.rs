use std::path::Path;

use super::{isolated_role, FixedCompositionFixture, IsolatedCompositionRole, TestResult};
use crate::provider_admission::tests::request_for;
use crate::provider_admission::ProviderImageSnapshot;
use crate::sandbox_provider_protocol::PartitionDescriptor;
use crate::selector::installation::fixture::{
    admitted_state_with_arguments, admitted_state_with_salt, ddi_fixture, ddi_salt,
    materialize_state, ImageSigning,
};
use crate::selector::installation::tests::refresh_table_crc;
use crate::selector::installation::{InstalledSelectorState, SANDBOX_ARTIFACT_ROOT};
use crate::selector::SelectorBoundaryError;

const SECTOR: usize = 512;

#[test]
fn held_image_admission_accepts_full_length_arguments() -> TestResult {
    if matches!(
        isolated_role(
            "root_selector::tests::admission_bounds::held_image_admission_accepts_full_length_arguments"
        )?,
        IsolatedCompositionRole::Delegated
    ) {
        return Ok(());
    }
    let (image, partitions) = ddi_fixture("x86-64")?;
    let arguments = vec!["x".repeat(256); 256];
    for arguments in [&[][..], arguments.as_slice()] {
        let state = admitted_state_with_arguments(
            &image,
            b"adapter",
            &partitions,
            &ImageSigning::ddi("x86-64")?,
            ddi_salt("x86-64")?,
            arguments,
        )?;
        assert_public_admission(state, "full-length arguments", |snapshot| {
            assert_eq!(snapshot.image().manifest().arguments.as_slice(), arguments);
        })?;
    }
    Ok(())
}

#[test]
fn held_image_admission_accepts_two_mib_signature_partition() -> TestResult {
    if matches!(
        isolated_role(
            "root_selector::tests::admission_bounds::held_image_admission_accepts_two_mib_signature_partition"
        )?,
        IsolatedCompositionRole::Delegated
    ) {
        return Ok(());
    }
    let (image, partitions) = ddi_fixture("x86-64")?;
    let padded = pad_signature_partition(image.clone(), partitions.clone())?;
    assert_eq!(padded.1[2].length_bytes, 2_097_152);
    for (image, partitions) in [(&image, &partitions), (&padded.0, &padded.1)] {
        let state = admitted_state_with_salt(
            image,
            b"adapter",
            partitions,
            &ImageSigning::ddi("x86-64")?,
            ddi_salt("x86-64")?,
        )?;
        assert_public_admission(state, "signature partition length", |snapshot| {
            assert_eq!(snapshot.image().manifest().partitions, *partitions);
        })?;
    }
    Ok(())
}

#[test]
fn snapshot_open_enforces_gpt_bounds_on_both_architectures() -> TestResult {
    if matches!(
        isolated_role(
            "root_selector::tests::admission_bounds::snapshot_open_enforces_gpt_bounds_on_both_architectures"
        )?,
        IsolatedCompositionRole::Delegated
    ) {
        return Ok(());
    }
    // `image_gpt` unit tests cover each bound; this proves the public open
    // seam itself enforces one header and one entry bound on both signed
    // architectures, after the unchanged image is admitted end to end.
    let mut mismatches = Vec::new();
    for architecture in ["x86-64", "arm64"] {
        let (original, partitions) = ddi_fixture(architecture)?;
        let cases: [(&str, bool, fn(&mut [u8], u64) -> TestResult); 3] = [
            ("unchanged image", true, |_, _| Ok(())),
            ("zero disk GUID in both headers", false, |image, _| {
                let backup = image.len() - SECTOR;
                for header in [SECTOR, backup] {
                    image[header + 56..header + 72].fill(0);
                }
                Ok(())
            }),
            (
                "signature entry one sector after its signed extent",
                false,
                |image, signature| {
                    let backup = image.len() - SECTOR;
                    for header in [SECTOR, backup] {
                        let table = usize::try_from(little_u64(image, header + 72)?)? * SECTOR;
                        // Both fixtures hold 128 entries of 128 bytes.
                        for entry in image[table..table + 128 * 128].chunks_exact_mut(128) {
                            if little_u64(entry, 32)? == signature {
                                let last = little_u64(entry, 40)?;
                                entry[32..40].copy_from_slice(&(signature + 1).to_le_bytes());
                                entry[40..48].copy_from_slice(&(last + 1).to_le_bytes());
                            }
                        }
                    }
                    Ok(())
                },
            ),
        ];
        for (case, accepted, edit) in cases {
            let expected = if accepted {
                Ok(())
            } else {
                Err(SelectorBoundaryError::ArtifactInvalid)
            };
            match snapshot_open(architecture, &original, &partitions, edit) {
                Ok(outcome) if outcome == expected => {}
                Ok(outcome) => mismatches.push(format!(
                    "{architecture}: {case}: expected {expected:?}, snapshot open {outcome:?}"
                )),
                Err(error) => mismatches.push(format!("{architecture}: {case}: {error}")),
            }
        }
    }
    assert!(mismatches.is_empty(), "{mismatches:#?}");
    Ok(())
}

/// Edit a copy of one architecture's DDI, repair both GPT copies' CRCs, and
/// open it through the public snapshot seam. An accepted snapshot must also
/// pass held-image admission.
fn snapshot_open(
    architecture: &str,
    original: &[u8],
    partitions: &[PartitionDescriptor; 3],
    edit: fn(&mut [u8], u64) -> TestResult,
) -> TestResult<Result<(), SelectorBoundaryError>> {
    let mut image = original.to_vec();
    edit(
        &mut image,
        partitions[2].start_bytes / u64::try_from(SECTOR)?,
    )?;
    let backup = image.len() - SECTOR;
    for header in [SECTOR, backup] {
        refresh_table_crc(&mut image, header, SECTOR)?;
    }
    let state = admitted_state_with_salt(
        &image,
        b"adapter",
        partitions,
        &ImageSigning::ddi(architecture)?,
        ddi_salt(architecture)?,
    )?;
    open_installed(state, |opened| {
        Ok(match opened {
            Err(error) => Err(error),
            Ok(snapshot) => {
                assert_eq!(snapshot.image().manifest().partitions, *partitions);
                snapshot.admit_held_image()?;
                Ok(())
            }
        })
    })
}

fn assert_public_admission(
    state: InstalledSelectorState,
    context: &str,
    check: impl FnOnce(&ProviderImageSnapshot),
) -> TestResult {
    open_installed(state, |opened| {
        assert!(
            opened.is_ok(),
            "valid bounded image rejected by public snapshot admission: {:?}; {context}",
            opened.as_ref().err()
        );
        let snapshot = opened?;
        check(&snapshot);
        snapshot.admit_held_image()?;
        Ok(())
    })
}

/// Stage `state` at the fixed installation paths, open its snapshot through
/// the public seam and hand the outcome to `inspect`. The snapshot is a local
/// moved into `inspect`, so it drops before the installed state and paths.
fn open_installed<T>(
    state: InstalledSelectorState,
    inspect: impl FnOnce(Result<ProviderImageSnapshot, SelectorBoundaryError>) -> TestResult<T>,
) -> TestResult<T> {
    let _paths = FixedCompositionFixture::create()?;
    let installed = materialize_state(Path::new(SANDBOX_ARTIFACT_ROOT), state)?;
    let request = request_for(&installed)?.to_canonical_cbor()?;
    let opened = ProviderImageSnapshot::open(&request);
    inspect(opened)
}

/// Retain the real root/hash/proof bytes while extending only the NUL suffix
/// of the signature partition. Both GPT copies and their CRCs stay coherent.
fn pad_signature_partition(
    mut image: Vec<u8>,
    mut partitions: [PartitionDescriptor; 3],
) -> TestResult<(Vec<u8>, [PartitionDescriptor; 3])> {
    let signature = &mut partitions[2];
    let growth = 2 * 1024 * 1024 - usize::try_from(signature.length_bytes)?;
    let end = usize::try_from(signature.start_bytes + signature.length_bytes)?;
    drop(image.splice(end..end, std::iter::repeat_n(0, growth)));
    let last_lba = u64::try_from(image.len() / SECTOR - 1)?;
    let growth_lbas = u64::try_from(growth / SECTOR)?;
    image[458..462].copy_from_slice(&u32::try_from(last_lba)?.to_le_bytes());
    let backup = image.len() - SECTOR;
    image[SECTOR + 32..SECTOR + 40].copy_from_slice(&last_lba.to_le_bytes());
    image[backup + 24..backup + 32].copy_from_slice(&last_lba.to_le_bytes());
    let entries = little_u64(&image, backup + 72)? + growth_lbas;
    image[backup + 72..backup + 80].copy_from_slice(&entries.to_le_bytes());
    signature.length_bytes = 2 * 1024 * 1024;
    let signature_last = (signature.start_bytes + signature.length_bytes) / 512 - 1;
    for header in [SECTOR, backup] {
        let usable = little_u64(&image, header + 48)? + growth_lbas;
        image[header + 48..header + 56].copy_from_slice(&usable.to_le_bytes());
        let entries = usize::try_from(little_u64(&image, header + 72)?)? * SECTOR;
        // This source fixture has 128 GPT entries of 128 bytes each.
        let table = &mut image[entries..entries + 128 * 128];
        for entry in table.chunks_exact_mut(128) {
            if little_u64(entry, 32)? == signature.start_bytes / 512 {
                entry[40..48].copy_from_slice(&signature_last.to_le_bytes());
            }
        }
        refresh_table_crc(&mut image, header, SECTOR)?;
    }
    let start = usize::try_from(signature.start_bytes)?;
    let end = usize::try_from(signature.start_bytes + signature.length_bytes)?;
    signature.content_blake3_digest = *blake3::hash(&image[start..end]).as_bytes();
    Ok((image, partitions))
}

fn little_u64(bytes: &[u8], offset: usize) -> TestResult<u64> {
    Ok(u64::from_le_bytes(bytes[offset..offset + 8].try_into()?))
}
