use std::path::Path;

use super::image_files::refresh_table_crc;
use super::{isolated_role, FixedCompositionFixture, IsolatedCompositionRole, TestResult};
use crate::provider_admission::tests::request_for;
use crate::provider_admission::ProviderImageSnapshot;
use crate::sandbox_provider_protocol::PartitionDescriptor;
use crate::selector::installation::fixture::{
    admitted_state_with_arguments, admitted_state_with_salt, ddi_fixture, ddi_salt,
    materialize_state, ImageSigning,
};
use crate::selector::installation::{InstalledSelectorState, SANDBOX_ARTIFACT_ROOT};
use crate::selector::SelectorBoundaryError;

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
        assert_public_admission(state, true, |snapshot| {
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
        assert_public_admission(state, true, |snapshot| {
            assert_eq!(snapshot.image().manifest().partitions, *partitions);
        })?;
    }
    Ok(())
}

#[test]
fn held_image_admission_enforces_inclusive_gpt_usable_bounds() -> TestResult {
    const SECTOR: usize = 512;
    if matches!(
        isolated_role(
            "root_selector::tests::admission_bounds::held_image_admission_enforces_inclusive_gpt_usable_bounds"
        )?,
        IsolatedCompositionRole::Delegated
    ) {
        return Ok(());
    }
    for architecture in ["x86-64", "arm64"] {
        let (original, partitions) = ddi_fixture(architecture)?;
        let first = partitions[0].start_bytes / 512;
        let signature = &partitions[2];
        let last = (signature.start_bytes + signature.length_bytes) / 512 - 1;
        for (field, usable, accepted) in [
            (40, first, true),
            (40, first + 1, false),
            (48, last, true),
            (48, last - 1, false),
        ] {
            let mut image = original.clone();
            let backup = image.len() - SECTOR;
            // Keep both tables and all signed partition extents unchanged.
            // Equal header bounds admit the edge partition; moving a bound
            // inward by one sector excludes it without another GPT mismatch.
            for header in [SECTOR, backup] {
                image[header + field..header + field + 8].copy_from_slice(&usable.to_le_bytes());
                refresh_table_crc(&mut image, header, SECTOR)?;
            }
            let state = admitted_state_with_salt(
                &image,
                b"adapter",
                &partitions,
                &ImageSigning::ddi(architecture)?,
                ddi_salt(architecture)?,
            )?;
            assert_public_admission(state, accepted, |snapshot| {
                assert_eq!(snapshot.image().manifest().partitions, partitions);
            })?;
        }
    }
    Ok(())
}

fn assert_public_admission(
    state: InstalledSelectorState,
    accepted: bool,
    check: impl FnOnce(&ProviderImageSnapshot),
) -> TestResult {
    let _paths = FixedCompositionFixture::create()?;
    let installed = materialize_state(Path::new(SANDBOX_ARTIFACT_ROOT), state)?;
    let request = request_for(&installed)?.to_canonical_cbor()?;
    let opened = ProviderImageSnapshot::open(&request);
    if !accepted {
        assert_eq!(opened.err(), Some(SelectorBoundaryError::ArtifactInvalid));
        return Ok(());
    }
    assert!(
        opened.is_ok(),
        "valid bounded image rejected by public snapshot admission: {:?}",
        opened.as_ref().err()
    );
    let snapshot = opened?;
    check(&snapshot);
    snapshot.admit_held_image()?;
    Ok(())
}

/// Retain the real root/hash/proof bytes while extending only the NUL suffix
/// of the signature partition. Both GPT copies and their CRCs stay coherent.
fn pad_signature_partition(
    mut image: Vec<u8>,
    mut partitions: [PartitionDescriptor; 3],
) -> TestResult<(Vec<u8>, [PartitionDescriptor; 3])> {
    const SECTOR: usize = 512;
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
