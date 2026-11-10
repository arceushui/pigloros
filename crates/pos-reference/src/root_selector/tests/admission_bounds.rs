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

/// One GPT edit: its description, whether public admission accepts it, and
/// the edit itself. `GptImage::finish` repairs every CRC afterwards.
type GptCase = (&'static str, bool, fn(&mut GptImage) -> TestResult);

#[test]
fn held_image_admission_enforces_gpt_header_bounds() -> TestResult {
    if matches!(
        isolated_role(
            "root_selector::tests::admission_bounds::held_image_admission_enforces_gpt_header_bounds"
        )?,
        IsolatedCompositionRole::Delegated
    ) {
        return Ok(());
    }
    // Each edit is applied to both headers unless it names one, so only the
    // header bound under test differs from the unchanged fixture geometry.
    let cases: [GptCase; 11] = [
        ("zero disk GUID", false, |gpt| {
            gpt.set(DISK_GUID, &[0; 16]);
            Ok(())
        }),
        ("backup disk GUID differs in its last byte", false, |gpt| {
            let byte = gpt.backup() + DISK_GUID + 15;
            gpt.image[byte] ^= 1;
            Ok(())
        }),
        ("64-byte entries", false, |gpt| {
            gpt.set(ENTRY_SIZE, &64_u32.to_le_bytes());
            Ok(())
        }),
        (
            "first usable LBA 33 inside the primary table",
            false,
            |gpt| {
                gpt.set(FIRST_USABLE, &33_u64.to_le_bytes());
                Ok(())
            },
        ),
        ("first usable LBA 35 after one free sector", true, |gpt| {
            gpt.set(FIRST_USABLE, &35_u64.to_le_bytes());
            Ok(())
        }),
        ("last usable LBA 3253 before one free sector", true, |gpt| {
            gpt.set(LAST_USABLE, &3253_u64.to_le_bytes());
            Ok(())
        }),
        (
            "primary table at LBA 3 overlaps first usable LBA 34",
            false,
            |gpt| gpt.move_table(SECTOR, 3),
        ),
        (
            "64 entries within the 16 KiB minimum reserve",
            true,
            |gpt| {
                gpt.set(ENTRY_COUNT, &64_u32.to_le_bytes());
                Ok(())
            },
        ),
        (
            "64 entries, first usable LBA 33 inside the minimum reserve",
            false,
            |gpt| {
                gpt.set(ENTRY_COUNT, &64_u32.to_le_bytes());
                gpt.set(FIRST_USABLE, &33_u64.to_le_bytes());
                Ok(())
            },
        ),
        (
            "64 entries at backup LBA 3256, last usable LBA 3255 inside the minimum reserve",
            false,
            |gpt| {
                gpt.set(ENTRY_COUNT, &64_u32.to_le_bytes());
                gpt.set(LAST_USABLE, &3255_u64.to_le_bytes());
                gpt.move_table(gpt.backup(), 3256)
            },
        ),
        (
            "backup table at LBA 3254 overlaps last usable LBA 3254",
            false,
            |gpt| gpt.move_table(gpt.backup(), 3254),
        ),
    ];
    let mismatches = gpt_admission_mismatches(&cases)?;
    assert!(mismatches.is_empty(), "{mismatches:#?}");
    Ok(())
}

#[test]
fn held_image_admission_enforces_gpt_entry_bounds() -> TestResult {
    if matches!(
        isolated_role(
            "root_selector::tests::admission_bounds::held_image_admission_enforces_gpt_entry_bounds"
        )?,
        IsolatedCompositionRole::Delegated
    ) {
        return Ok(());
    }
    // Partition tables and signed extents stay unchanged unless an edit
    // names them; equal usable bounds admit the edge partitions.
    let cases: [GptCase; 7] = [
        (
            "256-byte entries put a partition in an extension",
            false,
            |gpt| {
                gpt.set(ENTRY_COUNT, &64_u32.to_le_bytes());
                gpt.set(ENTRY_SIZE, &256_u32.to_le_bytes());
                Ok(())
            },
        ),
        ("256-byte entries, one partition per entry", true, |gpt| {
            gpt.set(ENTRY_COUNT, &64_u32.to_le_bytes());
            gpt.set(ENTRY_SIZE, &256_u32.to_le_bytes());
            for header in gpt.headers() {
                let table = gpt.table_mut(header)?;
                let records = table[..3 * 128].to_vec();
                table[..5 * 128].fill(0);
                for (index, record) in records.chunks_exact(128).enumerate() {
                    table[index * 256..index * 256 + 128].copy_from_slice(record);
                }
            }
            Ok(())
        }),
        ("first usable LBA at the first partition", true, |gpt| {
            gpt.set(FIRST_USABLE, &gpt.first_partition.to_le_bytes());
            Ok(())
        }),
        (
            "first usable LBA one sector into the first partition",
            false,
            |gpt| {
                gpt.set(FIRST_USABLE, &(gpt.first_partition + 1).to_le_bytes());
                Ok(())
            },
        ),
        ("last usable LBA at the last partition", true, |gpt| {
            gpt.set(LAST_USABLE, &gpt.last_partition.to_le_bytes());
            Ok(())
        }),
        (
            "last usable LBA one sector into the last partition",
            false,
            |gpt| {
                gpt.set(LAST_USABLE, &(gpt.last_partition - 1).to_le_bytes());
                Ok(())
            },
        ),
        (
            "signature entry one sector after its signed extent",
            false,
            |gpt| {
                let signature = gpt.signature_partition;
                for header in gpt.headers() {
                    for entry in gpt.table_mut(header)?.chunks_exact_mut(128) {
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
    let mismatches = gpt_admission_mismatches(&cases)?;
    assert!(mismatches.is_empty(), "{mismatches:#?}");
    Ok(())
}

// GPT header field offsets (UEFI 2.10 table 5.21).
const FIRST_USABLE: usize = 40;
const LAST_USABLE: usize = 48;
const DISK_GUID: usize = 56;
const ENTRIES_LBA: usize = 72;
const ENTRY_COUNT: usize = 80;
const ENTRY_SIZE: usize = 84;
const SECTOR: usize = 512;

/// Run every case on both architectures' signed systemd-repart DDI through
/// public snapshot and held-image admission, and describe each case whose
/// outcome differs, so a failure names every affected architecture.
fn gpt_admission_mismatches(cases: &[GptCase]) -> TestResult<Vec<String>> {
    let mut mismatches = Vec::new();
    for architecture in ["x86-64", "arm64"] {
        let (original, partitions) = ddi_fixture(architecture)?;
        assert_tight_gpt(&original, architecture)?;
        for (case, accepted, edit) in cases {
            let mut gpt = GptImage::new(original.clone(), &partitions);
            edit(&mut gpt)?;
            let state = admitted_state_with_salt(
                &gpt.finish()?,
                b"adapter",
                &partitions,
                &ImageSigning::ddi(architecture)?,
                ddi_salt(architecture)?,
            )?;
            let outcome = public_admission(state, |snapshot| {
                assert_eq!(snapshot.image().manifest().partitions, partitions);
            })?;
            let expected = if *accepted {
                Ok(())
            } else {
                Err(SelectorBoundaryError::ArtifactInvalid)
            };
            if outcome != expected {
                mismatches.push(format!(
                    "{architecture}: {case}: expected {expected:?}, public admission {outcome:?}"
                ));
            }
        }
    }
    Ok(mismatches)
}

/// Both fixtures have a last LBA of 3287 and 128 entries of 128 bytes (32
/// sectors) at LBAs 2 and 3255 with usable LBAs 34..=3254, so every reserved
/// area is exactly full and each case's literal LBAs move one bound.
fn assert_tight_gpt(image: &[u8], architecture: &str) -> TestResult {
    assert_eq!(image.len() / SECTOR - 1, 3287, "{architecture}");
    for (header, entries) in [(SECTOR, 2), (image.len() - SECTOR, 3255)] {
        let field = |offset| little_u64(image, header + offset);
        assert_eq!(
            [
                field(FIRST_USABLE)?,
                field(LAST_USABLE)?,
                field(ENTRIES_LBA)?
            ],
            [34, 3254, entries],
            "{architecture}"
        );
        assert_eq!(
            [
                little_u32(image, header + ENTRY_COUNT)?,
                little_u32(image, header + ENTRY_SIZE)?,
            ],
            [128, 128],
            "{architecture}"
        );
    }
    Ok(())
}

/// A DDI image under edit, with its fixture's partition LBAs.
struct GptImage {
    image: Vec<u8>,
    first_partition: u64,
    last_partition: u64,
    signature_partition: u64,
}

impl GptImage {
    fn new(image: Vec<u8>, partitions: &[PartitionDescriptor; 3]) -> Self {
        let signature = &partitions[2];
        Self {
            image,
            first_partition: partitions[0].start_bytes / 512,
            last_partition: (signature.start_bytes + signature.length_bytes) / 512 - 1,
            signature_partition: signature.start_bytes / 512,
        }
    }

    fn backup(&self) -> usize {
        self.image.len() - SECTOR
    }

    fn headers(&self) -> [usize; 2] {
        [SECTOR, self.backup()]
    }

    /// Write one field identically in both headers.
    fn set(&mut self, field: usize, bytes: &[u8]) {
        for header in self.headers() {
            self.image[header + field..header + field + bytes.len()].copy_from_slice(bytes);
        }
    }

    /// One header's partition table, as its current LBA, count and size place it.
    fn table_mut(&mut self, header: usize) -> TestResult<&mut [u8]> {
        let start = usize::try_from(little_u64(&self.image, header + ENTRIES_LBA)?)? * SECTOR;
        let count = little_u32(&self.image, header + ENTRY_COUNT)?;
        let size = little_u32(&self.image, header + ENTRY_SIZE)?;
        let end = start + usize::try_from(count)? * usize::try_from(size)?;
        Ok(&mut self.image[start..end])
    }

    /// Copy one header's table to `lba` and point that header at the copy.
    fn move_table(&mut self, header: usize, lba: u64) -> TestResult {
        let table = self.table_mut(header)?.to_vec();
        let start = usize::try_from(lba)? * SECTOR;
        self.image[start..start + table.len()].copy_from_slice(&table);
        self.image[header + ENTRIES_LBA..header + ENTRIES_LBA + 8]
            .copy_from_slice(&lba.to_le_bytes());
        Ok(())
    }

    /// Repair both tables' and headers' CRCs so only the edited bound differs.
    fn finish(mut self) -> TestResult<Vec<u8>> {
        for header in self.headers() {
            refresh_table_crc(&mut self.image, header, SECTOR)?;
        }
        Ok(self.image)
    }
}

fn public_admission(
    state: InstalledSelectorState,
    check: impl FnOnce(&ProviderImageSnapshot),
) -> TestResult<Result<(), SelectorBoundaryError>> {
    let _paths = FixedCompositionFixture::create()?;
    let installed = materialize_state(Path::new(SANDBOX_ARTIFACT_ROOT), state)?;
    let request = request_for(&installed)?.to_canonical_cbor()?;
    // A local, not a match temporary, so the snapshot drops before the
    // installed state and fixed paths in every edition.
    let opened = ProviderImageSnapshot::open(&request);
    let outcome = match opened {
        Err(error) => Err(error),
        Ok(snapshot) => {
            check(&snapshot);
            let held = snapshot.admit_held_image();
            held.map(|_| ())
        }
    };
    Ok(outcome)
}

fn assert_public_admission(
    state: InstalledSelectorState,
    context: &str,
    check: impl FnOnce(&ProviderImageSnapshot),
) -> TestResult {
    let outcome = public_admission(state, check)?;
    assert!(
        outcome.is_ok(),
        "valid bounded image rejected by public admission: {:?}; {context}",
        outcome.err()
    );
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

fn little_u32(bytes: &[u8], offset: usize) -> TestResult<u32> {
    Ok(u32::from_le_bytes(bytes[offset..offset + 4].try_into()?))
}
