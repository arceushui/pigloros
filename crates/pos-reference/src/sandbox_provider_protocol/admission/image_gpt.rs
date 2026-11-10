//! Read-only GPT/SIM1 comparison; no dissection, repair or activation authority.
//!
//! Layout and CRC fields follow UEFI 2.10 chapter 5. Sector probing follows
//! systemd v260.2's `probe_sector_size`, including ambiguous-header rejection.

use std::fs::File;
use std::os::unix::fs::FileExt as _;

use flate2::Crc;

use super::{SandboxAdmissionError, SignedImageManifest};

const INVALID: SandboxAdmissionError = SandboxAdmissionError::ArtifactMismatch;
const GPT_SIGNATURE: &[u8; 8] = b"EFI PART";

#[derive(Eq, PartialEq)]
struct TableLayout {
    first_usable: u64,
    last_usable: u64,
    disk_guid: [u8; 16],
    count: u32,
    entry_size: u32,
}

struct Header {
    layout: TableLayout,
    entries: u64,
    crc: u32,
}

pub(super) fn verify(
    file: &File,
    image: &SignedImageManifest,
) -> Result<(), SandboxAdmissionError> {
    let mut probe = [0_u8; 8192];
    read_at(file, &mut probe, 0)?;
    let mut sectors = [512_usize, 1024, 2048, 4096]
        .into_iter()
        .filter(|offset| &probe[*offset..*offset + 8] == GPT_SIGNATURE);
    let sector = sectors.next().ok_or(INVALID)?;
    if sectors.next().is_some() || !image.root_image_length.is_multiple_of(sector as u64) {
        return Err(INVALID);
    }
    let last_lba = image.root_image_length / sector as u64 - 1;
    verify_mbr(&probe[..512], last_lba)?;
    let primary = read_header(file, sector, last_lba, true)?;
    let backup = read_header(file, sector, last_lba, false)?;
    if primary.layout != backup.layout {
        return Err(INVALID);
    }
    let primary_digest = verify_entries(file, &primary, sector as u64, image)?;
    let backup_digest = verify_entries(file, &backup, sector as u64, image)?;
    if primary_digest != backup_digest {
        return Err(INVALID);
    }
    for partition in &image.partitions {
        let mut hash = blake3::Hasher::new();
        read_range(
            file,
            partition.start_bytes,
            partition.length_bytes,
            |bytes| {
                hash.update(bytes);
                Ok(())
            },
        )?;
        if hash.finalize().as_bytes() != &partition.content_blake3_digest {
            return Err(INVALID);
        }
    }
    Ok(())
}

fn verify_mbr(bytes: &[u8], last_lba: u64) -> Result<(), SandboxAdmissionError> {
    if bytes[510..512] != [0x55, 0xaa] {
        return Err(INVALID);
    }
    let mut protective = false;
    for entry in bytes[446..510].chunks_exact(16) {
        if entry.iter().all(|byte| *byte == 0) {
            continue;
        }
        if protective
            || entry[0] != 0
            || entry[4] != 0xee
            || le32(entry, 8) != 1
            || u64::from(le32(entry, 12)) != last_lba.min(u64::from(u32::MAX))
        {
            return Err(INVALID);
        }
        protective = true;
    }
    if !protective {
        return Err(INVALID);
    }
    Ok(())
}

fn read_header(
    file: &File,
    sector: usize,
    last_lba: u64,
    primary: bool,
) -> Result<Header, SandboxAdmissionError> {
    let (current, alternate) = if primary {
        (1, last_lba)
    } else {
        (last_lba, 1)
    };
    let mut bytes = vec![0_u8; sector];
    read_at(file, &mut bytes, current * sector as u64)?;
    let size = u64::from(le32(&bytes, 12));
    if &bytes[..8] != GPT_SIGNATURE
        || le32(&bytes, 8) != 0x0001_0000
        || !(92..=sector as u64).contains(&size)
        || le32(&bytes, 20) != 0
        || le64(&bytes, 24) != current
        || le64(&bytes, 32) != alternate
        || bytes[92..].iter().any(|byte| *byte != 0)
    {
        return Err(INVALID);
    }
    let expected_crc = le32(&bytes, 16);
    bytes[16..20].fill(0);
    let mut crc = Crc::new();
    // Header size was bounded by the small sector buffer above.
    crc.update(&bytes[..usize::try_from(size).unwrap_or(bytes.len())]);
    if crc.sum() != expected_crc {
        return Err(INVALID);
    }
    let header = Header {
        layout: TableLayout {
            first_usable: le64(&bytes, 40),
            last_usable: le64(&bytes, 48),
            disk_guid: std::array::from_fn(|index| bytes[56 + index]),
            count: le32(&bytes, 80),
            entry_size: le32(&bytes, 84),
        },
        entries: le64(&bytes, 72),
        crc: le32(&bytes, 88),
    };
    header.validate_bounds(sector as u64, last_lba, primary)?;
    Ok(header)
}

impl Header {
    fn validate_bounds(
        &self,
        sector: u64,
        last_lba: u64,
        primary: bool,
    ) -> Result<(), SandboxAdmissionError> {
        let layout = &self.layout;
        let table_bytes = u64::from(layout.count) * u64::from(layout.entry_size);
        let blocks = table_bytes.div_ceil(sector);
        let reserved = table_bytes.max(16 * 1024).div_ceil(sector);
        if layout.count == 0
            || layout.entry_size < 128
            || !layout.entry_size.is_power_of_two()
            || layout.disk_guid == [0; 16]
            || layout.first_usable > layout.last_usable
            || layout.first_usable < 2 + reserved
            || layout.last_usable >= last_lba
            || reserved > last_lba - layout.last_usable - 1
        {
            return Err(INVALID);
        }
        let (start, end) = if primary {
            (2, layout.first_usable)
        } else {
            (layout.last_usable + 1, last_lba)
        };
        if self.entries < start || self.entries > end || blocks > end - self.entries {
            return Err(INVALID);
        }
        Ok(())
    }
}

fn verify_entries(
    file: &File,
    header: &Header,
    sector: u64,
    image: &SignedImageManifest,
) -> Result<[u8; 32], SandboxAdmissionError> {
    let mut crc = Crc::new();
    let mut hash = blake3::Hasher::new();
    let mut seen = [false; 3];
    let mut position = 0_u64;
    read_range(
        file,
        header.entries * sector,
        u64::from(header.layout.count) * u64::from(header.layout.entry_size),
        |bytes| {
            crc.update(bytes);
            hash.update(bytes);
            // Both entry size and read buffer are multiples of the 128-byte
            // base record, so a base record never straddles a read chunk.
            for record in bytes.chunks_exact(128) {
                if position.is_multiple_of(u64::from(header.layout.entry_size)) {
                    verify_entry(record, &header.layout, sector, image, &mut seen)?;
                } else if record.iter().any(|byte| *byte != 0) {
                    return Err(INVALID);
                }
                position += 128;
            }
            Ok(())
        },
    )?;
    if seen != [true; 3] || crc.sum() != header.crc {
        return Err(INVALID);
    }
    Ok(*hash.finalize().as_bytes())
}

fn verify_entry(
    entry: &[u8],
    layout: &TableLayout,
    sector: u64,
    image: &SignedImageManifest,
    seen: &mut [bool; 3],
) -> Result<(), SandboxAdmissionError> {
    if entry[..16] == [0; 16] {
        return Ok(());
    }
    let id = guid(&entry[16..32]);
    let ordinal = image
        .partitions
        .iter()
        .position(|p| p.partition_instance_uuid == id)
        .ok_or(INVALID)?;
    let partition = &image.partitions[ordinal];
    let first = le64(entry, 32);
    let last = le64(entry, 40);
    if seen[ordinal]
        || guid(&entry[..16]) != partition.partition_type_uuid
        || le64(entry, 48) & 0x0000_ffff_ffff_fff8 != 0
        || first < layout.first_usable
        || first > last
        || last > layout.last_usable
        || first * sector != partition.start_bytes
        || (last - first + 1) * sector != partition.length_bytes
    {
        return Err(INVALID);
    }
    seen[ordinal] = true;
    Ok(())
}

fn read_range(
    file: &File,
    mut offset: u64,
    mut remaining: u64,
    mut consume: impl FnMut(&[u8]) -> Result<(), SandboxAdmissionError>,
) -> Result<(), SandboxAdmissionError> {
    let mut buffer = vec![0_u8; 64 * 1024];
    while remaining > 0 {
        let count = usize::try_from(remaining)
            .unwrap_or(buffer.len())
            .min(buffer.len());
        read_at(file, &mut buffer[..count], offset)?;
        consume(&buffer[..count])?;
        remaining -= count as u64;
        offset += count as u64;
    }
    Ok(())
}

fn le32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(std::array::from_fn(|index| bytes[offset + index]))
}

fn le64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(std::array::from_fn(|index| bytes[offset + index]))
}

fn guid(bytes: &[u8]) -> [u8; 16] {
    let mut result = std::array::from_fn(|index| bytes[index]);
    result[..4].reverse();
    result[4..6].reverse();
    result[6..8].reverse();
    result
}

fn io_error(_: std::io::Error) -> SandboxAdmissionError {
    INVALID
}

fn read_at(file: &File, bytes: &mut [u8], offset: u64) -> Result<(), SandboxAdmissionError> {
    #[cfg(test)]
    if crate::image_read_fault::take(file, offset) {
        return Err(INVALID);
    }
    file.read_exact_at(bytes, offset).map_err(io_error)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::io::Write as _;

    use super::*;
    use crate::sandbox_provider_protocol::{Pkcs7Proof, SandboxArchitecture};

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    // Only the length and partition table are read by GPT admission.
    fn layout_manifest(
        architecture: SandboxArchitecture,
        image: &[u8],
        partitions: [crate::sandbox_provider_protocol::PartitionDescriptor; 3],
    ) -> TestResult<SignedImageManifest> {
        Ok(SignedImageManifest {
            image_id: "systemd-repart-ddi".to_owned(),
            architecture,
            root_image_length: u64::try_from(image.len())?,
            root_image_blake3_digest: *blake3::hash(image).as_bytes(),
            partitions,
            root_hash_sha256: [1; 32],
            verity_salt: [1; 32],
            root_hash_signature: Pkcs7Proof {
                der_length: 1,
                der_sha256: [1; 32],
                der_bytes: vec![0],
            },
            signing_certificate_sha256: [1; 32],
            kernel_key_description: "PiglorOS fixture: 01".to_owned(),
            executable_path: "/usr/bin/adapter".to_owned(),
            executable_blake3_digest: [1; 32],
            arguments: Vec::new(),
            image_trust_epoch: 1,
            image_project_key_id: "image".to_owned(),
            manifest_digest: [1; 32],
            signature: [1; 64],
        })
    }

    #[test]
    fn systemd_repart_layouts_pass_gpt_admission_on_both_architectures() -> TestResult {
        for (name, architecture) in [
            ("x86-64", SandboxArchitecture::X86_64),
            ("arm64", SandboxArchitecture::Aarch64),
        ] {
            let (image, partitions) = crate::selector::installation::tests::ddi_fixture(name)?;
            let mut file = tempfile::tempfile()?;
            file.write_all(&image)?;
            let mut manifest = layout_manifest(architecture, &image, partitions)?;
            verify(&file, &manifest)?;
            manifest.partitions[2].content_blake3_digest[0] ^= 1;
            assert!(verify(&file, &manifest).is_err());
        }
        Ok(())
    }

    // GPT header field offsets (UEFI 2.10 table 5.21).
    const SECTOR: usize = 512;
    const FIRST_USABLE: usize = 40;
    const LAST_USABLE: usize = 48;
    const DISK_GUID: usize = 56;
    const ENTRIES_LBA: usize = 72;
    const ENTRY_COUNT: usize = 80;
    const ENTRY_SIZE: usize = 84;
    const TABLE_CRC: usize = 88;

    /// One GPT edit: its description, whether admission accepts it, and the
    /// edit itself. `GptImage::finish` repairs every CRC afterwards.
    type GptCase = (&'static str, bool, fn(&mut GptImage) -> TestResult);

    #[test]
    fn usable_range_rejects_inversion_but_admits_a_single_lba() {
        let header = |first_usable, last_usable| Header {
            layout: TableLayout {
                first_usable,
                last_usable,
                disk_guid: [1; 16],
                count: 128,
                entry_size: 128,
            },
            entries: 2,
            crc: 0,
        };
        // Every other bound holds with room to spare for both headers.
        assert_eq!(header(100, 100).validate_bounds(512, 3287, true), Ok(()));
        assert_eq!(
            header(100, 50).validate_bounds(512, 3287, true),
            Err(INVALID)
        );
        assert_eq!(
            header(100, 99).validate_bounds(512, 3287, true),
            Err(INVALID)
        );
    }

    #[test]
    fn gpt_header_bounds_follow_both_systemd_repart_layouts() -> TestResult {
        // Each edit applies to both headers unless it names one, so only the
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
        let mismatches = gpt_mismatches(&cases)?;
        assert!(mismatches.is_empty(), "{mismatches:#?}");
        Ok(())
    }

    #[test]
    fn gpt_entry_bounds_follow_both_systemd_repart_layouts() -> TestResult {
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
                |gpt| gpt.shift_signature_entry(),
            ),
        ];
        let mismatches = gpt_mismatches(&cases)?;
        assert!(mismatches.is_empty(), "{mismatches:#?}");
        Ok(())
    }

    /// Run every case through `verify` on both architectures' systemd-repart
    /// DDI and describe each case whose outcome differs or whose edit fails,
    /// so a failure names every affected architecture and case.
    fn gpt_mismatches(cases: &[GptCase]) -> TestResult<Vec<String>> {
        let mut mismatches = Vec::new();
        for (name, architecture) in [
            ("x86-64", SandboxArchitecture::X86_64),
            ("arm64", SandboxArchitecture::Aarch64),
        ] {
            let (original, partitions) = crate::selector::installation::tests::ddi_fixture(name)?;
            assert_tight_gpt(&original, &partitions, name)?;
            let manifest = layout_manifest(architecture, &original, partitions.clone())?;
            for (case, accepted, edit) in cases {
                let expected = if *accepted { Ok(()) } else { Err(INVALID) };
                let outcome = run_case(&original, &partitions, &manifest, *edit);
                match outcome {
                    Ok(outcome) if outcome == expected => {}
                    Ok(outcome) => mismatches.push(format!(
                        "{name}: {case}: expected {expected:?}, verify {outcome:?}"
                    )),
                    Err(error) => mismatches.push(format!("{name}: {case}: {error}")),
                }
            }
        }
        Ok(mismatches)
    }

    /// Apply one edit to a copy of the fixture and verify it as a file.
    fn run_case(
        original: &[u8],
        partitions: &[crate::sandbox_provider_protocol::PartitionDescriptor; 3],
        manifest: &SignedImageManifest,
        edit: fn(&mut GptImage) -> TestResult,
    ) -> TestResult<Result<(), SandboxAdmissionError>> {
        let mut gpt = GptImage::new(original.to_vec(), partitions);
        edit(&mut gpt)?;
        let mut file = tempfile::tempfile()?;
        file.write_all(&gpt.finish()?)?;
        Ok(verify(&file, manifest))
    }

    /// Both fixtures have a last LBA of 3287 and 128 entries of 128 bytes (32
    /// sectors) at LBAs 2 and 3255 with usable LBAs 34..=3254, so every
    /// reserved area is exactly full and each case's literal LBAs move one
    /// bound. Partitions span LBAs 35..=3253 at most, leaving the free sector
    /// the accept cases and the signature shift rely on.
    fn assert_tight_gpt(
        image: &[u8],
        partitions: &[crate::sandbox_provider_protocol::PartitionDescriptor; 3],
        architecture: &str,
    ) -> TestResult {
        assert_eq!(image.len() / SECTOR - 1, 3287, "{architecture}");
        for (header, entries) in [(SECTOR, 2), (image.len() - SECTOR, 3255)] {
            assert_eq!(
                [
                    le64(image, header + FIRST_USABLE),
                    le64(image, header + LAST_USABLE),
                    le64(image, header + ENTRIES_LBA),
                ],
                [34, 3254, entries],
                "{architecture}"
            );
            assert_eq!(
                [
                    le32(image, header + ENTRY_COUNT),
                    le32(image, header + ENTRY_SIZE)
                ],
                [128, 128],
                "{architecture}"
            );
        }
        let gpt = GptImage::new(image.to_vec(), partitions);
        assert!(gpt.first_partition >= 35, "{architecture}");
        assert!(gpt.last_partition <= 3253, "{architecture}");
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
        fn new(
            image: Vec<u8>,
            partitions: &[crate::sandbox_provider_protocol::PartitionDescriptor; 3],
        ) -> Self {
            let sector = SECTOR as u64;
            let signature = &partitions[2];
            Self {
                image,
                first_partition: partitions[0].start_bytes / sector,
                last_partition: (signature.start_bytes + signature.length_bytes) / sector - 1,
                signature_partition: signature.start_bytes / sector,
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

        /// One header's table, as its current LBA, count and size place it.
        fn table_mut(&mut self, header: usize) -> TestResult<&mut [u8]> {
            let start = usize::try_from(le64(&self.image, header + ENTRIES_LBA))? * SECTOR;
            let count = usize::try_from(le32(&self.image, header + ENTRY_COUNT))?;
            let size = usize::try_from(le32(&self.image, header + ENTRY_SIZE))?;
            Ok(&mut self.image[start..start + count * size])
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

        /// Move the signature entry one sector later in both tables, keeping
        /// its length, so only its start disagrees with the manifest.
        fn shift_signature_entry(&mut self) -> TestResult {
            let signature = self.signature_partition;
            for header in self.headers() {
                for entry in self.table_mut(header)?.chunks_exact_mut(128) {
                    if le64(entry, 32) == signature {
                        let last = le64(entry, 40);
                        entry[32..40].copy_from_slice(&(signature + 1).to_le_bytes());
                        entry[40..48].copy_from_slice(&(last + 1).to_le_bytes());
                    }
                }
            }
            Ok(())
        }

        /// Repair both tables' and headers' CRCs so only the edit differs.
        fn finish(mut self) -> TestResult<Vec<u8>> {
            for header in self.headers() {
                let mut crc = Crc::new();
                crc.update(self.table_mut(header)?);
                self.image[header + TABLE_CRC..header + TABLE_CRC + 4]
                    .copy_from_slice(&crc.sum().to_le_bytes());
                let size = usize::try_from(le32(&self.image, header + 12))?;
                self.image[header + 16..header + 20].fill(0);
                let mut crc = Crc::new();
                crc.update(&self.image[header..header + size]);
                self.image[header + 16..header + 20].copy_from_slice(&crc.sum().to_le_bytes());
            }
            Ok(self.image)
        }
    }
}
