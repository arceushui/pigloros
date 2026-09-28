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
