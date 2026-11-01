//! The fixed, non-extracting ustar reader. No path is passed to filesystem APIs.

use super::PluginWitContentErrorV1 as Error;

const BLOCK: usize = 512;
// The ustar terminator occupies two complete 512-byte blocks.
const END_BYTES: usize = 1024;
const MAX_ARCHIVE_BYTES: usize = 4 * 1024 * 1024;
const MAX_FILES: usize = 256;
const MAX_PATH_SEGMENTS: usize = 32;

pub(super) struct WitFile<'a> {
    pub(super) path: String,
    pub(super) source: &'a str,
}

pub(super) fn read(bytes: &[u8]) -> Result<Vec<WitFile<'_>>, Error> {
    if bytes.len() > MAX_ARCHIVE_BYTES {
        return Err(Error::BoundsExceeded);
    }
    if !bytes.len().is_multiple_of(BLOCK) {
        return Err(Error::Malformed);
    }
    let mut files = Vec::new();
    let mut cursor = 0;
    loop {
        // cursor never exceeds the 4 MiB input, so this addition cannot overflow.
        let header = bytes.get(cursor..cursor + BLOCK).ok_or(Error::Malformed)?;
        if header.iter().all(|byte| *byte == 0) {
            return end(&bytes[cursor..]).map(|()| files);
        }
        if files.len() == MAX_FILES {
            return Err(Error::BoundsExceeded);
        }
        let path = path(header)?;
        check_path(&path, &files)?;
        let rest = &bytes[cursor + BLOCK..];
        // Payload bytes cannot consume the mandatory archive terminator.
        let available = rest.len().saturating_sub(END_BYTES);
        let size = payload_size(&header[124..136], available)?;
        // size is at most the remaining 4 MiB, including on 32-bit targets.
        let padded = size.div_ceil(BLOCK) * BLOCK;
        // rest contains complete blocks and size <= rest.len(), so rounding
        // size to a block cannot exceed rest.len().
        let padding = &rest[size..padded];
        if padding.iter().any(|byte| *byte != 0) {
            return Err(Error::Malformed);
        }
        let source = std::str::from_utf8(&rest[..size]).map_err(|_| Error::Malformed)?;
        files.push(WitFile { path, source });
        cursor += BLOCK + padded;
    }
}

fn end(bytes: &[u8]) -> Result<(), Error> {
    // read already obtained one whole block; only a single-block tail is short.
    if bytes.len() == BLOCK || bytes.iter().any(|byte| *byte != 0) {
        Err(Error::Malformed)
    } else {
        Ok(())
    }
}

fn path(header: &[u8]) -> Result<String, Error> {
    let checksum: usize = header
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (148..156).contains(&index) {
                usize::from(b' ')
            } else {
                usize::from(*byte)
            }
        })
        .sum();
    let expected = octal(&header[148..156])?
        .bytes()
        .fold(0_usize, |value, byte| value * 8 + usize::from(byte - b'0'));
    if checksum != expected {
        return Err(Error::Malformed);
    }
    if &header[257..263] != b"ustar\0" || &header[263..265] != b"00" {
        return Err(Error::UnsupportedFormat);
    }
    if header[156] != 0 && header[156] != b'0' {
        return Err(Error::UnsupportedFormat);
    }
    if header[157..257].iter().any(|byte| *byte != 0) || header[500..].iter().any(|byte| *byte != 0)
    {
        return Err(Error::Malformed);
    }
    metadata(header)?;
    let name = text(&header[..100])?;
    let prefix = text(&header[345..500])?;
    if prefix.is_empty() {
        Ok(name.to_owned())
    } else {
        Ok(format!("{prefix}/{name}"))
    }
}

fn text(field: &[u8]) -> Result<&str, Error> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    if field[end..].iter().any(|byte| *byte != 0) {
        return Err(Error::Malformed);
    }
    std::str::from_utf8(&field[..end]).map_err(|_| Error::Malformed)
}

fn metadata(header: &[u8]) -> Result<(), Error> {
    for field in [
        &header[100..108],
        &header[108..116],
        &header[116..124],
        &header[136..148],
    ] {
        octal(field)?;
    }
    // Device identifiers have no meaning on regular entries. Accept blank
    // fields, but require a well-formed number when they are populated.
    for field in [&header[329..337], &header[337..345]] {
        if field.iter().any(|byte| *byte != 0 && *byte != b' ') {
            octal(field)?;
        }
    }
    Ok(())
}

fn octal(field: &[u8]) -> Result<&str, Error> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    if (end == field.len() && field.last() != Some(&b' '))
        || field[end..].iter().any(|byte| *byte != 0 && *byte != b' ')
    {
        return Err(Error::Malformed);
    }
    std::str::from_utf8(&field[..end])
        .map_err(|_| Error::Malformed)
        .and_then(|field| {
            let digits = field.trim_matches(' ');
            if digits.is_empty() || digits.bytes().any(|byte| !(b'0'..=b'7').contains(&byte)) {
                Err(Error::Malformed)
            } else {
                Ok(digits)
            }
        })
}

fn payload_size(field: &[u8], available: usize) -> Result<usize, Error> {
    octal(field).and_then(|digits| {
        digits.bytes().try_fold(0_usize, |size, byte| {
            // Each successful prefix is at most the remaining 4 MiB, so the
            // next octal digit cannot overflow even on a 32-bit host.
            let size = size * 8 + usize::from(byte - b'0');
            if size > available {
                Err(Error::Malformed)
            } else {
                Ok(size)
            }
        })
    })
}

fn check_path(path: &str, files: &[WitFile<'_>]) -> Result<(), Error> {
    if !path.is_ascii()
        || path
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b'\\')
        || path.as_bytes().get(1) == Some(&b':')
        || path.split('/').any(|part| matches!(part, "" | "." | ".."))
    {
        return Err(Error::Malformed);
    }
    if path.split('/').count() > MAX_PATH_SEGMENTS {
        return Err(Error::BoundsExceeded);
    }
    if path
        .rsplit_once('.')
        .is_none_or(|(_, extension)| extension != "wit")
    {
        return Err(Error::UnsupportedFormat);
    }
    if files
        .last()
        .is_some_and(|previous| previous.path.as_str() >= path)
    {
        return Err(Error::Malformed);
    }
    let key = path.to_ascii_lowercase();
    if files.iter().any(|previous| {
        let previous = previous.path.to_ascii_lowercase();
        previous == key
            || previous.starts_with(&format!("{key}/"))
            || key.starts_with(&format!("{previous}/"))
    }) {
        Err(Error::Malformed)
    } else {
        Ok(())
    }
}
