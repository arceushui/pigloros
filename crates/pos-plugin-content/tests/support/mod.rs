//! Independent ustar fixtures, constructed without the production reader.

pub const WORLD: &[u8] = b"package pigloros:plugin@0.1.0; world community-plugin {}";

pub fn archive(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (path, source) in files {
        let mut header = [0; 512];
        let (prefix, name) = if path.len() <= 100 {
            ("", *path)
        } else {
            path.rsplit_once('/').unwrap_or(("", *path))
        };
        assert!(name.len() <= 100 && prefix.len() <= 155);
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
        header[100..108].copy_from_slice(b"0000644\0");
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");
        header[124..136].copy_from_slice(format!("{:011o}\0", source.len()).as_bytes());
        header[136..148].copy_from_slice(b"00000000000\0");
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        checksum(&mut header);
        bytes.extend_from_slice(&header);
        bytes.extend_from_slice(source);
        bytes.resize(bytes.len().next_multiple_of(512), 0);
    }
    bytes.resize(bytes.len() + 1024, 0);
    bytes
}

pub fn reheader(bytes: &mut [u8], change: impl FnOnce(&mut [u8])) {
    let header = &mut bytes[..512];
    change(header);
    checksum(header);
}

fn checksum(header: &mut [u8]) {
    header[148..156].fill(b' ');
    let sum: usize = header.iter().map(|byte| usize::from(*byte)).sum();
    header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
}
