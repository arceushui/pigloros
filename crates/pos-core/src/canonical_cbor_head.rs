//! Small shared deterministic-CBOR head encoder for native V1 records.

/// Write the preferred definite-length header for one CBOR major type.
pub fn encode_head(out: &mut Vec<u8>, major: u8, value: u64) {
    let prefix = major << 5;
    let bytes = value.to_be_bytes();
    match value {
        0..=23 => out.push(prefix | bytes[7]),
        24..=0xff => out.extend_from_slice(&[prefix | 0x18, bytes[7]]),
        0x100..=0xffff => {
            out.push(prefix | 0x19);
            out.extend_from_slice(&bytes[6..]);
        }
        0x1_0000..=0xffff_ffff => {
            out.push(prefix | 0x1a);
            out.extend_from_slice(&bytes[4..]);
        }
        _ => {
            out.push(prefix | 0x1b);
            out.extend_from_slice(&bytes);
        }
    }
}
