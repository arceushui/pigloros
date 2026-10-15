//! Native lifecycle records preserve the pinned ordinary reader's wire contract.

use super::{
    encoded, field, fields, lifecycle, parity, replace_first, value, Fallible, Guard, ReadError,
};
use ciborium::Value;
use pos_core::{KeyRegistryStateV1, KeyRoleV1};

#[test]
#[cfg_attr(coverage_nightly, coverage(off))]
fn unknown_lifecycle_fields_keep_parity_and_truncated_wide_scalars_refuse() -> Fallible<()> {
    let states = lifecycle("a", KeyRoleV1::TimelineIntegritySigning)?;
    let marker = Value::Text("ignored-lifecycle-wire-value".to_owned());
    let needle = encoded(&marker)?;
    for (index, map) in [(2, "pending_destructions"), (3, "tombstones")] {
        let (state, required) = &states[index];
        let mut snapshot = value(state)?;
        let (_, record) = fields(field(&mut snapshot, map)?)?
            .first_mut()
            .ok_or("native lifecycle entry")?;
        // These nested native records accept unknown fields in the pinned
        // ordinary decoder. This is not the root governance envelope.
        fields(record)?.push((Value::Text("extra".to_owned()), marker.clone()));
        let bytes = encoded(&snapshot)?;
        assert_eq!(
            bytes
                .windows(needle.len())
                .filter(|part| *part == needle.as_slice())
                .count(),
            1
        );
        let start = bytes
            .windows(needle.len())
            .position(|part| part == needle.as_slice())
            .ok_or("lifecycle wire marker")?;
        for (header, width) in [(0x19, 2), (0x1a, 4), (0x1b, 8)] {
            let mut scalar = vec![header];
            scalar.extend(std::iter::repeat_n(0, width));
            let complete = replace_first(&bytes, &needle, &scalar)?;
            assert_eq!(parity(&complete)?, *state);
            let mut guard = Guard::new(*required);
            assert_eq!(
                KeyRegistryStateV1::from_durable_cbor_with_read_guard(&complete, &mut guard)?,
                *state
            );
            // The independent lifecycle inventory is unchanged: ignored wire
            // scalars borrow their bytes and materialize no owned carrier.
            assert_eq!(guard.remaining, 0);

            // Keep the valid native prefix through this unknown field, then
            // end inside its declared scalar payload. Typed Value construction
            // cannot express this EOF; neither native reader may accept it.
            let mut truncated = bytes[..start].to_vec();
            truncated.extend_from_slice(&scalar[..scalar.len() - 1]);
            assert_eq!(parity(&truncated), Err(ReadError::InvalidSnapshot));
        }
    }
    Ok(())
}
