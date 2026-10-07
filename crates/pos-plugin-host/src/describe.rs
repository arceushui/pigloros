//! The `describe` ABI check against the negotiated release.
//!
//! Negotiation sees only the manifest. The guest's own `plugin-descriptor`
//! must describe the same release: its Plugin ID, world, ABI major, declared
//! minor range and required features must equal the negotiated record, and
//! its `migrations` must be empty, because a V1 host never invokes
//! `migrate-state`. Any mismatch or bound violation is `InvalidGuestOutput`.
//! Fields are checked in WIT order, so the lowest failing ordinal wins.
//!
//! Two owner decisions (ADR-061 revision 6) fix the remaining fields:
//! - `manifest-digest` and `release-digest` must be 32 zero bytes. Both real
//!   digests cover the Component's own digest (PMF1 field 9), so no Component
//!   can declare the values of its own release.
//! - `capabilities` and `dependencies` are only count-bounded; the manifest,
//!   not `describe`, is their authority.
//!
//! `release-semver` is only lifted as text: ADR-061 revision 6 item 2 lists
//! exactly what `describe` is checked against, and the manifest (PMF1 field 3)
//! is the authority for the release version.

use pos_runtime::community_plugin_host::{NegotiatedCommunityPluginV1, PluginDescriptorV1};
use wasmtime::component::Val;

use crate::lift::{
    digest, ensure, fields, id, list, ordered_digests, text, u16_value, Lifted, INVALID,
};

/// PMF1 bound on event schemas, capabilities and dependencies.
///
/// It is the at-most-256 row of PMF1 fields 11-13; fields 14 and 17 have
/// the same bound.
const MAX_DESCRIPTOR_ITEMS: usize = 256;

/// Lift one `plugin-descriptor` and check it against `negotiated`.
pub(crate) fn plugin_descriptor(
    value: &Val,
    negotiated: &NegotiatedCommunityPluginV1,
) -> Lifted<PluginDescriptorV1> {
    let [plugin_id, semver, world, major, min_minor, max_minor, features, events, state, capabilities, migrations, dependencies, manifest, release] =
        fields(value)?;
    let (negotiated_major, _) = negotiated.abi();
    let (declared_min, declared_max) = negotiated.declared_minor_range();
    let plugin_id = matching(id(plugin_id)?, negotiated.plugin_id())?;
    let release_semver = text(semver)?;
    let world = matching(text(world)?, negotiated.world())?;
    let abi_major = matching(u16_value(major)?, &negotiated_major)?;
    let min_abi_minor = matching(u16_value(min_minor)?, &declared_min)?;
    let max_abi_minor = matching(u16_value(max_minor)?, &declared_max)?;
    let required_features = matching(id_list(features)?, negotiated.required_features())?;
    let event_schema_digests = ordered_digests(events)?;
    bounded(event_schema_digests.len())?;
    let state_schema_digest = digest(state)?;
    bounded(list(capabilities)?.len())?;
    ensure(list(migrations)?.is_empty(), INVALID)?;
    bounded(list(dependencies)?.len())?;
    Ok(PluginDescriptorV1 {
        plugin_id,
        release_semver,
        world,
        abi_major,
        min_abi_minor,
        max_abi_minor,
        required_features,
        event_schema_digests,
        state_schema_digest,
        manifest_digest: zero_digest(manifest)?,
        release_digest: zero_digest(release)?,
    })
}

/// `value` if it equals `expected`.
fn matching<T: PartialEq<U>, U: ?Sized>(value: T, expected: &U) -> Lifted<T> {
    ensure(value == *expected, INVALID)?;
    Ok(value)
}

/// A `digest32` of 32 zero bytes, as V1 `describe` digests must be.
fn zero_digest(value: &Val) -> Lifted<[u8; 32]> {
    matching(digest(value)?, &[0; 32])
}

fn id_list(value: &Val) -> Lifted<Vec<String>> {
    list(value)?.iter().map(id).collect()
}

const fn bounded(count: usize) -> Lifted<()> {
    ensure(count <= MAX_DESCRIPTOR_ITEMS, INVALID)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use pos_runtime::community_plugin_host::CommunityPluginHostAbiV1;

    use super::*;
    use crate::test_values::{
        digest_val, negotiate, numbered_digest, ok, record, release, text_val,
    };

    fn texts(items: &[&str]) -> Val {
        Val::List(items.iter().map(|item| text_val(item)).collect())
    }

    fn negotiated() -> NegotiatedCommunityPluginV1 {
        let host = ok(CommunityPluginHostAbiV1::new(
            0,
            0,
            vec!["feature.a".to_owned()],
        ));
        negotiate(&release(3, &["feature.a"]), &host, None)
    }

    /// Descriptor fields in WIT order, matching [`negotiated`].
    fn descriptor_fields() -> Vec<(&'static str, Val)> {
        vec![
            ("plugin-id", text_val("plugin-a")),
            ("release-semver", text_val("1.2.3")),
            ("world", text_val("pigloros:plugin/community-plugin@0.1.0")),
            ("abi-major", Val::U16(0)),
            ("min-abi-minor", Val::U16(0)),
            ("max-abi-minor", Val::U16(3)),
            ("required-features", texts(&["feature.a"])),
            (
                "event-schema-digests",
                Val::List(vec![digest_val(&[3; 32]), digest_val(&[4; 32])]),
            ),
            ("state-schema-digest", digest_val(&[5; 32])),
            ("capabilities", Val::List(Vec::new())),
            ("migrations", Val::List(Vec::new())),
            ("dependencies", Val::List(Vec::new())),
            ("manifest-digest", digest_val(&[0; 32])),
            ("release-digest", digest_val(&[0; 32])),
        ]
    }

    fn with(index: usize, value: Val) -> Lifted<PluginDescriptorV1> {
        let mut fields = descriptor_fields();
        fields[index].1 = value;
        plugin_descriptor(&record(fields), &negotiated())
    }

    #[test]
    fn a_matching_descriptor_lifts() {
        let lifted = plugin_descriptor(&record(descriptor_fields()), &negotiated());
        let expected = PluginDescriptorV1 {
            plugin_id: "plugin-a".to_owned(),
            release_semver: "1.2.3".to_owned(),
            world: "pigloros:plugin/community-plugin@0.1.0".to_owned(),
            abi_major: 0,
            min_abi_minor: 0,
            max_abi_minor: 3,
            required_features: vec!["feature.a".to_owned()],
            event_schema_digests: vec![[3; 32], [4; 32]],
            state_schema_digest: [5; 32],
            manifest_digest: [0; 32],
            release_digest: [0; 32],
        };
        assert_eq!(lifted, Ok(expected));
    }

    #[test]
    fn every_negotiated_field_must_match() {
        let mismatches = [
            (0, text_val("plugin-b")),
            (0, text_val("Plugin-a")),
            (2, text_val("pigloros:plugin/community-plugin@0.2.0")),
            (3, Val::U16(1)),
            (4, Val::U16(1)),
            (5, Val::U16(2)),
            (6, texts(&[])),
            (6, texts(&["feature.a", "feature.b"])),
        ];
        for (index, value) in mismatches {
            assert_eq!(with(index, value), Err(INVALID), "field {index}");
        }
    }

    #[test]
    fn descriptor_bounds_and_migrations_are_checked() {
        let many = |count: usize| Val::List(vec![Val::Bool(false); count]);
        let ordered: Vec<Val> = (0..=MAX_DESCRIPTOR_ITEMS)
            .map(|index| digest_val(&numbered_digest(index)))
            .collect();
        assert!(with(7, Val::List(ordered[..MAX_DESCRIPTOR_ITEMS].to_vec())).is_ok());
        let invalid = [
            (7, Val::List(ordered)),
            (
                7,
                Val::List(vec![digest_val(&[4; 32]), digest_val(&[3; 32])]),
            ),
            (8, digest_val(&[5; 31])),
            (9, many(MAX_DESCRIPTOR_ITEMS + 1)),
            (10, many(1)),
            (11, many(MAX_DESCRIPTOR_ITEMS + 1)),
            (12, digest_val(&[0; 31])),
            (13, digest_val(&[0; 31])),
            (12, digest_val(&[6; 32])),
            (13, digest_val(&[7; 32])),
        ];
        for (index, value) in invalid {
            assert_eq!(with(index, value), Err(INVALID), "field {index}");
        }
        assert!(with(9, many(MAX_DESCRIPTOR_ITEMS)).is_ok());
        assert!(with(11, many(MAX_DESCRIPTOR_ITEMS)).is_ok());
        assert_eq!(plugin_descriptor(&Val::U8(0), &negotiated()), Err(INVALID));
    }

    #[test]
    fn every_field_of_the_wrong_kind_is_invalid() {
        for index in 0..descriptor_fields().len() {
            assert_eq!(with(index, Val::U8(0)), Err(INVALID), "field {index}");
        }
        assert_eq!(with(6, Val::List(vec![Val::U8(0)])), Err(INVALID));
    }
}
