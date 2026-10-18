//! systemd v260.2 image-policy grammar and outcome equivalence.
//!
//! This ports `image_policy_from_string()` with `graceful=false` and
//! `image_policy_equivalent()` from `src/shared/image-policy.c`. Two policies
//! are equal when they reach the same per-designator decision for every
//! designator: the defaults are compared extended, each designator is read
//! exhaustively, and Verity partitions without an explicit rule derive their
//! policy only from an explicitly listed data partition. The grammar is
//! closed: no whitespace, unknown designators, unknown flags, empty rules or
//! duplicate rules are accepted.
//!
//! Every bit operation goes through the small helpers below so that each one
//! is exercised with overlapping operands.

/// The ADR-087 requested policy: a signed EROFS root and nothing else.
pub(super) const REQUESTED: &str = "root=signed+erofs:=absent";

/// `partition_designator_table` order from `src/shared/gpt.c`.
const DESIGNATORS: [&str; 13] = [
    "root",
    "usr",
    "home",
    "srv",
    "esp",
    "xbootldr",
    "swap",
    "root-verity",
    "usr-verity",
    "root-verity-sig",
    "usr-verity-sig",
    "tmp",
    "var",
];
const ROOT: usize = 0;
const USR: usize = 1;
const ROOT_VERITY: usize = 7;
const USR_VERITY: usize = 8;
const ROOT_VERITY_SIG: usize = 9;
const USR_VERITY_SIG: usize = 10;

// `PartitionPolicyFlags` values from `src/shared/image-policy.h`.
const VERITY: u32 = 0x1;
const SIGNED: u32 = 0x2;
const UNPROTECTED: u32 = 0x10;
const ABSENT: u32 = 0x40;
const OPEN: u32 = 0x7f;
const IGNORE: u32 = 0x60;
const USE_MASK: u32 = 0x7f;
const READ_ONLY_MASK: u32 = 0x180;
const GROWFS_MASK: u32 = 0x600;
const PARTITION_FLAGS_MASK: u32 = 0x780;
/// `VERITY | SIGNED`.
const VERITY_PROTECTION: u32 = 0x3;
/// `VERITY | SIGNED | ENCRYPTED | ENCRYPTEDWITHINTEGRITY`.
const DATA_PROTECTION: u32 = 0xf;
/// `UNUSED | ABSENT`.
const PRESENCE: u32 = 0x60;

/// `policy_flag_from_string_one()` and `policy_flag_from_fstype()`.
const FLAGS: [(&str, u32); 20] = [
    ("verity", VERITY),
    ("signed", SIGNED),
    ("encrypted", 0x4),
    ("encryptedwithintegrity", 0x8),
    ("unprotected", UNPROTECTED),
    ("unused", 0x20),
    ("absent", ABSENT),
    ("open", OPEN),
    ("ignore", IGNORE),
    ("read-only-on", 0x100),
    ("read-only-off", 0x80),
    ("growfs-on", 0x400),
    ("growfs-off", 0x200),
    ("btrfs", 0x800),
    ("erofs", 0x1000),
    ("ext4", 0x2000),
    ("f2fs", 0x4000),
    ("squashfs", 0x8000),
    ("vfat", 0x1_0000),
    ("xfs", 0x2_0000),
];

/// Verity designator, its data designator, and the data protection that
/// permits deriving its policy (`image_policy_get()`).
const VERITY_SOURCES: [(usize, usize, u32); 4] = [
    (ROOT_VERITY, ROOT, VERITY_PROTECTION),
    (USR_VERITY, USR, VERITY_PROTECTION),
    (ROOT_VERITY_SIG, ROOT, SIGNED),
    (USR_VERITY_SIG, USR, SIGNED),
];

#[derive(Clone, Copy, Debug)]
struct ImagePolicy {
    default: u32,
    entries: [Option<u32>; DESIGNATORS.len()],
}

/// Whether mountfsd's effective policy reaches the requested decisions.
pub(super) fn matches_requested(effective: &str) -> bool {
    parse(REQUESTED)
        .zip(parse(effective))
        .is_some_and(|(requested, effective)| equivalent(&requested, &effective))
}

fn parse(text: &str) -> Option<ImagePolicy> {
    match text {
        "" | "-" => Some(ImagePolicy::uniform(IGNORE)),
        "*" => Some(ImagePolicy::uniform(OPEN)),
        "~" => Some(ImagePolicy::uniform(ABSENT)),
        _ => text
            .split(':')
            .try_fold((ImagePolicy::uniform(IGNORE), false), add_rule)
            .map(|(policy, _)| policy),
    }
}

fn add_rule(state: (ImagePolicy, bool), rule: &str) -> Option<(ImagePolicy, bool)> {
    let (mut policy, default_seen) = state;
    let (name, flags) = rule.split_once('=')?;
    let flags = parse_flags(flags)?;
    if name.is_empty() {
        if default_seen {
            return None;
        }
        policy.default = flags;
        return Some((policy, true));
    }
    let index = DESIGNATORS.iter().position(|known| *known == name)?;
    if policy.entries[index].is_some() {
        return None;
    }
    policy.entries[index] = Some(flags);
    Some((policy, default_seen))
}

fn parse_flags(text: &str) -> Option<u32> {
    if text.is_empty() || text == "-" {
        return Some(0);
    }
    text.split('+').try_fold(0, |flags, token| {
        FLAGS
            .iter()
            .find(|(name, _)| *name == token)
            .map(|(_, flag)| union(flags, *flag))
    })
}

impl ImagePolicy {
    const fn uniform(default: u32) -> Self {
        Self {
            default,
            entries: [None; DESIGNATORS.len()],
        }
    }

    /// `image_policy_get()`: an explicit rule, or one derived for Verity.
    fn explicit(&self, designator: usize) -> Option<u32> {
        self.entries[designator]
            .map(|flags| normalized(flags, designator))
            .or_else(|| self.derived(designator))
    }

    fn derived(&self, designator: usize) -> Option<u32> {
        VERITY_SOURCES
            .iter()
            .find(|(verity, _, _)| *verity == designator)
            .and_then(|(_, data, required)| {
                self.entries[*data]
                    .map(|flags| normalized(flags, *data))
                    .filter(|flags| overlaps(*flags, *required))
            })
            .map(|data| {
                let inherited = union(masked(data, PRESENCE), masked(data, PARTITION_FLAGS_MASK));
                normalized(union(UNPROTECTED, inherited), designator)
            })
    }

    /// `image_policy_get_exhaustively()`.
    fn exhaustive(&self, designator: usize) -> u32 {
        self.explicit(designator)
            .unwrap_or_else(|| normalized(self.default, designator))
    }
}

/// `image_policy_equivalent()`.
fn equivalent(left: &ImagePolicy, right: &ImagePolicy) -> bool {
    extended(left.default) == extended(right.default)
        && (0..DESIGNATORS.len())
            .all(|designator| left.exhaustive(designator) == right.exhaustive(designator))
}

/// `partition_policy_flags_extend()`: an unspecified group allows everything.
fn extended(flags: u32) -> u32 {
    [USE_MASK, READ_ONLY_MASK, GROWFS_MASK]
        .into_iter()
        .fold(flags, |flags, group| {
            if masked(flags, group) == 0 {
                union(flags, group)
            } else {
                flags
            }
        })
}

/// `partition_policy_normalized_flags()`.
fn normalized(flags: u32, designator: usize) -> u32 {
    let flags = extended(flags);
    let flags = if is_verity(designator) {
        without(flags, DATA_PROTECTION)
    } else {
        flags
    };
    let flags = if has_verity(designator) {
        flags
    } else {
        without(flags, VERITY_PROTECTION)
    };
    if masked(flags, USE_MASK) == ABSENT {
        without(flags, PARTITION_FLAGS_MASK)
    } else {
        flags
    }
}

fn is_verity(designator: usize) -> bool {
    VERITY_SOURCES
        .iter()
        .any(|(verity, _, _)| *verity == designator)
}

fn has_verity(designator: usize) -> bool {
    [ROOT, USR].contains(&designator)
}

const fn union(flags: u32, other: u32) -> u32 {
    flags | other
}

const fn masked(flags: u32, mask: u32) -> u32 {
    flags & mask
}

const fn without(flags: u32, mask: u32) -> u32 {
    flags & !mask
}

const fn overlaps(flags: u32, mask: u32) -> bool {
    flags & mask != 0
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn same(left: &str, right: &str) -> bool {
        match (parse(left), parse(right)) {
            (Some(left), Some(right)) => equivalent(&left, &right),
            _ => false,
        }
    }

    #[test]
    fn bit_helpers_handle_overlapping_operands() {
        assert_eq!(union(0x3, 0x6), 0x7);
        assert_eq!(union(0x2, 0x2), 0x2);
        assert_eq!(masked(0x3, 0x6), 0x2);
        assert_eq!(without(0x7, 0x6), 0x1);
        assert!(overlaps(0x3, 0x6));
        assert!(!overlaps(0x1, 0x6));
    }

    #[test]
    fn requested_policy_accepts_only_its_own_decisions() {
        assert!(matches_requested(REQUESTED));
        assert!(matches_requested(
            "root=signed+erofs+read-only-on+read-only-off:root-verity=unprotected:=absent"
        ));
        // v260.2 mountfsd intersects with a default lacking filesystem flags.
        assert!(!matches_requested("root=signed:=absent"));
        assert!(!matches_requested("root=verity+signed+erofs:=absent"));
        assert!(!matches_requested("root=signed+erofs:=ignore"));
        assert!(!matches_requested("root=signed+erofs:usr=signed:=absent"));
        assert!(!matches_requested("root=signed+erofs:=absent:"));
        assert!(!matches_requested("root = signed+erofs:=absent"));
    }

    #[test]
    fn every_designator_and_flag_name_is_recognised() {
        for designator in DESIGNATORS {
            assert!(
                parse(&format!("{designator}=open")).is_some(),
                "{designator}"
            );
        }
        for (flag, _) in FLAGS {
            assert!(parse(&format!("home={flag}")).is_some(), "{flag}");
        }
        assert!(!same("root=signed", "usr=signed"));
        assert!(!same("root-verity=absent", "usr-verity=absent"));
        assert!(!same("root-verity-sig=absent", "usr-verity-sig=absent"));
        assert!(!same("home=btrfs", "home=xfs"));
    }

    #[test]
    fn closed_grammar_rejects_ambiguous_rules() {
        for invalid in [
            "root",
            "root=signed:root=verity",
            "=absent:=ignore",
            "boot=signed",
            "root=signed+zfs",
            "root=signed++erofs",
            "root=signed::=absent",
            " root=signed",
        ] {
            assert!(parse(invalid).is_none(), "{invalid}");
        }
    }

    #[test]
    fn symbolic_policies_match_their_long_forms() {
        assert!(same("*", "=open"));
        assert!(same("~", "=absent"));
        assert!(same("-", "=ignore"));
        assert!(same("", "-"));
        assert!(same("root=", "root=open"));
        assert!(same("root=-", "root=open"));
        assert!(!same("*", "~"));
        assert!(!same("-", "~"));
    }

    #[test]
    fn repeated_flags_are_a_union() {
        assert!(same("root=signed+signed", "root=signed"));
        assert!(!same("root=signed+verity", "root=signed"));
    }

    #[test]
    fn unspecified_groups_extend_to_every_option() {
        assert!(same(
            "root=signed",
            "root=signed+read-only-on+read-only-off+growfs-on+growfs-off"
        ));
        assert!(!same("root=read-only-on", "root=open"));
        assert!(!same("root=growfs-off", "root=open"));
    }

    #[test]
    fn defaults_are_compared_even_when_every_designator_is_explicit() {
        let all = DESIGNATORS
            .iter()
            .map(|designator| format!("{designator}=absent"))
            .collect::<Vec<_>>()
            .join(":");
        assert!(same(&format!("{all}:=absent"), &format!("{all}:=absent")));
        assert!(!same(&format!("{all}:=absent"), &format!("{all}:=ignore")));
        assert!(!same("root=signed:=absent", "root=verity:=absent"));
    }

    #[test]
    fn verity_designators_drop_data_protection() {
        assert!(same(
            "root-verity=signed+encrypted:=absent",
            "root-verity=verity:=absent"
        ));
        assert!(same(
            "usr-verity-sig=encryptedwithintegrity:=absent",
            "usr-verity-sig=signed:=absent"
        ));
        assert!(!same(
            "root-verity=unprotected:=absent",
            "root-verity=signed:=absent"
        ));
    }

    #[test]
    fn designators_without_verity_drop_verity_protection() {
        assert!(same("home=signed", "home=verity"));
        assert!(!same("home=signed", "home=encrypted"));
        assert!(!same("root=signed", "root=verity"));
        assert!(!same("usr=signed", "usr=verity"));
    }

    #[test]
    fn absent_partitions_ignore_partition_flags() {
        assert!(same("home=absent+read-only-on", "home=absent"));
        assert!(!same("home=unused+read-only-on", "home=unused"));
    }

    #[test]
    fn verity_policy_derives_only_from_explicit_protected_data() {
        for data in ["root", "usr"] {
            assert!(same(
                &format!("{data}=signed:=absent"),
                &format!(
                    "{data}=signed:{data}-verity=unprotected:{data}-verity-sig=unprotected:=absent"
                )
            ));
            // Verity-only data derives the hash partition but not the signature.
            assert!(same(
                &format!("{data}=verity:=absent"),
                &format!("{data}=verity:{data}-verity=unprotected:=absent")
            ));
            assert!(!same(
                &format!("{data}=verity:=absent"),
                &format!(
                    "{data}=verity:{data}-verity=unprotected:{data}-verity-sig=unprotected:=absent"
                )
            ));
            // Unprotected data derives nothing; the default applies.
            assert!(!same(
                &format!("{data}=unprotected:=absent"),
                &format!("{data}=unprotected:{data}-verity=unprotected:=absent")
            ));
        }
        // A default rule never derives Verity policy.
        assert!(!same("=signed", "=signed:root-verity=unprotected"));
    }

    #[test]
    fn derived_verity_policy_inherits_presence_and_partition_flags() {
        assert!(same(
            "root=signed+absent:=ignore",
            "root=signed+absent:root-verity=unprotected+absent:\
             root-verity-sig=unprotected+absent:=ignore"
        ));
        assert!(same(
            "root=signed+read-only-on:=absent",
            "root=signed+read-only-on:root-verity=unprotected+read-only-on:\
             root-verity-sig=unprotected+read-only-on:=absent"
        ));
        assert!(!same(
            "root=signed+read-only-on:=absent",
            "root=signed+read-only-on:root-verity=unprotected:\
             root-verity-sig=unprotected:=absent"
        ));
    }
}
