//! The normative cgroup counter parser of ADR-069 R9 §4.6.2.
//!
//! It restates the provider's `parse_flat_counters` independently, so a
//! verifier parses the raw TME1 sources by the same rules.

use std::collections::BTreeMap;

use crate::sandbox_provider_protocol::CgroupCounters;

/// The required counters of the four sources, in TME1 source order:
/// `memory.events.local`, `memory.swap.events`, `pids.events.local` and
/// `cpu.stat`.
pub(super) fn parse(sources: &[Vec<u8>; 4]) -> Option<CgroupCounters> {
    let [memory, swap, pids, cpu] = sources;
    let (memory, swap, pids, cpu) = (flat(memory)?, flat(swap)?, flat(pids)?, flat(cpu)?);
    Some(CgroupCounters {
        oom_kill: *memory.get("oom_kill")?,
        memory_max: *memory.get("max")?,
        swap_max: *swap.get("max")?,
        pids_max: *pids.get("max")?,
        nr_throttled: *cpu.get("nr_throttled")?,
        throttled_usec: *cpu.get("throttled_usec")?,
    })
}

/// One flat-keyed source: UTF-8 ending in LF; one `key value` pair per line,
/// split on ASCII whitespace; a value of ASCII digits that fits a `u64`; and
/// unique keys.
fn flat(source: &[u8]) -> Option<BTreeMap<&str, u64>> {
    let text = std::str::from_utf8(source)
        .ok()
        .filter(|text| text.ends_with('\n'))?;
    let mut counters = BTreeMap::new();
    text.lines()
        .all(|line| {
            let mut fields = line.split_ascii_whitespace();
            match (fields.next(), fields.next(), fields.next()) {
                (Some(key), Some(value), None) => {
                    counter(value).is_some_and(|value| counters.insert(key, value).is_none())
                }
                _ => false,
            }
        })
        .then_some(counters)
}

/// One or more ASCII digits that fit a `u64`; leading zeros are accepted.
fn counter(value: &str) -> Option<u64> {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit())
        .then(|| value.parse().ok())
        .flatten()
}
