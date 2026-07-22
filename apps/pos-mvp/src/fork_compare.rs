//! Wave 7 #75 — personal fork: dual `CoW` futures from a shared "now".
//!
//! Local-first: Memory store fork ×2, force each option on one arm, compare
//! with `pos_time::compare`. Gateway/WS live twins remain deferred.

use pos_core::{
    event::{CanonicalBytes, EventDraft, Kind},
    ids::EntityId,
};
use pos_plugin_persona::{
    DecisionPayload, PersonaModel, PreferencePayload, EVENT_TYPE_DECISION, EVENT_TYPE_PREFERENCE,
};
use pos_state::{EntityStateProjection, ProjectionRegistry};
use pos_store::{open_store, StoreConfig};
use pos_time::ForkDiff;

/// Summary of a dual-future personal fork compare.
#[derive(Debug, Clone)]
pub struct ForkCompareSummary {
    pub fork_seq: u64,
    pub chosen_a: String,
    pub chosen_b: String,
    pub score_a: f64,
    pub score_b: f64,
    pub only_in_a: usize,
    pub only_in_b: usize,
    pub diverged_entities: usize,
}

/// Run local `CoW` personal forks for two options and compare post-fork divergence.
///
/// Uses an in-memory store only (demo path); panics if the Memory backend fails.
#[must_use]
pub fn run_personal_fork_compare(
    preferences: &[(String, f64)],
    option_a: &str,
    option_b: &str,
) -> ForkCompareSummary {
    let mut store = open_store(StoreConfig::Memory).expect("memory store opens");
    let base = store
        .create_timeline("shared-now")
        .expect("create shared-now");
    let base_id = base.id();
    let twin = EntityId::new();

    let pref_drafts: Vec<EventDraft> = preferences
        .iter()
        .map(|(dim, score)| preference_draft(twin, dim, *score))
        .collect();
    if !pref_drafts.is_empty() {
        store
            .append(base_id, &pref_drafts)
            .expect("seed preferences");
    }

    let base_meta = store
        .list_timelines()
        .expect("list timelines")
        .into_iter()
        .find(|t| t.id() == base_id)
        .expect("base timeline present");
    let fork_seq = base_meta.head;

    let arm_a = store
        .fork(base_id, fork_seq, "future-a")
        .expect("fork future-a");
    let arm_b = store
        .fork(base_id, fork_seq, "future-b")
        .expect("fork future-b");

    let model = PersonaModel::new(preferences.to_vec());
    let score_a = model.score_option(option_a);
    let score_b = model.score_option(option_b);

    store
        .append(
            arm_a.id(),
            &[forced_decision(twin, option_a, option_b, true)],
        )
        .expect("append future-a");
    store
        .append(
            arm_b.id(),
            &[forced_decision(twin, option_a, option_b, false)],
        )
        .expect("append future-b");

    let mut reg_a = ProjectionRegistry::new();
    reg_a.register("entity_state", Box::new(EntityStateProjection));
    let mut reg_b = ProjectionRegistry::new();
    reg_b.register("entity_state", Box::new(EntityStateProjection));

    let diff: ForkDiff = pos_time::compare(
        store.as_ref(),
        arm_a.id(),
        arm_b.id(),
        fork_seq,
        &mut reg_a,
        &mut reg_b,
    )
    .expect("compare futures");

    ForkCompareSummary {
        fork_seq: fork_seq.as_u64(),
        chosen_a: option_a.to_owned(),
        chosen_b: option_b.to_owned(),
        score_a,
        score_b,
        only_in_a: diff.only_in_a.len(),
        only_in_b: diff.only_in_b.len(),
        diverged_entities: diff.diverged_entities.len(),
    }
}

fn preference_draft(entity: EntityId, dimension: &str, score: f64) -> EventDraft {
    let payload = PreferencePayload {
        dimension: dimension.to_owned(),
        score,
        confidence: 1.0,
    };
    let mut buf = Vec::new();
    ciborium::into_writer(&payload, &mut buf)
        .expect("CBOR encoding infallible for PreferencePayload");
    EventDraft::new(
        entity,
        Kind::new(EVENT_TYPE_PREFERENCE),
        CanonicalBytes::from_vec(buf),
    )
}

fn forced_decision(entity: EntityId, option_a: &str, option_b: &str, choose_a: bool) -> EventDraft {
    let chosen = if choose_a {
        option_a.to_owned()
    } else {
        option_b.to_owned()
    };
    let payload = DecisionPayload {
        option_a: option_a.to_owned(),
        option_b: option_b.to_owned(),
        chosen,
        regret_prob: 0.25,
    };
    let mut buf = Vec::new();
    ciborium::into_writer(&payload, &mut buf)
        .expect("CBOR encoding infallible for DecisionPayload");
    EventDraft::new(
        entity,
        Kind::new(EVENT_TYPE_DECISION),
        CanonicalBytes::from_vec(buf),
    )
}

/// Print side-by-side personal fork futures (#75).
pub fn print_fork_compare(summary: &ForkCompareSummary, label_a: &str, label_b: &str) {
    println!("Personal fork — two futures from shared-now (local `CoW`, #75)");
    println!("  Forked at seq {}", summary.fork_seq);
    println!();
    println!("  Future A  → choose {label_a} (`{}`)", summary.chosen_a);
    println!(
        "    persona match score {:.3} · post-fork events only here: {}",
        summary.score_a, summary.only_in_a
    );
    println!("  Future B  → choose {label_b} (`{}`)", summary.chosen_b);
    println!(
        "    persona match score {:.3} · post-fork events only here: {}",
        summary.score_b, summary.only_in_b
    );
    println!(
        "  Diverged entities after fork: {}",
        summary.diverged_entities
    );
    println!();
    let winner = if (summary.score_a - summary.score_b).abs() < 0.02 {
        "Toss-up — both futures score nearly the same under your prefs.".to_owned()
    } else if summary.score_a > summary.score_b {
        format!("Future A ({label_a}) fits your prefs better in this preview.")
    } else {
        format!("Future B ({label_b}) fits your prefs better in this preview.")
    };
    println!("→ Side-by-side: {winner}");
    println!(
        "  Thin #75 slice: local CoW + forced decisions; gateway-hosted twins / experiment-forward deferred."
    );
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn personal_fork_compare_diverges_on_forced_choices() {
        let prefs = vec![("nature".to_owned(), 0.9), ("food".to_owned(), 0.2)];
        let summary = run_personal_fork_compare(&prefs, "kyoto nature", "osaka food");
        assert_eq!(summary.chosen_a, "kyoto nature");
        assert_eq!(summary.chosen_b, "osaka food");
        assert!(summary.only_in_a >= 1);
        assert!(summary.only_in_b >= 1);
        assert!(summary.score_a > summary.score_b);
    }

    #[test]
    fn personal_fork_compare_works_with_empty_prefs() {
        let summary = run_personal_fork_compare(&[], "a", "b");
        assert_eq!(summary.fork_seq, 0);
        assert_eq!(summary.only_in_a, 1);
        assert_eq!(summary.only_in_b, 1);
    }

    #[test]
    fn print_fork_compare_runs() {
        let summary = ForkCompareSummary {
            fork_seq: 2,
            chosen_a: "A".into(),
            chosen_b: "B".into(),
            score_a: 0.8,
            score_b: 0.4,
            only_in_a: 1,
            only_in_b: 1,
            diverged_entities: 1,
        };
        print_fork_compare(&summary, "Park", "Cafe");
        let tied = ForkCompareSummary {
            score_a: 0.5,
            score_b: 0.5,
            ..summary.clone()
        };
        print_fork_compare(&tied, "Park", "Cafe");
        let b_wins = ForkCompareSummary {
            score_a: 0.2,
            score_b: 0.9,
            ..summary
        };
        print_fork_compare(&b_wins, "Park", "Cafe");
    }

    #[test]
    fn preference_and_decision_drafts_encode() {
        let e = EntityId::new();
        let p = preference_draft(e, "trust", 0.5);
        assert_eq!(p.event_type.as_str(), EVENT_TYPE_PREFERENCE);
        let d = forced_decision(e, "x", "y", false);
        assert_eq!(d.event_type.as_str(), EVENT_TYPE_DECISION);
        let d_a = forced_decision(e, "x", "y", true);
        assert_eq!(d_a.event_type.as_str(), EVENT_TYPE_DECISION);
    }
}
