//! AI Influence Index (#79) — product headline for decision preview.
//!
//! Fraction of the information environment (timeline events) originating from
//! AI agents with identifiable goals (`agent.action`, `agent.decision`, …),
//! broken down by archetype.

use std::collections::BTreeMap;

/// How the index was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiInfluenceMode {
    /// Computed from gateway timeline poll.
    Live,
    /// No `--gateway`/`--timeline`; still show a headline (assumed 0%).
    LocalPreview,
}

/// First-class AI Influence Index for the decision preview.
#[derive(Debug, Clone, PartialEq)]
pub struct AiInfluenceIndex {
    /// Share of counted events from AI agents, in `[0, 1]`.
    pub index: f64,
    pub ai_events: u64,
    pub total_events: u64,
    /// Archetype label → event count (sorted keys for stable output).
    pub by_archetype: BTreeMap<String, u64>,
    pub mode: AiInfluenceMode,
}

/// Local preview headline: no shared timeline observed.
#[must_use]
pub fn local_ai_influence() -> AiInfluenceIndex {
    AiInfluenceIndex {
        index: 0.0,
        ai_events: 0,
        total_events: 0,
        by_archetype: BTreeMap::new(),
        mode: AiInfluenceMode::LocalPreview,
    }
}

/// Compute the index from gateway JSON event views.
#[must_use]
pub fn ai_influence_from_events(events: &[serde_json::Value]) -> AiInfluenceIndex {
    let mut ai_events = 0_u64;
    let mut total_events = 0_u64;
    let mut by_archetype: BTreeMap<String, u64> = BTreeMap::new();

    for event in events {
        let Some(event_type) = event.get("event_type").and_then(serde_json::Value::as_str) else {
            continue;
        };
        if event_type.is_empty() {
            continue;
        }
        total_events += 1;
        if !is_ai_agent_event(event_type) {
            continue;
        }
        ai_events += 1;
        let archetype = archetype_for(event, event_type);
        *by_archetype.entry(archetype).or_insert(0) += 1;
    }

    AiInfluenceIndex {
        index: influence_ratio(ai_events, total_events),
        ai_events,
        total_events,
        by_archetype,
        mode: AiInfluenceMode::Live,
    }
}

/// AI share in `[0, 1]`. Saturates at `u32::MAX` for clippy-friendly float conversion.
fn influence_ratio(ai_events: u64, total_events: u64) -> f64 {
    if total_events == 0 {
        return 0.0;
    }
    let ai = u32::try_from(ai_events).unwrap_or(u32::MAX);
    let total = u32::try_from(total_events).unwrap_or(u32::MAX);
    f64::from(ai) / f64::from(total)
}

/// `agent.action` (goal-seeking ai-agent), `agent.decision` (rule-agent), and future `agent.*`.
fn is_ai_agent_event(event_type: &str) -> bool {
    event_type == "agent.action"
        || event_type == "agent.decision"
        || (event_type.starts_with("agent.") && event_type.len() > "agent.".len())
}

fn archetype_for(event: &serde_json::Value, event_type: &str) -> String {
    if let Some(label) = event
        .get("payload")
        .and_then(|p| p.get("archetype"))
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return label.to_owned();
    }
    if let Some(goal) = event
        .get("payload")
        .and_then(|p| p.get("goal"))
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return format!("goal:{goal}");
    }
    match event_type {
        "agent.action" => "goal-seeking".to_owned(),
        "agent.decision" => "rule-bound".to_owned(),
        other => other.strip_prefix("agent.").unwrap_or(other).to_owned(),
    }
}

/// Human-readable lines for the decision-preview headline (#79 / O12).
#[must_use]
pub fn format_ai_influence_lines(index: &AiInfluenceIndex) -> Vec<String> {
    let pct = format!("{:.0}", index.index * 100.0);
    match index.mode {
        AiInfluenceMode::LocalPreview => vec![
            format!(
                "AI Influence Index: {pct}% — local preview (no shared timeline; live share needs --gateway/--timeline)"
            ),
        ],
        AiInfluenceMode::Live if index.total_events == 0 => {
            vec!["AI Influence Index: 0% — no events on shared timeline yet".to_owned()]
        }
        AiInfluenceMode::Live => {
            let mut lines = vec![format!(
                "AI Influence Index: {pct}% — {} of {} info events from AI agents with identifiable goals",
                index.ai_events, index.total_events
            )];
            if !index.by_archetype.is_empty() {
                let parts: Vec<String> = index
                    .by_archetype
                    .iter()
                    .map(|(name, n)| format!("{name}×{n}"))
                    .collect();
                lines.push(format!("  Traceable archetypes: {}", parts.join(", ")));
            }
            lines
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn local_preview_is_zero() {
        let idx = local_ai_influence();
        assert_eq!(idx.mode, AiInfluenceMode::LocalPreview);
        assert!((idx.index - 0.0).abs() < f64::EPSILON);
        let lines = format_ai_influence_lines(&idx);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("AI Influence Index: 0%"));
        assert!(lines[0].contains("local preview"));
    }

    #[test]
    fn empty_live_timeline() {
        let idx = ai_influence_from_events(&[]);
        assert_eq!(idx.mode, AiInfluenceMode::Live);
        assert_eq!(idx.total_events, 0);
        let lines = format_ai_influence_lines(&idx);
        assert!(lines[0].contains("no events"));
    }

    #[test]
    fn skips_missing_or_empty_event_type() {
        let events = vec![
            serde_json::json!({ "payload": {} }),
            serde_json::json!({ "event_type": "" }),
            serde_json::json!({ "event_type": "world.action" }),
        ];
        let idx = ai_influence_from_events(&events);
        assert_eq!(idx.total_events, 1);
        assert_eq!(idx.ai_events, 0);
        assert!((idx.index - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn mixes_ai_and_human_with_default_archetypes() {
        let events = vec![
            serde_json::json!({ "event_type": "agent.action", "payload": { "action": "move" } }),
            serde_json::json!({ "event_type": "agent.decision", "payload": { "action": "stay" } }),
            serde_json::json!({ "event_type": "society.signal", "payload": { "dimension": "trust", "value": 0.5 } }),
            serde_json::json!({ "event_type": "world.action", "payload": {} }),
            serde_json::json!({ "event_type": "persona.decision", "payload": {} }),
        ];
        let idx = ai_influence_from_events(&events);
        assert_eq!(idx.total_events, 5);
        assert_eq!(idx.ai_events, 2);
        assert!((idx.index - 0.4).abs() < f64::EPSILON);
        assert_eq!(idx.by_archetype.get("goal-seeking"), Some(&1));
        assert_eq!(idx.by_archetype.get("rule-bound"), Some(&1));
        let lines = format_ai_influence_lines(&idx);
        assert!(lines[0].contains("40%"));
        assert!(lines[0].contains("2 of 5"));
        assert!(lines[1].contains("goal-seeking×1"));
        assert!(lines[1].contains("rule-bound×1"));
    }

    #[test]
    fn payload_archetype_and_goal_override_defaults() {
        let events = vec![
            serde_json::json!({
                "event_type": "agent.action",
                "payload": { "archetype": "scout" }
            }),
            serde_json::json!({
                "event_type": "agent.action",
                "payload": { "goal": "maximize-trust" }
            }),
            serde_json::json!({
                "event_type": "agent.action",
                "payload": { "archetype": "  " }
            }),
        ];
        let idx = ai_influence_from_events(&events);
        assert_eq!(idx.ai_events, 3);
        assert_eq!(idx.by_archetype.get("scout"), Some(&1));
        assert_eq!(idx.by_archetype.get("goal:maximize-trust"), Some(&1));
        assert_eq!(idx.by_archetype.get("goal-seeking"), Some(&1));
    }

    #[test]
    fn future_agent_event_types_count_as_ai() {
        let events = vec![serde_json::json!({
            "event_type": "agent.plan",
            "payload": {}
        })];
        let idx = ai_influence_from_events(&events);
        assert_eq!(idx.ai_events, 1);
        assert_eq!(idx.by_archetype.get("plan"), Some(&1));
    }

    #[test]
    fn live_zero_ai_formats_without_archetypes() {
        let events = vec![serde_json::json!({ "event_type": "world.action" })];
        let idx = ai_influence_from_events(&events);
        let lines = format_ai_influence_lines(&idx);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("0%"));
        assert!(lines[0].contains("0 of 1"));
        assert!(!lines[0].contains("Traceable"));
    }

    #[test]
    fn influence_ratio_saturates_huge_counts() {
        assert!((influence_ratio(0, 0) - 0.0).abs() < f64::EPSILON);
        assert!((influence_ratio(1, 4) - 0.25).abs() < f64::EPSILON);
        assert!((influence_ratio(u64::MAX, u64::MAX) - 1.0).abs() < f64::EPSILON);
        assert!(influence_ratio(u64::MAX, 2) > 1.0);
    }

    #[test]
    fn empty_goal_falls_back_to_default_archetype() {
        let events = vec![serde_json::json!({
            "event_type": "agent.decision",
            "payload": { "goal": "   " }
        })];
        let idx = ai_influence_from_events(&events);
        assert_eq!(idx.by_archetype.get("rule-bound"), Some(&1));
    }
}
