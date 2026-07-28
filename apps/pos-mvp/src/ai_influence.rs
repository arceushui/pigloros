//! AI Influence Index (#79) — product headline for decision preview.
//!
//! Fraction of the information environment (timeline events) originating from
//! AI agents with identifiable goals (`agent.action`, `agent.decision`, …),
//! broken down by archetype.

use std::collections::BTreeMap;

/// Max characters kept for archetype / goal labels printed to the CLI.
const MAX_LABEL_CHARS: usize = 64;

/// How the index was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AiInfluenceMode {
    /// Computed from gateway timeline poll.
    Live,
    /// No `--gateway`/`--timeline`; still show a headline (assumed 0%).
    LocalPreview,
    /// Flags were set but the gateway poll failed.
    Unavailable,
}

/// First-class AI Influence Index for the decision preview.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct AiInfluenceIndex {
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
pub(crate) fn local_ai_influence() -> AiInfluenceIndex {
    AiInfluenceIndex {
        index: 0.0,
        ai_events: 0,
        total_events: 0,
        by_archetype: BTreeMap::new(),
        mode: AiInfluenceMode::LocalPreview,
    }
}

/// Headline when `--gateway`/`--timeline` were set but the poll failed.
#[must_use]
pub(crate) fn unavailable_ai_influence() -> AiInfluenceIndex {
    AiInfluenceIndex {
        index: 0.0,
        ai_events: 0,
        total_events: 0,
        by_archetype: BTreeMap::new(),
        mode: AiInfluenceMode::Unavailable,
    }
}

/// Compute the index from gateway JSON event views.
#[must_use]
pub(crate) fn ai_influence_from_events(events: &[serde_json::Value]) -> AiInfluenceIndex {
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
    let total = u32::try_from(total_events).unwrap_or(u32::MAX);
    let ai = u32::try_from(ai_events).unwrap_or(u32::MAX).min(total);
    f64::from(ai) / f64::from(total)
}

/// Any non-empty `agent.*` event type (ai-agent, rule-agent, future agents).
fn is_ai_agent_event(event_type: &str) -> bool {
    event_type.starts_with("agent.") && event_type.len() > "agent.".len()
}

/// Strip control characters and truncate so CLI headlines stay single-line.
fn sanitize_label(raw: &str) -> Option<String> {
    let mut out = String::new();
    for c in raw.chars() {
        if c.is_control() {
            continue;
        }
        if out.chars().count() >= MAX_LABEL_CHARS {
            break;
        }
        out.push(c);
    }
    let trimmed = out.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn archetype_for(event: &serde_json::Value, event_type: &str) -> String {
    if let Some(label) = event
        .get("payload")
        .and_then(|p| p.get("archetype"))
        .and_then(serde_json::Value::as_str)
        .and_then(sanitize_label)
    {
        return label;
    }
    if let Some(goal) = event
        .get("payload")
        .and_then(|p| p.get("goal"))
        .and_then(serde_json::Value::as_str)
        .and_then(sanitize_label)
    {
        return format!("goal:{goal}");
    }
    match event_type {
        "agent.action" => "goal-seeking".to_owned(),
        "agent.decision" => "rule-bound".to_owned(),
        other => {
            // `is_ai_agent_event` already requires a non-empty `agent.` prefix.
            let suffix = &other["agent.".len()..];
            sanitize_label(suffix).unwrap_or_else(|| "agent".to_owned())
        }
    }
}

/// Human-readable lines for the decision-preview headline (#79 / O12).
#[must_use]
pub(crate) fn format_ai_influence_lines(index: &AiInfluenceIndex) -> Vec<String> {
    let pct = format!("{:.0}", index.index * 100.0);
    match index.mode {
        AiInfluenceMode::LocalPreview => vec![
            format!(
                "AI Influence Index: {pct}% — local preview (no shared timeline; live share needs --gateway/--timeline)"
            ),
        ],
        AiInfluenceMode::Unavailable => {
            vec![
                "AI Influence Index: n/a — gateway poll failed (see warning)".to_owned(),
            ]
        }
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
            if index.ai_events == 0 {
                lines.push(
                    "  (no agent.* events yet — gateway HTTP posts world.action/society.signal; seed agent events or see #72 for a non-zero live index)"
                        .to_owned(),
                );
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
        assert!(!lines[0].contains("n/a"));
    }

    #[test]
    fn unavailable_formats_poll_failed_not_local() {
        let idx = unavailable_ai_influence();
        assert_eq!(idx.mode, AiInfluenceMode::Unavailable);
        let lines = format_ai_influence_lines(&idx);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("n/a"));
        assert!(lines[0].contains("gateway poll failed"));
        assert!(!lines[0].contains("needs --gateway"));
        assert!(!lines[0].contains("local preview"));
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
    fn sanitize_strips_controls_and_truncates() {
        let events = vec![
            serde_json::json!({
                "event_type": "agent.action",
                "payload": { "archetype": "evil\nextra-line" }
            }),
            serde_json::json!({
                "event_type": "agent.action",
                "payload": { "goal": format!("{}!", "x".repeat(80)) }
            }),
            serde_json::json!({
                "event_type": "agent.action",
                "payload": { "archetype": "\u{0001}\u{0002}" }
            }),
        ];
        let idx = ai_influence_from_events(&events);
        assert_eq!(idx.by_archetype.get("evilextra-line"), Some(&1));
        let goal_key = idx
            .by_archetype
            .keys()
            .find(|k| k.starts_with("goal:"))
            .expect("goal key");
        assert!(goal_key.starts_with("goal:"));
        assert!(goal_key.len() <= "goal:".len() + MAX_LABEL_CHARS);
        assert!(!goal_key.contains('\n'));
        // Control-only archetype falls back to default.
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
    fn control_only_agent_suffix_falls_back_to_agent() {
        let events = vec![serde_json::json!({
            "event_type": "agent.\u{0001}\u{0002}",
            "payload": {}
        })];
        let idx = ai_influence_from_events(&events);
        assert_eq!(idx.ai_events, 1);
        assert_eq!(idx.by_archetype.get("agent"), Some(&1));
    }

    #[test]
    fn bare_agent_prefix_alone_is_not_ai() {
        let events = vec![serde_json::json!({ "event_type": "agent." })];
        let idx = ai_influence_from_events(&events);
        assert_eq!(idx.total_events, 1);
        assert_eq!(idx.ai_events, 0);
    }

    #[test]
    fn live_zero_ai_formats_without_archetypes() {
        let events = vec![serde_json::json!({ "event_type": "world.action" })];
        let idx = ai_influence_from_events(&events);
        let lines = format_ai_influence_lines(&idx);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("0%"));
        assert!(lines[0].contains("0 of 1"));
        assert!(!lines[0].contains("Traceable"));
        assert!(lines[1].contains("no agent.*"));
        assert!(lines[1].contains("#72"));
    }

    #[test]
    fn influence_ratio_clamped_to_unit_interval() {
        assert!((influence_ratio(0, 0) - 0.0).abs() < f64::EPSILON);
        assert!((influence_ratio(1, 4) - 0.25).abs() < f64::EPSILON);
        assert!((influence_ratio(u64::MAX, u64::MAX) - 1.0).abs() < f64::EPSILON);
        assert!((influence_ratio(u64::MAX, 2) - 1.0).abs() < f64::EPSILON);
        assert!(influence_ratio(u64::MAX, 2) <= 1.0);
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
