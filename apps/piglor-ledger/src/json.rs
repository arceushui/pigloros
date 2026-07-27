//! JSON serialiser for the static `ledger.json` (ADR-017 Decision 3).
//!
//! Pretty-printed JSON in insertion order; byte-deterministic for a given
//! [`LedgerView`].

use pos_plugin_ledger::LedgerView;

/// Render the unified [`LedgerView`] as canonical pretty JSON.
///
/// [`LedgerView`] serialisation is infallible for all valid field types —
/// there are no custom serialisers with fallible paths, so the `serde_json`
/// error branch is unreachable. Returns `String` directly to avoid a
/// spurious `Result` wrapping an unreachable error variant.
///
/// # Panics
///
/// Never panics in practice: `LedgerView` serialisation via `serde_json`
/// is infallible for all valid field values.
#[must_use]
pub fn render_json(view: &LedgerView) -> String {
    serde_json::to_string_pretty(view).expect("LedgerView serialisation is infallible")
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use pos_plugin_ledger::LedgerEntryView;

    fn sample_view() -> LedgerView {
        LedgerView {
            entries: vec![LedgerEntryView {
                id: "01J3B0Y5ZK2J6MGK8D7QW3N0P4".to_owned(),
                title: "T".to_owned(),
                statement: "S".to_owned(),
                predicted_outcome: "O".to_owned(),
                confidence: 0.8,
                scenario: Some("places".to_owned()),
                status: "pending".to_owned(),
                brier_score: None,
                made_at: "2026-07-25T12:00:00Z".to_owned(),
                resolve_by: "2026-08-01".to_owned(),
                resolved_at: None,
                outcome: None,
                osf_link: "https://osf.io/example".to_owned(),
            }],
            n_pending: 1,
            n_overdue: 0,
            n_resolved: 0,
            mean_brier: None,
            warnings: Vec::new(),
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn json_contains_expected_keys_and_pretty_format() {
        let v = sample_view();
        let s = render_json(&v);
        assert!(s.contains("\"n_pending\": 1"));
        assert!(s.contains("\"n_resolved\": 0"));
        assert!(s.contains("\"mean_brier\": null"));
        assert!(s.contains("\"title\": \"T\""));
        assert!(s.contains("\"status\": \"pending\""));
        assert!(s.contains("\n  "));
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn json_is_deterministic_on_re_run() {
        let v = sample_view();
        assert_eq!(render_json(&v), render_json(&v));
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn empty_view_serialises_with_null_mean_brier() {
        let v = LedgerView {
            entries: Vec::new(),
            n_pending: 0,
            n_overdue: 0,
            n_resolved: 0,
            mean_brier: None,
            warnings: Vec::new(),
        };
        let s = render_json(&v);
        assert!(s.contains("\"mean_brier\": null"));
        assert!(s.contains("\"entries\": []"));
    }
}
