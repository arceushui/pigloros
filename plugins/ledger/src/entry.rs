//! Folded ledger entries and the unified serde view (ADR-017 Decision 6).

use serde::{Deserialize, Serialize};

use crate::{Ledger, LedgerOutcome, LedgerPrediction};

/// Display status of a folded entry (derived, never stored).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Not yet resolved; `resolve_by` has not passed.
    Pending,
    /// Not resolved although `resolve_by` has passed (derived at load time).
    Overdue,
    /// A matching outcome exists.
    Resolved,
}

impl Status {
    /// Stable lowercase key used in views and badges.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Overdue => "overdue",
            Self::Resolved => "resolved",
        }
    }
}

/// A prediction paired with its optional resolution — the fold result.
#[derive(Clone, Debug, PartialEq)]
pub struct LedgerEntry {
    /// The pre-registered prediction.
    pub prediction: LedgerPrediction,
    /// The resolution, when present.
    pub resolution: Option<LedgerOutcome>,
    /// Derived status at load time.
    pub status: Status,
}

impl LedgerEntry {
    /// Brier Score for a resolved entry: `(confidence - outcome)^2`.
    ///
    /// Returns `None` while unresolved — a pending prediction has no score
    /// (ADR-017 Decision 7: never display a fake 0.0).
    #[must_use]
    pub fn brier_score(&self) -> Option<f64> {
        self.resolution.as_ref().map(|r| {
            let outcome = f64::from(u8::from(r.outcome));
            (self.prediction.confidence - outcome).powi(2)
        })
    }
}

/// Unified JSON view of one entry — the single schema served by the gateway,
/// the static `ledger.json`, and the CLI (ADR-017 Decision 6).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct LedgerEntryView {
    /// Prediction id (ULID string).
    pub id: String,
    /// Short human-readable title.
    pub title: String,
    /// The falsifiable prediction statement.
    pub statement: String,
    /// The outcome label being predicted.
    pub predicted_outcome: String,
    /// Confidence in `[0.0, 1.0]`.
    pub confidence: f64,
    /// Optional domain Scenario.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scenario: Option<String>,
    /// `"pending"` | `"overdue"` | `"resolved"`.
    pub status: String,
    /// Brier Score when resolved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub brier_score: Option<f64>,
    /// Registration time (RFC-3339 UTC datetime).
    pub made_at: String,
    /// Resolution deadline (RFC-3339 date).
    pub resolve_by: String,
    /// Resolution time, when resolved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_at: Option<String>,
    /// Observed outcome, when resolved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<bool>,
    /// OSF pre-registration URL/DOI.
    pub osf_link: String,
}

impl From<&LedgerEntry> for LedgerEntryView {
    fn from(entry: &LedgerEntry) -> Self {
        Self {
            id: entry.prediction.prediction_id.clone(),
            title: entry.prediction.title.clone(),
            statement: entry.prediction.statement.clone(),
            predicted_outcome: entry.prediction.predicted_outcome.clone(),
            confidence: entry.prediction.confidence,
            scenario: entry.prediction.scenario.clone(),
            status: entry.status.as_str().to_owned(),
            brier_score: entry.brier_score(),
            made_at: entry.prediction.made_at.clone(),
            resolve_by: entry.prediction.resolve_by.clone(),
            resolved_at: entry.resolution.as_ref().map(|r| r.resolved_at.clone()),
            outcome: entry.resolution.as_ref().map(|r| r.outcome),
            osf_link: entry.prediction.osf_link.clone(),
        }
    }
}

/// Unified JSON view of the whole ledger (headline + entries + warnings).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct LedgerView {
    /// Folded, sorted entries.
    pub entries: Vec<LedgerEntryView>,
    /// Unresolved entries whose deadline has not passed.
    pub n_pending: usize,
    /// Unresolved entries whose deadline has passed.
    pub n_overdue: usize,
    /// Resolved entries.
    pub n_resolved: usize,
    /// Mean Brier Score over resolved entries; `None` until the first
    /// resolution (ADR-017 Decision 7). Always present in JSON (`null`
    /// when no resolutions yet) so external consumers don't have to
    /// branch on key presence.
    #[serde(default)]
    pub mean_brier: Option<f64>,
    /// Human-readable exclusion warnings (e.g. missing OSF links).
    /// Always present in JSON (`[]` when none) for the same reason.
    #[serde(default)]
    pub warnings: Vec<String>,
}

impl From<&Ledger> for LedgerView {
    fn from(ledger: &Ledger) -> Self {
        Self {
            entries: ledger.entries().iter().map(LedgerEntryView::from).collect(),
            n_pending: ledger.n_pending(),
            n_overdue: ledger.n_overdue(),
            n_resolved: ledger.n_resolved(),
            mean_brier: ledger.mean_brier(),
            warnings: ledger.warnings().iter().map(ToString::to_string).collect(),
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::payload::tests::sample_prediction;

    fn resolved_entry() -> LedgerEntry {
        LedgerEntry {
            prediction: sample_prediction("01J3B0Y5ZK2J6MGK8D7QW3N0P4"),
            resolution: Some(LedgerOutcome {
                prediction_id: "01J3B0Y5ZK2J6MGK8D7QW3N0P4".to_owned(),
                outcome: true,
                resolved_at: "2026-07-30T09:00:00Z".to_owned(),
            }),
            status: Status::Resolved,
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn status_strings() {
        assert_eq!(Status::Pending.as_str(), "pending");
        assert_eq!(Status::Overdue.as_str(), "overdue");
        assert_eq!(Status::Resolved.as_str(), "resolved");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn brier_score_math() -> Result<(), Box<dyn std::error::Error>> {
        let entry = resolved_entry();
        let score = entry.brier_score().ok_or("resolved score missing")?;
        assert!((score - 0.04).abs() < f64::EPSILON); // (0.8 - 1)^2

        let mut missed = entry;
        missed
            .resolution
            .as_mut()
            .ok_or("resolution missing")?
            .outcome = false;
        let score = missed.brier_score().ok_or("missed score missing")?;
        assert!((score - 0.64).abs() < f64::EPSILON); // (0.8 - 0)^2

        let pending = LedgerEntry {
            prediction: sample_prediction("01J3B0Y5ZK2J6MGK8D7QW3N0P4"),
            resolution: None,
            status: Status::Pending,
        };
        assert_eq!(pending.brier_score(), None);
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn view_from_resolved_entry() {
        let view = LedgerEntryView::from(&resolved_entry());
        assert_eq!(view.id, "01J3B0Y5ZK2J6MGK8D7QW3N0P4");
        assert_eq!(view.status, "resolved");
        assert_eq!(view.scenario.as_deref(), Some("places"));
        assert_eq!(view.resolved_at.as_deref(), Some("2026-07-30T09:00:00Z"));
        assert_eq!(view.outcome, Some(true));
        assert!(view.brier_score.is_some());
        assert_eq!(view.osf_link, "https://osf.io/example");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn view_from_pending_entry() {
        let pending = LedgerEntry {
            prediction: sample_prediction("01J3B0Y5ZK2J6MGK8D7QW3N0P4"),
            resolution: None,
            status: Status::Pending,
        };
        let view = LedgerEntryView::from(&pending);
        assert_eq!(view.status, "pending");
        assert_eq!(view.brier_score, None);
        assert_eq!(view.resolved_at, None);
        assert_eq!(view.outcome, None);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn view_serde_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let view = LedgerEntryView::from(&resolved_entry());
        let encoded = serde_json::to_string(&view)?;
        let back: LedgerEntryView = serde_json::from_str(&encoded)?;
        assert_eq!(back, view);
        Ok(())
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn ledger_view_from_ledger() -> Result<(), Box<dyn std::error::Error>> {
        let pair = (sample_prediction("01J3B0Y5ZK2J6MGK8D7QW3N0P4"), None);
        let ledger = crate::Ledger::from_pairs(vec![pair], "2026-07-25")?;
        let view = LedgerView::from(&ledger);
        assert_eq!(view.entries.len(), 1);
        assert_eq!(view.n_pending, 1);
        assert_eq!(view.n_overdue, 0);
        assert_eq!(view.n_resolved, 0);
        assert_eq!(view.mean_brier, None);
        assert!(view.warnings.is_empty());
        let entry = &view.entries[0];
        assert_eq!(entry.id, "01J3B0Y5ZK2J6MGK8D7QW3N0P4");
        assert_eq!(entry.status, "pending");
        assert_eq!(entry.scenario.as_deref(), Some("places"));
        Ok(())
    }
}
