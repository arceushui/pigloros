//! The folded [`Ledger`]: pairing, validation, status derivation, ordering,
//! and headline aggregation. Adapter-agnostic — both port adapters feed
//! `(prediction, resolution)` pairs through [`Ledger::from_pairs`].

use std::cmp::Ordering;
use std::fmt;

use crate::{
    entry::Status,
    payload::{is_valid_date, validate_outcome},
    store::{is_valid_osf_link, validate_prediction},
    LedgerEntry, LedgerError, LedgerOutcome, LedgerPrediction,
};

/// A non-fatal exclusion reported alongside the fold (ADR-017 Decision 8:
/// enforcement lives in tooling, surfaced loudly).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerWarning {
    /// Entry excluded because it lacks an OSF pre-registration link.
    MissingOsfLink {
        /// Excluded prediction id.
        prediction_id: String,
    },
    /// Entry excluded because its link is not safe to render as OSF navigation.
    UnsafeOsfLink {
        /// Excluded prediction id.
        prediction_id: String,
    },
}

impl fmt::Display for LedgerWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingOsfLink { prediction_id } => write!(
                f,
                "excluded {prediction_id}: missing osf_link (pre-registration required, ADR-017)"
            ),
            Self::UnsafeOsfLink { prediction_id } => write!(
                f,
                "excluded {prediction_id}: unsafe osf_link (must be canonical HTTPS on osf.io)"
            ),
        }
    }
}

/// The folded, sorted ledger plus exclusion warnings.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Ledger {
    entries: Vec<LedgerEntry>,
    warnings: Vec<LedgerWarning>,
}

impl Ledger {
    /// Fold `(prediction, resolution)` pairs into a sorted ledger.
    ///
    /// Structural problems (invalid payloads, id mismatches) are hard
    /// errors; entries lacking `osf_link` are excluded with a warning.
    ///
    /// # Errors
    /// Returns [`LedgerError::InvalidToday`] if `today` is not an RFC-3339
    /// date, or a validation error on any pair.
    pub(crate) fn from_pairs<I>(pairs: I, today: &str) -> Result<Self, LedgerError>
    where
        I: IntoIterator<Item = (LedgerPrediction, Option<LedgerOutcome>)>,
    {
        if !is_valid_date(today) {
            return Err(LedgerError::InvalidToday(today.to_owned()));
        }
        let mut entries = Vec::new();
        let mut warnings = Vec::new();
        for (prediction, resolution) in pairs {
            validate_prediction(&prediction)?;
            if let Some(outcome) = &resolution {
                validate_outcome(outcome)?;
                if outcome.prediction_id != prediction.prediction_id {
                    return Err(LedgerError::InvalidResolution(format!(
                        "outcome prediction_id {:?} does not match prediction {:?}",
                        outcome.prediction_id, prediction.prediction_id
                    )));
                }
            }
            if prediction.osf_link.trim().is_empty() {
                warnings.push(LedgerWarning::MissingOsfLink {
                    prediction_id: prediction.prediction_id.clone(),
                });
                continue;
            }
            if !is_valid_osf_link(&prediction.osf_link) {
                warnings.push(LedgerWarning::UnsafeOsfLink {
                    prediction_id: prediction.prediction_id.clone(),
                });
                continue;
            }
            let status = if resolution.is_some() {
                Status::Resolved
            } else if today > prediction.resolve_by.as_str() {
                Status::Overdue
            } else {
                Status::Pending
            };
            entries.push(LedgerEntry {
                prediction,
                resolution,
                status,
            });
        }
        entries.sort_by(compare_entries);
        Ok(Self { entries, warnings })
    }

    /// Folded, sorted entries (see ADR-017 Decision 7 for the ordering).
    #[must_use]
    pub fn entries(&self) -> &[LedgerEntry] {
        &self.entries
    }

    /// Exclusion warnings produced during the fold.
    #[must_use]
    pub fn warnings(&self) -> &[LedgerWarning] {
        &self.warnings
    }

    /// Unresolved entries whose deadline has not passed.
    #[must_use]
    pub fn n_pending(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.status == Status::Pending)
            .count()
    }

    /// Unresolved entries whose deadline has passed.
    #[must_use]
    pub fn n_overdue(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.status == Status::Overdue)
            .count()
    }

    /// Resolved entries.
    #[must_use]
    pub fn n_resolved(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.status == Status::Resolved)
            .count()
    }

    /// Mean Brier Score over resolved entries.
    ///
    /// `None` until the first resolution — the page must never print a
    /// fake `0.0` on an empty record (ADR-017 Decision 7).
    #[must_use]
    pub fn mean_brier(&self) -> Option<f64> {
        let mut sum = 0.0;
        let mut n = 0usize;
        for entry in &self.entries {
            if let Some(score) = entry.brier_score() {
                sum += score;
                n += 1;
            }
        }
        if n == 0 {
            None
        } else {
            let count = u32::try_from(n).map_or(f64::MAX, f64::from);
            Some(sum / count)
        }
    }
}

/// Ordering: unresolved (pending, then overdue interleaved by urgency)
/// first by `resolve_by` ascending, then resolved by `resolved_at`
/// descending. Ties break on prediction id for determinism.
fn compare_entries(a: &LedgerEntry, b: &LedgerEntry) -> Ordering {
    match (a.status, b.status) {
        (Status::Resolved, Status::Resolved) => {
            let a_at = a.resolution.as_ref().map_or("", |r| r.resolved_at.as_str());
            let b_at = b.resolution.as_ref().map_or("", |r| r.resolved_at.as_str());
            b_at.cmp(a_at)
                .then_with(|| a.prediction.prediction_id.cmp(&b.prediction.prediction_id))
        }
        (Status::Resolved, _) => Ordering::Greater,
        (_, Status::Resolved) => Ordering::Less,
        _ => a
            .prediction
            .resolve_by
            .cmp(&b.prediction.resolve_by)
            .then_with(|| a.prediction.prediction_id.cmp(&b.prediction.prediction_id)),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::payload::tests::sample_prediction;

    const ID1: &str = "01J3B0Y5ZK2J6MGK8D7QW3N0P1";
    const ID2: &str = "01J3B0Y5ZK2J6MGK8D7QW3N0P2";
    const ID3: &str = "01J3B0Y5ZK2J6MGK8D7QW3N0P3";

    fn outcome(id: &str, resolved_at: &str, outcome: bool) -> LedgerOutcome {
        LedgerOutcome {
            prediction_id: id.to_owned(),
            outcome,
            resolved_at: resolved_at.to_owned(),
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn empty_ledger_has_no_scores() {
        let ledger = Ledger::from_pairs(vec![], "2026-07-25").unwrap();
        assert!(ledger.entries().is_empty());
        assert!(ledger.warnings().is_empty());
        assert_eq!(ledger.n_pending(), 0);
        assert_eq!(ledger.n_overdue(), 0);
        assert_eq!(ledger.n_resolved(), 0);
        assert_eq!(ledger.mean_brier(), None);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn invalid_today_rejected() {
        let err = Ledger::from_pairs(vec![], "25-07-2026").unwrap_err();
        assert!(matches!(err, LedgerError::InvalidToday(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn invalid_prediction_and_resolution_propagate() {
        let mut bad = sample_prediction(ID1);
        bad.confidence = 2.0;
        let err = Ledger::from_pairs(vec![(bad, None)], "2026-07-25").unwrap_err();
        assert!(matches!(err, LedgerError::InvalidPrediction(_)));

        let good = sample_prediction(ID1);
        let bad_outcome = outcome("not-a-ulid", "2026-07-30T09:00:00Z", true);
        let err = Ledger::from_pairs(vec![(good, Some(bad_outcome))], "2026-07-25").unwrap_err();
        assert!(matches!(err, LedgerError::InvalidResolution(_)));

        let good = sample_prediction(ID1);
        let mismatched = outcome(ID2, "2026-07-30T09:00:00Z", true);
        let err = Ledger::from_pairs(vec![(good, Some(mismatched))], "2026-07-25").unwrap_err();
        assert!(matches!(err, LedgerError::InvalidResolution(_)));
        assert!(err.to_string().contains("does not match"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn missing_osf_link_excluded_with_warning() {
        let mut unregistered = sample_prediction(ID1);
        unregistered.osf_link = " ".to_owned();
        let ledger = Ledger::from_pairs(
            vec![(unregistered, None), (sample_prediction(ID2), None)],
            "2026-07-25",
        )
        .unwrap();
        assert_eq!(ledger.entries().len(), 1);
        assert_eq!(ledger.entries()[0].prediction.prediction_id, ID2);
        assert_eq!(ledger.warnings().len(), 1);
        let warning = ledger.warnings()[0].to_string();
        assert!(warning.contains(ID1));
        assert!(warning.contains("osf_link"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn unsafe_osf_link_is_excluded_with_warning() {
        let mut unsafe_prediction = sample_prediction(ID1);
        unsafe_prediction.osf_link = "javascript:alert(1)".to_owned();
        let ledger = Ledger::from_pairs(vec![(unsafe_prediction, None)], "2026-07-25").unwrap();

        assert!(ledger.entries().is_empty());
        assert_eq!(ledger.warnings().len(), 1);
        assert!(ledger.warnings()[0].to_string().contains("unsafe osf_link"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn status_derivation() {
        let mut pending = sample_prediction(ID1);
        pending.resolve_by = "2026-08-01".to_owned();
        let mut overdue = sample_prediction(ID2);
        overdue.made_at = "2026-07-15T12:00:00Z".to_owned();
        overdue.resolve_by = "2026-07-20".to_owned();
        let resolved = sample_prediction(ID3);
        let ledger = Ledger::from_pairs(
            vec![
                (pending, None),
                (overdue, None),
                (resolved, Some(outcome(ID3, "2026-07-24T10:00:00Z", true))),
            ],
            "2026-07-25",
        )
        .unwrap();
        assert_eq!(ledger.n_pending(), 1);
        assert_eq!(ledger.n_overdue(), 1);
        assert_eq!(ledger.n_resolved(), 1);
        // resolve_by equal to today is NOT yet overdue.
        let mut due_today = sample_prediction(ID1);
        due_today.resolve_by = "2026-07-25".to_owned();
        let ledger = Ledger::from_pairs(vec![(due_today, None)], "2026-07-25").unwrap();
        assert_eq!(ledger.n_pending(), 1);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn ordering_unresolved_first_then_resolved() {
        let mut later = sample_prediction(ID1);
        later.resolve_by = "2026-09-01".to_owned();
        let mut sooner = sample_prediction(ID2);
        sooner.resolve_by = "2026-08-01".to_owned();
        let resolved_old = sample_prediction(ID3);
        let resolved_new_id = "01J3B0Y5ZK2J6MGK8D7QW3N0P4";
        let resolved_new = sample_prediction(resolved_new_id);
        let ledger = Ledger::from_pairs(
            vec![
                (
                    resolved_old,
                    Some(outcome(ID3, "2026-07-20T10:00:00Z", true)),
                ),
                (later, None),
                (
                    resolved_new,
                    Some(outcome(resolved_new_id, "2026-07-24T10:00:00Z", false)),
                ),
                (sooner, None),
            ],
            "2026-07-25",
        )
        .unwrap();
        let ids: Vec<&str> = ledger
            .entries()
            .iter()
            .map(|e| e.prediction.prediction_id.as_str())
            .collect();
        assert_eq!(ids, vec![ID2, ID1, resolved_new_id, ID3]);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn ordering_tie_breaks_on_id() {
        let mut a = sample_prediction(ID1);
        a.resolve_by = "2026-08-01".to_owned();
        let mut b = sample_prediction(ID2);
        b.resolve_by = "2026-08-01".to_owned();
        let ledger =
            Ledger::from_pairs(vec![(b.clone(), None), (a.clone(), None)], "2026-07-25").unwrap();
        assert_eq!(ledger.entries()[0].prediction.prediction_id, ID1);

        let ra = outcome(ID1, "2026-07-24T10:00:00Z", true);
        let rb = outcome(ID2, "2026-07-24T10:00:00Z", true);
        let ledger = Ledger::from_pairs(vec![(b, Some(rb)), (a, Some(ra))], "2026-07-25").unwrap();
        assert_eq!(ledger.entries()[0].prediction.prediction_id, ID1);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn mean_brier_over_resolved_only() {
        let p1 = sample_prediction(ID1); // confidence 0.8
        let p2 = sample_prediction(ID2);
        let ledger = Ledger::from_pairs(
            vec![
                (p1, Some(outcome(ID1, "2026-07-24T10:00:00Z", true))), // 0.04
                (p2, Some(outcome(ID2, "2026-07-24T10:00:00Z", false))), // 0.64
                (sample_prediction(ID3), None),                         // unscored
            ],
            "2026-07-25",
        )
        .unwrap();
        let mean = ledger.mean_brier().unwrap();
        assert!((mean - 0.34).abs() < 1e-12);
    }
}
