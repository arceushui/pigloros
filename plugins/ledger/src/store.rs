//! The [`LedgerStore`] port (ADR-017 Decision 1) and its error type.

use crate::{
    payload::{LedgerOutcome, LedgerPrediction},
    Ledger,
};

/// Errors from ledger domain operations and adapters.
#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    /// Filesystem failure in a file-backed adapter.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// A TOML file could not be parsed.
    #[error("toml parse error in {path}: {reason}")]
    Toml {
        /// File that failed to parse.
        path: String,
        /// Parser diagnostic.
        reason: String,
    },
    /// A prediction failed validation.
    #[error("invalid prediction: {0}")]
    InvalidPrediction(String),
    /// A resolution failed validation.
    #[error("invalid resolution: {0}")]
    InvalidResolution(String),
    /// `today` argument is not an RFC-3339 date.
    #[error("invalid today date: {0}")]
    InvalidToday(String),
    /// Resolution references a prediction id that does not exist.
    #[error("orphan resolution: {0}")]
    OrphanResolution(String),
    /// Resolution targets an unknown prediction id.
    #[error("unknown prediction: {0}")]
    UnknownPrediction(String),
    /// Prediction already has a resolution.
    #[error("already resolved: {0}")]
    AlreadyResolved(String),
    /// CBOR payload could not be decoded.
    #[error("payload decode error: {0}")]
    Decode(String),
    /// Event store backend error.
    #[error("store error: {0}")]
    Store(String),
}

/// Input for registering a new prediction (everything but the generated id).
#[derive(Clone, Debug, PartialEq)]
pub struct NewPrediction {
    /// Short human-readable title.
    pub title: String,
    /// The falsifiable prediction statement.
    pub statement: String,
    /// The outcome label being predicted.
    pub predicted_outcome: String,
    /// Confidence in `[0.0, 1.0]`.
    pub confidence: f64,
    /// Optional domain Scenario.
    pub scenario: Option<String>,
    /// Registration time (RFC-3339 UTC datetime).
    pub made_at: String,
    /// Resolution deadline (RFC-3339 date).
    pub resolve_by: String,
    /// OSF pre-registration URL/DOI — required at write time
    /// (ADR-017 Decision 8).
    pub osf_link: String,
}

impl NewPrediction {
    /// Validate all fields, including the mandatory OSF link.
    ///
    /// # Errors
    /// Returns [`LedgerError::InvalidPrediction`] on the first violated rule.
    pub fn validate(&self) -> Result<(), LedgerError> {
        validate_fields(
            &self.title,
            &self.statement,
            &self.predicted_outcome,
            self.confidence,
            &self.made_at,
            &self.resolve_by,
        )?;
        if self.osf_link.trim().is_empty() {
            return Err(LedgerError::InvalidPrediction(
                "osf_link is required at registration (ADR-017)".to_owned(),
            ));
        }
        Ok(())
    }

    /// Attach a generated prediction id, producing the full payload.
    #[must_use]
    pub fn into_prediction(self, prediction_id: String) -> LedgerPrediction {
        LedgerPrediction {
            prediction_id,
            title: self.title,
            statement: self.statement,
            predicted_outcome: self.predicted_outcome,
            confidence: self.confidence,
            scenario: self.scenario,
            made_at: self.made_at,
            resolve_by: self.resolve_by,
            osf_link: self.osf_link,
        }
    }
}

/// Field validation shared by [`NewPrediction`] and [`LedgerPrediction`]
/// (the OSF link is *not* checked here — read-side exclusion handles it).
pub(crate) fn validate_fields(
    title: &str,
    statement: &str,
    predicted_outcome: &str,
    confidence: f64,
    made_at: &str,
    resolve_by: &str,
) -> Result<(), LedgerError> {
    if title.trim().is_empty() {
        return Err(LedgerError::InvalidPrediction(
            "title must not be empty".to_owned(),
        ));
    }
    if statement.trim().is_empty() {
        return Err(LedgerError::InvalidPrediction(
            "statement must not be empty".to_owned(),
        ));
    }
    if predicted_outcome.trim().is_empty() {
        return Err(LedgerError::InvalidPrediction(
            "predicted_outcome must not be empty".to_owned(),
        ));
    }
    if !confidence.is_finite() || !(0.0..=1.0).contains(&confidence) {
        return Err(LedgerError::InvalidPrediction(
            "confidence must be a finite value in [0.0, 1.0]".to_owned(),
        ));
    }
    if !is_valid_datetime(made_at) {
        return Err(LedgerError::InvalidPrediction(format!(
            "made_at must be an RFC-3339 UTC datetime (YYYY-MM-DDTHH:MM:SSZ), got {made_at:?}"
        )));
    }
    if !is_valid_date(resolve_by) {
        return Err(LedgerError::InvalidPrediction(format!(
            "resolve_by must be an RFC-3339 date (YYYY-MM-DD), got {resolve_by:?}"
        )));
    }
    if made_at[0..10] > *resolve_by {
        return Err(LedgerError::InvalidPrediction(
            "made_at must be on or before resolve_by".to_owned(),
        ));
    }
    Ok(())
}

/// Validate the payload-specific fields of a [`LedgerPrediction`].
pub(crate) fn validate_prediction(prediction: &LedgerPrediction) -> Result<(), LedgerError> {
    if ulid::Ulid::from_string(&prediction.prediction_id).is_err() {
        return Err(LedgerError::InvalidPrediction(format!(
            "prediction_id must be a ULID, got {:?}",
            prediction.prediction_id
        )));
    }
    validate_fields(
        &prediction.title,
        &prediction.statement,
        &prediction.predicted_outcome,
        prediction.confidence,
        &prediction.made_at,
        &prediction.resolve_by,
    )
}

/// Validate a [`LedgerOutcome`].
pub(crate) fn validate_outcome(outcome: &LedgerOutcome) -> Result<(), LedgerError> {
    if ulid::Ulid::from_string(&outcome.prediction_id).is_err() {
        return Err(LedgerError::InvalidResolution(format!(
            "prediction_id must be a ULID, got {:?}",
            outcome.prediction_id
        )));
    }
    if !is_valid_datetime(&outcome.resolved_at) {
        return Err(LedgerError::InvalidResolution(format!(
            "resolved_at must be an RFC-3339 UTC datetime (YYYY-MM-DDTHH:MM:SSZ), got {:?}",
            outcome.resolved_at
        )));
    }
    Ok(())
}

/// Check resolve preconditions and return the right error if violated.
/// Adapters call this after their own lookup — the lookup mechanism
/// differs per backend, but the error conditions are port-level rules.
pub(crate) fn check_resolve_status(
    found: bool,
    already_resolved: bool,
    prediction_id: &str,
) -> Result<(), LedgerError> {
    if !found {
        return Err(LedgerError::UnknownPrediction(prediction_id.to_owned()));
    }
    if already_resolved {
        return Err(LedgerError::AlreadyResolved(prediction_id.to_owned()));
    }
    Ok(())
}

/// Days per month (index 1-based; Feb always 28 — leap years ignored for
/// the ledger's domain, which doesn't need perfect calendar accuracy).
const DAYS_IN_MONTH: [u8; 13] = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// `YYYY-MM-DD` with real month/day ranges. Hand-rolled on purpose:
/// canonical UTC strings sort lexicographically, so no date crate is
/// needed (ADR-017).
pub(crate) fn is_valid_date(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return false;
    }
    if !s[0..4].bytes().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let (Ok(month), Ok(day)) = (s[5..7].parse::<u8>(), s[8..10].parse::<u8>()) else {
        return false;
    };
    (1..=12).contains(&month) && day >= 1 && day <= DAYS_IN_MONTH[usize::from(month)]
}

/// `YYYY-MM-DDTHH:MM:SSZ` (UTC only — offsets are rejected so strings
/// stay canonically sortable).
pub(crate) fn is_valid_datetime(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 20 || b[10] != b'T' || b[13] != b':' || b[16] != b':' || b[19] != b'Z' {
        return false;
    }
    if !is_valid_date(&s[0..10]) {
        return false;
    }
    let (Ok(hour), Ok(minute), Ok(second)) = (
        s[11..13].parse::<u8>(),
        s[14..16].parse::<u8>(),
        s[17..19].parse::<u8>(),
    ) else {
        return false;
    };
    hour < 24 && minute < 60 && second < 60
}

/// The ledger port: one interface, two first-class adapters
/// (ADR-017 Decision 1). Implementations: [`crate::TomlLedgerStore`]
/// (curated tier) and, from #109, an `EventStore` adapter (live tier).
pub trait LedgerStore {
    /// Fold all predictions and resolutions into a [`Ledger`].
    ///
    /// `today` is an RFC-3339 date used to derive overdue status; it is a
    /// parameter (not a clock read) so results are deterministic.
    ///
    /// # Errors
    /// Returns [`LedgerError`] on unreadable or invalid data.
    fn load(&self, today: &str) -> Result<Ledger, LedgerError>;

    /// Register a new prediction; returns the generated prediction id.
    ///
    /// # Errors
    /// Returns [`LedgerError::InvalidPrediction`] on validation failure, or
    /// an adapter error on write failure.
    fn register(&mut self, prediction: NewPrediction) -> Result<String, LedgerError>;

    /// Resolve an existing prediction with its observed outcome.
    ///
    /// Default implementation validates the [`LedgerOutcome`], checks resolve
    /// preconditions via [`Self::find_resolve_status`], then delegates
    /// persistence to [`Self::persist_resolve`].
    ///
    /// # Errors
    /// Returns [`LedgerError::UnknownPrediction`],
    /// [`LedgerError::AlreadyResolved`], [`LedgerError::InvalidResolution`],
    /// or an adapter error on write failure.
    fn resolve(&mut self, outcome: LedgerOutcome) -> Result<(), LedgerError> {
        validate_outcome(&outcome)?;
        let (found_prediction, already_resolved) =
            self.find_resolve_status(&outcome.prediction_id)?;
        check_resolve_status(found_prediction, already_resolved, &outcome.prediction_id)?;
        self.persist_resolve(outcome)
    }

    /// Check whether `prediction_id` exists and whether it already has a
    /// resolution. Adapter-specific — the lookup mechanism differs per
    /// backend.
    ///
    /// Returns `(found_prediction, already_resolved)`.
    ///
    /// # Errors
    /// Returns an adapter-specific error on lookup failure.
    fn find_resolve_status(&self, prediction_id: &str) -> Result<(bool, bool), LedgerError>;

    /// Persist a validated [`LedgerOutcome`] to the backend.
    ///
    /// # Errors
    /// Returns an adapter-specific error on write failure.
    fn persist_resolve(&mut self, outcome: LedgerOutcome) -> Result<(), LedgerError>;
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn sample_new() -> NewPrediction {
        NewPrediction {
            title: "Kyoto vs Osaka".to_owned(),
            statement: "Kyoto will be chosen".to_owned(),
            predicted_outcome: "Kyoto".to_owned(),
            confidence: 0.8,
            scenario: None,
            made_at: "2026-07-25T12:00:00Z".to_owned(),
            resolve_by: "2026-08-01".to_owned(),
            osf_link: "https://osf.io/example".to_owned(),
        }
    }

    fn expect_invalid(result: Result<(), LedgerError>, needle: &str) {
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains(needle),
            "expected {needle:?} in {err:?}"
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn new_prediction_validate_ok_and_into_prediction() {
        let new = sample_new();
        assert!(new.validate().is_ok());
        let prediction = new
            .clone()
            .into_prediction("01J3B0Y5ZK2J6MGK8D7QW3N0P4".to_owned());
        assert_eq!(prediction.prediction_id, "01J3B0Y5ZK2J6MGK8D7QW3N0P4");
        assert_eq!(prediction.title, new.title);
        assert_eq!(prediction.scenario, None);
        assert!(validate_prediction(&prediction).is_ok());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn new_prediction_validate_rejects_blank_strings() {
        let mut new = sample_new();
        new.title = "  ".to_owned();
        expect_invalid(new.validate(), "title");
        new.title = "t".to_owned();
        new.statement = String::new();
        expect_invalid(new.validate(), "statement");
        new.statement = "s".to_owned();
        new.predicted_outcome = " ".to_owned();
        expect_invalid(new.validate(), "predicted_outcome");
        new.predicted_outcome = "o".to_owned();
        new.osf_link = " ".to_owned();
        expect_invalid(new.validate(), "osf_link");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn new_prediction_validate_rejects_bad_confidence() {
        let mut new = sample_new();
        new.confidence = f64::NAN;
        expect_invalid(new.validate(), "confidence");
        new.confidence = -0.1;
        expect_invalid(new.validate(), "confidence");
        new.confidence = 1.1;
        expect_invalid(new.validate(), "confidence");
        new.confidence = 0.0;
        assert!(new.validate().is_ok());
        new.confidence = 1.0;
        assert!(new.validate().is_ok());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn new_prediction_validate_rejects_bad_dates() {
        let mut new = sample_new();
        new.made_at = "2026-07-25".to_owned();
        expect_invalid(new.validate(), "made_at");
        new.made_at = "2026-07-25T12:00:00Z".to_owned();
        new.resolve_by = "2026-08-01T00:00:00Z".to_owned();
        expect_invalid(new.validate(), "resolve_by");
        new.resolve_by = "2026-07-24".to_owned();
        expect_invalid(new.validate(), "on or before");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn validate_prediction_rejects_bad_ulid() {
        let prediction = sample_new().into_prediction("not-a-ulid".to_owned());
        expect_invalid(validate_prediction(&prediction), "ULID");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn validate_outcome_rules() {
        let ok = LedgerOutcome {
            prediction_id: "01J3B0Y5ZK2J6MGK8D7QW3N0P4".to_owned(),
            outcome: false,
            resolved_at: "2026-07-30T09:00:00Z".to_owned(),
        };
        assert!(validate_outcome(&ok).is_ok());
        let mut bad = ok.clone();
        bad.prediction_id = "nope".to_owned();
        expect_invalid(validate_outcome(&bad), "ULID");
        let mut bad = ok;
        bad.resolved_at = "2026-07-30T25:00:00Z".to_owned();
        expect_invalid(validate_outcome(&bad), "resolved_at");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn date_shape_checks() {
        assert!(is_valid_date("2026-07-25"));
        assert!(!is_valid_date("2026-7-25"));
        assert!(!is_valid_date("2026/07/25"));
        assert!(!is_valid_date("abcd-07-25"));
        assert!(!is_valid_date("2026-13-01"));
        assert!(!is_valid_date("2026-00-01"));
        assert!(!is_valid_date("2026-01-00"));
        assert!(!is_valid_date("2026-01-32"));
        assert!(!is_valid_date("2026-xx-01"));
        assert!(!is_valid_date("2026-01-xx"));

        assert!(is_valid_datetime("2026-07-25T12:00:00Z"));
        assert!(!is_valid_datetime("2026-07-25T12:00:00+02:00"));
        assert!(!is_valid_datetime("2026-07-25 12:00:00Z"));
        assert!(!is_valid_datetime("2026-02-30T12:00:00Z"));
        assert!(!is_valid_datetime("2026-07-25T24:00:00Z"));
        assert!(!is_valid_datetime("2026-07-25T12:60:00Z"));
        assert!(!is_valid_datetime("2026-07-25T12:00:60Z"));
        assert!(!is_valid_datetime("2026-07-25T12:00:00"));
        assert!(!is_valid_datetime("2026-07-25T12:00:0Z"));
        assert!(!is_valid_datetime("2026-07-25Txx:00:00Z"));
        assert!(!is_valid_datetime("2026-07-25T12:xx:00Z"));
        assert!(!is_valid_datetime("2026-07-25T12:00:xxZ"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn error_display_variants() {
        let cases: Vec<(LedgerError, &str)> = vec![
            (
                LedgerError::InvalidPrediction("p".into()),
                "invalid prediction",
            ),
            (
                LedgerError::InvalidResolution("r".into()),
                "invalid resolution",
            ),
            (LedgerError::InvalidToday("t".into()), "invalid today"),
            (
                LedgerError::OrphanResolution("o".into()),
                "orphan resolution",
            ),
            (
                LedgerError::UnknownPrediction("u".into()),
                "unknown prediction",
            ),
            (LedgerError::AlreadyResolved("a".into()), "already resolved"),
            (LedgerError::Decode("d".into()), "decode error"),
        ];
        for (err, needle) in cases {
            assert!(err.to_string().contains(needle), "{err} missing {needle}");
        }
        let io = LedgerError::Io(std::io::Error::other("x"));
        assert!(io.to_string().contains("io error"));
        let toml = LedgerError::Toml {
            path: "f".into(),
            reason: "r".into(),
        };
        assert!(toml.to_string().contains("toml parse error"));
        let store = LedgerError::Store("disk full".into());
        assert!(store.to_string().contains("store error"));
    }
}
