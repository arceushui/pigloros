//! The [`LedgerStore`] port (ADR-017 Decision 1) and its error type.

use crate::{
    payload::{
        is_valid_date, is_valid_datetime, validate_outcome, LedgerOutcome, LedgerPrediction,
    },
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

/// Result of checking a prediction's resolve preconditions.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ResolveStatus {
    /// Whether a prediction with the given id exists.
    pub found_prediction: bool,
    /// Whether the prediction already has a resolution.
    pub already_resolved: bool,
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
    /// Default implementation validates the outcome (defence-in-depth —
    /// [`LedgerOutcome`] fields are `pub` due to serde, even though callers
    /// should prefer [`LedgerOutcome::try_new`]), checks preconditions via
    /// [`Self::find_resolve_status`], then delegates persistence to
    /// [`Self::persist_resolve`].
    ///
    /// # Errors
    /// Returns [`LedgerError::InvalidResolution`],
    /// [`LedgerError::UnknownPrediction`],
    /// [`LedgerError::AlreadyResolved`],
    /// or an adapter error on write failure.
    fn resolve(&mut self, outcome: LedgerOutcome) -> Result<(), LedgerError> {
        validate_outcome(&outcome)?;
        let status = self.find_resolve_status(&outcome.prediction_id)?;
        if !status.found_prediction {
            return Err(LedgerError::UnknownPrediction(outcome.prediction_id));
        }
        if status.already_resolved {
            return Err(LedgerError::AlreadyResolved(outcome.prediction_id));
        }
        self.persist_resolve(outcome)
    }

    /// Check resolve preconditions for `prediction_id`. Adapter-specific —
    /// the lookup mechanism differs per backend.
    ///
    /// # Errors
    /// Returns an adapter-specific error on lookup failure.
    fn find_resolve_status(&self, prediction_id: &str) -> Result<ResolveStatus, LedgerError>;

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
        crate::payload::expect_invalid(new.validate(), "title");
        new.title = "t".to_owned();
        new.statement = String::new();
        crate::payload::expect_invalid(new.validate(), "statement");
        new.statement = "s".to_owned();
        new.predicted_outcome = " ".to_owned();
        crate::payload::expect_invalid(new.validate(), "predicted_outcome");
        new.predicted_outcome = "o".to_owned();
        new.osf_link = " ".to_owned();
        crate::payload::expect_invalid(new.validate(), "osf_link");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn new_prediction_validate_rejects_bad_confidence() {
        let mut new = sample_new();
        new.confidence = f64::NAN;
        crate::payload::expect_invalid(new.validate(), "confidence");
        new.confidence = -0.1;
        crate::payload::expect_invalid(new.validate(), "confidence");
        new.confidence = 1.1;
        crate::payload::expect_invalid(new.validate(), "confidence");
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
        crate::payload::expect_invalid(new.validate(), "made_at");
        new.made_at = "2026-07-25T12:00:00Z".to_owned();
        new.resolve_by = "2026-08-01T00:00:00Z".to_owned();
        crate::payload::expect_invalid(new.validate(), "resolve_by");
        new.resolve_by = "2026-07-24".to_owned();
        crate::payload::expect_invalid(new.validate(), "on or before");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn validate_prediction_rejects_bad_ulid() {
        let prediction = sample_new().into_prediction("not-a-ulid".to_owned());
        crate::payload::expect_invalid(validate_prediction(&prediction), "ULID");
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
