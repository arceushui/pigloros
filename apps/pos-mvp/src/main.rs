#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `PiglorOS` Single-User MVP: Trip Preview — Kyoto vs Osaka.
//!
//! Composes persona + eval (+ geo cloaking) and proves a closed calibration loop:
//! persona decisions emit matched `eval.prediction` / `eval.outcome` pairs so
//! [`pos_plugin_eval::compute_report`] yields `n_resolved > 0`.
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use pos_core::ids::EntityId;
use pos_experiment::{BacktestConfig, BacktestRunner};
use pos_plugin_eval::{EvalPlugin, EvalReducer};
use pos_plugin_geo::{GeoPlugin, GeoReducer, SpatialCloaker};
use pos_plugin_persona::{PersonaEvalDriver, PersonaModel, PersonaPlugin, PersonaReducer};
use pos_runtime::PluginRegistry;
use pos_store::StoreConfig;

fn default_preferences() -> Vec<(String, f64)> {
    vec![
        ("nature".to_owned(), 0.8),
        ("city".to_owned(), 0.5),
        ("food".to_owned(), 0.9),
        ("quiet".to_owned(), 0.7),
    ]
}

fn build_registry() -> PluginRegistry {
    let entity = EntityId::new();
    let model = PersonaModel::new(default_preferences());

    let mut registry = PluginRegistry::new();

    let persona = PersonaPlugin::new();
    registry
        .register(
            &persona,
            Some(Box::new(PersonaReducer)),
            Some(Box::new(PersonaEvalDriver::trip_preview(entity, model))),
        )
        .expect("persona plugin registration failed");

    let eval = EvalPlugin::new();
    registry
        .register(&eval, Some(Box::new(EvalReducer)), None)
        .expect("eval plugin registration failed");

    let geo = GeoPlugin::new();
    registry
        .register(&geo, Some(Box::new(GeoReducer)), None)
        .expect("geo plugin registration failed");

    registry
}

fn main() {
    println!("PiglorOS Single-User MVP: Trip Preview — Kyoto vs Osaka");
    println!();

    let model = PersonaModel::new(default_preferences());
    let kyoto_score = model.score_option("kyoto nature quiet temples");
    let osaka_score = model.score_option("osaka city food nightlife");

    println!("Persona preference scores:");
    println!("  Kyoto (nature, quiet, temples): {kyoto_score:.3}");
    println!("  Osaka (city, food, nightlife): {osaka_score:.3}");
    println!();

    // Degree-grid cloaking (not H3) for destination coords
    let cloaker = SpatialCloaker::new(0.1);
    let (kyoto_lat, kyoto_lng) = cloaker.cloak(35.0116, 135.7681);
    let (osaka_lat, osaka_lng) = cloaker.cloak(34.6937, 135.5023);
    println!("Cloaked destination cells (0.1° grid):");
    println!("  Kyoto: ({kyoto_lat:.1}, {kyoto_lng:.1})");
    println!("  Osaka: ({osaka_lat:.1}, {osaka_lng:.1})");
    println!();

    let config = BacktestConfig {
        experiment_name: "mvp-trip-preview".to_owned(),
        train_ticks: 5,
        eval_ticks: 5,
        store_config: StoreConfig::Memory,
    };

    let result = BacktestRunner::new(config, build_registry)
        .run()
        .expect("backtest run failed");

    println!("Backtest results:");
    println!("  Train events: {}", result.train_events);
    println!("  Eval events:  {}", result.eval_events);
    println!("  Persistence lift: {:.3}", result.persistence_lift);

    let report = result
        .eval_report
        .as_ref()
        .expect("eval report should be present");
    println!();
    println!("CalibrationReport (eval timeline):");
    println!("  n_predictions: {}", report.n_predictions);
    println!("  n_resolved:    {}", report.n_resolved);
    println!("  brier_score:   {:.4}", report.brier_score);
    println!("  ece:           {:.4}", report.ece);
    println!("  lift_vs_persistence: {:.4}", report.lift_vs_persistence);
    println!();

    assert!(
        report.n_resolved > 0,
        "MVP must close the eval loop (n_resolved > 0)"
    );

    println!("MVP complete — persona + eval loop closed");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn mvp_smoke_test() {
        let model = PersonaModel::new(vec![("nature".to_owned(), 0.8), ("food".to_owned(), 0.9)]);
        let kyoto_score = model.score_option("kyoto nature");
        assert!(kyoto_score > 0.0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn mvp_backtest_resolves_predictions() {
        let config = BacktestConfig {
            experiment_name: "mvp-test".to_owned(),
            train_ticks: 3,
            eval_ticks: 3,
            store_config: StoreConfig::Memory,
        };
        let result = BacktestRunner::new(config, build_registry)
            .run()
            .expect("backtest");
        let report = result.eval_report.expect("report");
        // Fork inherits train events; eval adds more — all should resolve.
        assert!(report.n_resolved >= 3);
        assert!(report.brier_score >= 0.0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn main_does_not_panic() {
        main();
    }
}
