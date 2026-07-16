#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `PiglorOS` Single-User MVP: Trip Preview — Kyoto vs Osaka.
//!
//! This MVP demonstrates:
//! 1. A `PersonaModel` that scores trip options by preference dimensions.
//! 2. A `BacktestRunner` that runs train + eval phases with a shared store.
//! 3. Wave 5 plugin composition (rule-agent + synthetic-obs).

use pos_core::ids::EntityId;
use pos_experiment::{BacktestConfig, BacktestRunner};
use pos_plugin_persona::PersonaModel;
use pos_plugin_rule_agent::{RuleAgentDriver, RuleAgentPlugin, RuleAgentReducer};
use pos_plugin_synthetic_obs::{SyntheticDriver, SyntheticObsPlugin, SyntheticReducer};
use pos_runtime::PluginRegistry;
use pos_store::StoreConfig;

fn main() {
    println!("PiglorOS Single-User MVP: Trip Preview — Kyoto vs Osaka");
    println!();

    // 1. Create a PersonaModel with preferences
    let preferences = vec![
        ("nature".to_owned(), 0.8),
        ("city".to_owned(), 0.5),
        ("food".to_owned(), 0.9),
        ("quiet".to_owned(), 0.7),
    ];
    let model = PersonaModel::new(preferences);

    // 2. Print scores for kyoto vs osaka
    let kyoto_score = model.score_option("kyoto nature quiet temples");
    let osaka_score = model.score_option("osaka city food nightlife");

    println!("Persona preference scores:");
    println!("  Kyoto (nature, quiet, temples): {kyoto_score:.3}");
    println!("  Osaka (city, food, nightlife): {osaka_score:.3}");
    println!();

    // 3. Run a BacktestRunner with 5 train ticks + 5 eval ticks
    let config = BacktestConfig {
        experiment_name: "mvp-trip-preview".to_owned(),
        train_ticks: 5,
        eval_ticks: 5,
        store_config: StoreConfig::Memory,
    };

    let runner = BacktestRunner::new(config, || {
        let agent_entity = EntityId::new();
        let obs_entity = EntityId::new();

        let agent_plugin = RuleAgentPlugin::new();
        let agent_driver = RuleAgentDriver::new(agent_entity, agent_plugin.actions().to_vec());
        let agent_reducer = RuleAgentReducer;

        let obs_plugin = SyntheticObsPlugin::new();
        let obs_driver = SyntheticDriver::new(obs_entity);
        let obs_reducer = SyntheticReducer;

        let mut registry = PluginRegistry::new();
        registry
            .register(
                &agent_plugin,
                Some(Box::new(agent_reducer)),
                Some(Box::new(agent_driver)),
            )
            .expect("agent plugin registration failed");
        registry
            .register(
                &obs_plugin,
                Some(Box::new(obs_reducer)),
                Some(Box::new(obs_driver)),
            )
            .expect("obs plugin registration failed");

        registry
    });

    let result = runner.run().expect("backtest run failed");

    // 4. Print results
    println!("Backtest results:");
    println!("  Train events: {}", result.train_events);
    println!("  Eval events:  {}", result.eval_events);
    println!(
        "  Persistence lift: {:.3}",
        result.persistence_lift
    );
    println!();

    println!("MVP complete — Wave 5 Single-User MVP scaffold ready");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mvp_smoke_test() {
        // Just ensure the persona model works
        let model = PersonaModel::new(vec![
            ("nature".to_owned(), 0.8),
            ("food".to_owned(), 0.9),
        ]);
        let kyoto_score = model.score_option("kyoto nature");
        assert!(kyoto_score > 0.0);
    }

    #[test]
    fn main_does_not_panic() {
        // Call main to ensure it runs without panicking
        main();
    }
}
