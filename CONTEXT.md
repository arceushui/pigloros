# PiglorOS — Domain Context & Glossary

A shared language for humans and agents working on PiglorOS. Use these terms exactly — don't drift to synonyms.

---

## What PiglorOS Is

**PiglorOS** is a deterministic, event-sourced simulation world engine written in Rust. It allows users and AI agents to **preview decisions** — scoring two options against preference weights, simulating dual-future timeline forks, and evaluating prediction accuracy via calibration metrics — before committing to a choice in the real world.

---

## Core Concepts

| Term | Crate / Module | Meaning |
|---|---|---|
| **Timeline** | `pos-core`, `pos-store` | An append-only, ULID-identified event log. The atomic unit of shared state. |
| **Event** | `pos-core` | An immutable record appended to a Timeline. Has `entity_id`, `event_type`, `seq`, and a canonical CBOR payload. |
| **EntityId** | `pos-core` | A ULID identifying a simulation entity (persona, agent, society aggregate, etc.). |
| **EventStore** | `pos-store` | The `EventStore` trait abstraction over storage backends (SQLite WAL or in-memory). |
| **Projection** | `pos-state` | A fold over a Timeline's events that produces current state. Managed by `ProjectionRegistry`. |
| **Fork** | `pos-time` | A Copy-on-Write branch of a Timeline used to simulate a hypothetical future without mutating the original. |
| **Merge** | `pos-time` | Rejoining a forked Timeline back into the main branch after comparison. |
| **Replay** | `pos-time` | Re-running events from a Timeline from a given sequence number to rebuild state. |
| **Snapshot** | `pos-time` | A point-in-time capture of projected state, used to accelerate Replay. |

---

## Decision Preview Pipeline

| Term | Module | Meaning |
|---|---|---|
| **Decision Preview** | `apps/pos-mvp` | The core user-facing loop: preferences → option scoring → recommendation → calibration. |
| **Scenario** | `pos-mvp` | A named binary decision domain (e.g. `places`, `work`). Defines two `OptionSpec`s and default preference weights. |
| **OptionSpec** | `pos-mvp` | One side of a binary decision: a label, tags, lean hint, and optional coordinates. |
| **Preference** | `pos-mvp`, `pos-plugin-persona` | A named dimension weight in `[-1.0, 1.0]` expressing affinity (e.g. `nature=0.8`). |
| **PersonaModel** | `plugins/persona` | Scores an option's tags against a set of Preferences using a weighted dot product. |
| **Match Score** | `pos-mvp` | The output of `PersonaModel::score_option` for one option (a real number). |
| **Recommendation** | `pos-mvp` | The winning option determined by comparing Match Scores; "Toss-up" when margin < 0.02. |
| **Fork Compare** | `pos-mvp`, `pos-time` | `--fork-compare` mode — CoW twin timelines, one per option — showing diverged entity state side-by-side. |

---

## Shared World Layer

| Term | Module | Meaning |
|---|---|---|
| **Gateway** | `apps/piglor-gateway` | The local-first HTTP gateway (ADR-014). Manages Timelines and event append/poll over HTTP. |
| **Society Signal** | `plugins/society` | A `society.signal` event encoding a value for one social dimension (`trust`, `opinion`, `culture`, `economy`, `polarization`). |
| **Society Reducer** | `plugins/society` | Folds Society Signals into running means per dimension. |
| **Context Nudge** | `apps/pos-mvp` (gateway_context.rs) | Adjusts Preferences using Society Signal means before scoring. Formula: `adjusted = clamp(pref + avg(nudges), -1, 1)` where `nudge = (mean - 0.5) × 0.25`. |
| **AI Influence Index** | `apps/pos-mvp` (ai_influence.rs) | Fraction of Timeline events from AI agents (`agent.*`), broken down by archetype (`goal-seeking`, `rule-bound`). Always shown as a headline. |
| **Prediction Ledger** | `apps/piglor-gateway` | `GET /v1/ledger` — tamper-evident log of predictions with confidence scores, Brier scores, and verification hashes (ADR-016). |

---

## Calibration & Evaluation

| Term | Module | Meaning |
|---|---|---|
| **Brier Score** | `plugins/eval` | Mean squared error of probabilistic predictions. Lower = better; 0 = perfect; 0.25 ≈ coin-flip. |
| **ECE** | `plugins/eval` | Expected Calibration Error across 10 equal-width probability bins. |
| **Lift** | `plugins/eval` | Brier improvement over a naive baseline predictor. Positive = model beats base rate. |
| **Lift vs Personal Base Rate** | `plugins/eval` | Per-entity Brier improvement. Each entity's predictions are scored against its own historical outcome rate (leave-one-out). |
| **CRPS** | `plugins/eval` | Continuous Ranked Probability Score. For binary outcomes equals Brier; for continuous distributions it may diverge in future. |
| **Calibration Report** | `plugins/eval` | Output of `compute_report`: Brier + CRPS + ECE + Lift + Personal Base Rate + reliability bins. |
| **Reliability Bin** | `plugins/eval` | One of 10 equal-width buckets mapping predicted probability to observed frequency. |
| **Backtest** | `apps/pos-experiment` | Running a `BacktestRunner` over train + eval ticks to produce a `CalibrationReport`. |

---

## Plugin System

| Term | Module | Meaning |
|---|---|---|
| **Plugin** | `pos-runtime` | A named, schema-registered domain extension. Must implement `Plugin` trait. |
| **PluginRegistry** | `pos-runtime` | Hosts plugins and routes events to their `Reducer` and `Driver`. |
| **Reducer** | `pos-runtime` | Folds events into `State`. Read-only w.r.t. the event store. |
| **Driver** | `pos-runtime` | Produces `EventDraft`s in response to state or external stimuli. |
| **Hasher** | `pos-core` | Trait decoupling BLAKE3 from store adapters (`genesis_hash`, `hash_payload`, `hash_event`). Default: `Blake3Hasher`. |
| **Upcaster** | `pos-core` | Trait for schema evolution: transforms a payload from one `SchemaVersion` to the next. |
| **UpcasterRegistry** | `pos-core` | Registry of `Upcaster`s, keyed by `(event_type, source_version)`. Applied via `EventStore::read_upcast`. |

---

## Delivery Vocabulary

| Term | Meaning |
|---|---|
| **Wave** | A named delivery increment. Waves 1–7 shipped on `main`. Wave 8+ planned. |
| **ADR** | Architecture Decision Record. Canonical on Redmine wiki (`redmine.piglor.com/projects/pigloros/wiki`). |
| **Thin MVP** | Minimal vertical slice — just enough to validate the concept without deferred features. |
| **Deferred** | Explicitly out-of-scope for the current wave; tracked in Redmine or ADR non-goals. |

---

## Terms to Avoid

| Don't say | Say instead |
|---|---|
| "event log" | **Timeline** |
| "user profile" | **Persona** or **PersonaModel** |
| "prediction accuracy" | **Brier Score** or **Calibration Report** |
| "branch" (for simulation) | **Fork** |
| "social data" | **Society Signal** |
| "AI share" | **AI Influence Index** |
