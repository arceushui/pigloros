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
| **Timeline Order** | `pos-core`, `pos-store` | The authoritative logical order of a Timeline's stitched Event history. Public Timeline APIs expose this order through `Event.seq`; fork adapters may persist child-segment-local sequence numbers internally. |
| **Logical Head** | `pos-core`, `pos-store` | The last logical `seq` visible in a stitched Timeline, including inherited fork history and the Timeline's own segment. Distinct from `Timeline.head`, which is the local segment head. |
| **Event** | `pos-core` | An immutable record appended to a Timeline. Has `entity_id`, `event_type`, `seq`, and a canonical CBOR payload. |
| **EntityId** | `pos-core` | A ULID identifying a simulation entity (persona, agent, society aggregate, etc.). |
| **EventStore** | `pos-store` | The `EventStore` trait abstraction over storage backends (SQLite WAL or in-memory). |
| **Projection** | `pos-state` | A fold over a Timeline's events that produces current state. Managed by `ProjectionRegistry`. |
| **Fork** | `pos-time` | A Copy-on-Write branch of a Timeline used to simulate a hypothetical future without mutating the original. |
| **Merge** | `pos-time` | Rejoining a forked Timeline back into the main branch after comparison. |
| **Replay** | `pos-time` | Re-running events from a Timeline from a given sequence number to rebuild state. |
| **Snapshot** | `pos-time` | A point-in-time capture of projected state, used to accelerate Replay. |
| **Tick Boundary** | `pos-experiment` | The host-owned coordination point that folds one complete contiguous Timeline range before or after an atomic driver step. Events are never folded while `step_all` is active. |
| **Fold Cursor** | `pos-experiment` | The last logical Timeline sequence incorporated into live projections. It advances only after a complete validated range is folded and is independent of the local Timeline head. |
| **ObservationSnapshot** | `pos-runtime` | Immutable projection state captured after a tick's pre-step fold and shared by every due Driver for that atomic step. |
| **Simulation Time** | `pos-runtime`, `pos-experiment` | Monotonic host-supplied nanoseconds used only to decide Driver cadence eligibility. Distinct from Event `wall_time` and optional wall-clock demo pacing. |

---

## Decision Preview Pipeline

| Term | Module | Meaning |
|---|---|---|
| **Decision Preview** | external client + `plugins/persona` | The user-facing loop: client-supplied preferences and options → scoring → recommendation → calibration. It is not a bundled scenario or demo binary. |
| **Scenario Room** | planned Wave 9 client contract | A user-configured simulation context with explicit inputs and reproducible Fork identity. No current Rust type or Gateway route is allowed to imply that this contract already exists. It is never a hard-coded product scenario. |
| **OptionSpec** | planned external-client/persona contract | One user- or client-supplied side of a decision: a label, tags, lean hint, and optional coordinates. The current PersonaModel accepts caller-supplied preference inputs; the public client contract remains a Wave 9 deliverable. |
| **Preference** | external client, `pos-plugin-persona` | A named dimension weight in `[-1.0, 1.0]` expressing affinity (e.g. `nature=0.8`). |
| **PersonaModel** | `plugins/persona` | Current in-process validation primitive: scores an option string by averaging matching preference dimensions and normalizing the result. It has no public `OptionSpec` or tag contract yet. |
| **Match Score** | `pos-plugin-persona` | The output of `PersonaModel::score_option` for one option string (a real number); the third-party client contract remains a Wave 9 deliverable. |
| **Recommendation** | external client + `pos-plugin-persona` | The winning option determined by comparing Match Scores; "Toss-up" when margin < 0.02. |
| **Fork Compare** | external client, `pos-time` | CoW Timelines, one per user-supplied option, showing diverged state side-by-side. |

---

## Shared World Layer

| Term | Module | Meaning |
|---|---|---|
| **Gateway** | `apps/piglor-gateway` | The local-first HTTP gateway (ADR-014). Manages Timelines and event append/poll over HTTP. |
| **Society Signal** | `plugins/society` | A `society.signal` event encoding a value for one social dimension (`trust`, `opinion`, `culture`, `economy`, `polarization`). |
| **Society Reducer** | `plugins/society` | Folds Society Signals into running means per dimension. |
| **Context Nudge** | future client composition | Adjusts Preferences using Society Signal means before scoring. Formula: `adjusted = clamp(pref + avg(nudges), -1, 1)` where `nudge = (mean - 0.5) × 0.25`. |
| **AI Influence Index** | future client projection | Fraction of Timeline events from AI agents (`agent.*`), broken down by archetype (`goal-seeking`, `rule-bound`). It is not a current MVP claim. |
| **Prediction Ledger** | `plugins/ledger`, `apps/piglor-ledger`, `apps/piglor-gateway` | Public pre-registered prediction log with Brier Scores, verification hashes, and OSF workflow. Curated TOML tier + signed EventStore tier (ADR-017). |

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

---

## Delivery Vocabulary

| Term | Meaning |
|---|---|
| **Wave** | A named delivery increment. Waves 1–6 shipped foundation increments on `main`; Wave 7's hard-coded demo was retired; Wave 8+ remain planned or in progress. |
| **ADR** | Architecture Decision Record. Canonical on Redmine wiki (`redmine.piglor.com/projects/pigloros/wiki`). |
| **MVP** | The first usable product boundary: an independently built third-party client can submit user-supplied preferences/options, receive a decision preview, operate a Timeline/Scenario Room through documented public contracts, observe committed Events/state, and use Replay/Fork. A hard-coded scenario, generic fixture shell, curl-only smoke test, or embedded demo does not qualify. |
| **Retired demo** | Removed code or documentation that is preserved only as historical context; it is not part of the product or roadmap status. |
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
