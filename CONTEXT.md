# PiglorOS domain glossary

Use the names in this glossary consistently. Describe current behavior from the checked-in
implementation source. Decisions and plans explain intent or history; they do not prove what the
code currently does.

## Timeline model

| Term | Code | Meaning |
|---|---|---|
| **Timeline** | `pos-core`, `pos-store` | An append-only sequence of Events. |
| **Timeline Order** | `pos-core`, `pos-store` | The logical order of Events in a Timeline, including inherited Fork history. |
| **Logical Head** | `pos-core`, `pos-store` | The last Event visible in Timeline Order. It can differ from a Fork's local segment head. |
| **Event** | `pos-core` | An immutable record appended to a Timeline. |
| **EntityId** | `pos-core` | A ULID that identifies a simulation entity. |
| **EventStore** | `pos-store` | The storage interface used by the memory and SQLite adapters. |
| **Projection** | `pos-state` | State derived by folding Events in Timeline Order. |
| **Fork** | `pos-time`, `pos-experiment` | A copy-on-write Timeline derived from a parent Timeline to evaluate a counterfactual history. |
| **Tick Boundary** | `pos-experiment` | A host-owned boundary around folding and an atomic Driver step. |
| **ObservationSnapshot** | `pos-runtime` | The projection state shared by Drivers during one scheduled step. |
| **Simulation Time** | `pos-runtime`, `pos-experiment` | Monotonic host-supplied time used to decide Driver cadence. It is separate from Event wall time. |

## Gateway and decisions

| Term | Code | Meaning |
|---|---|---|
| **Gateway** | `apps/piglor-gateway` | The local HTTP service for Timeline, decision, consent, erasure, action, signal, and Prediction Ledger operations. Protected routes require the host's Local Principal and a matching grant. |
| **Local Principal** | `apps/piglor-gateway` | The host-provisioned identity and grants used to authorize protected Gateway operations. |
| **Scenario Room** | `apps/piglor-gateway`, `pos-runtime` | A user-configured simulation context with explicit inputs and immutable revisions. |
| **Preference** | `apps/piglor-gateway`, `pos-plugin-persona` | A set of weighted dimensions used to score options. |
| **OptionSpec** | `apps/piglor-gateway` | A user-authored option with a label, tags, lean hint, and optional coordinates. |
| **Decision Preview** | `apps/piglor-gateway`, `pos-runtime` | A Gateway resource that scores OptionSpec revisions against a Preference and Scenario Room. The release composition currently has no installed execution profile, so fresh preview creation fails closed. |
| **Match Score** | `pos-runtime` | An integer micro-unit score from matching an option's tags to Preference dimensions. |
| **Recommendation** | `pos-runtime` | The option with the strongest Match Score. The Gateway reports a toss-up when the score margin is below 20,000 micro-units and insufficient evidence when no dimension matches. |
| **Society Signal** | `plugins/society` | A `society.signal` Event that records a value for a social dimension. |
| **Consent Timeline** | `apps/piglor-gateway` | The host-owned Timeline that records a Local Principal's consent grants and revocations. |
| **Erasure Host Timeline** | `apps/piglor-gateway`, `pos-runtime` | The host-owned Timeline used by the local erasure authority. Clients cannot read or write it through Gateway routes. |
| **Prediction Ledger** | `plugins/ledger`, `apps/piglor-ledger`, `apps/piglor-gateway` | A public log of registered predictions and their evaluation results. |

## Simulation and plugins

| Term | Code | Meaning |
|---|---|---|
| **Plugin** | `pos-runtime` | A named domain extension that provides a Reducer and may provide a Driver. |
| **PluginRegistry** | `pos-runtime` | The runtime registry that hosts Plugins and routes Events to their Reducers and Drivers. |
| **Reducer** | `pos-runtime` | A component that folds Events into state without writing to the EventStore. |
| **Driver** | `pos-runtime` | A component that produces Event drafts from state or external input. |
| **Sandbox Provider** | `pos-reference`, `apps/pos-sandboxd` | The privileged boundary for isolated adapter execution. `pos-reference` defines the protocol; `pos-sandboxd` implements the Linux systemd provider. |
| **Tenure** | `pos-core`, `pos-runtime` | The Timeline Order range in which one implementation is effective for a required composition entry. |
| **Effective Composition** | `pos-core`, `pos-runtime` | The composition selected at a Timeline position after applying its declarations and activation Events. |

## Evaluation

| Term | Code | Meaning |
|---|---|---|
| **Brier Score** | `plugins/eval` | Mean squared error for probabilistic predictions. Lower is better; zero is perfect. |
| **ECE** | `plugins/eval` | Expected Calibration Error across ten probability bins. |
| **Lift** | `plugins/eval` | Improvement in Brier Score over a baseline predictor. |
| **Calibration Report** | `plugins/eval` | A report containing prediction calibration metrics and reliability bins. |
| **Backtest** | `apps/pos-experiment` | A run over training and evaluation ticks that produces a Calibration Report. |

## Terms to avoid

| Avoid | Use |
|---|---|
| “event log” for the persisted model | **Timeline** |
| “branch” for a simulation alternative | **Fork** |
| “user profile” for weighted scoring input | **Preference** |
| “prediction accuracy” for a calibration measure | **Brier Score** or **Calibration Report** |
