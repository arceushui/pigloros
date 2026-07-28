# GPU-Accelerated Multi-Agent Simulation Architectures

Research note for ADR-019. Investigates seven systems to inform PiglorOS's
architecture for GPU-accelerated multi-agent simulation.

**Date:** 2026-07-28
**Status:** Draft

---

## 1. Madrona

**Source:** [madrona-engine.github.io](https://madrona-engine.github.io/),
[SIGGRAPH 2023 paper](https://madrona-engine.github.io/shacklett_siggraph23.pdf),
[GitHub: shacklettbp/madrona](https://github.com/shacklettbp/madrona)

**Type:** GPU-accelerated ECS game engine for batch simulation (C++ with Python
bindings via nanobind).

### Architecture

Madrona implements the **first fully GPU-accelerated ECS** that natively supports
batch environment simulation. The core idea is that the Entity Component System
(ECS) design pattern imposes structure on a training environment's logic and
state that allows the system to efficiently manage state, amortize work, and
identify GPU-friendly coherent parallel computations within and across different
environments.

- **ECS Registry** (`ECSRegistry`): User code registers all ECS Components and
  Archetypes upfront. Unlike other ECS engines, adding and removing components
  dynamically from entities is not supported — all archetypes must be declared
  at initialization time.
- **Task Graph** (`TaskGraphBuilder`): The simulation step is expressed as a
  task graph that is executed across all worlds. This is the structural analog
  to PiglorOS's `PluginRegistry::step_all()`.
- **Dual Backend**: `MWCudaExecutor` (GPU) and `TaskGraphExecutor` (CPU).
  Simulators can execute on GPU or CPU with no code changes — a single public
  interface via the `Context` class (`include/madrona/context.hpp`).
- **State Export**: ECS simulation state can be exported as PyTorch tensors via
  nanobind's dlpack integration for efficient interoperability with learning
  code.
- **Batch Renderer**: Separate high-throughput batch renderer (SIGGRAPH Asia
  2024), achieving >300K FPS on geometrically simple scenes and 30K FPS on
  scenes with ~7M triangles (RTX 4090/H100).

### Performance Claims

| Environment | Throughput (RTX 4090) | CPU Baseline Speedup |
|---|---|---|
| Overcooked-AI | 40M steps/s | >1000x over Python baseline |
| Hanabi | 20M steps/s | — |
| Hide and Seek (3D) | 1.9M steps/s | 2-3 orders of magnitude over CPU; 5-33x over 32-thread CPU |

The SIGGRAPH 2023 paper reports GPU speedups of **two to three orders of
magnitude** over open-source CPU baselines and **5×–33×** over strong baselines
running on a 32-thread CPU.

### Language / Bindings

- **Core**: C++ (CUDA for GPU backend)
- **Python**: nanobind bindings with dlpack tensor export (PyTorch-focused)
- **Rust**: No Rust bindings. The engine is a C++ library integrated as a CMake
  submodule.

### Integration Potential with PiglorOS

Madrona would **not** integrate under `pos-runtime` — it would effectively
**replace** the simulation loop. Madrona is a game engine/framework, not a
plugin host. The ECS is entirely GPU-resident; there is no concept of an
event store, replay, or fork.

**Key design lessons for PiglorOS:**

1. **Declare archetypes upfront** — Madrona requires all component combinations
   to be registered at init time. This is the constraint that enables GPU
   memory layout and kernel batching. If PiglorOS wants GPU-accelerated
   drivers, it may need a similar "driver schema" that declares entity types
   and component layouts at registration time.

2. **Task Graph as step loop** — Madrona's `TaskGraphBuilder` is structurally
   equivalent to `PluginRegistry::step_all()`. The task graph model could
   inform a parallelized step loop where drivers declare their dependencies
   and the runtime schedules them on GPU streams.

3. **Dual CPU/GPU backend** — Madrona proves that a single API surface can
   serve both CPU debugging and GPU production. PiglorOS could adopt the same
   pattern: drivers implement a single trait, and the runtime selects a
   CPU or GPU executor.

4. **State export to tensors** — Madrona's dlpack integration for exporting ECS
   state as learning-framework tensors could inform a PiglorOS bridge that
   exports `ProjectionRegistry` state to PyTorch/JAX tensors for ML training
   loops.

### Key Design Decisions

- ECS is the right abstraction for GPU batching: the structure imposed by
  components and archetypes enables the compiler/runtime to lay out memory
  contiguously and launch coherent kernels.
- Requiring upfront archetype registration is a performance trade-off that
  eliminates dynamic allocation and enables static memory planning.
- The task graph model (systems wired into a DAG) is more flexible than a
  simple sequential loop and allows the runtime to identify parallelism.

---

## 2. PufferLib

**Source:** [GitHub: PufferAI/PufferLib](https://github.com/PufferAI/PufferLib),
[puffer.ai](https://puffer.ai),
[PufferLib 2.0 paper (RLJ 2025)](https://arxiv.org/abs/2406.12905)

**Type:** End-to-end RL training library with native CUDA C backend
(20M steps/s). Includes Ocean environment framework.

### Architecture

PufferLib 4.0 has a **native CUDA C backend** (~5,000 lines) with a PyTorch
fallback (~1,000 lines Python). The architecture has three layers:

- **PuffeRL**: The training runtime. Implements PPO variant with Muon optimizer,
  custom GAE+VTrace advantage, and prioritized replay over trajectory segments
  using absolute advantage. Uses MinGRU (parallelizable RNN) + highway nets
  architecture.
- **Ocean**: 20+ environments from simple arcade games to massively multi-agent
  simulations. Environments are written in **C** (not C++), compiled to shared
  libraries. Observations, actions, rewards, terminals are allocated as
  contiguous buffers across all environment instances.
- **Constellation**: Experiment dashboard and visualization in C.

**Memory Model:** Tensors are structs with shape and data pointer. Every tensor
registers its size with an allocator at init time. After all tensors are
registered, the allocator sums up the sizes and does a **single allocation of
contiguous memory**. Separate allocators for weights, gradients, and activations.
No tensors are created or reallocated afterwards. Static memory improves
performance, simplifies CUDA graph tracing, and cleans up profile timelines.

**Vectorization:** Environment instances are chunked into buffers, each
associated with a rollout worker on a separate CUDA stream. Within each buffer,
environment execution is parallelized with OMP threading. Rollout workers are
independent but each process the same number of environment steps per epoch.
Each buffer asynchronously queues data transfers to/from the GPU using pinned
memory.

**Environment Model:** Ocean environments follow a simple C interface:
- `.h` file: core environment logic
- `.c` file: standalone demo
- Only the `.h` file is compiled for training. Observations, actions, rewards,
  and terminals are contiguous across all environment instances.
- Environment handles its own resets internally.

### Performance Claims

- **20M step/s training** (CUDA C native backend)
- **5M step/s training** (PyTorch backend)
- Single RTX 5090 trains Breakout agent in 3-5 seconds
- Atari-level environments run at 1M+ steps/s in-browser (WebGPU)

### Language / Bindings

- **Core**: CUDA C, C (environments), Python (interface/orchestration)
- **Rust**: No Rust bindings or integration points.

### Integration Potential with PiglorOS

PufferLib offers **no direct integration** — it's a monolithic RL training
library, not a simulation framework. However, its design patterns are highly
relevant:

1. **Static memory allocation** — The "register all tensors, allocate once"
   pattern eliminates allocation overhead from the hot path. PiglorOS's
   `EventStore` append path could adopt a similar pre-allocation strategy for
   GPU-accelerated event batches.

2. **Contiguous multi-agent buffers** — Ocean's design of contiguous
   observations/actions/rewards across all environments and all agents is the
   pattern Gigaflow also uses. This could inform a "batch event draft" format
   in pos-runtime where `DraftBatch` becomes a GPU buffer rather than
   `Vec<EventDraft>`.

3. **CUDA streams for parallel rollout** — The pattern of splitting environments
   into chunks on separate CUDA streams could apply to parallelizing
   `step_all()` across driver groups.

4. **Environment-as-C-library** — Ocean environments are pure C files with a
   simple interface, compiled to `.so`. This is similar to PiglorOS's plugin
   model (Rust trait), but at a lower level that enables direct GPU kernel
   fusion.

### Key Design Decisions

- Native CUDA C, not Python wrappers around C++ — the simplest possible
  interface to the GPU.
- Separate allocators for weights, gradients, activations — eliminates
  fragmentation and enables single-kernel updates.
- Environment logic lives in C headers, compiled directly into training binary
  — no serialization, no IPC.
- Muon optimizer + MinGRU + highway nets as the default architecture — chosen
  for throughput, not novelty.

---

## 3. GIGAFLOW

**Source:** Cusumano-Towner et al., "Robust Autonomy Emerges from Self-Play,"
[arXiv:2502.03349](https://arxiv.org/abs/2502.03349) (2025),
[HTML version](https://arxiv.org/html/2502.03349v1)

**Type:** Custom batched simulator purpose-built for self-play RL at
unprecedented scale (1.6 billion km of driving).

### Architecture

Gigaflow simulates **38,400 environments in parallel across 8 GPUs**, with up
to **150 vehicles per environment** — a total of ~5.7M agents. The key
architectural decisions:

**Simulator Design (Appendix A):**
- **2.5-D simulation**: Dynamics model uses a bicycle model with acceleration,
  steering, and brake actions. 2D kinematics with semantic elevation — no full
  3D physics.
- **Spatial hash for map observations**: Precomputes and caches all map
  observations (lane points, boundaries) in a spatial hash. Fast GPU-based
  runtime lookup and retrieval.
- **Observation construction on demand**: To reduce memory, observations are not
  stored in the rollout buffer but calculated from stored world states. This is
  the opposite of PiglorOS's approach (storing all events).
- **Collision detection**: Optimized GPU data structures for agent localization
  and collision checking. All operations batched across agents.
- **No scenario scripting**: Agents are spawned randomly on road networks and
  tasked with reaching random goals. All behavior emerges from self-play.
- **Eight maps**: 4-40 km of drivable lanes each, 136 km total. Randomly
  perturbed with rescaling, shears, flips, reflections.

**Policy Architecture (Appendix D):**
- **Single unified policy** (6M parameters) for all traffic participants:
  vehicles, pedestrians, cyclists, trucks.
- **Deep Sets architecture**: Permutation-invariant with respect to each
  observation type (agents, lanes, boundaries, stop lines).
- **Conditioning parameters C**: `C_dynamics` (vehicle type, dimensions, turning
  radius) and `C_reward` (randomized reward weights) modulate behavior.
  Critically: an agent observes ONLY its own conditioning, not others'.
  This forces robustness to unpredictable behaviors.
- **Feed-forward**: No recurrence, no planning module, no search. Optimizes
  long-term return directly without explicit horizon.

**Training (Appendix C):**
- **PPO with advantage filtering**: Filters up to 80% of samples with low
  absolute advantage. Focuses training on informative state transitions,
  significantly increases learning throughput without sacrificing sample
  efficiency.
- **Inference**: 7.4M decisions/s during experience collection (batch size
  2.6M). 8 gradient updates/s during training (batch size 256K). On 8× A100.

### Performance Claims

| Metric | Value |
|---|---|
| State transitions per hour | 4.4 billion |
| Driving km per hour | 7.2 million |
| Speedup vs real time | 360,000× |
| Full training run | 1 trillion state transitions, 1.6 billion km, ~9,500 years subjective |
| Training wall time | <10 days on 8× A100 |
| Cost per million km | <$5 (public cloud rates) |
| Incidents per km (eval) | 1 per 3M km (17.5 years continuous driving) |

### Language / Bindings

- **Core**: Likely C++/CUDA (authors include Erik Wijmans, co-author of Madrona;
  paper cites Madrona for batched simulator methodology). Not open-source as of
  writing.
- **Rust**: No Rust bindings.

### Integration Potential with PiglorOS

Gigaflow is the closest architectural analog to what PiglorOS could become with
GPU acceleration. The key parallels and contrasts:

**Parallels:**
- Gigaflow's "single policy for all agents" maps to PiglorOS's `Driver::step()`
  being called for each plugin. A GPU-accelerated PiglorOS would similarly batch
  all agents through a single kernel.
- The conditioning parameters `C` are analogous to PiglorOS's `PersonaModel`
  preferences — a single policy expressing diverse behaviors.
- The map+agents observation model maps to PiglorOS's `ProjectionRegistry`
  fold — agents observe the folded state of the world.

**Contrasts:**
- Gigaflow does **not** have an event store. Observations are computed on
  demand from world state — they are not persisted. PiglorOS persists
  everything.
- Gigaflow has **no replay determinism** mechanism. The Recorder is a PiglorOS
  differentiator.
- Gigaflow simulates only driving (one domain). PiglorOS is a general-purpose
  simulation world.
- Gigaflow's 6M-parameter policy is a neural network. PiglorOS's drivers are
  arbitrary Rust code — more flexible but harder to GPU-accelerate.

**Key design lessons:**
1. **Single-policy batching is the secret to scale**: By making all agents share
   one neural network, Gigaflow needs only one forward pass per step for all
   5.7M agents. This is the architectural constraint that enables the
   throughput.
2. **Don't store observations, compute them**: Gigaflow computes agent
   observations from world state instead of storing them. This eliminates the
   memory bottleneck. For PiglorOS, this suggests that `ProjectionRegistry` may
   not need to store full state per agent — it could compute views on demand.
3. **Advantage filtering eliminates compute waste**: 80% of transitions have
   near-zero advantage in steady-state driving. Filtering them saves compute
   without hurting sample efficiency. PiglorOS could apply a similar filter at
   the event level — skip replay/fold for events that don't change the decision
   landscape.
4. **2.5-D is sufficient**: Gigaflow proves that 2D kinematics + semantic
   elevation is enough for rich emergent behavior. PiglorOS doesn't need full
   3D physics for most social simulation scenarios.

---

## 4. Genesis (now Genesis World)

**Source:** [genesis-embodied-ai.github.io](https://genesis-embodied-ai.github.io/),
[GitHub: Genesis-Embodied-AI/genesis-world](https://github.com/Genesis-Embodied-AI/genesis-world),
[Blog: "The Role of Simulation in Scalable Robotics"](https://www.genesis.ai/blog/the-role-of-simulation-in-scalable-robotics-genesis-world-10-and-the-path-forward) (May 2026)

**Type:** Python-based unified multi-physics simulation platform for robotics
and embodied AI. Originally claimed 43M FPS for simple scenes.

### Architecture

Genesis World is a four-layer stack:

1. **Simulation Interface** — Pythonic API: asset parsing (URDF, MJCF, OBJ, GLB,
   USD), entity accessors, controllers, sensors, parallel and heterogeneous
   environments, built-in GUI.

2. **Physics** — Unified multi-physics engine integrating:
   - Rigid body dynamics
   - FEM (Finite Element Method)
   - MPM (Material Point Method)
   - Particle-based (PBD/SPH)
   - [uipc](https://github.com/spiriMirror/libuipc) IPC solver
   - SAP constraint solver
   - Explicit coupler for multi-physics interaction

3. **Render** — Three rendering paths as camera sensors:
   - **Nyx**: In-house photorealistic renderer designed for robotics
   - **Luisa**: DSL ray tracer
   - **Pyrender**: Rasterizer

4. **Compiler** — **[Quadrants](https://github.com/Genesis-Embodied-AI/quadrants)**:
   Lowers Python kernel code to CUDA, AMD ROCm, Apple Metal, Vulkan, x86, and
   ARM64. Carries Genesis's autodiff, GPU graphs, and fastcache. Forked from
   Taichi in June 2025.

**Parallel environments:** Supports parallel and heterogeneous simulation
environments via the Python API.

**No built-in agent model:** Genesis is a physics engine, not an agent
framework. Agents (RL policies, controllers) are external to Genesis and
interact through the Python API.

### Performance Claims

- Originally claimed **43M FPS** for a falling-army scene (specific
  configuration: single rigid body, no rendering)
- The 43M FPS number is from a specific early benchmark, not representative
  of general simulation throughput
- Current focus is on platform breadth (multi-physics, multi-backend) rather
  than raw throughput

### Language / Bindings

- **Core**: Python API with C++/CUDA backends (via Quadrants compiler)
- **Rust**: No Rust support. The Quadrants compiler compiles Python to GPU
  kernels, using Taichi-style metaprogramming.

### Integration Potential with PiglorOS

Genesis is **not a good integration target** for PiglorOS:

1. **Python-centric**: The entire API is Python. PiglorOS is Rust. Bridging
   via PyO3 would add significant overhead.
2. **Physics, not agents**: Genesis simulates physics, not agent decision-making.
   It has no concept of plugins, drivers, or event sourcing.
3. **No replay determinism**: Genesis does not provide deterministic replay
   across runs.
4. **Large dependency**: Genesis brings Taichi/Quadrants, multiple solver
   backends, rendering systems — massive dependency footprint.

**Key design lesson:**
- Genesis's multi-physics coupling approach (rigid + FEM + MPM in one scene)
  could inform a PiglorOS "world model" plugin that combines physics with
  social simulation. But the actual integration would likely be through
  Genesis as an external service, not as a plugin.

---

## 5. Melting Pot

**Source:** [GitHub: google-deepmind/meltingpot](https://github.com/google-deepmind/meltingpot),
[Melting Pot (ICML 2021)](https://arxiv.org/abs/2107.06857),
[Melting Pot 2.0 (arXiv:2211.13746)](https://arxiv.org/abs/2211.13746),
[Docs: concepts.md](https://github.com/google-deepmind/meltingpot/blob/main/docs/concepts.md)

**Type:** Multi-agent RL evaluation framework with 50+ substrates and 256+
scenarios. Built on DeepMind Lab2D (C++ grid engine with Lua scripting).

### Architecture

Melting Pot is built on **DeepMind Lab2D**, a 2D grid-based game engine where
environments consist of a grid `(x, y, layer)`. The Melting Pot layer adds
Object-Oriented abstractions:

**Substrate Concepts (from concepts.md):**

- **GameObject**: Every object in Melting Pot is a GameObject (avatars, walls,
  spawn points, logical objects). A GameObject is an empty vessel — it does
  nothing by itself. You add Components to make it functional.
- **Component**: A piece of logic (Lua code) attached to a GameObject. Always
  has `StateManager` and `Transform` components. Optional components include
  `Avatar`, `Zapper`, `Appearance`, etc.
- **StateManager**: Tracks state (layer, sprite, groups, contact). State changes
  are not immediate — they are queued and take effect after an engine update.
- **Transform**: Position `(x, y)` and orientation (N/E/S/W). Provides
  movement, teleport, and query methods.
- **Updaters**: An alternative to the `update()` callback. Registered with
  parameters: priority, start frame (delay after state change), probability
  (per-step execution probability), group/state filtering.
- **Simulation**: Contains all GameObjects, provides queries by name or
  component type.

**Key structural split:**
- **Substrate**: A game environment (the "physical" world) + optional bots.
  ~50 substrates covering cooperation, competition, deception, reciprocation,
  trust, stubbornness, etc.
- **Scenario**: A substrate + a specific background population of bots.
  ~256 scenarios. This is the generalization test: train on substrate with
  one set of partners, evaluate with different partners.

**Python/Lua boundary:**
- Entire level configuration is a Python dictionary. Lua is only needed for
  writing custom Components.
- Bot policies must be TensorFlow SavedModel format. Puppets can use
  `Puppeteer` classes.
- Actions are discrete (grid movement, rotation, beam firing).

**No GPU batching:** Lab2D runs one environment instance at a time on CPU.
Melting Pot evaluates generalization, not throughput.

### Performance Claims

- No GPU acceleration. Evaluates generalization quality, not simulation
  throughput.
- Designed for research, not production simulation scale.

### Language / Bindings

- **Core**: C++ (DeepMind Lab2D engine), Lua (substrate logic), Python
  (configuration and RL integration)
- **Rust**: No Rust bindings.

### Integration Potential with PiglorOS

Melting Pot is the **most conceptually relevant** system to PiglorOS:

1. **Substrate = Plugin**: Melting Pot's "substrate" is structurally equivalent
   to a PiglorOS plugin — a named module that defines event types, entities, and
   game logic. Substrates can be composed (multiple substrates share the grid).
2. **Scenario = Experiment config**: The substrate+population split maps to
   PiglorOS's `ExperimentConfig` + plugin registration.
3. **GameObject + Component = Entity + Reducer**: The decomposition of behavior
   into Components attached to GameObjects is analogous to PiglorOS's Reducer
   trait that folds events into entity state.
4. **Updaters = Driver::step()**: The updater system (priority-ordered,
   state-filtered, probabilistic per-step callbacks) is a more sophisticated
   version of `Driver::step()`.
5. **StateManager queueing = Event sourcing**: State changes in Melting Pot are
   not immediate — they are queued and applied after the update. This is the
   same principle as PiglorOS's event sourcing: actions produce drafts, drafts
   become events, events fold into state.
6. **Generalization protocol**: Melting Pot's evaluation of generalization to
   novel social partners is directly applicable to PiglorOS's fork-compare
   and backtest workflows.

**Key design lessons:**
- The substrate/scenario split is a proven pattern for evaluating social
  generalization. PiglorOS could adopt a similar "evaluation scenario"
  concept for backtests.
- Component-based GameObject design enables reuse across substrates.
  PiglorOS's plugin model already supports this through shared Reducers.
- Melting Pot's integration of game-theoretic and evolutionary-biology-inspired
  scenarios demonstrates what social simulations should cover. These could be
  ported as PiglorOS substrate plugins.
- The Lua scripting model (Python for config, Lua for logic) is a lesson in
  what NOT to do for performance — PiglorOS's all-Rust approach avoids the
  language boundary overhead.

---

## 6. Isaac Lab (NVIDIA)

**Source:** [isaac-sim.github.io/IsaacLab](https://isaac-sim.github.io/IsaacLab/)
(redirects to latest), NVIDIA Omniverse documentation

**Type:** GPU-accelerated robotics simulation and RL training framework built on
NVIDIA Omniverse (Isaac Sim).

### Architecture

Isaac Lab is NVIDIA's unified framework for robot learning, built on top of
**Isaac Sim** (which is built on Omniverse, using PhysX for physics):

- **Isaac Sim**: Omniverse-based robotics simulator with PhysX 5, RTX rendering,
  ROS integration. GPU-accelerated physics simulation.
- **Isaac Lab**: Adds RL training workflows, environment APIs (Gymnasium-style),
  domain randomization, teacher-student training, multi-environment parallelism.
- **Parallel environments**: Runs many independent simulation instances (each in
  its own PhysX scene) on a single GPU or across multiple GPUs.
- **Tile rendering**: Renders multiple camera views in a single render pass
  for efficient visual RL.

### Performance Claims

- Claimed significant speedups (100-1000x vs CPU robotics simulators) for
  parallel kinematics and dynamics
- Specific numbers depend on scene complexity, number of environments, and
  rendering requirements
- Not designed for multi-agent social simulation — focused on single-robot
  or multi-robot manipulation/locomotion tasks

### Language / Bindings

- **Core**: C++/CUDA (Omniverse/PhysX), Python (Isaac Lab API)
- **Rust**: No Rust support.

### Integration Potential with PiglorOS

Isaac Lab has **minimal relevance** to PiglorOS's domain:

1. **Robotics, not social simulation**: Isaac Lab is purpose-built for robot
   manipulation and locomotion. Its physics engine (PhysX) and rendering
   pipeline (RTX) are overkill for social simulation.
2. **NVIDIA lock-in**: Requires Omniverse + RTX GPU + specific driver versions.
   PiglorOS targets commodity hardware.
3. **Gymnasium-style API**: The environment interface is Gymnasium (step,
   reset, observe), not event-sourced.

**Key design lessons:**
- The parallel environment model (many independent PhysX scenes on one GPU) is
  similar to Madrona's and Gigaflow's batching approach.
- Domain randomization as a first-class feature could inform PiglorOS's
  "scenario diversity" patterns for backtesting.
- Teacher-student training in Isaac Lab maps conceptually to PiglorOS's
  fork-compare where one fork is the "teacher" (real world) and another is
  the "student" (simulation).

---

## 7. Cross-Cutting Analysis: Relevance to PiglorOS

### The Batching Spectrum

All GPU-accelerated systems studied here use one of two batching strategies:

| Strategy | Systems | Description |
|---|---|---|
| **Environment-level batching** | Madrona, PufferLib, Isaac Lab | Many independent envs share one GPU kernel. Each env has its own state, agents are environment-local. |
| **Agent-level batching** | GIGAFLOW | All agents across all envs share one policy network. One forward pass computes actions for all agents. |

PiglorOS currently does neither — it steps each driver sequentially. A
GPU-accelerated PiglorOS would need to choose one or combine both.

### Event Sourcing vs. World State

All seven systems use **world state** (mutable in-memory state updated in-place).
None use event sourcing. This is the fundamental architectural difference:

- **World state systems**: Step = update all entities in place. Fast,
  GPU-friendly. No history. No replay without checkpointing.
- **PiglorOS**: Step = append immutable events. State = fold over events. Slow
  (per-event), CPU-bound. Full history. Deterministic replay by construction.

If PiglorOS wants GPU acceleration, it has three options:

1. **Hybrid event + state**: Keep the event store for persistence/replay, but
   maintain a GPU-resident "hot state" that drivers read from. Events are the
   source of truth; GPU state is a cache.
2. **Batch event generation**: Drivers produce event drafts in GPU batches
   (like Gigaflow's single-policy inference). The event store append remains
   CPU-based but batch-sized.
3. **GPU-native event store**: An event store backend that stores events in
   GPU memory and supports GPU-side fold/replay. This is a research problem.

### The PiglorOS Differentiators

These capabilities make PiglorOS unique and should be preserved in any GPU
acceleration plan:

| Capability | Systems that have it | Value |
|---|---|---|
| Event sourcing | None | Full audit trail, deterministic replay, fork/merge |
| Recorder (deterministic nondeterminism) | None | LLM calls, RNG, sensor reads are reproducible |
| Fork/Merge | None (except git-inspired) | Compare decision outcomes side by side |
| Plugin model | Melting Pot (substrates) | Open ecosystem, composability |
| Calibration metrics | None | Brier Score, ECE, Lift — science-grade evaluation |

### Recommended Architecture for ADR-019

Based on this research, a GPU-accelerated PiglorOS architecture should consider:

1. **GPU Driver trait**: A new `GpuDriver` trait that produces `GpuDraftBatch`
   (a GPU buffer of event drafts) instead of `Vec<EventDraft>`. The runtime
   selects the GPU executor when available.

2. **Hot State Cache**: A GPU-resident mirror of `ProjectionRegistry` state.
   Updated incrementally after each event batch. Drivers read from GPU state,
   produce GPU drafts. The event store remains the source of truth.

3. **Single-Policy Architecture** (inspired by Gigaflow): For ML-based agents,
   all agents share one neural network. Conditioning parameters (persona,
   preferences) modulate behavior. This enables the key scalability insight:
   one forward pass for all agents.

4. **Gigaflow-style advantage filtering for event pruning**: During replay for
   training, filter out events that have minimal impact on the decision
   landscape. This reduces the computational cost of fold/replay without
   losing signal.

5. **Madrona-style archetype pre-declaration**: GPU drivers declare their entity
   types, component layouts, and memory requirements at registration time.
   This enables static memory planning and eliminates allocation overhead.

---

## References

1. Shacklett et al., "An Extensible, Data-Oriented Architecture for
   High-Performance, Many-World Simulation," ACM Trans. Graph. (SIGGRAPH 2023).
   https://madrona-engine.github.io/shacklett_siggraph23.pdf

2. Rosenzweig et al., "High-Throughput Batch Rendering for Embodied AI,"
   SIGGRAPH Asia 2024.
   https://madrona-engine.github.io/madrona-renderer.pdf

3. Suarez, "PufferLib 2.0: Reinforcement Learning at 1M steps/s,"
   Reinforcement Learning Journal, vol. 6, pp. 1378-1388, 2025.
   https://arxiv.org/abs/2406.12905

4. Cusumano-Towner et al., "Robust Autonomy Emerges from Self-Play,"
   arXiv:2502.03349, 2025.
   https://arxiv.org/abs/2502.03349

5. Genesis AI Team, "The Role of Simulation in Scalable Robotics, Genesis World
   1.0, and the Path Forward," Genesis AI Blog, May 2026.
   https://www.genesis.ai/blog/the-role-of-simulation-in-scalable-robotics-genesis-world-10-and-the-path-forward

6. Leibo et al., "Scalable Evaluation of Multi-Agent Reinforcement Learning
   with Melting Pot," ICML 2021.
   https://arxiv.org/abs/2107.06857

7. Agapiou et al., "Melting Pot 2.0," arXiv:2211.13746, 2022.
   https://arxiv.org/abs/2211.13746

8. Madrona GitHub repository. https://github.com/shacklettbp/madrona

9. PufferLib GitHub repository. https://github.com/PufferAI/PufferLib

10. Genesis World GitHub repository. https://github.com/Genesis-Embodied-AI/genesis-world

11. Melting Pot GitHub repository. https://github.com/google-deepmind/meltingpot

12. Melting Pot Substrate Concepts. https://github.com/google-deepmind/meltingpot/blob/main/docs/concepts.md

13. NVIDIA Isaac Lab documentation. https://isaac-sim.github.io/IsaacLab/
