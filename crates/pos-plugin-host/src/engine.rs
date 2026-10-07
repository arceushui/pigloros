//! The pinned engine, Component loading and single-invocation execution.

use wasmtime::component::types::ComponentItem;
use wasmtime::component::{Component, ComponentExportIndex, Instance, InstancePre, Linker, Val};
use wasmtime::{Config, Engine, OptLevel, Store, Strategy, WasmBacktraceDetails};

use crate::host_v1::{self, HostInputs, HostState, MemoryLimiter};
use crate::outcome::{classify, InvocationFailure, InvocationReport, LoadError};
use crate::MAX_WASM_STACK_BYTES;

const GUEST_V1_INTERFACE: &str = "pigloros:plugin/guest-v1@0.1.0";

/// One `guest-v1` export that the host may invoke.
///
/// `migrate-state` is deliberately absent: a V1 host never invokes it.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum GuestExport {
    /// `describe: func() -> result<plugin-descriptor, plugin-error>`.
    Describe,
    /// `reduce: func(input: plugin-invocation) -> result<plugin-output, plugin-error>`.
    Reduce,
    /// `drive: func(input: plugin-invocation) -> result<plugin-output, plugin-error>`.
    Drive,
}

impl GuestExport {
    /// Every export the host may invoke, in WIT declaration order.
    pub const ALL: [Self; 3] = [Self::Describe, Self::Reduce, Self::Drive];

    /// The export's WIT name inside `guest-v1`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Describe => "describe",
            Self::Reduce => "reduce",
            Self::Drive => "drive",
        }
    }
}

/// Deterministic budget and operational watchdog for one invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvocationLimits {
    /// Wasmtime fuel shared by instantiation and the call.
    pub fuel: u64,
    /// Ceiling, in bytes, on the linear memory of all the Component's memories.
    pub memory_bytes: u64,
    /// Engine epoch ticks before the operational watchdog stops the guest.
    ///
    /// Zero stops the guest at its first epoch check. The watchdog that
    /// advances the epoch arrives with the worker supervisor in #542.
    pub watchdog_epochs: u32,
}

/// The pinned Wasmtime engine and a linker that provides only `host-v1`.
pub struct ComponentHost {
    engine: Engine,
    linker: Linker<HostState>,
}

/// A compiled Component whose imports and `guest-v1` exports were checked.
pub struct LoadedComponent {
    pre: InstancePre<HostState>,
    describe: ComponentExportIndex,
    reduce: ComponentExportIndex,
    drive: ComponentExportIndex,
}

impl LoadedComponent {
    const fn export(&self, export: GuestExport) -> ComponentExportIndex {
        match export {
            GuestExport::Describe => self.describe,
            GuestExport::Reduce => self.reduce,
            GuestExport::Drive => self.drive,
        }
    }
}

impl ComponentHost {
    /// Build the pinned engine and its `host-v1`-only linker.
    ///
    /// # Errors
    ///
    /// Returns the Wasmtime error when this platform rejects the pinned engine
    /// configuration.
    pub fn new() -> wasmtime::Result<Self> {
        Engine::new(&engine_config()).and_then(|engine| {
            let mut linker = Linker::new(&engine);
            host_v1::define(&mut linker).map(|()| Self { engine, linker })
        })
    }

    /// Compile a Component and link it against `host-v1` before any execution.
    ///
    /// # Errors
    ///
    /// Returns [`LoadError::InvalidComponent`] for bytes that are not a valid
    /// Component, [`LoadError::ImportDenied`] when the Component imports
    /// anything the `host-v1` linker does not provide with a matching type, and
    /// [`LoadError::MissingGuestExport`] when `guest-v1` lacks `describe`,
    /// `reduce` or `drive`.
    pub fn load(&self, bytes: &[u8]) -> Result<LoadedComponent, LoadError> {
        let component =
            Component::from_binary(&self.engine, bytes).map_err(|_| LoadError::InvalidComponent)?;
        let pre = self
            .linker
            .instantiate_pre(&component)
            .map_err(|_| LoadError::ImportDenied)?;
        let [Some(describe), Some(reduce), Some(drive)] =
            GuestExport::ALL.map(|export| guest_export(&component, export))
        else {
            return Err(LoadError::MissingGuestExport);
        };
        Ok(LoadedComponent {
            pre,
            describe,
            reduce,
            drive,
        })
    }

    /// Instantiate the Component in a fresh store and call one export.
    ///
    /// Fuel and memory are charged from instantiation onwards. The store, and
    /// with it every guest allocation and operational log record, is dropped
    /// before a failure is returned.
    ///
    /// # Errors
    ///
    /// Returns the closed [`InvocationFailure`] that classifies the trap, the
    /// limit or the refusal that ended the invocation.
    pub fn invoke(
        &self,
        component: &LoadedComponent,
        export: GuestExport,
        args: &[Val],
        limits: InvocationLimits,
        inputs: HostInputs,
    ) -> Result<InvocationReport, InvocationFailure> {
        // A limit above the address space saturates: no guest can reserve more
        // than `usize::MAX` bytes, so saturating never admits extra memory.
        let limit = usize::try_from(limits.memory_bytes).unwrap_or(usize::MAX);
        let memory = MemoryLimiter::new(limit);
        let mut store = Store::new(
            &self.engine,
            HostState {
                inputs,
                memory,
                log: Vec::new(),
            },
        );
        store.limiter(|state| &mut state.memory);
        store.set_epoch_deadline(u64::from(limits.watchdog_epochs));
        let index = component.export(export);
        let outcome = store
            .set_fuel(limits.fuel)
            .and_then(|()| component.pre.instantiate(&mut store))
            .and_then(|instance| {
                let after_startup = store.get_fuel()?;
                call(&mut store, instance, index, args).map(|value| (value, after_startup))
            })
            .and_then(|(value, after_startup)| {
                store.get_fuel().map(|after_call| (value, after_startup, after_call))
            });
        let (value, after_startup, after_call) = outcome.map_err(|error| classify(&error))?;
        let state = store.into_data();
        Ok(InvocationReport {
            value,
            startup_fuel: limits.fuel.saturating_sub(after_startup),
            call_fuel: after_startup.saturating_sub(after_call),
            memory_bytes: state.memory.reserved_bytes(),
            operational_log: state.log,
        })
    }
}

/// The pinned engine configuration recorded in the execution profile.
fn engine_config() -> Config {
    let mut config = Config::new();
    config
        .strategy(Strategy::Cranelift)
        .cranelift_opt_level(OptLevel::Speed)
        .cranelift_nan_canonicalization(true)
        .relaxed_simd_deterministic(true)
        .wasm_component_model(true)
        .consume_fuel(true)
        .epoch_interruption(true)
        .max_wasm_stack(MAX_WASM_STACK_BYTES)
        .wasm_backtrace_max_frames(None)
        .wasm_backtrace_details(WasmBacktraceDetails::Disable);
    config
}

/// Resolve a `guest-v1` function export before any instance exists.
fn guest_export(component: &Component, export: GuestExport) -> Option<ComponentExportIndex> {
    component
        .get_export_index(None, GUEST_V1_INTERFACE)
        .and_then(|interface| component.get_export(Some(&interface), export.name()))
        .and_then(|(item, index)| matches!(item, ComponentItem::ComponentFunc(_)).then_some(index))
}

fn call(
    store: &mut Store<HostState>,
    instance: Instance,
    index: ComponentExportIndex,
    args: &[Val],
) -> wasmtime::Result<Val> {
    let mut results = [Val::Bool(false)];
    instance
        .get_func(&mut *store, index)
        .ok_or_else(|| wasmtime::Error::msg("guest-v1 export missing from the instance"))
        .and_then(|func| func.call(&mut *store, args, &mut results))
        .map(|()| {
            let [value] = results;
            value
        })
}
