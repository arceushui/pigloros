//! The pinned engine, Component loading and single-invocation execution.

use pos_crypto::plugin_execution::DeterministicBudgetV1;
use pos_runtime::community_plugin_host::{
    CommunityPluginHostErrorV1, GuestReturnV1, InvocationOptionsV1, InvocationReportV1, MeteringV1,
    NegotiatedCommunityPluginV1, OperationalLogRecord, PluginDescriptorV1, PluginInvocationV1,
    PluginOutputV1,
};
use wasmtime::component::types::{ComponentFunc, ComponentItem};
use wasmtime::component::{Component, ComponentExportIndex, Instance, InstancePre, Linker, Val};
use wasmtime::{Config, Engine, OptLevel, Store, Strategy, WasmBacktraceDetails};

use crate::describe::plugin_descriptor;
use crate::host_v1::{self, HostFault, HostState};
use crate::lift::{guest_return, Lifted};
use crate::lower::invocation_val;
use crate::outcome::{classify, LoadError, RuntimeNotPinnedV1};
use crate::output::{plugin_output, OutputBounds};
use crate::runtime::{is_pinned_runtime, MAX_WASM_STACK_BYTES, PINNED_ENGINE_CONFIG};
use crate::signatures::{export_is_exact, imported_functions_are_exact};

const GUEST_V1_INTERFACE: &str = "pigloros:plugin/guest-v1@0.1.0";

/// One `guest-v1` export that the host may invoke.
///
/// `migrate-state` is deliberately absent: a V1 host never invokes it. The
/// discriminants follow [`GuestExport::ALL`], so they index export tables.
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
    ///
    /// For `reduce` and `drive` it is also the `invocation-kind` case name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Describe => "describe",
            Self::Reduce => "reduce",
            Self::Drive => "drive",
        }
    }
}

/// A negotiated release whose profile pins this engine's runtime.
///
/// Building one is the precondition of every invocation: the profile must
/// record exactly [`crate::runtime::pinned_runtime`], whose validated trap table has a row
/// for `OutOfFuel`, `Interrupt` and every other pinned trap code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedExecutionV1 {
    negotiated: NegotiatedCommunityPluginV1,
}

impl PinnedExecutionV1 {
    /// Accept `negotiated` only when its profile pins this engine's runtime.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeNotPinnedV1`] when the profile records no runtime or a
    /// runtime other than [`crate::runtime::pinned_runtime`].
    pub fn new(negotiated: NegotiatedCommunityPluginV1) -> Result<Self, RuntimeNotPinnedV1> {
        let pinned = negotiated.runtime().is_some_and(is_pinned_runtime);
        pinned
            .then_some(Self { negotiated })
            .ok_or(RuntimeNotPinnedV1)
    }

    /// The negotiated release.
    #[must_use]
    pub const fn negotiated(&self) -> &NegotiatedCommunityPluginV1 {
        &self.negotiated
    }

    /// The effective limits fixed at negotiation.
    const fn limits(&self) -> DeterministicBudgetV1 {
        self.negotiated.limits().values()
    }
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

/// The lifted return and the metering of one call, not yet validated.
struct RawReport {
    value: Val,
    metering: MeteringV1,
    operational_log: Vec<OperationalLogRecord>,
}

impl RawReport {
    /// Validate the return with `lift`; any failure discards everything.
    fn lift<T>(
        self,
        lift: impl FnOnce(&Val) -> Lifted<GuestReturnV1<T>>,
    ) -> Result<InvocationReportV1<T>, CommunityPluginHostErrorV1> {
        let result = lift(&self.value)?;
        Ok(InvocationReportV1 {
            result,
            metering: self.metering,
            operational_log: self.operational_log,
        })
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

    /// Advance the engine epoch by one tick.
    ///
    /// The operational watchdog calls it; an invocation whose
    /// `watchdog_epochs` have elapsed stops with `OperationalWatchdogStop`.
    pub fn increment_epoch(&self) {
        self.engine.increment_epoch();
    }

    /// Compile a Component and check its imports and exports before any
    /// execution.
    ///
    /// Every refusal converts to the closed `IncompatibleAbi`.
    ///
    /// # Errors
    ///
    /// Returns [`LoadError::InvalidComponent`] for bytes that are not a valid
    /// Component, [`LoadError::ImportDenied`] when the Component imports a
    /// function other than a `host-v1` function with its exact type, or
    /// anything else the linker does not provide,
    /// [`LoadError::MissingGuestExport`] when `guest-v1` lacks a `describe`,
    /// `reduce` or `drive` function, and [`LoadError::MistypedGuestExport`]
    /// when one of them does not have its exact WIT signature.
    pub fn load(&self, bytes: &[u8]) -> Result<LoadedComponent, LoadError> {
        let component = self.compile(bytes)?;
        let pre = self
            .linker
            .instantiate_pre(&component)
            .map_err(|_| LoadError::ImportDenied)?;
        let [Some(describe), Some(reduce), Some(drive)] =
            GuestExport::ALL.map(|export| guest_export(&component, export))
        else {
            return Err(LoadError::MissingGuestExport);
        };
        let typed = [
            (GuestExport::Describe, &describe.0),
            (GuestExport::Reduce, &reduce.0),
            (GuestExport::Drive, &drive.0),
        ];
        let exact = typed
            .iter()
            .all(|(export, func)| export_is_exact(*export, func));
        exact.then_some(()).ok_or(LoadError::MistypedGuestExport)?;
        Ok(LoadedComponent {
            pre,
            describe: describe.1,
            reduce: reduce.1,
            drive: drive.1,
        })
    }

    /// Call `describe` and check the descriptor against the negotiated release.
    ///
    /// # Errors
    ///
    /// Returns the closed error that ended the invocation, or
    /// `InvalidGuestOutput` for a descriptor that does not lift or does not
    /// describe the negotiated release (Plugin ID, world, ABI major, declared
    /// minors, required features) or that declares a migration.
    pub fn describe(
        &self,
        component: &LoadedComponent,
        execution: &PinnedExecutionV1,
        options: InvocationOptionsV1,
    ) -> Result<InvocationReportV1<PluginDescriptorV1>, CommunityPluginHostErrorV1> {
        let negotiated = execution.negotiated();
        self.call(component, GuestExport::Describe, &[], execution, options)?
            .lift(|value| guest_return(value, |payload| plugin_descriptor(payload, negotiated)))
    }

    /// Call `reduce` with `invocation` and validate the complete output.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInvocation` before any guest code runs for an
    /// invocation outside its WIT bounds, then the closed error that ended
    /// the invocation or that output validation found.
    pub fn reduce(
        &self,
        component: &LoadedComponent,
        execution: &PinnedExecutionV1,
        invocation: &PluginInvocationV1,
        options: InvocationOptionsV1,
    ) -> Result<InvocationReportV1<PluginOutputV1>, CommunityPluginHostErrorV1> {
        self.invoke_output(
            component,
            GuestExport::Reduce,
            execution,
            invocation,
            options,
        )
    }

    /// Call `drive` with `invocation` and validate the complete output.
    ///
    /// # Errors
    ///
    /// As [`Self::reduce`].
    pub fn drive(
        &self,
        component: &LoadedComponent,
        execution: &PinnedExecutionV1,
        invocation: &PluginInvocationV1,
        options: InvocationOptionsV1,
    ) -> Result<InvocationReportV1<PluginOutputV1>, CommunityPluginHostErrorV1> {
        self.invoke_output(
            component,
            GuestExport::Drive,
            execution,
            invocation,
            options,
        )
    }

    /// Compile `bytes` and require exact `host-v1` function imports.
    fn compile(&self, bytes: &[u8]) -> Result<Component, LoadError> {
        let component =
            Component::from_binary(&self.engine, bytes).map_err(|_| LoadError::InvalidComponent)?;
        if imported_functions_are_exact(&self.engine, &component) {
            Ok(component)
        } else {
            Err(LoadError::ImportDenied)
        }
    }

    fn invoke_output(
        &self,
        component: &LoadedComponent,
        export: GuestExport,
        execution: &PinnedExecutionV1,
        invocation: &PluginInvocationV1,
        options: InvocationOptionsV1,
    ) -> Result<InvocationReportV1<PluginOutputV1>, CommunityPluginHostErrorV1> {
        invocation.validate()?;
        let args = [invocation_val(invocation, export.name())];
        let bounds = OutputBounds {
            invocation_id: invocation.invocation_id,
            limits: execution.limits(),
        };
        self.call(component, export, &args, execution, options)?
            .lift(|value| guest_return(value, |payload| plugin_output(payload, &bounds)))
    }

    /// Instantiate the Component in a fresh store and call one export.
    ///
    /// Fuel and memory are charged from instantiation onwards. The store, and
    /// with it every guest allocation and operational log record, is dropped
    /// before a failure is returned.
    fn call(
        &self,
        component: &LoadedComponent,
        export: GuestExport,
        args: &[Val],
        execution: &PinnedExecutionV1,
        options: InvocationOptionsV1,
    ) -> Result<RawReport, CommunityPluginHostErrorV1> {
        let limits = execution.limits();
        let state = HostState::new(options.host_inputs, &limits);
        let mut store = Store::new(&self.engine, state);
        store.limiter(|state| &mut state.memory);
        store.set_epoch_deadline(u64::from(options.watchdog_epochs));
        let index = component.export(export);
        let outcome = store
            .set_fuel(limits.fuel)
            .and_then(|()| run_export(&mut store, &component.pre, index, args));
        let (value, after_startup, after_call) = outcome.map_err(|error| classify(&error))?;
        let state = store.into_data();
        Ok(RawReport {
            value,
            metering: MeteringV1 {
                startup_fuel: limits.fuel.saturating_sub(after_startup),
                call_fuel: after_startup.saturating_sub(after_call),
                memory_bytes: state.memory.reserved,
                host_calls: limits.host_calls.saturating_sub(state.budget.host_calls),
            },
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
        .consume_fuel(PINNED_ENGINE_CONFIG.consume_fuel)
        .epoch_interruption(PINNED_ENGINE_CONFIG.epoch_interruption)
        .max_wasm_stack(MAX_WASM_STACK_BYTES)
        .wasm_backtrace_max_frames(None)
        .wasm_backtrace_details(WasmBacktraceDetails::Disable);
    config
}

/// Resolve a `guest-v1` function export and its type before any instance
/// exists.
fn guest_export(
    component: &Component,
    export: GuestExport,
) -> Option<(ComponentFunc, ComponentExportIndex)> {
    component
        .get_export_index(None, GUEST_V1_INTERFACE)
        .and_then(|interface| component.get_export(Some(&interface), export.name()))
        .and_then(|(item, index)| func_of(item).map(|func| (func, index)))
}

/// The function type of an export item, if it is a function.
fn func_of(item: ComponentItem) -> Option<ComponentFunc> {
    match item {
        ComponentItem::ComponentFunc(func) => Some(func),
        _ => None,
    }
}

/// Instantiate the Component and call one export.
///
/// It returns the lifted value with the fuel left after instantiation and
/// after the call. The pinned engine always meters fuel, so both readings
/// succeed; they are combined last, so no early return depends on them.
fn run_export(
    store: &mut Store<HostState>,
    pre: &InstancePre<HostState>,
    index: ComponentExportIndex,
    args: &[Val],
) -> wasmtime::Result<(Val, u64, u64)> {
    let instance = pre.instantiate(&mut *store)?;
    let after_startup = store.get_fuel();
    let value = call_export(store, instance, index, args)?;
    let after_call = store.get_fuel();
    after_startup.and_then(|startup| after_call.map(|call| (value, startup, call)))
}

/// Call one export of `instance`.
///
/// An index of another Component resolves to no function; that is
/// `InvalidGuestOutput`, like any export the guest cannot serve.
fn call_export(
    store: &mut Store<HostState>,
    instance: Instance,
    index: ComponentExportIndex,
    args: &[Val],
) -> wasmtime::Result<Val> {
    let mut results = [Val::Bool(false)];
    instance
        .get_func(&mut *store, index)
        .ok_or(HostFault::GuestAbi)
        .map_err(wasmtime::Error::new)
        .and_then(|func| func.call(&mut *store, args, &mut results))
        .map(|()| {
            let [value] = results;
            value
        })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use pos_crypto::plugin_execution::{
        PluginAbiRequirementV1, PluginExecutionProjectionFixtureV1, PluginExecutionProjectionV1,
    };
    use pos_runtime::community_plugin_host::{
        negotiate_community_plugin_v1, CommunityPluginCeilingsV1,
        CommunityPluginExecutionProfileV1, CommunityPluginHostAbiV1, CommunityPluginModeV1,
        HostInputs,
    };

    use super::*;

    const PROBE: &str = include_str!("../tests/components/probe.wat");
    const RUST_GUEST: &[u8] = include_bytes!(
        "../../../plugins/community/examples/compatibility-prototype/fixtures/rust-guest.wasm"
    );

    fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| std::panic::resume_unwind(Box::new(format!("{error:?}"))))
    }

    fn execution() -> PinnedExecutionV1 {
        let release = PluginExecutionProjectionV1::from(PluginExecutionProjectionFixtureV1 {
            pmf1_digest: [1; 32],
            release_digest: [2; 32],
            plugin_id: "plugin-a".to_owned(),
            abi: PluginAbiRequirementV1 {
                major: 0,
                min_minor: 0,
                max_minor: 0,
                required_features: Vec::new(),
            },
            capabilities: Vec::new(),
            budget: DeterministicBudgetV1::MAXIMA,
        });
        let profile = CommunityPluginExecutionProfileV1::new(
            CommunityPluginModeV1::Local,
            CommunityPluginCeilingsV1::V1,
            Some(ok(crate::runtime::pinned_runtime())),
        );
        let host = CommunityPluginHostAbiV1::v1();
        let negotiated = ok(negotiate_community_plugin_v1(&release, &host, &profile));
        ok(PinnedExecutionV1::new(negotiated))
    }

    #[test]
    fn an_export_index_of_another_component_is_invalid_guest_output() {
        let host = ok(ComponentHost::new());
        let probe = ok(host.load(&ok(wat::parse_str(PROBE))));
        let rust = ok(host.load(RUST_GUEST));
        // The probe's instance with the Rust guest's `describe` index.
        let mixed = LoadedComponent {
            pre: probe.pre.clone(),
            describe: rust.describe,
            reduce: probe.reduce,
            drive: probe.drive,
        };
        let options = InvocationOptionsV1 {
            host_inputs: HostInputs { simulation_time: 0 },
            watchdog_epochs: 1,
        };
        let failure = host.describe(&mixed, &execution(), options).err();
        assert_eq!(
            failure,
            Some(CommunityPluginHostErrorV1::InvalidGuestOutput)
        );
    }
}
