//! The `host-v1` imports, their counters, the memory limiter and host state.
//!
//! The linker defines only the three `host-v1` functions. A Component that
//! needs any other function, WASI included, fails to load before any
//! execution, and the load-time import check compares the exact type of every
//! imported `host-v1` function. The world's types-only `contract-v1` import
//! carries no function and needs no definition.
//!
//! Every call is charged against the invocation's effective `host_calls`
//! limit before its arguments are read. `record-operational-log` is also
//! charged against `log_calls`, `log_bytes` and the 256-byte message bound.

use std::fmt;

use pos_crypto::plugin_execution::DeterministicBudgetV1;
use pos_runtime::community_plugin_host::CommunityPluginHostErrorV1;
use wasmtime::component::{Linker, Val};
use wasmtime::ResourceLimiter;

/// The `host-v1` interface name inside the world.
pub(crate) const HOST_V1_INTERFACE: &str = "pigloros:plugin/host-v1@0.1.0";
/// Largest `deterministic-random` request, in bytes.
pub(crate) const MAX_RANDOM_BYTES: u32 = 4_096;
/// WIT bound on one operational log message, in bytes.
pub(crate) const MAX_LOG_MESSAGE_BYTES: usize = 256;
/// Largest element count of any guest table.
const MAX_TABLE_ELEMENTS: usize = 65_536;

/// Deterministic values that `host-v1` exposes to one invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostInputs {
    /// Simulation Time returned by `simulation-time`.
    pub simulation_time: u64,
}

/// One accepted `record-operational-log` call.
///
/// Operational logs are never authoritative behaviour inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationalLogRecord {
    /// Category chosen by the guest.
    pub category: u16,
    /// UTF-8 message of at most 256 bytes.
    pub message: String,
}

/// A host-side refusal raised inside Wasmtime and classified after the call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HostFault {
    /// The effective `host_calls` limit, or a per-call request bound.
    HostCallLimit,
    /// An operational log limit: `log_calls`, `log_bytes` or 256 bytes.
    OutputLimit,
    /// The guest broke the canonical ABI contract of a call or an export.
    GuestAbi,
    /// Memory or table growth beyond the invocation's limit.
    MemoryLimit,
}

impl HostFault {
    /// The closed host error this refusal reports.
    pub(crate) const fn error(self) -> CommunityPluginHostErrorV1 {
        match self {
            Self::HostCallLimit => CommunityPluginHostErrorV1::HostCallLimitExceeded,
            Self::OutputLimit => CommunityPluginHostErrorV1::OutputLimitExceeded,
            Self::GuestAbi => CommunityPluginHostErrorV1::InvalidGuestOutput,
            Self::MemoryLimit => CommunityPluginHostErrorV1::MemoryLimitExceeded,
        }
    }
}

impl fmt::Display for HostFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::HostCallLimit => "host-v1 call limit exceeded",
            Self::OutputLimit => "operational log limit exceeded",
            Self::GuestAbi => "guest broke the canonical ABI contract",
            Self::MemoryLimit => "linear memory or table limit exceeded",
        })
    }
}

impl std::error::Error for HostFault {}

/// What remains of one invocation's host-call and log limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CallBudget {
    pub(crate) host_calls: u64,
    log_calls: u64,
    log_bytes: u64,
}

impl CallBudget {
    /// The full effective limits of one invocation.
    pub(crate) const fn new(limits: &DeterministicBudgetV1) -> Self {
        Self {
            host_calls: limits.host_calls,
            log_calls: limits.log_calls,
            log_bytes: limits.log_bytes,
        }
    }

    /// Charge one `host-v1` call.
    fn charge_call(&mut self) -> Result<(), HostFault> {
        self.host_calls = self
            .host_calls
            .checked_sub(1)
            .ok_or(HostFault::HostCallLimit)?;
        Ok(())
    }

    /// Charge one log message of `message_bytes` bytes.
    fn charge_log(&mut self, message_bytes: usize) -> Result<(), HostFault> {
        let bytes = u64::try_from(message_bytes).unwrap_or(u64::MAX);
        let calls = self.log_calls.checked_sub(1);
        let left = self.log_bytes.checked_sub(bytes);
        match (message_bytes <= MAX_LOG_MESSAGE_BYTES, calls, left) {
            (true, Some(calls), Some(left)) => {
                self.log_calls = calls;
                self.log_bytes = left;
                Ok(())
            }
            _ => Err(HostFault::OutputLimit),
        }
    }
}

/// Host state owned by one invocation's store and dropped with it.
pub(crate) struct HostState {
    pub(crate) inputs: HostInputs,
    pub(crate) memory: MemoryLimiter,
    pub(crate) budget: CallBudget,
    pub(crate) log: Vec<OperationalLogRecord>,
}

impl HostState {
    /// Fresh state for one invocation under `limits`.
    pub(crate) fn new(inputs: HostInputs, limits: &DeterministicBudgetV1) -> Self {
        Self {
            inputs,
            memory: MemoryLimiter {
                limit: usize::try_from(limits.memory_bytes).unwrap_or(usize::MAX),
                reserved: 0,
            },
            budget: CallBudget::new(limits),
            log: Vec::new(),
        }
    }
}

/// Charges every linear-memory reservation against one invocation limit.
///
/// Reservations are never returned: a reservation that Wasmtime later fails to
/// commit still counts, which only makes the limit stricter. A denial is an
/// error, never a silent `-1`, so it is always `MemoryLimitExceeded`.
pub(crate) struct MemoryLimiter {
    limit: usize,
    reserved: usize,
}

impl MemoryLimiter {
    /// A limiter that has reserved nothing yet and refuses beyond `limit` bytes.
    pub(crate) const fn new(limit: usize) -> Self {
        Self { limit, reserved: 0 }
    }

    /// Bytes reserved so far, widened losslessly (`usize` is at most 64 bits).
    pub(crate) const fn reserved_bytes(&self) -> u64 {
        self.reserved as u64
    }
}

impl ResourceLimiter for MemoryLimiter {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        let reserved = self
            .reserved
            .saturating_add(desired.saturating_sub(current));
        if reserved > self.limit {
            return Err(HostFault::MemoryLimit.into());
        }
        self.reserved = reserved;
        Ok(true)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if desired > MAX_TABLE_ELEMENTS {
            return Err(HostFault::MemoryLimit.into());
        }
        Ok(true)
    }
}

/// Define the `host-v1` instance and nothing else.
pub(crate) fn define(linker: &mut Linker<HostState>) -> wasmtime::Result<()> {
    linker.instance(HOST_V1_INTERFACE).and_then(|mut host| {
        host.func_wrap("simulation-time", |mut store, ()| {
            simulation_time(store.data_mut())
        })
        .and_then(|()| {
            host.func_new("deterministic-random", |mut store, _, params, results| {
                random_call(&mut store.data_mut().budget, params, results)
            })
        })
        .and_then(|()| {
            host.func_new("record-operational-log", |mut store, _, params, results| {
                log_call(store.data_mut(), params, results)
            })
        })
    })
}

/// `simulation-time() -> u64`.
fn simulation_time(state: &mut HostState) -> wasmtime::Result<(u64,)> {
    state.budget.charge_call()?;
    Ok((state.inputs.simulation_time,))
}

/// `deterministic-random(domain, offset, length) -> result<bytes, plugin-error>`.
///
/// The bytes are the BLAKE3 extendable output keyed by the guest's 32-byte
/// domain, read from `offset`.
fn random_call(
    budget: &mut CallBudget,
    params: &[Val],
    results: &mut [Val],
) -> wasmtime::Result<()> {
    budget.charge_call()?;
    let (domain, offset, length) = random_request(params)?;
    let bytes = random_bytes(&domain, offset, length);
    store_result(results, Val::Result(Ok(Some(Box::new(byte_list(&bytes))))))
}

/// `record-operational-log(category, message) -> result<_, plugin-error>`.
fn log_call(state: &mut HostState, params: &[Val], results: &mut [Val]) -> wasmtime::Result<()> {
    state.budget.charge_call()?;
    let record = log_request(params)?;
    state.budget.charge_log(record.message.len())?;
    state.log.push(record);
    store_result(results, Val::Result(Ok(None)))
}

fn random_request(params: &[Val]) -> Result<([u8; 32], u64, u32), HostFault> {
    let [domain, Val::U64(offset), Val::U32(length)] = params else {
        return Err(HostFault::GuestAbi);
    };
    let domain = byte_record(domain)
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or(HostFault::GuestAbi)?;
    if *length > MAX_RANDOM_BYTES {
        return Err(HostFault::HostCallLimit);
    }
    Ok((domain, *offset, *length))
}

fn log_request(params: &[Val]) -> Result<OperationalLogRecord, HostFault> {
    let [Val::U16(category), message] = params else {
        return Err(HostFault::GuestAbi);
    };
    let message = byte_record(message)
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .ok_or(HostFault::GuestAbi)?;
    Ok(OperationalLogRecord {
        category: *category,
        message,
    })
}

/// Bytes of a single-field `record { value: list<u8> }` such as `digest32`.
fn byte_record(value: &Val) -> Option<Vec<u8>> {
    let Val::Record(fields) = value else {
        return None;
    };
    let [(_, Val::List(items))] = fields.as_slice() else {
        return None;
    };
    items.iter().map(byte_value).collect()
}

const fn byte_value(value: &Val) -> Option<u8> {
    match value {
        Val::U8(byte) => Some(*byte),
        _ => None,
    }
}

/// A `list<u8>` value.
pub(crate) fn byte_list(bytes: &[u8]) -> Val {
    Val::List(bytes.iter().copied().map(Val::U8).collect())
}

fn random_bytes(domain: &[u8; 32], offset: u64, length: u32) -> Vec<u8> {
    let mut bytes = vec![0; length as usize];
    let mut reader = blake3::Hasher::new_keyed(domain).finalize_xof();
    reader.set_position(offset);
    reader.fill(&mut bytes);
    bytes
}

fn store_result(results: &mut [Val], value: Val) -> wasmtime::Result<()> {
    let [slot] = results else {
        return Err(HostFault::GuestAbi.into());
    };
    *slot = value;
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    const LIMITS: DeterministicBudgetV1 = DeterministicBudgetV1 {
        memory_bytes: 65_536,
        fuel: 1,
        host_calls: 100,
        event_count: 0,
        event_bytes: 0,
        state_bytes: 0,
        log_calls: 3,
        log_bytes: 600,
    };

    fn byte_record_of(bytes: &[u8]) -> Val {
        Val::Record(vec![("value".to_owned(), byte_list(bytes))])
    }

    fn random_params(domain: &[u8], length: u32) -> [Val; 3] {
        [byte_record_of(domain), Val::U64(7), Val::U32(length)]
    }

    fn log_params(message: &[u8]) -> [Val; 2] {
        [Val::U16(1), byte_record_of(message)]
    }

    fn state(limits: &DeterministicBudgetV1) -> HostState {
        HostState::new(HostInputs { simulation_time: 5 }, limits)
    }

    fn fault(result: wasmtime::Result<()>) -> Option<HostFault> {
        result
            .err()
            .and_then(|error| error.downcast_ref::<HostFault>().copied())
    }

    #[test]
    fn byte_records_accept_only_single_byte_list_records() {
        assert_eq!(byte_record(&byte_record_of(&[1, 2])), Some(vec![1, 2]));
        assert_eq!(byte_record(&Val::Bool(true)), None);
        assert_eq!(byte_record(&Val::Record(Vec::new())), None);
        let wide = Val::Record(vec![("value".to_owned(), Val::List(vec![Val::U16(1)]))]);
        assert_eq!(byte_record(&wide), None);
    }

    #[test]
    fn random_requests_need_a_32_byte_domain_and_a_bounded_length() {
        let domain = [9; 32];
        assert_eq!(
            random_request(&random_params(&domain, MAX_RANDOM_BYTES)),
            Ok((domain, 7, MAX_RANDOM_BYTES))
        );
        assert_eq!(
            random_request(&random_params(&domain, MAX_RANDOM_BYTES + 1)),
            Err(HostFault::HostCallLimit)
        );
        assert_eq!(
            random_request(&random_params(&[9; 31], 16)),
            Err(HostFault::GuestAbi)
        );
        assert_eq!(
            random_request(&[Val::Bool(true), Val::U64(7), Val::U32(16)]),
            Err(HostFault::GuestAbi)
        );
        assert_eq!(random_request(&[]), Err(HostFault::GuestAbi));
    }

    #[test]
    fn random_bytes_are_a_seekable_keyed_stream() {
        let domain = [3; 32];
        let whole = random_bytes(&domain, 0, 32);
        assert_eq!(whole.len(), 32);
        assert_eq!(random_bytes(&domain, 16, 16), whole[16..]);
        assert_ne!(random_bytes(&[4; 32], 0, 32), whole);
        assert!(random_bytes(&domain, 0, 0).is_empty());
    }

    #[test]
    fn random_calls_are_charged_and_reject_malformed_results() {
        let mut budget = CallBudget::new(&LIMITS);
        let mut results = [Val::Bool(false)];
        assert_eq!(
            fault(random_call(&mut budget, &[], &mut results)),
            Some(HostFault::GuestAbi)
        );
        let params = random_params(&[1; 32], 2);
        assert_eq!(
            fault(random_call(&mut budget, &params, &mut [])),
            Some(HostFault::GuestAbi)
        );
        assert!(random_call(&mut budget, &params, &mut results).is_ok());
        let expected = byte_list(&random_bytes(&[1; 32], 7, 2));
        assert_eq!(results, [Val::Result(Ok(Some(Box::new(expected))))]);
        assert_eq!(budget.host_calls, LIMITS.host_calls - 3);
        let mut spent = CallBudget {
            host_calls: 0,
            ..budget
        };
        assert_eq!(
            fault(random_call(&mut spent, &params, &mut results)),
            Some(HostFault::HostCallLimit)
        );
    }

    #[test]
    fn simulation_time_is_charged_as_a_host_call() {
        let one = DeterministicBudgetV1 {
            host_calls: 1,
            ..LIMITS
        };
        let mut host = state(&one);
        assert!(simulation_time(&mut host).is_ok_and(|(time,)| time == 5));
        let refused = simulation_time(&mut host).map(|_| ());
        assert_eq!(fault(refused), Some(HostFault::HostCallLimit));
    }

    #[test]
    fn log_requests_need_utf8_byte_records() {
        let accepted = log_request(&log_params(b"ok")).map(|record| record.message);
        assert_eq!(accepted, Ok("ok".to_owned()));
        assert_eq!(log_request(&log_params(&[0xff])), Err(HostFault::GuestAbi));
        assert_eq!(
            log_request(&[Val::U16(1), Val::Bool(true)]),
            Err(HostFault::GuestAbi)
        );
        assert_eq!(log_request(&[]), Err(HostFault::GuestAbi));
    }

    #[test]
    fn log_calls_stop_at_the_effective_call_limit() {
        let mut host = state(&LIMITS);
        let mut results = [Val::Bool(false)];
        for _ in 0..LIMITS.log_calls {
            assert!(log_call(&mut host, &log_params(b"ok"), &mut results).is_ok());
        }
        assert_eq!(results, [Val::Result(Ok(None))]);
        assert_eq!(
            fault(log_call(&mut host, &log_params(b"ok"), &mut results)),
            Some(HostFault::OutputLimit)
        );
        assert_eq!(host.log.len(), 3);
        let expected = OperationalLogRecord {
            category: 1,
            message: "ok".to_owned(),
        };
        assert_eq!(host.log.first(), Some(&expected));
        assert_eq!(
            fault(log_call(&mut host, &[], &mut results)),
            Some(HostFault::GuestAbi)
        );
    }

    #[test]
    fn log_messages_stop_at_256_bytes_and_the_byte_limit() {
        let mut budget = CallBudget::new(&LIMITS);
        assert_eq!(budget.charge_log(MAX_LOG_MESSAGE_BYTES), Ok(()));
        assert_eq!(
            budget.charge_log(MAX_LOG_MESSAGE_BYTES + 1),
            Err(HostFault::OutputLimit)
        );
        assert_eq!(budget.log_bytes, LIMITS.log_bytes - 256);
        assert_eq!(budget.charge_log(344), Ok(()));
        assert_eq!(budget.log_bytes, 0);
        assert_eq!(budget.charge_log(1), Err(HostFault::OutputLimit));
        assert_eq!(budget.log_calls, 1);
        assert_eq!(budget.charge_log(0), Ok(()));
        assert_eq!(budget.charge_log(0), Err(HostFault::OutputLimit));
    }

    #[test]
    fn host_calls_stop_at_the_effective_limit() {
        let one = DeterministicBudgetV1 {
            host_calls: 1,
            ..LIMITS
        };
        let mut host = state(&one);
        let mut results = [Val::Bool(false)];
        assert!(log_call(&mut host, &log_params(b"a"), &mut results).is_ok());
        assert_eq!(
            fault(log_call(&mut host, &log_params(b"a"), &mut results)),
            Some(HostFault::HostCallLimit)
        );
        assert_eq!(host.log.len(), 1);
        assert_eq!(host.budget.charge_call(), Err(HostFault::HostCallLimit));
    }

    #[test]
    fn memory_reservations_stop_exactly_at_the_limit() {
        let mut limiter = MemoryLimiter::new(131_072);
        assert!(matches!(limiter.memory_growing(0, 65_536, None), Ok(true)));
        assert!(matches!(
            limiter.memory_growing(65_536, 131_072, None),
            Ok(true)
        ));
        assert_eq!(limiter.reserved_bytes(), 131_072);
        let denied = limiter.memory_growing(131_072, 196_608, None);
        assert!(denied.is_err_and(|error| error.is::<HostFault>()));
        assert_eq!(limiter.reserved_bytes(), 131_072);
    }

    #[test]
    fn tables_stop_at_the_element_ceiling() {
        let mut limiter = state(&LIMITS).memory;
        assert_eq!(limiter.limit, 65_536);
        let largest = limiter.table_growing(0, MAX_TABLE_ELEMENTS, None);
        assert!(matches!(largest, Ok(true)));
        let beyond = limiter.table_growing(0, MAX_TABLE_ELEMENTS + 1, None);
        assert!(beyond.is_err_and(|error| error.is::<HostFault>()));
    }

    #[test]
    fn host_faults_map_to_closed_errors_with_stable_messages() {
        let faults = [
            (
                HostFault::HostCallLimit,
                CommunityPluginHostErrorV1::HostCallLimitExceeded,
                "host-v1 call limit exceeded",
            ),
            (
                HostFault::OutputLimit,
                CommunityPluginHostErrorV1::OutputLimitExceeded,
                "operational log limit exceeded",
            ),
            (
                HostFault::GuestAbi,
                CommunityPluginHostErrorV1::InvalidGuestOutput,
                "guest broke the canonical ABI contract",
            ),
            (
                HostFault::MemoryLimit,
                CommunityPluginHostErrorV1::MemoryLimitExceeded,
                "linear memory or table limit exceeded",
            ),
        ];
        for (fault, error, message) in faults {
            assert_eq!(fault.error(), error);
            assert_eq!(fault.to_string(), message);
        }
    }
}
