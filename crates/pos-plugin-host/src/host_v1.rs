//! The `host-v1` imports, the memory limiter and per-invocation host state.
//!
//! The linker defines only the three `host-v1` functions. A Component that
//! needs any other function, WASI included, fails to link before any execution.
//! The world's types-only `contract-v1` import carries no function and needs no
//! definition.

use std::fmt;

use wasmtime::component::{Linker, Val};
use wasmtime::ResourceLimiter;

const HOST_V1_INTERFACE: &str = "pigloros:plugin/host-v1@0.1.0";
/// Largest `deterministic-random` request served by the prototype, in bytes.
const MAX_RANDOM_BYTES: u32 = 4_096;
/// WIT ceiling on `record-operational-log` calls in one invocation.
const MAX_LOG_CALLS: usize = 64;
/// WIT ceiling on one operational log message, in bytes.
const MAX_LOG_MESSAGE_BYTES: usize = 256;
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
    /// A `host-v1` call whose arguments or count the host refuses.
    CallRejected,
    /// Linear-memory growth beyond the invocation's memory limit.
    MemoryLimit,
    /// An export resolved at load time is not a function of the instance.
    MissingExport,
}

impl fmt::Display for HostFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CallRejected => "host-v1 call rejected",
            Self::MemoryLimit => "linear memory limit exceeded",
            Self::MissingExport => "guest-v1 export missing from the instance",
        })
    }
}

impl std::error::Error for HostFault {}

/// Host state owned by one invocation's store and dropped with it.
pub(crate) struct HostState {
    pub(crate) inputs: HostInputs,
    pub(crate) memory: MemoryLimiter,
    pub(crate) log: Vec<OperationalLogRecord>,
}

/// Charges every linear-memory reservation against one invocation limit.
///
/// Reservations are never returned: a reservation that Wasmtime later fails to
/// commit still counts, which only makes the limit stricter.
pub(crate) struct MemoryLimiter {
    pub(crate) limit: usize,
    pub(crate) reserved: usize,
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
        Ok(desired <= MAX_TABLE_ELEMENTS)
    }
}

/// Define the `host-v1` instance and nothing else.
pub(crate) fn define(linker: &mut Linker<HostState>) -> wasmtime::Result<()> {
    linker.instance(HOST_V1_INTERFACE).and_then(|mut host| {
        host.func_wrap("simulation-time", |store, ()| {
            Ok((store.data().inputs.simulation_time,))
        })
        .and_then(|()| {
            host.func_new("deterministic-random", |_, _, params, results| {
                random_call(params, results)
            })
        })
        .and_then(|()| {
            host.func_new("record-operational-log", |mut store, _, params, results| {
                log_call(&mut store.data_mut().log, params, results)
            })
        })
    })
}

/// `deterministic-random(domain, offset, length) -> result<bytes, plugin-error>`.
///
/// The bytes are the BLAKE3 extendable output keyed by the 32-byte domain,
/// starting at `offset`. #541 binds the domain to the invocation.
fn random_call(params: &[Val], results: &mut [Val]) -> wasmtime::Result<()> {
    let (domain, offset, length) = random_request(params).ok_or(HostFault::CallRejected)?;
    let bytes = random_bytes(&domain, offset, length);
    store_result(results, Val::Result(Ok(Some(Box::new(byte_list(&bytes))))))
}

/// `record-operational-log(category, message) -> result<_, plugin-error>`.
fn log_call(
    log: &mut Vec<OperationalLogRecord>,
    params: &[Val],
    results: &mut [Val],
) -> wasmtime::Result<()> {
    let record = log_request(params)
        .filter(|_| log.len() < MAX_LOG_CALLS)
        .ok_or(HostFault::CallRejected)?;
    log.push(record);
    store_result(results, Val::Result(Ok(None)))
}

fn random_request(params: &[Val]) -> Option<([u8; 32], u64, u32)> {
    let [domain, Val::U64(offset), Val::U32(length)] = params else {
        return None;
    };
    let domain = <[u8; 32]>::try_from(byte_record(domain)?).ok()?;
    (*length <= MAX_RANDOM_BYTES).then_some((domain, *offset, *length))
}

fn log_request(params: &[Val]) -> Option<OperationalLogRecord> {
    let [Val::U16(category), message] = params else {
        return None;
    };
    let message = String::from_utf8(byte_record(message)?).ok()?;
    (message.len() <= MAX_LOG_MESSAGE_BYTES).then_some(OperationalLogRecord {
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

fn byte_list(bytes: &[u8]) -> Val {
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
        return Err(HostFault::CallRejected.into());
    };
    *slot = value;
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn byte_record_of(bytes: &[u8]) -> Val {
        Val::Record(vec![("value".to_owned(), byte_list(bytes))])
    }

    fn random_params(domain: &[u8], length: u32) -> [Val; 3] {
        [byte_record_of(domain), Val::U64(7), Val::U32(length)]
    }

    fn log_params(message: &[u8]) -> [Val; 2] {
        [Val::U16(1), byte_record_of(message)]
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
            Some((domain, 7, MAX_RANDOM_BYTES))
        );
        assert_eq!(
            random_request(&random_params(&domain, MAX_RANDOM_BYTES + 1)),
            None
        );
        assert_eq!(random_request(&random_params(&[9; 31], 16)), None);
        assert_eq!(
            random_request(&[Val::Bool(true), Val::U64(7), Val::U32(16)]),
            None
        );
        assert_eq!(random_request(&[]), None);
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
    fn random_calls_reject_malformed_arguments_and_results() {
        let mut results = [Val::Bool(false)];
        assert!(random_call(&[], &mut results).is_err());
        assert!(random_call(&random_params(&[1; 32], 2), &mut []).is_err());
        assert!(random_call(&random_params(&[1; 32], 2), &mut results).is_ok());
        let expected = byte_list(&random_bytes(&[1; 32], 7, 2));
        assert_eq!(results, [Val::Result(Ok(Some(Box::new(expected))))]);
    }

    #[test]
    fn log_requests_need_bounded_utf8() {
        let longest = [b'a'; MAX_LOG_MESSAGE_BYTES];
        let accepted = log_request(&log_params(&longest)).map(|record| record.message.len());
        assert_eq!(accepted, Some(MAX_LOG_MESSAGE_BYTES));
        assert_eq!(
            log_request(&log_params(&[b'a'; MAX_LOG_MESSAGE_BYTES + 1])),
            None
        );
        assert_eq!(log_request(&log_params(&[0xff])), None);
        assert_eq!(log_request(&[Val::U16(1), Val::Bool(true)]), None);
        assert_eq!(log_request(&[]), None);
    }

    #[test]
    fn log_calls_stop_at_the_wit_ceiling() {
        let mut log = Vec::new();
        let mut results = [Val::Bool(false)];
        for _ in 0..MAX_LOG_CALLS {
            assert!(log_call(&mut log, &log_params(b"ok"), &mut results).is_ok());
        }
        assert_eq!(results, [Val::Result(Ok(None))]);
        assert!(log_call(&mut log, &log_params(b"ok"), &mut results).is_err());
        assert_eq!(log.len(), MAX_LOG_CALLS);
        let expected = OperationalLogRecord {
            category: 1,
            message: "ok".to_owned(),
        };
        assert_eq!(log.first(), Some(&expected));
    }

    #[test]
    fn memory_reservations_stop_exactly_at_the_limit() {
        let mut limiter = MemoryLimiter {
            limit: 131_072,
            reserved: 0,
        };
        assert!(matches!(limiter.memory_growing(0, 65_536, None), Ok(true)));
        assert!(matches!(
            limiter.memory_growing(65_536, 131_072, None),
            Ok(true)
        ));
        assert_eq!(limiter.reserved, 131_072);
        let denied = limiter.memory_growing(131_072, 196_608, None);
        assert!(denied.is_err_and(|error| error.is::<HostFault>()));
        assert_eq!(limiter.reserved, 131_072);
    }

    #[test]
    fn tables_stop_at_the_element_ceiling() {
        let mut limiter = MemoryLimiter {
            limit: 0,
            reserved: 0,
        };
        let largest = limiter.table_growing(0, MAX_TABLE_ELEMENTS, None);
        assert!(matches!(largest, Ok(true)));
        let beyond = limiter.table_growing(0, MAX_TABLE_ELEMENTS + 1, None);
        assert!(matches!(beyond, Ok(false)));
    }

    #[test]
    fn host_faults_have_stable_messages() {
        assert_eq!(HostFault::CallRejected.to_string(), "host-v1 call rejected");
        assert_eq!(
            HostFault::MemoryLimit.to_string(),
            "linear memory limit exceeded"
        );
        assert_eq!(
            HostFault::MissingExport.to_string(),
            "guest-v1 export missing from the instance"
        );
    }
}
