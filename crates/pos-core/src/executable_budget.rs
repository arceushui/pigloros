//! Structural EBP1 executable-budget policies.
//!
//! This module contains only the immutable, canonical policy value.  Decoding
//! a policy never creates a runtime reservation, CPU receipt, or admission
//! capability; those remain owned by the runtime host.

use crate::{Hash, PluginId};

/// Maximum canonical EBP1 bytes.
pub const MAX_EXECUTABLE_BUDGET_POLICY_BYTES_V1: usize = 65_536;
/// Maximum Plugin rows in one policy.
pub const MAX_PLUGIN_CPU_RESERVATIONS_V1: usize = 256;

const MAX_FIDELITY_EVENTS_V1: [u32; 3] = [65_536, 131_072, 32_768];
const MAX_FIDELITY_BYTES_V1: [u64; 3] = [64 * 1024 * 1024, 128 * 1024 * 1024, 16 * 1024 * 1024];
const MAX_FIDELITY_CPU_US_V1: [u32; 3] = [500_000, 250_000, 50_000];

/// Workload profile selected by the host policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkloadProfileV1 {
    Interactive,
    Fork,
    Research,
}

impl WorkloadProfileV1 {
    const fn code(self) -> u8 {
        match self {
            Self::Interactive => 0,
            Self::Fork => 1,
            Self::Research => 2,
        }
    }

    const fn max_event_bytes(self) -> u32 {
        match self {
            Self::Interactive | Self::Fork => 4096,
            Self::Research => 16_384,
        }
    }

    const fn from_code(code: u8) -> Result<Self, ExecutableBudgetErrorV1> {
        match code {
            0 => Ok(Self::Interactive),
            1 => Ok(Self::Fork),
            2 => Ok(Self::Research),
            _ => Err(ExecutableBudgetErrorV1::UnsupportedValue),
        }
    }
}

/// One fidelity-level event, byte, CPU, and shared-host budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FidelityBudgetV1 {
    pub level: u8,
    pub max_events: u32,
    pub max_bytes: u64,
    pub max_cpu_us: u32,
    pub shared_host_cpu_reservation_us: u32,
}

/// One Plugin's CPU reservation for each fidelity level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PluginCpuReservationV1 {
    pub plugin_id: PluginId,
    pub cpu_reservations_us: [u32; 3],
}

/// Closed structural errors for EBP1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ExecutableBudgetErrorV1 {
    #[error("invalid executable budget encoding")]
    InvalidEncoding,
    #[error("unsupported executable budget value")]
    UnsupportedValue,
    #[error("executable budget field out of bounds")]
    FieldOutOfBounds,
    #[error("noncanonical executable budget")]
    NonCanonical,
}

/// Untrusted construction input for an immutable EBP1 policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutableBudgetPolicyInputV1 {
    pub revision: u32,
    pub workload_profile: WorkloadProfileV1,
    pub cut_budget_family: u8,
    pub max_event_bytes: u32,
    pub fidelity_budgets: [FidelityBudgetV1; 3],
    pub plugin_cpu_reservations: Vec<PluginCpuReservationV1>,
    pub accounting_semantics: u8,
    pub execution_profile_hash: Hash,
    pub max_pass_wall_duration_us: u64,
}

/// Immutable, structurally validated EBP1 policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutableBudgetPolicyV1(ExecutableBudgetPolicyInputV1);

impl ExecutableBudgetPolicyV1 {
    /// Construct and validate an EBP1 policy without sorting or defaulting.
    pub fn new(input: ExecutableBudgetPolicyInputV1) -> Result<Self, ExecutableBudgetErrorV1> {
        if input.revision == 0
            || input.cut_budget_family != 0
            || input.accounting_semantics != 0
            || input.execution_profile_hash == Hash::zero()
            || input.max_pass_wall_duration_us == 0
            || input.max_event_bytes == 0
            || input.max_event_bytes > input.workload_profile.max_event_bytes()
            || input.plugin_cpu_reservations.is_empty()
            || input.plugin_cpu_reservations.len() > MAX_PLUGIN_CPU_RESERVATIONS_V1
        {
            return Err(ExecutableBudgetErrorV1::FieldOutOfBounds);
        }
        if input
            .fidelity_budgets
            .iter()
            .enumerate()
            .any(|(index, budget)| {
                budget.level != u8::try_from(index).expect("fidelity index fits in u8")
                    || budget.max_events == 0
                    || budget.max_events > MAX_FIDELITY_EVENTS_V1[index]
                    || budget.max_bytes == 0
                    || budget.max_bytes > MAX_FIDELITY_BYTES_V1[index]
                    || budget.max_cpu_us == 0
                    || budget.max_cpu_us > MAX_FIDELITY_CPU_US_V1[index]
                    || u64::from(budget.shared_host_cpu_reservation_us)
                        > u64::from(budget.max_cpu_us)
            })
        {
            return Err(ExecutableBudgetErrorV1::FieldOutOfBounds);
        }
        if input
            .plugin_cpu_reservations
            .windows(2)
            .any(|pair| pair[0].plugin_id >= pair[1].plugin_id)
        {
            return Err(ExecutableBudgetErrorV1::NonCanonical);
        }
        for level in 0..3 {
            let plugin_sum = input
                .plugin_cpu_reservations
                .iter()
                .map(|row| u64::from(row.cpu_reservations_us[level]))
                .try_fold(0_u64, |sum, value| sum.checked_add(value))
                .ok_or(ExecutableBudgetErrorV1::FieldOutOfBounds)?;
            let total = plugin_sum
                .checked_add(u64::from(
                    input.fidelity_budgets[level].shared_host_cpu_reservation_us,
                ))
                .ok_or(ExecutableBudgetErrorV1::FieldOutOfBounds)?;
            if total > u64::from(input.fidelity_budgets[level].max_cpu_us) {
                return Err(ExecutableBudgetErrorV1::FieldOutOfBounds);
            }
        }
        Ok(Self(input))
    }

    #[must_use]
    pub const fn fields(&self) -> &ExecutableBudgetPolicyInputV1 {
        &self.0
    }

    /// Encode the exact definite EBP1 array.
    #[must_use]
    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        let mut out = vec![0x8b, 0x44, b'E', b'B', b'P', b'1', 1];
        encode_uint(&mut out, u64::from(self.0.revision));
        encode_uint(&mut out, u64::from(self.0.workload_profile.code()));
        encode_uint(&mut out, u64::from(self.0.cut_budget_family));
        encode_uint(&mut out, u64::from(self.0.max_event_bytes));
        out.push(0x83);
        for budget in self.0.fidelity_budgets {
            out.push(0x85);
            encode_uint(&mut out, u64::from(budget.level));
            encode_uint(&mut out, u64::from(budget.max_events));
            encode_uint(&mut out, budget.max_bytes);
            encode_uint(&mut out, u64::from(budget.max_cpu_us));
            encode_uint(&mut out, u64::from(budget.shared_host_cpu_reservation_us));
        }
        encode_rows(&mut out, &self.0.plugin_cpu_reservations);
        encode_uint(&mut out, u64::from(self.0.accounting_semantics));
        out.extend_from_slice(&[0x58, 32]);
        out.extend_from_slice(self.0.execution_profile_hash.as_bytes());
        encode_uint(&mut out, self.0.max_pass_wall_duration_us);
        out
    }

    /// Decode a bounded canonical EBP1 value.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ExecutableBudgetErrorV1> {
        if bytes.len() > MAX_EXECUTABLE_BUDGET_POLICY_BYTES_V1 {
            return Err(ExecutableBudgetErrorV1::FieldOutOfBounds);
        }
        let mut reader = Reader { bytes, offset: 0 };
        reader.array(11)?;
        if reader.blob::<4>()? != *b"EBP1" || reader.uint()? != 1 {
            return Err(ExecutableBudgetErrorV1::UnsupportedValue);
        }
        let revision = reader.uint_u32()?;
        let workload_profile = WorkloadProfileV1::from_code(reader.uint_u8()?)?;
        let cut_budget_family = reader.uint_u8()?;
        let max_event_bytes = reader.uint_u32()?;
        reader.array(3)?;
        let mut fidelity_budgets = [FidelityBudgetV1 {
            level: 0,
            max_events: 0,
            max_bytes: 0,
            max_cpu_us: 0,
            shared_host_cpu_reservation_us: 0,
        }; 3];
        for budget in &mut fidelity_budgets {
            reader.array(5)?;
            budget.level = reader.uint_u8()?;
            budget.max_events = reader.uint_u32()?;
            budget.max_bytes = reader.uint()?;
            budget.max_cpu_us = reader.uint_u32()?;
            budget.shared_host_cpu_reservation_us = reader.uint_u32()?;
        }
        let plugin_cpu_reservations = reader.rows()?;
        let accounting_semantics = reader.uint_u8()?;
        let execution_profile_hash = Hash::from_bytes(reader.blob::<32>()?);
        let max_pass_wall_duration_us = reader.uint()?;
        if reader.offset != bytes.len() {
            return Err(ExecutableBudgetErrorV1::NonCanonical);
        }
        let policy = Self::new(ExecutableBudgetPolicyInputV1 {
            revision,
            workload_profile,
            cut_budget_family,
            max_event_bytes,
            fidelity_budgets,
            plugin_cpu_reservations,
            accounting_semantics,
            execution_profile_hash,
            max_pass_wall_duration_us,
        })?;
        if policy.to_canonical_cbor() != bytes {
            return Err(ExecutableBudgetErrorV1::NonCanonical);
        }
        Ok(policy)
    }

    /// Ordinary BLAKE3 identity of the exact canonical policy bytes.
    #[must_use]
    pub fn digest(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"pigloros.executable-budget-policy.v1");
        hasher.update(&[0]);
        hasher.update(&self.to_canonical_cbor());
        Hash::from_bytes(*hasher.finalize().as_bytes())
    }
}

fn encode_uint(out: &mut Vec<u8>, value: u64) {
    const MAX_U32: u64 = u32::MAX as u64;
    match value {
        0..=23 => out.push(byte(value)),
        24..=255 => out.extend_from_slice(&[0x18, byte(value)]),
        256..=65_535 => out.extend_from_slice(&[0x19, byte(value >> 8), byte(value)]),
        65_536..=MAX_U32 => out.extend_from_slice(&[
            0x1a,
            byte(value >> 24),
            byte(value >> 16),
            byte(value >> 8),
            byte(value),
        ]),
        _ => out.extend_from_slice(&[
            0x1b,
            byte(value >> 56),
            byte(value >> 48),
            byte(value >> 40),
            byte(value >> 32),
            byte(value >> 24),
            byte(value >> 16),
            byte(value >> 8),
            byte(value),
        ]),
    }
}

fn byte(value: u64) -> u8 {
    u8::try_from(value & 0xff).expect("masked value fits in u8")
}

fn encode_rows(out: &mut Vec<u8>, rows: &[PluginCpuReservationV1]) {
    match rows.len() {
        0..=23 => out.push(0x80 | u8::try_from(rows.len()).expect("row count fits in u8")),
        24..=255 => out.extend_from_slice(&[
            0x98,
            u8::try_from(rows.len()).expect("row count fits in u8"),
        ]),
        _ => out.extend_from_slice(&[
            0x99,
            u8::try_from(rows.len() >> 8).expect("row count high byte fits in u8"),
            u8::try_from(rows.len()).expect("row count fits in u8"),
        ]),
    }
    for row in rows {
        out.push(0x82);
        out.extend_from_slice(&[0x50]);
        out.extend_from_slice(&row.plugin_id.inner().to_bytes());
        out.push(0x83);
        for reservation in row.cpu_reservations_us {
            encode_uint(out, u64::from(reservation));
        }
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], ExecutableBudgetErrorV1> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ExecutableBudgetErrorV1::InvalidEncoding)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ExecutableBudgetErrorV1::InvalidEncoding)?;
        self.offset = end;
        Ok(value)
    }

    fn head(&mut self, major: u8) -> Result<(u8, u64), ExecutableBudgetErrorV1> {
        let initial = *self
            .take(1)?
            .first()
            .ok_or(ExecutableBudgetErrorV1::InvalidEncoding)?;
        if initial >> 5 != major {
            return Err(ExecutableBudgetErrorV1::InvalidEncoding);
        }
        let additional = initial & 0x1f;
        let (width, value) = match additional {
            0..=23 => (0, u64::from(additional)),
            24 => (1, u64::from(self.take(1)?[0])),
            25 => {
                let bytes = self.take(2)?;
                (2, u64::from(u16::from_be_bytes([bytes[0], bytes[1]])))
            }
            26 => {
                let bytes = self.take(4)?;
                (
                    4,
                    u64::from(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
                )
            }
            27 => {
                let bytes = self.take(8)?;
                (
                    8,
                    u64::from_be_bytes([
                        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
                        bytes[7],
                    ]),
                )
            }
            _ => return Err(ExecutableBudgetErrorV1::InvalidEncoding),
        };
        let minimum = match width {
            0 => 0,
            1 => 24,
            2 => 256,
            4 => 65_536,
            8 => 1_u64 << 32,
            _ => return Err(ExecutableBudgetErrorV1::InvalidEncoding),
        };
        if value < minimum {
            return Err(ExecutableBudgetErrorV1::NonCanonical);
        }
        Ok((width, value))
    }

    fn uint(&mut self) -> Result<u64, ExecutableBudgetErrorV1> {
        Ok(self.head(0)?.1)
    }

    fn uint_u8(&mut self) -> Result<u8, ExecutableBudgetErrorV1> {
        self.uint()?
            .try_into()
            .map_err(|_| ExecutableBudgetErrorV1::FieldOutOfBounds)
    }

    fn uint_u32(&mut self) -> Result<u32, ExecutableBudgetErrorV1> {
        self.uint()?
            .try_into()
            .map_err(|_| ExecutableBudgetErrorV1::FieldOutOfBounds)
    }

    fn array(&mut self, length: u64) -> Result<(), ExecutableBudgetErrorV1> {
        if self.head(4)?.1 == length {
            Ok(())
        } else {
            Err(ExecutableBudgetErrorV1::InvalidEncoding)
        }
    }

    fn blob<const N: usize>(&mut self) -> Result<[u8; N], ExecutableBudgetErrorV1> {
        let length = self.head(2)?.1;
        if length != N as u64 {
            return Err(ExecutableBudgetErrorV1::InvalidEncoding);
        }
        self.take(N)?
            .try_into()
            .map_err(|_| ExecutableBudgetErrorV1::InvalidEncoding)
    }

    fn rows(&mut self) -> Result<Vec<PluginCpuReservationV1>, ExecutableBudgetErrorV1> {
        let count = self.head(4)?.1;
        let count: usize = count
            .try_into()
            .map_err(|_| ExecutableBudgetErrorV1::FieldOutOfBounds)?;
        if count == 0 || count > MAX_PLUGIN_CPU_RESERVATIONS_V1 {
            return Err(ExecutableBudgetErrorV1::FieldOutOfBounds);
        }
        let mut rows = Vec::with_capacity(count);
        for _ in 0..count {
            self.array(2)?;
            let id = self.blob::<16>()?;
            self.array(3)?;
            let mut cpu_reservations_us = [0_u32; 3];
            for reservation in &mut cpu_reservations_us {
                *reservation = self.uint_u32()?;
            }
            rows.push(PluginCpuReservationV1 {
                plugin_id: PluginId::from_ulid(ulid::Ulid::from(u128::from_be_bytes(id))),
                cpu_reservations_us,
            });
        }
        Ok(rows)
    }
}
