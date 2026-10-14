//! Metadata-only native registry work and the private refusal latch.

use super::{KeyIdentityV1, KeyRoleV1, OwnerIdV1};
use thiserror::Error;

/// One native work observation, with no registry contents or authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyRegistryReadWorkV1 {
    /// Check the original operation epoch and its permanent failure latch.
    Checkpoint,
    /// Debit logical owned-buffer or native-copy bytes before materialization.
    MaterializeBytes(usize),
}

/// Refusal of native read work, without input or policy details.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("key registry read work refused")]
pub struct KeyRegistryReadRefusedV1;

/// Synchronous metadata-only observation of native registry read work.
///
/// Protected consumers install their own reviewed accounting adapter. A guard
/// grants neither signing authority nor permission to release protected data.
pub trait KeyRegistryReadGuardV1 {
    /// Observe a checkpoint or a prospective native materialization.
    ///
    /// # Errors
    /// Returns the closed refusal value when this operation must stop.
    fn observe(&mut self, work: KeyRegistryReadWorkV1) -> Result<(), KeyRegistryReadRefusedV1>;
}

/// Closed native snapshot or read-policy failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum KeyRegistryReadErrorV1 {
    /// The durable snapshot violates its native representation or invariants.
    #[error("invalid key registry snapshot")]
    InvalidSnapshot,
    /// The read guard refused work; no further native read work is permitted.
    #[error("key registry read refused")]
    ReadRefused,
}

pub(super) struct ReadContext<'guard> {
    guard: &'guard mut dyn KeyRegistryReadGuardV1,
    refused: bool,
}

impl<'guard> ReadContext<'guard> {
    pub(super) fn new(guard: &'guard mut dyn KeyRegistryReadGuardV1) -> Self {
        Self {
            guard,
            refused: false,
        }
    }

    pub(super) fn checkpoint(&mut self) -> Result<(), KeyRegistryReadErrorV1> {
        self.observe(KeyRegistryReadWorkV1::Checkpoint)
    }

    fn observe(&mut self, work: KeyRegistryReadWorkV1) -> Result<(), KeyRegistryReadErrorV1> {
        if self.refused {
            return Err(KeyRegistryReadErrorV1::ReadRefused);
        }
        self.guard.observe(work).map_err(|_| {
            self.refused = true;
            KeyRegistryReadErrorV1::ReadRefused
        })
    }

    pub(super) fn materialize(&mut self, bytes: usize) -> Result<(), KeyRegistryReadErrorV1> {
        if bytes == 0 {
            self.checkpoint()
        } else {
            self.observe(KeyRegistryReadWorkV1::MaterializeBytes(bytes))
        }
    }

    fn materialize_sum(
        &mut self,
        field_bytes: usize,
        extra_bytes: usize,
    ) -> Result<(), KeyRegistryReadErrorV1> {
        self.checkpoint().and_then(|()| {
            if let Some(bytes) = field_bytes.checked_add(extra_bytes) {
                self.materialize(bytes)
            } else {
                self.refused = true;
                Err(KeyRegistryReadErrorV1::ReadRefused)
            }
        })
    }

    /// A native failure still receives its post-step checkpoint. A refusal
    /// takes precedence, including on a malformed snapshot's failure path.
    pub(super) fn step<T>(
        &mut self,
        work: impl FnOnce(&mut Self) -> Result<T, KeyRegistryReadErrorV1>,
    ) -> Result<T, KeyRegistryReadErrorV1> {
        self.checkpoint().and_then(|()| {
            let result = work(self);
            if matches!(&result, Err(KeyRegistryReadErrorV1::ReadRefused)) {
                return result;
            }
            self.checkpoint().and(result)
        })
    }

    pub(super) fn scope(
        &mut self,
        owner: &OwnerIdV1,
        role: KeyRoleV1,
    ) -> Result<(OwnerIdV1, KeyRoleV1), KeyRegistryReadErrorV1> {
        self.step(|context| {
            context
                .materialize_sum(owner.as_str().len(), 1)
                .map(|()| (*owner, role))
        })
    }

    pub(super) fn identity(
        &mut self,
        owner: &OwnerIdV1,
        role: KeyRoleV1,
        epoch: u64,
    ) -> Result<KeyIdentityV1, KeyRegistryReadErrorV1> {
        self.step(|context| {
            context
                .materialize_sum(owner.as_str().len(), 9)
                .map(|()| KeyIdentityV1::from_parts(*owner, role, epoch))
        })
    }
}

/// Only ordinary native validation uses this private infallible adapter.
pub(super) struct OrdinaryReadGuard;

impl KeyRegistryReadGuardV1 for OrdinaryReadGuard {
    fn observe(&mut self, _: KeyRegistryReadWorkV1) -> Result<(), KeyRegistryReadRefusedV1> {
        Ok(())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::{
        deletion_receipt, Hash, KeyDestructionRequestV1, KeyRegistrationV1, KeyRegistryErrorV1,
        KeyRegistryStateV1, PublicKey,
    };

    type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

    #[derive(Default)]
    struct Guard {
        remaining: usize,
        fail_at: Option<usize>,
        events: Vec<KeyRegistryReadWorkV1>,
    }

    impl KeyRegistryReadGuardV1 for Guard {
        fn observe(&mut self, work: KeyRegistryReadWorkV1) -> Result<(), KeyRegistryReadRefusedV1> {
            let ordinal = self.events.len();
            self.events.push(work);
            if self.fail_at == Some(ordinal) {
                return Err(KeyRegistryReadRefusedV1);
            }
            if let KeyRegistryReadWorkV1::MaterializeBytes(bytes) = work {
                self.remaining = self
                    .remaining
                    .checked_sub(bytes)
                    .ok_or(KeyRegistryReadRefusedV1)?;
            }
            Ok(())
        }
    }

    fn lifecycle(owner: &str) -> Fallible<Vec<(KeyRegistryStateV1, usize)>> {
        let n = owner.len();
        let identity = KeyIdentityV1::from_parts(
            OwnerIdV1::new(owner)?,
            KeyRoleV1::TimelineIntegritySigning,
            1,
        );
        let material = Hash::from_bytes([0x31; 32]);
        let mut live = KeyRegistryStateV1::new();
        live.register_key(KeyRegistrationV1::new(
            identity,
            material,
            Some(PublicKey::from_bytes([0x32; 32])),
        ))?;
        let request =
            KeyDestructionRequestV1::new(identity, material, Hash::from_bytes([0x33; 32]));
        let mut pending = live.clone();
        pending.begin_key_destruction(request)?;
        let mut destroyed = pending.clone();
        destroyed.complete_key_destruction(request, deletion_receipt(&request))?;
        // Independent ADR-116 invariant schedule, not measured remaining units:
        // live: record scope + live set + active scope + identity + active scope;
        // pending: record scope + live set + pending scope + identity;
        // destroyed: record scope + identity + destroyed set.
        Ok(vec![
            (KeyRegistryStateV1::new(), 0),
            (live, 4 * n + 44),
            (pending, 3 * n + 43),
            (destroyed, 2 * n + 42),
        ])
    }

    #[test]
    fn native_invariants_charge_exact_lifecycle_units_without_changing_ordinary_results(
    ) -> Fallible<()> {
        for owner in ["a".to_owned(), "é".repeat(64)] {
            for (state, expected) in lifecycle(&owner)? {
                assert_eq!(state.validate(), Ok(()));
                for limit in 0..=expected {
                    let mut guard = Guard {
                        remaining: limit,
                        ..Guard::default()
                    };
                    let result =
                        state.validate_with_read_context(&mut ReadContext::new(&mut guard));
                    if limit == expected {
                        assert_eq!(result, Ok(()));
                        assert_eq!(guard.remaining, 0);
                    } else {
                        assert_eq!(result, Err(KeyRegistryReadErrorV1::ReadRefused));
                    }
                    assert!(!guard
                        .events
                        .contains(&KeyRegistryReadWorkV1::MaterializeBytes(0)));
                }
            }
        }
        Ok(())
    }

    #[test]
    fn native_invariant_repeats_share_the_guard_and_never_refund_work() -> Fallible<()> {
        for (state, expected) in lifecycle("a")? {
            let mut guard = Guard {
                remaining: expected * 2,
                ..Guard::default()
            };
            let mut context = ReadContext::new(&mut guard);
            assert_eq!(state.validate_with_read_context(&mut context), Ok(()));
            assert_eq!(state.validate_with_read_context(&mut context), Ok(()));
            let third = state.validate_with_read_context(&mut context);
            if expected == 0 {
                assert_eq!(third, Ok(()));
            } else {
                assert_eq!(third, Err(KeyRegistryReadErrorV1::ReadRefused));
            }
            assert_eq!(guard.remaining, 0);
        }
        Ok(())
    }

    #[test]
    fn every_native_observation_can_refuse_and_the_first_refusal_is_permanent() -> Fallible<()> {
        for (state, expected) in lifecycle("a")? {
            let mut baseline = Guard {
                remaining: expected,
                ..Guard::default()
            };
            assert_eq!(
                state.validate_with_read_context(&mut ReadContext::new(&mut baseline)),
                Ok(())
            );
            for fail_at in 0..baseline.events.len() {
                let mut guard = Guard {
                    remaining: expected,
                    fail_at: Some(fail_at),
                    ..Guard::default()
                };
                let mut context = ReadContext::new(&mut guard);
                assert_eq!(
                    state.validate_with_read_context(&mut context),
                    Err(KeyRegistryReadErrorV1::ReadRefused)
                );
                assert_eq!(
                    context.checkpoint(),
                    Err(KeyRegistryReadErrorV1::ReadRefused)
                );
                assert_eq!(
                    context.materialize(1),
                    Err(KeyRegistryReadErrorV1::ReadRefused)
                );
                assert_eq!(guard.events, baseline.events[..=fail_at]);
            }
        }
        Ok(())
    }

    fn two_owners() -> Fallible<KeyRegistryStateV1> {
        let mut state = lifecycle("a")?.swap_remove(1).0;
        state.register_key(KeyRegistrationV1::new(
            KeyIdentityV1::new("b", KeyRoleV1::TimelineIntegritySigning, 1),
            Hash::from_bytes([0x41; 32]),
            Some(PublicKey::from_bytes([0x42; 32])),
        ))?;
        Ok(state)
    }

    #[test]
    fn repeated_high_water_scans_checkpoint_unmatched_record_keys() -> Fallible<()> {
        let state = two_owners()?;
        let mut guard = Guard {
            remaining: 96,
            // Root checkpoint, two complete record steps (9 observations
            // each), high-water entry checkpoint, then two checkpoints for
            // matched key a. Ordinal 22 is before examining unmatched key b.
            fail_at: Some(22),
            ..Guard::default()
        };
        assert_eq!(
            state.validate_with_read_context(&mut ReadContext::new(&mut guard)),
            Err(KeyRegistryReadErrorV1::ReadRefused)
        );
        assert_eq!(guard.events.len(), 23);
        assert_eq!(guard.events[22], KeyRegistryReadWorkV1::Checkpoint);
        assert_eq!(guard.remaining, 28);
        Ok(())
    }

    #[test]
    fn duplicate_material_short_circuits_without_inventing_another_set_copy() -> Fallible<()> {
        let mut state = two_owners()?;
        state
            .records
            .get_mut(&KeyIdentityV1::new(
                "b",
                KeyRoleV1::TimelineIntegritySigning,
                1,
            ))
            .ok_or("second record")?
            .private_material_digest = Some(Hash::from_bytes([0x31; 32]));
        assert_eq!(state.validate(), Err(KeyRegistryErrorV1::InvalidState));
        let mut guard = Guard {
            // Two actual scopes (2 each) and only the first unique digest (32).
            remaining: 36,
            ..Guard::default()
        };
        assert_eq!(
            state.validate_with_read_context(&mut ReadContext::new(&mut guard)),
            Err(KeyRegistryReadErrorV1::InvalidSnapshot)
        );
        assert_eq!(guard.remaining, 0);
        let native_trace = guard.events.clone();
        let mut refused = Guard {
            remaining: 36,
            fail_at: Some(native_trace.len() - 1),
            ..Guard::default()
        };
        assert_eq!(
            state.validate_with_read_context(&mut ReadContext::new(&mut refused)),
            Err(KeyRegistryReadErrorV1::ReadRefused)
        );
        assert_eq!(refused.events, native_trace);
        Ok(())
    }

    #[test]
    fn zero_byte_work_checkpoints_and_closed_errors_reveal_no_native_details() -> Fallible<()> {
        let mut guard = Guard::default();
        ReadContext::new(&mut guard).materialize(0)?;
        assert_eq!(guard.events, [KeyRegistryReadWorkV1::Checkpoint]);
        assert_eq!(
            KeyRegistryReadErrorV1::InvalidSnapshot.to_string(),
            "invalid key registry snapshot"
        );
        assert_eq!(
            KeyRegistryReadErrorV1::ReadRefused.to_string(),
            "key registry read refused"
        );
        assert_eq!(
            KeyRegistryReadRefusedV1.to_string(),
            "key registry read work refused"
        );
        Ok(())
    }

    #[test]
    fn checked_native_unit_overflow_refuses_without_an_invented_debit_and_latches() {
        let mut guard = Guard {
            remaining: usize::MAX,
            ..Guard::default()
        };
        let mut context = ReadContext::new(&mut guard);
        assert_eq!(
            context.materialize_sum(usize::MAX, 1),
            Err(KeyRegistryReadErrorV1::ReadRefused)
        );
        assert_eq!(
            context.checkpoint(),
            Err(KeyRegistryReadErrorV1::ReadRefused)
        );
        assert_eq!(
            context.materialize_sum(1, 0),
            Err(KeyRegistryReadErrorV1::ReadRefused)
        );
        assert_eq!(guard.events, [KeyRegistryReadWorkV1::Checkpoint]);
        assert_eq!(guard.remaining, usize::MAX);
    }
}
