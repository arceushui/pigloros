//! `MemoryStore` adapter for the ADR-105 `FIP1` issuer-policy port.
//!
//! The retained history is one vector whose last entry is the floor, so a
//! single push installs the policy and advances the floor together. Each
//! entry keeps the digest recorded at install, and every read cross-checks an
//! entry against its position, the floor scope, and that digest, as the
//! `SQLite` adapter does for its rows.

use super::MemoryStore;
use crate::fork_attribution_issuer_policy::{
    admit_fork_attribution_issuer, checked_retained_policy, pinned_issuer_policy,
    plan_issuer_policy_install, AuthenticatedOperatorPolicyPinV1,
    ForkAttributionIssuerAdmissionBasisV1, ForkAttributionIssuerAdmissionQueryV1,
    ForkAttributionIssuerAdmissionV1, ForkAttributionIssuerPolicyErrorV1,
    ForkAttributionIssuerPolicyInstallationPortV1, IssuerPolicyFloorV1,
    IssuerPolicyInstallOutcomeV1, IssuerPolicyInstallReceiptV1, LoadedIssuerPolicyV1,
};

impl MemoryStore {
    /// The retained policy at `generation`, cross-checked like a stored row.
    fn retained_issuer_policy(&self, generation: u64) -> LoadedIssuerPolicyV1 {
        let history = &self.fork_attribution_issuer_policies;
        let floor = history.last();
        let scope = floor.map(|(_, floor)| floor.input().scope.as_str());
        let position = usize::try_from(generation).ok();
        let index = position.and_then(|position| position.checked_sub(1));
        index
            .and_then(|index| history.get(index))
            .zip(scope)
            .map(|((digest, policy), scope)| {
                checked_retained_policy(policy.clone(), scope, generation, *digest)
            })
            .transpose()
    }

    /// The floor policy: the retained policy at the history length.
    fn floor_issuer_policy(&self) -> LoadedIssuerPolicyV1 {
        let count = self.fork_attribution_issuer_policies.len();
        let generation = u64::try_from(count).unwrap_or(0);
        self.retained_issuer_policy(generation)
    }
}

impl ForkAttributionIssuerPolicyInstallationPortV1 for MemoryStore {
    fn install(
        &mut self,
        pin: &AuthenticatedOperatorPolicyPinV1,
        policy_bytes: &[u8],
    ) -> Result<IssuerPolicyInstallReceiptV1, ForkAttributionIssuerPolicyErrorV1> {
        pinned_issuer_policy(pin, policy_bytes).and_then(|candidate| {
            let current = self.floor_issuer_policy()?;
            let receipt = plan_issuer_policy_install(&candidate, current.as_ref())?;
            if receipt.outcome == IssuerPolicyInstallOutcomeV1::Installed {
                let digest = candidate.digest();
                self.fork_attribution_issuer_policies
                    .push((digest, candidate));
            }
            Ok(receipt)
        })
    }

    fn issuer_policy_floor(
        &self,
    ) -> Result<Option<IssuerPolicyFloorV1>, ForkAttributionIssuerPolicyErrorV1> {
        let floor = self.floor_issuer_policy()?;
        Ok(floor.as_ref().map(IssuerPolicyFloorV1::of))
    }

    fn admit_issuer(
        &self,
        query: &ForkAttributionIssuerAdmissionQueryV1,
    ) -> Result<ForkAttributionIssuerAdmissionV1, ForkAttributionIssuerPolicyErrorV1> {
        admit_fork_attribution_issuer(query, |basis| match basis {
            ForkAttributionIssuerAdmissionBasisV1::CommittedImport { policy_generation } => {
                self.retained_issuer_policy(policy_generation)
            }
            ForkAttributionIssuerAdmissionBasisV1::AbsentImport => self.floor_issuer_policy(),
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use ed25519_dalek::SigningKey;
    use pos_core::{
        ForkAttributionIssuerPolicyEntryV1, ForkAttributionIssuerPolicyInputV1,
        ForkAttributionIssuerPolicyV1, ForkAttributionIssuerStateV1, ForkAttributionIssuerV1, Hash,
        PublicKey,
    };

    use super::*;

    type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
    type Outcome = Result<IssuerPolicyInstallOutcomeV1, ForkAttributionIssuerPolicyErrorV1>;
    type Admission = Result<ForkAttributionIssuerAdmissionV1, ForkAttributionIssuerPolicyErrorV1>;

    const CORRUPT: ForkAttributionIssuerPolicyErrorV1 =
        ForkAttributionIssuerPolicyErrorV1::CorruptPolicy;

    fn issuer() -> Fallible<ForkAttributionIssuerV1> {
        let signing = SigningKey::from_bytes(&[1; 32]);
        let key = PublicKey::from_bytes(signing.verifying_key().to_bytes());
        Ok(ForkAttributionIssuerV1::new("issuer-a", 1, key)?)
    }

    /// One policy holding the single test issuer in `state`.
    fn policy(
        scope: &str,
        generation: u64,
        previous: Option<Hash>,
        state: ForkAttributionIssuerStateV1,
    ) -> Fallible<ForkAttributionIssuerPolicyV1> {
        Ok(ForkAttributionIssuerPolicyV1::new(
            ForkAttributionIssuerPolicyInputV1 {
                scope: scope.to_owned(),
                generation,
                previous_policy_digest: previous,
                entries: vec![ForkAttributionIssuerPolicyEntryV1 {
                    issuer: issuer()?,
                    state,
                }],
            },
        )?)
    }

    fn install(store: &mut MemoryStore, policy: &ForkAttributionIssuerPolicyV1) -> Outcome {
        let pin = AuthenticatedOperatorPolicyPinV1::new("destination-a", policy.digest());
        store
            .install(&pin, &policy.to_canonical_cbor())
            .map(|receipt| receipt.outcome)
    }

    fn committed(store: &MemoryStore, digest: Hash, generation: u64) -> Fallible<Admission> {
        Ok(store.admit_issuer(&ForkAttributionIssuerAdmissionQueryV1 {
            issuer: issuer()?,
            policy_digest: digest,
            basis: ForkAttributionIssuerAdmissionBasisV1::CommittedImport {
                policy_generation: generation,
            },
        }))
    }

    /// A store whose issuer is Active at generation 1 and revoked at 2.
    fn installed_store() -> Fallible<(MemoryStore, ForkAttributionIssuerPolicyV1)> {
        let active = ForkAttributionIssuerStateV1::Active;
        let revoked = ForkAttributionIssuerStateV1::Revoked;
        let first = policy("destination-a", 1, None, active)?;
        let second = policy("destination-a", 2, Some(first.digest()), revoked)?;
        let mut store = MemoryStore::new();
        for policy in [&first, &second] {
            let outcome = install(&mut store, policy);
            assert_eq!(outcome, Ok(IssuerPolicyInstallOutcomeV1::Installed));
        }
        Ok((store, first))
    }

    #[test]
    fn tampered_retained_records_are_corrupt() -> Fallible<()> {
        let active = ForkAttributionIssuerStateV1::Active;
        let unknown = Some(Hash::from_bytes([3; 32]));
        let moved = policy("destination-a", 5, unknown, active)?;
        let rescoped = policy("destination-b", 1, None, active)?;
        let (store, first) = installed_store()?;
        assert!(committed(&store, first.digest(), 1)?.is_ok());
        // Each case stores its own content digest, so only the targeted
        // generation, digest, or scope check can reject it.
        for tampered in [
            (moved.digest(), moved),
            (Hash::from_bytes([0; 32]), first.clone()),
            (rescoped.digest(), rescoped),
        ] {
            let (mut store, first) = installed_store()?;
            store.fork_attribution_issuer_policies[0] = tampered;
            assert_eq!(committed(&store, first.digest(), 1)?, Err(CORRUPT));
        }
        Ok(())
    }

    #[test]
    fn a_tampered_floor_digest_is_corrupt() -> Fallible<()> {
        let (mut store, first) = installed_store()?;
        store.fork_attribution_issuer_policies[1].0 = Hash::from_bytes([0; 32]);
        assert_eq!(store.issuer_policy_floor(), Err(CORRUPT));
        let active = ForkAttributionIssuerStateV1::Active;
        let third = policy("destination-a", 3, Some(first.digest()), active)?;
        assert_eq!(install(&mut store, &third), Err(CORRUPT));
        Ok(())
    }

    #[test]
    fn a_ninety_seventh_record_is_refused() -> Fallible<()> {
        // Single-step transitions reach at most 95 records, so seed a
        // 96-record history directly.
        let active = ForkAttributionIssuerStateV1::Active;
        let mut store = MemoryStore::new();
        let mut previous = None;
        for generation in 1..=96 {
            let seeded = policy("destination-a", generation, previous, active)?;
            previous = Some(seeded.digest());
            store
                .fork_attribution_issuer_policies
                .push((seeded.digest(), seeded));
        }
        let next = policy("destination-a", 97, previous, active)?;
        let exhausted = Err(ForkAttributionIssuerPolicyErrorV1::HistoryExhausted);
        assert_eq!(install(&mut store, &next), exhausted);
        assert_eq!(store.fork_attribution_issuer_policies.len(), 96);
        Ok(())
    }
}
