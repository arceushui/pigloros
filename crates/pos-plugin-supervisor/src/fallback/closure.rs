//! Closure derivation: the implementation every tenure of a slot ran, from the Events alone
//! (ADR-119 section 4.6, "Evidence and closure").

use std::collections::BTreeMap;

use pos_core::{
    Event, EventId, FallbackActivatedInputV1, FallbackActivatedPayloadV1, ImplementationKeyV1, Seq,
    COMPOSITION_FALLBACK_ACTIVATED_EVENT_TYPE_V1,
};
use pos_runtime::community_plugin_host::{cbor, PLUGIN_RELEASE_ACTIVATED_EVENT_TYPE_V1};

use super::FallbackRestartSlotV1;

/// The CBOR head of a 32-byte byte string.
const DIGEST_HEAD: [u8; 2] = [0x58, 0x20];
/// The length of a BLAKE3-256 digest.
const DIGEST_LEN: usize = 32;

/// The evidence that names the implementation of one tenure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FallbackTenureEvidenceV1 {
    /// Tenure 0, the composer's base implementation. It is identified by the composer's
    /// admitted-release evidence ([`FallbackTenuresV1::admitted_release_v1`]), which shows
    /// admission, not execution.
    Base,
    /// A later tenure: the activation Event that opened it, which carries the full IMK1.
    Activation {
        /// The activation Event's ID.
        event_id: EventId,
        /// The activation Event's logical sequence; the tenure is effective from here on.
        seq: Seq,
    },
}

/// One tenure of one slot: a maximal range in which one implementation is effective.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FallbackTenureV1 {
    /// The ordinal; tenure 0 runs the composer's base implementation.
    pub ordinal: u64,
    /// The implementation the tenure runs.
    pub implementation: ImplementationKeyV1,
    /// The evidence that names it.
    pub evidence: FallbackTenureEvidenceV1,
}

impl FallbackTenureV1 {
    /// The position the tenure opens at: 0 for tenure 0, its activation's sequence after.
    #[must_use]
    pub const fn opened_at(&self) -> Seq {
        match self.evidence {
            FallbackTenureEvidenceV1::Base => Seq::ZERO,
            FallbackTenureEvidenceV1::Activation { seq, .. } => seq,
        }
    }
}

/// A closure derivation that the Events refuse.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FallbackClosureErrorV1 {
    /// An activation Event does not decode.
    #[error("an activation Event does not decode")]
    UndecodableActivation,
    /// An activation does not close its entry's current tenure on its effective
    /// implementation.
    #[error("an activation does not close its entry's current tenure")]
    Discontinuous,
    /// An activation of the scope names an entry key that no slot of the recipe names.
    #[error("an activation names an entry key outside the recipe")]
    UnknownEntry,
}

/// The tenures of every slot of a composition, in order.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FallbackTenuresV1 {
    entries: BTreeMap<String, Vec<FallbackTenureV1>>,
}

impl FallbackTenuresV1 {
    /// The tenures of `entry_key`, tenure 0 first; empty for a key no slot names.
    #[must_use]
    pub fn tenures(&self, entry_key: &str) -> &[FallbackTenureV1] {
        let tenures = self.entries.get(entry_key);
        tenures.map(Vec::as_slice).unwrap_or_default()
    }

    /// The tenure of `entry_key` effective at `position`: the last one opened at or before it.
    #[must_use]
    pub fn tenure_at(&self, entry_key: &str, position: Seq) -> Option<&FallbackTenureV1> {
        self.tenures(entry_key)
            .iter()
            .rev()
            .find(|tenure| tenure.opened_at() <= position)
    }

    /// The implementation `entry_key` runs after the last folded Event.
    #[must_use]
    pub fn effective(&self, entry_key: &str) -> Option<&ImplementationKeyV1> {
        let latest = self.tenures(entry_key).last();
        latest.map(|tenure| &tenure.implementation)
    }

    /// The composer's admitted-release evidence of `entry_key`'s tenure 0 (the tenure-0 rule).
    ///
    /// It is the first `release-activated` Event of `admissions` whose payload names the
    /// tenure-0 Plugin ID and release digest in `trust_scope` (ADR-119 section 4.6).
    ///
    /// That Event shows admission, not execution. It sits on the installer-supplied Timeline,
    /// which need not be the activation target, and it carries no version text: the tenure-0
    /// version is the label of the composer's recipe. When several releases of the Plugin ID
    /// were admitted, only the one whose release digest is the tenure-0 IMK1's counts.
    #[must_use]
    pub fn admitted_release_v1<'e>(
        &self,
        entry_key: &str,
        trust_scope: &str,
        admissions: &'e [Event],
    ) -> Option<&'e Event> {
        let base = self.tenures(entry_key).first();
        base.and_then(|base| {
            let key = &base.implementation;
            admissions
                .iter()
                .find(|event| admits(event, trust_scope, key))
        })
    }

    /// `slot` with its base pin running its latest tenure's implementation.
    ///
    /// A restart therefore composes an entry frozen by a withdrawal (ADR-119 section 4.3) on
    /// the implementation it froze. The roles are the base pin's, which every candidate shares
    /// (section 4.1 rule 1).
    #[must_use]
    pub(super) fn restart_slot(&self, slot: &FallbackRestartSlotV1) -> FallbackRestartSlotV1 {
        let base = slot.base.implementation();
        let effective = self.effective(&slot.entry_key).unwrap_or(base);
        FallbackRestartSlotV1 {
            entry_key: slot.entry_key.clone(),
            base: slot.base.with_implementation(effective.clone()),
        }
    }

    /// Fold one activation Event.
    fn folded(mut self, scope: &str, event: &Event) -> Result<Self, FallbackClosureErrorV1> {
        let payload = FallbackActivatedPayloadV1::from_canonical_cbor(event.payload.as_slice());
        let undecodable = Err(FallbackClosureErrorV1::UndecodableActivation);
        let payload = payload.or(undecodable)?;
        let input = payload.as_input();
        if input.scope != scope {
            return Ok(self);
        }
        let unknown = FallbackClosureErrorV1::UnknownEntry;
        let tenures = self.entries.get_mut(&input.entry_key).ok_or(unknown)?;
        let opened = open_tenure(tenures, input, event);
        opened.map(|()| self)
    }
}

/// Derive the tenures of every slot from `events` (ADR-119 section 4.6 and case 6).
///
/// Tenure 0 of each slot runs the composer's base implementation. Each activation Event of
/// `scope` for a slot opens the next tenure on its `to_imk1_bytes`, which name the
/// implementation in full. No DFP1 bytes and no registry row are read, and nothing is
/// classified or activated, so Replay and a Timeline exported without the policy bytes resolve
/// the same tenures. A declaration changes no tenure: a re-base continues it.
///
/// Pass the Events at or before a position to close the composition at that position; a
/// Fork's Events include its inherited prefix. Activations of another scope are not folded.
/// An activation of `scope` for a key no slot names fails closed: every declared entry key is
/// a slot of the composer's recipe (ADR-119 section 1), so such an Event means the recipe and
/// the Timeline disagree.
///
/// # Errors
/// [`FallbackClosureErrorV1::UndecodableActivation`] for an activation Event that does not
/// decode, [`FallbackClosureErrorV1::UnknownEntry`] for one of `scope` whose entry key no slot
/// names, and [`FallbackClosureErrorV1::Discontinuous`] for one that does not close its
/// entry's current tenure on its effective implementation.
pub fn fallback_tenures_v1(
    scope: &str,
    slots: &[FallbackRestartSlotV1],
    events: &[Event],
) -> Result<FallbackTenuresV1, FallbackClosureErrorV1> {
    let entries = slots.iter().map(base_entry).collect();
    let tenures = FallbackTenuresV1 { entries };
    let fold = |tenures: FallbackTenuresV1, event| tenures.folded(scope, event);
    activation_events(events).try_fold(tenures, fold)
}

/// The activation Events among `events`, in order, whatever their scope.
pub(super) fn activation_events(events: &[Event]) -> impl Iterator<Item = &Event> {
    let activated = COMPOSITION_FALLBACK_ACTIVATED_EVENT_TYPE_V1;
    events
        .iter()
        .filter(move |event| event.event_type.as_str() == activated)
}

/// The entry of `slot` with tenure 0 alone.
fn base_entry(slot: &FallbackRestartSlotV1) -> (String, Vec<FallbackTenureV1>) {
    let tenure = FallbackTenureV1 {
        ordinal: 0,
        implementation: slot.base.implementation().clone(),
        evidence: FallbackTenureEvidenceV1::Base,
    };
    (slot.entry_key.clone(), vec![tenure])
}

/// Open the tenure `input` activates, after the current one, which it must close.
fn open_tenure(
    tenures: &mut Vec<FallbackTenureV1>,
    input: &FallbackActivatedInputV1,
    event: &Event,
) -> Result<(), FallbackClosureErrorV1> {
    let current = tenures.last().filter(|current| closes(current, input));
    let ordinal = current.and_then(|current| current.ordinal.checked_add(1));
    let ordinal = ordinal.ok_or(FallbackClosureErrorV1::Discontinuous)?;
    let evidence = FallbackTenureEvidenceV1::Activation {
        event_id: event.id,
        seq: event.seq,
    };
    tenures.push(FallbackTenureV1 {
        ordinal,
        implementation: input.to.clone(),
        evidence,
    });
    Ok(())
}

/// Whether `input` closes `current` on its implementation.
fn closes(current: &FallbackTenureV1, input: &FallbackActivatedInputV1) -> bool {
    current.ordinal == input.closing_tenure_ordinal && current.implementation == input.from
}

/// Whether `event` is a `release-activated` Event of `key`'s release in `trust_scope`.
fn admits(event: &Event, trust_scope: &str, key: &ImplementationKeyV1) -> bool {
    let activation = event.event_type.as_str() == PLUGIN_RELEASE_ACTIVATED_EVENT_TYPE_V1;
    activation && names_release(event.payload.as_slice(), trust_scope, key)
}

/// Whether `payload` is the canonical `[scope, plugin_id, pmf1_digest, release_digest]` of
/// `key`'s release in `trust_scope`, whatever its PMF1 digest.
fn names_release(payload: &[u8], trust_scope: &str, key: &ImplementationKeyV1) -> bool {
    let mut head = Vec::new();
    cbor::array(&mut head, 4);
    cbor::text(&mut head, trust_scope);
    cbor::text(&mut head, key.plugin_id());
    let mut tail = Vec::new();
    cbor::bytes(&mut tail, key.release_digest().as_bytes());
    let pmf1 = payload.strip_prefix(head.as_slice());
    let pmf1 = pmf1.and_then(|rest| rest.strip_suffix(tail.as_slice()));
    let pmf1 = pmf1.and_then(|item| item.strip_prefix(&DIGEST_HEAD));
    pmf1.is_some_and(|digest| digest.len() == DIGEST_LEN)
}
