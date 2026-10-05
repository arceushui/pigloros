//! Closed domain vocabularies shared by the evaluator's independent codecs.
//!
//! Every CPF1, CFB1, EAI1, and CNR1 discriminant is decoded into one of these
//! enums at the wire boundary. A value outside the closed range cannot be
//! represented, so no validated profile, bundle, attempt, or report can carry
//! an invalid discriminant. The wire codes are exactly the integers the codecs
//! always emitted; `code` is the single place that maps a value back to them.
//!
//! This module owns only the vocabularies. The archive (CFB1) verifier and the
//! profile (CPF1) verifier keep their own relationship checks on purpose: each
//! re-derives closure, ordering, and binding rules from the bytes it receives,
//! and that duplication is an independence control that must not be merged.

macro_rules! closed_codes {
    (
        $(#[$meta:meta])*
        $name:ident { $($variant:ident = $code:literal),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            /// Every value in ascending wire order.
            pub const ALL: &[Self] = &[$(Self::$variant),+];

            /// Decode one exact wire code, rejecting every unassigned value.
            #[must_use]
            pub const fn from_code(code: u8) -> Option<Self> {
                match code {
                    $($code => Some(Self::$variant),)+
                    _ => None,
                }
            }

            /// Return the exact wire code.
            #[must_use]
            pub const fn code(self) -> u8 {
                match self {
                    $(Self::$variant => $code),+
                }
            }
        }
    };
}

closed_codes! {
    /// Independently reportable conformance claim layer.
    ClaimLayer {
        ArtifactIntegrity = 0,
        ReplayConformance = 1,
        KnowledgeNonInterference = 2,
        GatewayClientConformance = 3,
        PluginConformance = 4,
        MetricConformance = 5,
        EmpiricalEvaluation = 6,
    }
}

closed_codes! {
    /// Fixture family exercised once per provider, mode, and execution profile.
    FixtureFamily {
        Positive = 0,
        Denied = 1,
        Malformed = 2,
        ResourceExhaustion = 3,
        DeletionRedaction = 4,
        Downgrade = 5,
        IndependentEvaluation = 6,
    }
}

closed_codes! {
    /// Deterministic execution mode of one attempt.
    ExecutionMode {
        Local = 0,
        AirGapped = 1,
        Replay = 2,
        Fork = 3,
    }
}

closed_codes! {
    /// Strength of the replay claim a case or report supports.
    ReplayClaim {
        Exact = 0,
        ExactAuthoritativeWithRedactedViews = 1,
        StructuralOnly = 2,
        UnverifiableArtifactsMissing = 3,
        IncompatibleProfile = 4,
    }
}

closed_codes! {
    /// How much case evidence a redaction removed.
    RedactionState {
        Unredacted = 0,
        RedactedViews = 1,
        StructuralOnly = 2,
        EvidenceMissing = 3,
    }
}

closed_codes! {
    /// Closed kind of the first mismatch between two deterministic results.
    DivergenceMismatchKind {
        EventIdentity = 0,
        EventOrder = 1,
        CanonicalBytes = 2,
        ProjectionCheckpoint = 3,
        TypedFailure = 4,
        Artifact = 5,
        SchemaOrUpcaster = 6,
        NumericProfile = 7,
        ProhibitedOperationalInput = 8,
    }
}

closed_codes! {
    /// Role of one immutable CFB1 archive member.
    MemberRole {
        FixtureInput = 0,
        ExpectedResult = 1,
        Profile = 2,
        NormativeSpecification = 3,
        Schema = 4,
        Licence = 5,
        Notice = 6,
        Sbom = 7,
        Provenance = 8,
        Limitations = 9,
        AuthorityInventory = 10,
        ExecutionMatrix = 11,
        FixtureProviderRegistry = 12,
        FixtureProviderPackage = 13,
        ExecutionProfile = 14,
        TrustPolicySnapshot = 15,
        ReleaseAdmission = 16,
        EvidenceStatus = 17,
        FixtureContractPolicy = 18,
        AuthorityDeclaration = 19,
    }
}

closed_codes! {
    /// Expected result classification of verifying one fixture.
    VerificationOutcome {
        VerifiedExact = 0,
        Diverged = 1,
        InvalidManifest = 2,
        UnverifiableArtifactsMissing = 3,
        IncompatibleProfile = 4,
        ResourceLimitExceeded = 5,
    }
}

closed_codes! {
    /// Closed safe error vocabulary shared by verification and conformance cases.
    SafeErrorCode {
        InvalidEncoding = 0,
        UnsupportedVersion = 1,
        FieldOutOfBounds = 2,
        NonCanonicalOrder = 3,
        DigestMismatch = 4,
        SignatureInvalid = 5,
        TrustRootUnknown = 6,
        TrustSnapshotRollback = 7,
        ArtifactRevoked = 8,
        ClosureIncomplete = 9,
        ProfileClassMismatch = 10,
        ProfileUnsupported = 11,
        ProvenanceMissing = 12,
        ResourceLimitExceeded = 13,
    }
}

impl ExecutionMode {
    /// Decode a CFB1 archive mode, which only ever selects Local or Air-Gapped.
    #[must_use]
    pub const fn archive_from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Local),
            1 => Some(Self::AirGapped),
            _ => None,
        }
    }
}

impl DivergenceMismatchKind {
    /// Decode a kind a CPF1 fixture may declare as its expected divergence.
    ///
    /// The numeric-profile and prohibited-operational-input kinds are only
    /// observable from a subject and are never valid fixture declarations.
    #[must_use]
    pub const fn fixture_from_code(code: u8) -> Option<Self> {
        if code <= Self::SchemaOrUpcaster.code() {
            Self::from_code(code)
        } else {
            None
        }
    }
}

impl RedactionState {
    /// Report whether this redaction state coheres with a replay claim.
    ///
    /// An incompatible profile coheres with every state; each other claim must
    /// match the evidence the state removed.
    #[must_use]
    pub const fn admits_replay(self, claim: ReplayClaim) -> bool {
        use ReplayClaim::{
            ExactAuthoritativeWithRedactedViews, IncompatibleProfile, StructuralOnly,
            UnverifiableArtifactsMissing,
        };
        matches!(claim, IncompatibleProfile)
            || match self {
                Self::Unredacted => true,
                Self::RedactedViews => matches!(claim, ExactAuthoritativeWithRedactedViews),
                Self::StructuralOnly => matches!(claim, StructuralOnly),
                Self::EvidenceMissing => matches!(claim, UnverifiableArtifactsMissing),
            }
    }
}

impl VerificationOutcome {
    /// Report whether this outcome is a typed failure rather than a result.
    #[must_use]
    pub const fn is_failure(self) -> bool {
        self.failure_safe_error().is_some()
    }

    /// Return the safe error a failing fixture of this outcome must report.
    #[must_use]
    pub const fn failure_safe_error(self) -> Option<SafeErrorCode> {
        match self {
            Self::VerifiedExact | Self::Diverged => None,
            Self::InvalidManifest => Some(SafeErrorCode::InvalidEncoding),
            Self::UnverifiableArtifactsMissing => Some(SafeErrorCode::ClosureIncomplete),
            Self::IncompatibleProfile => Some(SafeErrorCode::ProfileUnsupported),
            Self::ResourceLimitExceeded => Some(SafeErrorCode::ResourceLimitExceeded),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Debug;

    fn assert_closed<T: Copy + Debug + Eq>(
        all: &[T],
        from_code: fn(u8) -> Option<T>,
        code: fn(T) -> u8,
    ) {
        let mut next = 0_u8;
        for (wire, value) in (0_u8..).zip(all.iter().copied()) {
            assert_eq!(code(value), wire);
            assert_eq!(from_code(wire), Some(value));
            next = wire.saturating_add(1);
        }
        assert_eq!(usize::from(next), all.len());
        assert_eq!(from_code(next), None);
        assert_eq!(from_code(u8::MAX), None);
    }

    #[test]
    fn every_vocabulary_is_closed_and_round_trips_its_wire_codes() {
        assert_closed(ClaimLayer::ALL, ClaimLayer::from_code, ClaimLayer::code);
        assert_closed(
            FixtureFamily::ALL,
            FixtureFamily::from_code,
            FixtureFamily::code,
        );
        assert_closed(
            ExecutionMode::ALL,
            ExecutionMode::from_code,
            ExecutionMode::code,
        );
        assert_closed(ReplayClaim::ALL, ReplayClaim::from_code, ReplayClaim::code);
        assert_closed(
            RedactionState::ALL,
            RedactionState::from_code,
            RedactionState::code,
        );
        assert_closed(
            DivergenceMismatchKind::ALL,
            DivergenceMismatchKind::from_code,
            DivergenceMismatchKind::code,
        );
        assert_closed(MemberRole::ALL, MemberRole::from_code, MemberRole::code);
        assert_closed(
            VerificationOutcome::ALL,
            VerificationOutcome::from_code,
            VerificationOutcome::code,
        );
        assert_closed(
            SafeErrorCode::ALL,
            SafeErrorCode::from_code,
            SafeErrorCode::code,
        );
        assert_eq!(ClaimLayer::ALL.len(), 7);
        assert_eq!(FixtureFamily::ALL.len(), 7);
        assert_eq!(ExecutionMode::ALL.len(), 4);
        assert_eq!(ReplayClaim::ALL.len(), 5);
        assert_eq!(RedactionState::ALL.len(), 4);
        assert_eq!(DivergenceMismatchKind::ALL.len(), 9);
        assert_eq!(MemberRole::ALL.len(), 20);
        assert_eq!(VerificationOutcome::ALL.len(), 6);
        assert_eq!(SafeErrorCode::ALL.len(), 14);
    }

    #[test]
    fn archive_modes_admit_only_local_and_air_gapped() {
        assert_eq!(
            ExecutionMode::archive_from_code(0),
            Some(ExecutionMode::Local)
        );
        assert_eq!(
            ExecutionMode::archive_from_code(1),
            Some(ExecutionMode::AirGapped)
        );
        assert_eq!(ExecutionMode::archive_from_code(2), None);
        assert_eq!(ExecutionMode::archive_from_code(u8::MAX), None);
    }

    #[test]
    fn fixture_divergences_exclude_subject_only_kinds() {
        for kind in DivergenceMismatchKind::ALL {
            let expected = (kind.code() <= 6).then_some(*kind);
            assert_eq!(
                DivergenceMismatchKind::fixture_from_code(kind.code()),
                expected
            );
        }
        assert_eq!(DivergenceMismatchKind::fixture_from_code(u8::MAX), None);
    }

    #[test]
    fn redaction_states_admit_exactly_their_replay_claims() {
        use ReplayClaim::{
            ExactAuthoritativeWithRedactedViews, IncompatibleProfile, StructuralOnly,
            UnverifiableArtifactsMissing,
        };
        let restricted = [
            (
                RedactionState::RedactedViews,
                ExactAuthoritativeWithRedactedViews,
            ),
            (RedactionState::StructuralOnly, StructuralOnly),
            (
                RedactionState::EvidenceMissing,
                UnverifiableArtifactsMissing,
            ),
        ];
        for claim in ReplayClaim::ALL.iter().copied() {
            assert!(RedactionState::Unredacted.admits_replay(claim));
            for (state, admitted) in restricted {
                let expected = claim == admitted || claim == IncompatibleProfile;
                assert_eq!(state.admits_replay(claim), expected);
            }
        }
    }

    #[test]
    fn verification_outcomes_map_to_their_safe_errors() {
        let expected = [
            None,
            None,
            Some(SafeErrorCode::InvalidEncoding),
            Some(SafeErrorCode::ClosureIncomplete),
            Some(SafeErrorCode::ProfileUnsupported),
            Some(SafeErrorCode::ResourceLimitExceeded),
        ];
        for (outcome, error) in VerificationOutcome::ALL.iter().zip(expected) {
            assert_eq!(outcome.failure_safe_error(), error);
            assert_eq!(outcome.is_failure(), error.is_some());
        }
    }
}
