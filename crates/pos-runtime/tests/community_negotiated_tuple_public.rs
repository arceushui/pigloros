//! Independent CNT1/profile preimages through the public negotiation boundary.

use ciborium::value::Value;
use pos_core::community_lifecycle::CommunityLifecycleErrorV1 as Error;
use pos_core::Hash;
use pos_crypto::plugin_execution::{
    DeterministicBudgetV1 as Budget, PluginCapabilityDescriptorV1 as Capability,
    COMMUNITY_PLUGIN_WORLD_V1,
};
use pos_runtime::community_plugin_host::{
    CeilingValuesV1, CommunityNegotiatedTupleV1 as Tuple, CommunityPluginCeilingsV1 as Ceilings,
    CommunityPluginExecutionProfileV1 as Profile, CommunityPluginHostAbiV1 as Host,
    CommunityPluginModeV1 as Mode, ComponentTrapClassV1, EffectiveExecutionLimitsV1,
    NegotiatedCommunityPluginV1 as Negotiated, NegotiatedTransportV1 as Transport,
    PinnedComponentRuntimeV1 as Runtime, PinnedEngineConfigV1 as Engine, TrapOutcomeV1,
    TrapTableEntryV1 as Trap,
};

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;

fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}
fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}
fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}
fn encode(value: &Value) -> Fallible<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out)?;
    Ok(out)
}
const fn engine() -> Engine {
    Engine {
        max_wasm_stack: 524_288,
        consume_fuel: true,
        epoch_interruption: true,
    }
}
fn traps() -> Vec<Trap> {
    vec![
        Trap {
            trap_code: "ZZCustom".into(),
            outcome: TrapOutcomeV1::Trap(ComponentTrapClassV1::Other),
        },
        Trap {
            trap_code: "OutOfFuel".into(),
            outcome: TrapOutcomeV1::FuelExhausted,
        },
        Trap {
            trap_code: "Interrupt".into(),
            outcome: TrapOutcomeV1::WatchdogStop,
        },
    ]
}
fn runtime() -> Fallible<Runtime> {
    Ok(Runtime::new(
        "49.0.5".into(),
        vec!["z-feature".into(), "a-feature".into()],
        engine(),
        traps(),
    )?)
}
fn profile(mode: Mode) -> Fallible<Profile> {
    Ok(Profile::new(mode, Ceilings::V1, Some(runtime()?)))
}
fn capability(id: &str) -> Capability {
    Capability {
        capability_id: id.into(),
        operation: "read".into(),
        resource_pattern: "*".into(),
        purpose: "purpose".into(),
        audience: "audience".into(),
        required: false,
        max_calls: 1,
        max_request_bytes: 2,
        max_response_bytes: 3,
    }
}
fn transport(profile: &Profile) -> Transport {
    Transport {
        world: COMMUNITY_PLUGIN_WORLD_V1.into(),
        plugin_id: "plugin-a".into(),
        pmf1_digest: [1; 32],
        release_digest: [2; 32],
        abi_major: 0,
        abi_minor: 3,
        declared_minors: (0, 5),
        required_features: vec!["alpha".into(), "beta".into()],
        not_granted_capabilities: vec![capability("a-cap"), capability("z-cap")],
        mode: profile.mode(),
        limits: EffectiveExecutionLimitsV1::clamp(Budget::MAXIMA, profile.ceilings()).values(),
        execution_profile_digest: profile.digest(),
    }
}
fn rebuild(transport: Transport, profile: &Profile) -> Fallible<Negotiated> {
    let host = Host::new(1, 3, transport.required_features.clone())?;
    Ok(Negotiated::from_transport(transport, &host, profile)?)
}
fn negotiated(profile: &Profile) -> Fallible<Negotiated> {
    rebuild(transport(profile), profile)
}
fn profile_value() -> Value {
    Value::Array(vec![
        Value::Array(vec![
            uint(67_108_864),
            uint(1_000_000_000),
            uint(1_000_000),
            uint(16_777_216),
            uint(16_384),
        ]),
        Value::Array(vec![
            text("49.0.5"),
            Value::Array(vec![text("a-feature"), text("z-feature")]),
            Value::Array(vec![uint(524_288), Value::Bool(true), Value::Bool(true)]),
            Value::Array(vec![
                Value::Array(vec![text("Interrupt"), text("OperationalWatchdogStop")]),
                Value::Array(vec![text("OutOfFuel"), text("FuelExhausted")]),
                Value::Array(vec![text("ZZCustom"), text("other")]),
            ]),
        ]),
    ])
}
fn expected(mode: u64) -> Fallible<Vec<u8>> {
    let body = encode(&profile_value())?;
    let mut preimage = b"PiglorOS.Plugin.ExecutionProfile.v1\0".to_vec();
    preimage.extend_from_slice(&(body.len() as u64).to_be_bytes());
    preimage.extend_from_slice(&body);
    let profile_digest = blake3::hash(&preimage);
    let caps = Value::Array(
        ["a-cap", "z-cap"]
            .into_iter()
            .map(|id| {
                Value::Array(vec![
                    text(id),
                    text("read"),
                    text("*"),
                    text("purpose"),
                    text("audience"),
                    Value::Bool(false),
                    uint(1),
                    uint(2),
                    uint(3),
                ])
            })
            .collect(),
    );
    encode(&Value::Array(vec![
        bytes(b"CNT1"),
        uint(1),
        text(COMMUNITY_PLUGIN_WORLD_V1),
        text("plugin-a"),
        bytes(&[1; 32]),
        bytes(&[2; 32]),
        uint(0),
        uint(3),
        uint(0),
        uint(5),
        Value::Array(vec![text("alpha"), text("beta")]),
        caps,
        uint(mode),
        Value::Array(vec![
            uint(67_108_864),
            uint(1_000_000_000),
            uint(1_000_000),
            uint(1024),
            uint(16_777_216),
            uint(1_048_576),
            uint(64),
            uint(16_384),
        ]),
        bytes(&body),
        bytes(profile_digest.as_bytes()),
    ]))
}

#[test]
fn negotiated_tuple_has_exact_sixteen_fields_and_existing_profile_hash() -> TestResult {
    let profile = profile(Mode::Local)?;
    let negotiated = negotiated(&profile)?;
    let tuple = Tuple::new(&negotiated, &profile)?;
    let expected = expected(0)?;
    assert_eq!(&*tuple.to_canonical_cbor(), &expected);
    assert!(std::ptr::eq(tuple.negotiated(), &raw const negotiated));
    let mut preimage = b"PiglorOS.Community.CNT1.v1\0".to_vec();
    preimage.extend_from_slice(&expected);
    assert_eq!(
        tuple.digest(),
        Hash::from_bytes(*blake3::hash(&preimage).as_bytes())
    );
    assert_eq!(
        Tuple::validate_canonical_cbor(&expected, &negotiated, &profile)?.digest(),
        tuple.digest()
    );
    Ok(())
}

#[test]
fn mode_is_retained_even_when_execution_profile_hashes_equal() -> TestResult {
    let local = profile(Mode::Local)?;
    let air = profile(Mode::AirGapped)?;
    assert_eq!(local.digest(), air.digest());
    let local_negotiated = negotiated(&local)?;
    let air_negotiated = negotiated(&air)?;
    let local_tuple = Tuple::new(&local_negotiated, &local)?;
    let air_tuple = Tuple::new(&air_negotiated, &air)?;
    assert_ne!(local_tuple.digest(), air_tuple.digest());
    assert_eq!(&*air_tuple.to_canonical_cbor(), &expected(1)?);
    assert_eq!(
        Tuple::new(&local_negotiated, &air).err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}

#[test]
fn equivalent_runtime_order_reconstructs_same_canonical_tuple() -> TestResult {
    let profile = profile(Mode::Local)?;
    let negotiated = negotiated(&profile)?;
    let mut runtime_traps = traps();
    runtime_traps.reverse();
    let reordered = Runtime::new(
        "49.0.5".into(),
        vec!["a-feature".into(), "z-feature".into()],
        engine(),
        runtime_traps,
    )?;
    let reordered = Profile::new(Mode::Local, Ceilings::V1, Some(reordered));
    assert_eq!(profile.digest(), reordered.digest());
    assert_eq!(
        Tuple::new(&negotiated, &reordered)?.digest(),
        Tuple::new(&negotiated, &profile)?.digest()
    );
    Ok(())
}

#[test]
fn tuple_refuses_missing_foreign_profile_and_zero_release_identities() -> TestResult {
    let profile = profile(Mode::Local)?;
    let negotiated = negotiated(&profile)?;
    let missing = Profile::new(Mode::Local, Ceilings::V1, None);
    assert_eq!(
        Tuple::new(&negotiated, &missing).err(),
        Some(Error::InvalidBinding)
    );
    let foreign = Runtime::new("49.0.6".into(), vec![], engine(), vec![])?;
    let foreign = Profile::new(Mode::Local, Ceilings::V1, Some(foreign));
    assert_eq!(
        Tuple::new(&negotiated, &foreign).err(),
        Some(Error::InvalidBinding)
    );
    let ceilings = Ceilings::new(CeilingValuesV1 {
        fuel: 9,
        ..Ceilings::V1.values()
    })?;
    let changed = Profile::new(Mode::Local, ceilings, Some(runtime()?));
    assert_eq!(
        Tuple::new(&negotiated, &changed).err(),
        Some(Error::InvalidBinding)
    );
    for pmf in [true, false] {
        let mut transport = transport(&profile);
        if pmf {
            transport.pmf1_digest = [0; 32];
        } else {
            transport.release_digest = [0; 32];
        }
        let negotiated = rebuild(transport, &profile)?;
        assert_eq!(
            Tuple::new(&negotiated, &profile).err(),
            Some(Error::InvalidBinding)
        );
    }
    Ok(())
}

#[test]
fn tuple_bounds_version_and_resolved_feature_metadata_before_staging() -> TestResult {
    for (version, features, acceptable) in [
        ("v".repeat(64), vec!["f".repeat(128)], true),
        (String::new(), vec![], false),
        ("v".repeat(65), vec![], false),
        ("v".into(), vec![String::new()], false),
        ("v".into(), vec!["f".repeat(129)], false),
    ] {
        let runtime = Runtime::new(version, features, engine(), vec![])?;
        let profile = Profile::new(Mode::Local, Ceilings::V1, Some(runtime));
        let negotiated = negotiated(&profile)?;
        assert_eq!(Tuple::new(&negotiated, &profile).is_ok(), acceptable);
    }
    for count in [256, 257] {
        let features = (0..count).map(|index| format!("f{index:03}")).collect();
        let runtime = Runtime::new("v".into(), features, engine(), vec![])?;
        let profile = Profile::new(Mode::Local, Ceilings::V1, Some(runtime));
        let negotiated = negotiated(&profile)?;
        assert_eq!(Tuple::new(&negotiated, &profile).is_ok(), count == 256);
    }
    Ok(())
}

#[test]
fn tuple_bounds_trap_code_text_and_both_metadata_row_limits() -> TestResult {
    for code in [String::new(), "t".repeat(128), "t".repeat(129)] {
        let acceptable = code.len() == 128;
        let runtime = Runtime::new(
            "v".into(),
            vec![],
            engine(),
            vec![Trap {
                trap_code: code,
                outcome: TrapOutcomeV1::Trap(ComponentTrapClassV1::Other),
            }],
        )?;
        let profile = Profile::new(Mode::Local, Ceilings::V1, Some(runtime));
        let negotiated = negotiated(&profile)?;
        assert_eq!(Tuple::new(&negotiated, &profile).is_ok(), acceptable);
    }
    for count in [256, 257] {
        let traps = (0..count)
            .map(|index| Trap {
                trap_code: format!("Trap{index:03}"),
                outcome: TrapOutcomeV1::Trap(ComponentTrapClassV1::Other),
            })
            .collect();
        let runtime = Runtime::new("v".into(), vec![], engine(), traps)?;
        let profile = Profile::new(Mode::Local, Ceilings::V1, Some(runtime));
        let negotiated = negotiated(&profile)?;
        assert_eq!(Tuple::new(&negotiated, &profile).is_ok(), count == 256);
    }
    let profile = profile(Mode::Local)?;
    for count in [256, 257] {
        let mut transport = transport(&profile);
        transport.required_features = (0..count).map(|index| format!("f{index:03}")).collect();
        let negotiated = rebuild(transport, &profile)?;
        assert_eq!(Tuple::new(&negotiated, &profile).is_ok(), count == 256);
    }
    Ok(())
}

#[test]
fn tuple_rejects_unordered_duplicate_or_invalid_optional_capabilities() -> TestResult {
    let profile = profile(Mode::Local)?;
    let mut invalid = Vec::new();
    for (index, text) in [
        (0, "UpperCase"),
        (0, ""),
        (1, "bad operation"),
        (2, ""),
        (2, "bad\npattern"),
        (3, "bad\u{85}purpose"),
        (4, ""),
    ] {
        let mut cap = capability("a-cap");
        match index {
            0 => cap.capability_id = text.into(),
            1 => cap.operation = text.into(),
            2 => cap.resource_pattern = text.into(),
            3 => cap.purpose = text.into(),
            _ => cap.audience = text.into(),
        }
        invalid.push(cap);
    }
    for index in 0..5 {
        let mut cap = capability("a-cap");
        match index {
            0 => cap.capability_id = "a".repeat(129),
            1 => cap.operation = "a".repeat(129),
            2 => cap.resource_pattern = "a".repeat(513),
            3 => cap.purpose = "a".repeat(129),
            _ => cap.audience = "a".repeat(129),
        }
        invalid.push(cap);
    }
    for index in 0..3 {
        let mut cap = capability("a-cap");
        match index {
            0 => cap.max_calls = Budget::MAXIMA.host_calls + 1,
            1 => cap.max_request_bytes = Budget::MAXIMA.event_bytes + 1,
            _ => cap.max_response_bytes = Budget::MAXIMA.event_bytes + 1,
        }
        invalid.push(cap);
    }
    for cap in invalid {
        let mut transport = transport(&profile);
        transport.not_granted_capabilities = vec![cap];
        let negotiated = rebuild(transport, &profile)?;
        assert_eq!(
            Tuple::new(&negotiated, &profile).err(),
            Some(Error::BoundsExceeded)
        );
    }
    for caps in [
        vec![capability("z-cap"), capability("a-cap")],
        vec![capability("a-cap"), capability("a-cap")],
    ] {
        let mut transport = transport(&profile);
        transport.not_granted_capabilities = caps;
        let negotiated = rebuild(transport, &profile)?;
        assert_eq!(
            Tuple::new(&negotiated, &profile).err(),
            Some(Error::InvalidBinding)
        );
    }
    Ok(())
}

#[test]
fn tuple_preserves_maximum_allowed_capability_strings_and_counts() -> TestResult {
    let profile = profile(Mode::Local)?;
    let mut transport = transport(&profile);
    transport.not_granted_capabilities = (0..256)
        .map(|index| Capability {
            capability_id: format!("c{index:03}{}", "a".repeat(124)),
            operation: "o".repeat(128),
            resource_pattern: "p".repeat(512),
            purpose: "p".repeat(128),
            audience: "a".repeat(128),
            required: false,
            max_calls: Budget::MAXIMA.host_calls,
            max_request_bytes: Budget::MAXIMA.event_bytes,
            max_response_bytes: Budget::MAXIMA.event_bytes,
        })
        .collect();
    let negotiated = rebuild(transport, &profile)?;
    let tuple = Tuple::new(&negotiated, &profile)?;
    let encoded = tuple.to_canonical_cbor();
    assert!(encoded.len() < 1_048_576);
    assert_eq!(
        Tuple::validate_canonical_cbor(&encoded, &negotiated, &profile)?.digest(),
        tuple.digest()
    );
    Ok(())
}

#[test]
fn tuple_rejects_any_truncation_nonpreferred_field_or_default_substitution() -> TestResult {
    let profile = profile(Mode::Local)?;
    let negotiated = negotiated(&profile)?;
    let encoded = expected(0)?;
    for end in 0..encoded.len() {
        assert_eq!(
            Tuple::validate_canonical_cbor(&encoded[..end], &negotiated, &profile).err(),
            Some(Error::InvalidBinding)
        );
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        Tuple::validate_canonical_cbor(&trailing, &negotiated, &profile).err(),
        Some(Error::InvalidBinding)
    );
    let mut nonpreferred = encoded.clone();
    nonpreferred.splice(6..7, [0x18, 1]);
    assert_eq!(
        Tuple::validate_canonical_cbor(&nonpreferred, &negotiated, &profile).err(),
        Some(Error::InvalidBinding)
    );
    let mut other = encoded;
    other[6] = 2;
    assert_eq!(
        Tuple::validate_canonical_cbor(&other, &negotiated, &profile).err(),
        Some(Error::InvalidBinding)
    );
    assert_eq!(
        Tuple::validate_canonical_cbor(&vec![0; 1_048_577], &negotiated, &profile).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}
