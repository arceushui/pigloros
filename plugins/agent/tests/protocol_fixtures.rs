use pos_core::ids::{EntityId, PluginId, TimelineId};
use pos_plugin_agent::protocol::{
    ActionCatalogueV1, AgentActionV1, AgentDecisionError, AgentDecisionRequestV1,
    AgentProviderProvenanceV1, BoundedProviderBytes, DecisionNoActionCodeV1, DecisionRecordV1,
    DecisionResultV1, ProviderDecisionV1, ProviderFailureCode,
};
use std::fmt::Write as _;
use ulid::Ulid;

const CATALOGUE_HEX: &str = "8344504143310181646d6f7665";
const REQUEST_HEX: &str = concat!(
    "8d44505152310150",
    "000102030405060708090a0b0c0d0e0f",
    "182a50",
    "101112131415161718191a1b1c1d1e1f",
    "075820",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "50",
    "202122232425262728292a2b2c2d2e2f",
    "65312e302e305820",
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "676c6f63616c2d31",
    "6276315820",
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
);
const PDP_ACCEPTED_HEX: &str = "8544504450310100001a000f4240";
const PDP_NO_ACTION_HEX: &str = "8344504450310101";
const RECORD_ACCEPTED_HEX: &str = concat!(
    "9044504452310150",
    "000102030405060708090a0b0c0d0e0f",
    "182a50",
    "101112131415161718191a1b1c1d1e1f",
    "075820",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "50",
    "202122232425262728292a2b2c2d2e2f",
    "65312e302e305820",
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "676c6f63616c2d31",
    "6276315820",
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "5820",
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    "82015820",
    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    "8300001a000f4240",
);
const RECORD_NO_ACTION_HEX: &str = concat!(
    "9044504452310150",
    "000102030405060708090a0b0c0d0e0f",
    "182a50",
    "101112131415161718191a1b1c1d1e1f",
    "075820",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "50",
    "202122232425262728292a2b2c2d2e2f",
    "65312e302e305820",
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "676c6f63616c2d31",
    "6276315820",
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "5820",
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    "8100820105",
);
const ACTION_HEX: &str = concat!(
    "87445041413101646d6f76651a000f4240075820",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "5820",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
);

// These literals are derived by an independent fixture program using BLAKE3
// derive-key mode, then frozen here. They are intentionally not calculated by
// the protocol implementation or its helpers.
const CATALOGUE_HASH: [u8; 32] = [
    0x6c, 0xd4, 0x37, 0xe1, 0x5c, 0x0d, 0xac, 0x9e, 0x0f, 0x69, 0x0f, 0xdb, 0x0a, 0xd6, 0xf7, 0xfe,
    0x17, 0x6e, 0x03, 0x0b, 0xe5, 0x4f, 0x85, 0xe6, 0x8e, 0x59, 0x83, 0x03, 0xa3, 0x9f, 0x1d, 0xb8,
];
const REQUEST_HASH: [u8; 32] = [
    0x87, 0x31, 0xb2, 0x7e, 0xf5, 0x49, 0x85, 0x19, 0xe8, 0xac, 0xd1, 0xad, 0xb3, 0x1c, 0x95, 0xbb,
    0x7f, 0xb2, 0x05, 0x98, 0x9b, 0xc8, 0x8c, 0x92, 0x9b, 0xfb, 0xc9, 0x3b, 0xa2, 0xd4, 0x05, 0x40,
];
const RESPONSE_HASH: [u8; 32] = [
    0x56, 0x73, 0x53, 0x23, 0x01, 0x96, 0x75, 0x50, 0x8b, 0x95, 0xcb, 0x27, 0x90, 0x11, 0x50, 0x04,
    0x1b, 0x5a, 0x00, 0x06, 0xe8, 0x23, 0x90, 0x70, 0x2c, 0x89, 0x84, 0xfe, 0xf4, 0x41, 0xa0, 0xc8,
];
const RECORD_HASH: [u8; 32] = [
    0x1a, 0x65, 0xab, 0xbc, 0xa5, 0x5c, 0xdc, 0xe6, 0xcf, 0x02, 0x6e, 0x3c, 0x2a, 0x6b, 0x7c, 0xeb,
    0x2b, 0x4e, 0x61, 0x94, 0x58, 0x60, 0x7f, 0x93, 0x6c, 0xaa, 0xe3, 0x52, 0xef, 0xc8, 0xf3, 0xfe,
];

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "fixture hex has an odd length");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|digits| u8::from_str_radix(digits, 16).ok())
                .expect("fixture hex")
        })
        .collect()
}

fn encode_hex(value: &[u8]) -> String {
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn id(bytes: [u8; 16]) -> Ulid {
    Ulid::from(bytes)
}

fn provenance() -> AgentProviderProvenanceV1 {
    AgentProviderProvenanceV1::try_new(
        PluginId::from_ulid(id([
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
            0x2e, 0x2f,
        ])),
        "1.0.0".to_owned(),
        [0xbb; 32],
        "local-1".to_owned(),
        "v1".to_owned(),
        [0xcc; 32],
    )
    .expect("fixed provenance is valid")
}

fn request() -> AgentDecisionRequestV1 {
    AgentDecisionRequestV1::new(
        TimelineId::from_ulid(id([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])),
        42,
        EntityId::from_ulid(id([
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ])),
        7,
        [0xaa; 32],
        provenance(),
    )
}

#[test]
fn golden_codecs_and_domain_hashes_match_frozen_external_fixtures() {
    let catalogue = ActionCatalogueV1::try_new(vec!["move".to_owned()]).expect("valid catalogue");
    let request = request();
    let accepted = ProviderDecisionV1::accepted(0, 1_000_000).expect("valid accepted decision");
    let accepted_record = DecisionRecordV1::try_new(
        request.clone(),
        [0xdd; 32],
        Some([0xee; 32]),
        DecisionResultV1::from(accepted),
    )
    .expect("accepted record digest matrix");
    let no_action_record = DecisionRecordV1::try_new(
        request.clone(),
        [0xdd; 32],
        None,
        DecisionResultV1::NoAction(DecisionNoActionCodeV1::ProviderNoAction),
    )
    .expect("no-action record digest matrix");
    let action = AgentActionV1::try_new("move".to_owned(), 1_000_000, 7, [0xaa; 32], [0xff; 32])
        .expect("valid derived action");

    assert_eq!(
        encode_hex(&catalogue.encode().expect("catalogue encode")),
        CATALOGUE_HEX
    );
    assert_eq!(
        encode_hex(&request.encode().expect("request encode")),
        REQUEST_HEX
    );
    assert_eq!(
        encode_hex(&accepted.encode().expect("accepted encode")),
        PDP_ACCEPTED_HEX
    );
    assert_eq!(
        encode_hex(
            &ProviderDecisionV1::no_action()
                .encode()
                .expect("no-action encode")
        ),
        PDP_NO_ACTION_HEX
    );
    assert_eq!(
        encode_hex(&accepted_record.encode().expect("record encode")),
        RECORD_ACCEPTED_HEX
    );
    assert_eq!(
        encode_hex(&no_action_record.encode().expect("record encode")),
        RECORD_NO_ACTION_HEX
    );
    assert_eq!(
        encode_hex(&action.encode().expect("action encode")),
        ACTION_HEX
    );

    assert_eq!(catalogue.hash().expect("catalogue hash"), CATALOGUE_HASH);
    assert_eq!(request.hash().expect("request hash"), REQUEST_HASH);
    assert_eq!(
        ProviderDecisionV1::hash_response(&decode_hex(PDP_ACCEPTED_HEX)),
        RESPONSE_HASH
    );
    assert_eq!(accepted_record.hash().expect("record hash"), RECORD_HASH);

    assert_eq!(
        ActionCatalogueV1::decode(&decode_hex(CATALOGUE_HEX)).expect("catalogue decode"),
        catalogue
    );
    assert_eq!(
        AgentDecisionRequestV1::decode(&decode_hex(REQUEST_HEX)).expect("request decode"),
        request
    );
    assert_eq!(
        ProviderDecisionV1::decode(&decode_hex(PDP_ACCEPTED_HEX)).expect("accepted decode"),
        accepted
    );
    assert_eq!(
        ProviderDecisionV1::decode(&decode_hex(PDP_NO_ACTION_HEX)).expect("no-action decode"),
        ProviderDecisionV1::no_action()
    );
    assert_eq!(
        DecisionRecordV1::decode(&decode_hex(RECORD_ACCEPTED_HEX)).expect("record decode"),
        accepted_record
    );
    assert_eq!(
        DecisionRecordV1::decode(&decode_hex(RECORD_NO_ACTION_HEX)).expect("record decode"),
        no_action_record
    );
    assert_eq!(
        AgentActionV1::decode(&decode_hex(ACTION_HEX)).expect("action decode"),
        action
    );
}

#[test]
fn public_decoders_reject_trailing_bytes_after_an_empty_array() {
    let wire = [0x80, 0x00];
    assert_malformed(
        ActionCatalogueV1::decode(&wire),
        "catalogue trailing empty array",
    );
    assert_malformed(
        AgentDecisionRequestV1::decode(&wire),
        "request trailing empty array",
    );
    assert_malformed(
        ProviderDecisionV1::decode(&wire),
        "provider trailing empty array",
    );
    assert_malformed(
        DecisionRecordV1::decode(&wire),
        "record trailing empty array",
    );
    assert_malformed(AgentActionV1::decode(&wire), "action trailing empty array");
}

#[test]
fn validated_protocol_values_expose_their_bounded_host_owned_fields() {
    let catalogue = ActionCatalogueV1::try_new(vec!["move".to_owned()]).expect("catalogue");
    assert_eq!(catalogue.action(0), Some("move"));
    assert_eq!(catalogue.action(1), None);
    assert_eq!(catalogue.len(), 1);
    assert!(!catalogue.is_empty());

    let provenance = provenance();
    assert_eq!(
        provenance.plugin_id(),
        PluginId::from_ulid(id([
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
            0x2e, 0x2f,
        ]))
    );
    assert_eq!(provenance.plugin_version(), "1.0.0");
    assert_eq!(provenance.plugin_content_hash(), [0xbb; 32]);
    assert_eq!(provenance.provider_id(), "local-1");
    assert_eq!(provenance.provider_version(), "v1");
    assert_eq!(provenance.provider_content_hash(), [0xcc; 32]);

    let request = request();
    assert_eq!(
        request.timeline_id(),
        TimelineId::from_ulid(id([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]))
    );
    assert_eq!(request.observed_through(), 42);
    assert_eq!(
        request.agent_id(),
        EntityId::from_ulid(id([
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ]))
    );
    assert_eq!(request.driver_tick(), 7);
    assert_eq!(request.catalogue_hash(), [0xaa; 32]);
    assert_eq!(request.provenance(), &provenance);

    let response = BoundedProviderBytes::try_from(vec![1, 2]).expect("bounded response");
    assert_eq!(response.as_slice(), &[1, 2]);

    let decision = ProviderDecisionV1::accepted(3, 4).expect("accepted decision");
    assert_eq!(
        ProviderDecisionV1::no_action(),
        ProviderDecisionV1::NoAction
    );
    assert_eq!(
        DecisionResultV1::from(ProviderDecisionV1::no_action()),
        DecisionResultV1::NoAction(DecisionNoActionCodeV1::ProviderNoAction)
    );
    for (failure, code) in [
        (ProviderFailureCode::Unavailable, 1),
        (ProviderFailureCode::Timeout, 2),
        (ProviderFailureCode::Rejected, 3),
        (ProviderFailureCode::RateLimited, 4),
    ] {
        assert_eq!(failure.code(), code);
        assert_eq!(DecisionNoActionCodeV1::from(failure).code(), code);
    }

    let record = DecisionRecordV1::try_new(
        request.clone(),
        [0xdd; 32],
        Some([0xee; 32]),
        decision.into(),
    )
    .expect("accepted record digest matrix");
    assert_eq!(record.request(), &request);
    assert_eq!(record.request_hash(), [0xdd; 32]);
    assert_eq!(record.response_digest(), Some([0xee; 32]));
    assert_eq!(
        record.result(),
        DecisionResultV1::Accepted {
            action_index: pos_plugin_agent::protocol::ActionIndexV1::try_from(3).expect("index"),
            confidence: pos_plugin_agent::protocol::ConfidencePpmV1::try_from(4)
                .expect("confidence"),
        }
    );

    let action =
        AgentActionV1::try_new("move".to_owned(), 4, 7, [0xaa; 32], [0xff; 32]).expect("action");
    assert_eq!(action.action_id(), "move");
    assert_eq!(action.confidence().get(), 4);
    assert_eq!(action.driver_tick(), 7);
    assert_eq!(action.catalogue_hash(), [0xaa; 32]);
    assert_eq!(action.decision_record_hash(), [0xff; 32]);
}

#[test]
fn catalogue_constructor_enforces_the_exact_pac1_encoded_size_boundary() {
    let mut accepted_lengths = vec![64; 64];
    accepted_lengths[..3].copy_from_slice(&[24; 3]);
    accepted_lengths[3] = 47;
    let accepted = ActionCatalogueV1::try_new(catalogue_ids(&accepted_lengths))
        .expect("4,096-byte PAC1 catalogue");
    assert_eq!(accepted.encode().expect("accepted PAC1").len(), 4096);

    let mut rejected_lengths = accepted_lengths;
    rejected_lengths[3] = 48;
    assert_eq!(
        ActionCatalogueV1::try_new(catalogue_ids(&rejected_lengths)),
        Err(AgentDecisionError::MalformedWire)
    );
}

#[test]
fn provider_decision_prioritises_readable_non_v1_versions_before_trailing_or_shape() {
    for wire in ["8344504450310200f6", "85445044503102a0a0a0"] {
        assert_eq!(
            ProviderDecisionV1::decode(&decode_hex(wire)),
            Err(AgentDecisionError::UnsupportedWireVersion),
            "{wire}"
        );
    }
}

#[test]
fn provider_decision_rejects_noncanonical_values_before_range_validation() {
    for wire in [
        "854450445031010019004000",
        "8544504450310100001b00000000000f4241",
    ] {
        assert_eq!(
            ProviderDecisionV1::decode(&decode_hex(wire)),
            Err(AgentDecisionError::MalformedWire),
            "{wire}"
        );
    }

    for (wire, error) in [
        (
            "8544504450310100184000",
            AgentDecisionError::InvalidActionIndex,
        ),
        (
            "8544504450310100001a000f4241",
            AgentDecisionError::InvalidConfidence,
        ),
    ] {
        assert_eq!(
            ProviderDecisionV1::decode(&decode_hex(wire)),
            Err(error),
            "{wire}"
        );
    }
}

#[test]
fn exact_encoders_use_shortest_integer_widths() {
    let decision = ProviderDecisionV1::accepted(24, 500).expect("in-range decision");
    assert_eq!(
        encode_hex(&decision.encode().expect("encode decision")),
        "854450445031010018181901f4"
    );
    assert_eq!(
        ProviderDecisionV1::decode(&decode_hex("854450445031010018181901f4")),
        Ok(decision)
    );
}

#[test]
fn catalogue_decoder_has_a_field_specific_malformed_matrix() {
    let canonical = decode_hex(CATALOGUE_HEX);
    let mut wrong_magic_type = canonical.clone();
    wrong_magic_type[1] = 0x64;
    let mut wrong_magic = canonical.clone();
    wrong_magic[2] = b'X';
    let mut wrong_entry_type = canonical.clone();
    wrong_entry_type[8] = 0x44;
    let mut control_identifier = canonical.clone();
    replace_once(&mut control_identifier, b"move", b"m\0ve");
    let over_limit = oversized_catalogue_wire();

    for (name, wire) in [
        ("empty", Vec::new()),
        ("truncated", canonical[..canonical.len() - 1].to_vec()),
        ("trailing", append(&canonical, 0)),
        ("missing outer item", decode_hex("82445041433101")),
        ("extra outer item", extra_outer_item(&canonical, 0x84)),
        ("magic type", wrong_magic_type),
        ("magic value", wrong_magic),
        ("magic width", decode_hex("834550414331000181646d6f7665")),
        ("version", decode_hex("8344504143310281646d6f7665")),
        (
            "nonshortest version",
            decode_hex("834450414331180181646d6f7665"),
        ),
        ("entry type", wrong_entry_type),
        ("action collection type", decode_hex("8344504143310100")),
        ("control identifier", control_identifier),
        (
            "invalid UTF-8 action identifier",
            replace_once_with(&canonical, &decode_hex("646d6f7665"), &decode_hex("62c328")),
        ),
        ("zero action count", decode_hex("8344504143310180")),
        ("too many actions", too_many_catalogue_actions()),
        (
            "indefinite nested array",
            decode_hex("834450414331019f646d6f7665ff"),
        ),
        ("over limit nested catalogue", over_limit),
    ] {
        assert_malformed(ActionCatalogueV1::decode(&wire), name);
    }

    for (name, wire) in foreign_root_wires() {
        assert_malformed(ActionCatalogueV1::decode(&wire), name);
    }
}

#[test]
fn request_decoder_has_a_field_specific_malformed_matrix() {
    let canonical = decode_hex(REQUEST_HEX);
    let mut wrong_magic_type = canonical.clone();
    wrong_magic_type[1] = 0x64;
    let mut wrong_magic = canonical.clone();
    wrong_magic[2] = b'X';
    let timeline = decode_hex("50000102030405060708090a0b0c0d0e0f");
    let wrong_timeline_type = replace_once_with(&canonical, &timeline, &text_bytes(16, b'a'));
    let wrong_timeline_width = replace_once_with(&canonical, &timeline, &timeline[..16]);
    let plugin_id = decode_hex("50202122232425262728292a2b2c2d2e2f");
    let wrong_plugin_type = replace_once_with(&canonical, &plugin_id, &text_bytes(16, b'a'));
    let invalid_provider_id = replace_once_with(&canonical, b"local-1", b"Local-1");
    let nonshortest_observed = replace_once_with(&canonical, &[0x18, 0x2a], &[0x19, 0, 0x2a]);

    for (name, wire) in [
        ("empty", Vec::new()),
        ("truncated", canonical[..canonical.len() - 1].to_vec()),
        ("trailing", append(&canonical, 0)),
        (
            "missing outer item",
            missing_outer_item(&canonical, 0x8c, 34),
        ),
        ("extra outer item", extra_outer_item(&canonical, 0x8e)),
        ("magic type", wrong_magic_type),
        ("magic value", wrong_magic),
        (
            "version",
            replace_once_with(&canonical, &[1, 0x50], &[2, 0x50]),
        ),
        ("nonshortest observed through", nonshortest_observed),
        ("timeline type", wrong_timeline_type),
        ("timeline width", wrong_timeline_width),
        ("plugin identifier type", wrong_plugin_type),
        ("provider identifier grammar", invalid_provider_id),
        ("over limit", vec![0; 4097]),
    ] {
        assert_malformed(AgentDecisionRequestV1::decode(&wire), name);
    }

    for (name, wire) in foreign_root_wires() {
        assert_malformed(AgentDecisionRequestV1::decode(&wire), name);
    }
}

#[test]
fn request_decoder_reaches_every_agent_and_provenance_field() {
    let canonical = decode_hex(REQUEST_HEX);
    let agent_id = decode_hex("50101112131415161718191a1b1c1d1e1f");
    let catalogue_hash = bytes_of(32, 0xaa);
    let plugin_content_hash = bytes_of(32, 0xbb);
    let provider_content_hash = bytes_of(32, 0xcc);
    let plugin_version = decode_hex("65312e302e30");
    let provider_version = decode_hex("627631");
    let invalid_utf8 = decode_hex("62c328");

    for (name, wire) in [
        (
            "agent identifier type",
            replace_once_with(&canonical, &agent_id, &text_bytes(16, b'a')),
        ),
        (
            "agent identifier width",
            replace_once_with(&canonical, &agent_id, &bytes_of(15, 0x10)),
        ),
        (
            "driver tick type",
            replace_once_with(&canonical, &[7, 0x58, 0x20], &[0x40, 0x58, 0x20]),
        ),
        (
            "driver tick nonshortest",
            replace_once_with(&canonical, &[7, 0x58, 0x20], &[0x18, 7, 0x58, 0x20]),
        ),
        (
            "catalogue hash type",
            replace_once_with(&canonical, &catalogue_hash, &text_bytes(32, b'a')),
        ),
        (
            "catalogue hash width",
            replace_once_with(&canonical, &catalogue_hash, &bytes_of(31, 0xaa)),
        ),
        (
            "plugin content hash type",
            replace_once_with(&canonical, &plugin_content_hash, &text_bytes(32, b'a')),
        ),
        (
            "plugin content hash width",
            replace_once_with(&canonical, &plugin_content_hash, &bytes_of(31, 0xbb)),
        ),
        (
            "provider content hash type",
            replace_once_with(&canonical, &provider_content_hash, &text_bytes(32, b'a')),
        ),
        (
            "provider content hash width",
            replace_once_with(&canonical, &provider_content_hash, &bytes_of(31, 0xcc)),
        ),
        (
            "plugin version grammar",
            replace_once_with(&canonical, &plugin_version, &decode_hex("6120")),
        ),
        (
            "plugin version length",
            replace_once_with(&canonical, &plugin_version, &text_bytes(33, b'a')),
        ),
        (
            "plugin version primitive",
            replace_once_with(&canonical, &plugin_version, &bytes_of(5, b'a')),
        ),
        (
            "plugin version invalid UTF-8",
            replace_once_with(&canonical, &plugin_version, &invalid_utf8),
        ),
        (
            "provider version grammar",
            replace_once_with(&canonical, &provider_version, &decode_hex("6120")),
        ),
        (
            "provider version length",
            replace_once_with(&canonical, &provider_version, &text_bytes(65, b'a')),
        ),
        (
            "provider version primitive",
            replace_once_with(&canonical, &provider_version, &bytes_of(2, b'a')),
        ),
        (
            "provider version invalid UTF-8",
            replace_once_with(&canonical, &provider_version, &invalid_utf8),
        ),
        (
            "provider identifier invalid UTF-8",
            replace_once_with(&canonical, &decode_hex("676c6f63616c2d31"), &invalid_utf8),
        ),
    ] {
        assert_malformed(AgentDecisionRequestV1::decode(&wire), name);
    }
}

#[test]
fn provider_decoder_has_a_field_specific_malformed_matrix() {
    let canonical = decode_hex(PDP_ACCEPTED_HEX);
    let mut wrong_magic_type = canonical.clone();
    wrong_magic_type[1] = 0x64;
    let mut wrong_magic = canonical.clone();
    wrong_magic[2] = b'X';
    let wrong_kind_type = decode_hex("8544504450310140001a000f4240");

    for (name, wire) in [
        ("empty", Vec::new()),
        ("truncated", canonical[..canonical.len() - 1].to_vec()),
        ("trailing", append(&canonical, 0)),
        (
            "missing outer item",
            missing_outer_item(&canonical, 0x84, 5),
        ),
        ("extra outer item", extra_outer_item(&canonical, 0x86)),
        ("magic type", wrong_magic_type),
        ("magic value", wrong_magic),
        ("version type", decode_hex("854450445031a000001a000f4240")),
        (
            "nonshortest version",
            decode_hex("854450445031180100001a000f4240"),
        ),
        ("kind type", wrong_kind_type),
        ("action index width", decode_hex("854450445031010019010000")),
        ("confidence type", decode_hex("85445044503101000040")),
        (
            "confidence width",
            decode_hex("8544504450310100001b0000000100000000"),
        ),
        ("invalid kind", decode_hex("8344504450310102")),
        ("over limit", vec![0; 4097]),
    ] {
        assert_malformed(ProviderDecisionV1::decode(&wire), name);
    }

    for (name, wire) in foreign_root_wires() {
        assert_malformed(ProviderDecisionV1::decode(&wire), name);
    }
}

#[test]
fn record_decoder_has_a_field_specific_malformed_matrix() {
    let canonical = decode_hex(RECORD_ACCEPTED_HEX);
    let mut wrong_magic_type = canonical.clone();
    wrong_magic_type[1] = 0x64;
    let mut wrong_magic = canonical.clone();
    wrong_magic[2] = b'X';
    let request_hash = decode_hex(concat!(
        "5820",
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    ));
    let wrong_hash_type = replace_once_with(&canonical, &request_hash, &text_bytes(32, b'a'));
    let wrong_hash_width = replace_once_with(&canonical, &request_hash, &bytes_of(31, 0xdd));
    let wrong_request_field = replace_once_with(
        &canonical,
        &decode_hex("50000102030405060708090a0b0c0d0e0f"),
        &text_bytes(16, b'a'),
    );
    let wrong_result_type = replace_once_with(&canonical, &decode_hex("8300001a000f4240"), &[0]);

    for (name, wire) in [
        ("empty", Vec::new()),
        ("truncated", canonical[..canonical.len() - 1].to_vec()),
        ("trailing", append(&canonical, 0)),
        (
            "missing outer item",
            missing_outer_item(&canonical, 0x8f, 8),
        ),
        ("extra outer item", extra_outer_item(&canonical, 0x91)),
        ("magic type", wrong_magic_type),
        ("magic value", wrong_magic),
        (
            "version",
            replace_once_with(&canonical, &[1, 0x50], &[2, 0x50]),
        ),
        (
            "nonshortest version",
            replace_once_with(&canonical, &[1, 0x50], &[0x18, 1, 0x50]),
        ),
        ("request hash type", wrong_hash_type),
        ("request hash width", wrong_hash_width),
        ("nested request field type", wrong_request_field),
        ("result type", wrong_result_type),
        ("over limit", vec![0; 4097]),
    ] {
        assert_malformed(DecisionRecordV1::decode(&wire), name);
    }

    for (name, wire) in foreign_root_wires() {
        assert_malformed(DecisionRecordV1::decode(&wire), name);
    }
}

#[test]
fn record_decoder_reaches_every_response_digest_branch() {
    let digest = bytes_of(32, 0xee);
    let invalid_utf8 = decode_hex("62c328");

    for (name, wire) in [
        ("digest container scalar", record_with_digest(&[0])),
        (
            "present digest wrong width",
            record_with_digest(&concatenate(&[&[0x82, 1], &bytes_of(31, 0xee)])),
        ),
        (
            "present digest wrong type",
            record_with_digest(&concatenate(&[&[0x82, 1], &text_bytes(32, b'a')])),
        ),
        (
            "present digest discriminator",
            record_with_digest(&concatenate(&[&[0x82, 2], &digest])),
        ),
        ("absent digest under arity", record_with_digest(&[0x80])),
        (
            "absent digest over arity",
            record_with_digest(&[0x82, 0, 0]),
        ),
        ("present digest under arity", record_with_digest(&[0x81, 1])),
        (
            "present digest over arity",
            record_with_digest(&concatenate(&[&[0x83, 1], &digest, &[0]])),
        ),
        (
            "nested request invalid UTF-8",
            replace_once_with(
                &decode_hex(RECORD_ACCEPTED_HEX),
                &decode_hex("65312e302e30"),
                &invalid_utf8,
            ),
        ),
    ] {
        assert_malformed(DecisionRecordV1::decode(&wire), name);
    }
}

#[test]
fn record_decoder_reaches_every_result_branch() {
    for (name, wire) in [
        (
            "accepted under arity",
            record_with_result(&decode_hex("820000")),
        ),
        (
            "accepted over arity",
            record_with_result(&decode_hex("8400001a000f424000")),
        ),
        (
            "accepted index range",
            record_with_result(&decode_hex("830018401a000f4240")),
        ),
        (
            "accepted confidence range",
            record_with_result(&decode_hex("8300001a000f4241")),
        ),
        (
            "accepted index type",
            record_with_result(&decode_hex("8300f401")),
        ),
        (
            "accepted confidence type",
            record_with_result(&decode_hex("830000f4")),
        ),
        (
            "accepted index over width",
            record_with_result(&decode_hex("830019010001")),
        ),
        (
            "accepted confidence over width",
            record_with_result(&decode_hex("8300001b0000000100000000")),
        ),
        (
            "accepted index nonshortest",
            record_with_result(&decode_hex("8300180001")),
        ),
        (
            "accepted confidence nonshortest",
            record_with_result(&decode_hex("8300001b00000000000f4240")),
        ),
        (
            "no-action under arity",
            record_with_no_action_result(&decode_hex("8101")),
        ),
        (
            "no-action over arity",
            record_with_no_action_result(&decode_hex("83010500")),
        ),
    ] {
        assert_malformed(DecisionRecordV1::decode(&wire), name);
    }
}

#[test]
fn record_decoder_accepts_each_no_action_code_and_rejects_other_result_values() {
    for code in no_action_codes() {
        let wire = record_no_action_wire(code.code());
        let decoded = DecisionRecordV1::decode(&wire).expect("authoritative no-action record");
        assert_eq!(
            decoded.result(),
            DecisionResultV1::NoAction(code),
            "{code:?}"
        );
    }

    for code in [0, 10] {
        assert_malformed(
            DecisionRecordV1::decode(&record_no_action_wire(code)),
            "unknown code",
        );
    }

    let nonshortest_code = replace_once_with(
        &decode_hex(RECORD_NO_ACTION_HEX),
        &[0x82, 1, 5],
        &[0x82, 1, 0x18, 5],
    );
    assert_malformed(
        DecisionRecordV1::decode(&nonshortest_code),
        "nonshortest no-action code",
    );
    let no_action_code_type = replace_once_with(
        &decode_hex(RECORD_NO_ACTION_HEX),
        &[0x82, 1, 5],
        &[0x82, 1, 0x40],
    );
    assert_malformed(
        DecisionRecordV1::decode(&no_action_code_type),
        "no-action code type",
    );
}

#[test]
fn action_decoder_has_a_field_specific_malformed_matrix() {
    let canonical = decode_hex(ACTION_HEX);
    let mut wrong_magic_type = canonical.clone();
    wrong_magic_type[1] = 0x64;
    let mut wrong_magic = canonical.clone();
    wrong_magic[2] = b'X';
    let wrong_hash_width = replace_once_with(
        &canonical,
        &decode_hex(concat!(
            "5820",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        )),
        &bytes_of(31, 0xff),
    );
    let invalid_identifier = replace_once_with(&canonical, b"move", b"m\0ve");
    let invalid_utf8_identifier =
        replace_once_with(&canonical, &decode_hex("646d6f7665"), &decode_hex("62c328"));
    let invalid_confidence = replace_once_with(
        &canonical,
        &[0x1a, 0, 0x0f, 0x42, 0x40],
        &[0x1a, 0, 0x0f, 0x42, 0x41],
    );
    let wrong_confidence_type =
        replace_once_with(&canonical, &[0x1a, 0, 0x0f, 0x42, 0x40], &[0x40]);
    let wrong_driver_tick_type = replace_once_with(&canonical, &[7, 0x58], &[0x40, 0x58]);
    let wrong_hash_type = replace_once_with(
        &canonical,
        &decode_hex(concat!(
            "5820",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )),
        &text_bytes(32, b'a'),
    );

    for (name, wire) in [
        ("empty", Vec::new()),
        ("truncated", canonical[..canonical.len() - 1].to_vec()),
        ("trailing", append(&canonical, 0)),
        (
            "missing outer item",
            missing_outer_item(&canonical, 0x86, 34),
        ),
        ("extra outer item", extra_outer_item(&canonical, 0x88)),
        ("magic type", wrong_magic_type),
        ("magic value", wrong_magic),
        (
            "version",
            replace_once_with(&canonical, &[1, 0x64], &[2, 0x64]),
        ),
        (
            "nonshortest version",
            replace_once_with(&canonical, &[1, 0x64], &[0x18, 1, 0x64]),
        ),
        (
            "action identifier type",
            replace_once_with(&canonical, &[0x64], &[0x44]),
        ),
        ("action identifier grammar", invalid_identifier),
        ("action identifier invalid UTF-8", invalid_utf8_identifier),
        ("confidence type", wrong_confidence_type),
        ("confidence range", invalid_confidence),
        ("driver tick type", wrong_driver_tick_type),
        (
            "driver tick canonicality",
            replace_once_with(&canonical, &[7, 0x58], &[0x18, 7, 0x58]),
        ),
        ("hash width", wrong_hash_width),
        ("hash type", wrong_hash_type),
        ("over limit", vec![0; 513]),
    ] {
        assert_malformed(AgentActionV1::decode(&wire), name);
    }

    for (name, wire) in foreign_root_wires() {
        assert_malformed(AgentActionV1::decode(&wire), name);
    }
}

#[test]
fn exact_writers_cover_all_integer_widths_and_no_action_assignments() {
    let action = AgentActionV1::try_new("move".to_owned(), 1, u64::MAX, [0; 32], [1; 32])
        .expect("valid max tick action");
    assert_eq!(
        AgentActionV1::decode(&action.encode().expect("max tick encode")),
        Ok(action)
    );

    for code in no_action_codes() {
        let response_digest = match code {
            DecisionNoActionCodeV1::ResponseMalformed
            | DecisionNoActionCodeV1::ResponseVersionUnsupported
            | DecisionNoActionCodeV1::ResponseValueInvalid => Some([0xee; 32]),
            _ => None,
        };
        let record = DecisionRecordV1::try_new(
            request(),
            [0xdd; 32],
            response_digest,
            DecisionResultV1::NoAction(code),
        )
        .expect("valid no-action digest matrix");
        let encoded = record.encode().expect("no-action record encode");
        assert_eq!(encoded.last().copied(), Some(code.code()));
    }
}

fn replace_once(bytes: &mut [u8], needle: &[u8], replacement: &[u8]) {
    assert_eq!(needle.len(), replacement.len(), "fixture replacement width");
    let start = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("fixture marker exists");
    bytes[start..start + replacement.len()].copy_from_slice(replacement);
}

fn catalogue_ids(lengths: &[usize]) -> Vec<String> {
    lengths
        .iter()
        .enumerate()
        .map(|(index, length)| format!("{index:02}{}", "x".repeat(length - 2)))
        .collect()
}

fn append(bytes: &[u8], byte: u8) -> Vec<u8> {
    let mut result = bytes.to_vec();
    result.push(byte);
    result
}

fn concatenate(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

fn missing_outer_item(bytes: &[u8], outer_header: u8, final_item_bytes: usize) -> Vec<u8> {
    let mut result = bytes.to_vec();
    result[0] = outer_header;
    result.truncate(result.len() - final_item_bytes);
    result
}

fn extra_outer_item(bytes: &[u8], outer_header: u8) -> Vec<u8> {
    let mut result = bytes.to_vec();
    result[0] = outer_header;
    result.push(0);
    result
}

fn text_bytes(length: usize, byte: u8) -> Vec<u8> {
    let mut result = if length <= 23 {
        vec![0x60 | u8::try_from(length).expect("short test text")]
    } else {
        vec![0x78, u8::try_from(length).expect("one-byte test text")]
    };
    result.extend(std::iter::repeat_n(byte, length));
    result
}

fn bytes_of(length: usize, byte: u8) -> Vec<u8> {
    let mut result = vec![0x58, u8::try_from(length).expect("short test bytes")];
    result.extend(std::iter::repeat_n(byte, length));
    result
}

fn replace_once_with(bytes: &[u8], needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    let start = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("fixture marker exists");
    let mut replaced = Vec::with_capacity(bytes.len() - needle.len() + replacement.len());
    replaced.extend_from_slice(&bytes[..start]);
    replaced.extend_from_slice(replacement);
    replaced.extend_from_slice(&bytes[start + needle.len()..]);
    replaced
}

fn foreign_root_wires() -> Vec<(&'static str, Vec<u8>)> {
    [
        ("map", "a0"),
        ("tag", "c0f6"),
        ("float", "f90000"),
        ("indefinite array", "9fff"),
        ("indefinite text", "7f6161ff"),
        ("indefinite bytes", "5f4100ff"),
    ]
    .into_iter()
    .map(|(name, wire)| (name, decode_hex(wire)))
    .collect()
}

fn oversized_catalogue_wire() -> Vec<u8> {
    let mut wire = vec![0x83, 0x44, b'P', b'A', b'C', b'1', 1, 0x98, 0x40];
    for _ in 0..64 {
        wire.extend([0x58, 0x40]);
        wire.extend(std::iter::repeat_n(b'a', 64));
    }
    wire
}

fn too_many_catalogue_actions() -> Vec<u8> {
    let mut wire = vec![0x83, 0x44, b'P', b'A', b'C', b'1', 1, 0x98, 0x41];
    for _ in 0..65 {
        wire.extend([0x61, b'a']);
    }
    wire
}

fn no_action_codes() -> [DecisionNoActionCodeV1; 9] {
    [
        DecisionNoActionCodeV1::ProviderUnavailable,
        DecisionNoActionCodeV1::ProviderTimeout,
        DecisionNoActionCodeV1::ProviderRejected,
        DecisionNoActionCodeV1::ProviderRateLimited,
        DecisionNoActionCodeV1::ProviderNoAction,
        DecisionNoActionCodeV1::ResponseTooLarge,
        DecisionNoActionCodeV1::ResponseMalformed,
        DecisionNoActionCodeV1::ResponseVersionUnsupported,
        DecisionNoActionCodeV1::ResponseValueInvalid,
    ]
}

fn record_no_action_wire(code: u8) -> Vec<u8> {
    if let 7..=9 = code {
        replace_once_with(
            &decode_hex(RECORD_ACCEPTED_HEX),
            &decode_hex("8300001a000f4240"),
            &[0x82, 1, code],
        )
    } else {
        let mut wire = decode_hex(RECORD_NO_ACTION_HEX);
        *wire.last_mut().expect("record fixture has a result code") = code;
        wire
    }
}

fn record_with_digest(digest: &[u8]) -> Vec<u8> {
    replace_once_with(
        &decode_hex(RECORD_ACCEPTED_HEX),
        &decode_hex(concat!(
            "82015820",
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        )),
        digest,
    )
}

fn record_with_result(result: &[u8]) -> Vec<u8> {
    replace_once_with(
        &decode_hex(RECORD_ACCEPTED_HEX),
        &decode_hex("8300001a000f4240"),
        result,
    )
}

fn record_with_no_action_result(result: &[u8]) -> Vec<u8> {
    replace_once_with(
        &decode_hex(RECORD_NO_ACTION_HEX),
        &decode_hex("820105"),
        result,
    )
}

fn assert_malformed<T>(result: Result<T, AgentDecisionError>, context: &str) {
    assert_eq!(
        result.err(),
        Some(AgentDecisionError::MalformedWire),
        "{context}"
    );
}
