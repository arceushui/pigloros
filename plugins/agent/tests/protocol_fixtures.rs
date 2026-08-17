use pos_core::ids::{EntityId, PluginId, TimelineId};
use pos_plugin_agent::protocol::{
    ActionCatalogueV1, AgentActionV1, AgentDecisionError, AgentDecisionRequestV1,
    AgentProviderProvenanceV1, DecisionNoActionCodeV1, DecisionRecordV1, DecisionResultV1,
    ProviderDecisionV1,
};
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
    value.iter().map(|byte| format!("{byte:02x}")).collect()
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
    let accepted_record = DecisionRecordV1::new(
        request.clone(),
        [0xdd; 32],
        Some([0xee; 32]),
        DecisionResultV1::from(accepted),
    );
    let no_action_record = DecisionRecordV1::new(
        request.clone(),
        [0xdd; 32],
        None,
        DecisionResultV1::NoAction(DecisionNoActionCodeV1::ProviderNoAction),
    );
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
fn decoders_reject_noncanonical_and_foreign_wire_values() {
    let foreign_values = [
        "a0",       // map
        "c0f6",     // tag
        "f90000",   // float
        "9fff",     // indefinite array
        "7f6161ff", // indefinite text
        "5f4100ff", // indefinite bytes
    ];

    for wire in foreign_values {
        let bytes = decode_hex(wire);
        assert_eq!(
            ActionCatalogueV1::decode(&bytes),
            Err(AgentDecisionError::MalformedWire),
            "catalogue {wire}"
        );
        assert_eq!(
            AgentDecisionRequestV1::decode(&bytes),
            Err(AgentDecisionError::MalformedWire),
            "request {wire}"
        );
        assert_eq!(
            ProviderDecisionV1::decode(&bytes),
            Err(AgentDecisionError::MalformedWire),
            "response {wire}"
        );
        assert_eq!(
            DecisionRecordV1::decode(&bytes),
            Err(AgentDecisionError::MalformedWire),
            "record {wire}"
        );
        assert_eq!(
            AgentActionV1::decode(&bytes),
            Err(AgentDecisionError::MalformedWire),
            "action {wire}"
        );
    }

    let mut trailing = decode_hex(PDP_NO_ACTION_HEX);
    trailing.push(0);
    assert_eq!(
        ProviderDecisionV1::decode(&trailing),
        Err(AgentDecisionError::MalformedWire)
    );
    assert_eq!(
        ProviderDecisionV1::decode(&decode_hex("834450445031180101")),
        Err(AgentDecisionError::MalformedWire)
    );
    assert_eq!(
        ProviderDecisionV1::decode(&decode_hex("82445044503101")),
        Err(AgentDecisionError::MalformedWire)
    );
    assert_eq!(
        ProviderDecisionV1::decode(&decode_hex("8344504450310102")),
        Err(AgentDecisionError::MalformedWire)
    );
    assert_eq!(
        ProviderDecisionV1::decode(&decode_hex("8544504450310100184000")),
        Err(AgentDecisionError::InvalidActionIndex)
    );
    assert_eq!(
        ProviderDecisionV1::decode(&decode_hex("8544504450310100001a000f4241")),
        Err(AgentDecisionError::InvalidConfidence)
    );

    // The version is structurally readable before V1 field validation, so it
    // takes precedence even though the final field is the wrong primitive.
    assert_eq!(
        ProviderDecisionV1::decode(&decode_hex("85445044503102a0a0a0")),
        Err(AgentDecisionError::UnsupportedWireVersion)
    );

    assert_eq!(
        ActionCatalogueV1::decode(&decode_hex("8344504143310181656d6f766500")),
        Err(AgentDecisionError::MalformedWire)
    );
    assert_eq!(
        ActionCatalogueV1::decode(&decode_hex("834450414331018161ff")),
        Err(AgentDecisionError::MalformedWire)
    );

    let mut wrong_request_id_width = decode_hex(REQUEST_HEX);
    wrong_request_id_width[6] = 0x4f;
    assert_eq!(
        AgentDecisionRequestV1::decode(&wrong_request_id_width),
        Err(AgentDecisionError::MalformedWire)
    );

    let mut oversized_catalogue = vec![0x83, 0x44, b'P', b'A', b'C', b'1', 0x01, 0x98, 0x40];
    for _ in 0..64 {
        oversized_catalogue.push(0x58);
        oversized_catalogue.push(0x40);
        oversized_catalogue.extend(std::iter::repeat_n(b'a', 64));
    }
    assert!(oversized_catalogue.len() > 4096);
    assert_eq!(
        ActionCatalogueV1::decode(&oversized_catalogue),
        Err(AgentDecisionError::MalformedWire)
    );

    let over_limit = vec![0; 4097];
    assert_eq!(
        ActionCatalogueV1::decode(&over_limit),
        Err(AgentDecisionError::MalformedWire)
    );
    assert_eq!(
        AgentDecisionRequestV1::decode(&over_limit),
        Err(AgentDecisionError::MalformedWire)
    );
    assert_eq!(
        ProviderDecisionV1::decode(&over_limit),
        Err(AgentDecisionError::MalformedWire)
    );
    assert_eq!(
        DecisionRecordV1::decode(&over_limit),
        Err(AgentDecisionError::MalformedWire)
    );
    assert_eq!(
        AgentActionV1::decode(&vec![0; 513]),
        Err(AgentDecisionError::MalformedWire)
    );
}

#[test]
fn every_decoder_rejects_its_own_incomplete_trailing_and_wrong_shape_values() {
    let catalogue = decode_hex(CATALOGUE_HEX);
    let request = decode_hex(REQUEST_HEX);
    let decision = decode_hex(PDP_ACCEPTED_HEX);
    let record = decode_hex(RECORD_ACCEPTED_HEX);
    let action = decode_hex(ACTION_HEX);

    for wire in [&catalogue, &request, &decision, &record, &action] {
        let mut truncated = wire.clone();
        truncated.pop();
        assert_all_malformed(&truncated);
    }

    for wire in [&catalogue, &request, &decision, &record, &action] {
        let mut trailing = wire.clone();
        trailing.push(0);
        assert_all_malformed(&trailing);
    }

    for (wire, wrong_array_length) in [
        (catalogue.clone(), 0x82),
        (request.clone(), 0x8c),
        (decision.clone(), 0x84),
        (record.clone(), 0x8f),
        (action.clone(), 0x86),
    ] {
        let mut malformed = wire;
        malformed[0] = wrong_array_length;
        assert_all_malformed(&malformed);
    }

    for wire in [&catalogue, &request, &decision, &record, &action] {
        let mut wrong_magic_type = wire.clone();
        wrong_magic_type[1] = 0x61;
        assert_all_malformed(&wrong_magic_type);
    }

    let mut wrong_catalogue_magic = catalogue;
    wrong_catalogue_magic[2] = b'X';
    assert_eq!(
        ActionCatalogueV1::decode(&wrong_catalogue_magic),
        Err(AgentDecisionError::MalformedWire)
    );
    let mut wrong_request_magic = request;
    wrong_request_magic[2] = b'X';
    assert_eq!(
        AgentDecisionRequestV1::decode(&wrong_request_magic),
        Err(AgentDecisionError::MalformedWire)
    );
    let mut wrong_record_magic = record;
    wrong_record_magic[2] = b'X';
    assert_eq!(
        DecisionRecordV1::decode(&wrong_record_magic),
        Err(AgentDecisionError::MalformedWire)
    );
    let mut wrong_action_magic = action;
    wrong_action_magic[2] = b'X';
    assert_eq!(
        AgentActionV1::decode(&wrong_action_magic),
        Err(AgentDecisionError::MalformedWire)
    );
    let mut wrong_decision_magic = decision;
    wrong_decision_magic[2] = b'X';
    assert_eq!(
        ProviderDecisionV1::decode(&wrong_decision_magic),
        Err(AgentDecisionError::MalformedWire)
    );

    assert_eq!(
        ActionCatalogueV1::decode(&decode_hex("83445041433102")),
        Err(AgentDecisionError::MalformedWire)
    );
    assert_eq!(
        AgentDecisionRequestV1::decode(&decode_hex("8d445051523102")),
        Err(AgentDecisionError::MalformedWire)
    );
    assert_eq!(
        DecisionRecordV1::decode(&decode_hex("90445044523102")),
        Err(AgentDecisionError::MalformedWire)
    );
    assert_eq!(
        AgentActionV1::decode(&decode_hex("87445041413102")),
        Err(AgentDecisionError::MalformedWire)
    );

    assert_eq!(
        ActionCatalogueV1::decode(&decode_hex("8344504143310181656d6f766500")),
        Err(AgentDecisionError::MalformedWire)
    );
    assert_eq!(
        AgentDecisionRequestV1::decode(&decode_hex("8d4450515231014f")),
        Err(AgentDecisionError::MalformedWire)
    );
    assert_eq!(
        DecisionRecordV1::decode(&decode_hex("904450445231014f")),
        Err(AgentDecisionError::MalformedWire)
    );
    assert_eq!(
        AgentActionV1::decode(&decode_hex("87445041413101646d6f76651a000f4240074f")),
        Err(AgentDecisionError::MalformedWire)
    );
    let mut invalid_request_provider_id = decode_hex(REQUEST_HEX);
    replace_once(&mut invalid_request_provider_id, b"local-1", b"Local-1");
    assert_eq!(
        AgentDecisionRequestV1::decode(&invalid_request_provider_id),
        Err(AgentDecisionError::MalformedWire)
    );
    let mut invalid_record_provider_id = decode_hex(RECORD_ACCEPTED_HEX);
    replace_once(&mut invalid_record_provider_id, b"local-1", b"Local-1");
    assert_eq!(
        DecisionRecordV1::decode(&invalid_record_provider_id),
        Err(AgentDecisionError::MalformedWire)
    );
    let mut invalid_action_identifier = decode_hex(ACTION_HEX);
    replace_once(&mut invalid_action_identifier, b"move", b"m\0ve");
    assert_eq!(
        AgentActionV1::decode(&invalid_action_identifier),
        Err(AgentDecisionError::MalformedWire)
    );

    assert_eq!(
        ProviderDecisionV1::decode(&decode_hex("8544504450310100184000")),
        Err(AgentDecisionError::InvalidActionIndex)
    );
    assert_eq!(
        ProviderDecisionV1::decode(&decode_hex("8544504450310100001a000f4241")),
        Err(AgentDecisionError::InvalidConfidence)
    );
    assert_eq!(
        DecisionRecordV1::decode(&decode_hex("90445044523101")),
        Err(AgentDecisionError::MalformedWire)
    );
    assert_eq!(
        AgentActionV1::decode(&decode_hex("87445041413101646d6f76651a000f4241075820")),
        Err(AgentDecisionError::MalformedWire)
    );
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

fn assert_all_malformed(bytes: &[u8]) {
    assert_eq!(
        ActionCatalogueV1::decode(bytes),
        Err(AgentDecisionError::MalformedWire)
    );
    assert_eq!(
        AgentDecisionRequestV1::decode(bytes),
        Err(AgentDecisionError::MalformedWire)
    );
    assert_eq!(
        ProviderDecisionV1::decode(bytes),
        Err(AgentDecisionError::MalformedWire)
    );
    assert_eq!(
        DecisionRecordV1::decode(bytes),
        Err(AgentDecisionError::MalformedWire)
    );
    assert_eq!(
        AgentActionV1::decode(bytes),
        Err(AgentDecisionError::MalformedWire)
    );
}

fn replace_once(bytes: &mut [u8], needle: &[u8], replacement: &[u8]) {
    assert_eq!(needle.len(), replacement.len(), "fixture replacement width");
    let start = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("fixture marker exists");
    bytes[start..start + replacement.len()].copy_from_slice(replacement);
}
