//! R8-A15: composite faults, and the anchor.

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn encode(value: &Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out)?;
    Ok(out)
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

fn pair(digest: &[u8], bytes: &[u8]) -> Value {
    Value::Array(vec![
        Value::Bytes(digest.to_vec()),
        Value::Bytes(bytes.to_vec()),
    ])
}

/// The pieces of `blobs`, sorted by digest.
fn sorted(blobs: &[&[u8]]) -> Vec<Value> {
    let mut entries: Vec<([u8; 32], &[u8])> = blobs.iter().map(|b| (digest(b), *b)).collect();
    entries.sort();
    entries.into_iter().map(|(d, b)| pair(&d, b)).collect()
}

fn bytes(content: &[u8]) -> Value {
    Value::Bytes(content.to_vec())
}

fn composite_of(version: u8, list: Vec<Value>) -> Value {
    Value::Array(vec![
        Value::Text("PCW2".to_owned()),
        Value::Integer(version.into()),
        Value::Array(list),
    ])
}

fn good() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    encode(&composite_of(1, sorted(&[b"alpha", b"beta", b""])))
}

fn member(bytes: Vec<u8>) -> AttemptArtifact {
    AttemptArtifact {
        digest: digest(&bytes),
        bytes,
    }
}

#[test]
fn a_canonical_composite_gives_its_pieces() -> TestResult {
    let pieces = PiecesV1::from_bytes(&good()?)?;
    assert_eq!(pieces.get(&digest(b"alpha")), Some(b"alpha".as_slice()));
    assert_eq!(pieces.get(&digest(b"")), Some(b"".as_slice()));
    assert_eq!(pieces.get(&digest(b"gamma")), None);
    let empty = PiecesV1::from_bytes(&encode(&composite_of(1, Vec::new()))?)?;
    assert_eq!(empty.get(&digest(b"alpha")), None);
    Ok(())
}

#[test]
fn the_composite_is_the_unique_member_with_the_header() -> TestResult {
    let others = vec![
        member(b"evidence".to_vec()),
        member(vec![0x83, 0x64]),
        member(Vec::new()),
    ];
    assert_eq!(PiecesV1::find(&others), Err(PiecesFaultV1::Missing));
    assert_eq!(PiecesV1::find(&[]), Err(PiecesFaultV1::Missing));

    let mut with = others.clone();
    with.insert(1, member(good()?));
    assert!(PiecesV1::find(&with)?.get(&digest(b"beta")).is_some());

    with.push(member(good()?));
    assert_eq!(PiecesV1::find(&with), Err(PiecesFaultV1::Ambiguous));

    let broken = vec![member(vec![0x83, 0x64, 0x50, 0x43, 0x57, 0x32, 0xff])];
    assert_eq!(PiecesV1::find(&broken), Err(PiecesFaultV1::Invalid));
    Ok(())
}

fn invalid(bytes: &[u8]) -> bool {
    PiecesV1::from_bytes(bytes) == Err(PiecesFaultV1::Invalid)
}

#[test]
fn a_composite_that_is_not_canonical_cbor_is_invalid() -> TestResult {
    let canonical = good()?;
    let mut trailing = canonical.clone();
    trailing.push(0);
    assert!(invalid(&trailing), "trailing byte");
    assert!(invalid(&canonical[..canonical.len() - 1]), "truncated");
    assert!(invalid(&[]), "empty");
    assert!(invalid(b"\xff"), "break");

    // The pieces list as an indefinite-length array.
    let mut indefinite = vec![0x83, 0x64, 0x50, 0x43, 0x57, 0x32, 0x01, 0x9f];
    for entry in sorted(&[b"alpha"]) {
        indefinite.extend(encode(&entry)?);
    }
    indefinite.push(0xff);
    assert!(invalid(&indefinite), "indefinite-length array");

    // The version 1 in two bytes.
    let mut wide = vec![0x83, 0x64, 0x50, 0x43, 0x57, 0x32, 0x18, 0x01];
    wide.extend(encode(&Value::Array(Vec::new()))?);
    assert!(invalid(&wide), "non-shortest integer");

    // A byte string of a piece in an indefinite-length chunked form.
    let digest_bytes = digest(b"a");
    let mut chunked = vec![
        0x83, 0x64, 0x50, 0x43, 0x57, 0x32, 0x01, 0x81, 0x82, 0x58, 0x20,
    ];
    chunked.extend(digest_bytes);
    chunked.extend([0x5f, 0x41, b'a', 0xff]);
    assert!(invalid(&chunked), "indefinite-length byte string");
    Ok(())
}

#[test]
fn a_composite_of_the_wrong_shape_is_invalid() -> TestResult {
    let header = || Value::Text("PCW2".to_owned());
    let one = || Value::Integer(1_u8.into());
    let shapes = [
        Value::Array(vec![header(), one()]),
        Value::Array(vec![header(), one(), Value::Array(Vec::new()), one()]),
        Value::Array(vec![
            Value::Text("PCW3".to_owned()),
            one(),
            Value::Array(Vec::new()),
        ]),
        Value::Array(vec![
            header(),
            Value::Integer(2_u8.into()),
            Value::Array(Vec::new()),
        ]),
        Value::Array(vec![
            header(),
            Value::Text("1".to_owned()),
            Value::Array(Vec::new()),
        ]),
        Value::Array(vec![
            header(),
            Value::Integer((-1_i8).into()),
            Value::Array(Vec::new()),
        ]),
        Value::Array(vec![header(), one(), Value::Bytes(Vec::new())]),
        Value::Array(vec![
            header(),
            one(),
            Value::Array(vec![Value::Bytes(Vec::new())]),
        ]),
        composite_of(1, vec![Value::Array(vec![Value::Bytes(vec![0; 32])])]),
        composite_of(
            1,
            vec![Value::Array(vec![bytes(&[0; 32]), bytes(&[]), Value::Null])],
        ),
        composite_of(
            1,
            vec![Value::Array(vec![Value::Text("d".to_owned()), bytes(&[])])],
        ),
        composite_of(
            1,
            vec![Value::Array(vec![
                bytes(&digest(b"")),
                Value::Text(String::new()),
            ])],
        ),
        composite_of(1, vec![pair(&digest(b"x")[..31], b"x")]),
        composite_of(
            1,
            vec![pair(&[digest(b"x").as_slice(), b"0"].concat(), b"x")],
        ),
    ];
    for shape in shapes {
        // Prefix the header of the composite so the same bytes would also be found.
        let bytes = encode(&shape)?;
        assert!(invalid(&bytes), "{shape:?}");
    }
    assert!(invalid(&encode(&Value::Null)?), "not an array");
    Ok(())
}

#[test]
fn a_piece_must_hash_to_its_digest() -> TestResult {
    let wrong = composite_of(1, vec![pair(&digest(b"alpha"), b"alpha!")]);
    assert!(invalid(&encode(&wrong)?));
    Ok(())
}

#[test]
fn pieces_must_be_strictly_ascending_by_digest() -> TestResult {
    let mut list = sorted(&[b"alpha", b"beta"]);
    let duplicate = vec![list[0].clone(), list[0].clone()];
    assert!(
        invalid(&encode(&composite_of(1, duplicate))?),
        "duplicate digest"
    );
    list.reverse();
    assert!(invalid(&encode(&composite_of(1, list))?), "descending");
    Ok(())
}

#[test]
fn from_blobs_addresses_each_blob_by_digest() {
    let pieces = PiecesV1::from_blobs([b"one".to_vec(), b"two".to_vec()]);
    assert_eq!(pieces.get(&digest(b"one")), Some(b"one".as_slice()));
    assert_eq!(pieces.get(&digest(b"two")), Some(b"two".as_slice()));
    assert_eq!(
        pieces,
        PiecesV1::from_blobs([b"two".to_vec(), b"one".to_vec()])
    );
}

fn anchor_value(tag: &str, version: u8, scope: Value, lengths: [usize; 3]) -> Value {
    Value::Array(vec![
        Value::Text(tag.to_owned()),
        Value::Integer(version.into()),
        scope,
        Value::Bytes(vec![1; lengths[0]]),
        Value::Bytes(vec![2; lengths[1]]),
        Value::Bytes(vec![3; lengths[2]]),
    ])
}

#[test]
fn a_pca1_anchor_decodes_its_scope_and_three_digests() -> TestResult {
    let value = anchor_value("PCA1", 1, Value::Text("scope".to_owned()), [32; 3]);
    let anchor = decode_anchor(&encode(&value)?).ok_or("anchor")?;
    assert_eq!(anchor.scope, "scope");
    assert_eq!(anchor.ptr1_genesis_digest, [1; 32]);
    assert_eq!(anchor.operator_key, [2; 32]);
    assert_eq!(anchor.genesis_tps1_digest, [3; 32]);
    Ok(())
}

#[test]
fn an_undecodable_pca1_anchor_is_refused() -> TestResult {
    let text = || Value::Text("scope".to_owned());
    let refused = [
        anchor_value("PCA2", 1, text(), [32; 3]),
        anchor_value("PCA1", 2, text(), [32; 3]),
        anchor_value("PCA1", 1, Value::Bytes(vec![]), [32; 3]),
        anchor_value("PCA1", 1, text(), [31, 32, 32]),
        anchor_value("PCA1", 1, text(), [32, 33, 32]),
        anchor_value("PCA1", 1, text(), [32, 32, 0]),
        Value::Array(vec![Value::Text("PCA1".to_owned())]),
        Value::Null,
    ];
    for value in refused {
        assert!(decode_anchor(&encode(&value)?).is_none(), "{value:?}");
    }
    let canonical = encode(&anchor_value("PCA1", 1, text(), [32; 3]))?;
    let mut trailing = canonical.clone();
    trailing.push(0);
    assert!(decode_anchor(&trailing).is_none(), "trailing byte");
    let mut damaged = canonical;
    damaged[2] = 0x58;
    assert!(decode_anchor(&damaged).is_none(), "damaged tag");
    assert!(decode_anchor(b"").is_none());
    Ok(())
}
