# H3 Cell Codec and Reference-Cloaker Specification

## Authorization and boundary

Redmine #142 is authorized by accepted ADR-031, ADR-034, ADR-037, and CTO Harvey's 2026-08-04 review. The deliverable is the Wave 6 inert value seam only:

- A versioned GeoCellV1 value with validated H3 cell identity.
- A private, pure-Rust h3o = "=0.10.0" reference adapter.
- Validated Wgs84Point input, H3-specific normalization, coarsening, and strict deterministic encoding/decoding.
- Feature-enabled conformance and invalid-input tests.

This change must not add a geo.cell Event schema, Event writer or reader, Plugin capability, reducer, Gateway route, Fork/export path, migration, backfill, dual-write, or production activation. The existing reserved geo.cell boundary remains unchanged. Redmine #149 and accepted ADR-037 own the later enclosing Event and atomic admission transaction.

## Public interface

The new module is plugins/geo/src/geo_cell.rs and is exported only when the crate h3 feature is enabled. h3o types never appear in the public API.

~~~rust
pub const GEO_CELL_FORMAT_V1: u8 = 1;
pub const GEO_CELL_SYSTEM_H3_V4: &str = "h3-v4";

pub struct H3Resolution(u8);
impl H3Resolution {
    pub fn new(value: u8) -> Result<Self, GeoCellError>;
    pub const fn value(self) -> u8;
}

pub struct GeoCellV1 { /* private validated address and resolution */ }
impl GeoCellV1 {
    pub fn index(&self) -> &str;
    pub const fn resolution(&self) -> H3Resolution;
    pub fn encode_v1(&self) -> Result<CanonicalBytes, GeoCellError>;
    pub fn decode_v1(bytes: &CanonicalBytes) -> Result<Self, GeoCellError>;
}

pub struct H3ReferenceCloaker;
impl H3ReferenceCloaker {
    pub const fn new() -> Self;
    pub fn from_wgs84(
        &self,
        point: Wgs84Point,
        resolution: H3Resolution,
    ) -> Result<GeoCellV1, GeoCellError>;
    pub fn parse(&self, index: &str) -> Result<GeoCellV1, GeoCellError>;
    pub fn parent(
        &self,
        cell: GeoCellV1,
        target: H3Resolution,
    ) -> Result<GeoCellV1, GeoCellError>;
}
~~~

GeoCellV1 is constructible only through the adapter or strict decoder, so a caller cannot create a public value with a non-cell H3 mode, invalid reserved bits, a noncanonical address, or a mismatched resolution.

The private representation keeps a fixed 15-byte lowercase ASCII identity buffer and
an immutable textual view required by the public accessor. The adapter and decoder
validate the identity before construction. Invariant-only conversions from a
validated `Wgs84Point`, validated H3 index/resolution, and fixed serializable wire
shape retain documented internal `expect` checks; Harvey's CTO review confirmed
these are unreachable implementation-invariant failures rather than public input
error categories.

## Coordinate contract

Wgs84Point remains unchanged and is the only public coordinate input. Immediately before conversion, the adapter creates a private normalized input:

- negative zero becomes positive zero;
- longitude +180 becomes -180;
- longitude becomes positive zero at either pole;
- H3Resolution accepts exactly 0..=15.

The source Wgs84Point is not mutated and no coordinate pair is present in GeoCellV1 or its bytes.

## Canonical value bytes

The V1 value is exactly one four-field CBOR map using the repository RFC 8949 length-first canonical encoder:

| Field | Type | Constraint |
| --- | --- | --- |
| cell_format | unsigned integer | exactly 1 |
| system | text | exactly h3-v4 |
| index | text | exactly 15 lowercase ASCII hexadecimal characters and a valid H3 cell index |
| resolution | unsigned integer | 0..=15, equal to the parsed index resolution |

The canonical map is exactly 61 bytes for every V1 value. The known-answer fixture for index 8928308280fffff at resolution 9 is:

~~~text
a465696e6465786f3839323833303832383066666666666673797374656d6568332d76346a7265736f6c7574696f6e096b63656c6c5f666f726d617401
~~~

The decoder reads exactly one CBOR item, rejects trailing bytes, duplicate/unknown/missing keys, wrong types, nonminimal or indefinite encodings, and then validates the H3 index and resolution. It canonical-encodes the validated value and requires byte-for-byte equality with the input. Any failure returns no cell.

## H3 adapter contract

The adapter uses h3o::LatLng::new(...).to_cell(...) for point conversion, CellIndex::from_str plus a lowercase/15-character precheck for parsing, CellIndex::resolution for the derived resolution, CellIndex::parent for coarsening, and Display for canonical lowercase hexadecimal output. parent accepts equal or coarser targets only; finer targets return a typed error.

The Cargo feature is disabled by default:

~~~toml
[features]
default = []
h3 = ["dep:h3o"]

[dependencies]
h3o = { version = "=0.10.0", default-features = false, optional = true }
~~~

No h3o default or optional feature is enabled. Feature-enabled tests compare the adapter against the ADR-031 H3 Core v4.5.0 known-answer baseline and cover ordinary cells, resolutions, pentagons, poles, antimeridian normalization, boundaries, parents, and invalid indexes.

## Error and test requirements

GeoCellError has stable typed categories for invalid resolution, invalid/noncanonical H3 index, payload-size mismatch, malformed CBOR, noncanonical CBOR, missing/duplicate/unexpected/wrong fields, unsupported format/system, resolution mismatch, and finer-parent requests. It does not expose h3o types or backend diagnostic strings.

Tests cover the exact fixture, deterministic repeated encodes, declaration-order independence, strict malformed CBOR, all input boundaries, H3 Core known answers, all resolutions, pentagons, parent rules, and disabled-feature dependency isolation. Feature-enabled tests are included in local and GitHub quality gates rather than existing only in an unexecuted feature configuration.
