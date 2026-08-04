#![cfg(feature = "h3")]

use pos_plugin_geo::geo_cell::{GeoCellError, H3ReferenceCloaker};

#[test]
fn canonical_shaped_but_invalid_h3_text_is_rejected() {
    assert_eq!(
        H3ReferenceCloaker::new().parse("fffffffffffffff"),
        Err(GeoCellError::InvalidH3Index)
    );
}
