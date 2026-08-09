#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test_configure!(run_in_browser);

const EXPECTED_DIGEST: [u8; 32] = [
    179, 111, 48, 88, 213, 234, 83, 154, 148, 133, 42, 43, 48, 140, 142, 207, 213, 109, 156, 92,
    68, 255, 242, 164, 139, 148, 13, 116, 160, 96, 181, 179,
];

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn native_and_wasm_use_the_same_fixture_projection_path() {
    let export =
        piglor_world_client::decode_fixture(&piglor_world_client::fixture_bytes()).unwrap();
    let digest = piglor_world_client::project_fixture(&export).unwrap();

    assert_eq!(digest.signals, 2);
    assert_eq!(digest.trust_mean_bits, 0.75f64.to_bits());
    assert_eq!(digest.landmark_x_bits, 1.0f64.to_bits());
    assert_eq!(digest.digest_bytes(), EXPECTED_DIGEST);
}
