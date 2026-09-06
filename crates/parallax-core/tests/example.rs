//! The shipped example must parse into exactly the canonical fixture, so docs,
//! tests and the CLI all describe the same scenario.

use parallax_core::testing::canonical_config;
use parallax_core::Config;

#[test]
fn example_toml_is_the_canonical_scenario() {
    let text = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../example/parallax.toml"),
    )
    .unwrap();
    let parsed = Config::from_toml(&text).unwrap();
    assert_eq!(parsed, canonical_config());
}

#[test]
fn config_round_trips_through_toml() {
    let cfg = canonical_config();
    let text = cfg.to_toml().unwrap();
    assert_eq!(Config::from_toml(&text).unwrap(), cfg);
}
