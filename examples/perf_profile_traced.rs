//! Same pipeline as `perf_profile.rs`, but with `vega-prover`'s own existing
//! `tracing` instrumentation (61 call sites in `vega_mc_zkp.rs` alone)
//! surfaced via a real subscriber - a stage-by-stage breakdown INSIDE
//! `prep_prove`/`prove`, not just the two coarse top-level numbers.
//! Analysis tool, not part of the library.
//!
//! Run with `RUST_LOG=vega_prover=debug,info` (or `=trace` for everything)
//! to control verbosity. On Android, run as a plain native binary via
//! `adb shell` (no JVM/UniFFI/Zygote involved) so real CPU core affinity
//! (`taskset`) applies cleanly - see this crate's README/session notes for
//! the cross-compile command.

use std::time::Instant;
use tracing_subscriber::fmt::time::uptime;

fn main() {
  tracing_subscriber::fmt()
    .with_timer(uptime())
    .with_target(true)
    .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
    .init();

  let fixture = std::fs::read_to_string("test-vectors/mdl_4claims_mixed_disclosure.json")
    .expect("fixture (run `cargo run --release --example gen_test_mdocs` first)");
  let f: serde_json::Value = serde_json::from_str(&fixture).unwrap();
  let hexb = |s: &str| hex::decode(s).unwrap();

  let claims: Vec<zk_cred_vega::ClaimWitness> = f["claims"]
    .as_array()
    .unwrap()
    .iter()
    .map(|c| zk_cred_vega::ClaimWitness {
      issuer_signed_item_bytes: hexb(c["issuer_signed_item_bytes_hex"].as_str().unwrap()),
      disclose: c["disclose"].as_bool().unwrap(),
      digest_id: c["digest_id"].as_u64().unwrap() as u32,
    })
    .collect();

  let w = &f["ecdsa_witness"];
  use num_bigint::{BigInt, Sign};
  let ecdsa = zk_cred_vega::MdocEcdsaWitness {
    qx: zk_cred_vega::nonnative::util::nat_to_f(&BigInt::from_bytes_be(Sign::Plus, &hexb(w["qx_hex"].as_str().unwrap()))).unwrap(),
    qy: zk_cred_vega::nonnative::util::nat_to_f(&BigInt::from_bytes_be(Sign::Plus, &hexb(w["qy_hex"].as_str().unwrap()))).unwrap(),
    r: BigInt::from_bytes_be(Sign::Plus, &hexb(w["r_hex"].as_str().unwrap())),
    s: BigInt::from_bytes_be(Sign::Plus, &hexb(w["s_hex"].as_str().unwrap())),
    s_inv: BigInt::from_bytes_be(Sign::Plus, &hexb(w["s_inv_hex"].as_str().unwrap())),
  };
  let m = &f["mso_body"];
  let fx = |s: &str| -> [u8; 32] { hexb(s).try_into().unwrap() };
  let body = zk_cred_vega::mso::MsoBodyWitness {
    device_x: fx(m["device_x_hex"].as_str().unwrap()),
    device_y: fx(m["device_y_hex"].as_str().unwrap()),
    signed_ts: m["signed_ts"].as_str().unwrap().as_bytes().try_into().unwrap(),
    valid_from_ts: m["valid_from_ts"].as_str().unwrap().as_bytes().try_into().unwrap(),
    valid_until_ts: m["valid_until_ts"].as_str().unwrap().as_bytes().try_into().unwrap(),
  };
  let nonce = [0x5Au8; zk_cred_vega::BLIND_NONCE_BYTES];

  eprintln!("=== available parallelism: {:?} ===", std::thread::available_parallelism());

  let t = Instant::now();
  let keys = zk_cred_vega::setup().expect("setup");
  eprintln!("setup                : {:>8.2?}", t.elapsed());

  let t = Instant::now();
  let prep = zk_cred_vega::prep_prove(&keys.pk, &claims, &ecdsa, &body, &nonce).expect("prep_prove");
  eprintln!("prep_prove (total)   : {:>8.2?}", t.elapsed());

  let t = Instant::now();
  let (proof, _next) = zk_cred_vega::prove(&keys.pk, &claims, &ecdsa, &body, prep, &nonce).expect("prove");
  eprintln!("prove (total)        : {:>8.2?}", t.elapsed());

  let proof_bytes = bincode::serialize(&proof).unwrap().len();
  eprintln!("  proof              : {:>8.1} kB", proof_bytes as f64 / 1e3);
}
