//! Wall-clock and artifact-size profile of the full pipeline, so
//! optimisation targets can be picked from measurements rather than
//! intuition. Analysis tool, not part of the library.
//!
//! Run under `/usr/bin/time -v` to capture peak RSS.

use std::time::Instant;

fn main() {
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

  let t = Instant::now();
  let keys = zk_cred_vega::setup().expect("setup");
  println!("setup                : {:>8.2?}", t.elapsed());

  let pk_bytes = bincode::serialize(&keys.pk).unwrap().len();
  let vk_bytes = bincode::serialize(&keys.vk).unwrap().len();
  println!("  prover key         : {:>8.1} MB", pk_bytes as f64 / 1e6);
  println!("  verifier key       : {:>8.1} MB", vk_bytes as f64 / 1e6);

  let t = Instant::now();
  let prep = zk_cred_vega::prep_prove(&keys.pk, &claims, &ecdsa, &body, &nonce).expect("prep_prove");
  println!("prep_prove           : {:>8.2?}", t.elapsed());

  let prep_bytes = bincode::serialize(&prep.into_inner()).unwrap();
  println!("  prep state         : {:>8.1} MB", prep_bytes.len() as f64 / 1e6);
  let prep = zk_cred_vega::VegaMdocPrepState::from_inner(bincode::deserialize(&prep_bytes).unwrap());

  let t = Instant::now();
  let (proof, _next) = zk_cred_vega::prove(&keys.pk, &claims, &ecdsa, &body, prep, &nonce).expect("prove");
  println!("prove                : {:>8.2?}", t.elapsed());

  let proof_bytes = bincode::serialize(&proof).unwrap().len();
  println!("  proof              : {:>8.1} kB", proof_bytes as f64 / 1e3);

  let t = Instant::now();
  let (sv, cv) = zk_cred_vega::verify(&proof, &keys.vk).expect("verify");
  println!("verify               : {:>8.2?}", t.elapsed());

  let t = Instant::now();
  let disclosed: Vec<Option<Vec<u8>>> = claims.iter().map(|c| if c.disclose { Some(c.issuer_signed_item_bytes.clone()) } else { None }).collect();
  let _ = zk_cred_vega::verify_and_check_binding(&sv, &cv, &disclosed).expect("bind");
  println!("verify_and_check_bind: {:>8.2?}", t.elapsed());
}
