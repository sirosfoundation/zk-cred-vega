//! Wall-clock and artifact-size profile of the full pipeline, so
//! optimisation targets can be picked from measurements rather than
//! intuition. Analysis tool, not part of the library.
//!
//! Run under `/usr/bin/time -v` to capture peak RSS.

use std::time::Instant;

#[path = "common/r12_fixture.rs"]
mod r12_fixture;

fn main() {
  let r12_fixture::Presentation { claims, ecdsa, body, nonce } = r12_fixture::load();

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
