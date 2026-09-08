//! Cost profile of the offset-based PID age proof, measured by
//! synthesising the real thing.
//!
//! Run `cargo run --release --example gen_pid_fixture` first, then
//! `cargo run --release --example pid_age_offset [fixture.json]`.
//!
//! This supersedes `offset_prototype.rs`, which costed the offset shape
//! against a synthetic MSO and explicitly did *not* prove the offset
//! landed inside `valueDigests` — so its total was a floor, not a price.
//! Everything here goes through `zk_cred_vega::pid_age::synthesize`, the
//! same code path the tests check for soundness, and the constraint
//! system is asserted satisfied before any number is printed.
//!
//! Analysis tool, not library code.

use bellpepper_core::{test_cs::TestConstraintSystem};
use num_bigint::{BigInt, Sign};
use sha2::{Digest, Sha256};
use zk_cred_vega::offset_bind::Landmarks;
use zk_cred_vega::pid_age::{self, PidAgeWitness};
use zk_cred_vega::Engine_;

type Scalar = <Engine_ as vega_prover::traits::Engine>::Scalar;

/// Measured separately in `constraint_census`: one SHA-256 compression.
const COMP: usize = 25_840;
/// Measured separately: one `ClaimDigestStepCircuit`.
const STEP: usize = 112_605;

fn main() {
  let path = std::env::args().nth(1).unwrap_or_else(|| "test-vectors/pid_arf18_random.json".into());
  let json: serde_json::Value = serde_json::from_str(
    &std::fs::read_to_string(&path).expect("fixture (run `cargo run --release --example gen_pid_fixture`)"),
  )
  .unwrap();

  let sig = hex::decode(json["sig_structure_hex"].as_str().unwrap()).unwrap();
  let lm = &json["landmarks"];
  let target = json["claims"].as_array().unwrap().iter().find(|c| c["element_identifier"] == "birth_date").unwrap();
  let item = hex::decode(target["issuer_signed_item_bytes_hex"].as_str().unwrap()).unwrap();
  let digest_id = target["digest_id"].as_u64().unwrap() as u32;
  let num_entries = lm["num_entries"].as_u64().unwrap() as usize;

  let witness = PidAgeWitness {
    sig_structure: sig.clone(),
    landmarks: Landmarks {
      value_digests_key: lm["value_digests_key_offset"].as_u64().unwrap() as usize,
      region_start: lm["region_start"].as_u64().unwrap() as usize,
      device_key_info: lm["device_key_info_offset"].as_u64().unwrap() as usize,
      doc_type_key: lm["doc_type_offset"].as_u64().unwrap() as usize,
    },
    namespace: json["namespace"].as_str().unwrap().to_string(),
    doc_type: json["doc_type"].as_str().unwrap().to_string(),
    num_entries,
    item_bytes: item.clone(),
    digest_offset: target["digest_offset"].as_u64().unwrap() as usize,
  };

  let w = &json["ecdsa_witness"];
  let hx = |k: &str| hex::decode(w[k].as_str().unwrap()).unwrap();
  let z: [u8; 32] = Sha256::digest(&sig).into();
  let ecdsa = zk_cred_vega::ecdsa::EcdsaP256Witness::<Scalar> {
    qx: zk_cred_vega::nonnative::util::nat_to_f(&BigInt::from_bytes_be(Sign::Plus, &hx("qx_hex"))).unwrap(),
    qy: zk_cred_vega::nonnative::util::nat_to_f(&BigInt::from_bytes_be(Sign::Plus, &hx("qy_hex"))).unwrap(),
    r: BigInt::from_bytes_be(Sign::Plus, &hx("r_hex")),
    s: BigInt::from_bytes_be(Sign::Plus, &hx("s_hex")),
    s_inv: BigInt::from_bytes_be(Sign::Plus, &hx("s_inv_hex")),
    z: BigInt::from_bytes_be(Sign::Plus, &z),
  };

  println!("\nOffset-based age proof over a real EUDI PID");
  println!("  fixture         : {path}");
  println!("  docType         : {}", witness.doc_type);
  println!(
    "  Sig_structure   : {} bytes ({} SHA-256 blocks), {num_entries} attributes",
    sig.len(),
    zk_cred_vega::sha256_var::terminal_block_for_len(sig.len())
  );
  println!(
    "  digest region   : {}..{} ({} bytes)",
    witness.landmarks.region_start,
    witness.landmarks.device_key_info,
    witness.landmarks.device_key_info - witness.landmarks.region_start
  );
  println!(
    "  birth_date item : {} bytes, digestID {digest_id} ({}-byte CBOR)",
    item.len(),
    zk_cred_vega::cbor_uint::encode_cbor_uint(digest_id).len()
  );

  let mut cs = TestConstraintSystem::<Scalar>::new();
  let out = pid_age::synthesize(&mut cs, &witness, &ecdsa, b"2008-09-04").expect("synthesis");
  assert!(cs.is_satisfied(), "unsatisfied at {:?}", cs.which_is_unsatisfied());
  assert!(out.old_enough.get_value().unwrap());
  let total = cs.num_constraints();

  println!("\n  TOTAL (synthesised and satisfied)  {total:>9}");
  println!("  of which SHA-256 over the credential {:>7}   {:.0}%",
    pid_age::SIG_STRUCTURE_BLOCKS * COMP,
    (pid_age::SIG_STRUCTURE_BLOCKS * COMP) as f64 * 100.0 / total as f64);

  let recon = num_entries * STEP + pid_age::SIG_STRUCTURE_BLOCKS * COMP + num_entries * COMP + 400_000 + 10_256;
  println!("\n  the reconstruct architecture, same credential");
  println!("    would need {recon} constraints ({:.1}x) -- and a new circuit,", recon as f64 / total as f64);
  println!("    a new setup and a new published artifact for every distinct");
  println!("    attribute count, because its shape is fixed at {num_entries}.");
  println!("\n  today's shipped 4-attribute mDL circuit: 842,591\n");
}
