//! Measured cost of the offset-based age proof, per document type.
//!
//! Run `cargo run --release --example gen_mdoc_fixtures` first.
//!
//! Everything here goes through `zk_cred_vega::mdoc_age::synthesize`, the
//! same path the tests check for soundness, and the constraint system is
//! asserted satisfied before any number is printed.

use bellpepper_core::test_cs::TestConstraintSystem;
use num_bigint::{BigInt, Sign};
use sha2::{Digest, Sha256};
use zk_cred_vega::mdoc_age::{self, DateEncoding, MdocAgeWitness};
use zk_cred_vega::offset_bind::Landmarks;
use zk_cred_vega::Engine_;

type Scalar = <Engine_ as vega_prover::traits::Engine>::Scalar;

const COMP: usize = 25_840; // one SHA-256 compression, from constraint_census
const STEP: usize = 112_605; // one ClaimDigestStepCircuit, likewise

fn main() {
  let docs = ["mdl_iso18013", "pid_arf18", "photo_id_23220", "photo_id_23220_bare_date"];
  println!("\n  offset-based age proof, measured per document type");
  println!("  {:<26} {:>7} {:>5} {:>4} {:>7} {:>12}", "fixture", "bytes", "blks", "ns", "entries", "constraints");
  let mut shapes = Vec::new();

  for name in docs {
    let json: serde_json::Value =
      serde_json::from_str(&std::fs::read_to_string(format!("test-vectors/{name}.json")).expect("fixture")).unwrap();
    let sig = hex::decode(json["sig_structure_hex"].as_str().unwrap()).unwrap();
    let lm = &json["landmarks"];
    let ns = json["namespace"].as_str().unwrap();
    let target = json["claims"]
      .as_array()
      .unwrap()
      .iter()
      .find(|c| c["element_identifier"] == "birth_date" && c["namespace"] == ns)
      .unwrap();

    let witness = MdocAgeWitness {
      sig_structure: sig.clone(),
      landmarks: Landmarks {
        value_digests_key: lm["value_digests_key_offset"].as_u64().unwrap() as usize,
        namespace_key: lm["namespace_key_offset"].as_u64().unwrap() as usize,
        region_start: lm["region_start"].as_u64().unwrap() as usize,
        device_key_info: lm["device_key_info_offset"].as_u64().unwrap() as usize,
        doc_type_key: lm["doc_type_offset"].as_u64().unwrap() as usize,
      },
      namespace: ns.to_string(),
      doc_type: json["doc_type"].as_str().unwrap().to_string(),
      num_namespaces: lm["num_namespaces"].as_u64().unwrap() as usize,
      num_entries: lm["num_entries"].as_u64().unwrap() as usize,
      item_bytes: hex::decode(target["issuer_signed_item_bytes_hex"].as_str().unwrap()).unwrap(),
      digest_offset: target["digest_offset"].as_u64().unwrap() as usize,
      element_value_key_offset: json["element_value_key_offset"].as_u64().unwrap() as usize,
      date_encoding: match json["date_encoding"].as_str().unwrap() {
        "PhotoIdMap" => DateEncoding::PhotoIdMap,
        _ => DateEncoding::Bare,
      },
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

    let mut cs = TestConstraintSystem::<Scalar>::new();
    let out = mdoc_age::synthesize(&mut cs, &witness, &ecdsa, b"2008-10-01").expect("synthesis");
    assert!(cs.is_satisfied(), "{name}: unsatisfied at {:?}", cs.which_is_unsatisfied());
    assert!(out.old_enough.get_value().unwrap());

    let total_entries: usize = json["claims"].as_array().unwrap().len();
    println!(
      "  {:<26} {:>7} {:>5} {:>4} {:>7} {:>12}",
      name,
      sig.len(),
      zk_cred_vega::sha256_var::terminal_block_for_len(sig.len()),
      witness.num_namespaces,
      total_entries,
      cs.num_constraints()
    );
    shapes.push(cs.num_constraints());
  }

  assert!(shapes.windows(2).all(|w| w[0] == w[1]), "document types must share one circuit shape");
  let total = shapes[0];

  println!("\n  every document type synthesises the SAME {total} constraints,");
  println!("  so one setup and one published artifact serves all of them.");
  println!("\n  of which SHA-256 over the credential  {:>9}  {:.0}%",
    mdoc_age::SIG_STRUCTURE_BLOCKS * COMP,
    (mdoc_age::SIG_STRUCTURE_BLOCKS * COMP) as f64 * 100.0 / total as f64);

  // What the reconstruct architecture would need for the largest of them.
  let photo_entries = 56;
  let recon = photo_entries * STEP + mdoc_age::SIG_STRUCTURE_BLOCKS * COMP + photo_entries * COMP + 400_000 + 10_256;
  println!("\n  reconstruct architecture, Photo ID's {photo_entries} entries: {recon} ({:.1}x)", recon as f64 / total as f64);
  println!("  and it would need a separate circuit, setup and artifact per");
  println!("  attribute count -- 35 for the mDL, 34 for the PID, 56 here.\n");
}
