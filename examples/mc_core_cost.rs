//! Measures the folded core's constraint count against the single-circuit
//! one, to see how much the setup shape actually shrank. Analysis tool.

use bellpepper_core::test_cs::TestConstraintSystem;
use num_bigint::{BigInt, Sign};
use sha2::{Digest, Sha256};
use zk_cred_vega::mdoc_age::{self, DateEncoding, DeviceAuthWitness, Hasher, MdocAgeWitness};
use zk_cred_vega::mdoc_age_mc::{self, HashWitness};
use zk_cred_vega::offset_bind::Landmarks;
use zk_cred_vega::Engine_;

type Scalar = <Engine_ as vega_prover::traits::Engine>::Scalar;
const SESSION: &[u8; 32] = b"verifier-session-transcript-0001";
const NOW: &[u8; 20] = b"2026-10-10T12:00:00Z";
const CUTOFF: &[u8; 10] = b"2008-10-01";

fn load() -> (MdocAgeWitness, zk_cred_vega::ecdsa::EcdsaP256Witness<Scalar>) {
  let json: serde_json::Value =
    serde_json::from_str(&std::fs::read_to_string("test-vectors/mdl_iso18013.json").unwrap()).unwrap();
  let sig = hex::decode(json["sig_structure_hex"].as_str().unwrap()).unwrap();
  let lm = &json["landmarks"];
  let ns = json["namespace"].as_str().unwrap();
  let t = json["claims"].as_array().unwrap().iter()
    .find(|c| c["element_identifier"] == "birth_date" && c["namespace"] == ns).unwrap();
  let kb: [u8; 32] = hex::decode(json["device_private_key_hex"].as_str().unwrap()).unwrap().try_into().unwrap();
  let device_auth = {
    use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
    let sk = SigningKey::from_bytes(&kb.into()).unwrap();
    let sg: Signature = sk.sign_prehash(SESSION).unwrap();
    let n = zk_cred_vega::p256_ecc::p256_order();
    let sv = BigInt::from_bytes_be(Sign::Plus, &sg.s().to_bytes());
    DeviceAuthWitness { r: BigInt::from_bytes_be(Sign::Plus, &sg.r().to_bytes()), s: sv.clone(),
      s_inv: sv.modpow(&(n.clone() - BigInt::from(2)), &n) }
  };
  let w = &json["ecdsa_witness"];
  let hx = |k: &str| hex::decode(w[k].as_str().unwrap()).unwrap();
  let z: [u8; 32] = Sha256::digest(&sig).into();
  (
    MdocAgeWitness {
      sig_structure: sig, landmarks: Landmarks {
        value_digests_key: lm["value_digests_key_offset"].as_u64().unwrap() as usize,
        validity_info: lm["validity_info_offset"].as_u64().unwrap() as usize,
        namespace_key: lm["namespace_key_offset"].as_u64().unwrap() as usize,
        region_start: lm["region_start"].as_u64().unwrap() as usize,
        device_key_info: lm["device_key_info_offset"].as_u64().unwrap() as usize,
        doc_type_key: lm["doc_type_offset"].as_u64().unwrap() as usize,
      },
      namespace: ns.to_string(), doc_type: json["doc_type"].as_str().unwrap().to_string(),
      num_namespaces: lm["num_namespaces"].as_u64().unwrap() as usize,
      num_entries: lm["num_entries"].as_u64().unwrap() as usize,
      item_bytes: hex::decode(t["issuer_signed_item_bytes_hex"].as_str().unwrap()).unwrap(),
      digest_offset: t["digest_offset"].as_u64().unwrap() as usize,
      element_value_key_offset: json["element_value_key_offset"].as_u64().unwrap() as usize,
      date_encoding: match json["date_encoding"].as_str().unwrap() { "PhotoIdMap" => DateEncoding::PhotoIdMap, _ => DateEncoding::Bare },
      device_auth,
    },
    zk_cred_vega::ecdsa::EcdsaP256Witness::<Scalar> {
      qx: zk_cred_vega::nonnative::util::nat_to_f(&BigInt::from_bytes_be(Sign::Plus, &hx("qx_hex"))).unwrap(),
      qy: zk_cred_vega::nonnative::util::nat_to_f(&BigInt::from_bytes_be(Sign::Plus, &hx("qy_hex"))).unwrap(),
      r: BigInt::from_bytes_be(Sign::Plus, &hx("r_hex")), s: BigInt::from_bytes_be(Sign::Plus, &hx("s_hex")),
      s_inv: BigInt::from_bytes_be(Sign::Plus, &hx("s_inv_hex")), z: BigInt::from_bytes_be(Sign::Plus, &z),
    },
  )
}

fn main() {
  let (w, e) = load();
  let l = mdoc_age_mc::layout();
  let hw = HashWitness::from_witness(&w);

  // Single circuit, for reference.
  let mut cs = TestConstraintSystem::<Scalar>::new();
  mdoc_age::synthesize(&mut cs, &w, &e, CUTOFF, NOW, SESSION).unwrap();
  let sc = cs.num_constraints();

  // Folded core: same statement, compressions moved out.
  let mut cs = TestConstraintSystem::<Scalar>::new();
  let shared = zk_cred_vega::sha256_mc::alloc_shared(&mut cs, &hw.blocks, &hw.digests).unwrap();
  let cred = mdoc_age::synthesize_credential(
    &mut cs, &w, &e,
    &Hasher::Folded { shared: &shared, layout: &l, message: 0 },
    &Hasher::Folded { shared: &shared, layout: &l, message: 1 },
  ).unwrap();
  mdoc_age::synthesize_session(&mut cs, &cred.device_key, &cred.birth_date, &cred.valid_from,
    &cred.valid_until, &w.device_auth, CUTOFF, NOW, SESSION).unwrap();
  let core = cs.num_constraints();
  assert!(cs.is_satisfied(), "folded core must be satisfied: {:?}", cs.which_is_unsatisfied());

  // One step.
  let mut cs = TestConstraintSystem::<Scalar>::new();
  let shared = zk_cred_vega::sha256_mc::alloc_shared(&mut cs, &hw.blocks, &hw.digests).unwrap();
  let base = cs.num_constraints();
  zk_cred_vega::sha256_mc::synthesize_step(&mut cs, &shared, &l, 0).unwrap();
  let step = cs.num_constraints() - base;

  println!("\n  single circuit (everything unrolled) {sc:>10}");
  println!("  folded core  (no compressions)       {core:>10}   ({:.1}x smaller)", sc as f64 / core as f64);
  println!("  one step circuit                     {step:>10}");
  println!("  setup encodes core + one step        {:>10}   ({:.1}x smaller than SC)",
    core + step, sc as f64 / (core + step) as f64);
  println!("\n  but measured keys were 614.44 MB -> 420.11 MB (only 1.46x)");
  println!("  => the key is NOT dominated by our circuit's shape.");
}
