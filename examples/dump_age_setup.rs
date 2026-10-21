//! Writes the r13 setup artifacts so their real on-the-wire size can be
//! measured rather than estimated. Analysis tool, not part of the library.
//!
//! Usage: `cargo run --release --example dump_age_setup -- <out-dir>`

use vega_prover::traits::Engine;
use zk_cred_vega::Engine_;
use zk_cred_vega::mdoc_age_circuit::{self, MdocAgeCircuit};

type Scalar = <Engine_ as Engine>::Scalar;

/// Builds a circuit from a committed test fixture.
///
/// Exposed so the setup-dumping example and the end-to-end tests load a
/// prototype the same way. Setup only needs *a* satisfying witness --
/// the shape is identical across document types -- so a fixture is the
/// right source for a published artifact's provenance.
fn prototype_from_fixture(name: &str) -> MdocAgeCircuit<Engine_> {
  use num_bigint::{BigInt, Sign};
  use sha2::{Digest, Sha256};
  use zk_cred_vega::mdoc_age::{DateEncoding, DeviceAuthWitness, MdocAgeWitness};

  let json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(format!("test-vectors/{name}.json")).expect("fixture")).unwrap();
  let sig = hex::decode(json["sig_structure_hex"].as_str().unwrap()).unwrap();
  let lm = &json["landmarks"];
  let ns = json["namespace"].as_str().unwrap();
  let t = json["claims"]
    .as_array()
    .unwrap()
    .iter()
    .find(|c| c["element_identifier"] == "birth_date" && c["namespace"] == ns)
    .unwrap();
  let session = [0x5au8; 32];

  let kb: [u8; 32] = hex::decode(json["device_private_key_hex"].as_str().unwrap()).unwrap().try_into().unwrap();
  let device_auth = {
    use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
    let sk = SigningKey::from_bytes(&kb.into()).unwrap();
    let sg: Signature = sk.sign_prehash(&session).unwrap();
    let n = zk_cred_vega::p256_ecc::p256_order();
    let sv = BigInt::from_bytes_be(Sign::Plus, &sg.s().to_bytes());
    DeviceAuthWitness {
      r: BigInt::from_bytes_be(Sign::Plus, &sg.r().to_bytes()),
      s: sv.clone(),
      s_inv: sv.modpow(&(n.clone() - BigInt::from(2)), &n),
    }
  };
  let w = &json["ecdsa_witness"];
  let hx = |k: &str| hex::decode(w[k].as_str().unwrap()).unwrap();
  let z: [u8; 32] = Sha256::digest(&sig).into();

  MdocAgeCircuit {
    witness: MdocAgeWitness {
      sig_structure: sig,
      landmarks: zk_cred_vega::offset_bind::Landmarks {
        value_digests_key: lm["value_digests_key_offset"].as_u64().unwrap() as usize,
        validity_info: lm["validity_info_offset"].as_u64().unwrap() as usize,
        namespace_key: lm["namespace_key_offset"].as_u64().unwrap() as usize,
        region_start: lm["region_start"].as_u64().unwrap() as usize,
        device_key_info: lm["device_key_info_offset"].as_u64().unwrap() as usize,
        doc_type_key: lm["doc_type_offset"].as_u64().unwrap() as usize,
      },
      namespace: ns.to_string(),
      doc_type: json["doc_type"].as_str().unwrap().to_string(),
      num_entries: lm["num_entries"].as_u64().unwrap() as usize,
      item_bytes: hex::decode(t["issuer_signed_item_bytes_hex"].as_str().unwrap()).unwrap(),
      digest_offset: t["digest_offset"].as_u64().unwrap() as usize,
      element_value_key_offset: json["element_value_key_offset"].as_u64().unwrap() as usize,
      date_encoding: match json["date_encoding"].as_str().unwrap() {
        "PhotoIdMap" => DateEncoding::PhotoIdMap,
        _ => DateEncoding::Bare,
      },
      device_auth,
    },
    ecdsa: zk_cred_vega::ecdsa::EcdsaP256Witness::<Scalar> {
      qx: zk_cred_vega::nonnative::util::nat_to_f(&BigInt::from_bytes_be(Sign::Plus, &hx("qx_hex"))).unwrap(),
      qy: zk_cred_vega::nonnative::util::nat_to_f(&BigInt::from_bytes_be(Sign::Plus, &hx("qy_hex"))).unwrap(),
      r: BigInt::from_bytes_be(Sign::Plus, &hx("r_hex")),
      s: BigInt::from_bytes_be(Sign::Plus, &hx("s_hex")),
      s_inv: BigInt::from_bytes_be(Sign::Plus, &hx("s_inv_hex")),
      z: BigInt::from_bytes_be(Sign::Plus, &z),
    },
    cutoff: *b"2008-10-01",
    now: *b"2026-10-10T12:00:00Z",
    device_auth_digest: session,
  }
}

fn main() {
  let dir = std::env::args().nth(1).expect("usage: dump_age_setup <out-dir>");
  std::fs::create_dir_all(&dir).unwrap();
  eprintln!("running setup ...");
  let keys = mdoc_age_circuit::setup(prototype_from_fixture("mdl_iso18013")).expect("setup");
  for (name, bytes) in [
    ("prover-key.bin", bincode::serialize(&keys.pk).unwrap()),
    ("verifier-key.bin", bincode::serialize(&keys.vk).unwrap()),
  ] {
    let p = std::path::Path::new(&dir).join(name);
    std::fs::write(&p, &bytes).unwrap();
    println!("{name}: {} bytes ({:.1} MB)", bytes.len(), bytes.len() as f64 / 1e6);
  }
}
