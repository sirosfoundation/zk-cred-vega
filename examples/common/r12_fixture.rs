//! Loading one r12 presentation's witness from a test fixture, in the
//! one place the analysis tools share it.
//!
//! Three of them — `perf_profile`, `perf_profile_traced` and
//! `compressibility_probe` — run the same pipeline and differ only in
//! what they measure about it, so they had the same thirty-seven lines
//! of fixture decoding three times. That is what SonarCloud's
//! duplication gate was objecting to, and it was right to: the block
//! names every field of `ClaimWitness`, `MdocEcdsaWitness` and
//! `MsoBodyWitness`, so any change to those witnesses had to be made in
//! three files or the tools would silently diverge from each other.
//!
//! Included with `#[path]` rather than built as its own crate, because
//! Cargo examples cannot depend on one another and the fixture loader
//! needs `serde_json` and `hex`, which are dev-dependencies and so
//! cannot move into the library.
//!
//! This is the **r12** pipeline (`zk_cred_vega::setup`/`prep_prove`,
//! the `vega-mc-p256-v1` reconstruct circuit). r13's analysis tools go
//! through `mdoc_age_circuit` and `mdoc_age_mc` and load their own
//! fixtures.

use num_bigint::{BigInt, Sign};

/// One presentation's worth of witness, as the r12 entry points take it.
pub struct Presentation {
  pub claims: Vec<zk_cred_vega::ClaimWitness>,
  pub ecdsa: zk_cred_vega::MdocEcdsaWitness,
  pub body: zk_cred_vega::mso::MsoBodyWitness,
  pub nonce: [u8; zk_cred_vega::BLIND_NONCE_BYTES],
}

/// Reads `test-vectors/mdl_4claims_mixed_disclosure.json`.
///
/// Panics rather than returning an error: these are analysis tools run
/// by hand from the repository root, where a missing fixture is a
/// mistyped command and the actionable thing is the message telling you
/// to generate it.
pub fn load() -> Presentation {
  let fixture = std::fs::read_to_string("test-vectors/mdl_4claims_mixed_disclosure.json")
    .expect("fixture (run `cargo run --release --example gen_test_mdocs` first)");
  let f: serde_json::Value = serde_json::from_str(&fixture).unwrap();
  let hexb = |s: &str| hex::decode(s).unwrap();

  let claims = f["claims"]
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
  let nat = |s: &str| zk_cred_vega::nonnative::util::nat_to_f(&BigInt::from_bytes_be(Sign::Plus, &hexb(s))).unwrap();
  let int = |s: &str| BigInt::from_bytes_be(Sign::Plus, &hexb(s));
  let ecdsa = zk_cred_vega::MdocEcdsaWitness {
    qx: nat(w["qx_hex"].as_str().unwrap()),
    qy: nat(w["qy_hex"].as_str().unwrap()),
    r: int(w["r_hex"].as_str().unwrap()),
    s: int(w["s_hex"].as_str().unwrap()),
    s_inv: int(w["s_inv_hex"].as_str().unwrap()),
  };

  let m = &f["mso_body"];
  let fx = |s: &str| -> [u8; 32] { hexb(s).try_into().unwrap() };
  let ts = |s: &str| -> [u8; 20] { m[s].as_str().unwrap().as_bytes().try_into().unwrap() };
  let body = zk_cred_vega::mso::MsoBodyWitness {
    device_x: fx(m["device_x_hex"].as_str().unwrap()),
    device_y: fx(m["device_y_hex"].as_str().unwrap()),
    signed_ts: ts("signed_ts"),
    valid_from_ts: ts("valid_from_ts"),
    valid_until_ts: ts("valid_until_ts"),
  };

  Presentation { claims, ecdsa, body, nonce: [0x5A; zk_cred_vega::BLIND_NONCE_BYTES] }
}
