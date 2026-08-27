//! Generates a handful of realistic (real CBOR shape, real ≥16-byte
//! per-element salt, real ECDSA-P256 signature) mdoc-shaped test vectors
//! and writes them to `test-vectors/`, for testing this crate against
//! claim data that actually looks like a real ISO 18013-5 credential —
//! not the short, unsalted `b"family_name:Doe"`-style strings this
//! crate's own unit tests have used until now.
//!
//! This directly exercises the real-interop gap this crate closed: the
//! generated `IssuerSignedItem` bytes are 79-103 bytes long (real salt +
//! real CBOR framing), which fits `MAX_CLAIM_BYTES_V1` (128) but never
//! fit the old 64-byte limit, and the per-claim digest is computed over
//! those exact bytes (matching real `valueDigests` semantics) rather
//! than a zero-padded stand-in.
//!
//! Each `IssuerSignedItem` is hand-encoded via a small, purpose-built
//! CBOR builder (not a general parser/encoder — same "just enough for
//! this one fixed shape" philosophy as `crate::mso`), matching the real
//! CDDL fields (`digestID`, `random`, `elementIdentifier`, `elementValue`),
//! tag(24)-wrapped, in **canonical CBOR key order**
//! (`random`(6), `digestID`(8), `elementValue`(12), `elementIdentifier`(17)
//! — shortest key first, matching `vc`'s real `cbor.SortCanonical`
//! encoder) with a fixed 32-byte `random` salt — the exact real byte
//! shape `mso.rs`'s and `digest_id_extract`'s own module docs confirm
//! against a real signed test vector and a real device presentation,
//! respectively. (Earlier revisions of this generator used CDDL
//! declaration order and a 16-byte salt — self-consistent with this
//! crate's own, then-wrong, offset assumptions, but not what any real
//! issuer this integration targets actually produces.)
//!
//! digestIDs here deliberately span all four CBOR-uint length classes
//! (1/2/3/5 bytes — see `cbor_uint`'s module doc), not the narrow
//! `0..MAX_CLAIMS_V1` range `mso.rs` used to hardcode, to exercise real
//! spec-legal digestID interop end to end.
//!
//! The digestID used as an MSO map key really is bound to the `digestID`
//! field embedded inside the corresponding `IssuerSignedItem`'s own CBOR
//! bytes — `ClaimDigestStepCircuit` extracts it via `digest_id_extract`
//! and `verify_and_check_binding` cross-checks it against the core
//! circuit's witness. This generator keeps the two consistent by
//! construction (both come from the same `DIGEST_IDS` entry) rather than
//! exercising a deliberate mismatch — see `lib.rs`'s
//! `binding_check_rejects_mismatched_digest_ids` test for that.

use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::Write;

// ---- Minimal CBOR encoding, only for the shapes this file needs ----

fn cbor_length_prefix(major_type: u8, len: usize) -> Vec<u8> {
  let major = major_type << 5;
  if len < 24 {
    vec![major | len as u8]
  } else if len < 256 {
    vec![major | 24, len as u8]
  } else {
    panic!("length {len} too large for this minimal encoder");
  }
}

fn cbor_tstr(s: &str) -> Vec<u8> {
  let mut v = cbor_length_prefix(3, s.len());
  v.extend_from_slice(s.as_bytes());
  v
}

fn cbor_bstr(bytes: &[u8]) -> Vec<u8> {
  let mut v = cbor_length_prefix(2, bytes.len());
  v.extend_from_slice(bytes);
  v
}

/// Reuses the crate's own real, spec-range CBOR-uint encoder (rather than
/// a second, hand-rolled copy here) so `digestID` values spanning all
/// four length classes (up to 70000+ below) encode correctly — the old
/// minimal `<256`-only encoder this file used couldn't represent them.
fn cbor_uint(n: u64) -> Vec<u8> {
  zk_cred_vega::cbor_uint::encode_cbor_uint(u32::try_from(n).expect("test digestIDs fit in a u32"))
}

fn cbor_bool(b: bool) -> Vec<u8> {
  vec![if b { 0xf5 } else { 0xf4 }]
}

/// `full-date` per the mdoc CDDL: `#6.1004(tstr)` — an ISO 8601 calendar
/// date with no time component, e.g. `"1990-05-15"`.
fn cbor_full_date(date: &str) -> Vec<u8> {
  let mut v = vec![0xd9, 0x03, 0xec]; // tag(1004), 2-byte tag value form
  v.extend(cbor_tstr(date));
  v
}

fn cbor_tag24(inner: &[u8]) -> Vec<u8> {
  let mut v = vec![0xd8, 0x18]; // tag(24), 1-byte tag value form
  v.extend(cbor_bstr(inner));
  v
}

/// Builds one real-shape `IssuerSignedItem`, tag(24)-wrapped, in
/// canonical CBOR key order (`random`, `digestID`, `elementValue`,
/// `elementIdentifier` — see module doc for why).
fn build_issuer_signed_item(digest_id: u64, random: &[u8; 32], element_identifier: &str, element_value_cbor: &[u8]) -> Vec<u8> {
  let mut item = vec![0xa4]; // map, 4 entries
  item.extend(cbor_tstr("random"));
  item.extend(cbor_bstr(random));
  item.extend(cbor_tstr("digestID"));
  item.extend(cbor_uint(digest_id));
  item.extend(cbor_tstr("elementValue"));
  item.extend_from_slice(element_value_cbor);
  item.extend(cbor_tstr("elementIdentifier"));
  item.extend(cbor_tstr(element_identifier));
  cbor_tag24(&item)
}

#[derive(Serialize)]
struct TestClaim {
  element_identifier: String,
  digest_id: u64,
  disclose: bool,
  issuer_signed_item_bytes_hex: String,
  issuer_signed_item_bytes_len: usize,
}

#[derive(Serialize)]
struct TestEcdsaWitness {
  qx_hex: String,
  qy_hex: String,
  r_hex: String,
  s_hex: String,
  s_inv_hex: String,
}

#[derive(Serialize)]
struct TestMsoBody {
  device_x_hex: String,
  device_y_hex: String,
  signed_ts: String,
  valid_from_ts: String,
  valid_until_ts: String,
}

#[derive(Serialize)]
struct TestMdoc {
  description: String,
  claims: Vec<TestClaim>,
  ecdsa_witness: TestEcdsaWitness,
  mso_body: TestMsoBody,
}

fn gen_one(description: &str, out_path: &std::path::Path) {
  use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey, VerifyingKey};

  let mut rng = rand::thread_rng();

  // digestIDs deliberately span all four CBOR-uint length classes (see
  // cbor_uint's module doc: 1/2/3/5 bytes), not the narrow 0..3 range a
  // real issuer would never actually assign (ISO 18013-5 §9.1.2.4 warns
  // against small/correlated values) -- proving genuine spec-range
  // interop in this end-to-end fixture, not just the crate's own unit
  // tests.
  const DIGEST_IDS: [u64; 4] = [5, 26, 300, 70000];
  let claim_specs: Vec<(&str, Vec<u8>, bool)> = vec![
    ("family_name", cbor_tstr("Doe"), true),
    ("given_name", cbor_tstr("Jane"), true),
    ("birth_date", cbor_full_date("1990-05-15"), false),
    ("age_over_18", cbor_bool(true), false),
  ];

  let mut claims = Vec::with_capacity(claim_specs.len());
  let mut claim_digests: Vec<[u8; 32]> = Vec::with_capacity(claim_specs.len());
  let mut digest_ids: Vec<u32> = Vec::with_capacity(claim_specs.len());
  for (digest_id, (identifier, value_cbor, disclose)) in DIGEST_IDS.into_iter().zip(claim_specs) {
    let mut random = [0u8; 32];
    rng.fill_bytes(&mut random);
    let item_bytes = build_issuer_signed_item(digest_id, &random, identifier, &value_cbor);
    assert!(
      item_bytes.len() <= zk_cred_vega::MAX_CLAIM_BYTES_V1,
      "{identifier} item is {} bytes, exceeds MAX_CLAIM_BYTES_V1 ({})",
      item_bytes.len(),
      zk_cred_vega::MAX_CLAIM_BYTES_V1
    );
    let digest: [u8; 32] = Sha256::digest(&item_bytes).into();
    claim_digests.push(digest);
    digest_ids.push(u32::try_from(digest_id).unwrap());
    claims.push(TestClaim {
      element_identifier: identifier.to_string(),
      digest_id,
      disclose,
      issuer_signed_item_bytes_len: item_bytes.len(),
      issuer_signed_item_bytes_hex: hex::encode(&item_bytes),
    });
  }
  let digest_ids: [u32; 4] = digest_ids.try_into().unwrap();

  let mut device_x = [0u8; 32];
  let mut device_y = [0u8; 32];
  rng.fill_bytes(&mut device_x);
  rng.fill_bytes(&mut device_y);
  let mso_body = zk_cred_vega::mso::MsoBodyWitness {
    device_x,
    device_y,
    signed_ts: *b"2026-08-20T00:00:00Z",
    valid_from_ts: *b"2026-08-20T00:00:00Z",
    valid_until_ts: *b"2036-08-20T00:00:00Z",
  };

  let sig_structure = zk_cred_vega::mso::native_sig_structure_bytes(&digest_ids, &claim_digests, &mso_body);
  let z_bytes: [u8; 32] = Sha256::digest(&sig_structure).into();

  let mut key_bytes = [0u8; 32];
  rng.fill_bytes(&mut key_bytes);
  let signing_key = SigningKey::from_bytes(&key_bytes.into()).expect("valid scalar");
  let verifying_key = VerifyingKey::from(&signing_key);
  let signature: Signature = signing_key.sign_prehash(&z_bytes).expect("sign_prehash");

  let n = zk_cred_vega::p256_ecc::p256_order();
  let s = num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, &signature.s().to_bytes());
  let s_inv = s.modpow(&(n.clone() - num_bigint::BigInt::from(2)), &n);
  let encoded = verifying_key.to_encoded_point(false);

  let fixture = TestMdoc {
    description: description.to_string(),
    claims,
    ecdsa_witness: TestEcdsaWitness {
      qx_hex: hex::encode(encoded.x().expect("x")),
      qy_hex: hex::encode(encoded.y().expect("y")),
      r_hex: hex::encode(signature.r().to_bytes()),
      s_hex: hex::encode(signature.s().to_bytes()),
      s_inv_hex: hex::encode(s_inv.to_bytes_be().1),
    },
    mso_body: TestMsoBody {
      device_x_hex: hex::encode(device_x),
      device_y_hex: hex::encode(device_y),
      signed_ts: String::from_utf8(mso_body.signed_ts.to_vec()).unwrap(),
      valid_from_ts: String::from_utf8(mso_body.valid_from_ts.to_vec()).unwrap(),
      valid_until_ts: String::from_utf8(mso_body.valid_until_ts.to_vec()).unwrap(),
    },
  };

  let json = serde_json::to_string_pretty(&fixture).expect("serialize");
  std::fs::File::create(out_path)
    .and_then(|mut f| f.write_all(json.as_bytes()))
    .expect("write fixture");
  println!("wrote {}", out_path.display());
}

fn main() {
  let out_dir = std::path::Path::new("test-vectors");
  std::fs::create_dir_all(out_dir).expect("create test-vectors dir");
  gen_one(
    "Realistic 4-claim mDL: family_name/given_name disclosed, birth_date/age_over_18 undisclosed. \
     Real ≥16-byte per-element salts, real CBOR IssuerSignedItem framing (79-103 bytes each), \
     real ECDSA-P256 signature over the real MSO Sig_structure.",
    &out_dir.join("mdl_4claims_mixed_disclosure.json"),
  );
}
