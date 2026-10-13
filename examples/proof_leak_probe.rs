//! Does a real proof carry anything it is supposed to hide?
//!
//! # Why this exists
//!
//! A bug report arrived with a 25-line Python script and a captured
//! `proof.bin`, and the script recovered the holder's device public key
//! from it. It worked, the key was a valid P-256 point, and the report
//! said the proof came from r13.
//!
//! It did not. The script scans for a run of 2,328 consecutive 32-byte
//! cells each holding exactly 0 or 1 — a plaintext bit vector — and
//! reads a fixed offset out of it. That layout is byte-for-byte the
//! **r12** circuit's public inputs (`crate::mdoc_core`): a 23-byte nonce,
//! `device_x`, `device_y`, three timestamps, four `digestID`s, four
//! blinded claim digests. Nothing was being extracted; r12 publishes the
//! device key as 512 public input bits by design, and the script was
//! reading public IO out of a serialized proof.
//!
//! The mix-up was entirely reasonable: r13 has no FFI binding, so
//! `ffi_api::prove` still goes through the r12 path and any `proof_bytes`
//! captured from a real wallet flow *is* r12.
//!
//! Answering it took an afternoon of generating proofs and writing
//! throwaway search scripts. This is that work, kept — so the next such
//! report is answered in one command, against real proofs, with evidence
//! rather than an argument about layouts.
//!
//! # What it checks
//!
//! For both arithmetizations, on a real `setup` + `prove`:
//!
//! * every secret the circuit is supposed to hide is absent from the
//!   serialized proof, searched in ten encodings — raw bytes both
//!   endiannesses, one byte per field element, one bit per field element
//!   in both bit orders and both field encodings, one bit per byte;
//! * the longest run of 0/1 field cells, which is the structural
//!   property the r12 attack relies on. Measured: r12 offers **2,328**
//!   in a row — exactly the `CORE_BITS` the reported script asks for —
//!   and r13 offers **1**.
//!
//! # The positive control
//!
//! A leak probe that finds nothing is indistinguishable from a leak probe
//! that is broken. So it also requires the values that *are* public —
//! the cutoff and the verifier's clock — to be found, in the encoding
//! the circuit publishes them in. If those are missing the search itself
//! is not working and the run fails, rather than reporting a clean bill.
//!
//! # Which revision is this proof from?
//!
//! The question the report turned on, and nothing in the repository
//! answers it — "r12" and "r13" appear only in prose. The proofs
//! themselves are easy to tell apart:
//!
//! | | entry point | size | longest 0/1 cell run |
//! |---|---|---|---|
//! | r12 | `ffi_api::prove` -> `mdoc_core` | 232,697 B | **2328** |
//! | r13 single | `mdoc_age_circuit::prove` | 111,640 B | 1 |
//! | r13 folded | `mdoc_age_mc::prove` | 452,646 B | 1 |
//!
//! The run length is the decisive one: it is r12's public inputs laid
//! out one bit per field element, and r13 has no such block at all.
//! `ffi_api` still exposes only r12, so anything reached through the
//! UniFFI or cgo bindings is r12 whatever the caller intended.
//!
//! # What it does not establish
//!
//! Absence in these encodings is evidence, not a proof of zero knowledge.
//! That property rests on vega-prover's Spartan and Hyrax internals,
//! which this crate has not inspected. See the README.
//!
//! ```text
//! cargo run --release --example proof_leak_probe [fixture] [--dump DIR]
//! ```

use num_bigint::{BigInt, Sign};
use sha2::{Digest, Sha256};
use zk_cred_vega::mdoc_age::{DateEncoding, DeviceAuthWitness, MdocAgeWitness};
use zk_cred_vega::mdoc_age_circuit::{self, MdocAgeCircuit};
use zk_cred_vega::offset_bind::Landmarks;
use zk_cred_vega::Engine_;

type Scalar = <Engine_ as vega_prover::traits::Engine>::Scalar;

const CUTOFF: &[u8; 10] = b"2008-10-01";
const NOW: &[u8; 20] = b"2026-10-10T12:00:00Z";
const SESSION: &[u8; 32] = b"verifier-session-transcript-0001";

/// Bytes laid out one per field element, little-endian — how this
/// circuit publishes `cutoff` and `now`.
fn byte_cells_le(bytes: &[u8]) -> Vec<u8> {
  bytes.iter().flat_map(|&b| std::iter::once(b).chain([0u8; 31])).collect()
}

fn byte_cells_be(bytes: &[u8]) -> Vec<u8> {
  bytes.iter().flat_map(|&b| [0u8; 31].into_iter().chain(std::iter::once(b))).collect()
}

fn bits(bytes: &[u8], msb_first: bool) -> Vec<u8> {
  bytes
    .iter()
    .flat_map(|&b| (0..8).map(move |i| if msb_first { (b >> (7 - i)) & 1 } else { (b >> i) & 1 }))
    .collect()
}

/// Bits laid out one per field element — how r12 published the device
/// key, and what the reported script scans for.
fn bit_cells(bytes: &[u8], msb_first: bool, little_endian: bool) -> Vec<u8> {
  bits(bytes, msb_first)
    .into_iter()
    .flat_map(|v| {
      let mut cell = [0u8; 32];
      if v == 1 {
        cell[if little_endian { 0 } else { 31 }] = 1;
      }
      cell
    })
    .collect()
}

/// Every encoding a value could plausibly survive into a proof in.
fn encodings(bytes: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
  let mut out = vec![
    ("raw big-endian", bytes.to_vec()),
    ("raw little-endian", bytes.iter().rev().copied().collect()),
    ("one byte per field element, LE", byte_cells_le(bytes)),
    ("one byte per field element, BE", byte_cells_be(bytes)),
    ("one bit per byte, MSB first", bits(bytes, true)),
    ("one bit per byte, LSB first", bits(bytes, false)),
  ];
  for msb in [true, false] {
    for le in [true, false] {
      out.push((
        match (msb, le) {
          (true, true) => "one bit per field element, MSB/LE",
          (true, false) => "one bit per field element, MSB/BE",
          (false, true) => "one bit per field element, LSB/LE",
          (false, false) => "one bit per field element, LSB/BE",
        },
        bit_cells(bytes, msb, le),
      ));
    }
  }
  out
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
  if needle.is_empty() || needle.len() > haystack.len() {
    return None;
  }
  haystack.windows(needle.len()).position(|w| w == needle)
}

/// The longest run of consecutive 32-byte cells holding exactly 0 or 1.
///
/// Every byte alignment, each walked in 32-byte strides — which is what
/// the reported script effectively does, since it slides its start one
/// byte at a time and then reads cells at a fixed stride from there. A
/// bit vector sitting at any offset is therefore found.
///
/// Sliding one byte at a time *while counting cells* instead measures
/// overlapping windows and is wrong in both directions: two consecutive
/// zero cells report 33 rather than 2, and a zero cell followed by a one
/// cell reports 1 rather than 2. The first inflates a clean proof and
/// the second deflates a leaking one, so the discriminator this number
/// exists to be would have been meaningless.
fn longest_bit_cell_run(data: &[u8]) -> usize {
  let (zero, one) = ([0u8; 32], {
    let mut c = [0u8; 32];
    c[0] = 1;
    c
  });
  let mut best = 0usize;
  for align in 0..32 {
    let mut cur = 0usize;
    let mut off = align;
    while off + 32 <= data.len() {
      let c = &data[off..off + 32];
      cur = if c == zero || c == one { cur + 1 } else { 0 };
      best = best.max(cur);
      off += 32;
    }
  }
  best
}

struct Secret {
  what: &'static str,
  bytes: Vec<u8>,
}

fn sign_device_auth(key_hex: &str, digest: &[u8; 32]) -> DeviceAuthWitness {
  use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
  let b: [u8; 32] = hex::decode(key_hex).unwrap().try_into().unwrap();
  let sk = SigningKey::from_bytes(&b.into()).unwrap();
  let sig: Signature = sk.sign_prehash(digest).unwrap();
  let n = zk_cred_vega::p256_ecc::p256_order();
  let s = BigInt::from_bytes_be(Sign::Plus, &sig.s().to_bytes());
  DeviceAuthWitness {
    r: BigInt::from_bytes_be(Sign::Plus, &sig.r().to_bytes()),
    s: s.clone(),
    s_inv: s.modpow(&(n.clone() - BigInt::from(2)), &n),
  }
}

fn load(name: &str) -> (MdocAgeCircuit<Engine_>, Vec<Secret>, [u8; 32]) {
  let json: serde_json::Value =
    serde_json::from_str(&std::fs::read_to_string(format!("test-vectors/{name}.json")).expect("fixture"))
      .unwrap();
  let sig = hex::decode(json["sig_structure_hex"].as_str().unwrap()).unwrap();
  let lm = &json["landmarks"];
  let ns = json["namespace"].as_str().unwrap();
  let target = json["claims"]
    .as_array()
    .unwrap()
    .iter()
    .find(|c| c["element_identifier"] == "birth_date" && c["namespace"] == ns)
    .unwrap();

  let w = &json["ecdsa_witness"];
  let hx = |k: &str| hex::decode(w[k].as_str().unwrap()).unwrap();
  let z: [u8; 32] = Sha256::digest(&sig).into();
  let x_at = lm["device_key_x_offset"].as_u64().unwrap() as usize;
  let digest_at = target["digest_offset"].as_u64().unwrap() as usize;
  let item = hex::decode(target["issuer_signed_item_bytes_hex"].as_str().unwrap()).unwrap();
  let validity_at = lm["validity_info_offset"].as_u64().unwrap() as usize;

  let circuit = MdocAgeCircuit {
    witness: MdocAgeWitness {
      sig_structure: sig.clone(),
      landmarks: Landmarks {
        value_digests_key: lm["value_digests_key_offset"].as_u64().unwrap() as usize,
        validity_info: validity_at,
        namespace_key: lm["namespace_key_offset"].as_u64().unwrap() as usize,
        region_start: lm["region_start"].as_u64().unwrap() as usize,
        device_key_info: lm["device_key_info_offset"].as_u64().unwrap() as usize,
        doc_type_key: lm["doc_type_offset"].as_u64().unwrap() as usize,
      },
      namespace: ns.to_string(),
      doc_type: json["doc_type"].as_str().unwrap().to_string(),
      num_entries: lm["num_entries"].as_u64().unwrap() as usize,
      item_bytes: item.clone(),
      digest_offset: digest_at,
      element_value_key_offset: json["element_value_key_offset"].as_u64().unwrap() as usize,
      date_encoding: match json["date_encoding"].as_str().unwrap() {
        "PhotoIdMap" => DateEncoding::PhotoIdMap,
        _ => DateEncoding::Bare,
      },
      device_auth: sign_device_auth(json["device_private_key_hex"].as_str().unwrap(), SESSION),
    },
    ecdsa: zk_cred_vega::ecdsa::EcdsaP256Witness::<Scalar> {
      qx: zk_cred_vega::nonnative::util::nat_to_f(&BigInt::from_bytes_be(Sign::Plus, &hx("qx_hex"))).unwrap(),
      qy: zk_cred_vega::nonnative::util::nat_to_f(&BigInt::from_bytes_be(Sign::Plus, &hx("qy_hex"))).unwrap(),
      r: BigInt::from_bytes_be(Sign::Plus, &hx("r_hex")),
      s: BigInt::from_bytes_be(Sign::Plus, &hx("s_hex")),
      s_inv: BigInt::from_bytes_be(Sign::Plus, &hx("s_inv_hex")),
      z: BigInt::from_bytes_be(Sign::Plus, &z),
    },
    cutoff: *CUTOFF,
    now: *NOW,
    device_auth_digest: *SESSION,
  };

  // Everything the proof must not carry. The device key is first for a
  // reason: it is the one the report was about, and the one whose
  // exposure made every presentation of a credential linkable.
  let birth_date = circuit.witness.birth_date_bytes().expect("the fixture has a birth_date");
  let secrets = vec![
    Secret { what: "device key x", bytes: sig[x_at..x_at + 32].to_vec() },
    // `y` is at x + 35, not x + 33: COSE puts its own `22 58 20` label
    // and header between the two coordinates. See `DEVICE_KEY_Y_DELTA`,
    // which is `DEVICE_KEY_X_DELTA + 32 + 3`. Getting this wrong made
    // the probe search for `58 20 || y[0..30]` — a string that would be
    // absent even from a proof carrying `y` in full, so it could report
    // clean through an actual leak.
    Secret { what: "device key y", bytes: sig[x_at + 35..x_at + 67].to_vec() },
    Secret { what: "birth_date", bytes: birth_date.to_vec() },
    Secret { what: "the claim digest", bytes: sig[digest_at..digest_at + 32].to_vec() },
    Secret { what: "the IssuerSignedItem", bytes: item },
    Secret { what: "the item's random salt", bytes: sig[digest_at..digest_at + 16].to_vec() },
    Secret { what: "the validityInfo block", bytes: sig[validity_at..validity_at + 60].to_vec() },
  ];
  // The issuer key as the proof carries it: a field element, which
  // serializes little-endian.
  let mut issuer_qx: [u8; 32] = hx("qx_hex").try_into().expect("a 32-byte coordinate");
  issuer_qx.reverse();
  (circuit, secrets, issuer_qx)
}

/// Returns true if the proof is clean.
fn probe(label: &str, proof: &[u8], secrets: &[Secret], issuer_qx: &[u8; 32]) -> bool {
  println!("\n{label}: {} bytes", proof.len());

  // Positive controls first. If the published values cannot be found,
  // the search is broken and a clean result below would mean nothing.
  //
  // The issuer key is the control that carries the weight. The cutoff
  // and clock only show that *byte-per-field-element* search works; the
  // issuer's `qx` is a 32-byte elliptic-curve coordinate published as a
  // single field element, which is the same shape and the same encoding
  // a leaked device key would take. Finding it and not finding the
  // device key, in one pass over one proof, is the whole argument.
  let mut control_ok = true;
  for (what, pattern) in [
    ("cutoff", byte_cells_le(&CUTOFF[..])),
    ("verifier clock", byte_cells_le(&NOW[..])),
    ("issuer key qx (a 32-byte coordinate, like the device key)", issuer_qx.to_vec()),
  ] {
    match find(proof, &pattern) {
      Some(at) => println!("  control: {what} found at {at} (published, as expected)"),
      None => {
        println!("  CONTROL FAILED: {what} is a public input and was not found — the search is not working");
        control_ok = false;
      }
    }
  }

  let run = longest_bit_cell_run(proof);
  println!("  longest run of 0/1 field cells: {run}  (the r12 attack needs 2328 in a row)");

  let mut clean = true;
  for s in secrets {
    let mut found = Vec::new();
    for (how, pattern) in encodings(&s.bytes) {
      if let Some(at) = find(proof, &pattern) {
        found.push(format!("{how} at {at}"));
      }
    }
    if found.is_empty() {
      println!("  ok: {} ({} bytes) absent in all 10 encodings", s.what, s.bytes.len());
    } else {
      println!("  LEAK: {} present as {}", s.what, found.join("; "));
      clean = false;
    }
  }
  clean && control_ok
}

fn main() {
  let args: Vec<String> = std::env::args().skip(1).collect();
  let dump = args.iter().position(|a| a == "--dump").map(|i| args[i + 1].clone());
  let name = args.first().filter(|a| !a.starts_with("--")).cloned().unwrap_or_else(|| "mdl_iso18013".into());
  println!("fixture: {name}");

  let (circuit, secrets, issuer_qx) = load(&name);
  let mut clean = true;

  let keys = mdoc_age_circuit::setup(circuit.clone()).expect("setup");
  let proof = mdoc_age_circuit::prove(&keys.pk, circuit.clone()).expect("prove");
  let bytes = bincode::serialize(&proof).expect("serialize");
  clean &= probe("single circuit", &bytes, &secrets, &issuer_qx);
  if let Some(dir) = &dump {
    std::fs::write(format!("{dir}/proof_single.bin"), &bytes).expect("write");
  }

  let (steps, core) = zk_cred_vega::mdoc_age_mc::build(
    &circuit.witness,
    &circuit.ecdsa,
    circuit.cutoff,
    circuit.now,
    circuit.device_auth_digest,
  )
  .expect("folded build");
  let mc_keys = zk_cred_vega::mdoc_age_mc::setup(&steps[0], &core).expect("folded setup");
  let mc_proof = zk_cred_vega::mdoc_age_mc::prove(&mc_keys.pk, &steps, &core).expect("folded prove");
  let mc_bytes = bincode::serialize(&mc_proof).expect("serialize");
  clean &= probe("folded", &mc_bytes, &secrets, &issuer_qx);
  if let Some(dir) = &dump {
    std::fs::write(format!("{dir}/proof_folded.bin"), &mc_bytes).expect("write");
  }

  println!();
  if clean {
    println!("No secret found in either proof, and all three positive controls fired.");
    println!("Evidence, not a proof of zero knowledge — that rests on vega-prover's");
    println!("Spartan and Hyrax internals, which this crate has not inspected.");
  } else {
    println!("A secret was found, or a control did not fire. Read the lines above.");
    std::process::exit(1);
  }
}
