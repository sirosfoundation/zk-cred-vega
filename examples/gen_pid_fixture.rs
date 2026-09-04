//! Generates real-shaped, spec-conformant **EUDI PID** (`eu.europa.ec.eudi.pid.1`)
//! mdoc fixtures for the offset-based age-proof circuit.
//!
//! This is deliberately a different fixture from
//! `gen_test_mdocs.rs`'s 4-claim mDL: that one exists to exercise the
//! *reconstruct* architecture, whose circuit shape is fixed at exactly
//! `MAX_CLAIMS_V1` entries. A real ARF 1.8 PID carries 34 attributes in
//! its `valueDigests` map, which that architecture cannot express at all.
//!
//! What makes these fixtures real rather than a sketch:
//!
//! * The attribute set is the one our own issuer actually issues —
//!   `vc/metadata/pid_mdoc.mdoc.json`'s 34 `eu.europa.ec.eudi.pid.1`
//!   elements, with each element's declared `value_type` (`tstr`,
//!   `full-date`, `tdate`, `uint`, `bool`, `bstr`, `array`) encoded the
//!   way that issuer's `fxamacker/cbor` encoder encodes it.
//! * **Canonical CBOR ordering throughout** (RFC 8949 §4.2.1 core
//!   deterministic: shorter encoded key first, then bytewise) — for the
//!   MSO's own six keys, for `ValidityInfo`, for the COSE_Key, for the
//!   `IssuerSignedItem` keys, and — the one most easily got wrong — for
//!   the `valueDigests` map's *integer* `digestID` keys, which sort by
//!   encoded length class first and only then numerically.
//! * A real ~2 kB `portrait` bstr, so the fixture demonstrates the thing
//!   that makes the offset architecture work at all: a large attribute
//!   inflates its `IssuerSignedItem` but contributes exactly 32 bytes of
//!   digest to the signed MSO, so the circuit's cost is unaffected.
//! * A real ECDSA-P256 signature over the real `Sig_structure`.
//!
//! Two variants are emitted, because `digestID` width is the one part of
//! a PID's MSO byte layout an issuer genuinely varies:
//!
//! * `pid_arf18_sequential` — digestIDs `0..33`, which is what our own
//!   `MSOBuilder` assigns (a per-namespace counter). Mostly 1-byte
//!   encodings; the smallest realistic MSO.
//! * `pid_arf18_random` — digestIDs drawn uniformly from the full legal
//!   range (< 2^31), which is what ISO 18013-5 §9.1.2.4 actually directs
//!   issuers to do to prevent cross-presentation correlation. Nearly all
//!   5-byte encodings; the largest realistic MSO, and therefore the one
//!   the circuit must be sized for.
//!
//! Alongside the bytes, each fixture records the **structural landmarks**
//! the offset circuit witnesses and must prove (the offset of the
//! `"valueDigests"` key, the first and last byte of the digest region,
//! the offset of the `"deviceKeyInfo"` key that terminates it, and the
//! offset of the target attribute's digest within the region). These are
//! computed here by construction, so the prototype can check that what it
//! derives in-circuit agrees with ground truth rather than with itself.

use rand::{Rng, RngCore};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::Write;

const NAMESPACE: &str = "eu.europa.ec.eudi.pid.1";
const DOC_TYPE: &str = "eu.europa.ec.eudi.pid.1";

// ---- Minimal canonical CBOR, only the shapes a PID MSO needs --------

fn head(major: u8, len: u64) -> Vec<u8> {
  let m = major << 5;
  if len < 24 {
    vec![m | len as u8]
  } else if len < 0x100 {
    vec![m | 24, len as u8]
  } else if len < 0x1_0000 {
    let mut v = vec![m | 25];
    v.extend((len as u16).to_be_bytes());
    v
  } else {
    let mut v = vec![m | 26];
    v.extend((len as u32).to_be_bytes());
    v
  }
}

fn tstr(s: &str) -> Vec<u8> {
  let mut v = head(3, s.len() as u64);
  v.extend_from_slice(s.as_bytes());
  v
}

fn bstr(b: &[u8]) -> Vec<u8> {
  let mut v = head(2, b.len() as u64);
  v.extend_from_slice(b);
  v
}

fn uint(n: u64) -> Vec<u8> {
  head(0, n)
}

fn boolean(b: bool) -> Vec<u8> {
  vec![if b { 0xf5 } else { 0xf4 }]
}

/// `full-date`: `#6.1004(tstr)`, RFC 8943. This is what a PID's
/// `birth_date` actually is — *not* a bare tstr and not a `tdate`.
fn full_date(d: &str) -> Vec<u8> {
  let mut v = vec![0xd9, 0x03, 0xec];
  v.extend(tstr(d));
  v
}

/// `tdate`: `#6.0(tstr)`, RFC 8949 §3.4.1.
fn tdate(d: &str) -> Vec<u8> {
  let mut v = vec![0xc0];
  v.extend(tstr(d));
  v
}

fn array(items: &[Vec<u8>]) -> Vec<u8> {
  let mut v = head(4, items.len() as u64);
  for i in items {
    v.extend_from_slice(i);
  }
  v
}

fn tag24(inner: &[u8]) -> Vec<u8> {
  let mut v = vec![0xd8, 0x18];
  v.extend(bstr(inner));
  v
}

/// RFC 8949 §4.2.1 core-deterministic key order: shorter encoded key
/// first, ties broken bytewise. Applied to already-encoded keys.
fn canonical_sort(entries: &mut [(Vec<u8>, Vec<u8>)]) {
  entries.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then_with(|| a.0.cmp(&b.0)));
}


// ---- The real ARF 1.8 PID attribute set ----------------------------

/// The 34 `eu.europa.ec.eudi.pid.1` elements our issuer's MDDL schema
/// declares, each with a realistic value for the demo identity the rest
/// of this stack uses (Helen Mirren, SE, born 1996-01-30 — see
/// `sirosid-dev/fixtures/vc-bootstrapping/pid_1_8.json`).
fn pid_elements(portrait: &[u8], pseudonym_seed: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
  vec![
    ("family_name", tstr("Mirren")),
    ("given_name", tstr("Helen")),
    ("birth_date", full_date("1996-01-30")),
    ("issuance_date", full_date("2026-04-28")),
    ("expiry_date", full_date("2027-05-28")),
    ("issuing_country", tstr("SE")),
    ("issuing_authority", tstr("SUNET")),
    ("document_number", tstr("doc-pid-100")),
    ("administrative_number", tstr("pan-100")),
    ("issuing_jurisdiction", tstr("SE-AB")),
    ("portrait", bstr(portrait)),
    ("portrait_capture_date", tdate("2026-04-28T10:51:58Z")),
    ("family_name_birth", tstr("Mirren")),
    ("given_name_birth", tstr("Helen")),
    ("birth_place", tstr("Stockholm, SE")),
    ("birth_country", tstr("SE")),
    ("birth_state", tstr("Stockholm")),
    ("birth_city", tstr("Stockholm")),
    ("resident_address", tstr("Tulegatan 11, Stockholm")),
    ("resident_country", tstr("SE")),
    ("resident_state", tstr("Stockholm")),
    ("resident_city", tstr("Stockholm")),
    ("resident_postal_code", tstr("11353")),
    ("resident_street", tstr("Tulegatan")),
    ("resident_house_number", tstr("11")),
    ("sex", uint(2)),
    ("nationalities", array(&[tstr("SE")])),
    ("age_in_years", uint(30)),
    ("age_birth_year", uint(1996)),
    ("age_over_18", boolean(true)),
    ("email_address", tstr("mirren@example.com")),
    ("mobile_phone_number", tstr("+46700000000")),
    ("trust_anchor", tstr("https://trust.siros.org/anchors/se-pid")),
    ("pseudonym_seed", bstr(pseudonym_seed)),
  ]
}

/// One `IssuerSignedItem`, tag(24)-wrapped, canonical key order
/// (`random`(6) < `digestID`(8) < `elementValue`(12) <
/// `elementIdentifier`(17) — shortest key first).
fn issuer_signed_item(digest_id: u32, random: &[u8; 32], element_id: &str, value: &[u8]) -> Vec<u8> {
  let mut item = vec![0xa4];
  item.extend(tstr("random"));
  item.extend(bstr(random));
  item.extend(tstr("digestID"));
  item.extend(uint(digest_id as u64));
  item.extend(tstr("elementValue"));
  item.extend_from_slice(value);
  item.extend(tstr("elementIdentifier"));
  item.extend(tstr(element_id));
  tag24(&item)
}

// ---- Fixture shape --------------------------------------------------

#[derive(Serialize)]
struct FixtureClaim {
  element_identifier: String,
  digest_id: u32,
  /// Offset of this entry's 32 digest bytes within the whole
  /// `Sig_structure` — ground truth for what the circuit witnesses.
  digest_offset: usize,
  issuer_signed_item_bytes_len: usize,
  issuer_signed_item_bytes_hex: String,
}

#[derive(Serialize)]
struct Landmarks {
  /// Offset of the `0x6c "valueDigests"` map key.
  value_digests_key_offset: usize,
  /// First byte of the first `digestID => bstr(32)` entry.
  region_start: usize,
  /// Total length of the digest region (all entries, all namespaces
  /// covered here being one).
  region_len: usize,
  /// Offset of the `0x6d "deviceKeyInfo"` key that terminates the
  /// region — the anchor that pins the region's end.
  device_key_info_offset: usize,
  /// Offset of `deviceKey`'s 32-byte x-coordinate. The MSO carries no
  /// attribute *values* — only their digests — so this is the one
  /// 32-byte window in the signed bytes whose content the **holder**
  /// chooses, and therefore the one place a digest can be planted.
  device_key_x_offset: usize,
  /// Offset of the `0x67 "docType"` key.
  doc_type_offset: usize,
  num_entries: usize,
}

#[derive(Serialize)]
struct EcdsaWitness {
  qx_hex: String,
  qy_hex: String,
  r_hex: String,
  s_hex: String,
  s_inv_hex: String,
}

#[derive(Serialize)]
struct PidFixture {
  description: String,
  doc_type: String,
  namespace: String,
  signed_ts: String,
  valid_from_ts: String,
  valid_until_ts: String,
  sig_structure_len: usize,
  sig_structure_hex: String,
  landmarks: Landmarks,
  /// The attribute an age proof targets.
  target_element: String,
  /// Present only in the adversarial fixture: an `IssuerSignedItem` the
  /// issuer never signed, claiming a birthdate that would fail an
  /// age-over-18 check, whose SHA-256 has been planted in the signed
  /// bytes as the holder's own `deviceKey` x-coordinate.
  #[serde(skip_serializing_if = "Option::is_none")]
  forged_item_bytes_hex: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  forged_item_digest_offset: Option<usize>,
  claims: Vec<FixtureClaim>,
  ecdsa_witness: EcdsaWitness,
}

/// Assigns digestIDs the way the named issuer profile does.
enum DigestIdProfile {
  /// A per-namespace counter, as our own `MSOBuilder` does.
  Sequential,
  /// Uniform over the full legal range, as ISO 18013-5 §9.1.2.4 directs.
  Random,
  /// Random digestIDs, but with the holder's `deviceKey` x-coordinate set
  /// to the SHA-256 of a fabricated `birth_date` item. An offset proof
  /// with no structural binding accepts this; `offset_bind` must not.
  PlantedDeviceKey,
}

fn gen_pid(profile: DigestIdProfile, name: &str, description: &str) {
  use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey, VerifyingKey};
  let mut rng = rand::thread_rng();

  // A real PID portrait is a JPEG of a few kB. Its only effect on the
  // signed MSO is 32 bytes of digest — which is exactly the property
  // that makes an offset-based circuit's cost independent of attribute
  // size, so the fixture carries a realistically large one.
  let mut portrait = vec![0u8; 2048];
  rng.fill_bytes(&mut portrait);
  portrait[..3].copy_from_slice(&[0xff, 0xd8, 0xff]); // JPEG SOI
  let mut pseudonym_seed = [0u8; 32];
  rng.fill_bytes(&mut pseudonym_seed);

  let elements = pid_elements(&portrait, &pseudonym_seed);
  let n = elements.len();

  let digest_ids: Vec<u32> = match profile {
    DigestIdProfile::Sequential => (0..n as u32).collect(),
    DigestIdProfile::Random | DigestIdProfile::PlantedDeviceKey => {
      let mut seen = std::collections::BTreeSet::new();
      while seen.len() < n {
        seen.insert(rng.gen_range(0..=zk_cred_vega::cbor_uint::MAX_DIGEST_ID));
      }
      seen.into_iter().collect()
    }
  };

  // Build every item and its digest.
  let mut items: Vec<(u32, &'static str, Vec<u8>, [u8; 32])> = Vec::with_capacity(n);
  for (&digest_id, (element_id, value)) in digest_ids.iter().zip(elements.iter()) {
    let mut random = [0u8; 32];
    rng.fill_bytes(&mut random);
    let bytes = issuer_signed_item(digest_id, &random, element_id, value);
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    items.push((digest_id, element_id, bytes, digest));
  }

  // `valueDigests` for the namespace, in canonical *integer*-key order:
  // by encoded length class first, then numerically. `canonical_sort`
  // gets this right because it sorts on the encoded key bytes.
  let mut vd_entries: Vec<(Vec<u8>, Vec<u8>)> =
    items.iter().map(|(id, _, _, d)| (uint(*id as u64), bstr(d))).collect();
  canonical_sort(&mut vd_entries);
  let mut region = Vec::new();
  // Offset of each digest's 32 bytes, relative to the region start.
  let mut digest_offset_in_region: std::collections::HashMap<u32, usize> = Default::default();
  for (k, v) in &vd_entries {
    region.extend_from_slice(k);
    region.extend_from_slice(v);
    // v is `58 20` + 32 bytes, so the digest starts 2 bytes in.
    let id = {
      // Decode the canonical uint key back to its value.
      match k[0] {
        b if b < 24 => b as u32,
        0x18 => k[1] as u32,
        0x19 => u16::from_be_bytes([k[1], k[2]]) as u32,
        0x1a => u32::from_be_bytes([k[1], k[2], k[3], k[4]]),
        other => panic!("unexpected uint head {other:#04x}"),
      }
    };
    digest_offset_in_region.insert(id, region.len() - 32);
  }

  let signed_ts = "2026-09-04T00:00:00Z";
  let valid_from_ts = "2026-09-04T00:00:00Z";
  let valid_until_ts = "2027-09-04T00:00:00Z";

  let mut device_x = [0u8; 32];
  let mut device_y = [0u8; 32];
  rng.fill_bytes(&mut device_x);
  rng.fill_bytes(&mut device_y);

  // The adversarial variant. An mdoc's MSO contains no attribute values
  // at all — only their digests — so a holder wanting to plant 32 chosen
  // bytes in the signed structure has exactly one place to put them: the
  // `deviceKey` coordinates, which are theirs to choose. They do not even
  // need the matching private key, because this proof never exercises
  // device authentication.
  let forged = match profile {
    DigestIdProfile::PlantedDeviceKey => {
      let mut random = [0u8; 32];
      rng.fill_bytes(&mut random);
      let bytes = issuer_signed_item(digest_ids[2], &random, "birth_date", &full_date("2015-01-01"));
      let digest: [u8; 32] = Sha256::digest(&bytes).into();
      device_x = digest;
      Some(bytes)
    }
    _ => None,
  };

  // ---- MSO body, canonical order: docType, version, validityInfo,
  // valueDigests, deviceKeyInfo, digestAlgorithm. Built by hand rather
  // than via `map()` so the digest region stays one contiguous slice we
  // can record landmarks into.
  let validity_info = {
    let mut v = vec![0xa3];
    v.extend(tstr("signed"));
    v.extend(tdate(signed_ts));
    v.extend(tstr("validFrom"));
    v.extend(tdate(valid_from_ts));
    v.extend(tstr("validUntil"));
    v.extend(tdate(valid_until_ts));
    v
  };
  let device_key_x_offset_in_dki;
  let device_key_info = {
    let mut cose = vec![0xa4];
    cose.extend(vec![0x01, 0x02]); // 1: 2 (EC2)
    cose.extend(vec![0x20, 0x01]); // -1: 1 (P-256)
    cose.push(0x21); // -2
    cose.extend(head(2, 32));
    device_key_x_offset_in_dki = 1 + tstr("deviceKey").len() + cose.len();
    cose.extend_from_slice(&device_x);
    cose.push(0x22); // -3
    cose.extend(bstr(&device_y));
    let mut v = vec![0xa1];
    v.extend(tstr("deviceKey"));
    v.extend(cose);
    v
  };

  let mut mso = vec![0xa6];
  let doc_type_offset_in_mso = mso.len();
  mso.extend(tstr("docType"));
  mso.extend(tstr(DOC_TYPE));
  mso.extend(tstr("version"));
  mso.extend(tstr("1.0"));
  mso.extend(tstr("validityInfo"));
  mso.extend_from_slice(&validity_info);
  let value_digests_key_offset_in_mso = mso.len();
  mso.extend(tstr("valueDigests"));
  mso.push(0xa1); // one namespace
  mso.extend(tstr(NAMESPACE));
  mso.extend(head(5, n as u64)); // the digestID map header
  let region_start_in_mso = mso.len();
  mso.extend_from_slice(&region);
  let device_key_info_offset_in_mso = mso.len();
  mso.extend(tstr("deviceKeyInfo"));
  mso.extend_from_slice(&device_key_info);
  mso.extend(tstr("digestAlgorithm"));
  mso.extend(tstr("SHA-256"));

  // ---- Sig_structure = ["Signature1", protected, external_aad, payload]
  let mut sig = vec![0x84];
  sig.extend(tstr("Signature1"));
  sig.extend(bstr(&[0xa1, 0x01, 0x26])); // protected: {1: -7} (ES256)
  sig.extend(bstr(&[])); // external_aad
  let payload = tag24(&mso);
  let payload_header_len = head(2, payload.len() as u64).len();
  let mso_base = sig.len() + payload_header_len + 2 /* d8 18 */ + head(2, mso.len() as u64).len();
  sig.extend(bstr(&payload));

  let claims: Vec<FixtureClaim> = items
    .iter()
    .map(|(id, element_id, bytes, _)| FixtureClaim {
      element_identifier: element_id.to_string(),
      digest_id: *id,
      digest_offset: region_start_in_mso + mso_base + digest_offset_in_region[id],
      issuer_signed_item_bytes_len: bytes.len(),
      issuer_signed_item_bytes_hex: hex::encode(bytes),
    })
    .collect();

  // Ground-truth check: the recorded offsets really do point at the
  // digests. A fixture that lies about its own landmarks would make the
  // prototype's binding look sound when it isn't.
  for (claim, (_, _, _, digest)) in claims.iter().zip(items.iter()) {
    assert_eq!(
      &sig[claim.digest_offset..claim.digest_offset + 32],
      digest.as_slice(),
      "{}: recorded digest_offset does not point at its digest",
      claim.element_identifier
    );
    assert_eq!(&sig[claim.digest_offset - 2..claim.digest_offset], &[0x58, 0x20], "digest must be preceded by bstr(32) header");
  }
  let region_start = region_start_in_mso + mso_base;
  let device_key_info_offset = device_key_info_offset_in_mso + mso_base;
  assert_eq!(&sig[device_key_info_offset..device_key_info_offset + 1], &[0x6d], "deviceKeyInfo key header");
  assert_eq!(&sig[device_key_info_offset..device_key_info_offset + 14], b"\x6ddeviceKeyInfo", "deviceKeyInfo anchor");
  assert_eq!(device_key_info_offset - region_start, region.len());

  let device_key_x_offset = device_key_info_offset + tstr("deviceKeyInfo").len() + device_key_x_offset_in_dki;
  assert_eq!(&sig[device_key_x_offset..device_key_x_offset + 32], &device_x, "recorded deviceKey x offset");

  let z: [u8; 32] = Sha256::digest(&sig).into();
  let mut key_bytes = [0u8; 32];
  rng.fill_bytes(&mut key_bytes);
  let sk = SigningKey::from_bytes(&key_bytes.into()).expect("valid scalar");
  let vk = VerifyingKey::from(&sk);
  let signature: Signature = sk.sign_prehash(&z).expect("sign_prehash");
  let order = zk_cred_vega::p256_ecc::p256_order();
  let s = num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, &signature.s().to_bytes());
  let s_inv = s.modpow(&(order.clone() - num_bigint::BigInt::from(2)), &order);
  let enc = vk.to_encoded_point(false);

  let fixture = PidFixture {
    description: description.to_string(),
    doc_type: DOC_TYPE.to_string(),
    namespace: NAMESPACE.to_string(),
    signed_ts: signed_ts.to_string(),
    valid_from_ts: valid_from_ts.to_string(),
    valid_until_ts: valid_until_ts.to_string(),
    sig_structure_len: sig.len(),
    sig_structure_hex: hex::encode(&sig),
    landmarks: Landmarks {
      value_digests_key_offset: value_digests_key_offset_in_mso + mso_base,
      region_start,
      region_len: region.len(),
      device_key_info_offset,
      device_key_x_offset: device_key_info_offset + tstr("deviceKeyInfo").len() + device_key_x_offset_in_dki,
      doc_type_offset: doc_type_offset_in_mso + mso_base,
      num_entries: n,
    },
    target_element: "birth_date".to_string(),
    forged_item_bytes_hex: forged.as_ref().map(hex::encode),
    forged_item_digest_offset: forged.as_ref().map(|_| device_key_x_offset),
    claims,
    ecdsa_witness: EcdsaWitness {
      qx_hex: hex::encode(enc.x().expect("x")),
      qy_hex: hex::encode(enc.y().expect("y")),
      r_hex: hex::encode(signature.r().to_bytes()),
      s_hex: hex::encode(signature.s().to_bytes()),
      s_inv_hex: hex::encode(s_inv.to_bytes_be().1),
    },
  };

  let out = std::path::Path::new("test-vectors").join(format!("{name}.json"));
  let json = serde_json::to_string_pretty(&fixture).expect("serialize");
  std::fs::File::create(&out).and_then(|mut f| f.write_all(json.as_bytes())).expect("write");
  println!(
    "wrote {} -- Sig_structure {} bytes, {} entries, region {}..{} ({} bytes)",
    out.display(),
    sig.len(),
    n,
    region_start,
    device_key_info_offset,
    region.len()
  );
}

fn main() {
  std::fs::create_dir_all("test-vectors").expect("create test-vectors dir");
  gen_pid(
    DigestIdProfile::Sequential,
    "pid_arf18_sequential",
    "Full 34-attribute EUDI PID (eu.europa.ec.eudi.pid.1), digestIDs assigned by a \
     per-namespace counter as our own MSOBuilder does. Real canonical CBOR, real \
     2 kB portrait, real ECDSA-P256 signature over the real Sig_structure.",
  );
  gen_pid(
    DigestIdProfile::PlantedDeviceKey,
    "pid_arf18_planted_device_key",
    "Adversarial: a real, correctly issued 34-attribute PID whose holder chose a deviceKey \
     x-coordinate equal to SHA-256 of a birth_date item the issuer never signed, claiming a \
     birthdate of 2015-01-01. The forged item's digest really is present in the signed bytes, \
     so an offset proof that only checks \"this digest appears somewhere\" accepts it.",
  );
  gen_pid(
    DigestIdProfile::Random,
    "pid_arf18_random",
    "Full 34-attribute EUDI PID (eu.europa.ec.eudi.pid.1), digestIDs drawn uniformly \
     from the full legal range (< 2^31) as ISO 18013-5 §9.1.2.4 directs issuers to do. \
     Nearly all 5-byte digestID encodings: the largest realistic MSO, and the one the \
     circuit must be sized for.",
  );
}
