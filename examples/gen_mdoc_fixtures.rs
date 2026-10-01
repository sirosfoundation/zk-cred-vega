//! Generates real-shaped, spec-conformant mdoc fixtures for the
//! offset-based age-proof circuit: an **mDL**, an **EU PID 1.8**, and a
//! **Photo ID**.
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

use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::Write;


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


// ---- Document specifications ----------------------------------------

/// One namespace's worth of elements.
struct Ns {
  name: &'static str,
  elements: Vec<(&'static str, Vec<u8>)>,
}

struct DocSpec {
  name: &'static str,
  doc_type: &'static str,
  /// Namespaces, in the order given; `canonical_sort` fixes the encoding
  /// order so this list's order does not matter.
  namespaces: Vec<Ns>,
  /// Which namespace holds `birth_date` — the one the circuit targets.
  target_ns: &'static str,
  /// `random` salt length. ISO 18013-5 requires >= 16; our own
  /// `MSOBuilder` emits 16 to stay inside Longfellow's item ceiling,
  /// while 32 is what the zk-cred-vega fixtures have always used. Both
  /// are real, and the circuit has to accept either.
  salt_bytes: usize,
  /// Whether `birth_date`'s value is a bare `full-date` or the map form
  /// ISO/IEC 23220-2 §6.3.1.1.3 allows.
  photo_id_date_map: bool,
  /// Set the holder's `deviceKey` x-coordinate to the SHA-256 of a
  /// fabricated `birth_date` item. An mdoc MSO carries no attribute
  /// values -- only digests -- so this is the one 32-byte window in the
  /// signed bytes whose content the *holder* chooses, and therefore the
  /// one place a digest can be planted. No private key is needed,
  /// because an age proof never exercises device authentication.
  plant_forged_digest_in_device_key: bool,
  description: &'static str,
}

/// `birth date = { "birth_date": full-date }` — ISO/IEC 23220-2's
/// wrapped form, used by Photo ID.
fn birth_date_map(d: &str) -> Vec<u8> {
  let mut v = vec![0xa1];
  v.extend(tstr("birth_date"));
  v.extend(full_date(d));
  v
}

const BIRTH_DATE: &str = "1996-01-30";

/// The 35 `org.iso.18013.5.1` elements our own mDL schema declares
/// (`sirosid-dev/fixtures/vc-metadata/mdl.mdoc.json`).
fn mdl_elements(portrait: &[u8], seed: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
  vec![
    ("family_name", tstr("Mirren")),
    ("given_name", tstr("Helen")),
    ("birth_date", full_date(BIRTH_DATE)),
    ("issue_date", full_date("2026-04-28")),
    ("expiry_date", full_date("2031-04-28")),
    ("issuing_country", tstr("SE")),
    ("issuing_authority", tstr("Transportstyrelsen")),
    ("document_number", tstr("SE-DL-100")),
    ("portrait", bstr(portrait)),
    ("un_distinguishing_sign", tstr("S")),
    ("driving_privileges", array(&[{
      let mut m = head(5, 3);
      m.extend(tstr("vehicle_category_code"));
      m.extend(tstr("B"));
      m.extend(tstr("issue_date"));
      m.extend(full_date("2016-05-01"));
      m.extend(tstr("expiry_date"));
      m.extend(full_date("2031-04-28"));
      m
    }])),
    ("administrative_number", tstr("adm-100")),
    ("sex", uint(2)),
    ("height", uint(170)),
    ("weight", uint(65)),
    ("eye_colour", tstr("blue")),
    ("hair_colour", tstr("brown")),
    ("birth_place", tstr("Stockholm, SE")),
    ("resident_address", tstr("Tulegatan 11, Stockholm")),
    ("portrait_capture_date", tdate("2026-04-28T10:51:58Z")),
    ("age_in_years", uint(30)),
    ("age_birth_year", uint(1996)),
    ("age_over_18", boolean(true)),
    ("age_over_21", boolean(true)),
    ("age_over_65", boolean(false)),
    ("issuing_jurisdiction", tstr("SE-AB")),
    ("nationalities", array(&[tstr("SE")])),
    ("resident_city", tstr("Stockholm")),
    ("resident_state", tstr("Stockholm")),
    ("resident_postal_code", tstr("11353")),
    ("resident_country", tstr("SE")),
    ("family_name_national_character", tstr("Mirren")),
    ("given_name_national_character", tstr("Helen")),
    ("signature_usual_mark", bstr(&[0x89, 0x50, 0x4e, 0x47])),
    ("pseudonym_seed", bstr(seed)),
  ]
}

/// The 34 `eu.europa.ec.eudi.pid.1` elements our issuer declares.
fn pid_elements(portrait: &[u8], seed: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
  vec![
    ("family_name", tstr("Mirren")),
    ("given_name", tstr("Helen")),
    ("birth_date", full_date(BIRTH_DATE)),
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
    ("pseudonym_seed", bstr(seed)),
  ]
}

/// ISO/IEC 23220-4 Annex C Photo ID, as multipaz's `PhotoID.kt` declares
/// it: 27 elements in `org.iso.23220.1` (including `birth_date`), 11 in
/// `org.iso.23220.photoid.1`, 18 in `org.iso.23220.dtc.1`.
fn photo_id_namespaces(portrait: &[u8], date_map: bool) -> Vec<Ns> {
  let bd = if date_map { birth_date_map(BIRTH_DATE) } else { full_date(BIRTH_DATE) };
  vec![
    Ns {
      name: "org.iso.23220.1",
      elements: vec![
        ("family_name", tstr("Mirren")),
        ("family_name_viz", tstr("MIRREN")),
        ("given_name", tstr("Helen")),
        ("given_name_viz", tstr("HELEN")),
        ("birth_date", bd),
        ("portrait", bstr(portrait)),
        ("issue_date", full_date("2026-04-28")),
        ("expiry_date", full_date("2031-04-28")),
        ("issuing_authority_unicode", tstr("Polismyndigheten")),
        ("issuing_country", tstr("SE")),
        ("age_in_years", uint(30)),
        ("age_over_18", boolean(true)),
        ("age_birth_year", uint(1996)),
        ("portrait_capture_date", tdate("2026-04-28T10:51:58Z")),
        ("birthplace", tstr("Stockholm, SE")),
        ("name_at_birth", tstr("Mirren")),
        ("resident_address", tstr("Tulegatan 11")),
        ("resident_city", tstr("Stockholm")),
        ("resident_postal_code", tstr("11353")),
        ("resident_country", tstr("SE")),
        ("resident_city_latin1", tstr("Stockholm")),
        ("sex", uint(2)),
        ("nationality", tstr("SE")),
        ("document_number", tstr("SE-PID-100")),
        ("issuing_subdivision", tstr("SE-AB")),
        ("family_name_latin1", tstr("Mirren")),
        ("given_name_latin1", tstr("Helen")),
      ],
    },
    Ns {
      name: "org.iso.23220.photoid.1",
      elements: vec![
        ("person_id", tstr("pid-100")),
        ("birth_country", tstr("SE")),
        ("birth_state", tstr("Stockholm")),
        ("birth_city", tstr("Stockholm")),
        ("administrative_number", tstr("adm-100")),
        ("resident_street", tstr("Tulegatan")),
        ("resident_house_number", tstr("11")),
        ("travel_document_type", tstr("P")),
        ("travel_document_number", tstr("SE1234567")),
        ("travel_document_mrz", tstr("P<SWEMIRREN<<HELEN<<<<<<<<<<<<<<<<<<<<<<<<<<")),
        ("resident_state", tstr("Stockholm")),
      ],
    },
    Ns {
      name: "org.iso.23220.dtc.1",
      elements: vec![
        ("version", tstr("1.0")),
        ("sod", bstr(&[0x30, 0x82, 0x01, 0x00])),
        ("dg1", bstr(&[0x61, 0x5b])),
        ("dg2", bstr(&[0x75, 0x82])),
        ("dg3", bstr(&[0x63, 0x10])),
        ("dg4", bstr(&[0x76, 0x10])),
        ("dg5", bstr(&[0x65, 0x10])),
        ("dg6", bstr(&[0x66, 0x10])),
        ("dg7", bstr(&[0x67, 0x10])),
        ("dg8", bstr(&[0x68, 0x10])),
        ("dg9", bstr(&[0x69, 0x10])),
        ("dg10", bstr(&[0x6a, 0x10])),
        ("dg11", bstr(&[0x6b, 0x10])),
        ("dg12", bstr(&[0x6c, 0x10])),
        ("dg13", bstr(&[0x6d, 0x10])),
        ("dg14", bstr(&[0x6e, 0x10])),
        ("dg15", bstr(&[0x6f, 0x10])),
        ("dg16", bstr(&[0x70, 0x10])),
      ],
    },
  ]
}

// ---- Fixture shape --------------------------------------------------

#[derive(Serialize)]
struct FixtureClaim {
  namespace: String,
  element_identifier: String,
  digest_id: u32,
  digest_offset: usize,
  issuer_signed_item_bytes_len: usize,
  issuer_signed_item_bytes_hex: String,
}

#[derive(Serialize)]
struct Landmarks {
  value_digests_key_offset: usize,
  namespace_key_offset: usize,
  region_start: usize,
  region_len: usize,
  device_key_info_offset: usize,
  device_key_x_offset: usize,
  doc_type_offset: usize,
  num_namespaces: usize,
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
struct Fixture {
  description: String,
  doc_type: String,
  namespace: String,
  salt_bytes: usize,
  date_encoding: String,
  element_value_key_offset: usize,
  sig_structure_len: usize,
  sig_structure_hex: String,
  landmarks: Landmarks,
  target_element: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  forged_item_bytes_hex: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  forged_item_digest_offset: Option<usize>,
  claims: Vec<FixtureClaim>,
  ecdsa_witness: EcdsaWitness,
}

/// One `IssuerSignedItem`, tag(24)-wrapped, canonical key order
/// (`random`(6) < `digestID`(8) < `elementValue`(12) <
/// `elementIdentifier`(17)), with a salt of the caller's chosen length.
fn issuer_signed_item(digest_id: u32, random: &[u8], element_id: &str, value: &[u8]) -> Vec<u8> {
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

fn gen_doc(spec: DocSpec) {
  use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey, VerifyingKey};
  let mut rng = rand::thread_rng();

  // Build every item, per namespace, with a digestID counter per
  // namespace (what our own MSOBuilder does).
  let mut all_claims: Vec<FixtureClaim> = Vec::new();
  /// One built namespace: its name, its canonically sorted
  /// `digestID -> bstr(32)` entries, and the items behind them.
  struct BuiltNs {
    name: &'static str,
    entries: Vec<(Vec<u8>, Vec<u8>)>,
    items: Vec<BuiltItem>,
  }
  struct BuiltItem {
    digest_id: u32,
    digest: [u8; 32],
    element_id: &'static str,
    bytes: Vec<u8>,
  }
  let mut ns_regions: Vec<BuiltNs> = Vec::new();

  for ns in &spec.namespaces {
    let mut entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut items: Vec<BuiltItem> = Vec::new();
    for (i, (element_id, value)) in ns.elements.iter().enumerate() {
      let digest_id = i as u32;
      let mut salt = vec![0u8; spec.salt_bytes];
      rng.fill_bytes(&mut salt);
      let bytes = issuer_signed_item(digest_id, &salt, element_id, value);
      let digest: [u8; 32] = Sha256::digest(&bytes).into();
      entries.push((uint(digest_id as u64), bstr(&digest)));
      items.push(BuiltItem { digest_id, digest, element_id, bytes });
    }
    canonical_sort(&mut entries);
    ns_regions.push(BuiltNs { name: ns.name, entries, items });
  }

  // `valueDigests` namespaces sort canonically by their tstr keys.
  let mut ns_order: Vec<usize> = (0..ns_regions.len()).collect();
  ns_order.sort_by_key(|&i| (ns_regions[i].name.len(), ns_regions[i].name));

  let signed_ts = "2026-10-01T00:00:00Z";
  let mut device_x = [0u8; 32];
  let mut device_y = [0u8; 32];
  rng.fill_bytes(&mut device_x);
  rng.fill_bytes(&mut device_y);

  let forged = if spec.plant_forged_digest_in_device_key {
    let mut salt = vec![0u8; spec.salt_bytes];
    rng.fill_bytes(&mut salt);
    let value = if spec.photo_id_date_map { birth_date_map("2015-01-01") } else { full_date("2015-01-01") };
    let bytes = issuer_signed_item(2, &salt, "birth_date", &value);
    device_x = Sha256::digest(&bytes).into();
    Some(bytes)
  } else {
    None
  };

  let validity_info = {
    let mut v = vec![0xa3];
    for (k, t) in [("signed", signed_ts), ("validFrom", signed_ts), ("validUntil", "2031-10-01T00:00:00Z")] {
      v.extend(tstr(k));
      v.extend(tdate(t));
    }
    v
  };

  let mut mso = vec![0xa6];
  let doc_type_offset_in_mso = mso.len();
  mso.extend(tstr("docType"));
  mso.extend(tstr(spec.doc_type));
  mso.extend(tstr("version"));
  mso.extend(tstr("1.0"));
  mso.extend(tstr("validityInfo"));
  mso.extend_from_slice(&validity_info);

  let value_digests_key_offset_in_mso = mso.len();
  mso.extend(tstr("valueDigests"));
  mso.extend(head(5, ns_regions.len() as u64));

  let mut target_ns_key_in_mso = 0usize;
  let mut target_region_start_in_mso = 0usize;
  let mut target_region_len = 0usize;
  let mut target_num_entries = 0usize;
  // digest offsets, relative to the MSO, keyed by (ns, digest_id)
  let mut digest_offsets: std::collections::HashMap<(&str, u32), usize> = Default::default();

  for &i in &ns_order {
    let BuiltNs { name, entries, .. } = &ns_regions[i];
    let ns_key_at = mso.len();
    mso.extend(tstr(name));
    mso.extend(head(5, entries.len() as u64));
    let region_at = mso.len();
    for (k, v) in entries {
      mso.extend_from_slice(k);
      mso.extend_from_slice(v);
      let id = decode_uint(k);
      digest_offsets.insert((name, id), mso.len() - 32);
    }
    if *name == spec.target_ns {
      target_ns_key_in_mso = ns_key_at;
      target_region_start_in_mso = region_at;
      target_region_len = mso.len() - region_at;
      target_num_entries = entries.len();
    }
  }

  let device_key_info_offset_in_mso = mso.len();
  mso.extend(tstr("deviceKeyInfo"));
  let device_key_x_offset_in_mso;
  {
    let mut cose = vec![0xa4];
    cose.extend(vec![0x01, 0x02, 0x20, 0x01, 0x21]);
    cose.extend(head(2, 32));
    let mut v = vec![0xa1];
    v.extend(tstr("deviceKey"));
    device_key_x_offset_in_mso = mso.len() + 1 + tstr("deviceKey").len() + cose.len();
    v.extend(cose);
    v.extend_from_slice(&device_x);
    v.push(0x22);
    v.extend(bstr(&device_y));
    mso.extend(v);
  }
  mso.extend(tstr("digestAlgorithm"));
  mso.extend(tstr("SHA-256"));

  // Sig_structure = ["Signature1", protected, external_aad, payload]
  let mut sig = vec![0x84];
  sig.extend(tstr("Signature1"));
  sig.extend(bstr(&[0xa1, 0x01, 0x26]));
  sig.extend(bstr(&[]));
  let payload = tag24(&mso);
  let mso_base = sig.len() + head(2, payload.len() as u64).len() + 2 + head(2, mso.len() as u64).len();
  sig.extend(bstr(&payload));

  for BuiltNs { name, items, .. } in &ns_regions {
    for BuiltItem { digest_id, digest, element_id, bytes } in items {
      let off = mso_base + digest_offsets[&(*name, *digest_id)];
      assert_eq!(&sig[off..off + 32], digest.as_slice(), "{name}/{element_id}: digest offset");
      assert_eq!(&sig[off - 2..off], &[0x58, 0x20], "digest must follow a bstr(32) header");
      all_claims.push(FixtureClaim {
        namespace: name.to_string(),
        element_identifier: element_id.to_string(),
        digest_id: *digest_id,
        digest_offset: off,
        issuer_signed_item_bytes_len: bytes.len(),
        issuer_signed_item_bytes_hex: hex::encode(bytes),
      });
    }
  }

  let device_key_x_offset = mso_base + device_key_x_offset_in_mso;
  assert_eq!(&sig[device_key_x_offset..device_key_x_offset + 32], &device_x, "deviceKey x landmark");
  let device_key_info_offset = mso_base + device_key_info_offset_in_mso;
  assert_eq!(&sig[device_key_info_offset..device_key_info_offset + 14], b"\x6ddeviceKeyInfo", "deviceKeyInfo anchor");

  // The circuit's own offset arithmetic must agree with these bytes.
  let target = all_claims
    .iter()
    .find(|c| c.namespace == spec.target_ns && c.element_identifier == "birth_date")
    .expect("every document here carries a birth_date");
  let item = hex::decode(&target.issuer_signed_item_bytes_hex).unwrap();
  let width = zk_cred_vega::cbor_uint::encode_cbor_uint(target.digest_id).len();
  let value_key_offset = zk_cred_vega::mdoc_age::element_value_key_offset(spec.salt_bytes, width);
  assert_eq!(
    &item[value_key_offset..value_key_offset + 13],
    b"\x6celementValue",
    "{}: element_value_key_offset disagrees with the real item bytes",
    spec.name
  );

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

  let fixture = Fixture {
    description: spec.description.to_string(),
    doc_type: spec.doc_type.to_string(),
    namespace: spec.target_ns.to_string(),
    salt_bytes: spec.salt_bytes,
    date_encoding: if spec.photo_id_date_map { "PhotoIdMap".into() } else { "Bare".into() },
    element_value_key_offset: value_key_offset,
    sig_structure_len: sig.len(),
    sig_structure_hex: hex::encode(&sig),
    landmarks: Landmarks {
      value_digests_key_offset: mso_base + value_digests_key_offset_in_mso,
      namespace_key_offset: mso_base + target_ns_key_in_mso,
      region_start: mso_base + target_region_start_in_mso,
      region_len: target_region_len,
      device_key_info_offset,
      device_key_x_offset,
      doc_type_offset: mso_base + doc_type_offset_in_mso,
      num_namespaces: ns_regions.len(),
      num_entries: target_num_entries,
    },
    target_element: "birth_date".to_string(),
    forged_item_bytes_hex: forged.as_ref().map(hex::encode),
    forged_item_digest_offset: forged.as_ref().map(|_| device_key_x_offset),
    claims: all_claims,
    ecdsa_witness: EcdsaWitness {
      qx_hex: hex::encode(enc.x().expect("x")),
      qy_hex: hex::encode(enc.y().expect("y")),
      r_hex: hex::encode(signature.r().to_bytes()),
      s_hex: hex::encode(signature.s().to_bytes()),
      s_inv_hex: hex::encode(s_inv.to_bytes_be().1),
    },
  };

  let out = std::path::Path::new("test-vectors").join(format!("{}.json", spec.name));
  std::fs::File::create(&out)
    .and_then(|mut f| f.write_all(serde_json::to_string_pretty(&fixture).unwrap().as_bytes()))
    .expect("write");
  println!(
    "{:<24} {:>5}B  {} ns, {} entries in {}  salt={}B  value_key@{}  {}",
    spec.name,
    fixture.sig_structure_len,
    fixture.landmarks.num_namespaces,
    fixture.landmarks.num_entries,
    spec.target_ns,
    spec.salt_bytes,
    value_key_offset,
    fixture.date_encoding
  );
}

fn decode_uint(k: &[u8]) -> u32 {
  match k[0] {
    b if b < 24 => b as u32,
    0x18 => k[1] as u32,
    0x19 => u16::from_be_bytes([k[1], k[2]]) as u32,
    0x1a => u32::from_be_bytes([k[1], k[2], k[3], k[4]]),
    other => panic!("unexpected uint head {other:#04x}"),
  }
}

fn main() {
  std::fs::create_dir_all("test-vectors").expect("create test-vectors dir");
  let mut rng = rand::thread_rng();
  let mut portrait = vec![0u8; 2048];
  rng.fill_bytes(&mut portrait);
  portrait[..3].copy_from_slice(&[0xff, 0xd8, 0xff]);
  let mut seed = [0u8; 32];
  rng.fill_bytes(&mut seed);

  gen_doc(DocSpec {
    name: "mdl_iso18013",
    doc_type: "org.iso.18013.5.1.mDL",
    namespaces: vec![Ns { name: "org.iso.18013.5.1", elements: mdl_elements(&portrait, &seed) }],
    target_ns: "org.iso.18013.5.1",
    salt_bytes: 16,
    photo_id_date_map: false,
    plant_forged_digest_in_device_key: false,
    description: "ISO 18013-5 mDL, 35 elements, 16-byte salts (what our own MSOBuilder emits). \
                  Its namespace is neither equal to nor the same length as its docType."
      ,
  });

  gen_doc(DocSpec {
    name: "pid_arf18",
    doc_type: "eu.europa.ec.eudi.pid.1",
    namespaces: vec![Ns { name: "eu.europa.ec.eudi.pid.1", elements: pid_elements(&portrait, &seed) }],
    target_ns: "eu.europa.ec.eudi.pid.1",
    salt_bytes: 32,
    photo_id_date_map: false,
    plant_forged_digest_in_device_key: false,
    description: "EU PID ARF 1.8, 34 elements, 32-byte salts. docType and namespace coincide.",
  });

  gen_doc(DocSpec {
    name: "photo_id_23220",
    doc_type: "org.iso.23220.photoid.1",
    namespaces: photo_id_namespaces(&portrait, true),
    target_ns: "org.iso.23220.1",
    salt_bytes: 16,
    photo_id_date_map: true,
    plant_forged_digest_in_device_key: false,
    description: "ISO/IEC 23220-4 Annex C Photo ID: three namespaces, and birth_date lives in \
                  org.iso.23220.1, which sorts FIRST -- so its entries are followed by another \
                  namespace, not by deviceKeyInfo. Its elementValue uses the ISO 23220-2 map form.",
  });

  gen_doc(DocSpec {
    name: "mdl_planted_device_key",
    doc_type: "org.iso.18013.5.1.mDL",
    namespaces: vec![Ns { name: "org.iso.18013.5.1", elements: mdl_elements(&portrait, &seed) }],
    target_ns: "org.iso.18013.5.1",
    salt_bytes: 16,
    photo_id_date_map: false,
    plant_forged_digest_in_device_key: true,
    description: "Adversarial: a correctly issued mDL whose holder chose a deviceKey x-coordinate \
                  equal to SHA-256 of a birth_date item the issuer never signed, claiming 2015-01-01. \
                  The forged item's digest really is in the signed bytes, so an offset proof that only \
                  checks \"this digest appears somewhere\" accepts it.",
  });

  gen_doc(DocSpec {
    name: "photo_id_23220_bare_date",
    doc_type: "org.iso.23220.photoid.1",
    namespaces: photo_id_namespaces(&portrait, false),
    target_ns: "org.iso.23220.1",
    salt_bytes: 32,
    photo_id_date_map: false,
    plant_forged_digest_in_device_key: false,
    description: "Same Photo ID, but with a bare full-date birth_date and 32-byte salts -- the \
                  other half of the encoding/salt matrix.",
  });
}
