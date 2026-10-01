//! One circuit, three real document types.
//!
//! The offset architecture's claim is that a single circuit can prove an
//! age predicate over any ISO 18013-5-shaped credential carrying a
//! `birth_date`, for roughly the cost of hashing it once. These tests
//! check that against real-shaped mDL, EU PID 1.8 and ISO/IEC 23220-4
//! Photo ID fixtures, and check the structural binding that makes the
//! shape sound in the first place.
//!
//! Regenerate the fixtures with
//! `cargo run --release --example gen_mdoc_fixtures`.

use bellpepper_core::test_cs::TestConstraintSystem;
use ff::PrimeField;
use num_bigint::{BigInt, Sign};
use sha2::{Digest, Sha256};
use zk_cred_vega::mdoc_age::{synthesize, DateEncoding, MdocAgeWitness};
use zk_cred_vega::offset_bind::Landmarks;
use zk_cred_vega::Engine_;

type Scalar = <Engine_ as vega_prover::traits::Engine>::Scalar;

/// A fixed threshold, deliberately not derived from the clock: eighteen
/// years before the fixtures' issuance date, so these tests assert the
/// same thing whenever they run. A real verifier computes this from
/// today's date; a test that did the same would change behaviour as the
/// fixtures aged and start passing or failing for the wrong reason.
const CUTOFF: &[u8; 10] = b"2008-10-01";

/// Every document type the circuit is meant to serve.
const ALL_DOCS: [&str; 4] = ["mdl_iso18013", "pid_arf18", "photo_id_23220", "photo_id_23220_bare_date"];

struct Loaded {
  witness: MdocAgeWitness,
  ecdsa: zk_cred_vega::ecdsa::EcdsaP256Witness<Scalar>,
  json: serde_json::Value,
}

fn load(name: &str) -> Loaded {
  let raw = std::fs::read_to_string(format!("test-vectors/{name}.json"))
    .expect("fixture missing — run `cargo run --release --example gen_mdoc_fixtures`");
  let json: serde_json::Value = serde_json::from_str(&raw).unwrap();

  let sig = hex::decode(json["sig_structure_hex"].as_str().unwrap()).unwrap();
  let lm = &json["landmarks"];
  let target_ns = json["namespace"].as_str().unwrap();
  let target = json["claims"]
    .as_array()
    .unwrap()
    .iter()
    .find(|c| c["element_identifier"] == "birth_date" && c["namespace"] == target_ns)
    .expect("every document here carries a birth_date");

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

  Loaded {
    witness: MdocAgeWitness {
      sig_structure: sig,
      landmarks: Landmarks {
        value_digests_key: lm["value_digests_key_offset"].as_u64().unwrap() as usize,
        namespace_key: lm["namespace_key_offset"].as_u64().unwrap() as usize,
        region_start: lm["region_start"].as_u64().unwrap() as usize,
        device_key_info: lm["device_key_info_offset"].as_u64().unwrap() as usize,
        doc_type_key: lm["doc_type_offset"].as_u64().unwrap() as usize,
      },
      namespace: target_ns.to_string(),
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
    },
    ecdsa,
    json,
  }
}

/// The headline: an mDL, an EU PID and a Photo ID all prove age through
/// the same circuit.
///
/// Each breaks a different assumption the single-document version made.
/// The mDL's namespace is neither equal to nor the same length as its
/// `docType`, and it uses 16-byte salts. The PID uses 32. The Photo ID
/// has three namespaces, keeps `birth_date` in the one that sorts first,
/// and wraps the date in ISO/IEC 23220-2's map form.
#[test]
fn every_document_type_proves_age_through_the_same_circuit() {
  for name in ALL_DOCS {
    let l = load(name);
    let mut cs = TestConstraintSystem::<Scalar>::new();
    let out = synthesize(&mut cs, &l.witness, &l.ecdsa, CUTOFF).unwrap_or_else(|e| panic!("{name}: {e:?}"));
    assert!(cs.is_satisfied(), "{name}: unsatisfied at {:?}", cs.which_is_unsatisfied());
    assert!(out.old_enough.get_value().unwrap(), "{name}: born 1996-01-30, cutoff 2008-10-01");
  }
}

/// And they produce the *same* circuit, not merely a working one.
///
/// This is the property that makes "one circuit" a real claim rather than
/// a figure of speech: a fixed-setup folding system needs one R1CS shape,
/// so if the document type, namespace length, salt length, namespace
/// count or date encoding changed the emitted constraints, each variant
/// would need its own setup and its own published artifact.
#[test]
fn all_document_types_produce_an_identical_circuit_shape() {
  let mut shapes = Vec::new();
  for name in ALL_DOCS {
    let l = load(name);
    let mut cs = TestConstraintSystem::<Scalar>::new();
    synthesize(&mut cs, &l.witness, &l.ecdsa, CUTOFF).expect("synthesis");
    assert!(cs.is_satisfied(), "{name}: unsatisfied");
    shapes.push((name, cs.num_constraints(), cs.num_inputs()));
  }
  let (first, c0, i0) = shapes[0];
  for &(name, c, i) in &shapes[1..] {
    assert_eq!(
      (c, i),
      (c0, i0),
      "{name} emits {c} constraints / {i} inputs but {first} emits {c0} / {i0} — \
       each shape would need its own setup"
    );
  }
}

/// The threshold is a circuit variable, not a constant folded in.
///
/// Regression test for a bug no functional test would have caught: an
/// earlier revision emitted the cutoff's bits as `Boolean::constant`, so
/// the emitted constraints depended on the threshold's bit pattern. Every
/// proof still verified, but each distinct cutoff was a different R1CS —
/// a separate setup per threshold date, which is per day in practice.
#[test]
fn the_circuit_shape_does_not_depend_on_the_cutoff() {
  let l = load("mdl_iso18013");
  let mut shapes = Vec::new();
  for (cutoff, expected) in [(b"2008-10-01", true), (b"1990-01-01", false)] {
    let mut cs = TestConstraintSystem::<Scalar>::new();
    let out = synthesize(&mut cs, &l.witness, &l.ecdsa, cutoff).expect("synthesis");
    assert!(cs.is_satisfied());
    assert_eq!(out.old_enough.get_value().unwrap(), expected);
    shapes.push((cs.num_constraints(), cs.num_inputs()));
  }
  assert_eq!(shapes[0], shapes[1], "two cutoffs produced different shapes");
}

/// The attack the structural binding exists for.
///
/// An mdoc MSO carries no attribute *values*, only digests — so a holder
/// wanting 32 bytes of their own choosing inside the issuer's signed
/// bytes has exactly one place to put them: their `deviceKey`
/// coordinates. No private key is needed, because an age proof never
/// exercises device authentication.
///
/// The fixture is a correctly issued mDL whose holder set `deviceKey.x`
/// to SHA-256 of a `birth_date` item claiming 2015-01-01. That digest
/// really is in the signed bytes and the item really is its preimage, so
/// every check *except* the region binding passes.
#[test]
fn a_digest_planted_in_the_device_key_is_rejected() {
  let l = load("mdl_planted_device_key");
  let forged = hex::decode(l.json["forged_item_bytes_hex"].as_str().expect("adversarial fixture")).unwrap();
  let planted = l.json["forged_item_digest_offset"].as_u64().unwrap() as usize;

  // The premise: the forged item's digest genuinely sits at that offset
  // in bytes the issuer genuinely signed.
  let digest: [u8; 32] = Sha256::digest(&forged).into();
  assert_eq!(&l.witness.sig_structure[planted..planted + 32], digest.as_slice());
  assert!(planted >= l.witness.landmarks.device_key_info, "the plant must land outside the digest region");

  let mut attack = l.witness.clone();
  attack.item_bytes = forged;
  attack.digest_offset = planted;

  let mut cs = TestConstraintSystem::<Scalar>::new();
  let out = synthesize(&mut cs, &attack, &l.ecdsa, CUTOFF).expect("synthesis succeeds — this is a soundness check");
  assert!(!out.old_enough.get_value().unwrap(), "2015-01-01 is after the cutoff");
  let failed = cs.which_is_unsatisfied().expect("the planted digest must not satisfy the circuit");
  assert!(failed.contains("inside the region"), "expected the region range-bind to reject this, got {failed}");
}

/// Rejection is by *location*, not by a mismatched hash.
#[test]
fn the_binding_rejects_by_location_not_by_hash() {
  let l = load("mdl_planted_device_key");
  let mut attack = l.witness.clone();
  attack.digest_offset = l.witness.landmarks.device_key_info - 31;
  let mut cs = TestConstraintSystem::<Scalar>::new();
  let _ = synthesize(&mut cs, &attack, &l.ecdsa, CUTOFF).expect("synthesis");
  assert!(cs.which_is_unsatisfied().is_some(), "a window overrunning the region end must be rejected");
}

/// A Photo ID digest must sit at or after its own namespace's sub-map,
/// not in a namespace that sorts before it.
///
/// This is the lower bound the three-anchor binding adds. `birth_date`
/// lives in `org.iso.23220.1`, which sorts first of three — so for this
/// document the bound is only exercised from the other direction, and
/// pointing before it means pointing at the table header itself.
#[test]
fn a_digest_before_the_namespace_sub_map_is_rejected() {
  let l = load("photo_id_23220");
  let mut attack = l.witness.clone();
  attack.digest_offset = l.witness.landmarks.region_start - 8;
  let mut cs = TestConstraintSystem::<Scalar>::new();
  let _ = synthesize(&mut cs, &attack, &l.ecdsa, CUTOFF).expect("synthesis");
  assert!(cs.which_is_unsatisfied().is_some(), "a digest before the namespace's entries must be rejected");
}

/// The proof is bound to the namespace it names, and to the entry count.
#[test]
fn a_proof_is_bound_to_its_namespace_and_entry_count() {
  for (label, mutate) in [
    ("namespace", Box::new(|w: &mut MdocAgeWitness| w.namespace = "org.iso.18013.5.1".to_string()) as Box<dyn Fn(&mut MdocAgeWitness)>),
    ("entry count", Box::new(|w: &mut MdocAgeWitness| w.num_entries -= 1)),
    ("namespace count", Box::new(|w: &mut MdocAgeWitness| w.num_namespaces += 1)),
  ] {
    let l = load("photo_id_23220");
    let mut w = l.witness.clone();
    mutate(&mut w);
    let mut cs = TestConstraintSystem::<Scalar>::new();
    // Either outcome is a rejection: an anchor literal that cannot
    // match leaves the system unsatisfied, and a shape the binding
    // refuses outright comes back as an error.
    if synthesize(&mut cs, &w, &l.ecdsa, CUTOFF).is_ok() {
      assert!(cs.which_is_unsatisfied().is_some(), "a mismatched {label} must not be provable");
    }
  }
}

/// A prover cannot name a document type the issuer did not sign.
#[test]
fn a_proof_cannot_name_a_doc_type_the_issuer_did_not_sign() {
  let l = load("pid_arf18");
  let mut wrong = l.witness.clone();
  wrong.doc_type = "org.iso.18013.5.1.mDL".to_string();
  let mut cs = TestConstraintSystem::<Scalar>::new();
  match synthesize(&mut cs, &wrong, &l.ecdsa, CUTOFF) {
    Ok(_) => panic!("a docType the issuer did not sign must be rejected"),
    Err(e) => assert!(matches!(e, bellpepper_core::SynthesisError::Unsatisfiable), "got {e:?}"),
  }
}

/// The issuer key and cutoff have to reach the caller, or the statement
/// is empty: `synthesize` verifies the signature against `qx`/`qy`
/// allocated as private witnesses, and if those never become public
/// inputs the proof says only "signed by some key whose private half I
/// hold" — which any prover satisfies with a key made a moment ago.
#[test]
fn the_issuer_key_and_cutoff_reach_the_caller() {
  let l = load("mdl_iso18013");
  let mut cs = TestConstraintSystem::<Scalar>::new();
  let out = synthesize(&mut cs, &l.witness, &l.ecdsa, CUTOFF).expect("synthesis");
  assert!(cs.is_satisfied());
  assert_eq!(out.issuer_qx.get_value().unwrap(), l.ecdsa.qx);
  assert_eq!(out.issuer_qy.get_value().unwrap(), l.ecdsa.qy);
  let recovered: Vec<u8> = out.cutoff.iter().map(|c| c.get_value().unwrap().to_repr().as_ref()[0]).collect();
  assert_eq!(&recovered[..], CUTOFF.as_slice());
}

/// Reading a 16-byte-salt item at the 32-byte offset must fail.
///
/// This is the live bug that broke a real device presentation: the
/// circuit hardcoded the offset for a 32-byte salt, our issuer emits 16,
/// and every claim failed `InvalidSumcheckProof` because the circuit was
/// reading the issuer's bytes at the wrong place. The offset is witnessed
/// now, so the wrong one has to be rejected rather than silently believed.
#[test]
fn an_item_read_at_the_wrong_salt_offset_is_rejected() {
  let l = load("mdl_iso18013"); // 16-byte salts
  assert_eq!(l.witness.element_value_key_offset, 39, "fixture should be the 16-byte-salt layout");
  let mut wrong = l.witness.clone();
  wrong.element_value_key_offset = 56; // where a 32-byte salt would put it
  let mut cs = TestConstraintSystem::<Scalar>::new();
  if synthesize(&mut cs, &wrong, &l.ecdsa, CUTOFF).is_ok() {
    assert!(cs.which_is_unsatisfied().is_some(), "the wrong salt offset must not be provable");
  }
}

/// Malformed witnesses come back as errors, never as panics: this crate
/// is built as `cdylib`/`staticlib` into an Android AAR and a Go cgo
/// binary, where a panic aborts the host process rather than unwinding.
#[test]
fn malformed_witnesses_return_errors_rather_than_panicking() {
  type Corruption = (&'static str, Box<dyn Fn(&mut MdocAgeWitness)>);
  let l = load("pid_arf18");
  let cases: Vec<Corruption> = vec![
    ("Sig_structure over budget", Box::new(|w: &mut MdocAgeWitness| w.sig_structure = vec![0u8; 8192])),
    ("item over budget", Box::new(|w: &mut MdocAgeWitness| w.item_bytes = vec![0u8; 4096])),
    ("inverted region", Box::new(|w: &mut MdocAgeWitness| w.landmarks.device_key_info = w.landmarks.region_start - 1)),
    ("docType landmark past the end", Box::new(|w: &mut MdocAgeWitness| w.landmarks.doc_type_key = usize::MAX - 64)),
    ("too many entries", Box::new(|w: &mut MdocAgeWitness| w.num_entries = 300)),
    ("namespace too long", Box::new(|w: &mut MdocAgeWitness| w.namespace = "n".repeat(300))),
    ("unreachable elementValue offset", Box::new(|w: &mut MdocAgeWitness| w.element_value_key_offset = 7)),
    ("namespace key before the table", Box::new(|w: &mut MdocAgeWitness| w.landmarks.namespace_key = 0)),
  ];
  for (name, mutate) in cases {
    let mut w = l.witness.clone();
    mutate(&mut w);
    let mut cs = TestConstraintSystem::<Scalar>::new();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| synthesize(&mut cs, &w, &l.ecdsa, CUTOFF).map(|_| ())));
    match result {
      Err(_) => panic!("{name}: panicked instead of returning an error"),
      Ok(Ok(())) => panic!("{name}: was accepted, but the witness is malformed"),
      Ok(Err(e)) => assert!(matches!(e, bellpepper_core::SynthesisError::Unsatisfiable), "{name}: got {e:?}"),
    }
  }
}
