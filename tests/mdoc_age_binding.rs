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
use zk_cred_vega::mdoc_age::{synthesize, DateEncoding, DeviceAuthWitness, MdocAgeWitness};
use zk_cred_vega::offset_bind::Landmarks;
use zk_cred_vega::Engine_;

type Scalar = <Engine_ as vega_prover::traits::Engine>::Scalar;

/// A fixed threshold, deliberately not derived from the clock: eighteen
/// years before the fixtures' issuance date, so these tests assert the
/// same thing whenever they run. A real verifier computes this from
/// today's date; a test that did the same would change behaviour as the
/// fixtures aged and start passing or failing for the wrong reason.
const CUTOFF: &[u8; 10] = b"2008-10-01";

/// The verifier's clock. Fixed, like `CUTOFF`, so these tests assert the
/// same thing whenever they run; a real verifier uses its own.
const NOW: &[u8; 20] = b"2026-10-10T12:00:00Z";

/// Every document type the circuit is meant to serve.
/// A stand-in for the digest a verifier computes over
/// `DeviceAuthentication = ["DeviceAuthentication", SessionTranscript,
/// DocType, DeviceNameSpacesBytes]` (ISO 18013-5 §9.1.3.4). Its content
/// does not matter to the circuit; that it is the *verifier's* choice
/// is the whole point.
const SESSION: &[u8; 32] = b"verifier-session-transcript-0001";

const ALL_DOCS: [&str; 4] = ["mdl_iso18013", "pid_arf18", "photo_id_23220", "photo_id_23220_bare_date"];

/// Signs a verifier digest with the holder's device key, the way a
/// wallet's secure element would.
fn sign_device_auth(private_key_hex: &str, digest: &[u8; 32]) -> DeviceAuthWitness {
  use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
  let bytes: [u8; 32] = hex::decode(private_key_hex).unwrap().try_into().unwrap();
  let sk = SigningKey::from_bytes(&bytes.into()).unwrap();
  let sig: Signature = sk.sign_prehash(digest).unwrap();
  let n = zk_cred_vega::p256_ecc::p256_order();
  let s_val = BigInt::from_bytes_be(Sign::Plus, &sig.s().to_bytes());
  DeviceAuthWitness {
    r: BigInt::from_bytes_be(Sign::Plus, &sig.r().to_bytes()),
    s: s_val.clone(),
    s_inv: s_val.modpow(&(n.clone() - BigInt::from(2)), &n),
  }
}

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

  let device_auth = sign_device_auth(json["device_private_key_hex"].as_str().unwrap(), SESSION);

  Loaded {
    witness: MdocAgeWitness {
      sig_structure: sig,
      landmarks: Landmarks {
        value_digests_key: lm["value_digests_key_offset"].as_u64().unwrap() as usize,
      validity_info: lm["validity_info_offset"].as_u64().unwrap() as usize,
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
      device_auth,
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
    let out = synthesize(&mut cs, &l.witness, &l.ecdsa, CUTOFF, NOW, SESSION).unwrap_or_else(|e| panic!("{name}: {e:?}"));
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
    synthesize(&mut cs, &l.witness, &l.ecdsa, CUTOFF, NOW, SESSION).expect("synthesis");
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
    let out = synthesize(&mut cs, &l.witness, &l.ecdsa, cutoff, NOW, SESSION).expect("synthesis");
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
  let out = synthesize(&mut cs, &attack, &l.ecdsa, CUTOFF, NOW, SESSION).expect("synthesis succeeds — this is a soundness check");
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
  let _ = synthesize(&mut cs, &attack, &l.ecdsa, CUTOFF, NOW, SESSION).expect("synthesis");
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
  let _ = synthesize(&mut cs, &attack, &l.ecdsa, CUTOFF, NOW, SESSION).expect("synthesis");
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
    if synthesize(&mut cs, &w, &l.ecdsa, CUTOFF, NOW, SESSION).is_ok() {
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
  match synthesize(&mut cs, &wrong, &l.ecdsa, CUTOFF, NOW, SESSION) {
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
  let out = synthesize(&mut cs, &l.witness, &l.ecdsa, CUTOFF, NOW, SESSION).expect("synthesis");
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
  if synthesize(&mut cs, &wrong, &l.ecdsa, CUTOFF, NOW, SESSION).is_ok() {
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
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| synthesize(&mut cs, &w, &l.ecdsa, CUTOFF, NOW, SESSION).map(|_| ())));
    match result {
      Err(_) => panic!("{name}: panicked instead of returning an error"),
      Ok(Ok(())) => panic!("{name}: was accepted, but the witness is malformed"),
      Ok(Err(e)) => assert!(matches!(e, bellpepper_core::SynthesisError::Unsatisfiable), "{name}: got {e:?}"),
    }
  }
}

// ---- Holder binding, session binding, unlinkability -----------------
//
// The three gaps an external review raised against the r12 circuit. r12
// proved "this issuer signed these claims" and nothing more: it never
// exercised the device key, took no verifier input, and published the
// device key, the validity timestamps and every digestID as public
// values. These tests are what stop any of that recurring here.

/// Possessing the credential's bytes is not enough: you must hold the
/// device private key the issuer bound into it.
///
/// This is the one that matters most. Without it, anyone with a copy of
/// the signed bytes can mint presentations — including a verifier who
/// received an earlier disclosure, who could then impersonate the holder
/// to every other verifier.
#[test]
fn a_presentation_signed_by_the_wrong_device_key_is_rejected() {
  let l = load("mdl_iso18013");
  let attacker_key = "11".repeat(32); // a key the attacker controls, not the holder's

  let mut impersonation = l.witness.clone();
  impersonation.device_auth = sign_device_auth(&attacker_key, SESSION);

  let mut cs = TestConstraintSystem::<Scalar>::new();
  let _ = synthesize(&mut cs, &impersonation, &l.ecdsa, CUTOFF, NOW, SESSION).expect("synthesis");
  assert!(
    cs.which_is_unsatisfied().is_some(),
    "holding the credential's bytes must not be enough to present it"
  );
}

/// A proof is bound to one verifier's session and does not replay.
///
/// The holder signs the verifier's own `DeviceAuthentication` digest, so
/// a proof made for one session fails against any other. r12 took no
/// verifier input at all, which made its proofs replayable verbatim.
#[test]
fn a_proof_does_not_replay_to_a_different_session() {
  let l = load("mdl_iso18013"); // device_auth signed over SESSION
  const OTHER: &[u8; 32] = b"a-different-verifier-session-002";
  assert_ne!(SESSION, OTHER);

  let mut cs = TestConstraintSystem::<Scalar>::new();
  let _ = synthesize(&mut cs, &l.witness, &l.ecdsa, CUTOFF, NOW, OTHER).expect("synthesis");
  assert!(
    cs.which_is_unsatisfied().is_some(),
    "a proof made for one session must not satisfy another"
  );
}

/// The device key never becomes a public value.
///
/// It is the holder binding's *input*, not its output. Publishing it is a
/// stable per-credential identifier that lets any two verifiers link
/// every presentation of that credential — which is exactly what r12 did,
/// alongside the validity timestamps and every digestID.
#[test]
fn the_device_key_is_never_exposed_to_the_verifier() {
  use ff::Field;
  let l = load("mdl_iso18013");
  let json = &l.json;
  let sig = &l.witness.sig_structure;
  let x_at = json["landmarks"]["device_key_x_offset"].as_u64().unwrap() as usize;

  let mut cs = TestConstraintSystem::<Scalar>::new();
  let out = synthesize(&mut cs, &l.witness, &l.ecdsa, CUTOFF, NOW, SESSION).expect("synthesis");
  assert!(cs.is_satisfied());

  // Everything the caller is told to make public.
  let mut exposed: Vec<Scalar> = Vec::new();
  exposed.extend(out.doc_type.iter().map(|n| n.get_value().unwrap()));
  exposed.extend(out.cutoff.iter().map(|n| n.get_value().unwrap()));
  exposed.extend(out.namespace.iter().map(|n| n.get_value().unwrap()));
  exposed.extend(out.device_auth_digest.iter().map(|n| n.get_value().unwrap()));
  exposed.push(out.issuer_qx.get_value().unwrap());
  exposed.push(out.issuer_qy.get_value().unwrap());

  // The device key's two coordinates, and each 16-byte half of them, must
  // appear nowhere in that set.
  for half in 0..4 {
    let bytes = &sig[x_at + half * 16..x_at + half * 16 + 16];
    let mut v = Scalar::ZERO;
    for &b in bytes {
      v = v * Scalar::from(256u64) + Scalar::from(b as u64);
    }
    assert!(!exposed.contains(&v), "a 16-byte half of the device key leaked into the public outputs");
  }

  // And the outputs are only what we intend: docType (2 packs), cutoff
  // (10 bytes), device-auth digest (2 packs), issuer key (2).
  assert_eq!(out.doc_type.len(), 2);
  assert_eq!(out.cutoff.len(), 10);
  assert_eq!(out.device_auth_digest.len(), 2);
  assert_eq!(out.namespace.len(), zk_cred_vega::mdoc_age::NAMESPACE_OUT_BYTES);
  assert_eq!(
    exposed.len(),
    2 + 10 + zk_cred_vega::mdoc_age::NAMESPACE_OUT_BYTES + 2 + 2,
    "the public surface grew — check it is intended"
  );
}

/// CIRCUIT-03: the namespace is part of the accepted statement.
///
/// Without it the verifier learns the document type but not which
/// namespace the `birth_date` came from. A Photo ID carries three, and
/// the region binding only rules out namespaces sorting *before* the
/// claimed one — so a verifier that cannot see this is accepting a
/// weaker statement than it believes.
#[test]
fn the_namespace_is_part_of_the_accepted_statement() {
  use ff::PrimeField;
  for name in ALL_DOCS {
    let l = load(name);
    let mut cs = TestConstraintSystem::<Scalar>::new();
    let out = synthesize(&mut cs, &l.witness, &l.ecdsa, CUTOFF, NOW, SESSION).expect("synthesis");
    assert!(cs.is_satisfied(), "{name}: unsatisfied");
    let got: Vec<u8> = out.namespace.iter().map(|n| n.get_value().unwrap().to_repr().as_ref()[0]).collect();
    let got = String::from_utf8(got.iter().copied().take_while(|&b| b != 0).collect()).unwrap();
    assert_eq!(
      got, l.witness.namespace,
      "{name}: the exposed namespace must be the one the attribute was read from"
    );
  }
  // And it really does distinguish: a Photo ID's birth_date namespace is
  // not its docType, which is exactly the case the omission hid.
  let photo = load("photo_id_23220");
  assert_eq!(photo.witness.namespace, "org.iso.23220.1");
  assert_ne!(photo.witness.namespace, photo.witness.doc_type);
}

/// CIRCUIT-04's behavioural half: the predicate is computed, not assumed.
///
/// The documentation now states that publishing `old_enough` is not
/// enough and the verifier must require it to be 1. This pins the other
/// side of that contract — that the bit really is the comparison's
/// result, so a verifier who does check it learns something true.
#[test]
fn the_age_bit_is_computed_not_assumed() {
  let l = load("mdl_iso18013"); // holder born 1996-01-30
  for (cutoff, expected) in [(b"2008-10-01", true), (b"1990-01-01", false)] {
    let mut cs = TestConstraintSystem::<Scalar>::new();
    let out = synthesize(&mut cs, &l.witness, &l.ecdsa, cutoff, NOW, SESSION).expect("synthesis");
    assert!(cs.is_satisfied(), "unsatisfied at {:?}", cs.which_is_unsatisfied());
    assert_eq!(
      out.old_enough.get_value().unwrap(),
      expected,
      "cutoff {:?} should give {expected}",
      std::str::from_utf8(cutoff).unwrap()
    );
  }
}

// ---- Validity window -------------------------------------------------

/// An expired credential cannot prove age, however well-formed it is.
///
/// The fixture is correctly issued and correctly signed; every binding in
/// this file still holds for it. Only the validity window has passed.
///
/// This is *enforced*, not reported: an expired credential simply has no
/// satisfying witness. Exposing a validity bit instead would have been a
/// second instance of CIRCUIT-04 — a flag the verifier might publish and
/// forget to require.
#[test]
fn an_expired_credential_cannot_prove_age() {
  let l = load("mdl_expired"); // valid 2020-01-01 .. 2021-01-01
  let mut cs = TestConstraintSystem::<Scalar>::new();
  let _ = synthesize(&mut cs, &l.witness, &l.ecdsa, CUTOFF, NOW, SESSION).expect("synthesis");
  let failed = cs.which_is_unsatisfied().expect("an expired credential must not satisfy the circuit");
  assert!(
    failed.contains("has not expired") || failed.contains("validUntil"),
    "expected the expiry check to reject this, got {failed}"
  );
}

/// Nor can one whose validity has not begun.
#[test]
fn a_credential_not_yet_valid_cannot_prove_age() {
  let l = load("mdl_not_yet_valid"); // valid 2040-01-01 .. 2045-01-01
  let mut cs = TestConstraintSystem::<Scalar>::new();
  let _ = synthesize(&mut cs, &l.witness, &l.ecdsa, CUTOFF, NOW, SESSION).expect("synthesis");
  let failed = cs.which_is_unsatisfied().expect("a credential that is not yet valid must be rejected");
  assert!(
    failed.contains("has started") || failed.contains("validFrom"),
    "expected the validFrom check to reject this, got {failed}"
  );
}

/// The same credential is provable while it is live and not afterwards,
/// which shows the check follows the verifier's clock rather than
/// something baked in.
#[test]
fn the_validity_check_follows_the_verifier_clock() {
  let l = load("mdl_expired"); // valid 2020-01-01 .. 2021-01-01
  // A clock inside the window: provable.
  let mut cs = TestConstraintSystem::<Scalar>::new();
  let out = synthesize(&mut cs, &l.witness, &l.ecdsa, CUTOFF, b"2020-06-01T00:00:00Z", SESSION).expect("synthesis");
  assert!(cs.is_satisfied(), "unsatisfied at {:?}", cs.which_is_unsatisfied());
  assert!(out.old_enough.get_value().unwrap());

  // The same credential, a clock after it: not provable.
  let mut cs = TestConstraintSystem::<Scalar>::new();
  let _ = synthesize(&mut cs, &l.witness, &l.ecdsa, CUTOFF, b"2022-01-01T00:00:00Z", SESSION).expect("synthesis");
  assert!(cs.which_is_unsatisfied().is_some(), "past validUntil must not be provable");
}

/// The verifier's clock is part of the accepted statement.
///
/// Without it a prover would choose the instant their credential was
/// checked against, which is the same as not checking expiry at all.
#[test]
fn the_verifier_clock_is_part_of_the_accepted_statement() {
  use ff::PrimeField;
  let l = load("mdl_iso18013");
  let mut cs = TestConstraintSystem::<Scalar>::new();
  let out = synthesize(&mut cs, &l.witness, &l.ecdsa, CUTOFF, NOW, SESSION).expect("synthesis");
  assert!(cs.is_satisfied());
  let got: Vec<u8> = out.now.iter().map(|n| n.get_value().unwrap().to_repr().as_ref()[0]).collect();
  assert_eq!(&got[..], NOW.as_slice());
}
