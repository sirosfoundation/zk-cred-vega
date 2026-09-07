//! What the structural binding is actually worth, against a real EUDI PID.
//!
//! The offset architecture's whole claim is that it can prove things about
//! a 34-attribute credential for roughly the cost of hashing it once. The
//! risk it takes on is that "this digest appears in the signed bytes" is a
//! far weaker statement than "this digest is one of the issuer's
//! `valueDigests` entries", and the gap between them is exploitable.
//!
//! These tests exercise that gap end to end using
//! `test-vectors/pid_arf18_*.json` (regenerate with
//! `cargo run --release --example gen_pid_fixture`).

use zk_cred_vega::offset_bind::Landmarks;
use zk_cred_vega::pid_age::{synthesize, PidAgeWitness};
use zk_cred_vega::Engine_;

use bellpepper_core::test_cs::TestConstraintSystem;
use num_bigint::{BigInt, Sign};
use sha2::{Digest, Sha256};
use ff::PrimeField;

type Scalar = <Engine_ as vega_prover::traits::Engine>::Scalar;

/// A fixed threshold date, deliberately not derived from the clock: it is
/// eighteen years before the fixtures' issuance date, so these tests
/// assert the same thing whenever they run. A real verifier computes this
/// from today's date; a test that did the same would change behaviour as
/// the fixtures aged and start passing or failing for the wrong reason.
const CUTOFF: &[u8; 10] = b"2008-09-04";

struct Loaded {
  witness: PidAgeWitness,
  ecdsa: zk_cred_vega::ecdsa::EcdsaP256Witness<Scalar>,
  json: serde_json::Value,
}

fn load(name: &str) -> Loaded {
  let raw = std::fs::read_to_string(format!("test-vectors/{name}.json"))
    .expect("fixture missing — run `cargo run --release --example gen_pid_fixture`");
  let json: serde_json::Value = serde_json::from_str(&raw).unwrap();

  let sig = hex::decode(json["sig_structure_hex"].as_str().unwrap()).unwrap();
  let lm = &json["landmarks"];
  let target = json["claims"]
    .as_array()
    .unwrap()
    .iter()
    .find(|c| c["element_identifier"] == "birth_date")
    .expect("every PID has a birth_date");

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
    witness: PidAgeWitness {
      sig_structure: sig,
      landmarks: Landmarks {
        value_digests_key: lm["value_digests_key_offset"].as_u64().unwrap() as usize,
        region_start: lm["region_start"].as_u64().unwrap() as usize,
        device_key_info: lm["device_key_info_offset"].as_u64().unwrap() as usize,
        doc_type_key: lm["doc_type_offset"].as_u64().unwrap() as usize,
      },
      namespace: json["namespace"].as_str().unwrap().to_string(),
      doc_type: json["doc_type"].as_str().unwrap().to_string(),
      num_entries: lm["num_entries"].as_u64().unwrap() as usize,
      item_bytes: hex::decode(target["issuer_signed_item_bytes_hex"].as_str().unwrap()).unwrap(),
      digest_offset: target["digest_offset"].as_u64().unwrap() as usize,
    },
    ecdsa,
    json,
  }
}

/// Both realistic `digestID` assignment strategies must work: our own
/// issuer's sequential counter, and the full-range random assignment ISO
/// 18013-5 §9.1.2.4 actually asks issuers for. They produce MSOs of
/// different lengths and different per-entry widths, and one circuit has
/// to cover both.
#[test]
fn a_genuine_pid_proves_age_under_both_digest_id_profiles() {
  for name in ["pid_arf18_sequential", "pid_arf18_random"] {
    let l = load(name);
    let mut cs = TestConstraintSystem::<Scalar>::new();
    let out = synthesize(&mut cs, &l.witness, &l.ecdsa, CUTOFF).expect("synthesis");
    assert!(cs.is_satisfied(), "{name}: unsatisfied at {:?}", cs.which_is_unsatisfied());
    assert!(out.old_enough.get_value().unwrap(), "{name}: 1996-01-30 is before the 18-year cutoff");
  }
}

/// A holder born after the cutoff gets a proof that synthesises fine and
/// reports `false` — the circuit computes the predicate, it does not
/// assume it.
#[test]
fn the_predicate_is_computed_not_assumed() {
  let l = load("pid_arf18_random");
  let mut cs = TestConstraintSystem::<Scalar>::new();
  // A cutoff before the holder's birthdate: they are not old enough.
  let out = synthesize(&mut cs, &l.witness, &l.ecdsa, b"1990-01-01").expect("synthesis");
  assert!(cs.is_satisfied(), "unsatisfied at {:?}", cs.which_is_unsatisfied());
  assert!(!out.old_enough.get_value().unwrap(), "born 1996-01-30, cutoff 1990-01-01: must be false");
}

/// The attack the binding exists for.
///
/// An mdoc's MSO carries no attribute *values*, only their digests — so a
/// holder who wants 32 bytes of their own choosing inside the issuer's
/// signed bytes has exactly one place to put them: their `deviceKey`
/// coordinates. They need no private key for it, because an age proof
/// never exercises device authentication.
///
/// The fixture is a genuinely, correctly issued PID whose holder set
/// `deviceKey.x` to `SHA-256` of a `birth_date` item claiming 2015-01-01.
/// That digest really is in the signed bytes and the item really is its
/// preimage, so every check *except* the region binding passes.
#[test]
fn a_digest_planted_in_the_device_key_is_rejected() {
  let l = load("pid_arf18_planted_device_key");
  let forged = hex::decode(l.json["forged_item_bytes_hex"].as_str().expect("adversarial fixture")).unwrap();
  let planted_offset = l.json["forged_item_digest_offset"].as_u64().unwrap() as usize;

  // The premise: the forged item's digest genuinely sits at that offset
  // in bytes the issuer genuinely signed. If this fails the test is not
  // testing what it claims to.
  let digest: [u8; 32] = Sha256::digest(&forged).into();
  assert_eq!(
    &l.witness.sig_structure[planted_offset..planted_offset + 32],
    digest.as_slice(),
    "fixture does not actually contain the planted digest"
  );
  assert!(
    planted_offset >= l.witness.landmarks.device_key_info,
    "the plant must land outside the digest region for this test to mean anything"
  );

  let mut attack = l.witness.clone();
  attack.item_bytes = forged;
  attack.digest_offset = planted_offset;

  let mut cs = TestConstraintSystem::<Scalar>::new();
  let out = synthesize(&mut cs, &attack, &l.ecdsa, CUTOFF).expect("synthesis still succeeds — this is a soundness check, not a crash");

  // The forged birthdate would have passed: 2015-01-01 is after the
  // cutoff, so the predicate itself reports "not old enough" — but that
  // is not what stops the attack. What stops it is that the digest is
  // outside the region.
  assert!(!out.old_enough.get_value().unwrap());
  let failed = cs.which_is_unsatisfied().expect("the planted digest must not satisfy the circuit");
  assert!(
    failed.contains("inside the region"),
    "expected the region range-bind to be what rejects this, got {failed}"
  );
}

/// The same plant, but pointed at a digest slot the holder does not
/// control: proving that what the binding rejects is the *location*, not
/// merely a mismatched hash.
#[test]
fn the_binding_rejects_by_location_not_by_hash() {
  let l = load("pid_arf18_planted_device_key");
  let mut attack = l.witness.clone();
  // Keep the real item and its real digest, but claim it sits one byte
  // past the end of the region.
  attack.digest_offset = l.witness.landmarks.device_key_info - 31;

  let mut cs = TestConstraintSystem::<Scalar>::new();
  let _ = synthesize(&mut cs, &attack, &l.ecdsa, CUTOFF).expect("synthesis");
  assert!(cs.which_is_unsatisfied().is_some(), "a digest window overrunning the region end must be rejected");
}

/// The proof is bound to a namespace, not merely to "some digest table".
/// An mDL and a PID both have a `valueDigests` map of the same shape; if
/// the namespace were not part of the anchor, a proof about one could be
/// replayed as a proof about the other.
#[test]
fn a_proof_is_bound_to_the_namespace_it_names() {
  let l = load("pid_arf18_random");
  let mut wrong = l.witness.clone();
  wrong.namespace = "org.iso.18013.5.1".to_string();

  let mut cs = TestConstraintSystem::<Scalar>::new();
  let _ = synthesize(&mut cs, &wrong, &l.ecdsa, CUTOFF).expect("synthesis");
  let failed = cs.which_is_unsatisfied().expect("a mismatched namespace must not be satisfiable");
  assert!(failed.contains("valueDigests"), "expected the opening anchor to reject this, got {failed}");
}

/// Likewise the entry count: it is part of the `valueDigests` map header,
/// so a prover cannot claim a different-sized table than the issuer signed.
#[test]
fn a_proof_is_bound_to_the_entry_count() {
  let l = load("pid_arf18_random");
  let mut wrong = l.witness.clone();
  wrong.num_entries -= 1;

  let mut cs = TestConstraintSystem::<Scalar>::new();
  let _ = synthesize(&mut cs, &wrong, &l.ecdsa, CUTOFF).expect("synthesis");
  assert!(cs.which_is_unsatisfied().is_some(), "a mismatched entry count must not be satisfiable");
}

/// The cutoff must be a circuit *variable*, not a constant folded into
/// the constraint system.
///
/// This is the regression test for a bug that no functional test would
/// have caught: an earlier revision took the cutoff as bytes and emitted
/// its bits as `Boolean::constant`, which made the emitted constraints
/// depend on the threshold's bit pattern. Every proof still verified — but
/// each distinct cutoff was a *different R1CS*, so a fixed-setup folding
/// system would have needed its own setup and its own published artifact
/// per threshold date. Per day, in practice.
///
/// Two thresholds with different bit patterns and different answers must
/// produce byte-identical circuit shapes.
#[test]
fn the_circuit_shape_does_not_depend_on_the_cutoff() {
  let l = load("pid_arf18_random");

  let mut shapes = Vec::new();
  for (cutoff, expected) in [(b"2008-09-04", true), (b"1990-01-01", false)] {
    let mut cs = TestConstraintSystem::<Scalar>::new();
    let out = synthesize(&mut cs, &l.witness, &l.ecdsa, cutoff).expect("synthesis");
    assert!(cs.is_satisfied(), "unsatisfied at {:?}", cs.which_is_unsatisfied());
    assert_eq!(out.old_enough.get_value().unwrap(), expected, "cutoff {:?}", std::str::from_utf8(cutoff));
    shapes.push((cs.num_constraints(), cs.num_inputs()));
  }
  assert_eq!(
    shapes[0], shapes[1],
    "the two cutoffs produced different circuit shapes ({:?} vs {:?}) -- each would need its own setup",
    shapes[0], shapes[1]
  );
}

/// The issuer key has to reach the caller, or the statement is empty.
///
/// `synthesize` verifies the signature against `qx`/`qy` allocated as
/// private witnesses. If those never become public inputs, the proof says
/// only "signed by some key whose private half I hold" — which any prover
/// satisfies with a key they generated a moment ago. Exposing them in
/// `PidAgeOutputs` is what lets a `VegaCircuit` pin them, so this checks
/// the plumbing actually carries the issuer's real key.
#[test]
fn the_issuer_key_reaches_the_caller_so_it_can_be_made_public() {
    let l = load("pid_arf18_random");
    let mut cs = TestConstraintSystem::<Scalar>::new();
    let out = synthesize(&mut cs, &l.witness, &l.ecdsa, CUTOFF).expect("synthesis");
    assert!(cs.is_satisfied());

    assert_eq!(out.issuer_qx.get_value().unwrap(), l.ecdsa.qx, "issuer qx must be the key the signature verified against");
    assert_eq!(out.issuer_qy.get_value().unwrap(), l.ecdsa.qy, "issuer qy must be the key the signature verified against");

    // And the cutoff, so a verifier can see which threshold was compared.
    let recovered: Vec<u8> = out
        .cutoff
        .iter()
        .map(|c| {
            let repr = c.get_value().unwrap().to_repr();
            repr.as_ref()[0]
        })
        .collect();
    assert_eq!(&recovered[..], CUTOFF.as_slice(), "the cutoff must be recoverable from the outputs");
}
