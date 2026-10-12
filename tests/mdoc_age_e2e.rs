//! Stage D/E evidence: real proofs under real keys.
//!
//! Everything else in this crate's test suite checks constraint
//! satisfaction via `TestConstraintSystem`. That is Stage C — it shows an
//! assignment does or does not satisfy the relation, but it never runs
//! the proof system. The red-team guide is explicit that a constraint
//! counterexample and an accepted malicious proof are different evidence
//! levels, and that a circuit cannot be signed off on the former alone.
//!
//! So this file does the expensive thing: one `setup`, then honest and
//! malicious proofs generated and verified under *those same* keys. The
//! verifier artifact is never modified to manufacture a result.
//!
//! These are slow (a ~1.3M-constraint circuit) and are therefore
//! `#[ignore]`d by default. Run them with:
//!   cargo test --release --test mdoc_age_e2e -- --ignored --nocapture

use bellpepper_core::test_cs::TestConstraintSystem;
use num_bigint::{BigInt, Sign};
use sha2::{Digest, Sha256};
use std::time::Instant;
use zk_cred_vega::mdoc_age::{DateEncoding, DeviceAuthWitness, MdocAgeWitness};
use zk_cred_vega::mdoc_age_circuit::{self, ExpectedContext, MdocAgeCircuit};
use zk_cred_vega::offset_bind::Landmarks;
use zk_cred_vega::Engine_;

type Scalar = <Engine_ as vega_prover::traits::Engine>::Scalar;

const SESSION: &[u8; 32] = b"verifier-session-transcript-0001";
const OTHER_SESSION: &[u8; 32] = b"a-different-verifier-session-002";
const CUTOFF: &[u8; 10] = b"2008-10-01";

/// The verifier's clock. Fixed, like `CUTOFF`, so these tests assert the
/// same thing whenever they run; a real verifier uses its own.
const NOW: &[u8; 20] = b"2026-10-10T12:00:00Z";

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

fn circuit(name: &str, cutoff: &[u8; 10], session: &[u8; 32], device_key: Option<&str>) -> MdocAgeCircuit<Engine_> {
  let json: serde_json::Value =
    serde_json::from_str(&std::fs::read_to_string(format!("test-vectors/{name}.json")).expect("fixture")).unwrap();
  let sig = hex::decode(json["sig_structure_hex"].as_str().unwrap()).unwrap();
  let lm = &json["landmarks"];
  let ns = json["namespace"].as_str().unwrap();
  let t = json["claims"].as_array().unwrap().iter()
    .find(|c| c["element_identifier"] == "birth_date" && c["namespace"] == ns).unwrap();
  let key = device_key.unwrap_or_else(|| json["device_private_key_hex"].as_str().unwrap());

  let w = &json["ecdsa_witness"];
  let hx = |k: &str| hex::decode(w[k].as_str().unwrap()).unwrap();
  let z: [u8; 32] = Sha256::digest(&sig).into();

  MdocAgeCircuit {
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
      namespace: ns.to_string(),
      doc_type: json["doc_type"].as_str().unwrap().to_string(),
      num_namespaces: lm["num_namespaces"].as_u64().unwrap() as usize,
      num_entries: lm["num_entries"].as_u64().unwrap() as usize,
      item_bytes: hex::decode(t["issuer_signed_item_bytes_hex"].as_str().unwrap()).unwrap(),
      digest_offset: t["digest_offset"].as_u64().unwrap() as usize,
      element_value_key_offset: json["element_value_key_offset"].as_u64().unwrap() as usize,
      date_encoding: match json["date_encoding"].as_str().unwrap() {
        "PhotoIdMap" => DateEncoding::PhotoIdMap,
        _ => DateEncoding::Bare,
      },
      device_auth: sign_device_auth(key, session),
    },
    ecdsa: zk_cred_vega::ecdsa::EcdsaP256Witness::<Scalar> {
      qx: zk_cred_vega::nonnative::util::nat_to_f(&BigInt::from_bytes_be(Sign::Plus, &hx("qx_hex"))).unwrap(),
      qy: zk_cred_vega::nonnative::util::nat_to_f(&BigInt::from_bytes_be(Sign::Plus, &hx("qy_hex"))).unwrap(),
      r: BigInt::from_bytes_be(Sign::Plus, &hx("r_hex")),
      s: BigInt::from_bytes_be(Sign::Plus, &hx("s_hex")),
      s_inv: BigInt::from_bytes_be(Sign::Plus, &hx("s_inv_hex")),
      z: BigInt::from_bytes_be(Sign::Plus, &z),
    },
    cutoff: *cutoff,
    now: *NOW,
    device_auth_digest: *session,
  }
}

/// Stage D: honest proof accepted, four malicious ones rejected, all
/// under one set of keys that is never modified.
#[test]
#[ignore = "slow: runs a real setup and several real proofs"]
fn real_proofs_under_real_keys() {
  let t = Instant::now();
  let keys = mdoc_age_circuit::setup(circuit("mdl_iso18013", CUTOFF, SESSION, None)).expect("setup");
  println!("setup: {:?}", t.elapsed());

  let expected = ExpectedContext { device_auth_digest: *SESSION, cutoff: *CUTOFF, now: *NOW };

  // --- honest positive control -------------------------------------
  let t = Instant::now();
  let proof = mdoc_age_circuit::prove(&keys.pk, circuit("mdl_iso18013", CUTOFF, SESSION, None)).expect("prove");
  println!("prove: {:?}", t.elapsed());
  let ok = mdoc_age_circuit::verify_age(&proof, &keys.vk, &expected).expect("honest proof must verify");
  assert_eq!(ok.doc_type, "org.iso.18013.5.1.mDL");
  assert_eq!(ok.namespace, "org.iso.18013.5.1");
  println!("honest proof accepted: docType={} ns={}", ok.doc_type, ok.namespace);

  // --- replay to another verifier's session -------------------------
  let replayed = ExpectedContext { device_auth_digest: *OTHER_SESSION, cutoff: *CUTOFF, now: *NOW };
  assert!(
    mdoc_age_circuit::verify_age(&proof, &keys.vk, &replayed).is_err(),
    "a proof made for one session must not be accepted by another"
  );

  // --- a different question than the one asked ----------------------
  let other_q = ExpectedContext { device_auth_digest: *SESSION, cutoff: *b"1990-01-01", now: *NOW };
  assert!(
    mdoc_age_circuit::verify_age(&proof, &keys.vk, &other_q).is_err(),
    "a proof about one threshold must not answer another"
  );

  // --- an under-age holder: the proof is valid, the answer is no ----
  // CIRCUIT-04's real test. The circuit happily proves `old_enough = 0`;
  // the acceptance path is what must refuse it.
  let under = circuit("mdl_iso18013", b"1990-01-01", SESSION, None);
  let under_proof = mdoc_age_circuit::prove(&keys.pk, under).expect("an honest 'no' still proves");
  assert!(
    mdoc_age_circuit::verify_age(
      &under_proof,
      &keys.vk,
      &ExpectedContext { device_auth_digest: *SESSION, cutoff: *b"1990-01-01", now: *NOW }
    )
    .is_err(),
    "a proof whose predicate is false must not be accepted"
  );
  println!("under-age proof correctly refused by the acceptance path");
}

/// A proof the attacker cannot even produce: without the device private
/// key the witness does not satisfy the relation, so proving fails before
/// any verifier is involved.
#[test]
#[ignore = "slow: runs a real setup and a real proof attempt"]
fn impersonation_cannot_produce_a_proof() {
  let keys = mdoc_age_circuit::setup(circuit("mdl_iso18013", CUTOFF, SESSION, None)).expect("setup");
  let attacker = circuit("mdl_iso18013", CUTOFF, SESSION, Some(&"11".repeat(32)));

  // Confirm first that this witness genuinely fails the relation, so a
  // proving failure below is the defect we mean and not an accident.
  let mut cs = TestConstraintSystem::<Scalar>::new();
  let _ = zk_cred_vega::mdoc_age::synthesize(&mut cs, &attacker.witness, &attacker.ecdsa, CUTOFF, NOW, SESSION).unwrap();
  assert!(cs.which_is_unsatisfied().is_some(), "wrong device key must not satisfy the relation");

  match mdoc_age_circuit::prove(&keys.pk, attacker) {
    Err(_) => println!("impersonation: proving refused, as it must be"),
    Ok(p) => assert!(
      mdoc_age_circuit::verify_age(&p, &keys.vk, &ExpectedContext { device_auth_digest: *SESSION, cutoff: *CUTOFF, now: *NOW }).is_err(),
      "a proof from a witness that does not satisfy the relation must not verify"
    ),
  }
}

/// Artifact sizes, for the catalog entry r13 will need.
#[test]
#[ignore = "slow: runs a real setup and a real proof"]
fn artifact_sizes() {
  let keys = mdoc_age_circuit::setup(circuit("mdl_iso18013", CUTOFF, SESSION, None)).expect("setup");
  let proof = mdoc_age_circuit::prove(&keys.pk, circuit("mdl_iso18013", CUTOFF, SESSION, None)).expect("prove");
  let pk = bincode::serialize(&keys.pk).map(|v| v.len()).unwrap_or(0);
  let vk = bincode::serialize(&keys.vk).map(|v| v.len()).unwrap_or(0);
  let pr = bincode::serialize(&proof).map(|v| v.len()).unwrap_or(0);
  println!("prover key   : {:>9.2} MB", pk as f64 / 1e6);
  println!("verifier key : {:>9.2} MB", vk as f64 / 1e6);
  println!("proof        : {:>9.2} kB", pr as f64 / 1e3);
  println!("public inputs: {}", zk_cred_vega::mdoc_age_circuit::PUBLIC_INPUT_LEN);
}

// ---- The folded (multi-circuit) arithmetization ---------------------

fn mc_build(name: &str, cutoff: &[u8; 10], session: &[u8; 32])
  -> (Vec<zk_cred_vega::mdoc_age_mc::StepCircuit<Engine_>>, zk_cred_vega::mdoc_age_mc::CoreCircuit<Engine_>) {
  let c = circuit(name, cutoff, session, None);
  zk_cred_vega::mdoc_age_mc::build(&c.witness, &c.ecdsa, c.cutoff, c.now, c.device_auth_digest)
}

/// The folded form proves and verifies the same statement.
///
/// This is the whole point of §4.2: every SHA-256 compression becomes an
/// instance of one small step circuit, the core keeps none, and setup
/// therefore encodes one step plus one core instead of an unrolled hash.
#[test]
#[ignore = "slow: runs a real folded setup and proof"]
fn folded_proofs_verify_under_folded_keys() {
  use zk_cred_vega::mdoc_age_mc as mc;
  let (steps, core) = mc_build("mdl_iso18013", CUTOFF, SESSION);
  let t = Instant::now();
  let keys = mc::setup(&steps[0], &core).expect("setup");
  println!("MC setup: {:?}", t.elapsed());

  let t = Instant::now();
  let proof = mc::prove(&keys.pk, &steps, &core).expect("prove");
  println!("MC prove: {:?}", t.elapsed());

  let expected = ExpectedContext { device_auth_digest: *SESSION, cutoff: *CUTOFF, now: *NOW };
  let ok = mc::verify_age(&proof, &keys.vk, &expected).expect("honest folded proof must verify");
  assert_eq!(ok.doc_type, "org.iso.18013.5.1.mDL");
  assert_eq!(ok.namespace, "org.iso.18013.5.1");

  // Same obligations as the single-circuit path.
  assert!(
    mc::verify_age(&proof, &keys.vk, &ExpectedContext { device_auth_digest: *OTHER_SESSION, cutoff: *CUTOFF, now: *NOW }).is_err(),
    "a folded proof must not replay to another session"
  );

  let pk = bincode::serialize(&keys.pk).map(|v| v.len()).unwrap_or(0);
  let vk = bincode::serialize(&keys.vk).map(|v| v.len()).unwrap_or(0);
  let pr = bincode::serialize(&proof).map(|v| v.len()).unwrap_or(0);
  println!("MC prover key   : {:>9.2} MB", pk as f64 / 1e6);
  println!("MC verifier key : {:>9.2} MB", vk as f64 / 1e6);
  println!("MC proof        : {:>9.2} kB", pr as f64 / 1e3);
  println!("  single-circuit was 614.44 MB / 614.44 MB / 111.83 kB");
}

/// MC-01 end-to-end: a prover that folds the wrong step indices.
///
/// Guide Stage D — not "an assignment satisfies the constraints" but "the
/// original verifier accepts a malicious proof". The prover folds `n`
/// copies of step 0 instead of steps `0..n-1`, so every block except the
/// first is unproven and its shared digest is free.
#[test]
#[ignore = "slow: runs a real folded setup and a malicious proof attempt"]
fn mc01_folding_the_wrong_indices_is_caught_by_the_acceptance_path() {
  use zk_cred_vega::mdoc_age_mc as mc;
  let (steps, core) = mc_build("mdl_iso18013", CUTOFF, SESSION);
  let keys = mc::setup(&steps[0], &core).expect("setup");
  let expected = ExpectedContext { device_auth_digest: *SESSION, cutoff: *CUTOFF, now: *NOW };

  // Honest control first.
  let honest = mc::prove(&keys.pk, &steps, &core).expect("honest prove");
  assert!(mc::verify_age(&honest, &keys.vk, &expected).is_ok(), "honest control must verify");

  // The attack: every folded instance claims index 0.
  let all_zero: Vec<_> = (0..steps.len()).map(|_| steps[0].clone()).collect();
  match mc::prove(&keys.pk, &all_zero, &core) {
    Err(e) => println!("MC-01: proving refused outright ({e:?})"),
    Ok(bad) => {
      // If it proves, the acceptance path is the only thing left.
      let accepted = mc::verify_age(&bad, &keys.vk, &expected).is_ok();
      assert!(
        !accepted,
        "a proof folding only step 0 was ACCEPTED — the step-index check in verify_age is \
         the sole defence and it failed"
      );
      println!("MC-01: proof generated, and rejected by the step-index check in verify_age");
    }
  }
}
