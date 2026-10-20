//! Do the two arithmetizations accept the same statement?
//!
//! r13 now ships two: the single-circuit form (`mdoc_age_circuit`) and
//! the folded one (`mdoc_age_mc`). The red-team guide is explicit that
//! "one reviewed entry point does not cover every parameterization" and
//! that "shared source does not establish that different compilation
//! flags generate the same relation" — so the two sharing
//! `synthesize_credential` is an argument, not evidence.
//!
//! These tests are the evidence: for an honest witness and for every
//! corruption the binding suite exercises, the two relations must reach
//! the *same* verdict. A corruption rejected by one and accepted by the
//! other is a soundness hole in whichever accepts it.
//!
//! They also attack the folded form's own new surface — the shared
//! witness — which the single-circuit form does not have.

use bellpepper_core::test_cs::TestConstraintSystem;
use num_bigint::{BigInt, Sign};
use sha2::{Digest, Sha256};
use zk_cred_vega::Engine_;
use zk_cred_vega::mdoc_age::{self, DateEncoding, DeviceAuthWitness, Hasher, MdocAgeWitness};
use zk_cred_vega::mdoc_age_mc::{self, HashWitness};
use zk_cred_vega::offset_bind::Landmarks;
use zk_cred_vega::sha256_mc;

type Scalar = <Engine_ as vega_prover::traits::Engine>::Scalar;
const SESSION: &[u8; 32] = b"verifier-session-transcript-0001";
const NOW: &[u8; 20] = b"2026-10-10T12:00:00Z";
const CUTOFF: &[u8; 10] = b"2008-10-01";

struct Loaded {
  w: MdocAgeWitness,
  e: zk_cred_vega::ecdsa::EcdsaP256Witness<Scalar>,
}

fn sign_device_auth(key_hex: &str, digest: &[u8; 32]) -> DeviceAuthWitness {
  use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
  let b: [u8; 32] = hex::decode(key_hex).unwrap().try_into().unwrap();
  let sk = SigningKey::from_bytes(&b.into()).unwrap();
  let sg: Signature = sk.sign_prehash(digest).unwrap();
  let n = zk_cred_vega::p256_ecc::p256_order();
  let s = BigInt::from_bytes_be(Sign::Plus, &sg.s().to_bytes());
  DeviceAuthWitness {
    r: BigInt::from_bytes_be(Sign::Plus, &sg.r().to_bytes()),
    s: s.clone(),
    s_inv: s.modpow(&(n.clone() - BigInt::from(2)), &n),
  }
}

fn load(name: &str) -> Loaded {
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
  let w = &json["ecdsa_witness"];
  let hx = |k: &str| hex::decode(w[k].as_str().unwrap()).unwrap();
  let z: [u8; 32] = Sha256::digest(&sig).into();
  Loaded {
    w: MdocAgeWitness {
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
      num_entries: lm["num_entries"].as_u64().unwrap() as usize,
      item_bytes: hex::decode(t["issuer_signed_item_bytes_hex"].as_str().unwrap()).unwrap(),
      digest_offset: t["digest_offset"].as_u64().unwrap() as usize,
      element_value_key_offset: json["element_value_key_offset"].as_u64().unwrap() as usize,
      date_encoding: match json["date_encoding"].as_str().unwrap() {
        "PhotoIdMap" => DateEncoding::PhotoIdMap,
        _ => DateEncoding::Bare,
      },
      device_auth: sign_device_auth(json["device_private_key_hex"].as_str().unwrap(), SESSION),
    },
    e: zk_cred_vega::ecdsa::EcdsaP256Witness::<Scalar> {
      qx: zk_cred_vega::nonnative::util::nat_to_f(&BigInt::from_bytes_be(Sign::Plus, &hx("qx_hex"))).unwrap(),
      qy: zk_cred_vega::nonnative::util::nat_to_f(&BigInt::from_bytes_be(Sign::Plus, &hx("qy_hex"))).unwrap(),
      r: BigInt::from_bytes_be(Sign::Plus, &hx("r_hex")),
      s: BigInt::from_bytes_be(Sign::Plus, &hx("s_hex")),
      s_inv: BigInt::from_bytes_be(Sign::Plus, &hx("s_inv_hex")),
      z: BigInt::from_bytes_be(Sign::Plus, &z),
    },
  }
}

/// Satisfiability under the single-circuit relation.
fn sc_accepts(l: &Loaded, w: &MdocAgeWitness, now: &[u8; 20], session: &[u8; 32]) -> bool {
  let mut cs = TestConstraintSystem::<Scalar>::new();
  match mdoc_age::synthesize(&mut cs, w, &l.e, CUTOFF, now, session) {
    Err(_) => false,
    Ok(_) => cs.is_satisfied(),
  }
}

/// Satisfiability under the folded relation: the core *and* every step.
fn mc_accepts(l: &Loaded, w: &MdocAgeWitness, hash: &HashWitness, now: &[u8; 20], session: &[u8; 32]) -> bool {
  let layout = mdoc_age_mc::layout();
  let mut cs = TestConstraintSystem::<Scalar>::new();
  let shared = match sha256_mc::alloc_shared(&mut cs, &hash.blocks, &hash.digests) {
    Ok(s) => s,
    Err(_) => return false,
  };
  let cred = match mdoc_age::synthesize_credential(
    &mut cs,
    w,
    &l.e,
    &Hasher::Folded {
      shared: &shared,
      layout: &layout,
      message: 0,
    },
    &Hasher::Folded {
      shared: &shared,
      layout: &layout,
      message: 1,
    },
  ) {
    Ok(c) => c,
    Err(_) => return false,
  };
  if mdoc_age::synthesize_session(
    &mut cs,
    &cred.device_key,
    &cred.birth_date,
    &cred.valid_from,
    &cred.valid_until,
    &w.device_auth,
    CUTOFF,
    now,
    session,
  )
  .is_err()
  {
    return false;
  }
  if !cs.is_satisfied() {
    return false;
  }
  // Every folded step must hold too, against the same shared witness.
  for step in 0..layout.total_blocks() {
    let mut cs = TestConstraintSystem::<Scalar>::new();
    let shared = sha256_mc::alloc_shared(&mut cs, &hash.blocks, &hash.digests).unwrap();
    if sha256_mc::synthesize_step(&mut cs, &shared, &layout, step).is_err() || !cs.is_satisfied() {
      return false;
    }
  }
  true
}

type Corruption = (&'static str, Box<dyn Fn(&mut MdocAgeWitness)>, bool);

/// The two relations must agree on every case — honest and corrupt.
#[test]
fn the_two_arithmetizations_agree_on_every_witness() {
  let cases: Vec<Corruption> = vec![
    ("honest", Box::new(|_: &mut MdocAgeWitness| {}), true),
    (
      "wrong device key",
      Box::new(|w: &mut MdocAgeWitness| {
        w.device_auth = sign_device_auth(&"11".repeat(32), SESSION);
      }),
      false,
    ),
    (
      "digest offset outside the region",
      Box::new(|w: &mut MdocAgeWitness| {
        w.digest_offset = w.landmarks.device_key_info + 4;
      }),
      false,
    ),
    (
      "wrong salt offset",
      Box::new(|w: &mut MdocAgeWitness| {
        w.element_value_key_offset = if w.element_value_key_offset == 39 { 56 } else { 39 };
      }),
      false,
    ),
    (
      "wrong namespace",
      Box::new(|w: &mut MdocAgeWitness| {
        w.namespace = "org.iso.23220.1".to_string();
      }),
      false,
    ),
    (
      "wrong entry count",
      Box::new(|w: &mut MdocAgeWitness| {
        w.num_entries -= 1;
      }),
      false,
    ),
    (
      "truncated item",
      Box::new(|w: &mut MdocAgeWitness| {
        w.item_bytes.truncate(64);
      }),
      false,
    ),
  ];

  for (name, mutate, expected) in cases {
    let l = load("mdl_iso18013");
    let mut w = l.w.clone();
    mutate(&mut w);
    // An honest prover's shared witness is derived from its own witness.
    let hash = HashWitness::from_witness(&w).unwrap();
    let sc = sc_accepts(&l, &w, NOW, SESSION);
    let mc = mc_accepts(&l, &w, &hash, NOW, SESSION);
    assert_eq!(sc, expected, "{name}: single-circuit verdict");
    assert_eq!(
      mc, sc,
      "{name}: the two arithmetizations disagree (single-circuit {sc}, folded {mc}) — \
       whichever accepts is unsound"
    );
  }
}

/// Session and clock corruptions, likewise.
#[test]
fn the_two_arithmetizations_agree_on_session_and_clock() {
  let l = load("mdl_iso18013");
  let hash = HashWitness::from_witness(&l.w).unwrap();
  for (name, now, session, expected) in [
    ("honest", NOW, SESSION, true),
    ("replayed session", NOW, b"a-different-verifier-session-002", false),
  ] {
    let sc = sc_accepts(&l, &l.w, now, session);
    let mc = mc_accepts(&l, &l.w, &hash, now, session);
    assert_eq!(sc, expected, "{name}: single-circuit verdict");
    assert_eq!(mc, sc, "{name}: arithmetizations disagree");
  }

  // Expired credential, under both.
  let l = load("mdl_expired");
  let hash = HashWitness::from_witness(&l.w).unwrap();
  assert!(!sc_accepts(&l, &l.w, NOW, SESSION), "expired must fail single-circuit");
  assert!(!mc_accepts(&l, &l.w, &hash, NOW, SESSION), "expired must fail folded");
}

// ---- The folded form's own new attack surface -----------------------

/// A shared witness whose blocks are not the credential's.
///
/// This surface does not exist in the single-circuit form. A malicious
/// prover controls the shared vector independently of the message, so
/// `bind_message_to_shared` is the only thing tying them together — and
/// if it did not, the folded steps would be proving compressions over
/// blocks unrelated to the credential while the core proved everything
/// else about the real one.
#[test]
fn a_shared_witness_that_is_not_the_credential_is_rejected() {
  let l = load("mdl_iso18013");
  let other = load("pid_arf18");
  let wrong = HashWitness::from_witness(&other.w).unwrap();

  // The steps are internally consistent — they are a real SHA-256 chain,
  // just of the wrong document — so this is not caught by the steps.
  let layout = mdoc_age_mc::layout();
  for step in 0..layout.total_blocks() {
    let mut cs = TestConstraintSystem::<Scalar>::new();
    let shared = sha256_mc::alloc_shared(&mut cs, &wrong.blocks, &wrong.digests).unwrap();
    sha256_mc::synthesize_step(&mut cs, &shared, &layout, step).unwrap();
    assert!(cs.is_satisfied(), "the substituted chain is itself valid — step {step}");
  }

  assert!(
    !mc_accepts(&l, &l.w, &wrong, NOW, SESSION),
    "a shared witness from another credential must be rejected by the core's binding"
  );
}

/// Tampering with one block of an otherwise-good shared witness.
#[test]
fn a_tampered_shared_block_is_rejected() {
  let l = load("mdl_iso18013");
  let mut hash = HashWitness::from_witness(&l.w).unwrap();
  hash.blocks[2][7] ^= 0x01;
  assert!(!mc_accepts(&l, &l.w, &hash, NOW, SESSION), "a tampered shared block must be rejected");
}

/// Tampering with an intermediate digest.
#[test]
fn a_tampered_intermediate_digest_is_rejected() {
  let l = load("mdl_iso18013");
  let mut hash = HashWitness::from_witness(&l.w).unwrap();
  hash.digests[3][0] ^= 0x80;
  assert!(!mc_accepts(&l, &l.w, &hash, NOW, SESSION), "a tampered intermediate digest must be rejected");
}

/// MC-01: if the folded steps do not cover every block, the unproven
/// blocks' digests are free — and one of them is the hash the signature
/// is checked against.
///
/// `vega_mc_zkp::verify` checks the *number* of step instances against
/// the key, never their public values. Nothing in the proof system
/// requires the folded steps to be indices `0..n-1`. A prover who folds
/// `n` copies of step 0 proves one compression and leaves the other
/// blocks' shared digests unconstrained.
///
/// This test keeps the blocks honest — so `bind_message_to_shared`
/// passes — and replaces only the terminal digest, which is what
/// `select_digest` hands to the ECDSA check as the signed message. A
/// prover who can choose that can pair one credential's bytes with
/// another credential's genuine signature.
#[test]
fn mc01_unproven_blocks_leave_the_signed_digest_free() {
  let l = load("mdl_iso18013");
  let layout = mdoc_age_mc::layout();
  let mut hash = HashWitness::from_witness(&l.w).unwrap();

  // The block whose digest the core selects for the Sig_structure.
  let terminal = zk_cred_vega::sha256_var::terminal_block_for_len(l.w.sig_structure.len()) - 1;
  assert!(terminal > 0, "the attack needs a block the lone proven step does not cover");
  hash.digests[terminal][0] ^= 0xff;

  // Step 0 — the only index a lazy prover would fold — still verifies:
  // it never touches the block we tampered with.
  let mut cs = TestConstraintSystem::<Scalar>::new();
  let shared = sha256_mc::alloc_shared(&mut cs, &hash.blocks, &hash.digests).unwrap();
  sha256_mc::synthesize_step(&mut cs, &shared, &layout, 0).unwrap();
  assert!(cs.is_satisfied(), "step 0 does not constrain the tampered digest");

  // And the step that *would* catch it is the one the prover omits.
  let mut cs = TestConstraintSystem::<Scalar>::new();
  let shared = sha256_mc::alloc_shared(&mut cs, &hash.blocks, &hash.digests).unwrap();
  sha256_mc::synthesize_step(&mut cs, &shared, &layout, terminal).unwrap();
  assert!(
    cs.which_is_unsatisfied().is_some(),
    "step {terminal} is what binds this digest — the index check is what forces it to be folded"
  );
}

/// Both deployment circuits are driven through the `VegaCircuit` trait
/// exactly as the prover drives them, and what they publish is what they
/// say they publish.
///
/// Every other test here calls the gadgets directly, which skips the two
/// places this one covers: the `precommitted` vector's layout, and the
/// agreement between `public_values` and the values `synthesize` actually
/// inputizes. Both are pure bookkeeping and both are easy to get wrong —
/// adding one value to the credential-bound half left the folded core
/// slicing the old layout, and that surfaces as an out-of-range panic
/// inside the prover rather than a verification failure. The end-to-end
/// tests catch it, but they are `#[ignore]`d and CI does not run them, so
/// it would have merged.
///
/// `TestConstraintSystem::verify` is the sharp part: it requires the
/// declared public values to equal the inputized ones, position by
/// position.
#[test]
fn both_deployment_circuits_publish_what_they_declare() {
  use vega_prover::traits::circuit::VegaCircuit;
  use zk_cred_vega::Engine_;
  use zk_cred_vega::mdoc_age_circuit::{MdocAgeCircuit, PRECOMMITTED_LEN, PUBLIC_INPUT_LEN};

  for name in ["mdl_iso18013", "pid_arf18", "photo_id_23220"] {
    let l = load(name);

    // ---- single circuit ----
    let sc = MdocAgeCircuit::<Engine_> {
      witness: l.w.clone(),
      ecdsa: l.e.clone(),
      cutoff: *CUTOFF,
      now: *NOW,
      device_auth_digest: *SESSION,
    };
    let declared = sc.public_values().expect("public values");
    assert_eq!(declared.len(), PUBLIC_INPUT_LEN, "{name}: single-circuit public input count");

    let mut cs = TestConstraintSystem::<Scalar>::new();
    let shared = sc.shared(&mut cs).expect("shared");
    let pre = sc.precommitted(&mut cs, &shared).expect("precommitted");
    assert_eq!(pre.len(), PRECOMMITTED_LEN, "{name}: single-circuit precommitted length");
    sc.synthesize(&mut cs, &shared, &pre, None).expect("synthesize");
    assert!(cs.is_satisfied(), "{name}: single circuit unsatisfied at {:?}", cs.which_is_unsatisfied());
    assert!(cs.verify(&declared), "{name}: the single circuit published something it did not declare");

    // ---- folded core and one step ----
    let (steps, core) = mdoc_age_mc::build(&l.w, &l.e, *CUTOFF, *NOW, *SESSION).expect("folded build");
    let core_declared = core.public_values().expect("core public values");
    assert_eq!(core_declared, declared, "{name}: the two arithmetizations must publish the same statement");

    let mut cs = TestConstraintSystem::<Scalar>::new();
    let shared = core.shared(&mut cs).expect("core shared");
    let pre = core.precommitted(&mut cs, &shared).expect("core precommitted");
    assert_eq!(pre.len(), PRECOMMITTED_LEN, "{name}: folded core precommitted length");
    core.synthesize(&mut cs, &shared, &pre, None).expect("core synthesize");
    assert!(cs.is_satisfied(), "{name}: folded core unsatisfied at {:?}", cs.which_is_unsatisfied());
    assert!(cs.verify(&core_declared), "{name}: the folded core published something it did not declare");

    for step in [0, steps.len() / 2, steps.len() - 1] {
      let s = &steps[step];
      let mut cs = TestConstraintSystem::<Scalar>::new();
      let shared = s.shared(&mut cs).expect("step shared");
      let pre = s.precommitted(&mut cs, &shared).expect("step precommitted");
      s.synthesize(&mut cs, &shared, &pre, None).expect("step synthesize");
      assert!(cs.is_satisfied(), "{name}: step {step} unsatisfied");
      assert!(
        cs.verify(&s.public_values().expect("step public values")),
        "{name}: step {step} published an index it did not declare"
      );
    }
  }
}
