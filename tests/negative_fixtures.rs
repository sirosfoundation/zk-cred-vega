//! Negative-path counterpart to `real_mdoc_fixtures.rs`: runs the same
//! real, independently-generated fixture through the full `setup ->
//! prep_prove -> prove -> verify -> verify_and_check_binding` pipeline,
//! but with exactly one thing deliberately wrong each time, and asserts
//! the pipeline never produces a successfully verified presentation.
//!
//! This crate already has internal unit tests
//! (`binding_check_rejects_mismatched_claims`,
//! `binding_check_rejects_mismatched_digest_ids`, in `src/lib.rs`) that
//! cover the step<->core cross-binding check with short, hand-rolled
//! claim bytes built via a test-only helper that places `digestID` at
//! exactly `digest_id_extract::DIGEST_ID_OFFSET_BYTES` *by construction*.
//! That's tautological with respect to that constant: if the constant
//! itself regressed, the helper and the crate would still agree, and
//! those tests would keep passing. The fixtures here come from an
//! independent generator (`examples/gen_test_mdocs.rs`, cross-checked
//! with Python `cbor2`, see `real_mdoc_fixtures.rs`'s own doc) with real
//! CBOR framing, so a regression in that offset (exactly the bug fixed
//! this session for `digest_id_extract.rs`) is something these tests can
//! actually catch.
//!
//! Every test here only uses this crate's public API (`tests/*.rs` is a
//! separate crate with no access to `pub(crate)` helpers like
//! `pad_claims`/`core_digest_ids`/`core_claim_digests`), matching how a
//! real caller (the Go verifier, the Kotlin/Swift SDKs) is limited to
//! exactly this surface too.

use serde::Deserialize;
use sha2::{Digest, Sha256};
use zk_cred_vega::mso::MsoBodyWitness;
use zk_cred_vega::{ClaimWitness, MdocEcdsaWitness, MAX_CLAIMS_V1};

/// Disclosed bytes now travel beside the proof (see
/// `verify_and_check_binding`), so callers hand them over explicitly.
fn disclosed_for(claims: &[zk_cred_vega::ClaimWitness]) -> Vec<Option<Vec<u8>>> {
  let mut v: Vec<Option<Vec<u8>>> = claims
    .iter()
    .map(|c| if c.disclose { Some(c.issuer_signed_item_bytes.clone()) } else { None })
    .collect();
  v.resize(zk_cred_vega::MAX_CLAIMS_V1, None);
  v
}

#[derive(Deserialize)]
struct FixtureClaim {
  #[allow(dead_code)]
  element_identifier: String,
  digest_id: u64,
  disclose: bool,
  issuer_signed_item_bytes_hex: String,
  #[allow(dead_code)]
  issuer_signed_item_bytes_len: usize,
}

#[derive(Deserialize)]
struct FixtureEcdsaWitness {
  qx_hex: String,
  qy_hex: String,
  r_hex: String,
  s_hex: String,
  s_inv_hex: String,
}

#[derive(Deserialize)]
struct FixtureMsoBody {
  device_x_hex: String,
  device_y_hex: String,
  signed_ts: String,
  valid_from_ts: String,
  valid_until_ts: String,
}

#[derive(Deserialize)]
struct Fixture {
  #[allow(dead_code)]
  description: String,
  claims: Vec<FixtureClaim>,
  ecdsa_witness: FixtureEcdsaWitness,
  mso_body: FixtureMsoBody,
}

fn hex_bytes(s: &str) -> Vec<u8> {
  hex::decode(s).expect("valid hex")
}

fn fixed_bytes<const N: usize>(s: &str) -> [u8; N] {
  hex_bytes(s).try_into().expect("expected length")
}

fn load_fixture() -> Fixture {
  let raw = std::fs::read_to_string("test-vectors/mdl_4claims_mixed_disclosure.json")
    .expect("read fixture (run `cargo run --release --example gen_test_mdocs` if missing)");
  serde_json::from_str(&raw).expect("parse fixture")
}

fn fixture_claims(fixture: &Fixture) -> Vec<ClaimWitness> {
  fixture
    .claims
    .iter()
    .map(|c| ClaimWitness {
      issuer_signed_item_bytes: hex_bytes(&c.issuer_signed_item_bytes_hex),
      disclose: c.disclose,
      digest_id: u32::try_from(c.digest_id).expect("fixture digestID fits in a u32"),
    })
    .collect()
}

fn fixture_mso_body(fixture: &Fixture) -> MsoBodyWitness {
  MsoBodyWitness {
    device_x: fixed_bytes(&fixture.mso_body.device_x_hex),
    device_y: fixed_bytes(&fixture.mso_body.device_y_hex),
    signed_ts: fixture.mso_body.signed_ts.as_bytes().try_into().expect("20 bytes"),
    valid_from_ts: fixture.mso_body.valid_from_ts.as_bytes().try_into().expect("20 bytes"),
    valid_until_ts: fixture.mso_body.valid_until_ts.as_bytes().try_into().expect("20 bytes"),
  }
}

fn fixture_ecdsa_witness(fixture: &Fixture) -> MdocEcdsaWitness {
  use num_bigint::{BigInt, Sign};
  use zk_cred_vega::nonnative::util::nat_to_f;
  let qx = nat_to_f(&BigInt::from_bytes_be(Sign::Plus, &hex_bytes(&fixture.ecdsa_witness.qx_hex))).expect("qx fits");
  let qy = nat_to_f(&BigInt::from_bytes_be(Sign::Plus, &hex_bytes(&fixture.ecdsa_witness.qy_hex))).expect("qy fits");
  MdocEcdsaWitness {
    qx,
    qy,
    r: BigInt::from_bytes_be(Sign::Plus, &hex_bytes(&fixture.ecdsa_witness.r_hex)),
    s: BigInt::from_bytes_be(Sign::Plus, &hex_bytes(&fixture.ecdsa_witness.s_hex)),
    s_inv: BigInt::from_bytes_be(Sign::Plus, &hex_bytes(&fixture.ecdsa_witness.s_inv_hex)),
  }
}

/// The real `z` (SHA-256 of the real MSO `Sig_structure`) this fixture's
/// claims+mso_body actually sign — independently recomputed here via the
/// crate's own public `mso::native_sig_structure_bytes` (the same
/// function `verify_and_check_binding` uses), needed to mint a *fresh*,
/// self-consistent ECDSA signature over the exact same message for the
/// forged-signature test below. The fixture already carries exactly
/// `MAX_CLAIMS_V1` claims, so no padding step is needed here (unlike
/// production `pad_claims`, which only matters for fewer-than-max claim
/// sets).
fn fixture_z(fixture: &Fixture) -> [u8; 32] {
  assert_eq!(fixture.claims.len(), MAX_CLAIMS_V1, "fixture must carry exactly MAX_CLAIMS_V1 claims for this helper");
  let digest_ids: [u32; MAX_CLAIMS_V1] =
    std::array::from_fn(|i| u32::try_from(fixture.claims[i].digest_id).expect("fits u32"));
  let claim_digests: Vec<[u8; 32]> = fixture
    .claims
    .iter()
    .map(|c| Sha256::digest(hex_bytes(&c.issuer_signed_item_bytes_hex)).into())
    .collect();
  let sig_structure = zk_cred_vega::mso::native_sig_structure_bytes(&digest_ids, &claim_digests, &fixture_mso_body(fixture));
  Sha256::digest(&sig_structure).into()
}

/// Signs `z` with a fresh, random P-256 key and returns the `(qx, qy)` /
/// `(r, s, s_inv)` halves separately, so callers can mix-and-match them
/// across two different keys.
fn sign_z(z: &[u8; 32], key_byte: u8) -> ((num_bigint::BigInt, num_bigint::BigInt), (num_bigint::BigInt, num_bigint::BigInt, num_bigint::BigInt)) {
  use num_bigint::{BigInt, Sign};
  use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey, VerifyingKey};
  use zk_cred_vega::p256_ecc::p256_order;

  let signing_key = SigningKey::from_bytes(&[key_byte; 32].into()).expect("valid scalar");
  let verifying_key = VerifyingKey::from(&signing_key);
  let signature: Signature = signing_key.sign_prehash(z).expect("sign_prehash");

  let r = BigInt::from_bytes_be(Sign::Plus, &signature.r().to_bytes());
  let s = BigInt::from_bytes_be(Sign::Plus, &signature.s().to_bytes());
  let n = p256_order();
  let s_inv = s.modpow(&(n.clone() - BigInt::from(2)), &n);

  let encoded = verifying_key.to_encoded_point(false);
  let qx = BigInt::from_bytes_be(Sign::Plus, encoded.x().expect("uncompressed x"));
  let qy = BigInt::from_bytes_be(Sign::Plus, encoded.y().expect("uncompressed y"));

  ((qx, qy), (r, s, s_inv))
}

/// The single most safety-critical property this crate has: a
/// presentation is only valid for the public key that *actually*
/// produced the signature, not any public key the prover feels like
/// claiming. Builds two independent, individually-valid P-256 keypairs
/// signing the exact same real MSO `z` — "victim" and "attacker" - then
/// witnesses the *victim's* `qx`/`qy` (the identity a relying party would
/// trust-anchor-check) alongside the *attacker's* own genuinely-valid
/// `r`/`s`/`s_inv` (a real signature, just from the wrong key). Neither
/// half is malformed on its own; only the combination is a forgery. If
/// this test fails to reject, the crate's ECDSA gadget isn't actually
/// binding `Q` to the signature it accepts.
#[test]
fn forged_ecdsa_signature_binding_is_rejected() {
  let fixture = load_fixture();
  let claims = fixture_claims(&fixture);
  let mso_body = fixture_mso_body(&fixture);
  let z = fixture_z(&fixture);

  let (victim_q, _victim_sig) = sign_z(&z, 0x11);
  let (_attacker_q, attacker_sig) = sign_z(&z, 0x22);

  use zk_cred_vega::nonnative::util::nat_to_f;
  let forged_witness = MdocEcdsaWitness {
    qx: nat_to_f(&victim_q.0).expect("qx fits"),
    qy: nat_to_f(&victim_q.1).expect("qy fits"),
    r: attacker_sig.0,
    s: attacker_sig.1,
    s_inv: attacker_sig.2,
  };

  let outcome = (|| -> Result<_, Box<dyn std::error::Error>> {
    let keys = zk_cred_vega::setup()?;
    let nonce = zk_cred_vega::fresh_nonce()?;
    let prep = zk_cred_vega::prep_prove(&keys.pk, &claims, &forged_witness, &mso_body, &nonce)?;
    let (proof, _next_prep) = zk_cred_vega::prove(&keys.pk, &claims, &forged_witness, &mso_body, prep, &nonce)?;
    let (step_public_values, core_public_values) = zk_cred_vega::verify(&proof, &keys.vk)?;
    let verified = zk_cred_vega::verify_and_check_binding(&step_public_values, &core_public_values, &disclosed_for(&claims))?;
    Ok(verified)
  })();

  assert!(
    outcome.is_err(),
    "a signature genuinely valid for the ATTACKER's key must not verify as belonging to the VICTIM's qx/qy \
     -- got Ok({outcome:?}), meaning the pipeline accepted a forged key binding"
  );
}

// Deliberately NOT tested here: "verify a genuine proof against a
// *different* `setup()` call's verifier key." Checked directly against
// the source first -- `setup()` (`src/lib.rs`) derives `pk`/`vk` from a
// fully fixed, hardcoded prototype witness with no randomness anywhere
// in the call chain, so two `setup()` calls for the same `MAX_CLAIMS_V1`
// circuit shape are not independent keys the way a per-tenant trusted
// setup would be -- they're deterministically identical, by design
// (this is what lets `go-zk-circuits` publish exactly one verifier key
// per circuit version for every relying party to share). An earlier
// version of this test asserted the opposite and failed -- not because
// of a crate bug, but because the test's own premise (that a second
// `setup()` call produces a meaningfully different key) doesn't hold
// for this circuit. Confirmed empirically before deleting the test
// rather than leaving a permanently-red assertion in the suite.

/// Real-fixture-scale analogue of `binding_check_rejects_mismatched_digest_ids`
/// (see this file's module doc for why the short hand-rolled version
/// alone isn't sufficient coverage): takes one real, independently-minted
/// claim and witnesses a `digest_id` that does NOT match what's actually
/// CBOR-encoded inside its real bytes at `digest_id_extract::DIGEST_ID_OFFSET_BYTES`
/// -- everything else (the claim bytes themselves, the ECDSA signature,
/// the MSO body) stays genuinely valid and self-consistent.
#[test]
fn wrong_digest_id_on_a_real_claim_is_rejected() {
  let fixture = load_fixture();
  let mso_body = fixture_mso_body(&fixture);
  let ecdsa_witness = fixture_ecdsa_witness(&fixture);

  let mut claims = fixture_claims(&fixture);
  // family_name's real digest_id is 5 (see the fixture's own JSON) --
  // claim a different one instead of what's really embedded in its bytes.
  let real_digest_id = claims[0].digest_id;
  claims[0].digest_id = real_digest_id.wrapping_add(1);

  let outcome = (|| -> Result<_, Box<dyn std::error::Error>> {
    let keys = zk_cred_vega::setup()?;
    let nonce = zk_cred_vega::fresh_nonce()?;
    let prep = zk_cred_vega::prep_prove(&keys.pk, &claims, &ecdsa_witness, &mso_body, &nonce)?;
    let (proof, _next_prep) = zk_cred_vega::prove(&keys.pk, &claims, &ecdsa_witness, &mso_body, prep, &nonce)?;
    let (step_public_values, core_public_values) = zk_cred_vega::verify(&proof, &keys.vk)?;
    let verified = zk_cred_vega::verify_and_check_binding(&step_public_values, &core_public_values, &disclosed_for(&claims))?;
    Ok(verified)
  })();

  assert!(
    outcome.is_err(),
    "witnessing digest_id={} for a real claim whose actual embedded digestID is {real_digest_id} must be rejected \
     -- got Ok({outcome:?})",
    real_digest_id.wrapping_add(1)
  );
}

/// The direct, positive-property regression test for the fix itself
/// (rather than the negative/rejection tests above): presents the exact
/// same real credential (identical claims, identical ECDSA witness/MSO
/// body) *twice*, each through its own fresh `setup->prep_prove->prove`
/// run (not a reused prep state -- see `fresh_nonce`'s doc for why a
/// reused prep state can't get a fresh nonce), and confirms the wire
/// value for an UNDISCLOSED claim (`birth_date`, never revealed) differs
/// completely between the two presentations. Before this fix, that
/// position on the wire was the claim's raw, unblinded SHA-256 digest --
/// identical on every presentation of the same credential, letting any
/// two relying parties who both saw it trivially confirm "same
/// credential, same hidden value" without ever learning the plaintext.
#[test]
fn two_presentations_of_the_same_undisclosed_claim_are_unlinkable() {
  let fixture = load_fixture();
  let claims = fixture_claims(&fixture);
  let mso_body = fixture_mso_body(&fixture);
  let ecdsa_witness = fixture_ecdsa_witness(&fixture);

  // birth_date (index 2 in the fixture) is undisclosed -- see the
  // fixture's own JSON (`disclose: false`).
  let undisclosed_index = fixture
    .claims
    .iter()
    .position(|c| !c.disclose)
    .expect("fixture has an undisclosed claim");
  assert!(!claims[undisclosed_index].disclose);

  let wire_value_for = || -> Vec<<zk_cred_vega::Engine_ as vega_prover::traits::Engine>::Scalar> {
    let keys = zk_cred_vega::setup().expect("setup");
    let nonce = zk_cred_vega::fresh_nonce().expect("fresh_nonce");
    let prep = zk_cred_vega::prep_prove(&keys.pk, &claims, &ecdsa_witness, &mso_body, &nonce).expect("prep_prove");
    let (proof, _next_prep) =
      zk_cred_vega::prove(&keys.pk, &claims, &ecdsa_witness, &mso_body, prep, &nonce).expect("prove");
    let (step_public_values, _core_public_values) = zk_cred_vega::verify(&proof, &keys.vk).expect("verify");
    step_public_values[undisclosed_index][0..256].to_vec()
  };

  let first = wire_value_for();
  let second = wire_value_for();
  assert_ne!(
    first, second,
    "the same undisclosed claim's wire value must differ across two independent presentations of the same \
     credential -- an identical value here means the digest is still linkable across relying parties"
  );
}
