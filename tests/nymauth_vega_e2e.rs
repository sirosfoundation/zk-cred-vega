//! The `nymauth` binding end to end, over the reference credential of the nym_auth circuits
//! archive (`test-vectors/nymauth/`) and the PUBLISHED shapes (`shapes.zst`, the catalog's
//! `vega-nymauth` mdoc artifact, decompressed here as the SDK does): a real proof verifies, the
//! pseudonym is the fixture's, and tampered inputs are refused. The engine's own statement tests
//! live in the prover fork (`vega-prover/nymauth/tests`).

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use serde_json::Value as Json;
use zk_cred_vega::nymauth_vega::*;

fn dir() -> PathBuf {
  PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-vectors/nymauth")
}

fn json(name: &str) -> Json {
  serde_json::from_slice(&std::fs::read(dir().join(name)).unwrap()).unwrap()
}

fn s<'a>(j: &'a Json, path: &[&str]) -> &'a str {
  path.iter().fold(j, |j, k| &j[*k]).as_str().unwrap()
}

fn b64url(text: &str) -> Vec<u8> {
  let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  let (mut out, mut acc, mut bits) = (Vec::new(), 0u32, 0u32);
  for c in text.trim().bytes() {
    acc = (acc << 6) | alphabet.iter().position(|a| *a == c).unwrap() as u32;
    bits += 6;
    if bits >= 8 {
      bits -= 8;
      out.push((acc >> bits) as u8);
      acc &= (1 << bits) - 1;
    }
  }
  out
}

struct Fixture {
  statement: NymAuthVegaStatement,
  issuer_signed: Vec<u8>,
  seed: Vec<u8>,
  device_signature: Vec<u8>,
  pseudonym: Vec<u8>,
}

impl Fixture {
  fn load() -> Self {
    let (req, nym) = (json("verifier.json"), json("pseudonym.json"));
    let (x, y) = s(&req, &["issuer_key"]).split_once(',').unwrap();
    let v = &nym["verifiers"][0];
    Fixture {
      statement: NymAuthVegaStatement {
        issuer_key_x: hex::decode(x).unwrap(),
        issuer_key_y: hex::decode(y).unwrap(),
        time: s(&req, &["mdoc", "time"]).into(),
        earliest: s(&req, &["mdoc", "earliest"]).into(),
        cutoff: s(&req, &["mdoc", "cutoff"]).into(),
        challenge_digest: hex::decode(s(v, &["mdoc", "challenge_digest"])).unwrap(),
        verifier_input: hex::decode(s(v, &["verifier_input"])).unwrap(),
      },
      issuer_signed: b64url(&std::fs::read_to_string(dir().join("nym-auth-mdoc.txt")).unwrap()),
      seed: hex::decode(s(&nym, &["holder", "secret_seed"])).unwrap(),
      device_signature: hex::decode(s(v, &["mdoc", "device_signature"])).unwrap(),
      pseudonym: hex::decode(s(v, &["pseudonym"])).unwrap(),
    }
  }

  fn holder(&self) -> NymAuthVegaHolder {
    NymAuthVegaHolder {
      issuer_signed: self.issuer_signed.clone(),
      secret_seed: self.seed.clone(),
      device_signature: self.device_signature.clone(),
    }
  }
}

fn keys() -> &'static Arc<NymAuthVegaKeys> {
  static KEYS: OnceLock<Arc<NymAuthVegaKeys>> = OnceLock::new();
  KEYS.get_or_init(|| {
    let shapes =
      zstd::stream::decode_all(&std::fs::read(dir().join("shapes.zst")).unwrap()[..]).unwrap();
    let t = Instant::now();
    let keys = nymauth_vega_load_keys(shapes).unwrap();
    eprintln!("nymauth key setup from shapes: {:?}", t.elapsed());
    keys
  })
}

fn honest() -> &'static (Fixture, NymAuthVegaProof) {
  static HONEST: OnceLock<(Fixture, NymAuthVegaProof)> = OnceLock::new();
  HONEST.get_or_init(|| {
    let f = Fixture::load();
    let t = Instant::now();
    let proof = nymauth_vega_prove(keys(), f.statement.clone(), f.holder()).unwrap();
    eprintln!("nymauth prove: {:?}, {} proof bytes", t.elapsed(), proof.proof.len());
    (f, proof)
  })
}

#[test]
fn a_real_proof_verifies_and_reveals_the_fixture_pseudonym() {
  let (f, proof) = honest();
  assert_eq!(proof.pseudonym, f.pseudonym);
  let t = Instant::now();
  let revealed = nymauth_vega_verify(keys(), f.statement.clone(), proof.proof.clone()).unwrap();
  eprintln!("nymauth verify: {:?}", t.elapsed());
  assert_eq!(revealed, f.pseudonym);
}

#[test]
fn the_catalog_artifacts_own_reference_proof_verifies() {
  // proof.bin of the circuits archive was made by the upstream reference prover.
  let f = Fixture::load();
  let proof = std::fs::read(dir().join("reference-proof.bin")).unwrap();
  assert_eq!(nymauth_vega_verify(keys(), f.statement.clone(), proof).unwrap(), f.pseudonym);
}

#[test]
fn wrong_seed_is_refused() {
  let mut f = Fixture::load();
  f.seed[3] ^= 0x10;
  match nymauth_vega_prove(keys(), f.statement.clone(), f.holder()) {
    Err(NymAuthVegaError::Refused { message }) => assert!(message.contains("seed"), "{message}"),
    other => panic!("expected Refused, got {:?}", other.map(|p| p.proof.len())),
  }
}

#[test]
fn wrong_device_signature_is_refused() {
  let mut f = Fixture::load();
  f.device_signature[10] ^= 1;
  assert!(matches!(
    nymauth_vega_prove(keys(), f.statement.clone(), f.holder()),
    Err(NymAuthVegaError::Refused { .. })
  ));
}

#[test]
fn wrong_issuer_key_is_refused_by_the_prover_and_the_verifier() {
  let mut f = Fixture::load();
  f.statement.issuer_key_x[0] ^= 1;
  assert!(matches!(
    nymauth_vega_prove(keys(), f.statement.clone(), f.holder()),
    Err(NymAuthVegaError::Refused { .. })
  ));
  let (_, proof) = honest();
  assert!(nymauth_vega_verify(keys(), f.statement.clone(), proof.proof.clone()).is_err());
}

#[test]
fn wrong_verifier_input_is_refused_by_the_verifier() {
  let (f, proof) = honest();
  let mut st = f.statement.clone();
  st.verifier_input = hex::decode("5ff3c35cfed806981de9ad610c4a7fe100867aee4530485aed3a0cc6e71f22b1").unwrap();
  assert!(matches!(
    nymauth_vega_verify(keys(), st, proof.proof.clone()),
    Err(NymAuthVegaError::Mismatch { .. }) | Err(NymAuthVegaError::ProofInvalid { .. })
  ));
}

#[test]
fn wrong_challenge_time_and_bounds_are_refused_by_the_verifier() {
  let (f, proof) = honest();
  for edit in [
    (|st: &mut NymAuthVegaStatement| st.challenge_digest[0] ^= 1) as fn(&mut NymAuthVegaStatement),
    |st| st.time = "2026-10-07T12:00:01Z".into(),
    |st| st.cutoff = "2008-10-08".into(),
    |st| st.earliest = "1900-01-01".into(),
  ] {
    let mut st = f.statement.clone();
    edit(&mut st);
    assert!(nymauth_vega_verify(keys(), st, proof.proof.clone()).is_err());
  }
}

#[test]
fn malformed_input_is_a_typed_error() {
  let f = Fixture::load();
  let mut h = f.holder();
  h.issuer_signed = vec![0xff];
  assert!(matches!(
    nymauth_vega_prove(keys(), f.statement.clone(), h),
    Err(NymAuthVegaError::InvalidInput { .. })
  ));
  let mut h = f.holder();
  h.secret_seed.pop();
  assert!(matches!(
    nymauth_vega_prove(keys(), f.statement.clone(), h),
    Err(NymAuthVegaError::InvalidInput { .. })
  ));
  let mut st = f.statement.clone();
  st.time = "yesterday".into();
  assert!(matches!(
    nymauth_vega_verify(keys(), st, vec![]),
    Err(NymAuthVegaError::InvalidInput { .. })
  ));
  assert!(matches!(
    nymauth_vega_load_keys(vec![1, 2, 3]),
    Err(NymAuthVegaError::InvalidShapes { .. })
  ));
}
