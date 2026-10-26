// SPDX-License-Identifier: BSD-2-Clause
//! `nymauth_vega_prove_with`: the same proof on one thread, on two and on the global pool, over the
//! reference credential of the nym_auth circuits archive and the published shapes (as
//! `nymauth_vega_e2e.rs`).

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
      seed: hex::decode(s(&nym, &["holder", "test_seed"])).unwrap(),
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
    let shapes = zstd::stream::decode_all(&std::fs::read(dir().join("shapes.zst")).unwrap()[..]).unwrap();
    let t = Instant::now();
    let keys = nymauth_vega_load_keys(shapes).unwrap();
    eprintln!("nymauth key setup from shapes: {:?}", t.elapsed());
    keys
  })
}

#[test]
fn proves_on_one_thread_on_two_and_on_the_global_pool() {
  let f = Fixture::load();
  for threads in [1u32, 2, 0] {
    let t = Instant::now();
    let p = nymauth_vega_prove_with(keys(), f.statement.clone(), f.holder(), threads).unwrap();
    eprintln!("threads {threads}: {:?}", t.elapsed());
    assert_eq!(p.pseudonym, f.pseudonym);
    assert_eq!(nymauth_vega_verify(keys(), f.statement.clone(), p.proof.clone()).unwrap(), f.pseudonym);
  }
}

#[test]
fn a_refusal_comes_back_as_from_nymauth_vega_prove() {
  let f = Fixture::load();
  let mut h = f.holder();
  h.secret_seed[0] ^= 1;
  let e = nymauth_vega_prove_with(keys(), f.statement.clone(), h, 1).err().unwrap();
  assert!(matches!(e, NymAuthVegaError::Refused { .. }), "{e:?}");
}
