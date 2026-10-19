// SPDX-License-Identifier: BSD-2-Clause
//! The shared challenge vectors (`test-vectors/nymauth/challenge-vectors.json`, byte-identical in
//! zk-cred-vega and zk-cred-longfellow): e2 and the transcript seed per `SPEC.md` section 3.

use serde_json::Value as Json;
use zk_cred_vega::nymauth_vega::{NymAuthVegaError, nymauth_vega_challenge_digest, nymauth_vega_derive_challenge};

fn vectors() -> Json {
  let path = concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors/nymauth/challenge-vectors.json");
  serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn s(j: &Json, k: &str) -> String {
  j[k].as_str().unwrap().to_string()
}

fn thumb(j: &Json) -> Option<Vec<u8>> {
  j["jwk_thumbprint_hex"].as_str().map(|h| hex::decode(h).unwrap())
}

#[test]
fn derive_matches_every_shared_vector() {
  let v = vectors();
  let all = v["derive"].as_array().unwrap();
  assert!(all.len() >= 4);
  for case in all {
    let c = nymauth_vega_derive_challenge(s(case, "origin"), s(case, "nonce"), s(case, "doc_type"), thumb(case)).unwrap();
    assert_eq!(hex::encode(&c.session_transcript), s(case, "session_transcript_hex"), "{}", s(case, "name"));
    assert_eq!(hex::encode(&c.challenge_digest), s(case, "challenge_digest_hex"), "{}", s(case, "name"));
    // the digest of the transcript alone agrees
    let d = nymauth_vega_challenge_digest(c.session_transcript, s(case, "doc_type")).unwrap();
    assert_eq!(hex::encode(d), s(case, "challenge_digest_hex"));
  }
}

#[test]
fn the_archive_fixture_e2_is_the_credential_pseudonym_json_value() {
  // verifier 1's e2 is the one the fixtures' device signature was made over.
  let path = concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors/nymauth/pseudonym.json");
  let nym: Json = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
  let listed = nym["verifiers"][0]["mdoc"]["challenge_digest"].as_str().unwrap();
  assert_eq!(vectors()["derive"][0]["challenge_digest_hex"].as_str().unwrap(), listed);
}

#[test]
fn the_kotlin_fixture_transcript_gives_the_red_team_e2() {
  let v = vectors();
  let case = &v["digest"][0];
  let st = hex::decode(s(case, "session_transcript_hex")).unwrap();
  let d = nymauth_vega_challenge_digest(st, s(case, "doc_type")).unwrap();
  let d = hex::encode(d);
  assert_eq!(d, s(case, "challenge_digest_hex"));
  assert!(d.starts_with("205f2280") && d.ends_with("d1a0"));
}

#[test]
fn every_shared_reject_vector_is_refused() {
  let v = vectors();
  let rejects = v["rejects"].as_array().unwrap();
  assert!(rejects.len() >= 8);
  for case in rejects {
    let r = match s(case, "op").as_str() {
      "derive" => nymauth_vega_derive_challenge(s(case, "origin"), s(case, "nonce"), s(case, "doc_type"), thumb(case)).map(|_| ()),
      "digest" => nymauth_vega_challenge_digest(hex::decode(s(case, "session_transcript_hex")).unwrap(), s(case, "doc_type")).map(|_| ()),
      other => panic!("unknown op {other}"),
    };
    assert!(
      matches!(r, Err(NymAuthVegaError::InvalidInput { .. })),
      "{} was not refused: {r:?}",
      s(case, "name")
    );
  }
  // and the shortest accepted nonce is exactly min_nonce_chars
  let min = v["min_nonce_chars"].as_u64().unwrap() as usize;
  let nonce: String = "a".repeat(min);
  assert!(nymauth_vega_derive_challenge("https://verifier.example".into(), nonce, "x".into(), None).is_ok());
}
