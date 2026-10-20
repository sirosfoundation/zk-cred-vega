// SPDX-License-Identifier: BSD-2-Clause
//! The shared challenge vectors (`test-vectors/nymauth/challenge-vectors.json`, byte-identical in
//! zk-cred-vega and zk-cred-longfellow): e2 and the transcript seed per `SPEC.md` section 3.

use serde_json::Value as Json;
use zk_cred_vega::nymauth_vega::{NymAuthVegaError, nymauth_challenge_digest, nymauth_derive_challenge};

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
    let c = nymauth_derive_challenge(s(case, "origin"), s(case, "nonce"), s(case, "doc_type"), thumb(case)).unwrap();
    assert_eq!(hex::encode(&c.session_transcript), s(case, "session_transcript_hex"), "{}", s(case, "name"));
    assert_eq!(hex::encode(&c.challenge_digest), s(case, "challenge_digest_hex"), "{}", s(case, "name"));
    // the digest of the transcript alone agrees
    let d = nymauth_challenge_digest(c.session_transcript, s(case, "doc_type")).unwrap();
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
  let d = nymauth_challenge_digest(st, s(case, "doc_type")).unwrap();
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
      "derive" => nymauth_derive_challenge(s(case, "origin"), s(case, "nonce"), s(case, "doc_type"), thumb(case)).map(|_| ()),
      "digest" => nymauth_challenge_digest(hex::decode(s(case, "session_transcript_hex")).unwrap(), s(case, "doc_type")).map(|_| ()),
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
  assert!(nymauth_derive_challenge("https://verifier.example".into(), nonce, "x".into(), None).is_ok());
}

#[test]
fn verifier_input_is_the_sha256_of_the_client_id_and_fields_are_capped() {
  use zk_cred_vega::nymauth_vega::nymauth_verifier_input;
  let nym: Json = serde_json::from_slice(&std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors/nymauth/pseudonym.json")).unwrap()).unwrap();
  let v = &nym["verifiers"][0];
  let vi = nymauth_verifier_input(v["client_id"].as_str().unwrap().to_string()).unwrap();
  assert_eq!(hex::encode(vi), v["verifier_input"].as_str().unwrap());
  assert!(nymauth_verifier_input(String::new()).is_err());
  assert!(nymauth_verifier_input("x".repeat(4097)).is_err());
  assert!(nymauth_verifier_input("x".repeat(4096)).is_ok());
  let long = "o".repeat(4097);
  assert!(nymauth_derive_challenge(long, "pOA0oqEAhLnqug2r7Ve4tQ".into(), "d".into(), None).is_err());
}

// The redirect (OpenID4VPHandover) vectors. There is no redirect `derive` entry point yet, so these tests
// run the vectors through the channel-agnostic code that exists (`nymauth_challenge_digest`).

fn sha256_of(b: &[u8]) -> Vec<u8> {
  use sha2::{Digest, Sha256};
  Sha256::digest(b).to_vec()
}

/// `[null, null, ["OpenID4VPHandover", bstr(SHA-256(handover_info))]]`, assembled from the vector's own
/// `handover_info_hex` (OpenID4VP 1.0 appendix B.2.6.1).
fn redirect_transcript_from_info(info: &[u8]) -> Vec<u8> {
  let mut st = vec![0x83, 0xf6, 0xf6, 0x82, 0x71];
  st.extend_from_slice(b"OpenID4VPHandover");
  st.extend_from_slice(&[0x58, 0x20]);
  st.extend_from_slice(&sha256_of(info));
  st
}

#[test]
fn redirect_vectors_give_their_e2_through_the_channel_agnostic_digest() {
  let v = vectors();
  let all = v["derive_redirect"].as_array().unwrap();
  assert!(all.len() >= 6);
  for case in all {
    let name = s(case, "name");
    let st = hex::decode(s(case, "session_transcript_hex")).unwrap();
    // the transcript is the handover over exactly the listed OpenID4VPHandoverInfo
    let info = hex::decode(s(case, "handover_info_hex")).unwrap();
    assert_eq!(st, redirect_transcript_from_info(&info), "{name}");
    // over redirects the response is encrypted: a 32-byte thumbprint is the third member (0x58 0x20)
    assert!(thumb(case).is_some_and(|t| t.len() == 32), "{name}");
    assert_eq!(info[0], 0x84, "{name}: OpenID4VPHandoverInfo is a 4-item array");
    // e2 is the shared digest of the transcript, and is not the DC API's
    let d = nymauth_challenge_digest(st, s(case, "doc_type")).unwrap();
    assert_eq!(hex::encode(d), s(case, "challenge_digest_hex"), "{name}");
  }
}

#[test]
fn every_redirect_reject_vector_breaks_a_rule_and_the_digest_refuses_what_it_can() {
  let v = vectors();
  let min = v["min_nonce_chars"].as_u64().unwrap() as usize;
  let rejects = v["rejects_redirect"].as_array().unwrap();
  assert!(rejects.len() >= 8);
  for case in rejects {
    let name = s(case, "name");
    assert_eq!(s(case, "op"), "derive_redirect", "{name}");
    let t = thumb(case);
    let broken = s(case, "client_id").is_empty()
      || s(case, "nonce").chars().count() < min
      || s(case, "response_uri").is_empty()
      || s(case, "doc_type").is_empty()
      || t.as_ref().is_none_or(|t| t.len() != 32);
    assert!(broken, "{name} breaks none of the redirect rules: it is not a reject vector");
    // the one rule the existing code enforces: an empty docType is refused by the digest
    if s(case, "doc_type").is_empty() {
      let st = redirect_transcript_from_info(b"x");
      assert!(
        matches!(nymauth_challenge_digest(st, String::new()), Err(NymAuthVegaError::InvalidInput { .. })),
        "{name}"
      );
    }
  }
  // the null thumbprint is a reject over redirects, and carries its reason
  assert!(
    rejects
      .iter()
      .any(|c| c["jwk_thumbprint_hex"].is_null() && c["reason"].as_str().is_some_and(|r| r.contains("encrypted")))
  );
}
