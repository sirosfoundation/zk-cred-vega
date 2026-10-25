// SPDX-License-Identifier: BSD-2-Clause
//! The nymauth C ABI (`src/nymauth_go_ffi.rs`) called as C would: argument validation, status
//! codes, seed zeroing and buffer ownership. The cgo smoke test over the credential fixtures is
//! `go/nymauth/nymauth_test.go`.

use std::ptr::{null, null_mut};
use std::sync::OnceLock;

use zk_cred_vega::nymauth_go_ffi::*;

fn s(b: &[u8]) -> ZkNymSlice {
  ZkNymSlice { ptr: b.as_ptr(), len: b.len() }
}

fn dir() -> std::path::PathBuf {
  std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-vectors/nymauth")
}

fn keys() -> *mut ZkNymKeys {
  struct P(*mut ZkNymKeys);
  unsafe impl Send for P {}
  unsafe impl Sync for P {}
  static K: OnceLock<P> = OnceLock::new();
  K.get_or_init(|| {
    let shapes = zstd::stream::decode_all(&std::fs::read(dir().join("shapes.zst")).unwrap()[..]).unwrap();
    let mut k = null_mut();
    assert_eq!(unsafe { zk_cred_vega_nymauth_load_keys(shapes.as_ptr(), shapes.len(), &mut k) }, ZK_NYM_OK);
    assert!(!k.is_null());
    P(k)
  })
  .0
}

struct Fx {
  x: Vec<u8>,
  y: Vec<u8>,
  e2: Vec<u8>,
  vi: Vec<u8>,
  proof: Vec<u8>,
  pseudonym: Vec<u8>,
}

fn fx() -> Fx {
  let req: serde_json::Value = serde_json::from_slice(&std::fs::read(dir().join("verifier.json")).unwrap()).unwrap();
  let nym: serde_json::Value = serde_json::from_slice(&std::fs::read(dir().join("pseudonym.json")).unwrap()).unwrap();
  let (x, y) = req["issuer_key"].as_str().unwrap().split_once(',').unwrap();
  let v = &nym["verifiers"][0];
  Fx {
    x: hex::decode(x).unwrap(),
    y: hex::decode(y).unwrap(),
    e2: hex::decode(v["mdoc"]["challenge_digest"].as_str().unwrap()).unwrap(),
    vi: hex::decode(v["verifier_input"].as_str().unwrap()).unwrap(),
    proof: std::fs::read(dir().join("reference-proof.bin")).unwrap(),
    pseudonym: hex::decode(v["pseudonym"].as_str().unwrap()).unwrap(),
  }
}

fn statement(f: &Fx) -> ZkNymStatement {
  ZkNymStatement {
    issuer_key_x: s(&f.x),
    issuer_key_y: s(&f.y),
    time: s(b"2026-10-07T12:00:00Z"),
    earliest: s(b"0000-00-00"),
    cutoff: s(b"2008-10-07"),
    challenge_digest: s(&f.e2),
    verifier_input: s(&f.vi),
  }
}

#[test]
fn verify_accepts_the_reference_proof_and_returns_the_pseudonym() {
  let f = fx();
  let st = statement(&f);
  let mut out = [0u8; 32];
  let r = unsafe { zk_cred_vega_nymauth_verify(keys(), &st, f.proof.as_ptr(), f.proof.len(), out.as_mut_ptr()) };
  assert_eq!(r, ZK_NYM_OK);
  assert_eq!(out.to_vec(), f.pseudonym);
}

#[test]
fn verify_refuses_by_status_code() {
  let f = fx();
  let mut out = [0u8; 32];
  let mut st = statement(&f);
  let other = [0x5fu8; 32];
  st.verifier_input = s(&other);
  assert_eq!(
    unsafe { zk_cred_vega_nymauth_verify(keys(), &st, f.proof.as_ptr(), f.proof.len(), out.as_mut_ptr()) },
    ZK_NYM_MISMATCH
  );
  assert_eq!(out, [0u8; 32], "no pseudonym is written on a refusal");
  let st = statement(&f);
  let mut longer = f.proof.clone();
  longer.push(0);
  assert_eq!(
    unsafe { zk_cred_vega_nymauth_verify(keys(), &st, longer.as_ptr(), longer.len(), out.as_mut_ptr()) },
    ZK_NYM_PROOF_ENCODING
  );
}

#[test]
fn null_pointers_and_oversize_lengths_are_invalid_arguments_not_crashes() {
  let f = fx();
  let st = statement(&f);
  let mut out = [0u8; 32];
  unsafe {
    assert_eq!(
      zk_cred_vega_nymauth_verify(null(), &st, f.proof.as_ptr(), f.proof.len(), out.as_mut_ptr()),
      ZK_NYM_INVALID_ARG
    );
    assert_eq!(
      zk_cred_vega_nymauth_verify(keys(), null(), f.proof.as_ptr(), f.proof.len(), out.as_mut_ptr()),
      ZK_NYM_INVALID_ARG
    );
    assert_eq!(
      zk_cred_vega_nymauth_verify(keys(), &st, f.proof.as_ptr(), f.proof.len(), null_mut()),
      ZK_NYM_INVALID_ARG
    );
    // a null proof with a non-zero length, and a length past the cap
    assert_eq!(zk_cred_vega_nymauth_verify(keys(), &st, null(), 10, out.as_mut_ptr()), ZK_NYM_INVALID_ARG);
    assert_eq!(
      zk_cred_vega_nymauth_verify(keys(), &st, f.proof.as_ptr(), usize::MAX, out.as_mut_ptr()),
      ZK_NYM_INVALID_ARG
    );
    // a statement slice that is null with a length
    let mut bad = st;
    bad.time = ZkNymSlice { ptr: null(), len: 20 };
    assert_eq!(
      zk_cred_vega_nymauth_verify(keys(), &bad, f.proof.as_ptr(), f.proof.len(), out.as_mut_ptr()),
      ZK_NYM_INVALID_ARG
    );
    // load_keys
    let mut k = std::ptr::dangling_mut::<ZkNymKeys>();
    assert_eq!(zk_cred_vega_nymauth_load_keys(null(), 5, &mut k), ZK_NYM_INVALID_ARG);
    assert!(k.is_null(), "the handle is nulled on failure");
    assert_eq!(zk_cred_vega_nymauth_load_keys(null(), 0, null_mut()), ZK_NYM_INVALID_ARG);
    assert_eq!(zk_cred_vega_nymauth_load_keys([1u8, 2, 3].as_ptr(), 3, &mut k), ZK_NYM_UNKNOWN_CIRCUIT);
    // freeing null is a no-op
    zk_cred_vega_nymauth_free_keys(null_mut());
    zk_cred_vega_nymauth_free_buffer(null_mut(), 0);
  }
}

#[test]
fn prove_zeroes_the_seed_on_every_path_and_refuses_by_code() {
  let f = fx();
  let st = statement(&f);
  let mut seed = *b"0123456789abcdef";
  let holder = ZkNymHolder {
    issuer_signed: s(&[0xff]),
    secret_seed: seed.as_mut_ptr(),
    secret_seed_len: 16,
    device_signature: s(&[0u8; 64]),
  };
  let (mut p, mut n, mut pseud) = (null_mut(), 0usize, [0u8; 32]);
  let r = unsafe { zk_cred_vega_nymauth_prove(keys(), &st, &holder, &mut p, &mut n, pseud.as_mut_ptr()) };
  assert_eq!(r, ZK_NYM_INVALID_INPUT);
  assert!(p.is_null() && n == 0);
  assert_eq!(seed, [0u8; 16], "zeroed after an input error");
  // a null statement is an invalid argument and still zeroes the seed
  let mut seed = *b"0123456789abcdef";
  let holder = ZkNymHolder {
    secret_seed: seed.as_mut_ptr(),
    ..holder
  };
  let r = unsafe { zk_cred_vega_nymauth_prove(keys(), null(), &holder, &mut p, &mut n, pseud.as_mut_ptr()) };
  assert_eq!(r, ZK_NYM_INVALID_ARG);
  assert_eq!(seed, [0u8; 16], "zeroed after an invalid argument");
}

#[test]
fn derive_challenge_returns_e2_and_an_owned_transcript() {
  let (mut e2, mut t, mut n) = ([0u8; 32], null_mut(), 0usize);
  let r = unsafe {
    zk_cred_vega_nymauth_derive_challenge(
      s(b"https://verifier.example"),
      s(b"pOA0oqEAhLnqug2r7Ve4tQ"),
      s(b"eu.europa.ec.eudi.nym_auth.1"),
      ZkNymSlice { ptr: null(), len: 0 },
      &mut t,
      &mut n,
      e2.as_mut_ptr(),
    )
  };
  assert_eq!(r, ZK_NYM_OK);
  assert_eq!(hex::encode(e2), "7eea0f8e073961c3e82e9562e0f79edaa66dbfc17eaf0ac0596a987733516dd9");
  let transcript = unsafe { std::slice::from_raw_parts(t, n) }.to_vec();
  let mut again = [0u8; 32];
  assert_eq!(
    unsafe { zk_cred_vega_nymauth_challenge_digest(s(&transcript), s(b"eu.europa.ec.eudi.nym_auth.1"), again.as_mut_ptr()) },
    ZK_NYM_OK
  );
  assert_eq!(again, e2);
  unsafe { zk_cred_vega_nymauth_free_buffer(t, n) };
  // short nonce, empty transcript
  let r = unsafe {
    zk_cred_vega_nymauth_derive_challenge(
      s(b"https://v"),
      s(b"short"),
      s(b"d"),
      ZkNymSlice { ptr: null(), len: 0 },
      &mut t,
      &mut n,
      e2.as_mut_ptr(),
    )
  };
  assert_eq!(r, ZK_NYM_INVALID_INPUT);
  assert!(t.is_null());
  assert_eq!(
    unsafe { zk_cred_vega_nymauth_challenge_digest(s(&[]), s(b"d"), again.as_mut_ptr()) },
    ZK_NYM_INVALID_INPUT
  );
}

#[test]
fn verifier_input_is_sha256_of_the_client_id() {
  let mut out = [0u8; 32];
  assert_eq!(
    unsafe { zk_cred_vega_nymauth_verifier_input(s(b"x509_san_dns:verifier.example"), out.as_mut_ptr()) },
    ZK_NYM_OK
  );
  assert_eq!(hex::encode(out), "6eae85a0b2dfcd7d8b716291e54a004da798f93a26a248c265becd33a04a6bab");
  assert_eq!(unsafe { zk_cred_vega_nymauth_verifier_input(s(b""), out.as_mut_ptr()) }, ZK_NYM_INVALID_INPUT);
  assert_eq!(unsafe { zk_cred_vega_nymauth_verifier_input(s(b"x"), null_mut()) }, ZK_NYM_INVALID_ARG);
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

#[test]
fn prove_succeeds_through_the_abi_and_the_proof_verifies() {
  let f = fx();
  let st = statement(&f);
  let nym: serde_json::Value = serde_json::from_slice(&std::fs::read(dir().join("pseudonym.json")).unwrap()).unwrap();
  let mut seed = hex::decode(nym["holder"]["test_seed"].as_str().unwrap()).unwrap();
  let dev = hex::decode(nym["verifiers"][0]["mdoc"]["device_signature"].as_str().unwrap()).unwrap();
  let cred = b64url(&std::fs::read_to_string(dir().join("nym-auth-mdoc.txt")).unwrap());
  let holder = ZkNymHolder {
    issuer_signed: s(&cred),
    secret_seed: seed.as_mut_ptr(),
    secret_seed_len: seed.len(),
    device_signature: s(&dev),
  };
  let (mut p, mut n, mut pseud) = (null_mut(), 0usize, [0u8; 32]);
  assert_eq!(
    unsafe { zk_cred_vega_nymauth_prove(keys(), &st, &holder, &mut p, &mut n, pseud.as_mut_ptr()) },
    ZK_NYM_OK
  );
  assert_eq!(pseud.to_vec(), f.pseudonym);
  assert!(seed.iter().all(|b| *b == 0), "the seed is zeroed after success too");
  let proof = unsafe { std::slice::from_raw_parts(p, n) }.to_vec();
  let mut out = [0u8; 32];
  assert_eq!(
    unsafe { zk_cred_vega_nymauth_verify(keys(), &st, proof.as_ptr(), proof.len(), out.as_mut_ptr()) },
    ZK_NYM_OK
  );
  assert_eq!(out.to_vec(), f.pseudonym);
  unsafe { zk_cred_vega_nymauth_free_buffer(p, n) };
}

#[test]
fn prove_and_the_helpers_refuse_every_invalid_argument() {
  let f = fx();
  let st = statement(&f);
  let mut seed = [1u8; 16];
  let (mut p, mut n, mut pseud) = (null_mut(), 0usize, [0u8; 32]);
  let good = ZkNymHolder {
    issuer_signed: s(&[0xff]),
    secret_seed: seed.as_mut_ptr(),
    secret_seed_len: 16,
    device_signature: s(&[0u8; 64]),
  };
  unsafe {
    // null keys, holder, outputs
    assert_eq!(
      zk_cred_vega_nymauth_prove(null(), &st, &good, &mut p, &mut n, pseud.as_mut_ptr()),
      ZK_NYM_INVALID_ARG
    );
    assert_eq!(
      zk_cred_vega_nymauth_prove(keys(), &st, null(), &mut p, &mut n, pseud.as_mut_ptr()),
      ZK_NYM_INVALID_ARG
    );
    assert_eq!(
      zk_cred_vega_nymauth_prove(keys(), &st, &good, null_mut(), &mut n, pseud.as_mut_ptr()),
      ZK_NYM_INVALID_ARG
    );
    // a null or over-long seed is refused without being read
    let no_seed = ZkNymHolder {
      secret_seed: null_mut(),
      ..good
    };
    assert_eq!(
      zk_cred_vega_nymauth_prove(keys(), &st, &no_seed, &mut p, &mut n, pseud.as_mut_ptr()),
      ZK_NYM_INVALID_ARG
    );
    let long_seed = ZkNymHolder {
      secret_seed_len: usize::MAX,
      ..good
    };
    assert_eq!(
      zk_cred_vega_nymauth_prove(keys(), &st, &long_seed, &mut p, &mut n, pseud.as_mut_ptr()),
      ZK_NYM_INVALID_ARG
    );
    // a credential or signature slice that is null with a length
    let bad = ZkNymHolder {
      issuer_signed: ZkNymSlice { ptr: null(), len: 5 },
      ..good
    };
    assert_eq!(
      zk_cred_vega_nymauth_prove(keys(), &st, &bad, &mut p, &mut n, pseud.as_mut_ptr()),
      ZK_NYM_INVALID_ARG
    );
    let bad = ZkNymHolder {
      device_signature: ZkNymSlice { ptr: null(), len: 5 },
      ..good
    };
    assert_eq!(
      zk_cred_vega_nymauth_prove(keys(), &st, &bad, &mut p, &mut n, pseud.as_mut_ptr()),
      ZK_NYM_INVALID_ARG
    );

    // derive_challenge: null outputs, a bad text slice, and a thumbprint of 32 bytes
    let none = ZkNymSlice { ptr: null(), len: 0 };
    let (mut e2, mut t, mut tl) = ([0u8; 32], null_mut(), 0usize);
    let origin = s(b"https://verifier.example");
    let nonce = s(b"pOA0oqEAhLnqug2r7Ve4tQ");
    let doc = s(b"eu.europa.ec.eudi.nym_auth.1");
    assert_eq!(
      zk_cred_vega_nymauth_derive_challenge(origin, nonce, doc, none, null_mut(), &mut tl, e2.as_mut_ptr()),
      ZK_NYM_INVALID_ARG
    );
    assert_eq!(
      zk_cred_vega_nymauth_derive_challenge(origin, nonce, doc, none, &mut t, null_mut(), e2.as_mut_ptr()),
      ZK_NYM_INVALID_ARG
    );
    assert_eq!(
      zk_cred_vega_nymauth_derive_challenge(origin, nonce, doc, none, &mut t, &mut tl, null_mut()),
      ZK_NYM_INVALID_ARG
    );
    assert_eq!(
      zk_cred_vega_nymauth_derive_challenge(ZkNymSlice { ptr: null(), len: 4 }, nonce, doc, none, &mut t, &mut tl, e2.as_mut_ptr()),
      ZK_NYM_INVALID_ARG
    );
    let thumb = [0x11u8; 32];
    assert_eq!(
      zk_cred_vega_nymauth_derive_challenge(origin, nonce, doc, s(&thumb), &mut t, &mut tl, e2.as_mut_ptr()),
      ZK_NYM_OK
    );
    assert_eq!(hex::encode(e2), "59481f3b8d5ddc29777522b268170f5bc4cba969e5344de22d33857677550724");
    zk_cred_vega_nymauth_free_buffer(t, tl);
    assert_eq!(
      zk_cred_vega_nymauth_derive_challenge(origin, nonce, doc, s(&thumb[..31]), &mut t, &mut tl, e2.as_mut_ptr()),
      ZK_NYM_INVALID_INPUT
    );

    // challenge_digest: null output, a bad slice
    assert_eq!(
      zk_cred_vega_nymauth_challenge_digest(s(&[0x83, 0xf6, 0xf6, 0xf6]), doc, null_mut()),
      ZK_NYM_INVALID_ARG
    );
    assert_eq!(
      zk_cred_vega_nymauth_challenge_digest(ZkNymSlice { ptr: null(), len: 4 }, doc, e2.as_mut_ptr()),
      ZK_NYM_INVALID_ARG
    );
    assert_eq!(
      zk_cred_vega_nymauth_challenge_digest(s(&[0x83, 0xf6, 0xf6, 0xf6]), ZkNymSlice { ptr: null(), len: 4 }, e2.as_mut_ptr()),
      ZK_NYM_INVALID_ARG
    );
    // verifier_input: a bad slice
    assert_eq!(
      zk_cred_vega_nymauth_verifier_input(ZkNymSlice { ptr: null(), len: 4 }, e2.as_mut_ptr()),
      ZK_NYM_INVALID_ARG
    );
  }
}

/// Every way out of prove zeroes the caller's seed, argument-validation failures included.
#[test]
fn prove_zeroes_the_seed_on_every_argument_failure() {
  let f = fx();
  let st = statement(&f);
  let (mut p, mut n, mut pseud) = (null_mut::<u8>(), 0usize, [0u8; 32]);
  let cred = [0xffu8];
  let sig = [0u8; 64];
  /// The pointers a call is given; each case changes one of them.
  #[derive(Clone, Copy)]
  struct Args {
    keys: *const ZkNymKeys,
    st: *const ZkNymStatement,
    out: *mut *mut u8,
    len_out: *mut usize,
    ps: *mut u8,
  }
  let good = Args {
    keys: keys(),
    st: &st,
    out: &mut p,
    len_out: &mut n,
    ps: pseud.as_mut_ptr(),
  };
  let run = |args: Args, mutate: &dyn Fn(&mut ZkNymHolder), want: i32, what: &str| {
    let mut seed = [0x5au8; 16];
    let mut holder = ZkNymHolder {
      issuer_signed: s(&cred),
      secret_seed: seed.as_mut_ptr(),
      secret_seed_len: 16,
      device_signature: s(&sig),
    };
    mutate(&mut holder);
    let r = unsafe { zk_cred_vega_nymauth_prove(args.keys, args.st, &holder, args.out, args.len_out, args.ps) };
    assert_eq!(r, want, "{what}");
    assert_eq!(seed, [0u8; 16], "{what}: the seed was not zeroed");
  };
  let none: &dyn Fn(&mut ZkNymHolder) = &|_| {};
  run(Args { keys: null(), ..good }, none, ZK_NYM_INVALID_ARG, "null keys");
  run(Args { out: null_mut(), ..good }, none, ZK_NYM_INVALID_ARG, "null proof out");
  run(Args { len_out: null_mut(), ..good }, none, ZK_NYM_INVALID_ARG, "null length out");
  run(Args { ps: null_mut(), ..good }, none, ZK_NYM_INVALID_ARG, "null pseudonym out");
  run(Args { st: null(), ..good }, none, ZK_NYM_INVALID_ARG, "null statement");
  run(
    good,
    &|h| h.issuer_signed = ZkNymSlice { ptr: null(), len: 3 },
    ZK_NYM_INVALID_ARG,
    "null credential with a length",
  );
  run(
    good,
    &|h| {
      h.issuer_signed = ZkNymSlice {
        ptr: cred.as_ptr(),
        len: usize::MAX,
      }
    },
    ZK_NYM_INVALID_ARG,
    "credential length past its cap",
  );
  run(
    good,
    &|h| h.device_signature = ZkNymSlice { ptr: null(), len: 3 },
    ZK_NYM_INVALID_ARG,
    "null device signature with a length",
  );
  run(good, none, ZK_NYM_INVALID_INPUT, "malformed credential");
  // a seed of the wrong length is an input error and is zeroed too
  let mut seed = [0x5au8; 8];
  let holder = ZkNymHolder {
    issuer_signed: s(&cred),
    secret_seed: seed.as_mut_ptr(),
    secret_seed_len: 8,
    device_signature: s(&sig),
  };
  let r = unsafe { zk_cred_vega_nymauth_prove(keys(), &st, &holder, &mut p, &mut n, pseud.as_mut_ptr()) };
  assert_eq!(r, ZK_NYM_INVALID_INPUT);
  assert_eq!(seed, [0u8; 8]);
  // no holder at all: nothing to zero, and no crash
  let r = unsafe { zk_cred_vega_nymauth_prove(keys(), &st, null(), &mut p, &mut n, pseud.as_mut_ptr()) };
  assert_eq!(r, ZK_NYM_INVALID_ARG);
}
