//! Plain C-ABI bindings for a Go (cgo) verifier service — the `zk-cred-vega`
//! counterpart of `zk-cred-longfellow`'s own `src/go_ffi.rs` (mirror that
//! file's shape/conventions if this one needs to change).
//!
//! `ffi_api.rs` exports a UniFFI-based ABI (RustBuffer wire format) for the
//! native wallet SDKs, feature-gated behind `uniffi`. UniFFI does not target
//! Go, and its RustBuffer protocol is not cgo-friendly, so this module is a
//! separate, hand-written, ordinary `extern "C"` ABI (plain pointers,
//! lengths, small integer status codes), built unconditionally (no feature
//! flag) — same split as Longfellow's crate.
//!
//! Only the verify path is exposed here: a Go verifier never proves, so
//! `prep_prove`/`prove` have no C-ABI equivalent.
//!
//! ## A real shape difference from Longfellow's C ABI
//!
//! Longfellow's `rust_verify_with_ppid` takes the *expected* attribute
//! values as input and returns only a status code — the caller already
//! knows what should be true and just asks Rust to confirm it. This
//! crate's `verify` takes only the proof and *returns* the recomputed
//! public values (issuer pubkey, disclosed claims, MSO-body fields) for the
//! caller to check against whatever it independently knows — see this
//! crate's own `verify_and_check_binding` doc. [`zk_cred_vega_verify`]
//! mirrors that: a fixed-shape out-param struct, not a bare status code.
//!
//! Every value this crate's circuit ever exposes has a fixed size known at
//! compile time ([`crate::MAX_CLAIMS_V1`] claim slots, each up to
//! [`crate::MAX_CLAIM_BYTES_V1`] bytes, [`crate::mso::TIMESTAMP_LEN`]-byte
//! timestamps) — so [`CVerifyResult`] is a plain, fixed-size, `Copy`
//! struct the caller allocates itself and passes a pointer to, with no
//! nested heap allocations and therefore no corresponding free function for
//! the result (only [`zk_cred_vega_free_error_string`] for the error-string
//! out-param, and [`zk_cred_vega_free_verifier_key`] for the verifier-key
//! handle).
//!
//! ## Handle safety
//!
//! Same handle-lifecycle contract as Longfellow's `MdocZkVerifier`: the
//! opaque `GoVegaVerifierKey` pointer is created via `Box::into_raw` in
//! [`zk_cred_vega_deserialize_verifier_key`] and consumed exactly once by
//! [`zk_cred_vega_free_verifier_key`] via `Box::from_raw`. Do not free the
//! same pointer twice; do not use it after freeing; do not free it while a
//! [`zk_cred_vega_verify`] call using it is still in flight on another
//! thread.
//!
//! ## Error reporting
//!
//! Same "owned, caller-freed error string" shape as Longfellow's module:
//! every fallible function takes an `error_out: *mut *mut c_char`
//! out-parameter (may be null). On failure, an owned NUL-terminated UTF-8
//! error string is written there, to be freed via
//! [`zk_cred_vega_free_error_string`]. On success, `*error_out` is set to
//! null (if non-null).

use crate::{DisclosedClaim, MAX_CLAIM_BYTES_V1, MAX_CLAIMS_V1, VerifiedPresentation};
use std::ffi::{CString, c_char};
use std::slice;
use vega_prover::{
  traits::Engine,
  vega_mc_zkp::{VegaMcVerifierKey, VegaMcZkSNARK},
};

type Scalar = <crate::Engine_ as Engine>::Scalar;

/// P-256 field-element/coordinate width in bytes — see `ffi_api.rs`'s own
/// `scalar_to_bytes` doc comment for why this must always be a fixed-width,
/// left-padded encoding rather than `BigInt`'s minimal one.
const P256_COORDINATE_BYTES: usize = 32;

/// [`crate::mso::TIMESTAMP_LEN`] duplicated as a `const` usable in this
/// file's `#[repr(C)]` array sizes (array lengths must be a `usize`
/// constant expression at this call site either way); the compile-time
/// assertion below ties it back to the real crate constant so a future
/// change there is caught here instead of silently desyncing this hand
/// -maintained ABI and its hand-maintained C header.
const C_TIMESTAMP_LEN: usize = 20;
const _: () = assert!(
  C_TIMESTAMP_LEN == crate::mso::TIMESTAMP_LEN,
  "C_TIMESTAMP_LEN (and the hand-written zk_cred_vega_go.h header) must be updated to match crate::mso::TIMESTAMP_LEN"
);
const _: () = assert!(
  MAX_CLAIMS_V1 == 4,
  "MAX_CLAIMS_V1 changed - the hand-written zk_cred_vega_go.h header's CVerifyResult.claims array length must be updated to match"
);
const _: () = assert!(
  MAX_CLAIM_BYTES_V1 == 176,
  "MAX_CLAIM_BYTES_V1 changed - the hand-written zk_cred_vega_go.h header's CDisclosedClaim.plaintext array length must be updated to match"
);

fn scalar_to_bytes(s: Scalar) -> [u8; P256_COORDINATE_BYTES] {
  let unpadded = crate::nonnative::util::f_to_nat(&s).to_bytes_be().1;
  debug_assert!(unpadded.len() <= P256_COORDINATE_BYTES);
  let mut padded = [0u8; P256_COORDINATE_BYTES];
  padded[P256_COORDINATE_BYTES - unpadded.len()..].copy_from_slice(&unpadded);
  padded
}

/// Opaque handle to a deserialized verifier key, obtained from
/// [`zk_cred_vega_deserialize_verifier_key`] and released with
/// [`zk_cred_vega_free_verifier_key`]. Deserializing a verifier key is
/// cheap relative to a circuit-compiling `rust_initialize_verifier` in
/// Longfellow's crate (no circuit compilation happens here - `verify`
/// itself takes the already-published verifier key directly) but a
/// long-lived Go process should still cache this handle across calls
/// rather than deserializing on every verification.
pub struct GoVegaVerifierKey(VegaMcVerifierKey<crate::Engine_>);

/// One claim slot's verified disclosure outcome, crossing the C ABI as a
/// fixed-size (no heap allocation) twin of [`crate::DisclosedClaim`].
///
/// `plaintext` is always [`MAX_CLAIM_BYTES_V1`] bytes; only the first
/// `real_len` are meaningful, and only when `disclosed != 0` (all-zero
/// otherwise, mirroring `DisclosedClaim.plaintext`'s own masking - see its
/// doc comment).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct CDisclosedClaim {
  pub disclosed: u8,
  pub digest: [u8; 32],
  pub real_len: u32,
  pub plaintext: [u8; MAX_CLAIM_BYTES_V1],
  pub digest_id: u32,
}

impl Default for CDisclosedClaim {
  fn default() -> Self {
    CDisclosedClaim {
      disclosed: 0,
      digest: [0u8; 32],
      real_len: 0,
      plaintext: [0u8; MAX_CLAIM_BYTES_V1],
      digest_id: 0,
    }
  }
}

/// One claim slot's disclosed bytes, supplied *in* to
/// [`zk_cred_vega_verify`]. The `IssuerSignedItem` plaintext is no longer
/// a public value of the proof (see `crate::verify_and_check_binding`):
/// it travels beside the proof and is bound by the blinded digest, which
/// verification checks. Set `present = 0` for an undisclosed slot; set
/// `present = 1` and fill `len`/`bytes` for a disclosed one.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct CDisclosedInput {
  pub present: u8,
  pub len: usize,
  pub bytes: [u8; MAX_CLAIM_BYTES_V1],
}

/// The verified, bound public output of a presentation - a fixed-size (no
/// heap allocation) twin of [`crate::VerifiedPresentation`]. The caller
/// allocates this struct itself (e.g. on the stack, or as a Go value) and
/// passes a pointer to [`zk_cred_vega_verify`]; there is no corresponding
/// free function since nothing here is separately heap-allocated.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct CVerifyResult {
  pub qx: [u8; P256_COORDINATE_BYTES],
  pub qy: [u8; P256_COORDINATE_BYTES],
  pub claims: [CDisclosedClaim; MAX_CLAIMS_V1],
  pub device_x: [u8; 32],
  pub device_y: [u8; 32],
  pub signed_ts: [u8; C_TIMESTAMP_LEN],
  pub valid_from_ts: [u8; C_TIMESTAMP_LEN],
  pub valid_until_ts: [u8; C_TIMESTAMP_LEN],
}

fn to_c_result(v: VerifiedPresentation) -> Result<CVerifyResult, anyhow::Error> {
  if v.claims.len() != MAX_CLAIMS_V1 {
    return Err(anyhow::anyhow!("expected exactly {MAX_CLAIMS_V1} claims, got {}", v.claims.len()));
  }
  let mut claims = [CDisclosedClaim::default(); MAX_CLAIMS_V1];
  for (i, c) in v.claims.into_iter().enumerate() {
    claims[i] = to_c_claim(c)?;
  }
  Ok(CVerifyResult {
    qx: scalar_to_bytes(v.qx),
    qy: scalar_to_bytes(v.qy),
    claims,
    device_x: v.device_x,
    device_y: v.device_y,
    signed_ts: v.signed_ts,
    valid_from_ts: v.valid_from_ts,
    valid_until_ts: v.valid_until_ts,
  })
}

fn to_c_claim(c: DisclosedClaim) -> Result<CDisclosedClaim, anyhow::Error> {
  if c.plaintext.len() != c.real_len {
    return Err(anyhow::anyhow!(
      "claim plaintext length ({}) did not match its own real_len ({}) - this indicates a bug in the crate's own verify_and_check_binding, not caller input",
      c.plaintext.len(),
      c.real_len
    ));
  }
  if c.real_len > MAX_CLAIM_BYTES_V1 {
    return Err(anyhow::anyhow!(
      "claim real_len ({}) exceeds MAX_CLAIM_BYTES_V1 ({MAX_CLAIM_BYTES_V1}) - this indicates a bug in the crate's own verify_and_check_binding, not caller input",
      c.real_len
    ));
  }
  let mut plaintext = [0u8; MAX_CLAIM_BYTES_V1];
  plaintext[..c.plaintext.len()].copy_from_slice(&c.plaintext);
  Ok(CDisclosedClaim {
    disclosed: u8::from(c.disclosed),
    digest: c.digest,
    real_len: c.real_len as u32,
    plaintext,
    digest_id: c.digest_id,
  })
}

/// Builds a `&[u8]` from a pointer+length pair — see
/// `zk-cred-longfellow`'s `go_ffi.rs::bytes_or_empty` for the exact same
/// contract (a zero length is always an empty slice, regardless of
/// whether the pointer is null).
///
/// # Safety
///
/// If `len > 0`, `ptr` must be non-null and point to at least `len` valid,
/// initialized bytes that live at least as long as the borrow returned
/// here.
unsafe fn bytes_or_empty<'a>(ptr: *const u8, len: usize, field: &str) -> Result<&'a [u8], anyhow::Error> {
  if len == 0 {
    return Ok(&[]);
  }
  if ptr.is_null() {
    return Err(anyhow::anyhow!("{field} has nonzero length ({len}) but a null pointer"));
  }
  // SAFETY: forwarded from the caller's safety contract; `ptr` is non-null
  // and `len` is nonzero per the checks above.
  Ok(unsafe { slice::from_raw_parts(ptr, len) })
}

/// Clears `*error_out` to null, if `error_out` itself is non-null.
///
/// # Safety
///
/// If non-null, `error_out` must point to a valid, writable `*mut c_char`.
unsafe fn clear_error_out(error_out: *mut *mut c_char) {
  if error_out.is_null() {
    return;
  }
  // SAFETY: forwarded from the caller's safety contract.
  unsafe {
    *error_out = std::ptr::null_mut();
  }
}

/// Writes an owned, NUL-terminated copy of `message` into `*error_out`, if
/// `error_out` itself is non-null — see `zk-cred-longfellow`'s
/// `go_ffi.rs::set_error_out` for the identical contract and rationale.
///
/// # Safety
///
/// If non-null, `error_out` must point to a valid, writable `*mut c_char`.
unsafe fn set_error_out(error_out: *mut *mut c_char, message: &str) {
  if error_out.is_null() {
    return;
  }
  let sanitized = if message.contains('\0') {
    message.replace('\0', "\u{fffd}")
  } else {
    message.to_owned()
  };
  let c_message =
    CString::new(sanitized).unwrap_or_else(|_| CString::new("error message could not be encoded as a C string").expect("literal has no interior NUL"));
  // SAFETY: forwarded from the caller's safety contract.
  unsafe {
    *error_out = c_message.into_raw();
  }
}

/// Formats a `std::panic::catch_unwind` payload into a human-readable
/// message.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
  if let Some(s) = payload.downcast_ref::<&str>() {
    format!("panic in FFI call: {s}")
  } else if let Some(s) = payload.downcast_ref::<String>() {
    format!("panic in FFI call: {s}")
  } else {
    "panic in FFI call: unknown panic payload".to_owned()
  }
}

/// Deserializes a published verifier-key artifact (fetched from
/// `go-zk-circuits`, the same bytes [`crate::ffi_api::deserialize_verifier_key`]
/// accepts) into an opaque handle usable by [`zk_cred_vega_verify`].
///
/// Returns null on failure, with `*error_out` set to an owned error message
/// (see the module documentation on error reporting).
///
/// # Safety
///
/// * `bytes` must point to at least `len` valid, initialized bytes.
/// * `error_out` may be null; if non-null, it must point to a valid,
///   writable `*mut c_char`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zk_cred_vega_deserialize_verifier_key(bytes: *const u8, len: usize, error_out: *mut *mut c_char) -> *mut GoVegaVerifierKey {
  // SAFETY: `error_out`'s validity is part of this function's own safety
  // contract, documented above.
  unsafe {
    clear_error_out(error_out);
  }

  let result = std::panic::catch_unwind(|| -> Result<GoVegaVerifierKey, anyhow::Error> {
    // SAFETY: `bytes`/`len`'s validity is part of this function's own
    // safety contract, documented above.
    let bytes = unsafe { bytes_or_empty(bytes, len, "verifier_key_bytes") }?;
    if bytes.is_empty() {
      return Err(anyhow::anyhow!("verifier_key_bytes must not be empty"));
    }
    let vk: VegaMcVerifierKey<crate::Engine_> = bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!("failed to deserialize verifier key: {e}"))?;
    Ok(GoVegaVerifierKey(vk))
  });

  match result {
    Ok(Ok(vk)) => Box::into_raw(Box::new(vk)),
    Ok(Err(e)) => {
      // SAFETY: as above.
      unsafe {
        set_error_out(error_out, &e.to_string());
      }
      std::ptr::null_mut()
    }
    Err(panic) => {
      // SAFETY: as above.
      unsafe {
        set_error_out(error_out, &panic_message(&*panic));
      }
      std::ptr::null_mut()
    }
  }
}

/// Frees a verifier-key handle previously returned by
/// [`zk_cred_vega_deserialize_verifier_key`].
///
/// Passing null is a no-op. Passing the same non-null pointer more than
/// once, or using the pointer after freeing it, is undefined behavior (the
/// same rules as `free()` in C).
///
/// # Safety
///
/// `verifier_key` must either be null, or a pointer previously returned by
/// [`zk_cred_vega_deserialize_verifier_key`] that has not already been
/// freed, and there must be no other in-flight [`zk_cred_vega_verify`]
/// call using this handle concurrently with this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zk_cred_vega_free_verifier_key(verifier_key: *mut GoVegaVerifierKey) {
  if verifier_key.is_null() {
    return;
  }
  // SAFETY: forwarded from the caller's safety contract, documented above.
  let _ = unsafe { Box::from_raw(verifier_key) };
}

/// Frees an error string previously written by this module's functions into
/// an `error_out` out-parameter.
///
/// Passing null is a no-op.
///
/// # Safety
///
/// `ptr` must either be null, or a pointer previously written into an
/// `error_out` parameter by a function in this module, that has not already
/// been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zk_cred_vega_free_error_string(ptr: *mut c_char) {
  if ptr.is_null() {
    return;
  }
  // SAFETY: forwarded from the caller's safety contract, documented above.
  let _ = unsafe { CString::from_raw(ptr) };
}

/// Verifies a proof and checks the step<->core binding (see
/// `crate::verify_and_check_binding`'s doc) in one call — a caller never
/// sees an unbound "valid" proof. This does not weaken any check performed
/// by the crate's safe Rust API; it is a thin allocation/parsing wrapper
/// around `crate::verify` + `crate::verify_and_check_binding`, unchanged.
///
/// On success, `*result_out` (if non-null) is filled in with the verified,
/// bound public values and `0` is returned. **Unlike Longfellow's
/// `rust_verify_with_ppid`, this does not compare against any
/// caller-supplied expected values — the caller must independently check
/// the returned `qx`/`qy`/claims/timestamps against whatever it already
/// knows (issuer pubkey, wire-declared claim values, current time)** - see
/// this module's own doc comment on this shape difference.
///
/// On failure, returns a negative status code (`-1`: input validation or
/// verification error; `-2`: an internal panic was caught) and, if
/// `error_out` is non-null, writes an owned error message there.
///
/// # Safety
///
/// * `verifier_key` must be a live pointer previously returned by
///   [`zk_cred_vega_deserialize_verifier_key`] (not null, not freed, not
///   concurrently being freed by another thread during this call).
/// * `proof` must point to at least `proof_len` valid bytes.
/// * `result_out` may be null (the call still validates the proof and
///   returns a status code, just without writing the public values
///   anywhere); if non-null, it must point to a valid, writable
///   `CVerifyResult`.
/// * `error_out` may be null; if non-null, it must point to a valid,
///   writable `*mut c_char`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zk_cred_vega_verify(
  verifier_key: *const GoVegaVerifierKey,
  proof: *const u8,
  proof_len: usize,
  disclosed: *const CDisclosedInput,
  disclosed_len: usize,
  result_out: *mut CVerifyResult,
  error_out: *mut *mut c_char,
) -> i32 {
  // SAFETY: `error_out`'s validity is part of this function's own safety
  // contract, documented above.
  unsafe {
    clear_error_out(error_out);
  }

  let result = std::panic::catch_unwind(|| -> Result<CVerifyResult, anyhow::Error> {
    if verifier_key.is_null() {
      return Err(anyhow::anyhow!("verifier_key must not be null"));
    }
    // SAFETY: forwarded from this function's safety contract:
    // `verifier_key` is a live handle from
    // `zk_cred_vega_deserialize_verifier_key`.
    let verifier_key: &GoVegaVerifierKey = unsafe { &*verifier_key };

    // SAFETY: forwarded from this function's safety contract.
    let proof_bytes = unsafe { bytes_or_empty(proof, proof_len, "proof") }?;
    if proof_bytes.is_empty() {
      return Err(anyhow::anyhow!("proof must not be empty"));
    }
    let proof: VegaMcZkSNARK<crate::Engine_> = bincode::deserialize(proof_bytes).map_err(|e| anyhow::anyhow!("failed to deserialize proof: {e}"))?;

    if disclosed.is_null() {
      return Err(anyhow::anyhow!("disclosed must not be null"));
    }
    if disclosed_len != MAX_CLAIMS_V1 {
      return Err(anyhow::anyhow!(
        "disclosed_len must be exactly {MAX_CLAIMS_V1}, got {disclosed_len}"
      ));
    }
    // SAFETY: forwarded from this function's safety contract -- the caller
    // guarantees `disclosed` points to `disclosed_len` initialised entries.
    let disclosed_slice = unsafe { std::slice::from_raw_parts(disclosed, disclosed_len) };
    let disclosed_vec: Vec<Option<Vec<u8>>> = disclosed_slice
      .iter()
      .map(|d| {
        if d.present == 0 {
          Ok(None)
        } else if d.len > MAX_CLAIM_BYTES_V1 {
          Err(anyhow::anyhow!("disclosed len {} exceeds MAX_CLAIM_BYTES_V1", d.len))
        } else {
          Ok(Some(d.bytes[..d.len].to_vec()))
        }
      })
      .collect::<Result<_, _>>()?;

    let (step_public_values, core_public_values) = crate::verify(&proof, &verifier_key.0).map_err(|e| anyhow::anyhow!(e))?;
    let verified = crate::verify_and_check_binding(&step_public_values, &core_public_values, &disclosed_vec).map_err(|e| anyhow::anyhow!(e))?;

    to_c_result(verified)
  });

  match result {
    Ok(Ok(r)) => {
      if !result_out.is_null() {
        // SAFETY: `result_out`'s validity (when non-null) is part of
        // this function's own safety contract, documented above.
        unsafe {
          *result_out = r;
        }
      }
      0
    }
    Ok(Err(e)) => {
      // SAFETY: as above.
      unsafe {
        set_error_out(error_out, &e.to_string());
      }
      -1
    }
    Err(panic) => {
      // SAFETY: as above.
      unsafe {
        set_error_out(error_out, &panic_message(&*panic));
      }
      -2
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use num_bigint::BigInt;
  use std::ffi::CStr;

  /// Everything a golden C-ABI test needs: a real published-shaped
  /// verifier key, a real proof over it (built via the crate's own safe
  /// API, mirroring `ffi_api::tests::ffi_round_trip_with_real_signature`),
  /// and the expected values a correct verify should report back.
  struct GoldenFixture {
    vk_bytes: Vec<u8>,
    proof_bytes: Vec<u8>,
    claim0: Vec<u8>,
    expected_qx: [u8; 32],
    expected_qy: [u8; 32],
    device_x: [u8; 32],
    valid_until_ts: [u8; 20],
  }

  fn build_golden_fixture() -> GoldenFixture {
    use crate::mso::MsoBodyWitness;
    use crate::{ClaimWitness, MdocEcdsaWitness};
    use p256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::hazmat::PrehashSigner};
    use sha2::{Digest, Sha256};

    fn claim_bytes_with_digest_id(digest_id: u32, marker: &[u8]) -> Vec<u8> {
      let mut bytes = vec![0xAAu8; crate::digest_id_extract::DIGEST_ID_OFFSET_BYTES];
      bytes.extend(crate::cbor_uint::encode_cbor_uint(digest_id));
      bytes.extend_from_slice(marker);
      bytes
    }

    let keys = crate::setup().expect("setup");
    let vk_bytes = bincode::serialize(&keys.vk).expect("serialize vk");

    let claim0 = claim_bytes_with_digest_id(26, b"family_name:Doe");
    let claim1 = claim_bytes_with_digest_id(300, b"given_name:Jane");
    let claims_witness = vec![
      ClaimWitness {
        issuer_signed_item_bytes: claim0.clone(),
        disclose: true,
        digest_id: 26,
      },
      ClaimWitness {
        issuer_signed_item_bytes: claim1.clone(),
        disclose: false,
        digest_id: 300,
      },
    ];
    let claim_digests = crate::core_claim_digests(&claims_witness).expect("core_claim_digests");
    let digest_ids = crate::core_digest_ids(&claims_witness).expect("core_digest_ids");

    let mso_body = MsoBodyWitness {
      device_x: [0x11u8; 32],
      device_y: [0x22u8; 32],
      signed_ts: *b"2026-08-20T00:00:00Z",
      valid_from_ts: *b"2026-08-20T00:00:00Z",
      valid_until_ts: *b"2036-08-20T00:00:00Z",
    };

    let signing_key = SigningKey::from_bytes(&[7u8; 32].into()).expect("valid scalar");
    let verifying_key = VerifyingKey::from(&signing_key);
    let sig_structure = crate::mso::native_sig_structure_bytes(&digest_ids, &claim_digests, &mso_body);
    let z_bytes: [u8; 32] = Sha256::digest(&sig_structure).into();
    let signature: Signature = signing_key.sign_prehash(&z_bytes).expect("sign_prehash");
    let n = crate::p256_ecc::p256_order();
    let s = BigInt::from_bytes_be(num_bigint::Sign::Plus, &signature.s().to_bytes());
    let s_inv = s.modpow(&(n.clone() - BigInt::from(2)), &n);
    let encoded = verifying_key.to_encoded_point(false);

    let ecdsa_witness = MdocEcdsaWitness {
      qx: crate::nonnative::util::nat_to_f(&BigInt::from_bytes_be(num_bigint::Sign::Plus, encoded.x().expect("x"))).expect("qx fits field"),
      qy: crate::nonnative::util::nat_to_f(&BigInt::from_bytes_be(num_bigint::Sign::Plus, encoded.y().expect("y"))).expect("qy fits field"),
      r: BigInt::from_bytes_be(num_bigint::Sign::Plus, &signature.r().to_bytes()),
      s,
      s_inv,
    };

    let nonce = crate::fresh_nonce().expect("fresh_nonce");
    let prep = crate::prep_prove(&keys.pk, &claims_witness, &ecdsa_witness, &mso_body, &nonce).expect("prep_prove");
    let (proof, _next_prep) =
      crate::prove(&keys.pk, &claims_witness, &ecdsa_witness, &mso_body, prep, &nonce).expect("prove");
    let proof_bytes = bincode::serialize(&proof).expect("serialize proof");

    GoldenFixture {
      vk_bytes,
      proof_bytes,
      claim0,
      expected_qx: scalar_to_bytes(ecdsa_witness.qx),
      expected_qy: scalar_to_bytes(ecdsa_witness.qy),
      device_x: mso_body.device_x,
      valid_until_ts: mso_body.valid_until_ts,
    }
  }

  /// Exercises the full lifecycle through the raw `extern "C"` functions
  /// exactly as a cgo caller would: deserialize a real published-shaped
  /// verifier key, verify a real proof, then free. Confirms the returned
  /// public values match what the safe API itself reports for the same
  /// proof.
  /// Slot 0 is the only disclosed claim in the golden fixture; slot 1 is
  /// deliberately undisclosed and slots 2/3 are padding.
  fn disclosed_inputs(claim0: &[u8]) -> [CDisclosedInput; MAX_CLAIMS_V1] {
    let mut d: [CDisclosedInput; MAX_CLAIMS_V1] = [CDisclosedInput {
      present: 0,
      len: 0,
      bytes: [0u8; MAX_CLAIM_BYTES_V1],
    }; MAX_CLAIMS_V1];
    d[0].present = 1;
    d[0].len = claim0.len();
    d[0].bytes[..claim0.len()].copy_from_slice(claim0);
    d
  }

  #[test]
  fn c_abi_round_trip_succeeds() {
    let golden = build_golden_fixture();

    // SAFETY: test-only exercise of the raw C ABI with well-formed,
    // valid inputs constructed above; every pointer handed to these
    // functions points at data owned by a local binding that outlives
    // the call.
    unsafe {
      let mut error_out: *mut c_char = std::ptr::null_mut();
      let vk_handle = zk_cred_vega_deserialize_verifier_key(golden.vk_bytes.as_ptr(), golden.vk_bytes.len(), &mut error_out);
      assert!(!vk_handle.is_null(), "deserialize_verifier_key failed");
      assert!(error_out.is_null());

      let mut result = std::mem::MaybeUninit::<CVerifyResult>::uninit();
      let mut error_out: *mut c_char = std::ptr::null_mut();
      let disclosed = disclosed_inputs(&golden.claim0);
      let status = zk_cred_vega_verify(
        vk_handle,
        golden.proof_bytes.as_ptr(),
        golden.proof_bytes.len(),
        disclosed.as_ptr(),
        disclosed.len(),
        result.as_mut_ptr(),
        &mut error_out,
      );
      assert_eq!(status, 0, "verify failed");
      assert!(error_out.is_null());
      let result = result.assume_init();

      assert_eq!(result.qx, golden.expected_qx);
      assert_eq!(result.qy, golden.expected_qy);
      assert_eq!(result.claims[0].disclosed, 1);
      assert_eq!(result.claims[0].real_len as usize, golden.claim0.len());
      assert_eq!(&result.claims[0].plaintext[..golden.claim0.len()], golden.claim0.as_slice());
      assert_eq!(result.claims[1].disclosed, 0);
      assert_eq!(result.device_x, golden.device_x);
      assert_eq!(result.valid_until_ts, golden.valid_until_ts);

      zk_cred_vega_free_verifier_key(vk_handle);
    }
  }

  /// Not part of the normal test run (`#[ignore]`): dumps the same
  /// known-good verifier-key + proof used by `c_abi_round_trip_succeeds`
  /// to `target/go-cabi/testdata/`, so a real Go program linking against
  /// `target/go-cabi/libzk_cred_vega.so` via cgo can verify it end-to-end
  /// through the actual C ABI, from actual Go - mirrors
  /// zk-cred-longfellow's own `dump_golden_fixture_for_go_smoke_test`. Run
  /// explicitly via:
  ///
  ///   cargo test --release go_ffi::tests::dump_golden_fixture_for_go_smoke_test -- --ignored
  #[test]
  #[ignore = "run explicitly to regenerate fixtures for the Go cgo smoke test"]
  fn dump_golden_fixture_for_go_smoke_test() {
    let golden = build_golden_fixture();
    let out_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/go-cabi/testdata");
    std::fs::create_dir_all(&out_dir).unwrap();
    std::fs::write(out_dir.join("verifier_key.bin"), &golden.vk_bytes).unwrap();
    std::fs::write(out_dir.join("proof.bin"), &golden.proof_bytes).unwrap();
    std::fs::write(out_dir.join("claim0.bin"), &golden.claim0).unwrap();
    eprintln!("wrote golden fixture to {}", out_dir.display());
  }

  /// A tampered proof must be rejected, and the rejection must come with a
  /// real (non-empty) error message via the out-parameter.
  #[test]
  fn c_abi_rejects_tampered_proof_with_error_message() {
    let keys = crate::setup().expect("setup");
    let vk_bytes = bincode::serialize(&keys.vk).expect("serialize vk");

    // A well-formed-length but garbage proof: bincode will fail to
    // deserialize it into a VegaMcZkSNARK, which is exactly the kind of
    // malformed input a real cgo caller could hand this function.
    let garbage_proof = [0xFFu8; 64];

    // SAFETY: as in `c_abi_round_trip_succeeds`.
    unsafe {
      let mut error_out: *mut c_char = std::ptr::null_mut();
      let vk_handle = zk_cred_vega_deserialize_verifier_key(vk_bytes.as_ptr(), vk_bytes.len(), &mut error_out);
      assert!(!vk_handle.is_null());

      let mut result = std::mem::MaybeUninit::<CVerifyResult>::uninit();
      let mut error_out: *mut c_char = std::ptr::null_mut();
      let disclosed = disclosed_inputs(b"unused: the proof is garbage");
      let status = zk_cred_vega_verify(vk_handle, garbage_proof.as_ptr(), garbage_proof.len(), disclosed.as_ptr(), disclosed.len(), result.as_mut_ptr(), &mut error_out);
      assert_ne!(status, 0, "garbage proof must not verify");
      assert!(!error_out.is_null(), "expected an error message");
      let message = CStr::from_ptr(error_out).to_str().unwrap();
      assert!(!message.is_empty());
      zk_cred_vega_free_error_string(error_out);

      zk_cred_vega_free_verifier_key(vk_handle);
    }
  }

  /// Null pointers where a value is required must produce a clean error,
  /// not a segfault/UB - this is the main risk cgo callers introduce (Go
  /// zero values are nil pointers).
  #[test]
  fn c_abi_rejects_null_required_pointers() {
    // SAFETY: as in `c_abi_round_trip_succeeds`; the null pointers
    // passed below are exactly the invalid inputs each call is
    // expected to reject with an error rather than dereference.
    unsafe {
      let mut error_out: *mut c_char = std::ptr::null_mut();
      let vk_handle = zk_cred_vega_deserialize_verifier_key(std::ptr::null(), 0, &mut error_out);
      assert!(vk_handle.is_null());
      assert!(!error_out.is_null());
      let message = CStr::from_ptr(error_out).to_str().unwrap();
      assert!(message.contains("verifier_key_bytes"), "message was: {message}");
      zk_cred_vega_free_error_string(error_out);

      let mut error_out: *mut c_char = std::ptr::null_mut();
      let status = zk_cred_vega_verify(std::ptr::null(), std::ptr::null(), 0, std::ptr::null(), 0, std::ptr::null_mut(), &mut error_out);
      assert_ne!(status, 0);
      assert!(!error_out.is_null());
      zk_cred_vega_free_error_string(error_out);
    }
  }

  #[test]
  fn free_null_handles_are_a_no_op() {
    // SAFETY: null is always a valid, documented no-op input to these
    // free functions.
    unsafe {
      zk_cred_vega_free_verifier_key(std::ptr::null_mut());
      zk_cred_vega_free_error_string(std::ptr::null_mut());
    }
  }
}
