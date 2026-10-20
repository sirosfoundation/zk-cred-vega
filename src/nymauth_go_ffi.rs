// SPDX-License-Identifier: BSD-2-Clause
//! Plain C ABI of the `nymauth` verifier and prover for a Go (cgo) caller, in the style of
//! [`crate::go_ffi`]: opaque handle, pointer-and-length arguments, small integer status codes,
//! built with the default features (no UniFFI). The header is `include/zk_cred_vega_nymauth_go.h`.
//!
//! * Every entry point runs under `catch_unwind` and returns [`ZK_NYM_INTERNAL`] on a panic: no
//!   unwinding crosses the boundary.
//! * Every pointer is checked for null and every length against a cap before use; a violation is
//!   [`ZK_NYM_INVALID_ARG`] and nothing is dereferenced.
//! * Status codes: 0 is success; 1 an invalid argument (null, length); 2 to 9 mirror
//!   [`crate::nymauth_vega::NymAuthVegaError`]; a refusal by the circuit is split into four codes
//!   (20 to 23) so a caller can tell a wrong seed from a wrong signature without a rule path.
//! * `zk_cred_vega_nymauth_prove` zeroes the caller's `secret_seed` in place before it returns.
//! * Buffers the library allocates (a proof, a transcript) are released with
//!   [`zk_cred_vega_nymauth_free_buffer`], with the same pointer and length.
//!
//! The integration contract of [`crate::nymauth_vega`] applies: the statement's time, challenge
//! digest and verifier_input must be the verifier's own, derived with
//! [`zk_cred_vega_nymauth_derive_challenge`].

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::slice;

use zeroize::Zeroize;

use crate::nymauth_vega::engine::challenge;
use crate::nymauth_vega::engine::statement::{self, Error, Holder, Keys, RefusalCode, Statement};

pub const ZK_NYM_OK: i32 = 0;
pub const ZK_NYM_INVALID_ARG: i32 = 1;
pub const ZK_NYM_INVALID_INPUT: i32 = 2;
pub const ZK_NYM_INVALID_SHAPES: i32 = 3;
pub const ZK_NYM_UNKNOWN_CIRCUIT: i32 = 4;
pub const ZK_NYM_PROVER_FAILED: i32 = 6;
pub const ZK_NYM_PROOF_INVALID: i32 = 7;
pub const ZK_NYM_MISMATCH: i32 = 8;
pub const ZK_NYM_INTERNAL: i32 = 9;
pub const ZK_NYM_REFUSED_SEED_MISMATCH: i32 = 20;
pub const ZK_NYM_REFUSED_ISSUER_SIGNATURE: i32 = 21;
pub const ZK_NYM_REFUSED_DEVICE_SIGNATURE: i32 = 22;
pub const ZK_NYM_REFUSED_CREDENTIAL: i32 = 23;

/// Longest shapes accepted (the real ones are about 12 MB).
const MAX_SHAPES: usize = 64 << 20;
/// Longest string or byte argument other than shapes, proofs and IssuerSigned.
const MAX_SMALL: usize = 4096;

/// Opaque handle to the keys of the approved nymauth circuit.
pub struct ZkNymKeys(Keys);

/// A byte or text argument: a pointer and its length. A zero length may come with any pointer.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ZkNymSlice {
  pub ptr: *const u8,
  pub len: usize,
}

/// The values the verifier names ([`crate::nymauth_vega::NymAuthVegaStatement`]). The three text
/// fields are UTF-8 without a terminator.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ZkNymStatement {
  pub issuer_key_x: ZkNymSlice,
  pub issuer_key_y: ZkNymSlice,
  pub time: ZkNymSlice,
  pub earliest: ZkNymSlice,
  pub cutoff: ZkNymSlice,
  pub challenge_digest: ZkNymSlice,
  pub verifier_input: ZkNymSlice,
}

/// What only the holder has. `secret_seed` is zeroed in place by the prove call.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ZkNymHolder {
  pub issuer_signed: ZkNymSlice,
  pub secret_seed: *mut u8,
  pub secret_seed_len: usize,
  pub device_signature: ZkNymSlice,
}

fn code(e: &Error) -> i32 {
  match e {
    Error::Input(_) => ZK_NYM_INVALID_INPUT,
    Error::Shapes(_) => ZK_NYM_INVALID_SHAPES,
    Error::UnknownCircuit(_) => ZK_NYM_UNKNOWN_CIRCUIT,
    Error::Refused(r) => match r.code {
      RefusalCode::SeedMismatch => ZK_NYM_REFUSED_SEED_MISMATCH,
      RefusalCode::IssuerSignature => ZK_NYM_REFUSED_ISSUER_SIGNATURE,
      RefusalCode::DeviceSignature => ZK_NYM_REFUSED_DEVICE_SIGNATURE,
      RefusalCode::Credential => ZK_NYM_REFUSED_CREDENTIAL,
    },
    Error::Prover(_) => ZK_NYM_PROVER_FAILED,
    Error::ProofInvalid(_) => ZK_NYM_PROOF_INVALID,
    Error::Mismatch(_) => ZK_NYM_MISMATCH,
    Error::Internal(_) => ZK_NYM_INTERNAL,
  }
}

/// Runs `f`, turning a panic into [`ZK_NYM_INTERNAL`].
fn guarded(f: impl FnOnce() -> i32) -> i32 {
  catch_unwind(AssertUnwindSafe(f)).unwrap_or(ZK_NYM_INTERNAL)
}

/// The bytes of a slice argument, or `None` for a null pointer with a length, or a length past `max`.
///
/// # Safety
/// `s.ptr` must be valid for reads of `s.len` bytes when non-null and `len > 0`.
unsafe fn bytes<'a>(s: ZkNymSlice, max: usize) -> Option<&'a [u8]> {
  if s.len > max {
    return None;
  }
  if s.len == 0 {
    return Some(&[]);
  }
  if s.ptr.is_null() {
    return None;
  }
  Some(unsafe { slice::from_raw_parts(s.ptr, s.len) })
}

/// A UTF-8 text argument.
unsafe fn text<'a>(s: ZkNymSlice) -> Option<&'a str> {
  std::str::from_utf8(unsafe { bytes(s, MAX_SMALL) }?).ok()
}

/// Hands a vector to the caller as a pointer and a length ([`zk_cred_vega_nymauth_free_buffer`]).
fn give(v: Vec<u8>, ptr_out: *mut *mut u8, len_out: *mut usize) {
  let boxed = v.into_boxed_slice();
  let len = boxed.len();
  unsafe {
    *len_out = len;
    *ptr_out = Box::into_raw(boxed) as *mut u8;
  }
}

/// Builds the keys from the circuit's decompressed shapes. Only approved shapes are accepted
/// ([`ZK_NYM_UNKNOWN_CIRCUIT`] otherwise). On success `*keys_out` is a handle to release with
/// [`zk_cred_vega_nymauth_free_keys`]; on failure it is null.
///
/// # Safety
/// `shapes` must be valid for `shapes_len` bytes, `keys_out` a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zk_cred_vega_nymauth_load_keys(shapes: *const u8, shapes_len: usize, keys_out: *mut *mut ZkNymKeys) -> i32 {
  guarded(|| {
    if keys_out.is_null() {
      return ZK_NYM_INVALID_ARG;
    }
    unsafe { *keys_out = std::ptr::null_mut() };
    let Some(shapes) = (unsafe { bytes(ZkNymSlice { ptr: shapes, len: shapes_len }, MAX_SHAPES) }) else {
      return ZK_NYM_INVALID_ARG;
    };
    match Keys::from_shapes(shapes) {
      Ok(keys) => {
        unsafe { *keys_out = Box::into_raw(Box::new(ZkNymKeys(keys))) };
        ZK_NYM_OK
      }
      Err(e) => code(&e),
    }
  })
}

/// Releases a handle from [`zk_cred_vega_nymauth_load_keys`]. Null is ignored. Do not free twice
/// or use the handle afterwards.
///
/// # Safety
/// `keys` must be null or a live handle not in use on another thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zk_cred_vega_nymauth_free_keys(keys: *mut ZkNymKeys) {
  if !keys.is_null() {
    let _ = catch_unwind(AssertUnwindSafe(|| drop(unsafe { Box::from_raw(keys) })));
  }
}

/// Releases a buffer the library returned, with the pointer and length it returned. Null is
/// ignored.
///
/// # Safety
/// `ptr`/`len` must be exactly a pair the library returned, not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zk_cred_vega_nymauth_free_buffer(ptr: *mut u8, len: usize) {
  if !ptr.is_null() {
    let _ = catch_unwind(AssertUnwindSafe(|| {
      drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)) })
    }));
  }
}

/// Reads a statement argument, or `None` when a pointer is null or a length is past its cap.
unsafe fn statement_of<'a>(st: *const ZkNymStatement) -> Option<Statement<'a>> {
  if st.is_null() {
    return None;
  }
  let st = unsafe { *st };
  Some(Statement {
    issuer_key_x: unsafe { bytes(st.issuer_key_x, MAX_SMALL) }?,
    issuer_key_y: unsafe { bytes(st.issuer_key_y, MAX_SMALL) }?,
    time: unsafe { text(st.time) }?,
    earliest: unsafe { text(st.earliest) }?,
    cutoff: unsafe { text(st.cutoff) }?,
    challenge_digest: unsafe { bytes(st.challenge_digest, MAX_SMALL) }?,
    verifier_input: unsafe { bytes(st.verifier_input, MAX_SMALL) }?,
  })
}

/// Accepts `proof` for the values the verifier named and writes the 32-byte pseudonym it reveals
/// to `pseudonym_out`. Returns [`ZK_NYM_OK`] only when the proof is accepted.
///
/// # Safety
/// All pointers must be valid for their lengths; `pseudonym_out` for 32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zk_cred_vega_nymauth_verify(
  keys: *const ZkNymKeys,
  statement: *const ZkNymStatement,
  proof: *const u8,
  proof_len: usize,
  pseudonym_out: *mut u8,
) -> i32 {
  guarded(|| {
    if keys.is_null() || pseudonym_out.is_null() {
      return ZK_NYM_INVALID_ARG;
    }
    let (Some(st), Some(proof)) = (unsafe { statement_of(statement) }, unsafe {
      bytes(ZkNymSlice { ptr: proof, len: proof_len }, statement::MAX_PROOF + 1)
    }) else {
      return ZK_NYM_INVALID_ARG;
    };
    match statement::verify(&unsafe { &*keys }.0, &st, proof) {
      Ok(pseudonym) => {
        unsafe { slice::from_raw_parts_mut(pseudonym_out, 32).copy_from_slice(&pseudonym) };
        ZK_NYM_OK
      }
      Err(e) => code(&e),
    }
  })
}

/// Proves the statement. On success writes the proof to `*proof_out`/`*proof_len_out` (release
/// with [`zk_cred_vega_nymauth_free_buffer`]) and the 32-byte pseudonym to `pseudonym_out`. The
/// caller's `holder.secret_seed` is zeroed in place on every path.
///
/// # Safety
/// All pointers must be valid for their lengths; `pseudonym_out` for 32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zk_cred_vega_nymauth_prove(
  keys: *const ZkNymKeys,
  statement: *const ZkNymStatement,
  holder: *const ZkNymHolder,
  proof_out: *mut *mut u8,
  proof_len_out: *mut usize,
  pseudonym_out: *mut u8,
) -> i32 {
  guarded(|| {
    if keys.is_null() || holder.is_null() || proof_out.is_null() || proof_len_out.is_null() || pseudonym_out.is_null() {
      return ZK_NYM_INVALID_ARG;
    }
    unsafe {
      *proof_out = std::ptr::null_mut();
      *proof_len_out = 0;
    }
    let h = unsafe { *holder };
    // The seed buffer: zeroed below whatever else happens.
    let seed = if h.secret_seed.is_null() || h.secret_seed_len > MAX_SMALL {
      None
    } else {
      Some(unsafe { slice::from_raw_parts_mut(h.secret_seed, h.secret_seed_len) })
    };
    let result = (|| {
      let seed_view: &[u8] = seed.as_deref().ok_or(ZK_NYM_INVALID_ARG)?;
      let st = unsafe { statement_of(statement) }.ok_or(ZK_NYM_INVALID_ARG)?;
      let issuer_signed = unsafe { bytes(h.issuer_signed, statement::MAX_ISSUER_SIGNED + 1) }.ok_or(ZK_NYM_INVALID_ARG)?;
      let device_signature = unsafe { bytes(h.device_signature, MAX_SMALL) }.ok_or(ZK_NYM_INVALID_ARG)?;
      statement::prove(
        &unsafe { &*keys }.0,
        &st,
        &Holder {
          issuer_signed,
          secret_seed: seed_view,
          device_signature,
        },
      )
      .map_err(|e| code(&e))
    })();
    if let Some(seed) = seed {
      seed.zeroize();
    }
    match result {
      Ok(proved) => {
        unsafe { slice::from_raw_parts_mut(pseudonym_out, 32).copy_from_slice(&proved.pseudonym) };
        give(proved.proof, proof_out, proof_len_out);
        ZK_NYM_OK
      }
      Err(status) => status,
    }
  })
}

/// Derives e2 (32 bytes to `e2_out`) and the transcript seed (the SessionTranscript; release with
/// [`zk_cred_vega_nymauth_free_buffer`]) from the verifier's request, per the circuits' `SPEC.md`
/// section 3. `jwk_thumbprint` is null (with length 0) for an unencrypted response, or 32 bytes.
///
/// # Safety
/// All pointers must be valid for their lengths; `e2_out` for 32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zk_cred_vega_nymauth_derive_challenge(
  origin: ZkNymSlice,
  nonce: ZkNymSlice,
  doc_type: ZkNymSlice,
  jwk_thumbprint: ZkNymSlice,
  transcript_out: *mut *mut u8,
  transcript_len_out: *mut usize,
  e2_out: *mut u8,
) -> i32 {
  guarded(|| {
    if e2_out.is_null() || transcript_out.is_null() || transcript_len_out.is_null() {
      return ZK_NYM_INVALID_ARG;
    }
    unsafe {
      *transcript_out = std::ptr::null_mut();
      *transcript_len_out = 0;
    }
    let (Some(origin), Some(nonce), Some(doc_type), Some(thumb)) = (unsafe { text(origin) }, unsafe { text(nonce) }, unsafe { text(doc_type) }, unsafe {
      bytes(jwk_thumbprint, MAX_SMALL)
    }) else {
      return ZK_NYM_INVALID_ARG;
    };
    let thumb = if jwk_thumbprint.ptr.is_null() && thumb.is_empty() {
      None
    } else {
      Some(thumb)
    };
    match challenge::derive(origin, nonce, doc_type, thumb) {
      Ok(c) => {
        unsafe { slice::from_raw_parts_mut(e2_out, 32).copy_from_slice(&c.digest) };
        give(c.session_transcript, transcript_out, transcript_len_out);
        ZK_NYM_OK
      }
      Err(_) => ZK_NYM_INVALID_INPUT,
    }
  })
}

/// e2 (32 bytes to `e2_out`) for a SessionTranscript already in hand and the credential's docType.
///
/// # Safety
/// All pointers must be valid for their lengths; `e2_out` for 32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zk_cred_vega_nymauth_challenge_digest(session_transcript: ZkNymSlice, doc_type: ZkNymSlice, e2_out: *mut u8) -> i32 {
  guarded(|| {
    if e2_out.is_null() {
      return ZK_NYM_INVALID_ARG;
    }
    let (Some(st), Some(doc_type)) = (unsafe { bytes(session_transcript, MAX_SMALL) }, unsafe { text(doc_type) }) else {
      return ZK_NYM_INVALID_ARG;
    };
    match challenge::digest_of_transcript(st, doc_type) {
      Ok(d) => {
        unsafe { slice::from_raw_parts_mut(e2_out, 32).copy_from_slice(&d) };
        ZK_NYM_OK
      }
      Err(_) => ZK_NYM_INVALID_INPUT,
    }
  })
}

/// `verifier_input = SHA-256(client_id)` (32 bytes to `out`); refuses an empty or over-long client_id.
///
/// # Safety
/// `client_id` must be valid for its length; `out` for 32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zk_cred_vega_nymauth_verifier_input(client_id: ZkNymSlice, out: *mut u8) -> i32 {
  guarded(|| {
    if out.is_null() {
      return ZK_NYM_INVALID_ARG;
    }
    let Some(id) = (unsafe { text(client_id) }) else {
      return ZK_NYM_INVALID_ARG;
    };
    match challenge::verifier_input(id) {
      Ok(d) => {
        unsafe { slice::from_raw_parts_mut(out, 32).copy_from_slice(&d) };
        ZK_NYM_OK
      }
      Err(_) => ZK_NYM_INVALID_INPUT,
    }
  })
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::nymauth_vega::engine::statement::Refusal;

  #[test]
  fn every_error_has_its_own_status_code() {
    let cases = [
      (Error::Input(String::new()), ZK_NYM_INVALID_INPUT),
      (Error::Shapes(String::new()), ZK_NYM_INVALID_SHAPES),
      (Error::UnknownCircuit(String::new()), ZK_NYM_UNKNOWN_CIRCUIT),
      (Error::Prover(String::new()), ZK_NYM_PROVER_FAILED),
      (Error::ProofInvalid(String::new()), ZK_NYM_PROOF_INVALID),
      (Error::Mismatch(String::new()), ZK_NYM_MISMATCH),
      (Error::Internal(String::new()), ZK_NYM_INTERNAL),
      (Error::Refused(Refusal::new(RefusalCode::SeedMismatch, "")), ZK_NYM_REFUSED_SEED_MISMATCH),
      (Error::Refused(Refusal::new(RefusalCode::IssuerSignature, "")), ZK_NYM_REFUSED_ISSUER_SIGNATURE),
      (Error::Refused(Refusal::new(RefusalCode::DeviceSignature, "")), ZK_NYM_REFUSED_DEVICE_SIGNATURE),
      (Error::Refused(Refusal::new(RefusalCode::Credential, "")), ZK_NYM_REFUSED_CREDENTIAL),
    ];
    let mut seen = std::collections::BTreeSet::new();
    for (e, want) in cases {
      assert_eq!(code(&e), want);
      assert!(seen.insert(want), "status {want} is used twice");
    }
  }

  #[test]
  fn a_panic_is_a_status_not_an_unwind() {
    assert_eq!(guarded(|| panic!("boom")), ZK_NYM_INTERNAL);
    assert_eq!(guarded(|| ZK_NYM_OK), ZK_NYM_OK);
  }

  #[test]
  fn slices_are_checked_before_they_are_read() {
    let data = [1u8, 2, 3];
    let ok = |s: ZkNymSlice, max| unsafe { bytes(s, max) };
    assert_eq!(ok(ZkNymSlice { ptr: data.as_ptr(), len: 3 }, 8), Some(&data[..]));
    assert_eq!(ok(ZkNymSlice { ptr: std::ptr::null(), len: 0 }, 8), Some(&[][..]));
    assert_eq!(ok(ZkNymSlice { ptr: std::ptr::null(), len: 3 }, 8), None);
    assert_eq!(ok(ZkNymSlice { ptr: data.as_ptr(), len: 9 }, 8), None);
    let bad_utf8 = [0xffu8, 0xfe];
    assert!(
      unsafe {
        text(ZkNymSlice {
          ptr: bad_utf8.as_ptr(),
          len: 2,
        })
      }
      .is_none()
    );
  }
}
