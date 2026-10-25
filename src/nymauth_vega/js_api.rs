// SPDX-License-Identifier: BSD-2-Clause
//! wasm-bindgen surface of the nymauth prover, for a wallet that proves in the page. It mirrors
//! [`super::nymauth_vega_load_keys`] and [`super::nymauth_vega_prove`]: the keys are built once
//! from the decompressed shapes and reused for every request.

use std::sync::Arc;

use wasm_bindgen::prelude::{JsError, wasm_bindgen};
use zeroize::Zeroize;

use super::{NymAuthVegaError, NymAuthVegaHolder, NymAuthVegaKeys, NymAuthVegaStatement};

/// `initThreadPool(n)`: starts rayon's pool on `n` Web Workers. Await it once, in a Worker,
/// before the first call that proves.
#[cfg(feature = "wasm-threads")]
pub use wasm_bindgen_rayon::init_thread_pool;

/// The keys built from one approved set of shapes.
#[wasm_bindgen(js_name = NymAuthVegaKeys)]
pub struct JsNymAuthVegaKeys(Arc<NymAuthVegaKeys>);

/// The proof and the pseudonym it reveals (32 bytes).
#[wasm_bindgen(js_name = NymAuthVegaProof, getter_with_clone)]
pub struct JsNymAuthVegaProof {
  pub proof: Vec<u8>,
  pub pseudonym: Vec<u8>,
}

fn js_error(e: NymAuthVegaError) -> JsError {
  JsError::new(&e.to_string())
}

/// Builds the keys from the decompressed shapes (the bincode `(step, core)` of the catalog's
/// `vega-nymauth` mdoc artifact).
#[wasm_bindgen]
pub fn nymauth_vega_load_keys(shapes: Vec<u8>) -> Result<JsNymAuthVegaKeys, JsError> {
  super::nymauth_vega_load_keys(shapes).map(JsNymAuthVegaKeys).map_err(js_error)
}

/// Proves the statement for the verifier's values. The arguments are the fields of
/// `NymAuthVegaStatement` then of `NymAuthVegaHolder`, in their order. The copies of
/// `issuer_signed`, `secret_seed` and `device_signature` in WASM memory are zeroed before this
/// returns; the caller zeroes its own.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn nymauth_vega_prove(
  keys: &JsNymAuthVegaKeys,
  issuer_key_x: Vec<u8>,
  issuer_key_y: Vec<u8>,
  time: String,
  earliest: String,
  cutoff: String,
  challenge_digest: Vec<u8>,
  verifier_input: Vec<u8>,
  issuer_signed: Vec<u8>,
  secret_seed: Vec<u8>,
  device_signature: Vec<u8>,
) -> Result<JsNymAuthVegaProof, JsError> {
  let statement = NymAuthVegaStatement {
    issuer_key_x,
    issuer_key_y,
    time,
    earliest,
    cutoff,
    challenge_digest,
    verifier_input,
  };
  let mut holder = NymAuthVegaHolder {
    issuer_signed,
    secret_seed,
    device_signature,
  };
  let r = super::prove_zeroing(&keys.0, &statement, &mut holder);
  holder.issuer_signed[..].zeroize();
  holder.device_signature[..].zeroize();
  r.map(|p| JsNymAuthVegaProof {
    proof: p.proof,
    pseudonym: p.pseudonym,
  })
  .map_err(js_error)
}
