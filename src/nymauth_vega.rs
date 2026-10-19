// SPDX-License-Identifier: BSD-2-Clause
//! The `nymauth` prover and verifier for the Vega proving system: the narrow call the SDKs' native
//! `NymAuthNativeProver` seam expects, as its own module. It is separate from the generic mdoc/age
//! entry points of [`crate::ffi_api`] on purpose: the nymauth circuits (age range and a
//! verifier-specific pseudonym, `known-offender-matching-ssc`) have their own shapes, witness and
//! public values. The statement itself lives in the prover fork (`vega-nymauth`); this file is
//! only the typed, FFI-safe layer over it.
//!
//! The catalog artifact of a `vega-nymauth` circuit is the circuit's SHAPES, not keys: call
//! [`nymauth_vega_load_keys`] once with the decompressed shapes (setup, about a second on a
//! desktop, see the README), keep the handle (it is the resident circuit), and pass it to
//! [`nymauth_vega_prove`] and [`nymauth_vega_verify`].
//!
//! # Integration contract
//!
//! The proof shows the statement for the values it is given, so `time`, `challenge_digest` and
//! `verifier_input` must come from the verifier (its clock, the request it issued, its own
//! identifier), never from the holder or the presentation: a verifier that reads them from the
//! presentation lets a holder replay or re-target a proof. `issuer_key_*` must be the key the
//! verifier trusts for the issuer. The key set is pinned: only shapes approved in the
//! prover fork (`vega_nymauth::statement::APPROVED_SHAPES`) are accepted. The age range follows
//! the rulebook (both bounds given: at least 365 days, `le >= ge`). Credentials must follow the
//! nym_auth issuance profile (unique attribute names). The circuit does not check that the issuer
//! key is a P-256 point; the library does on the host.
//!
//! mdoc only. SD-JWT VC is not exposed: its challenge needs the request's nonce, client_id and
//! origin, which the seam does not carry.
//!
//! Nothing here panics across the FFI boundary: a panic below is caught and returned as
//! [`NymAuthVegaError::Internal`]. The secret seed's Rust copies are zeroed before
//! [`nymauth_vega_prove`] returns; the caller zeroes its own.

use std::sync::Arc;

use vega_nymauth::statement::{self, Error, Holder, Keys, Statement};
use zeroize::Zeroize;

/// Why a proof could not be made or was not accepted.
#[derive(Debug, thiserror::Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum NymAuthVegaError {
  /// An input has the wrong length, format or structure.
  #[error("invalid input: {message}")]
  InvalidInput { message: String },
  /// The shapes are unreadable or past the circuit budget.
  #[error("invalid circuit shapes: {message}")]
  InvalidShapes { message: String },
  /// The shapes are well formed but are not an approved circuit; `message` is their SHA-256.
  #[error("circuit not approved: {message}")]
  UnknownCircuit { message: String },
  /// The inputs break a rule of the circuit. `message` is a coarse code (`SeedMismatch`,
  /// `IssuerSignature`, `DeviceSignature` or `Credential`), never the rule. No proof was made.
  #[error("inputs refused: {message}")]
  Refused { message: String },
  /// The prover failed.
  #[error("prover failed: {message}")]
  ProverFailed { message: String },
  /// The proof does not verify.
  #[error("proof invalid: {message}")]
  ProofInvalid { message: String },
  /// The proof verifies but not for the values the verifier named.
  #[error("proof does not match the named values: {message}")]
  Mismatch { message: String },
  /// A bug: a panic was caught.
  #[error("internal error: {message}")]
  Internal { message: String },
}

impl From<Error> for NymAuthVegaError {
  fn from(e: Error) -> Self {
    match e {
      Error::Input(message) => Self::InvalidInput { message },
      Error::Shapes(message) => Self::InvalidShapes { message },
      Error::UnknownCircuit(message) => Self::UnknownCircuit { message },
      Error::Refused(r) => Self::Refused { message: format!("{:?}", r.code) },
      Error::Prover(message) => Self::ProverFailed { message },
      Error::ProofInvalid(message) => Self::ProofInvalid { message },
      Error::Mismatch(message) => Self::Mismatch { message },
      Error::Internal(message) => Self::Internal { message },
    }
  }
}

/// The keys of the nymauth mdoc circuits, built from their shapes. Holds the prover and verifier
/// key: tens of MB of resident memory, built once.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct NymAuthVegaKeys(Keys);

/// The values the verifier names. Both sides need them.
#[derive(Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct NymAuthVegaStatement {
  /// Issuer key Q, big-endian x, 32 bytes.
  pub issuer_key_x: Vec<u8>,
  /// Issuer key Q, big-endian y, 32 bytes.
  pub issuer_key_y: Vec<u8>,
  /// T: `YYYY-MM-DDThh:mm:ssZ`.
  pub time: String,
  /// E: `YYYY-MM-DD`, `0000-00-00` for no lower bound.
  pub earliest: String,
  /// C: `YYYY-MM-DD`, `9999-12-31` for no upper bound.
  pub cutoff: String,
  /// e2: SHA-256 of the COSE `Signature1` message the device key signed, 32 bytes.
  pub challenge_digest: Vec<u8>,
  /// SHA-256(verifier_id), 32 bytes.
  pub verifier_input: Vec<u8>,
}

/// What only the holder has.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct NymAuthVegaHolder {
  /// The credential's `IssuerSigned` as CBOR, items in their original encoding.
  pub issuer_signed: Vec<u8>,
  /// The 16-byte `secret_seed`. Zeroed by [`nymauth_vega_prove`].
  pub secret_seed: Vec<u8>,
  /// The device key's ES256 signature on the challenge message, `r || s`, 64 bytes.
  pub device_signature: Vec<u8>,
}

/// The proof, as `nymauth_vega_verify` reads it, and the pseudonym it reveals (32 bytes).
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct NymAuthVegaProof {
  pub proof: Vec<u8>,
  pub pseudonym: Vec<u8>,
}

/// Builds the keys from the circuit's decompressed shapes (the bincode `(step, core)` of the
/// catalog's `vega-nymauth` mdoc artifact).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn nymauth_vega_load_keys(shapes: Vec<u8>) -> Result<Arc<NymAuthVegaKeys>, NymAuthVegaError> {
  Ok(Arc::new(NymAuthVegaKeys(Keys::from_shapes(&shapes)?)))
}

fn statement_of(s: &NymAuthVegaStatement) -> Statement<'_> {
  Statement {
    issuer_key_x: &s.issuer_key_x,
    issuer_key_y: &s.issuer_key_y,
    time: &s.time,
    earliest: &s.earliest,
    cutoff: &s.cutoff,
    challenge_digest: &s.challenge_digest,
    verifier_input: &s.verifier_input,
  }
}

/// Proves the statement for the verifier's values. `holder.secret_seed` is zeroed before this
/// returns, on every path. Refuses (`Refused`, naming the first broken rule) rather than make a
/// proof no verifier would accept.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn nymauth_vega_prove(
  keys: &NymAuthVegaKeys,
  statement: NymAuthVegaStatement,
  mut holder: NymAuthVegaHolder,
) -> Result<NymAuthVegaProof, NymAuthVegaError> {
  prove_zeroing(keys, &statement, &mut holder)
}

/// The body of [`nymauth_vega_prove`]: zeroes `holder.secret_seed` on every path.
pub fn prove_zeroing(
  keys: &NymAuthVegaKeys,
  statement: &NymAuthVegaStatement,
  holder: &mut NymAuthVegaHolder,
) -> Result<NymAuthVegaProof, NymAuthVegaError> {
  let result = statement::prove(
    &keys.0,
    &statement_of(statement),
    &Holder {
      issuer_signed: &holder.issuer_signed,
      secret_seed: &holder.secret_seed,
      device_signature: &holder.device_signature,
    },
  );
  // In place, keeping the length (Vec::zeroize would also truncate it).
  holder.secret_seed[..].zeroize();
  let proved = result?;
  Ok(NymAuthVegaProof { proof: proved.proof, pseudonym: proved.pseudonym.to_vec() })
}

/// Accepts a proof for the values the verifier named; returns the pseudonym it reveals (32 bytes).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn nymauth_vega_verify(
  keys: &NymAuthVegaKeys,
  statement: NymAuthVegaStatement,
  proof: Vec<u8>,
) -> Result<Vec<u8>, NymAuthVegaError> {
  Ok(statement::verify(&keys.0, &statement_of(&statement), &proof)?.to_vec())
}
