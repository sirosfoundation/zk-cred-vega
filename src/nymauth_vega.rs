// SPDX-License-Identifier: BSD-2-Clause
//! The `nymauth` prover and verifier for the Vega proving system: the narrow call the SDKs' native
//! `NymAuthNativeProver` seam expects, as its own module. It is separate from the generic mdoc/age
//! entry points of [`crate::ffi_api`] on purpose: the nymauth circuits (age range and a
//! verifier-specific pseudonym, `known-offender-matching-ssc`) have their own shapes, witness and
//! public values. The statement itself is [`engine`] (ported from our own `nym-auth-circuits`
//! archive, on top of the public API of `vega-prover`); this file is the typed, FFI-safe layer over it.
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
//! identifier), never from the holder or the presentation. Derive `challenge_digest` (e2) and the
//! transcript seed with [`nymauth_derive_challenge`] (or [`nymauth_challenge_digest`] for
//! a SessionTranscript already in hand), which follow the circuits' `SPEC.md` section 3 exactly. A
//! verifier that reads them from the
//! presentation lets a holder replay or re-target a proof. `issuer_key_*` must be the key the
//! verifier trusts for the issuer. The key set is pinned: only shapes approved in
//! [`engine::statement::APPROVED_SHAPES`] are accepted. The age range follows
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

pub mod engine;

use engine::statement::{self, Error, Holder, Keys, Statement};
use zeroize::Zeroize;

/// Why a proof could not be made or was not accepted.
#[derive(Debug, thiserror::Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum NymAuthVegaError {
  /// An input has the wrong length, format or structure.
  #[error("invalid input: {detail}")]
  InvalidInput { detail: String },
  /// The shapes are unreadable or past the circuit budget.
  #[error("invalid circuit shapes: {detail}")]
  InvalidShapes { detail: String },
  /// The shapes are well formed but are not an approved circuit; `detail` is their SHA-256.
  #[error("circuit not approved: {detail}")]
  UnknownCircuit { detail: String },
  /// The inputs break a rule of the circuit. `detail` is a coarse code (`SeedMismatch`,
  /// `IssuerSignature`, `DeviceSignature` or `Credential`), never the rule. No proof was made.
  #[error("inputs refused: {detail}")]
  Refused { detail: String },
  /// The prover failed.
  #[error("prover failed: {detail}")]
  ProverFailed { detail: String },
  /// The proof bytes are not one `vega-v1` proof.
  #[error("proof encoding: {detail}")]
  ProofEncoding { detail: String },
  /// The proof does not verify, or a step instance reports another position.
  #[error("proof invalid: {detail}")]
  ProofInvalid { detail: String },
  /// The proof verifies but not for the values the verifier named.
  #[error("proof does not match the named values: {detail}")]
  Mismatch { detail: String },
  /// A bug: a panic was caught.
  #[error("internal error: {detail}")]
  Internal { detail: String },
}

impl From<Error> for NymAuthVegaError {
  fn from(e: Error) -> Self {
    match e {
      Error::Input(detail) => Self::InvalidInput { detail },
      Error::Shapes(detail) => Self::InvalidShapes { detail },
      Error::UnknownCircuit(detail) => Self::UnknownCircuit { detail },
      Error::Refused(r) => Self::Refused {
        detail: format!("{:?}", r.code),
      },
      Error::Prover(detail) => Self::ProverFailed { detail },
      Error::ProofEncoding(detail) => Self::ProofEncoding { detail },
      Error::ProofInvalid(detail) => Self::ProofInvalid { detail },
      Error::Mismatch(detail) => Self::Mismatch { detail },
      Error::Internal(detail) => Self::Internal { detail },
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

/// Proves the statement for the verifier's values (`statement.challenge_digest` comes from
/// [`nymauth_derive_challenge`]). `holder.secret_seed` is zeroed before this
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
pub fn prove_zeroing(keys: &NymAuthVegaKeys, statement: &NymAuthVegaStatement, holder: &mut NymAuthVegaHolder) -> Result<NymAuthVegaProof, NymAuthVegaError> {
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
  Ok(NymAuthVegaProof {
    proof: proved.proof,
    pseudonym: proved.pseudonym.to_vec(),
  })
}

/// Accepts a proof for the values the verifier named, which the verifier derives itself:
/// `challenge_digest` with [`nymauth_derive_challenge`], `verifier_input` as
/// SHA-256(its client_id), `time` from its clock. Returns the pseudonym it reveals (32 bytes).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn nymauth_vega_verify(keys: &NymAuthVegaKeys, statement: NymAuthVegaStatement, proof: Vec<u8>) -> Result<Vec<u8>, NymAuthVegaError> {
  Ok(statement::verify(&keys.0, &statement_of(&statement), &proof)?.to_vec())
}

/// e2 and the transcript seed of one presentation request (`SPEC.md` section 3).
#[derive(Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct NymAuthChallenge {
  /// The SessionTranscript bytes: the transcript seed (Longfellow's Fiat-Shamir seed).
  pub session_transcript: Vec<u8>,
  /// e2: SHA-256 of the COSE `Signature1` message the device key signs, 32 bytes. This is the
  /// `challenge_digest` of [`NymAuthVegaStatement`].
  pub challenge_digest: Vec<u8>,
}

/// Derives e2 and the transcript seed for an mdoc presentation over the Digital Credentials API:
/// the way a verifier computes `NymAuthVegaStatement::challenge_digest` from its own request
/// (`origin`, `nonce`, the credential's `doc_type` and, for an encrypted response, the 32-byte
/// JWK thumbprint of the response key; `None` for CBOR null). Refuses an empty origin or docType,
/// a nonce shorter than 16 characters and a thumbprint that is not 32 bytes.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn nymauth_derive_challenge(
  origin: String,
  nonce: String,
  doc_type: String,
  jwk_thumbprint: Option<Vec<u8>>,
) -> Result<NymAuthChallenge, NymAuthVegaError> {
  let c = engine::challenge::derive(&origin, &nonce, &doc_type, jwk_thumbprint.as_deref()).map_err(|detail| NymAuthVegaError::InvalidInput { detail })?;
  Ok(NymAuthChallenge {
    session_transcript: c.session_transcript,
    challenge_digest: c.digest.to_vec(),
  })
}

/// e2 for a SessionTranscript already in hand (a definite CBOR array of three items, nothing
/// after it) and the credential's docType; refuses an empty or malformed transcript.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn nymauth_challenge_digest(session_transcript: Vec<u8>, doc_type: String) -> Result<Vec<u8>, NymAuthVegaError> {
  engine::challenge::digest_of_transcript(&session_transcript, &doc_type)
    .map(|d| d.to_vec())
    .map_err(|detail| NymAuthVegaError::InvalidInput { detail })
}

/// `verifier_input = SHA-256(client_id)`, the value a verifier names in its statement
/// (`NymAuthVegaStatement::verifier_input`); refuses an empty or over-long client_id.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn nymauth_verifier_input(client_id: String) -> Result<Vec<u8>, NymAuthVegaError> {
  engine::challenge::verifier_input(&client_id)
    .map(|d| d.to_vec())
    .map_err(|detail| NymAuthVegaError::InvalidInput { detail })
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::nymauth_vega::engine::statement::{Refusal, RefusalCode};

  #[test]
  fn every_engine_error_maps_to_its_binding_error() {
    let m = |e: Error| NymAuthVegaError::from(e);
    assert!(matches!(m(Error::Input("a".into())), NymAuthVegaError::InvalidInput { detail } if detail == "a"));
    assert!(matches!(m(Error::Shapes("a".into())), NymAuthVegaError::InvalidShapes { detail } if detail == "a"));
    assert!(matches!(m(Error::UnknownCircuit("h".into())), NymAuthVegaError::UnknownCircuit { detail } if detail == "h"));
    assert!(
      matches!(m(Error::Refused(Refusal::new(RefusalCode::DeviceSignature, "x/y"))), NymAuthVegaError::Refused { detail } if detail == "DeviceSignature")
    );
    assert!(matches!(m(Error::Prover("a".into())), NymAuthVegaError::ProverFailed { detail } if detail == "a"));
    assert!(matches!(m(Error::ProofEncoding("a".into())), NymAuthVegaError::ProofEncoding { detail } if detail == "a"));
    assert!(matches!(m(Error::ProofInvalid("a".into())), NymAuthVegaError::ProofInvalid { detail } if detail == "a"));
    assert!(matches!(m(Error::Mismatch("a".into())), NymAuthVegaError::Mismatch { detail } if detail == "a"));
    assert!(matches!(m(Error::Internal("a".into())), NymAuthVegaError::Internal { detail } if detail == "a"));
  }

  #[test]
  fn the_binding_errors_display_their_detail() {
    assert_eq!(
      NymAuthVegaError::Mismatch { detail: "d".into() }.to_string(),
      "proof does not match the named values: d"
    );
    assert_eq!(
      NymAuthVegaError::Refused { detail: "SeedMismatch".into() }.to_string(),
      "inputs refused: SeedMismatch"
    );
  }
}
