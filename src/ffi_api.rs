//! UniFFI-friendly API, consumed by the native SDKs (Kotlin first, per the
//! tracked plan). Mirrors `zk-cred-longfellow`'s own `ffi_api.rs` shape:
//! plain `#[uniffi::export]` free functions, an opaque error `Object`
//! wrapping `anyhow::Error`, `Record`s carrying only FFI-safe types.
//!
//! `VegaProverKey`/`VegaVerifierKey` are loaded from bytes, not generated
//! on-device — `setup()` runs once, offline, and its output is published
//! to `go-zk-circuits` (see `HANDOFF.md`); wallets fetch and deserialize
//! it. The prep-state cache that gives fold-and-reuse its latency win
//! crosses this boundary as plain bytes too (`prep_prove`'s return /
//! `prove`'s `prior_state` argument), matching exactly what flows through
//! `ZkProofSystem`'s `priorState`/`nextState` fields at the SDK layer —
//! no long-lived native object needs to survive between two separate
//! Kotlin/Swift calls.
//!
//! `verify` performs `crate::verify_and_check_binding` internally rather
//! than exposing raw per-step/core public-value scalars: a caller who
//! skipped that check would have a proof that "verifies" while mixing a
//! valid core signature for one claim set with valid step proofs for a
//! different one (see `mdoc_core`'s module doc) — not a mistake this
//! boundary should make possible to make by accident.

use crate::{
  self as vega_mdoc, nonnative::util::{f_to_nat, nat_to_f}, ClaimWitness, Engine_, MdocEcdsaWitness,
  VegaMdocPrepState,
};
use ff::Field;
use num_bigint::{BigInt, Sign};
use std::fmt::{self, Debug, Display};
use vega_prover::{
  traits::Engine,
  vega_mc_zkp::{VegaMcPrepZkSNARK, VegaMcProverKey, VegaMcVerifierKey, VegaMcZkSNARK},
};

type Scalar = <Engine_ as Engine>::Scalar;

fn bytes_to_bigint(bytes: &[u8]) -> BigInt {
  BigInt::from_bytes_be(Sign::Plus, bytes)
}

fn bigint_to_bytes(n: &BigInt) -> Vec<u8> {
  n.to_bytes_be().1
}

fn bytes_to_scalar(bytes: &[u8]) -> Result<Scalar, VegaFfiError> {
  nat_to_f(&bytes_to_bigint(bytes))
    .ok_or_else(|| VegaFfiError(anyhow::anyhow!("value does not fit in the field")))
}

fn scalar_to_bytes(s: Scalar) -> Vec<u8> {
  bigint_to_bytes(&f_to_nat(&s))
}

/// Big-endian-byte-encoded twin of [`crate::ClaimWitness`].
#[derive(Clone, uniffi::Record)]
pub struct FfiClaim {
  pub issuer_signed_item_bytes: Vec<u8>,
  pub disclose: bool,
}

impl From<FfiClaim> for ClaimWitness {
  fn from(c: FfiClaim) -> Self {
    ClaimWitness {
      issuer_signed_item_bytes: c.issuer_signed_item_bytes,
      disclose: c.disclose,
    }
  }
}

/// Big-endian-byte-encoded twin of [`crate::MdocEcdsaWitness`].
#[derive(uniffi::Record)]
pub struct FfiEcdsaWitness {
  pub qx: Vec<u8>,
  pub qy: Vec<u8>,
  pub r: Vec<u8>,
  pub s: Vec<u8>,
  pub s_inv: Vec<u8>,
}

impl TryFrom<FfiEcdsaWitness> for MdocEcdsaWitness {
  type Error = VegaFfiError;

  fn try_from(w: FfiEcdsaWitness) -> Result<Self, VegaFfiError> {
    Ok(MdocEcdsaWitness {
      qx: bytes_to_scalar(&w.qx)?,
      qy: bytes_to_scalar(&w.qy)?,
      r: bytes_to_bigint(&w.r),
      s: bytes_to_bigint(&w.s),
      s_inv: bytes_to_bigint(&w.s_inv),
    })
  }
}

#[derive(uniffi::Record)]
pub struct FfiProveResult {
  /// The proof, ready to send to a verifier.
  pub proof_bytes: Vec<u8>,
  /// The rerandomized prep-state cache for this credential's *next*
  /// presentation — bincode-serialized `VegaMcPrepZkSNARK`. Feed this back
  /// in as `prove`'s `prior_state` next time, skipping `prep_prove`.
  pub next_state: Vec<u8>,
}

/// The verified, bound public output of a presentation: the issuer's
/// public key (for trust-anchor checking) and each requested claim's
/// digest, in the same order the corresponding step circuits were given —
/// see this module's doc for why the step↔core binding check already ran
/// by the time this is returned.
#[derive(uniffi::Record)]
pub struct FfiVerifyResult {
  pub qx: Vec<u8>,
  pub qy: Vec<u8>,
  pub step_digests: Vec<Vec<u8>>,
}

fn bits_to_bytes(bits: &[Scalar]) -> Vec<u8> {
  bits
    .chunks(8)
    .map(|byte_bits| {
      byte_bits.iter().enumerate().fold(0u8, |byte, (i, bit)| {
        if *bit == Scalar::ONE {
          byte | (1 << (7 - i))
        } else {
          byte
        }
      })
    })
    .collect()
}

#[derive(uniffi::Object)]
pub struct VegaProverKey(pub(crate) VegaMcProverKey<Engine_>);

#[derive(uniffi::Object)]
pub struct VegaVerifierKey(pub(crate) VegaMcVerifierKey<Engine_>);

/// Deserializes a published prover-key artifact (fetched from
/// `go-zk-circuits`) into a handle usable by [`prep_prove`]/[`prove`].
#[uniffi::export]
pub fn deserialize_prover_key(bytes: &[u8]) -> Result<VegaProverKey, VegaFfiError> {
  bincode::deserialize(bytes)
    .map(VegaProverKey)
    .map_err(|e| VegaFfiError(anyhow::anyhow!(e)))
}

/// Deserializes a published verifier-key artifact into a handle usable by
/// [`verify`].
#[uniffi::export]
pub fn deserialize_verifier_key(bytes: &[u8]) -> Result<VegaVerifierKey, VegaFfiError> {
  bincode::deserialize(bytes)
    .map(VegaVerifierKey)
    .map_err(|e| VegaFfiError(anyhow::anyhow!(e)))
}

/// Runs `prep_prove` once for a credential, returning the (serialized)
/// prep-state cache — see this module's doc for why this crosses the FFI
/// boundary as bytes rather than a long-lived handle.
#[uniffi::export]
pub fn prep_prove(
  pk: &VegaProverKey,
  claims: Vec<FfiClaim>,
  ecdsa_witness: FfiEcdsaWitness,
) -> Result<Vec<u8>, VegaFfiError> {
  let claims: Vec<ClaimWitness> = claims.into_iter().map(Into::into).collect();
  let ecdsa_witness: MdocEcdsaWitness = ecdsa_witness.try_into()?;
  let prep = vega_mdoc::prep_prove(&pk.0, &claims, &ecdsa_witness)
    .map_err(|e| VegaFfiError(anyhow::anyhow!(e)))?;
  bincode::serialize(&prep.into_inner()).map_err(|e| VegaFfiError(anyhow::anyhow!(e)))
}

/// Produces a proof for this presentation, rerandomizing `prior_state` for
/// reuse on the *next* presentation of the same credential (to a
/// different verifier, say) — see `next_state` on [`FfiProveResult`].
#[uniffi::export]
pub fn prove(
  pk: &VegaProverKey,
  claims: Vec<FfiClaim>,
  ecdsa_witness: FfiEcdsaWitness,
  prior_state: Vec<u8>,
) -> Result<FfiProveResult, VegaFfiError> {
  let claims: Vec<ClaimWitness> = claims.into_iter().map(Into::into).collect();
  let ecdsa_witness: MdocEcdsaWitness = ecdsa_witness.try_into()?;
  let prep_snark: VegaMcPrepZkSNARK<Engine_> =
    bincode::deserialize(&prior_state).map_err(|e| VegaFfiError(anyhow::anyhow!(e)))?;
  let prep = VegaMdocPrepState::from_inner(prep_snark);

  let (proof, next_prep) = vega_mdoc::prove(&pk.0, &claims, &ecdsa_witness, prep)
    .map_err(|e| VegaFfiError(anyhow::anyhow!(e)))?;

  let proof_bytes = bincode::serialize(&proof).map_err(|e| VegaFfiError(anyhow::anyhow!(e)))?;
  let next_state = bincode::serialize(&next_prep.into_inner())
    .map_err(|e| VegaFfiError(anyhow::anyhow!(e)))?;

  Ok(FfiProveResult {
    proof_bytes,
    next_state,
  })
}

/// Verifies a proof and checks the step↔core binding (see this module's
/// doc) in one call — a caller never sees an unbound "valid" proof.
#[uniffi::export]
pub fn verify(vk: &VegaVerifierKey, proof_bytes: Vec<u8>) -> Result<FfiVerifyResult, VegaFfiError> {
  let proof: VegaMcZkSNARK<Engine_> =
    bincode::deserialize(&proof_bytes).map_err(|e| VegaFfiError(anyhow::anyhow!(e)))?;

  let (step_public_values, core_public_values) =
    vega_mdoc::verify(&proof, &vk.0).map_err(|e| VegaFfiError(anyhow::anyhow!(e)))?;

  let (qx, qy) = vega_mdoc::verify_and_check_binding(&step_public_values, &core_public_values)
    .map_err(|e| VegaFfiError(anyhow::anyhow!(e)))?;

  Ok(FfiVerifyResult {
    qx: scalar_to_bytes(qx),
    qy: scalar_to_bytes(qy),
    step_digests: step_public_values.iter().map(|bits| bits_to_bytes(bits)).collect(),
  })
}

#[derive(uniffi::Object)]
#[uniffi::export(Debug, Display)]
pub struct VegaFfiError(anyhow::Error);

impl std::error::Error for VegaFfiError {
  fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    self.0.source()
  }
}

impl Display for VegaFfiError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{:#}", self.0)
  }
}

impl Debug for VegaFfiError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    <anyhow::Error as Debug>::fmt(&self.0, f)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::p256_ecc::p256_order;
  use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey, VerifyingKey};
  use sha2::{Digest, Sha256};

  /// Exercises the FFI surface exactly as a Kotlin/Swift caller would:
  /// bytes in, bytes out, no direct access to any native Rust type —
  /// setup()'s keys serialized, deserialized via `deserialize_prover_key`/
  /// `deserialize_verifier_key`, a full prep_prove/prove/verify round trip
  /// (including a second presentation reusing `next_state`), all through
  /// this module's own public functions.
  #[test]
  fn ffi_round_trip_with_real_signature() {
    let keys = vega_mdoc::setup().expect("setup");
    let pk_bytes = bincode::serialize(&keys.pk).expect("serialize pk");
    let vk_bytes = bincode::serialize(&keys.vk).expect("serialize vk");

    let pk = deserialize_prover_key(&pk_bytes).expect("deserialize pk");
    let vk = deserialize_verifier_key(&vk_bytes).expect("deserialize vk");

    let claims = vec![
      FfiClaim {
        issuer_signed_item_bytes: b"family_name:Doe".to_vec(),
        disclose: true,
      },
      FfiClaim {
        issuer_signed_item_bytes: b"given_name:Jane".to_vec(),
        disclose: true,
      },
    ];
    let claim_witnesses: Vec<ClaimWitness> =
      claims.iter().map(|c| ClaimWitness {
        issuer_signed_item_bytes: c.issuer_signed_item_bytes.clone(),
        disclose: c.disclose,
      }).collect();
    let claim_digests =
      vega_mdoc::core_claim_digests(&claim_witnesses).expect("core_claim_digests");

    let signing_key = SigningKey::from_bytes(&[7u8; 32].into()).expect("valid scalar");
    let verifying_key = VerifyingKey::from(&signing_key);
    let mut hasher = Sha256::new();
    for d in &claim_digests {
      hasher.update(d);
    }
    let z_bytes: [u8; 32] = hasher.finalize().into();
    let signature: Signature = signing_key.sign_prehash(&z_bytes).expect("sign_prehash");
    let n = p256_order();
    let s = bytes_to_bigint(&signature.s().to_bytes());
    let s_inv = s.modpow(&(n.clone() - BigInt::from(2)), &n);
    let encoded = {
      verifying_key.to_encoded_point(false)
    };

    let ecdsa_witness = FfiEcdsaWitness {
      qx: encoded.x().expect("x").to_vec(),
      qy: encoded.y().expect("y").to_vec(),
      r: signature.r().to_bytes().to_vec(),
      s: signature.s().to_bytes().to_vec(),
      s_inv: bigint_to_bytes(&s_inv),
    };

    let prep_state = prep_prove(&pk, claims.clone(), ffi_witness_clone(&ecdsa_witness))
      .expect("prep_prove");
    let result1 = prove(&pk, claims.clone(), ffi_witness_clone(&ecdsa_witness), prep_state)
      .expect("prove 1");
    let verified1 = verify(&vk, result1.proof_bytes).expect("verify 1");
    assert_eq!(verified1.qx, ecdsa_witness.qx);
    assert_eq!(verified1.qy, ecdsa_witness.qy);
    assert_eq!(verified1.step_digests.len(), crate::MAX_CLAIMS_V1);

    // Second presentation reusing next_state (the fold-and-reuse path).
    let result2 = prove(&pk, claims, ffi_witness_clone(&ecdsa_witness), result1.next_state)
      .expect("prove 2 (reused prep state)");
    let verified2 = verify(&vk, result2.proof_bytes).expect("verify 2");
    assert_eq!(verified2.qx, ecdsa_witness.qx);
  }

  fn ffi_witness_clone(w: &FfiEcdsaWitness) -> FfiEcdsaWitness {
    FfiEcdsaWitness {
      qx: w.qx.clone(),
      qy: w.qy.clone(),
      r: w.r.clone(),
      s: w.s.clone(),
      s_inv: w.s_inv.clone(),
    }
  }
}
