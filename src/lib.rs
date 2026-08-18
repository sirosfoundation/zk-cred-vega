//! zk-cred-vega: mdoc selective-disclosure circuits built on top of
//! Microsoft's `vega-prover` ZK engine (https://github.com/microsoft/vega-prover).
//!
//! `vega-prover` supplies the proving system (NeutronNova-folding Spartan
//! over R1CS, no trusted setup) but has zero credential-specific code. This
//! crate supplies the mdoc-shaped circuit and the mobile-facing API on top
//! of it: one `VegaCircuit` "step" per disclosed/checked mdoc element,
//! verifying its SHA-256 digest against the corresponding entry read from
//! the mobile security object (MSO), folded together via `vega_mc_zkp`.
//!
//! Phase 1 (this file): digest-matching step circuits only, wired through a
//! real `setup`/`prep_prove`/`prove`/`verify` round-trip, with a stub core
//! circuit standing in for MSO signature verification. The core circuit's
//! `issuer_auth` ECDSA-P256 check (the actual "is this MSO genuinely signed
//! by the issuer" step) is Phase 2 — see `docs/plan.md`. Until Phase 2
//! lands, a proof from this crate demonstrates knowledge of preimages
//! matching claimed digests; it does **not** yet demonstrate that those
//! digests came from a validly-signed MSO. Do not treat it as a credential
//! presentation proof until Phase 2 is done.

use bellpepper::gadgets::sha256::sha256;
use bellpepper_core::{
  ConstraintSystem, SynthesisError,
  boolean::{AllocatedBit, Boolean},
  num::AllocatedNum,
};
use ff::{Field, PrimeFieldBits};
use sha2::{Digest, Sha256};
use std::marker::PhantomData;
use vega_prover::{
  provider::T256HyraxEngine,
  traits::{Engine, circuit::VegaCircuit},
  vega_mc_zkp::{VegaMcProverKey, VegaMcVerifierKey, VegaMcZkSNARK},
};

/// The curve/commitment engine this crate is built against. `T256HyraxEngine`
/// is `vega-prover`'s 2-cycle partner curve for `P256HyraxEngine`, chosen
/// upstream specifically to make in-circuit P-256 (mdoc/MSO's own signature
/// curve) arithmetic efficient — see Phase 2.
pub type Engine_ = T256HyraxEngine;

/// Maximum number of mdoc elements (namespace + value) one circuit instance
/// can check in a single presentation. Fixed per circuit "version", same as
/// Longfellow's own numAttributes-bound circuits — proving/verifying with a
/// different count requires a different `setup()` and a different published
/// artifact (see plan §5). Chosen small for the Phase 1 buildable skeleton;
/// revisit once real presentations are exercised.
pub const MAX_CLAIMS_V1: usize = 4;

/// Fixed byte length every claim's `IssuerSignedItem` bytes are padded (or
/// rejected as too long) to before hashing. NeutronNova folds instances of
/// the *same* R1CS shape — since SHA-256's padding scheme depends on
/// message length, a step circuit's constraint count depends on its input
/// byte length. `setup()`'s prototype circuit and every real circuit
/// passed to `prep_prove`/`prove` (real claims and padding slots alike)
/// must therefore all hash exactly this many bytes, or folding fails with
/// a shape mismatch (found via `round_trip_digest_only_proof` — see its
/// comment). Chosen small for the Phase 1 skeleton; real mdoc element
/// sizes (e.g. portrait/signature_usual_mark) will need a larger value or
/// a length-bucketing scheme in a later circuit version.
pub const MAX_CLAIM_BYTES_V1: usize = 64;

/// Errors from this crate's circuit/proving layer.
#[derive(Debug, thiserror::Error)]
pub enum VegaMdocError {
  #[error("expected at most {max} claims, got {got}")]
  TooManyClaims { max: usize, got: usize },
  #[error("claim bytes exceed the fixed {max}-byte circuit width, got {got}")]
  ClaimTooLong { max: usize, got: usize },
  #[error(transparent)]
  Circuit(#[from] SynthesisError),
  #[error(transparent)]
  Vega(#[from] vega_prover::errors::VegaError),
}

/// One mdoc element to be digest-checked: the exact bytes that were hashed
/// to produce the corresponding `valueDigests` entry in the MSO (i.e. the
/// CBOR-encoded `IssuerSignedItem`), and whether this element is being
/// disclosed (its plaintext value revealed in `public_values`) or merely
/// proved-consistent (digest checked, value kept private).
#[derive(Clone, Debug)]
pub struct ClaimWitness {
  pub issuer_signed_item_bytes: Vec<u8>,
  pub disclose: bool,
}

/// Step circuit: computes SHA-256 over one `IssuerSignedItem`'s bytes and
/// exposes the digest as a public value. The corresponding
/// `valueDigests[namespace][digestID]` comparison against this exposed
/// digest, and the decision of whether to also expose the plaintext value,
/// is the core circuit's job (today: a Phase 1 stub; Phase 2: real MSO
/// binding) — this keeps the expensive per-claim SHA-256 work foldable
/// across steps rather than repeated in the core circuit.
///
/// Modeled directly on `vega-prover`'s own `benches/sha256_vega_mc_zkp.rs`
/// `Sha256StepCircuit`, using the full-message `sha256` gadget (handles
/// padding/length internally) instead of the single-block compression
/// function, since mdoc elements vary in length.
#[derive(Clone, Debug)]
pub struct ClaimDigestStepCircuit<Eng: Engine> {
  bytes: Vec<u8>,
  _p: PhantomData<Eng>,
}

impl<Eng: Engine> ClaimDigestStepCircuit<Eng> {
  pub fn new(bytes: Vec<u8>) -> Self {
    Self {
      bytes,
      _p: PhantomData,
    }
  }

  fn digest_bits(&self) -> Vec<bool> {
    let mut hasher = Sha256::new();
    hasher.update(&self.bytes);
    let digest = hasher.finalize();
    digest
      .iter()
      .flat_map(|&byte| (0..8).rev().map(move |i| (byte >> i) & 1 == 1))
      .collect()
  }
}

impl<Eng: Engine> VegaCircuit<Eng> for ClaimDigestStepCircuit<Eng>
where
  Eng::Scalar: PrimeFieldBits,
{
  fn public_values(&self) -> Result<Vec<Eng::Scalar>, SynthesisError> {
    Ok(
      self
        .digest_bits()
        .into_iter()
        .map(|b| if b { Eng::Scalar::ONE } else { Eng::Scalar::ZERO })
        .collect(),
    )
  }

  fn shared<CS: ConstraintSystem<Eng::Scalar>>(
    &self,
    _cs: &mut CS,
  ) -> Result<Vec<AllocatedNum<Eng::Scalar>>, SynthesisError> {
    Ok(vec![])
  }

  fn precommitted<CS: ConstraintSystem<Eng::Scalar>>(
    &self,
    cs: &mut CS,
    _shared: &[AllocatedNum<Eng::Scalar>],
  ) -> Result<Vec<AllocatedNum<Eng::Scalar>>, SynthesisError> {
    let input_bits: Vec<Boolean> = self
      .bytes
      .iter()
      .flat_map(|byte| (0..8).rev().map(move |i| (byte >> i) & 1u8 == 1u8))
      .enumerate()
      .map(|(i, b)| {
        AllocatedBit::alloc(cs.namespace(|| format!("claim byte-bit {i}")), Some(b)).map(Boolean::from)
      })
      .collect::<Result<Vec<_>, _>>()?;

    let digest_bits = sha256(cs.namespace(|| "sha256(issuer_signed_item)"), &input_bits)?;

    for (i, bit) in digest_bits.iter().enumerate() {
      let value = bit.get_value().map(|b| {
        if b {
          Eng::Scalar::ONE
        } else {
          Eng::Scalar::ZERO
        }
      });
      let num = AllocatedNum::alloc(cs.namespace(|| format!("digest bit {i} as num")), || {
        value.ok_or(SynthesisError::AssignmentMissing)
      })?;
      cs.enforce(
        || format!("digest bit {i} matches boolean"),
        |lc| lc + &bit.lc(CS::one(), Eng::Scalar::ONE),
        |lc| lc + CS::one(),
        |lc| lc + num.get_variable(),
      );
      num.inputize(cs.namespace(|| format!("inputize digest bit {i}")))?;
    }

    Ok(vec![])
  }

  fn num_challenges(&self) -> usize {
    0
  }

  fn synthesize<CS: ConstraintSystem<Eng::Scalar>>(
    &self,
    _cs: &mut CS,
    _shared: &[AllocatedNum<Eng::Scalar>],
    _precommitted: &[AllocatedNum<Eng::Scalar>],
    _challenges: Option<&[Eng::Scalar]>,
  ) -> Result<(), SynthesisError> {
    Ok(())
  }
}

/// Phase 1 stub core circuit. Real job (Phase 2): parse `issuerAuth`,
/// verify its ECDSA-P256 COSE_Sign1 signature over the MSO, and check each
/// step circuit's exposed digest against the matching `valueDigests` entry.
/// For now it exposes a single constant public value, matching
/// `vega-prover`'s own trivial `CoreCircuit` bench shape, purely to keep
/// the "N steps + 1 core" structure `vega_mc_zkp` requires while the real
/// binding logic is built.
#[derive(Clone, Debug)]
pub struct StubCoreCircuit<Eng: Engine>(PhantomData<Eng>);

impl<Eng: Engine> StubCoreCircuit<Eng> {
  pub fn new() -> Self {
    Self(PhantomData)
  }
}

impl<Eng: Engine> Default for StubCoreCircuit<Eng> {
  fn default() -> Self {
    Self::new()
  }
}

impl<Eng: Engine> VegaCircuit<Eng> for StubCoreCircuit<Eng> {
  fn public_values(&self) -> Result<Vec<Eng::Scalar>, SynthesisError> {
    Ok(vec![Eng::Scalar::ZERO])
  }

  fn shared<CS: ConstraintSystem<Eng::Scalar>>(
    &self,
    _cs: &mut CS,
  ) -> Result<Vec<AllocatedNum<Eng::Scalar>>, SynthesisError> {
    Ok(vec![])
  }

  fn precommitted<CS: ConstraintSystem<Eng::Scalar>>(
    &self,
    cs: &mut CS,
    _shared: &[AllocatedNum<Eng::Scalar>],
  ) -> Result<Vec<AllocatedNum<Eng::Scalar>>, SynthesisError> {
    let x = AllocatedNum::alloc(cs.namespace(|| "core stub x"), || Ok(Eng::Scalar::ZERO))?;
    x.inputize(cs.namespace(|| "inputize core stub x"))?;
    Ok(vec![])
  }

  fn num_challenges(&self) -> usize {
    0
  }

  fn synthesize<CS: ConstraintSystem<Eng::Scalar>>(
    &self,
    _cs: &mut CS,
    _shared: &[AllocatedNum<Eng::Scalar>],
    _precommitted: &[AllocatedNum<Eng::Scalar>],
    _challenges: Option<&[Eng::Scalar]>,
  ) -> Result<(), SynthesisError> {
    Ok(())
  }
}

/// Prover/verifier keys for a fixed `MAX_CLAIMS_V1`-step circuit, produced
/// once by [`setup`] and published to `go-zk-circuits` per plan §5.
pub struct VegaMdocKeys {
  pub pk: VegaMcProverKey<Engine_>,
  pub vk: VegaMcVerifierKey<Engine_>,
}

/// Runs `VegaMcZkSNARK::setup` for the fixed claim-count circuit shape.
pub fn setup() -> Result<VegaMdocKeys, VegaMdocError> {
  let step_proto = ClaimDigestStepCircuit::<Engine_>::new(vec![0u8; MAX_CLAIM_BYTES_V1]);
  let core_proto = StubCoreCircuit::<Engine_>::new();
  let (pk, vk) = VegaMcZkSNARK::<Engine_>::setup(&step_proto, &core_proto, MAX_CLAIMS_V1)?;
  Ok(VegaMdocKeys { pk, vk })
}

/// Pads `bytes` to exactly `MAX_CLAIM_BYTES_V1` bytes (fixed circuit width
/// — see that constant's doc comment); errors if it's already longer.
fn fixed_width_claim_bytes(bytes: &[u8]) -> Result<Vec<u8>, VegaMdocError> {
  if bytes.len() > MAX_CLAIM_BYTES_V1 {
    return Err(VegaMdocError::ClaimTooLong {
      max: MAX_CLAIM_BYTES_V1,
      got: bytes.len(),
    });
  }
  let mut padded = bytes.to_vec();
  padded.resize(MAX_CLAIM_BYTES_V1, 0u8);
  Ok(padded)
}

fn pad_claims(claims: &[ClaimWitness]) -> Result<Vec<ClaimWitness>, VegaMdocError> {
  if claims.len() > MAX_CLAIMS_V1 {
    return Err(VegaMdocError::TooManyClaims {
      max: MAX_CLAIMS_V1,
      got: claims.len(),
    });
  }
  let mut padded = claims
    .iter()
    .map(|c| {
      Ok(ClaimWitness {
        issuer_signed_item_bytes: fixed_width_claim_bytes(&c.issuer_signed_item_bytes)?,
        disclose: c.disclose,
      })
    })
    .collect::<Result<Vec<_>, VegaMdocError>>()?;
  while padded.len() < MAX_CLAIMS_V1 {
    padded.push(ClaimWitness {
      issuer_signed_item_bytes: vec![0u8; MAX_CLAIM_BYTES_V1],
      disclose: false,
    });
  }
  Ok(padded)
}

/// Opaque prep state — the rerandomizable, per-credential cache that
/// `prove` reuses across presentations to different verifiers. This is
/// exactly what flows through `ZkProofSystem.priorState`/`nextState` at the
/// SDK layer (plan §Phase 3/6): serialize this out, hand it back in on the
/// next call for the same credential, and `prep_prove` is skipped.
pub struct VegaMdocPrepState(vega_prover::vega_mc_zkp::VegaMcPrepZkSNARK<Engine_>);

/// Runs `prep_prove` once for a given credential's claim set.
pub fn prep_prove(
  pk: &VegaMcProverKey<Engine_>,
  claims: &[ClaimWitness],
) -> Result<VegaMdocPrepState, VegaMdocError> {
  let padded = pad_claims(claims)?;
  let step_circuits: Vec<ClaimDigestStepCircuit<Engine_>> = padded
    .iter()
    .map(|c| ClaimDigestStepCircuit::new(c.issuer_signed_item_bytes.clone()))
    .collect();
  let core_circuit = StubCoreCircuit::<Engine_>::new();
  let prep = VegaMcZkSNARK::<Engine_>::prep_prove(pk, &step_circuits, &core_circuit, true)?;
  Ok(VegaMdocPrepState(prep))
}

/// Produces a proof, consuming and rerandomizing the prep state so it can
/// be reused for the next presentation of the same credential.
pub fn prove(
  pk: &VegaMcProverKey<Engine_>,
  claims: &[ClaimWitness],
  prep: VegaMdocPrepState,
) -> Result<(VegaMcZkSNARK<Engine_>, VegaMdocPrepState), VegaMdocError> {
  let padded = pad_claims(claims)?;
  let step_circuits: Vec<ClaimDigestStepCircuit<Engine_>> = padded
    .iter()
    .map(|c| ClaimDigestStepCircuit::new(c.issuer_signed_item_bytes.clone()))
    .collect();
  let core_circuit = StubCoreCircuit::<Engine_>::new();
  let (proof, next_prep) =
    VegaMcZkSNARK::<Engine_>::prove(pk, &step_circuits, &core_circuit, prep.0, true)?;
  Ok((proof, VegaMdocPrepState(next_prep)))
}

/// Per-step public values, and the core circuit's public values.
pub type VerifiedPublicValues = (Vec<Vec<<Engine_ as Engine>::Scalar>>, Vec<<Engine_ as Engine>::Scalar>);

/// Verifies a proof against the fixed `MAX_CLAIMS_V1` step count.
pub fn verify(
  proof: &VegaMcZkSNARK<Engine_>,
  vk: &VegaMcVerifierKey<Engine_>,
) -> Result<VerifiedPublicValues, VegaMdocError> {
  Ok(proof.verify(vk, MAX_CLAIMS_V1)?)
}

#[cfg(test)]
mod tests {
  use super::*;

  /// Phase 1 goal: the digest-matching circuit plumbing round-trips for
  /// real through setup/prep_prove/prove/verify, independent of the (not
  /// yet built) ECDSA-P256 core binding.
  #[test]
  fn round_trip_digest_only_proof() {
    let keys = setup().expect("setup");

    let claims = vec![
      ClaimWitness {
        issuer_signed_item_bytes: b"family_name:Doe".to_vec(),
        disclose: true,
      },
      ClaimWitness {
        issuer_signed_item_bytes: b"given_name:Jane".to_vec(),
        disclose: true,
      },
    ];

    let prep = prep_prove(&keys.pk, &claims).expect("prep_prove");
    let (proof, _next_prep) = prove(&keys.pk, &claims, prep).expect("prove");
    let (step_public_values, _core_public_values) = verify(&proof, &keys.vk).expect("verify");

    // Confirm the circuit is actually constraining the real digest, not
    // vacuously satisfiable: the padded claim set is [Doe, Jane, pad, pad]
    // (see `pad_claims`), so check the exposed public values for the two
    // real claims equal an independently-computed SHA-256 over their
    // (zero-padded-to-MAX_CLAIM_BYTES_V1) bytes.
    let padded = pad_claims(&claims).expect("pad_claims");
    for (step_values, claim) in step_public_values.iter().zip(padded.iter()) {
      let mut hasher = Sha256::new();
      hasher.update(&claim.issuer_signed_item_bytes);
      let expected_bits: Vec<<Engine_ as Engine>::Scalar> = hasher
        .finalize()
        .iter()
        .flat_map(|&byte| (0..8).rev().map(move |i| (byte >> i) & 1 == 1))
        .map(|b| if b { <Engine_ as Engine>::Scalar::ONE } else { <Engine_ as Engine>::Scalar::ZERO })
        .collect();
      assert_eq!(
        step_values, &expected_bits,
        "step circuit's exposed public digest must equal the real SHA-256 of its claim bytes"
      );
    }
  }
}
