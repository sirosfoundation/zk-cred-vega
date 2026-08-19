//! zk-cred-vega: mdoc selective-disclosure circuits built on top of
//! Microsoft's `vega-prover` ZK engine (https://github.com/microsoft/vega-prover).
//!
//! `vega-prover` supplies the proving system (NeutronNova-folding Spartan
//! over R1CS, no trusted setup) but has zero credential-specific code. This
//! crate supplies the mdoc-shaped circuit and the mobile-facing API on top
//! of it: one `VegaCircuit` "step" per disclosed/checked mdoc element
//! (`ClaimDigestStepCircuit`, this file), verifying its SHA-256 digest, and
//! one "core" circuit (`mdoc_core::MdocCoreCircuit`) proving a real
//! ECDSA-P256 signature over those digests, folded together via
//! `vega_mc_zkp`. See `HANDOFF.md` for full status against the tracked
//! plan (real MSO byte framing and a security review are still open) and
//! `ffi_api` for the UniFFI-exported surface consumed by the native SDKs.

pub mod ecdsa;
#[cfg(feature = "uniffi")]
pub mod ffi_api;
pub mod gadget_utils;
pub mod mdoc_core;
pub mod nonnative;
pub mod p256_ecc;

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

use bellpepper::gadgets::sha256::sha256;
use bellpepper_core::{
  ConstraintSystem, SynthesisError,
  boolean::{AllocatedBit, Boolean},
  num::AllocatedNum,
};
use ff::{Field, PrimeFieldBits};
use mdoc_core::MdocCoreCircuit;
use num_bigint::BigInt;
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
/// is the core circuit's job (`MdocCoreCircuit`) — this keeps the
/// expensive per-claim SHA-256 work foldable across steps rather than
/// repeated in the core circuit.
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

/// The ECDSA-P256 signature + issuer-key half of a presentation's witness
/// (see `mdoc_core::MdocCoreCircuit`) — everything the core circuit needs
/// beyond the per-claim digests already carried by `ClaimWitness`.
#[derive(Clone, Debug)]
pub struct MdocEcdsaWitness {
  pub qx: <Engine_ as Engine>::Scalar,
  pub qy: <Engine_ as Engine>::Scalar,
  pub r: BigInt,
  pub s: BigInt,
  pub s_inv: BigInt,
}

/// A real, valid P-256 ECDSA signature over
/// `SHA-256([0u8; 32] repeated MAX_CLAIMS_V1 times)` — i.e. genuinely
/// satisfying the ECDSA relation for exactly the `z` that
/// `MdocCoreCircuit::native_z_bytes` computes for setup's own all-zero
/// `claim_digests` prototype below — generated once via RustCrypto's
/// `p256` crate and frozen here as constants. Used only as [`setup`]'s
/// prototype circuit witness.
///
/// Genuinely satisfying the relation (not just "non-degenerate") matters:
/// an internally-inconsistent prototype (valid-looking scalars that don't
/// actually satisfy the signed relation) was tried first and produced a
/// setup whose real proofs failed PCS verification (`InvalidPCS: Inner
/// product argument verify: First equation failed`) despite the same
/// proofs' own R1CS constraints being individually satisfied — i.e. an
/// unsatisfiable *prototype* witness can still poison the derived prover
/// key in a way that doesn't surface until a real `verify()` call, not at
/// `setup()` itself. Don't assume "any non-degenerate values work here"
/// without a real round-trip test backing it, per this crate's own
/// `full_presentation_verifies_and_binds` test.
fn setup_prototype_ecdsa_witness() -> MdocEcdsaWitness {
  use crate::nonnative::util::nat_to_f;
  let parse = |s: &str| s.parse::<BigInt>().expect("valid decimal constant");
  MdocEcdsaWitness {
    qx: nat_to_f(&parse(
      "51206722373641483558790322998827362250192835690568432297698399643535245670501",
    ))
    .unwrap(),
    qy: nat_to_f(&parse(
      "107332639522564059748513735225121084070027309383763098932131650999881938986788",
    ))
    .unwrap(),
    r: parse("34158886365188924995576805369414955546695446637758572275049680737384481638550"),
    s: parse("50742202422105296391539965653035028790698587237099104849136725216325886541360"),
    s_inv: parse(
      "96193774504579357202359351098485493149433497819343073080230082391271389319288",
    ),
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
  let w = setup_prototype_ecdsa_witness();
  let core_proto = MdocCoreCircuit::<Engine_>::new(
    w.qx,
    w.qy,
    w.r,
    w.s,
    w.s_inv,
    vec![[0u8; 32]; MAX_CLAIMS_V1],
  );
  let (pk, vk) = VegaMcZkSNARK::<Engine_>::setup(&step_proto, &core_proto, MAX_CLAIMS_V1)?;
  Ok(VegaMdocKeys { pk, vk })
}

/// SHA-256 of `bytes`, as a `[u8; 32]` — the same digest a
/// [`ClaimDigestStepCircuit`] over the same bytes exposes (bit-for-bit,
/// modulo the bits-vs-bytes representation), used to build the core
/// circuit's `claim_digests` witness so the two actually agree.
fn claim_digest_bytes(bytes: &[u8]) -> [u8; 32] {
  let mut hasher = Sha256::new();
  hasher.update(bytes);
  hasher.finalize().into()
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

impl VegaMdocPrepState {
  /// Unwraps to the inner `vega-prover` type — used by `ffi_api` to
  /// (de)serialize the prep state to bytes for `ZkProofSystem`'s
  /// `priorState`/`nextState` fields.
  pub fn into_inner(self) -> vega_prover::vega_mc_zkp::VegaMcPrepZkSNARK<Engine_> {
    self.0
  }

  /// See [`Self::into_inner`].
  pub fn from_inner(inner: vega_prover::vega_mc_zkp::VegaMcPrepZkSNARK<Engine_>) -> Self {
    Self(inner)
  }
}

/// Builds the core circuit's `claim_digests` witness from a (pre-padding)
/// claim set, in the same padded order `prep_prove`/`prove` use for the
/// step circuits — the two must agree for `verify_and_check_binding` to
/// pass.
pub(crate) fn core_claim_digests(claims: &[ClaimWitness]) -> Result<Vec<[u8; 32]>, VegaMdocError> {
  let padded = pad_claims(claims)?;
  Ok(
    padded
      .iter()
      .map(|c| claim_digest_bytes(&c.issuer_signed_item_bytes))
      .collect(),
  )
}

/// Runs `prep_prove` once for a given credential's claim set and ECDSA
/// witness.
pub fn prep_prove(
  pk: &VegaMcProverKey<Engine_>,
  claims: &[ClaimWitness],
  ecdsa_witness: &MdocEcdsaWitness,
) -> Result<VegaMdocPrepState, VegaMdocError> {
  let padded = pad_claims(claims)?;
  let step_circuits: Vec<ClaimDigestStepCircuit<Engine_>> = padded
    .iter()
    .map(|c| ClaimDigestStepCircuit::new(c.issuer_signed_item_bytes.clone()))
    .collect();
  let core_circuit = MdocCoreCircuit::<Engine_>::new(
    ecdsa_witness.qx,
    ecdsa_witness.qy,
    ecdsa_witness.r.clone(),
    ecdsa_witness.s.clone(),
    ecdsa_witness.s_inv.clone(),
    core_claim_digests(claims)?,
  );
  let prep = VegaMcZkSNARK::<Engine_>::prep_prove(pk, &step_circuits, &core_circuit, false)?;
  Ok(VegaMdocPrepState(prep))
}

/// Produces a proof, consuming and rerandomizing the prep state so it can
/// be reused for the next presentation of the same credential.
pub fn prove(
  pk: &VegaMcProverKey<Engine_>,
  claims: &[ClaimWitness],
  ecdsa_witness: &MdocEcdsaWitness,
  prep: VegaMdocPrepState,
) -> Result<(VegaMcZkSNARK<Engine_>, VegaMdocPrepState), VegaMdocError> {
  let padded = pad_claims(claims)?;
  let step_circuits: Vec<ClaimDigestStepCircuit<Engine_>> = padded
    .iter()
    .map(|c| ClaimDigestStepCircuit::new(c.issuer_signed_item_bytes.clone()))
    .collect();
  let core_circuit = MdocCoreCircuit::<Engine_>::new(
    ecdsa_witness.qx,
    ecdsa_witness.qy,
    ecdsa_witness.r.clone(),
    ecdsa_witness.s.clone(),
    ecdsa_witness.s_inv.clone(),
    core_claim_digests(claims)?,
  );
  let (proof, next_prep) =
    VegaMcZkSNARK::<Engine_>::prove(pk, &step_circuits, &core_circuit, prep.0, false)?;
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

/// The step<->core binding check `mdoc_core`'s module doc describes: given
/// `verify`'s two outputs, confirms the core circuit's exposed ECDSA
/// message digest `z` actually equals `SHA-256` of the step circuits'
/// exposed digests concatenated in order. This is the check that gives
/// "the ECDSA signature core proved is valid" and "these are the digests
/// step proved" any actual connection to each other — without it, a
/// prover could mix a valid core proof for one claim set with valid step
/// proofs for a *different* one. Returns the parsed `(qx, qy)` public key
/// on success, since a caller will need it (e.g. to check `Q` against a
/// trust anchor) once framing is real (see `mdoc_core`'s module doc).
pub fn verify_and_check_binding(
  step_public_values: &[Vec<<Engine_ as Engine>::Scalar>],
  core_public_values: &[<Engine_ as Engine>::Scalar],
) -> Result<(<Engine_ as Engine>::Scalar, <Engine_ as Engine>::Scalar), VegaMdocError> {
  if core_public_values.len() != 2 + 256 {
    return Err(VegaMdocError::Circuit(SynthesisError::Unsatisfiable));
  }
  let qx = core_public_values[0];
  let qy = core_public_values[1];
  let core_z_bits = &core_public_values[2..2 + 256];

  let mut hasher = Sha256::new();
  for step_values in step_public_values {
    for byte_bits in step_values.chunks(8) {
      let mut byte = 0u8;
      for (i, bit) in byte_bits.iter().enumerate() {
        if *bit == <Engine_ as Engine>::Scalar::ONE {
          byte |= 1 << (7 - i);
        }
      }
      hasher.update([byte]);
    }
  }
  let expected_z_bytes: [u8; 32] = hasher.finalize().into();
  let expected_z_bits: Vec<<Engine_ as Engine>::Scalar> = expected_z_bytes
    .iter()
    .flat_map(|&byte| (0..8).rev().map(move |i| (byte >> i) & 1 == 1))
    .map(|b| if b { <Engine_ as Engine>::Scalar::ONE } else { <Engine_ as Engine>::Scalar::ZERO })
    .collect();

  if core_z_bits != expected_z_bits.as_slice() {
    return Err(VegaMdocError::Circuit(SynthesisError::Unsatisfiable));
  }

  Ok((qx, qy))
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::nonnative::util::nat_to_f;
  use crate::p256_ecc::p256_order;
  use num_bigint::Sign;
  use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey, VerifyingKey};

  /// Signs `SHA-256(claim_digests concatenated)` — matching
  /// `MdocCoreCircuit`'s own `native_z_bytes` exactly — with a fresh real
  /// P-256 key, and returns the resulting `MdocEcdsaWitness`.
  fn real_ecdsa_witness_over(claim_digests: &[[u8; 32]]) -> MdocEcdsaWitness {
    let signing_key = SigningKey::from_bytes(&[42u8; 32].into()).expect("valid scalar");
    let verifying_key = VerifyingKey::from(&signing_key);

    let mut hasher = Sha256::new();
    for d in claim_digests {
      hasher.update(d);
    }
    let z_bytes: [u8; 32] = hasher.finalize().into();

    let signature: Signature = signing_key.sign_prehash(&z_bytes).expect("sign_prehash");
    let r = BigInt::from_bytes_be(Sign::Plus, &signature.r().to_bytes());
    let s = BigInt::from_bytes_be(Sign::Plus, &signature.s().to_bytes());

    let n = p256_order();
    let s_inv = s.modpow(&(n.clone() - BigInt::from(2)), &n);

    let encoded = verifying_key.to_encoded_point(false);
    let qx = BigInt::from_bytes_be(Sign::Plus, encoded.x().expect("uncompressed x"));
    let qy = BigInt::from_bytes_be(Sign::Plus, encoded.y().expect("uncompressed y"));

    MdocEcdsaWitness {
      qx: nat_to_f(&qx).unwrap(),
      qy: nat_to_f(&qy).unwrap(),
      r,
      s,
      s_inv,
    }
  }

  fn expected_step_digest_bits(bytes: &[u8]) -> Vec<<Engine_ as Engine>::Scalar> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
      .finalize()
      .iter()
      .flat_map(|&byte| (0..8).rev().map(move |i| (byte >> i) & 1 == 1))
      .map(|b| if b { <Engine_ as Engine>::Scalar::ONE } else { <Engine_ as Engine>::Scalar::ZERO })
      .collect()
  }

  /// Note important for anyone signing the ECDSA verification path itself
  /// (independent of the mdoc-specific tests below): the P256 ECDSA
  /// gadget's own correctness is exercised directly in `ecdsa::tests`
  /// against RustCrypto vectors — these tests instead exercise the
  /// *composition*: real digests really flowing from the step circuits
  /// into the core circuit's signed message.
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
    let claim_digests = core_claim_digests(&claims).expect("core_claim_digests");
    let ecdsa_witness = real_ecdsa_witness_over(&claim_digests);

    let prep = prep_prove(&keys.pk, &claims, &ecdsa_witness).expect("prep_prove");
    let (proof, _next_prep) = prove(&keys.pk, &claims, &ecdsa_witness, prep).expect("prove");
    let (step_public_values, _core_public_values) = verify(&proof, &keys.vk).expect("verify");

    // Confirm the circuit is actually constraining the real digest, not
    // vacuously satisfiable: the padded claim set is [Doe, Jane, pad, pad]
    // (see `pad_claims`), so check the exposed public values for the two
    // real claims equal an independently-computed SHA-256 over their
    // (zero-padded-to-MAX_CLAIM_BYTES_V1) bytes.
    let padded = pad_claims(&claims).expect("pad_claims");
    for (step_values, claim) in step_public_values.iter().zip(padded.iter()) {
      assert_eq!(
        step_values,
        &expected_step_digest_bits(&claim.issuer_signed_item_bytes),
        "step circuit's exposed public digest must equal the real SHA-256 of its claim bytes"
      );
    }
  }

  /// Phase 3 goal: a full presentation — real per-claim digests (step
  /// circuits) *and* a real ECDSA-P256 signature genuinely computed over
  /// those exact digests (core circuit) — round-trips through
  /// setup/prep_prove/prove/verify, AND the verifier-side binding check
  /// (`verify_and_check_binding`) confirms the two halves actually agree.
  #[test]
  fn full_presentation_verifies_and_binds() {
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
      ClaimWitness {
        issuer_signed_item_bytes: b"age_over_18:true".to_vec(),
        disclose: true,
      },
    ];
    let claim_digests = core_claim_digests(&claims).expect("core_claim_digests");
    let ecdsa_witness = real_ecdsa_witness_over(&claim_digests);

    let prep = prep_prove(&keys.pk, &claims, &ecdsa_witness).expect("prep_prove");
    let (proof, next_prep) = prove(&keys.pk, &claims, &ecdsa_witness, prep).expect("prove");
    let (step_public_values, core_public_values) = verify(&proof, &keys.vk).expect("verify");

    let (qx, qy) = verify_and_check_binding(&step_public_values, &core_public_values)
      .expect("binding check must pass for a genuinely-matching signature+digests");
    assert_eq!(qx, ecdsa_witness.qx);
    assert_eq!(qy, ecdsa_witness.qy);

    // The fold-and-reuse prep state must also work for a second
    // presentation of the same credential (a different verifier, say) —
    // exercising `nextState`'s round-trip, not just a single `prove` call.
    let (proof2, _next_prep2) =
      prove(&keys.pk, &claims, &ecdsa_witness, next_prep).expect("second prove reusing prep state");
    let (step_public_values2, core_public_values2) = verify(&proof2, &keys.vk).expect("verify 2");
    verify_and_check_binding(&step_public_values2, &core_public_values2)
      .expect("binding check must also pass for the reused-prep-state proof");
  }

  /// The negative case `mdoc_core`'s module doc calls out explicitly:
  /// a core proof that's individually valid (real signature over *some*
  /// digests) must NOT bind against a step proof over *different* claims.
  ///
  /// This can't be expressed through `prep_prove`/`prove` (this crate's
  /// own wrapper functions always build the core circuit's digests from
  /// the same `claims` used for the step circuits — see
  /// `core_claim_digests`), so it drives `VegaMcZkSNARK` directly: step
  /// circuits genuinely, self-consistently prove `real_claims`; the core
  /// circuit genuinely, self-consistently signs `other_claims`' digests.
  /// Both circuits are individually valid (so `verify()` itself succeeds)
  /// — only `verify_and_check_binding`'s cross-circuit check should catch
  /// the mismatch.
  #[test]
  fn binding_check_rejects_mismatched_claims() {
    let keys = setup().expect("setup");

    let real_claims = vec![ClaimWitness {
      issuer_signed_item_bytes: b"family_name:Doe".to_vec(),
      disclose: true,
    }];
    let other_claims = vec![ClaimWitness {
      issuer_signed_item_bytes: b"family_name:Smith".to_vec(),
      disclose: true,
    }];

    let padded = pad_claims(&real_claims).expect("pad_claims");
    let step_circuits: Vec<ClaimDigestStepCircuit<Engine_>> = padded
      .iter()
      .map(|c| ClaimDigestStepCircuit::new(c.issuer_signed_item_bytes.clone()))
      .collect();

    let mismatched_digests = core_claim_digests(&other_claims).expect("core_claim_digests");
    let ecdsa_witness = real_ecdsa_witness_over(&mismatched_digests);
    let core_circuit = MdocCoreCircuit::<Engine_>::new(
      ecdsa_witness.qx,
      ecdsa_witness.qy,
      ecdsa_witness.r,
      ecdsa_witness.s,
      ecdsa_witness.s_inv,
      mismatched_digests,
    );

    let prep = VegaMcZkSNARK::<Engine_>::prep_prove(&keys.pk, &step_circuits, &core_circuit, false)
      .expect("prep_prove");
    let (proof, _next_prep) =
      VegaMcZkSNARK::<Engine_>::prove(&keys.pk, &step_circuits, &core_circuit, prep, false)
        .expect("prove");
    let (step_public_values, core_public_values) =
      proof.verify(&keys.vk, MAX_CLAIMS_V1).expect("verify");

    assert!(
      verify_and_check_binding(&step_public_values, &core_public_values).is_err(),
      "a proof whose core circuit signs different claims than its step circuits disclose must fail the binding check"
    );
  }
}
