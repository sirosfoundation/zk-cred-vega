//! The mdoc "core" circuit: proves the issuer's ECDSA-P256 signature over
//! an MSO is valid, and binds that check to the same per-claim digests the
//! step circuits (`crate::ClaimDigestStepCircuit`) independently compute
//! and expose — without an in-circuit CBOR parser (see below for why one
//! isn't needed).
//!
//! ## What's real here vs. a stand-in for real MSO framing
//!
//! A real ISO 18013-5 MSO is a specific CBOR structure (docType,
//! digestAlgorithm, `valueDigests` map, `validityInfo`, `deviceKeyInfo`),
//! and `issuerAuth` is a COSE_Sign1 signing a `Sig_structure` that wraps
//! it. This circuit does **not** parse or assemble that real byte layout
//! yet — `z` (the ECDSA message digest) is computed here as plain
//! `SHA-256(digest_1 || digest_2 || ... || digest_N)`, the concatenation
//! of exactly the per-claim digests the step circuits expose, in a fixed
//! order. Real MSO framing (canonical field ordering, `digestAlgorithm`,
//! `validityInfo`, `deviceKeyInfo`, the actual `Sig_structure` wrapper,
//! `x5chain`-based `Q` + trust-anchor checking) is follow-up work, not
//! done here — flagging this explicitly rather than presenting a
//! representative skeleton as the real thing.
//!
//! ## Why no CBOR parser is needed even once real framing lands
//!
//! `vega-prover`'s own paper (per this crate's Phase 0 research) extracts
//! fields from a credential via a *lookup argument* specifically to avoid
//! writing an in-circuit CBOR parser. This circuit sidesteps that need a
//! different way: it does not *search* a larger hidden byte blob for the
//! `valueDigests` entries at all. Instead it *assembles* (encodes) the
//! MSO-equivalent byte string being hashed, by concatenating witness
//! pieces in a fixed, known order — the per-claim digests (each 32
//! witness bytes) plus, when real framing lands, literal/witness bytes for
//! the other fixed-shape MSO fields. CBOR *encoding* a known structure is
//! just ordered byte concatenation (no grammar/branching to prove), unlike
//! *decoding* an opaque blob to find where a field starts. The binding to
//! the step circuits' own digests is then just an equality constraint
//! (this circuit's witness digest bytes must equal what the step circuits
//! compute) plus normal SHA-256, both already-available primitives.
//!
//! ## Where the step<->core binding is actually checked
//!
//! This circuit does **not** cross-reference the step circuits' witnesses
//! directly (`vega_mc_zkp`'s only cross-circuit channel, `shared()`, is
//! synthesized once from `step_circuits[0]` alone — awkward for binding
//! against *all* `N` steps at once). Instead, `z` is exposed as a **public
//! output** here (harmless: it reveals nothing beyond what the step
//! circuits' own exposed digests already do, since `z` is a pure function
//! of them). The verifier — outside the circuit, in ordinary Rust —
//! independently recomputes `SHA-256(step_public_values concatenated)` and
//! checks it equals this circuit's exposed `z`. See
//! `verify_and_check_binding` in `crate::lib` and its test for the
//! worked example. This is exactly the kind of "circuits prove local
//! facts, the verifier composes public outputs" pattern `vega_mc_zkp`'s
//! own `verify()` is shaped for (`step_public_values`/`core_public_values`
//! returned separately, not pre-merged).
//!
//! ## `is_small` must be `false` for this circuit
//!
//! `VegaMcZkSNARK::{prep_prove,prove}`'s `is_small: bool` parameter means
//! "do witness elements fit in machine words?" per its own doc comment.
//! `ClaimDigestStepCircuit`'s witness is 0/1 booleans only, so `is_small:
//! true` (matching `vega-prover`'s own SHA-256 bench) is correct there —
//! but this circuit's witness includes genuinely large field elements
//! (`qx`/`qy`, and internally the ECDSA gadget's `BigNat` limbs and P-256
//! point coordinates), so `is_small` must be `false` for the whole
//! `prep_prove`/`prove` call once this circuit is the core (see
//! `crate::setup`/`prep_prove`/`prove`). Getting this wrong doesn't error
//! anywhere in `setup`/`prep_prove`/`prove` — it silently produces a proof
//! that fails at `verify()` with `InvalidPCS: Inner product argument
//! verify: First equation failed`, despite every individual R1CS
//! constraint being satisfied (confirmed by isolating this circuit alone
//! with bellpepper's `TestConstraintSystem` — see this module's own
//! `core_circuit_constraints_are_satisfied_standalone` test, which passed
//! throughout the `is_small` investigation). This took an extended
//! bisection to isolate (initial theories — a step/core public-value-count
//! mismatch, sha256 constraint count, precommitted/rest proportions — were
//! all ruled out along the way by direct experiment) and isn't documented
//! anywhere in `vega-prover`'s book/spec/README as of this writing.

use crate::ecdsa::verify_ecdsa_p256_with_digest;
use crate::nonnative::bignat::{limbs_to_nat, BigNat, BigNatParams};
use bellpepper::gadgets::sha256::sha256;
use bellpepper_core::{
  boolean::{AllocatedBit, Boolean},
  num::AllocatedNum,
  ConstraintSystem, LinearCombination, SynthesisError,
};
use ff::{Field, PrimeFieldBits};
use num_bigint::BigInt;
use sha2::{Digest, Sha256};
use std::marker::PhantomData;
use vega_prover::traits::{circuit::VegaCircuit, Engine};

use crate::ecdsa::{LIMB_WIDTH, N_LIMBS};

/// Witness for the core circuit: the (hidden) ECDSA signature over the
/// (hidden) concatenation of per-claim digests, plus the (public) issuer
/// key. `claim_digests` must be in the exact same order the corresponding
/// step circuits were given theirs, and must be genuinely equal to what
/// each step circuit's own `public_values()` will expose (this circuit
/// enforces the SHA-256 composition but — per the module doc — the actual
/// cross-check that this matches the step circuits' real outputs happens
/// on the verifier side, not inside either circuit).
#[derive(Clone)]
pub struct MdocCoreCircuit<Eng: Engine> {
  pub qx: Eng::Scalar,
  pub qy: Eng::Scalar,
  pub r: BigInt,
  pub s: BigInt,
  pub s_inv: BigInt,
  pub claim_digests: Vec<[u8; 32]>,
  _p: PhantomData<Eng>,
}

impl<Eng: Engine> MdocCoreCircuit<Eng> {
  pub fn new(
    qx: Eng::Scalar,
    qy: Eng::Scalar,
    r: BigInt,
    s: BigInt,
    s_inv: BigInt,
    claim_digests: Vec<[u8; 32]>,
  ) -> Self {
    Self {
      qx,
      qy,
      r,
      s,
      s_inv,
      claim_digests,
      _p: PhantomData,
    }
  }

  /// `z = SHA-256(digest_1 || ... || digest_N)` — see module doc for why
  /// this stands in for a real MSO's `Sig_structure` digest for now.
  fn native_z_bytes(&self) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for d in &self.claim_digests {
      hasher.update(d);
    }
    hasher.finalize().into()
  }
}

/// Packs 256 big-endian bits (bit 0 = MSB of the overall value — the
/// convention `bellpepper::gadgets::sha256::sha256` returns) into a
/// `BigNat` using this crate's usual little-endian, 64-bit-limb
/// convention ([`LIMB_WIDTH`]/[`N_LIMBS`]). `limb[k]`'s bit `j` (LSB-first
/// within the limb) is the overall value's bit `64*k + j` (from the LSB),
/// which is `bits[255 - 64*k - j]` in the big-endian input.
fn bits_be_to_bignat<Scalar: PrimeFieldBits, CS: ConstraintSystem<Scalar>>(
  bits: &[Boolean],
) -> Result<BigNat<Scalar>, SynthesisError> {
  assert_eq!(bits.len(), N_LIMBS * LIMB_WIDTH);

  let mut limbs = Vec::with_capacity(N_LIMBS);
  let mut limb_values: Option<Vec<Scalar>> = Some(Vec::with_capacity(N_LIMBS));

  for k in 0..N_LIMBS {
    let mut lc = LinearCombination::zero();
    let mut coeff = Scalar::ONE;
    let mut value = Some(Scalar::ZERO);
    for j in 0..LIMB_WIDTH {
      let bit = &bits[255 - 64 * k - j];
      lc = lc + &bit.lc(CS::one(), coeff);
      value = match (value, bit.get_value()) {
        (Some(v), Some(true)) => Some(v + coeff),
        (Some(v), Some(false)) => Some(v),
        _ => None,
      };
      coeff = coeff.double();
    }
    limbs.push(lc);
    limb_values = match (limb_values, value) {
      (Some(mut vs), Some(v)) => {
        vs.push(v);
        Some(vs)
      }
      _ => None,
    };
  }

  let value = limb_values
    .as_ref()
    .map(|vs| limbs_to_nat::<Scalar, _, _>(vs.iter(), LIMB_WIDTH));

  Ok(BigNat {
    limbs,
    limb_values,
    value,
    params: BigNatParams::new(LIMB_WIDTH, N_LIMBS),
  })
}

impl<Eng: Engine> VegaCircuit<Eng> for MdocCoreCircuit<Eng>
where
  Eng::Scalar: PrimeFieldBits,
{
  fn public_values(&self) -> Result<Vec<Eng::Scalar>, SynthesisError> {
    let mut values = vec![self.qx, self.qy];
    let z_bytes = self.native_z_bytes();
    values.extend(z_bytes.iter().flat_map(|&byte| {
      (0..8)
        .rev()
        .map(move |i| if (byte >> i) & 1 == 1 { Eng::Scalar::ONE } else { Eng::Scalar::ZERO })
    }));
    Ok(values)
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
    // qx, qy as public inputs.
    let qx_num = AllocatedNum::alloc(cs.namespace(|| "qx"), || Ok(self.qx))?;
    qx_num.inputize(cs.namespace(|| "inputize qx"))?;
    let qy_num = AllocatedNum::alloc(cs.namespace(|| "qy"), || Ok(self.qy))?;
    qy_num.inputize(cs.namespace(|| "inputize qy"))?;

    // Witness each claim digest's 256 bits (big-endian, matching the step
    // circuits' own sha256 gadget output convention) and concatenate.
    let mut concatenated = Vec::with_capacity(self.claim_digests.len() * 256);
    for (ci, digest) in self.claim_digests.iter().enumerate() {
      for (bi, byte) in digest.iter().enumerate() {
        for i in (0..8).rev() {
          let bit_value = (byte >> i) & 1 == 1;
          let bit = AllocatedBit::alloc(
            cs.namespace(|| format!("claim {ci} byte {bi} bit {i}")),
            Some(bit_value),
          )?;
          concatenated.push(Boolean::from(bit));
        }
      }
    }

    let z_bits = sha256(cs.namespace(|| "z = sha256(claim digests)"), &concatenated)?;
    for (i, bit) in z_bits.iter().enumerate() {
      let value = bit.get_value().map(|b| if b { Eng::Scalar::ONE } else { Eng::Scalar::ZERO });
      let num = AllocatedNum::alloc(cs.namespace(|| format!("z bit {i} as num")), || {
        value.ok_or(SynthesisError::AssignmentMissing)
      })?;
      cs.enforce(
        || format!("z bit {i} matches boolean"),
        |lc| lc + &bit.lc(CS::one(), Eng::Scalar::ONE),
        |lc| lc + CS::one(),
        |lc| lc + num.get_variable(),
      );
      num.inputize(cs.namespace(|| format!("inputize z bit {i}")))?;
    }

    let z_bn = bits_be_to_bignat::<Eng::Scalar, CS>(&z_bits)?;

    verify_ecdsa_p256_with_digest(
      cs.namespace(|| "ecdsa"),
      self.qx,
      self.qy,
      &self.r,
      &self.s,
      &self.s_inv,
      &z_bn,
    )?;

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

#[cfg(test)]
mod tests {
  use super::*;
  use crate::nonnative::util::nat_to_f;
  use crate::p256_ecc::p256_order;
  use crate::Engine_;
  use bellpepper_core::test_cs::TestConstraintSystem;
  use num_bigint::Sign;
  use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey, VerifyingKey};

  /// Isolates `bits_be_to_bignat` from everything else: hash a known
  /// message via the real `sha256` gadget, pack the output bits into a
  /// `BigNat`, and compare its native `.value` against an
  /// independently-computed `BigInt::from_bytes_be` of the same hash.
  #[test]
  fn bits_be_to_bignat_matches_native_digest() {
    type Scalar = <Engine_ as Engine>::Scalar;
    let message = b"abc";
    let expected = Sha256::digest(message);
    let expected_int = BigInt::from_bytes_be(Sign::Plus, &expected);

    let mut cs = TestConstraintSystem::<Scalar>::new();
    let input_bits: Vec<Boolean> = message
      .iter()
      .flat_map(|byte| (0..8).rev().map(move |i| (byte >> i) & 1u8 == 1u8))
      .enumerate()
      .map(|(i, b)| {
        AllocatedBit::alloc(cs.namespace(|| format!("bit {i}")), Some(b)).map(Boolean::from)
      })
      .collect::<Result<Vec<_>, _>>()
      .unwrap();
    let z_bits = sha256(cs.namespace(|| "sha256"), &input_bits).unwrap();
    let z_bn = bits_be_to_bignat::<Scalar, TestConstraintSystem<Scalar>>(&z_bits).unwrap();

    assert_eq!(
      z_bn.value.expect("value known"),
      expected_int,
      "bits_be_to_bignat must reconstruct the same integer as BigInt::from_bytes_be of the real digest"
    );
  }

  /// Diagnostic: exercises `MdocCoreCircuit`'s own constraints directly via
  /// `TestConstraintSystem` (bypassing `vega_mc_zkp`'s full NeutronNova
  /// setup/prep_prove/prove/verify pipeline entirely), so a bug here is
  /// fast to isolate from a bug in the fold-and-reuse plumbing above it.
  #[test]
  fn core_circuit_constraints_are_satisfied_standalone() {
    let claim_digests = vec![[0xABu8; 32], [0xCDu8; 32]];

    let signing_key = SigningKey::from_bytes(&[42u8; 32].into()).expect("valid scalar");
    let verifying_key = VerifyingKey::from(&signing_key);

    let mut hasher = Sha256::new();
    for d in &claim_digests {
      hasher.update(d);
    }
    let z_bytes: [u8; 32] = hasher.finalize().into();

    let signature: Signature = signing_key.sign_prehash(&z_bytes).expect("sign_prehash");
    let r = BigInt::from_bytes_be(Sign::Plus, &signature.r().to_bytes());
    let s = BigInt::from_bytes_be(Sign::Plus, &signature.s().to_bytes());
    let n = p256_order();
    let s_inv = s.modpow(&(n.clone() - BigInt::from(2)), &n);

    let encoded = verifying_key.to_encoded_point(false);
    let qx = BigInt::from_bytes_be(Sign::Plus, encoded.x().unwrap());
    let qy = BigInt::from_bytes_be(Sign::Plus, encoded.y().unwrap());

    type Scalar = <Engine_ as Engine>::Scalar;
    let circuit = MdocCoreCircuit::<Engine_>::new(
      nat_to_f::<Scalar>(&qx).unwrap(),
      nat_to_f::<Scalar>(&qy).unwrap(),
      r,
      s,
      s_inv,
      claim_digests,
    );

    let mut cs = TestConstraintSystem::<Scalar>::new();
    let shared = circuit.shared(&mut cs).expect("shared");
    let precommitted = circuit.precommitted(&mut cs, &shared).expect("precommitted");
    circuit
      .synthesize(&mut cs, &shared, &precommitted, None)
      .expect("synthesize");

    if let Some(reason) = cs.which_is_unsatisfied() {
      panic!("constraint system unsatisfied at: {reason}");
    }
    assert!(cs.is_satisfied());
  }
}
