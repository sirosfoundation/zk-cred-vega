//! The mdoc "core" circuit: proves the issuer's ECDSA-P256 signature over
//! an MSO is valid, and binds that check to the same per-claim digests the
//! step circuits (`crate::ClaimDigestStepCircuit`) independently compute
//! and expose — without an in-circuit CBOR parser (see below for why one
//! isn't needed).
//!
//! ## Real MSO byte framing
//!
//! `z` (the ECDSA message digest) is `SHA-256` of a real `Sig_structure`
//! wrapping a real, byte-exact ISO 18013-5 `MobileSecurityObject` — see
//! `crate::mso`'s module doc for the exact byte layout and how it was
//! verified against a real signed mdoc (not a guess from the spec text
//! alone). Scope for this circuit version: one fixed `docType`, one fixed
//! namespace, exactly `MAX_CLAIMS_V1` digestIDs — see `crate::mso` for
//! what's fixed vs. witness. Still not done: `x5chain`-based `Q` +
//! trust-anchor checking (deliberately verifier-side, not this circuit's
//! job — `Q` is already exposed as a public output for exactly that).
//!
//! ## Why no CBOR parser was needed to build this
//!
//! `vega-prover`'s own paper extracts fields from a credential via a
//! *lookup argument* specifically to avoid writing an in-circuit CBOR
//! parser. This circuit sidesteps that need a different way: it does not
//! *search* a larger hidden byte blob for the `valueDigests` entries at
//! all. Instead it *assembles* (encodes) the real MSO byte string being
//! hashed, by concatenating fixed-template and witness pieces in a fixed,
//! known order (`crate::mso::alloc_sig_structure_bits`). CBOR *encoding* a
//! known structure is just ordered byte concatenation (no grammar/
//! branching to prove), unlike *decoding* an opaque blob to find where a
//! field starts. The binding to the step circuits' own digests is then
//! just an equality constraint (this circuit's witness digest bytes must
//! equal what the step circuits compute) plus normal SHA-256, both
//! already-available primitives.
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
  boolean::Boolean,
  num::AllocatedNum,
  ConstraintSystem, LinearCombination, SynthesisError,
};
use ff::PrimeFieldBits;
use num_bigint::BigInt;
use sha2::{Digest, Sha256};
use std::marker::PhantomData;
use vega_prover::traits::{circuit::VegaCircuit, Engine};

use crate::ecdsa::{LIMB_WIDTH, N_LIMBS};

/// Witness for the core circuit: the (hidden) ECDSA signature over a real
/// MSO's `Sig_structure` (see `crate::mso`), plus the (public) issuer key.
/// `claim_digests` must be in the exact same order the corresponding step
/// circuits were given theirs, and must be genuinely equal to what each
/// step circuit's own `public_values()` will expose (this circuit
/// constrains the byte assembly + SHA-256 + ECDSA check but — per the
/// module doc — the actual cross-check that these digests match the step
/// circuits' real outputs happens on the verifier side, not inside either
/// circuit).
#[derive(Clone)]
pub struct MdocCoreCircuit<Eng: Engine> {
  pub qx: Eng::Scalar,
  pub qy: Eng::Scalar,
  pub r: BigInt,
  pub s: BigInt,
  pub s_inv: BigInt,
  pub claim_digests: Vec<[u8; 32]>,
  pub mso_body: crate::mso::MsoBodyWitness,
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
    mso_body: crate::mso::MsoBodyWitness,
  ) -> Self {
    Self {
      qx,
      qy,
      r,
      s,
      s_inv,
      claim_digests,
      mso_body,
      _p: PhantomData,
    }
  }

  /// `z = SHA-256(Sig_structure)` over the real MSO byte framing — see
  /// `crate::mso`'s module doc for exactly what those bytes are and how
  /// they were verified against a real signed mdoc.
  fn native_z_bytes(&self) -> [u8; 32] {
    let sig_structure = crate::mso::native_sig_structure_bytes(&self.claim_digests, &self.mso_body);
    let mut hasher = Sha256::new();
    hasher.update(&sig_structure);
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

/// Big-endian bit expansion of `bytes`, native (not in-circuit) — used to
/// build `public_values()`'s expected output for a byte span, matching
/// the same MSB-first-per-byte convention `alloc_sig_structure_bits`
/// (and `bellpepper`'s `sha256` gadget) use.
pub(crate) fn native_bytes_to_bits<S: ff::PrimeField>(bytes: &[u8]) -> Vec<S> {
  bytes
    .iter()
    .flat_map(|&byte| (0..8).rev().map(move |i| (byte >> i) & 1 == 1))
    .map(|b| if b { S::ONE } else { S::ZERO })
    .collect()
}

/// Inputizes each bit in `bits` as its own public input (allocating a
/// `{0,1}`-constrained `AllocatedNum` per bit and asserting it equals the
/// `Boolean`) — the same per-bit pattern used repeatedly by this circuit's
/// public outputs, factored out since it's now needed for `z` and five
/// MSO-body fields.
pub(crate) fn inputize_bits<S: ff::PrimeField, CS: ConstraintSystem<S>>(
  cs: &mut CS,
  bits: &[Boolean],
  label: &str,
) -> Result<(), SynthesisError> {
  for (i, bit) in bits.iter().enumerate() {
    let value = bit.get_value().map(|b| if b { S::ONE } else { S::ZERO });
    let num = AllocatedNum::alloc(cs.namespace(|| format!("{label} bit {i} as num")), || {
      value.ok_or(SynthesisError::AssignmentMissing)
    })?;
    cs.enforce(
      || format!("{label} bit {i} matches boolean"),
      |lc| lc + &bit.lc(CS::one(), S::ONE),
      |lc| lc + CS::one(),
      |lc| lc + num.get_variable(),
    );
    num.inputize(cs.namespace(|| format!("inputize {label} bit {i}")))?;
  }
  Ok(())
}

impl<Eng: Engine> VegaCircuit<Eng> for MdocCoreCircuit<Eng>
where
  Eng::Scalar: PrimeFieldBits,
{
  fn public_values(&self) -> Result<Vec<Eng::Scalar>, SynthesisError> {
    let mut values = vec![self.qx, self.qy];
    values.extend(native_bytes_to_bits::<Eng::Scalar>(&self.native_z_bytes()));
    // Must match precommitted()'s inputize order exactly: z, then the
    // MSO-body fields — exposed so the verifier can reconstruct the full
    // Sig_structure (and thus z) from public data alone. See mdoc_core's
    // module doc and lib::verify_and_check_binding.
    values.extend(native_bytes_to_bits::<Eng::Scalar>(&self.mso_body.device_x));
    values.extend(native_bytes_to_bits::<Eng::Scalar>(&self.mso_body.device_y));
    values.extend(native_bytes_to_bits::<Eng::Scalar>(&self.mso_body.signed_ts));
    values.extend(native_bytes_to_bits::<Eng::Scalar>(&self.mso_body.valid_from_ts));
    values.extend(native_bytes_to_bits::<Eng::Scalar>(&self.mso_body.valid_until_ts));
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

    // Assemble the real MSO Sig_structure bytes (fixed template segments +
    // witness splices — see crate::mso's module doc) as a flat bit vector.
    let (mso_bits, body_bits) =
      crate::mso::alloc_sig_structure_bits(cs, &self.claim_digests, &self.mso_body)?;
    let z_bits = sha256(cs.namespace(|| "z = sha256(Sig_structure)"), &mso_bits)?;
    inputize_bits::<Eng::Scalar, CS>(cs, &z_bits, "z")?;

    // Expose the MSO-body fields too (same allocated bits already folded
    // into mso_bits/z above — not re-witnessed), in the same order
    // public_values() expects.
    inputize_bits::<Eng::Scalar, CS>(cs, &body_bits.device_x, "device_x")?;
    inputize_bits::<Eng::Scalar, CS>(cs, &body_bits.device_y, "device_y")?;
    inputize_bits::<Eng::Scalar, CS>(cs, &body_bits.signed_ts, "signed_ts")?;
    inputize_bits::<Eng::Scalar, CS>(cs, &body_bits.valid_from_ts, "valid_from_ts")?;
    inputize_bits::<Eng::Scalar, CS>(cs, &body_bits.valid_until_ts, "valid_until_ts")?;

    let z_bn = bits_be_to_bignat::<Eng::Scalar, CS>(&z_bits)?;

    verify_ecdsa_p256_with_digest(
      cs.namespace(|| "ecdsa"),
      &qx_num,
      &qy_num,
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
  use bellpepper_core::{boolean::AllocatedBit, test_cs::TestConstraintSystem};
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
    let claim_digests = vec![[0xABu8; 32], [0xCDu8; 32], [0xEFu8; 32], [0x12u8; 32]];
    let mso_body = crate::mso::MsoBodyWitness {
      device_x: [0x34u8; 32],
      device_y: [0x56u8; 32],
      signed_ts: *b"2026-08-20T00:00:00Z",
      valid_from_ts: *b"2026-08-20T00:00:00Z",
      valid_until_ts: *b"2036-08-20T00:00:00Z",
    };

    let signing_key = SigningKey::from_bytes(&[42u8; 32].into()).expect("valid scalar");
    let verifying_key = VerifyingKey::from(&signing_key);

    let sig_structure = crate::mso::native_sig_structure_bytes(&claim_digests, &mso_body);
    let z_bytes: [u8; 32] = Sha256::digest(&sig_structure).into();

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
      mso_body,
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
