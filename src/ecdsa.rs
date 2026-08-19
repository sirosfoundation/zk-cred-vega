//! In-circuit ECDSA-P256 signature verification.
//!
//! This is the piece `vega-prover` itself doesn't provide (see the crate's
//! top-level doc): given a public key `Q`, a signature `(r, s)`, and a
//! message digest `z`, constrains the standard ECDSA verification equation
//!
//!   R' = u1*G + u2*Q,  where u1 = z*s^-1 mod n,  u2 = r*s^-1 mod n
//!   accept iff R'.x mod n == r
//!
//! split across two different arithmetic domains, both provided by this
//! crate's other new modules:
//! - `u1`, `u2`, and the `s*s_inv ≡ 1 (mod n)` check are **non-native**
//!   (mod P-256's order `n`, via [`crate::nonnative::bignat`]) — `n` is not
//!   the circuit's native field.
//! - `u1*G`, `u2*Q`, and their sum are **native** point arithmetic (via
//!   [`crate::p256_ecc`]) — P-256's coordinate field *is* the circuit's
//!   native field, by construction of `vega-prover`'s P-256/T-256 cycle.
//!
//! `s_inv` (s^-1 mod n) is supplied as a prover witness hint rather than
//! computed in-circuit (inverting mod a non-native modulus would itself
//! need a `mult_mod` call to verify, which is exactly what step 1 below
//! does — computing the hint outside the circuit and checking it inside is
//! the standard pattern, not a shortcut).
//!
//! Soundness note: every raw (non-mult_mod-derived) `BigNat` witness input
//! must have [`BigNat::assert_well_formed`] called on it before use in
//! `mult_mod`/`red_mod` — those functions range-check the *outputs* they
//! allocate (quotient/remainder) but, like upstream `bellman-bignat`/Nova,
//! deliberately leave range-checking *inputs* to the caller, since an
//! input's limbs may already be known-well-formed from how it was produced
//! (e.g. `alloc_bignat_constant`, or a prior `mult_mod`/`red_mod` output).
//! Skipping this on a fresh raw input is exactly the kind of
//! under-constrained-wire bug the crate's docs already flag this gadget as
//! needing a security review for.

use crate::gadget_utils::alloc_bignat_constant;
use crate::nonnative::{bignat::BigNat, util::Num};
use crate::p256_ecc::{p256_generator, p256_order, AllocatedPoint};
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::{PrimeField, PrimeFieldBits};
use num_bigint::BigInt;

/// Limb width/count for every `BigNat` in this module. 4×64 = 256 bits,
/// matching P-256's ~256-bit order `n` exactly (see
/// [`crate::p256_ecc`]'s module doc for why `r`/`s`/`z` arithmetic needs
/// this non-native representation at all).
pub const LIMB_WIDTH: usize = 64;
/// See [`LIMB_WIDTH`].
pub const N_LIMBS: usize = 4;

/// Witness for one ECDSA-P256 verification. `qx`/`qy` are native (P-256's
/// base field *is* the circuit's native field); `r`/`s`/`z`/`s_inv` are
/// natural numbers mod `n` (P-256's order), represented as `BigInt` for
/// `BigNat` allocation.
#[derive(Clone, Debug)]
pub struct EcdsaP256Witness<Scalar: PrimeField> {
  pub qx: Scalar,
  pub qy: Scalar,
  pub r: BigInt,
  pub s: BigInt,
  pub z: BigInt,
  /// `s^-1 mod n`, computed by the prover outside the circuit (see module
  /// doc — checked, not trusted, via the `s * s_inv ≡ 1 (mod n)` constraint
  /// this gadget adds).
  pub s_inv: BigInt,
}

/// Constrains `w` to be a valid ECDSA-P256 signature. Adds no public
/// inputs of its own — callers decide which of `Q`/`r`/`s`/`z` are public
/// vs. kept private.
///
/// This is a thin wrapper around [`verify_ecdsa_p256_with_digest`] for
/// callers (e.g. Phase 2's own tests) with `z` as an ordinary native
/// witness value. `crate::mdoc_core::MdocCoreCircuit` (Phase 3) instead
/// derives `z` from an in-circuit SHA-256 over other witness data and
/// calls `verify_ecdsa_p256_with_digest` directly with that computed
/// `BigNat`, so the two share every constraint except how `z` is sourced.
pub fn verify_ecdsa_p256<Scalar, CS>(
  mut cs: CS,
  w: &EcdsaP256Witness<Scalar>,
) -> Result<(), SynthesisError>
where
  Scalar: PrimeFieldBits,
  CS: ConstraintSystem<Scalar>,
{
  let z_bn = BigNat::alloc_from_nat(
    cs.namespace(|| "z"),
    || Ok(w.z.clone()),
    LIMB_WIDTH,
    N_LIMBS,
  )?;
  z_bn.assert_well_formed(cs.namespace(|| "z well-formed"))?;

  verify_ecdsa_p256_with_digest(
    cs.namespace(|| "verify"),
    w.qx,
    w.qy,
    &w.r,
    &w.s,
    &w.s_inv,
    &z_bn,
  )
}

/// Core of [`verify_ecdsa_p256`], taking the message digest as an
/// already-allocated, already-well-formed `BigNat` rather than a native
/// witness value — see that function's doc for why.
#[allow(clippy::too_many_arguments)]
pub fn verify_ecdsa_p256_with_digest<Scalar, CS>(
  mut cs: CS,
  qx: Scalar,
  qy: Scalar,
  r: &BigInt,
  s: &BigInt,
  s_inv: &BigInt,
  z_bn: &BigNat<Scalar>,
) -> Result<(), SynthesisError>
where
  Scalar: PrimeFieldBits,
  CS: ConstraintSystem<Scalar>,
{
  let n = p256_order();

  let n_bn = alloc_bignat_constant(cs.namespace(|| "n"), &n, LIMB_WIDTH, N_LIMBS)?;
  let one_bn = alloc_bignat_constant(cs.namespace(|| "one"), &BigInt::from(1), LIMB_WIDTH, N_LIMBS)?;

  let r_bn = BigNat::alloc_from_nat(
    cs.namespace(|| "r"),
    || Ok(r.clone()),
    LIMB_WIDTH,
    N_LIMBS,
  )?;
  r_bn.assert_well_formed(cs.namespace(|| "r well-formed"))?;

  let s_bn = BigNat::alloc_from_nat(
    cs.namespace(|| "s"),
    || Ok(s.clone()),
    LIMB_WIDTH,
    N_LIMBS,
  )?;
  s_bn.assert_well_formed(cs.namespace(|| "s well-formed"))?;

  let s_inv_bn = BigNat::alloc_from_nat(
    cs.namespace(|| "s_inv"),
    || Ok(s_inv.clone()),
    LIMB_WIDTH,
    N_LIMBS,
  )?;
  s_inv_bn.assert_well_formed(cs.namespace(|| "s_inv well-formed"))?;

  // s * s_inv ≡ 1 (mod n) — binds the s_inv hint to the actual signature.
  let (_q, s_times_s_inv_mod_n) =
    s_bn.mult_mod(cs.namespace(|| "s * s_inv mod n"), &s_inv_bn, &n_bn)?;
  s_times_s_inv_mod_n
    .equal_when_carried_regroup(cs.namespace(|| "s * s_inv == 1 (mod n)"), &one_bn)?;

  // u1 = z * s_inv mod n
  let (_q, u1_bn) = z_bn.mult_mod(cs.namespace(|| "u1 = z * s_inv mod n"), &s_inv_bn, &n_bn)?;
  // u2 = r * s_inv mod n
  let (_q, u2_bn) = r_bn.mult_mod(cs.namespace(|| "u2 = r * s_inv mod n"), &s_inv_bn, &n_bn)?;

  let u1_bits = u1_bn.decompose_allocated(cs.namespace(|| "u1 bits"))?;
  let u2_bits = u2_bn.decompose_allocated(cs.namespace(|| "u2 bits"))?;

  // G, the P-256 generator, as an in-circuit constant (native arithmetic —
  // see crate::p256_ecc's module doc).
  let (gx, gy) = p256_generator::<Scalar>();
  let g_is_infinity = crate::gadget_utils::alloc_constant(cs.namespace(|| "G is_infinity"), &Scalar::ZERO)?;
  let g = AllocatedPoint::alloc_constant(cs.namespace(|| "G"), (gx, gy), g_is_infinity)?;

  // Q, the signer's public key, as a circuit witness — checked on-curve
  // rather than trusted, regardless of whether a caller treats it as
  // public or private (see module doc).
  let q = AllocatedPoint::alloc(cs.namespace(|| "Q"), Some((qx, qy, false)))?;
  q.check_on_curve(cs.namespace(|| "Q on curve"))?;

  let u1_g = g.scalar_mul(cs.namespace(|| "u1 * G"), &u1_bits)?;
  let u2_q = q.scalar_mul(cs.namespace(|| "u2 * Q"), &u2_bits)?;
  let r_point = u1_g.add(cs.namespace(|| "u1*G + u2*Q"), &u2_q)?;

  // Reduce the resulting point's (native, mod p) x-coordinate mod n, and
  // check it equals the signature's r — the actual ECDSA acceptance test.
  let x_num: AllocatedNum<Scalar> = r_point.x;
  let x_bn = BigNat::from_num(cs.namespace(|| "R'.x as BigNat"), &Num::from(x_num), LIMB_WIDTH, N_LIMBS)?;
  let x_mod_n = x_bn.red_mod(cs.namespace(|| "R'.x mod n"), &n_bn)?;
  x_mod_n.equal_when_carried_regroup(cs.namespace(|| "R'.x mod n == r"), &r_bn)?;

  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::nonnative::util::nat_to_f;
  use crate::p256_ecc::p256_order;
  use crate::Engine_;
  use bellpepper_core::test_cs::TestConstraintSystem;
  use num_bigint::{BigInt, Sign};
  use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
  use sha2::{Digest, Sha256};
  use vega_prover::traits::Engine;

  type Scalar = <Engine_ as Engine>::Scalar;

  fn bigint_to_scalar(n: &BigInt) -> Scalar {
    nat_to_f(n).expect("value fits in field")
  }

  /// Phase 2 goal: the ECDSA-P256 gadget (native point arithmetic +
  /// non-native mod-n arithmetic) constrains a REAL signature, produced by
  /// RustCrypto's independent, widely-used `p256` implementation — not a
  /// hand-rolled or self-referential test vector.
  #[test]
  fn verifies_a_real_p256_ecdsa_signature() {
    let signing_key = SigningKey::from_bytes(&[7u8; 32].into()).expect("valid scalar");
    let verifying_key = VerifyingKey::from(&signing_key);
    let message = b"zk-cred-vega ECDSA-P256 gadget test";

    let signature: Signature = signing_key.sign(message);
    let r_bytes = signature.r().to_bytes();
    let s_bytes = signature.s().to_bytes();
    let r = BigInt::from_bytes_be(Sign::Plus, &r_bytes);
    let s = BigInt::from_bytes_be(Sign::Plus, &s_bytes);

    let digest = Sha256::digest(message);
    let z = BigInt::from_bytes_be(Sign::Plus, &digest);

    let n = p256_order();
    let s_inv = s.modpow(&(n.clone() - BigInt::from(2)), &n);
    assert_eq!(
      (&s * &s_inv) % &n,
      BigInt::from(1),
      "sanity: s_inv must actually be s's inverse mod n"
    );

    let encoded = verifying_key.to_encoded_point(false);
    let qx = BigInt::from_bytes_be(Sign::Plus, encoded.x().expect("uncompressed point has x"));
    let qy = BigInt::from_bytes_be(Sign::Plus, encoded.y().expect("uncompressed point has y"));

    let witness = EcdsaP256Witness::<Scalar> {
      qx: bigint_to_scalar(&qx),
      qy: bigint_to_scalar(&qy),
      r,
      s,
      z,
      s_inv,
    };

    let mut cs = TestConstraintSystem::<Scalar>::new();
    verify_ecdsa_p256(&mut cs, &witness).expect("circuit synthesis succeeds");

    if let Some(reason) = cs.which_is_unsatisfied() {
      panic!("constraint system unsatisfied at: {reason}");
    }
    assert!(cs.is_satisfied(), "a real, valid ECDSA-P256 signature must satisfy the gadget");
  }

  /// A tampered signature (wrong `r`) must NOT satisfy the gadget — the
  /// positive test alone can't rule out a vacuously-true circuit.
  #[test]
  fn rejects_a_tampered_signature() {
    let signing_key = SigningKey::from_bytes(&[7u8; 32].into()).expect("valid scalar");
    let verifying_key = VerifyingKey::from(&signing_key);
    let message = b"zk-cred-vega ECDSA-P256 gadget test";

    let signature: Signature = signing_key.sign(message);
    let r_bytes = signature.r().to_bytes();
    let s_bytes = signature.s().to_bytes();
    let r = BigInt::from_bytes_be(Sign::Plus, &r_bytes) + BigInt::from(1); // tamper
    let s = BigInt::from_bytes_be(Sign::Plus, &s_bytes);

    let digest = Sha256::digest(message);
    let z = BigInt::from_bytes_be(Sign::Plus, &digest);

    let n = p256_order();
    let s_inv = s.modpow(&(n.clone() - BigInt::from(2)), &n);

    let encoded = verifying_key.to_encoded_point(false);
    let qx = BigInt::from_bytes_be(Sign::Plus, encoded.x().expect("uncompressed point has x"));
    let qy = BigInt::from_bytes_be(Sign::Plus, encoded.y().expect("uncompressed point has y"));

    let witness = EcdsaP256Witness::<Scalar> {
      qx: bigint_to_scalar(&qx),
      qy: bigint_to_scalar(&qy),
      r,
      s,
      z,
      s_inv,
    };

    let mut cs = TestConstraintSystem::<Scalar>::new();
    verify_ecdsa_p256(&mut cs, &witness).expect("circuit synthesis succeeds");
    assert!(!cs.is_satisfied(), "a tampered signature must NOT satisfy the gadget");
  }
}
