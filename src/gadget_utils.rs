//! Low-level circuit helpers, ported from `microsoft/Nova`'s
//! `src/gadgets/utils.rs` (MIT), trimmed to what `p256_ecc`/`ecdsa`
//! actually use. Dropped: `fingerprint`/`le_bits_to_num`/`le_num_to_num`/
//! `base_as_bigint`/`alloc_scalar_as_base`/`scalar_as_base`/`base_as_scalar`
//! (Nova's own IVC-recursion/random-oracle helpers, unused here) — kept
//! `field_switch` alone from that family, since we do need it once, outside
//! any circuit, to carry P-256's own (A, B) curve constants (native to
//! `p256::Base`) over into our circuit's native field `Eng::Scalar`
//! (`t256::Scalar`), which the P-256/T-256 2-cycle guarantees are the same
//! field under a different `halo2curves` type — see `p256_ecc`'s module doc.

use crate::nonnative::bignat::{nat_to_limbs, BigNat};
use bellpepper_core::{boolean::Boolean, num::AllocatedNum, ConstraintSystem, SynthesisError};
use bellpepper::gadgets::Assignment;
use ff::{PrimeField, PrimeFieldBits};
use num_bigint::BigInt;

/// Allocate a variable that is set to zero
pub fn alloc_zero<F: PrimeField, CS: ConstraintSystem<F>>(mut cs: CS) -> AllocatedNum<F> {
  let zero = AllocatedNum::alloc_infallible(cs.namespace(|| "alloc"), || F::ZERO);
  cs.enforce(
    || "check zero is valid",
    |lc| lc,
    |lc| lc,
    |lc| lc + zero.get_variable(),
  );
  zero
}

/// Convert a field element of one prime field into another, via its bit
/// decomposition. Valid only when the source value actually fits in the
/// destination field (true here: both fields have the same modulus, by
/// construction of the P-256/T-256 2-cycle).
pub fn field_switch<F1: PrimeField + PrimeFieldBits, F2: PrimeField>(x: F1) -> F2 {
  let input_bits = x.to_le_bits();
  let mut mult = F2::ONE;
  let mut val = F2::ZERO;
  for bit in input_bits {
    if bit {
      val += mult;
    }
    mult += mult;
  }
  val
}

/// Allocate a bignat as a constant
pub fn alloc_bignat_constant<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  val: &BigInt,
  limb_width: usize,
  n_limbs: usize,
) -> Result<BigNat<F>, SynthesisError> {
  let limbs = nat_to_limbs(val, limb_width, n_limbs).unwrap();
  let bignat = BigNat::alloc_from_limbs(
    cs.namespace(|| "alloc bignat"),
    || Ok(limbs.clone()),
    None,
    limb_width,
    n_limbs,
  )?;
  (0..n_limbs).for_each(|i| {
    cs.enforce(
      || format!("check limb {i}"),
      |lc| lc + &bignat.limbs[i],
      |lc| lc + CS::one(),
      |lc| lc + (limbs[i], CS::one()),
    );
  });
  Ok(bignat)
}

/// Check that two numbers are equal and return a bit
pub fn alloc_num_equals<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  b: &AllocatedNum<F>,
) -> Result<bellpepper_core::boolean::AllocatedBit, SynthesisError> {
  use bellpepper_core::boolean::AllocatedBit;

  let r_value = match (a.get_value(), b.get_value()) {
    (Some(a), Some(b)) => Some(a == b),
    _ => None,
  };

  let r = AllocatedBit::alloc(cs.namespace(|| "r"), r_value)?;

  let t = AllocatedNum::alloc(cs.namespace(|| "t"), || {
    Ok(if *a.get_value().get()? == *b.get_value().get()? {
      F::ONE
    } else {
      (*a.get_value().get()? - *b.get_value().get()?)
        .invert()
        .unwrap()
    })
  })?;

  cs.enforce(
    || "t*(a - b) = 1 - r",
    |lc| lc + t.get_variable(),
    |lc| lc + a.get_variable() - b.get_variable(),
    |lc| lc + CS::one() - r.get_variable(),
  );

  cs.enforce(
    || "r*(a - b) = 0",
    |lc| lc + r.get_variable(),
    |lc| lc + a.get_variable() - b.get_variable(),
    |lc| lc,
  );

  Ok(r)
}

/// If condition return a otherwise b
pub fn conditionally_select<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  b: &AllocatedNum<F>,
  condition: &Boolean,
) -> Result<AllocatedNum<F>, SynthesisError> {
  let c = AllocatedNum::alloc(cs.namespace(|| "conditional select result"), || {
    if *condition.get_value().get()? {
      Ok(*a.get_value().get()?)
    } else {
      Ok(*b.get_value().get()?)
    }
  })?;

  cs.enforce(
    || "conditional select constraint",
    |lc| lc + a.get_variable() - b.get_variable(),
    |_| condition.lc(CS::one(), F::ONE),
    |lc| lc + c.get_variable() - b.get_variable(),
  );

  Ok(c)
}

/// If condition (an `AllocatedNum` constrained to {0,1}) return a otherwise b
pub fn conditionally_select2<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  b: &AllocatedNum<F>,
  condition: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError> {
  let c = AllocatedNum::alloc(cs.namespace(|| "conditional select result"), || {
    if *condition.get_value().get()? == F::ONE {
      Ok(*a.get_value().get()?)
    } else {
      Ok(*b.get_value().get()?)
    }
  })?;

  cs.enforce(
    || "conditional select constraint",
    |lc| lc + a.get_variable() - b.get_variable(),
    |lc| lc + condition.get_variable(),
    |lc| lc + c.get_variable() - b.get_variable(),
  );

  Ok(c)
}

/// If condition set to 0 otherwise a. Condition is an allocated num
pub fn select_zero_or_num2<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  condition: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError> {
  let c = AllocatedNum::alloc(cs.namespace(|| "conditional select result"), || {
    if *condition.get_value().get()? == F::ONE {
      Ok(F::ZERO)
    } else {
      Ok(*a.get_value().get()?)
    }
  })?;

  cs.enforce(
    || "conditional select constraint",
    |lc| lc + a.get_variable(),
    |lc| lc + CS::one() - condition.get_variable(),
    |lc| lc + c.get_variable(),
  );

  Ok(c)
}

/// If condition set to a otherwise 0. Condition is an allocated num
pub fn select_num_or_zero2<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  condition: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError> {
  let c = AllocatedNum::alloc(cs.namespace(|| "conditional select result"), || {
    if *condition.get_value().get()? == F::ONE {
      Ok(*a.get_value().get()?)
    } else {
      Ok(F::ZERO)
    }
  })?;

  cs.enforce(
    || "conditional select constraint",
    |lc| lc + a.get_variable(),
    |lc| lc + condition.get_variable(),
    |lc| lc + c.get_variable(),
  );

  Ok(c)
}

/// If condition set to a otherwise 0
pub fn select_num_or_zero<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  condition: &Boolean,
) -> Result<AllocatedNum<F>, SynthesisError> {
  let c = AllocatedNum::alloc(cs.namespace(|| "conditional select result"), || {
    if *condition.get_value().get()? {
      Ok(*a.get_value().get()?)
    } else {
      Ok(F::ZERO)
    }
  })?;

  cs.enforce(
    || "conditional select constraint",
    |lc| lc + a.get_variable(),
    |_| condition.lc(CS::one(), F::ONE),
    |lc| lc + c.get_variable(),
  );

  Ok(c)
}

/// If condition set to 1 otherwise a
pub fn select_one_or_num2<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  condition: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError> {
  let c = AllocatedNum::alloc(cs.namespace(|| "conditional select result"), || {
    if *condition.get_value().get()? == F::ONE {
      Ok(F::ONE)
    } else {
      Ok(*a.get_value().get()?)
    }
  })?;

  cs.enforce(
    || "conditional select constraint",
    |lc| lc + CS::one() - a.get_variable(),
    |lc| lc + condition.get_variable(),
    |lc| lc + c.get_variable() - a.get_variable(),
  );
  Ok(c)
}

/// If condition set to 1 otherwise a - b
pub fn select_one_or_diff2<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  b: &AllocatedNum<F>,
  condition: &AllocatedNum<F>,
) -> Result<AllocatedNum<F>, SynthesisError> {
  let c = AllocatedNum::alloc(cs.namespace(|| "conditional select result"), || {
    if *condition.get_value().get()? == F::ONE {
      Ok(F::ONE)
    } else {
      Ok(*a.get_value().get()? - *b.get_value().get()?)
    }
  })?;

  cs.enforce(
    || "conditional select constraint",
    |lc| lc + CS::one() - a.get_variable() + b.get_variable(),
    |lc| lc + condition.get_variable(),
    |lc| lc + c.get_variable() - a.get_variable() + b.get_variable(),
  );
  Ok(c)
}

/// If condition set to a otherwise 1 for boolean conditions
pub fn select_num_or_one<F: PrimeField, CS: ConstraintSystem<F>>(
  mut cs: CS,
  a: &AllocatedNum<F>,
  condition: &Boolean,
) -> Result<AllocatedNum<F>, SynthesisError> {
  let c = AllocatedNum::alloc(cs.namespace(|| "conditional select result"), || {
    if *condition.get_value().get()? {
      Ok(*a.get_value().get()?)
    } else {
      Ok(F::ONE)
    }
  })?;

  cs.enforce(
    || "conditional select constraint",
    |lc| lc + a.get_variable() - CS::one(),
    |_| condition.lc(CS::one(), F::ONE),
    |lc| lc + c.get_variable() - CS::one(),
  );

  Ok(c)
}

/// Allocate a constant value in the circuit
pub fn alloc_constant<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
  mut cs: CS,
  c: &Scalar,
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
  let constant = AllocatedNum::alloc(cs.namespace(|| "constant"), || Ok(*c))?;

  cs.enforce(
    || "check eq given constant",
    |lc| lc + constant.get_variable(),
    |lc| lc + CS::one(),
    |lc| lc + (*c, CS::one()),
  );

  Ok(constant)
}
