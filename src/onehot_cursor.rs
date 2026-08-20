//! One-hot distributions over small, explicit (not necessarily
//! contiguous) sets of `usize` values, and combining them by sum.
//!
//! `sha256_var`/`digest_id_extract` both use "one-hot over `0..=N`" —
//! every value in a contiguous range gets its own selector bit. That
//! doesn't fit the MSO-assembly problem: placing 4 independently
//! variable-width `digestID` fields means each subsequent field's start
//! position depends on the *sum* of all preceding widths, and naively
//! tracking every `(w0, w1, ..., wk)` combination blows up
//! multiplicatively (4 widths per field → 4^4 = 256 combinations by the
//! 4th field). This module tracks the *set of distinct achievable sums*
//! instead — e.g. two fields each in `{1,2,3,5}` sum to one of only 8
//! distinct values (`{2,3,4,5,6,7,8,10}`), not 16 — by convolving one-hot
//! distributions and merging combinations that land on the same value,
//! keeping the state small enough to stay cheap through the whole chain.

use bellpepper_core::{
  boolean::{AllocatedBit, Boolean},
  ConstraintSystem, LinearCombination, SynthesisError,
};
use ff::PrimeField;

/// Allocates a one-hot distribution over `values` (which need not be
/// contiguous or sorted, but must not contain duplicates): exactly one
/// `Boolean` is `true`, at the index matching `real_value`.
pub fn alloc_one_hot<Scalar, CS>(mut cs: CS, values: &[usize], real_value: usize) -> Result<Vec<Boolean>, SynthesisError>
where
  Scalar: PrimeField,
  CS: ConstraintSystem<Scalar>,
{
  let real_idx = values
    .iter()
    .position(|&v| v == real_value)
    .unwrap_or_else(|| panic!("real_value {real_value} not in the provided value set"));
  let mut onehot: Vec<Boolean> = Vec::with_capacity(values.len());
  for (idx, _) in values.iter().enumerate() {
    let bit = AllocatedBit::alloc(cs.namespace(|| format!("one_hot {idx}")), Some(idx == real_idx))?;
    onehot.push(Boolean::from(bit));
  }
  {
    let mut lc = LinearCombination::<Scalar>::zero();
    for b in &onehot {
      lc = lc + &b.lc(CS::one(), Scalar::ONE);
    }
    cs.enforce(
      || "one_hot sums to exactly 1",
      |_| lc,
      |lc| lc + CS::one(),
      |lc| lc + CS::one(),
    );
  }
  Ok(onehot)
}

/// Combines two one-hot distributions (`a` over `a_values`, `b` over
/// `b_values`) into a new one-hot distribution over the *distinct* sums
/// `a_values[i] + b_values[j]`, for every `(i, j)` pair — the core
/// "convolve, then deduplicate by value" operation this module exists
/// for. Each output entry is `OR` over every `(i, j)` pair landing on
/// that sum of `AND(a[i], b[j])` — sound because `a`/`b` are each
/// one-hot, so at most one `(i, j)` pair is ever simultaneously active,
/// making the `OR` exactly equivalent to addition here (never more than
/// one term is `1`).
///
/// Returns `(sum_onehot, sum_values)`, with `sum_values` sorted and
/// deduplicated — `sum_onehot[k]` corresponds to `sum_values[k]`.
pub fn convolve_sum<Scalar, CS>(
  mut cs: CS,
  a: &[Boolean],
  a_values: &[usize],
  b: &[Boolean],
  b_values: &[usize],
) -> Result<(Vec<Boolean>, Vec<usize>), SynthesisError>
where
  Scalar: PrimeField,
  CS: ConstraintSystem<Scalar>,
{
  assert_eq!(a.len(), a_values.len());
  assert_eq!(b.len(), b_values.len());

  let mut sum_values: Vec<usize> = a_values
    .iter()
    .flat_map(|&av| b_values.iter().map(move |&bv| av + bv))
    .collect();
  sum_values.sort_unstable();
  sum_values.dedup();

  let mut sum_onehot: Vec<Boolean> = Vec::with_capacity(sum_values.len());
  for (out_idx, &sv) in sum_values.iter().enumerate() {
    let mut acc: Option<Boolean> = None;
    for (i, &av) in a_values.iter().enumerate() {
      for (j, &bv) in b_values.iter().enumerate() {
        if av + bv != sv {
          continue;
        }
        let term = Boolean::and(cs.namespace(|| format!("convolve sum={sv} out={out_idx} a={i} b={j}")), &a[i], &b[j])?;
        acc = Some(match acc {
          None => term,
          Some(prev) => Boolean::or(cs.namespace(|| format!("convolve-or sum={sv} out={out_idx} a={i} b={j}")), &prev, &term)?,
        });
      }
    }
    sum_onehot.push(acc.expect("every sum_values entry came from at least one (i,j) pair"));
  }

  Ok((sum_onehot, sum_values))
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::Engine_;
  use bellpepper_core::test_cs::TestConstraintSystem;
  use vega_prover::traits::Engine;

  type Scalar = <Engine_ as Engine>::Scalar;

  fn onehot_value(onehot: &[Boolean], values: &[usize]) -> usize {
    let active: Vec<usize> = onehot
      .iter()
      .zip(values)
      .filter(|(b, _)| b.get_value().expect("has a value"))
      .map(|(_, &v)| v)
      .collect();
    assert_eq!(active.len(), 1, "exactly one one-hot entry must be active");
    active[0]
  }

  #[test]
  fn alloc_one_hot_selects_exactly_the_real_value() {
    let values = [1usize, 2, 3, 5];
    for &real in &values {
      let mut cs = TestConstraintSystem::<Scalar>::new();
      let onehot = alloc_one_hot::<Scalar, _>(cs.namespace(|| format!("real={real}")), &values, real).expect("alloc");
      assert!(cs.is_satisfied());
      assert_eq!(onehot_value(&onehot, &values), real);
    }
  }

  #[test]
  fn convolve_sum_matches_every_real_combination_of_two_fields() {
    let widths = [1usize, 2, 3, 5];
    for &w0 in &widths {
      for &w1 in &widths {
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let a = alloc_one_hot::<Scalar, _>(cs.namespace(|| "a"), &widths, w0).expect("alloc a");
        let b = alloc_one_hot::<Scalar, _>(cs.namespace(|| "b"), &widths, w1).expect("alloc b");
        let (sum_onehot, sum_values) =
          convolve_sum::<Scalar, _>(cs.namespace(|| "convolve"), &a, &widths, &b, &widths).expect("convolve");

        if let Some(reason) = cs.which_is_unsatisfied() {
          panic!("w0={w0} w1={w1}: unsatisfied at {reason}");
        }
        assert!(cs.is_satisfied());
        assert_eq!(onehot_value(&sum_onehot, &sum_values), w0 + w1, "w0={w0} w1={w1}");
      }
    }
  }

  /// The whole point of this module: convolving two 4-value distributions
  /// must produce far fewer than 16 distinct sums (real widths `{1,2,3,5}`
  /// collide: e.g. 1+5 == 3+3 == 2+... no, but 1+3==2+2==4, so duplicates
  /// really do occur) — confirms deduplication is actually happening, not
  /// just a correct-but-wasteful 16-entry output.
  #[test]
  fn convolve_sum_deduplicates_real_collisions() {
    let widths = [1usize, 2, 3, 5];
    let mut cs = TestConstraintSystem::<Scalar>::new();
    let a = alloc_one_hot::<Scalar, _>(cs.namespace(|| "a"), &widths, 1).expect("alloc a");
    let b = alloc_one_hot::<Scalar, _>(cs.namespace(|| "b"), &widths, 3).expect("alloc b");
    let (_, sum_values) = convolve_sum::<Scalar, _>(cs.namespace(|| "convolve"), &a, &widths, &b, &widths).expect("convolve");
    // Distinct sums of two values from {1,2,3,5}: {2,3,4,5,6,7,8,10} = 8,
    // not 16.
    assert_eq!(sum_values, vec![2, 3, 4, 5, 6, 7, 8, 10]);
  }

  #[test]
  fn convolve_sum_chains_correctly_across_three_fields() {
    let widths = [1usize, 2, 3, 5];
    for &w0 in &widths {
      for &w1 in &widths {
        for &w2 in &widths {
          let mut cs = TestConstraintSystem::<Scalar>::new();
          let a = alloc_one_hot::<Scalar, _>(cs.namespace(|| "a"), &widths, w0).expect("alloc a");
          let b = alloc_one_hot::<Scalar, _>(cs.namespace(|| "b"), &widths, w1).expect("alloc b");
          let c = alloc_one_hot::<Scalar, _>(cs.namespace(|| "c"), &widths, w2).expect("alloc c");
          let (ab_onehot, ab_values) =
            convolve_sum::<Scalar, _>(cs.namespace(|| "ab"), &a, &widths, &b, &widths).expect("convolve ab");
          let (abc_onehot, abc_values) =
            convolve_sum::<Scalar, _>(cs.namespace(|| "abc"), &ab_onehot, &ab_values, &c, &widths).expect("convolve abc");

          assert!(cs.is_satisfied(), "w0={w0} w1={w1} w2={w2}");
          assert_eq!(onehot_value(&abc_onehot, &abc_values), w0 + w1 + w2, "w0={w0} w1={w1} w2={w2}");
        }
      }
    }
  }
}
