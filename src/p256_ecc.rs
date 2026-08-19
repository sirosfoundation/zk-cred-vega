//! In-circuit NIST P-256 elliptic-curve point arithmetic.
//!
//! Ported and adapted from `microsoft/Nova`'s `src/gadgets/ecc.rs` (MIT),
//! whose `AllocatedPoint<E>` gadget exists for exactly the same underlying
//! reason we need it: Nova's IVC circuits do EC scalar multiplication over
//! one curve of a 2-cycle pair *natively* (no foreign-field emulation)
//! because that curve's coordinate field equals the circuit's own native
//! field. `vega-prover` picked its own 2-cycle (P-256/T-256,
//! `provider::pt256`) specifically so the *same trick* applies to
//! ECDSA-P256 verification: our circuit's native field
//! (`T256HyraxEngine::Scalar`) equals P-256's own base/coordinate field
//! `p`. So P-256 point addition/doubling/scalar-multiplication below is
//! genuinely native arithmetic, not an approximation.
//!
//! Adaptation from upstream: Nova's version is generic over its own
//! `Engine`/`Group` traits and reads curve coefficients via
//! `E::GE::group_params()` — appropriate when the curve being represented
//! *is* the engine's own curve. Here the curve being represented (P-256) is
//! a *different* curve from the one `vega-prover`'s `T256HyraxEngine` is
//! built on (T-256) — they only share a field, not a curve — so this
//! module is generic over the field alone (`Scalar: PrimeFieldBits`,
//! meant to be instantiated with `T256HyraxEngine::Scalar`) and P-256's
//! (A, B) Weierstrass coefficients are supplied by [`p256_curve_params`],
//! computed once from `vega-prover`'s own real `p256::Point` curve
//! definition via [`crate::gadget_utils::field_switch`] rather than
//! hand-copied hex constants.
//!
//! Dropped relative to upstream: `AllocatedNonnativePoint` (Nova's
//! cross-curve representation for its *other*, non-native cycle direction —
//! not our situation) and `absorb_in_ro` (Nova's own IVC transcript hook).

use crate::gadget_utils::{
  alloc_zero, conditionally_select, conditionally_select2, field_switch, select_num_or_one,
  select_num_or_zero, select_num_or_zero2, select_one_or_diff2, select_zero_or_num2,
};
use bellpepper::gadgets::Assignment;
use bellpepper_core::{
  boolean::{AllocatedBit, Boolean},
  num::AllocatedNum,
  ConstraintSystem, SynthesisError,
};
use ff::PrimeFieldBits;
use vega_prover::{provider::pt256::p256, traits::Group};

use crate::gadget_utils::alloc_num_equals;

/// Returns P-256's Weierstrass equation coefficients `(A, B)` (in
/// `y^2 = x^3 + Ax + B`), converted from `vega-prover`'s own `p256::Point`
/// curve definition into `Scalar` (meant to be `T256HyraxEngine::Scalar`,
/// which the P-256/T-256 2-cycle guarantees is numerically the same field
/// as `p256::Base`, just a different `halo2curves` Rust type — hence the
/// [`field_switch`] rather than a direct cast).
pub fn p256_curve_params<Scalar: PrimeFieldBits>() -> (Scalar, Scalar) {
  let (a, b, _order, _base_size) = p256::Point::group_params();
  (field_switch(a), field_switch(b))
}

/// Returns P-256's base point (generator) `G`'s affine coordinates,
/// converted into `Scalar` the same way as [`p256_curve_params`].
pub fn p256_generator<Scalar: PrimeFieldBits>() -> (Scalar, Scalar) {
  use halo2curves::CurveAffine;
  let g = p256::Affine::generator();
  let coords = g.coordinates().unwrap();
  (field_switch(*coords.x()), field_switch(*coords.y()))
}

/// Returns P-256's group order `n` as a `BigInt`.
pub fn p256_order() -> num_bigint::BigInt {
  p256::Point::group_params().2
}

/// `AllocatedPoint` provides an elliptic curve abstraction inside a circuit,
/// over the circuit's native field (see module doc for why this is P-256's
/// own coordinate field here, not an emulated one).
#[derive(Clone)]
pub struct AllocatedPoint<Scalar: PrimeFieldBits> {
  /// The x-coordinate of the point.
  pub x: AllocatedNum<Scalar>,
  /// The y-coordinate of the point.
  pub y: AllocatedNum<Scalar>,
  /// Flag indicating if this is the point at infinity (1 = infinity, 0 = not infinity).
  pub is_infinity: AllocatedNum<Scalar>,
}

impl<Scalar: PrimeFieldBits> AllocatedPoint<Scalar> {
  /// Allocates a new point on the curve using coordinates provided by `coords`.
  /// If coords = None, it allocates the default infinity point
  pub fn alloc<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    coords: Option<(Scalar, Scalar, bool)>,
  ) -> Result<Self, SynthesisError> {
    let x = AllocatedNum::alloc(cs.namespace(|| "x"), || {
      Ok(coords.map_or(Scalar::ZERO, |c| c.0))
    })?;
    let y = AllocatedNum::alloc(cs.namespace(|| "y"), || {
      Ok(coords.map_or(Scalar::ZERO, |c| c.1))
    })?;
    let is_infinity = AllocatedNum::alloc(cs.namespace(|| "is_infinity"), || {
      Ok(if coords.is_none_or(|c| c.2) {
        Scalar::ONE
      } else {
        Scalar::ZERO
      })
    })?;
    cs.enforce(
      || "is_infinity is bit",
      |lc| lc + is_infinity.get_variable(),
      |lc| lc + CS::one() - is_infinity.get_variable(),
      |lc| lc,
    );

    Ok(AllocatedPoint { x, y, is_infinity })
  }

  /// checks if `self` is on the P-256 curve or if it is infinity
  pub fn check_on_curve<CS: ConstraintSystem<Scalar>>(&self, mut cs: CS) -> Result<(), SynthesisError> {
    let (a, b) = p256_curve_params::<Scalar>();

    let y_square = self.y.square(cs.namespace(|| "y_square"))?;
    let x_square = self.x.square(cs.namespace(|| "x_square"))?;
    let x_cube = self.x.mul(cs.namespace(|| "x_cube"), &x_square)?;

    let rhs = AllocatedNum::alloc(cs.namespace(|| "rhs"), || {
      if *self.is_infinity.get_value().get()? == Scalar::ONE {
        Ok(Scalar::ZERO)
      } else {
        Ok(*x_cube.get_value().get()? + *self.x.get_value().get()? * a + b)
      }
    })?;

    cs.enforce(
      || "rhs = (1-is_infinity) * (x^3 + Ax + B)",
      |lc| lc + x_cube.get_variable() + (a, self.x.get_variable()) + (b, CS::one()),
      |lc| lc + CS::one() - self.is_infinity.get_variable(),
      |lc| lc + rhs.get_variable(),
    );

    cs.enforce(
      || "check that y_square * (1 - is_infinity) = rhs",
      |lc| lc + y_square.get_variable(),
      |lc| lc + CS::one() - self.is_infinity.get_variable(),
      |lc| lc + rhs.get_variable(),
    );

    Ok(())
  }

  /// Allocates a default point on the curve, set to the identity point.
  pub fn default<CS: ConstraintSystem<Scalar>>(mut cs: CS) -> Result<Self, SynthesisError> {
    let zero = alloc_zero(cs.namespace(|| "zero"));
    let one = crate::gadget_utils::alloc_constant(cs.namespace(|| "one"), &Scalar::ONE)?;

    Ok(AllocatedPoint {
      x: zero.clone(),
      y: zero,
      is_infinity: one,
    })
  }

  /// Negates the provided point
  pub fn negate<CS: ConstraintSystem<Scalar>>(&self, mut cs: CS) -> Result<Self, SynthesisError> {
    let y = AllocatedNum::alloc(cs.namespace(|| "y"), || Ok(-*self.y.get_value().get()?))?;

    cs.enforce(
      || "check y = - self.y",
      |lc| lc + self.y.get_variable(),
      |lc| lc + CS::one(),
      |lc| lc - y.get_variable(),
    );

    Ok(Self {
      x: self.x.clone(),
      y,
      is_infinity: self.is_infinity.clone(),
    })
  }

  /// Add two points (may be equal)
  pub fn add<CS: ConstraintSystem<Scalar>>(
    &self,
    mut cs: CS,
    other: &AllocatedPoint<Scalar>,
  ) -> Result<Self, SynthesisError> {
    let equal_x = alloc_num_equals(
      cs.namespace(|| "check self.x == other.x"),
      &self.x,
      &other.x,
    )?;

    let equal_y = alloc_num_equals(
      cs.namespace(|| "check self.y == other.y"),
      &self.y,
      &other.y,
    )?;

    let (result_from_add, at_least_one_inf) =
      self.add_internal(cs.namespace(|| "add internal"), other, &equal_x)?;
    let result_from_double = self.double(cs.namespace(|| "double"))?;

    let result_for_equal_x = AllocatedPoint::select_point_or_infinity(
      cs.namespace(|| "equal_y ? result_from_double : infinity"),
      &result_from_double,
      &Boolean::from(equal_y),
    )?;

    let use_equal_x = AllocatedNum::alloc(cs.namespace(|| "equal_x and neither_inf"), || {
      let ex = if *equal_x.get_value().get()? {
        Scalar::ONE
      } else {
        Scalar::ZERO
      };
      Ok(ex * (Scalar::ONE - *at_least_one_inf.get_value().get()?))
    })?;
    cs.enforce(
      || "use_equal_x = equal_x * (1 - at_least_one_inf)",
      |lc| lc + equal_x.get_variable(),
      |lc| lc + CS::one() - at_least_one_inf.get_variable(),
      |lc| lc + use_equal_x.get_variable(),
    );

    AllocatedPoint::conditionally_select2(
      cs.namespace(|| "use_equal_x ? result_for_equal_x : result_from_add"),
      &result_for_equal_x,
      &result_from_add,
      &use_equal_x,
    )
  }

  /// Adds `other` to `self` and returns the result, along with the flag
  /// `at_least_one_inf` (= `self.is_infinity` OR `other.is_infinity`).
  pub fn add_internal<CS: ConstraintSystem<Scalar>>(
    &self,
    mut cs: CS,
    other: &AllocatedPoint<Scalar>,
    equal_x: &AllocatedBit,
  ) -> Result<(Self, AllocatedNum<Scalar>), SynthesisError> {
    let at_least_one_inf = AllocatedNum::alloc(cs.namespace(|| "at least one inf"), || {
      Ok(
        Scalar::ONE
          - (Scalar::ONE - *self.is_infinity.get_value().get()?)
            * (Scalar::ONE - *other.is_infinity.get_value().get()?),
      )
    })?;
    cs.enforce(
      || "1 - at least one inf = (1-self.is_infinity) * (1-other.is_infinity)",
      |lc| lc + CS::one() - self.is_infinity.get_variable(),
      |lc| lc + CS::one() - other.is_infinity.get_variable(),
      |lc| lc + CS::one() - at_least_one_inf.get_variable(),
    );

    let x_diff_is_actual =
      AllocatedNum::alloc(cs.namespace(|| "allocate x_diff_is_actual"), || {
        Ok(if *equal_x.get_value().get()? {
          Scalar::ONE
        } else {
          *at_least_one_inf.get_value().get()?
        })
      })?;
    cs.enforce(
      || "1 - x_diff_is_actual = (1-equal_x) * (1-at_least_one_inf)",
      |lc| lc + CS::one() - at_least_one_inf.get_variable(),
      |lc| lc + CS::one() - equal_x.get_variable(),
      |lc| lc + CS::one() - x_diff_is_actual.get_variable(),
    );

    let x_diff = select_one_or_diff2(
      cs.namespace(|| "Compute x_diff"),
      &other.x,
      &self.x,
      &x_diff_is_actual,
    )?;

    let lambda = AllocatedNum::alloc(cs.namespace(|| "lambda"), || {
      let x_diff_inv = if *x_diff_is_actual.get_value().get()? == Scalar::ONE {
        Scalar::ONE
      } else {
        (*other.x.get_value().get()? - *self.x.get_value().get()?)
          .invert()
          .unwrap()
      };

      Ok((*other.y.get_value().get()? - *self.y.get_value().get()?) * x_diff_inv)
    })?;
    cs.enforce(
      || "Check that lambda is correct",
      |lc| lc + lambda.get_variable(),
      |lc| lc + x_diff.get_variable(),
      |lc| lc + other.y.get_variable() - self.y.get_variable(),
    );

    let x = AllocatedNum::alloc(cs.namespace(|| "x"), || {
      Ok(
        *lambda.get_value().get()? * lambda.get_value().get()?
          - *self.x.get_value().get()?
          - *other.x.get_value().get()?,
      )
    })?;
    cs.enforce(
      || "check that x is correct",
      |lc| lc + lambda.get_variable(),
      |lc| lc + lambda.get_variable(),
      |lc| lc + x.get_variable() + self.x.get_variable() + other.x.get_variable(),
    );

    let y = AllocatedNum::alloc(cs.namespace(|| "y"), || {
      Ok(
        *lambda.get_value().get()? * (*self.x.get_value().get()? - *x.get_value().get()?)
          - *self.y.get_value().get()?,
      )
    })?;

    cs.enforce(
      || "Check that y is correct",
      |lc| lc + lambda.get_variable(),
      |lc| lc + self.x.get_variable() - x.get_variable(),
      |lc| lc + y.get_variable() + self.y.get_variable(),
    );

    let x1 = conditionally_select2(
      cs.namespace(|| "x1 = other.is_infinity ? self.x : x"),
      &self.x,
      &x,
      &other.is_infinity,
    )?;

    let x = conditionally_select2(
      cs.namespace(|| "x = self.is_infinity ? other.x : x1"),
      &other.x,
      &x1,
      &self.is_infinity,
    )?;

    let y1 = conditionally_select2(
      cs.namespace(|| "y1 = other.is_infinity ? self.y : y"),
      &self.y,
      &y,
      &other.is_infinity,
    )?;

    let y = conditionally_select2(
      cs.namespace(|| "y = self.is_infinity ? other.y : y1"),
      &other.y,
      &y1,
      &self.is_infinity,
    )?;

    let is_infinity1 = select_num_or_zero2(
      cs.namespace(|| "is_infinity1 = other.is_infinity ? self.is_infinity : 0"),
      &self.is_infinity,
      &other.is_infinity,
    )?;

    let is_infinity = conditionally_select2(
      cs.namespace(|| "is_infinity = self.is_infinity ? other.is_infinity : is_infinity1"),
      &other.is_infinity,
      &is_infinity1,
      &self.is_infinity,
    )?;

    Ok((Self { x, y, is_infinity }, at_least_one_inf))
  }

  /// Doubles the supplied point.
  pub fn double<CS: ConstraintSystem<Scalar>>(&self, mut cs: CS) -> Result<Self, SynthesisError> {
    let (a, _b) = p256_curve_params::<Scalar>();

    let tmp_actual = AllocatedNum::alloc(cs.namespace(|| "tmp_actual"), || {
      Ok(*self.y.get_value().get()? + *self.y.get_value().get()?)
    })?;
    cs.enforce(
      || "check tmp_actual",
      |lc| lc + CS::one() + CS::one(),
      |lc| lc + self.y.get_variable(),
      |lc| lc + tmp_actual.get_variable(),
    );

    let tmp = crate::gadget_utils::select_one_or_num2(
      cs.namespace(|| "tmp"),
      &tmp_actual,
      &self.is_infinity,
    )?;

    let prod_1 = AllocatedNum::alloc(cs.namespace(|| "alloc prod 1"), || {
      Ok(Scalar::from(3) * self.x.get_value().get()? * self.x.get_value().get()?)
    })?;
    cs.enforce(
      || "Check prod 1",
      |lc| lc + (Scalar::from(3), self.x.get_variable()),
      |lc| lc + self.x.get_variable(),
      |lc| lc + prod_1.get_variable(),
    );

    let lambda = AllocatedNum::alloc(cs.namespace(|| "alloc lambda"), || {
      let tmp_inv = if *self.is_infinity.get_value().get()? == Scalar::ONE {
        Scalar::ONE
      } else {
        (*tmp.get_value().get()?).invert().unwrap()
      };

      Ok(tmp_inv * (*prod_1.get_value().get()? + a))
    })?;

    cs.enforce(
      || "Check lambda",
      |lc| lc + tmp.get_variable(),
      |lc| lc + lambda.get_variable(),
      |lc| lc + prod_1.get_variable() + (a, CS::one()),
    );

    let x = AllocatedNum::alloc(cs.namespace(|| "x"), || {
      Ok(
        ((*lambda.get_value().get()?) * (*lambda.get_value().get()?))
          - *self.x.get_value().get()?
          - self.x.get_value().get()?,
      )
    })?;
    cs.enforce(
      || "Check x",
      |lc| lc + lambda.get_variable(),
      |lc| lc + lambda.get_variable(),
      |lc| lc + x.get_variable() + self.x.get_variable() + self.x.get_variable(),
    );

    let y = AllocatedNum::alloc(cs.namespace(|| "y"), || {
      Ok(
        (*lambda.get_value().get()?) * (*self.x.get_value().get()? - x.get_value().get()?)
          - self.y.get_value().get()?,
      )
    })?;
    cs.enforce(
      || "Check y",
      |lc| lc + lambda.get_variable(),
      |lc| lc + self.x.get_variable() - x.get_variable(),
      |lc| lc + y.get_variable() + self.y.get_variable(),
    );

    let x = select_zero_or_num2(cs.namespace(|| "final x"), &x, &self.is_infinity)?;
    let y = select_zero_or_num2(cs.namespace(|| "final y"), &y, &self.is_infinity)?;
    let is_infinity = self.is_infinity.clone();

    Ok(Self { x, y, is_infinity })
  }

  /// A gadget for scalar multiplication, optimized to use incomplete addition law
  /// for most bits and the complete addition law for the tail (see
  /// `microsoft/Nova`'s original doc comment for the arkworks reference this
  /// optimization follows).
  pub fn scalar_mul<CS: ConstraintSystem<Scalar>>(
    &self,
    mut cs: CS,
    scalar_bits: &[AllocatedBit],
  ) -> Result<Self, SynthesisError> {
    let split_len = core::cmp::min(scalar_bits.len(), (Scalar::NUM_BITS - 2) as usize);
    let (incomplete_bits, complete_bits) = scalar_bits.split_at(split_len);

    let mut p = AllocatedPointNonInfinity::from_allocated_point(self);

    let mut acc = p;
    p = acc.double_incomplete(cs.namespace(|| "double"))?;

    for (i, bit) in incomplete_bits.iter().enumerate().skip(1) {
      let temp = acc.add_incomplete(cs.namespace(|| format!("add {i}")), &p)?;
      acc = AllocatedPointNonInfinity::conditionally_select(
        cs.namespace(|| format!("acc_iteration_{i}")),
        &temp,
        &acc,
        &Boolean::from(bit.clone()),
      )?;

      p = p.double_incomplete(cs.namespace(|| format!("double {i}")))?;
    }

    let res = {
      let acc = acc.to_allocated_point(&self.is_infinity)?;

      let acc_minus_initial = {
        let neg = self.negate(cs.namespace(|| "negate"))?;
        acc.add(cs.namespace(|| "res minus self"), &neg)
      }?;

      AllocatedPoint::conditionally_select(
        cs.namespace(|| "remove slack if necessary"),
        &acc,
        &acc_minus_initial,
        &Boolean::from(scalar_bits[0].clone()),
      )?
    };

    let default = Self::default(cs.namespace(|| "default"))?;
    let x = conditionally_select2(
      cs.namespace(|| "check if self.is_infinity is zero (x)"),
      &default.x,
      &res.x,
      &self.is_infinity,
    )?;

    let y = conditionally_select2(
      cs.namespace(|| "check if self.is_infinity is zero (y)"),
      &default.y,
      &res.y,
      &self.is_infinity,
    )?;

    let mut acc = AllocatedPoint {
      x,
      y,
      is_infinity: res.is_infinity,
    };
    let mut p_complete = p.to_allocated_point(&self.is_infinity)?;

    for (i, bit) in complete_bits.iter().enumerate() {
      let temp = acc.add(cs.namespace(|| format!("add_complete {i}")), &p_complete)?;
      acc = AllocatedPoint::conditionally_select(
        cs.namespace(|| format!("acc_complete_iteration_{i}")),
        &temp,
        &acc,
        &Boolean::from(bit.clone()),
      )?;

      p_complete = p_complete.double(cs.namespace(|| format!("double_complete {i}")))?;
    }

    Ok(acc)
  }

  /// If condition outputs a otherwise outputs b
  pub fn conditionally_select<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    a: &Self,
    b: &Self,
    condition: &Boolean,
  ) -> Result<Self, SynthesisError> {
    let x = conditionally_select(cs.namespace(|| "select x"), &a.x, &b.x, condition)?;
    let y = conditionally_select(cs.namespace(|| "select y"), &a.y, &b.y, condition)?;
    let is_infinity = conditionally_select(
      cs.namespace(|| "select is_infinity"),
      &a.is_infinity,
      &b.is_infinity,
      condition,
    )?;

    Ok(Self { x, y, is_infinity })
  }

  /// Conditional select using an `AllocatedNum` (constrained to `{0, 1}`) instead of `Boolean`.
  pub fn conditionally_select2<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    a: &Self,
    b: &Self,
    condition: &AllocatedNum<Scalar>,
  ) -> Result<Self, SynthesisError> {
    let x = conditionally_select2(cs.namespace(|| "select x"), &a.x, &b.x, condition)?;
    let y = conditionally_select2(cs.namespace(|| "select y"), &a.y, &b.y, condition)?;
    let is_infinity = conditionally_select2(
      cs.namespace(|| "select is_infinity"),
      &a.is_infinity,
      &b.is_infinity,
      condition,
    )?;

    Ok(Self { x, y, is_infinity })
  }

  /// If condition outputs a otherwise infinity
  pub fn select_point_or_infinity<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    a: &Self,
    condition: &Boolean,
  ) -> Result<Self, SynthesisError> {
    let x = select_num_or_zero(cs.namespace(|| "select x"), &a.x, condition)?;
    let y = select_num_or_zero(cs.namespace(|| "select y"), &a.y, condition)?;
    let is_infinity = select_num_or_one(
      cs.namespace(|| "select is_infinity"),
      &a.is_infinity,
      condition,
    )?;

    Ok(Self { x, y, is_infinity })
  }

  /// Allocate a point with constant x and y coordinates and a provided `is_infinity` flag.
  pub fn alloc_constant<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    coords: (Scalar, Scalar),
    is_infinity: AllocatedNum<Scalar>,
  ) -> Result<AllocatedPoint<Scalar>, SynthesisError> {
    let x = crate::gadget_utils::alloc_constant(cs.namespace(|| "x"), &coords.0)?;
    let y = crate::gadget_utils::alloc_constant(cs.namespace(|| "y"), &coords.1)?;

    Ok(AllocatedPoint { x, y, is_infinity })
  }

  /// Enforce that self equals other.
  pub fn enforce_equal<CS: ConstraintSystem<Scalar>>(
    &self,
    mut cs: CS,
    other: &Self,
  ) -> Result<(), SynthesisError> {
    cs.enforce(
      || "check x equality",
      |lc| lc + self.x.get_variable() - other.x.get_variable(),
      |lc| lc + CS::one(),
      |lc| lc,
    );
    cs.enforce(
      || "check y equality",
      |lc| lc + self.y.get_variable() - other.y.get_variable(),
      |lc| lc + CS::one(),
      |lc| lc,
    );
    cs.enforce(
      || "check is_inf equality",
      |lc| lc + self.is_infinity.get_variable() - other.is_infinity.get_variable(),
      |lc| lc + CS::one(),
      |lc| lc,
    );

    Ok(())
  }
}

#[derive(Clone)]
/// `AllocatedPoint` but one that is guaranteed to be not infinity
pub struct AllocatedPointNonInfinity<Scalar: PrimeFieldBits> {
  /// The x-coordinate of the point.
  pub x: AllocatedNum<Scalar>,
  /// The y-coordinate of the point.
  pub y: AllocatedNum<Scalar>,
}

impl<Scalar: PrimeFieldBits> AllocatedPointNonInfinity<Scalar> {
  /// Turns an `AllocatedPoint` into an `AllocatedPointNonInfinity` (assumes it is not infinity)
  pub fn from_allocated_point(p: &AllocatedPoint<Scalar>) -> Self {
    Self {
      x: p.x.clone(),
      y: p.y.clone(),
    }
  }

  /// Returns an `AllocatedPoint` from an `AllocatedPointNonInfinity`
  pub fn to_allocated_point(
    &self,
    is_infinity: &AllocatedNum<Scalar>,
  ) -> Result<AllocatedPoint<Scalar>, SynthesisError> {
    Ok(AllocatedPoint {
      x: self.x.clone(),
      y: self.y.clone(),
      is_infinity: is_infinity.clone(),
    })
  }

  /// Add two points assuming self != +/- other
  pub fn add_incomplete<CS: ConstraintSystem<Scalar>>(
    &self,
    mut cs: CS,
    other: &Self,
  ) -> Result<Self, SynthesisError> {
    let lambda = AllocatedNum::alloc(cs.namespace(|| "lambda"), || {
      if *other.x.get_value().get()? == *self.x.get_value().get()? {
        Ok(Scalar::ONE)
      } else {
        Ok(
          (*other.y.get_value().get()? - *self.y.get_value().get()?)
            * (*other.x.get_value().get()? - *self.x.get_value().get()?)
              .invert()
              .unwrap(),
        )
      }
    })?;
    cs.enforce(
      || "Check that lambda is computed correctly",
      |lc| lc + lambda.get_variable(),
      |lc| lc + other.x.get_variable() - self.x.get_variable(),
      |lc| lc + other.y.get_variable() - self.y.get_variable(),
    );

    let x = AllocatedNum::alloc(cs.namespace(|| "x"), || {
      Ok(
        *lambda.get_value().get()? * lambda.get_value().get()?
          - *self.x.get_value().get()?
          - *other.x.get_value().get()?,
      )
    })?;
    cs.enforce(
      || "check that x is correct",
      |lc| lc + lambda.get_variable(),
      |lc| lc + lambda.get_variable(),
      |lc| lc + x.get_variable() + self.x.get_variable() + other.x.get_variable(),
    );

    let y = AllocatedNum::alloc(cs.namespace(|| "y"), || {
      Ok(
        *lambda.get_value().get()? * (*self.x.get_value().get()? - *x.get_value().get()?)
          - *self.y.get_value().get()?,
      )
    })?;

    cs.enforce(
      || "Check that y is correct",
      |lc| lc + lambda.get_variable(),
      |lc| lc + self.x.get_variable() - x.get_variable(),
      |lc| lc + y.get_variable() + self.y.get_variable(),
    );

    Ok(Self { x, y })
  }

  /// doubles the point; since this is called with a point not at infinity, it is guaranteed to be not infinity
  pub fn double_incomplete<CS: ConstraintSystem<Scalar>>(
    &self,
    mut cs: CS,
  ) -> Result<Self, SynthesisError> {
    let (a, _b) = p256_curve_params::<Scalar>();
    let x_sq = self.x.square(cs.namespace(|| "x_sq"))?;

    let lambda = AllocatedNum::alloc(cs.namespace(|| "lambda"), || {
      let n = Scalar::from(3) * x_sq.get_value().get()? + a;
      let d = Scalar::from(2) * *self.y.get_value().get()?;
      if d == Scalar::ZERO {
        Ok(Scalar::ONE)
      } else {
        Ok(n * d.invert().unwrap())
      }
    })?;
    cs.enforce(
      || "Check that lambda is computed correctly",
      |lc| lc + lambda.get_variable(),
      |lc| lc + (Scalar::from(2), self.y.get_variable()),
      |lc| lc + (Scalar::from(3), x_sq.get_variable()) + (a, CS::one()),
    );

    let x = AllocatedNum::alloc(cs.namespace(|| "x"), || {
      Ok(
        *lambda.get_value().get()? * *lambda.get_value().get()?
          - *self.x.get_value().get()?
          - *self.x.get_value().get()?,
      )
    })?;

    cs.enforce(
      || "check that x is correct",
      |lc| lc + lambda.get_variable(),
      |lc| lc + lambda.get_variable(),
      |lc| lc + x.get_variable() + (Scalar::from(2), self.x.get_variable()),
    );

    let y = AllocatedNum::alloc(cs.namespace(|| "y"), || {
      Ok(
        *lambda.get_value().get()? * (*self.x.get_value().get()? - *x.get_value().get()?)
          - *self.y.get_value().get()?,
      )
    })?;

    cs.enforce(
      || "Check that y is correct",
      |lc| lc + lambda.get_variable(),
      |lc| lc + self.x.get_variable() - x.get_variable(),
      |lc| lc + y.get_variable() + self.y.get_variable(),
    );

    Ok(Self { x, y })
  }

  /// If condition outputs a otherwise outputs b
  pub fn conditionally_select<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    a: &Self,
    b: &Self,
    condition: &Boolean,
  ) -> Result<Self, SynthesisError> {
    let x = conditionally_select(cs.namespace(|| "select x"), &a.x, &b.x, condition)?;
    let y = conditionally_select(cs.namespace(|| "select y"), &a.y, &b.y, condition)?;

    Ok(Self { x, y })
  }
}
