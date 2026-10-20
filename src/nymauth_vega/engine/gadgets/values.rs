// SPDX-License-Identifier: BSD-2-Clause
//! A circuit's values in the order a witness generator records them, computed natively.
//!
//! The prover takes the values of a circuit from its witness generator, `SatisfyingAssignment`,
//! which ignores the rules and records each allocated value in turn. Where synthesizing a gadget
//! costs far more than its values, the crate computes those values directly, in the gadget's order
//! and with the gadget's values: the step circuit ([`crate::nymauth_vega::engine::step::Step::assignment`], which mirrors
//! bellpepper's SHA-256 compression in [`super::sha256`]), and the ECDSA verifications, the windows
//! and the base64url decoding of the cores (the witness branches of [`super::p256::verify`],
//! [`super::window::Message::read`], [`super::base64::decode_chars`] and
//! [`super::base64::EncodedText::read_slots`]). The rules stay the gadgets' own: every other
//! constraint system builds them, and [`crate::nymauth_vega::engine::app::first_broken`] checks an assignment against
//! them.

use ff::{Field, PrimeField};
use vega_prover::provider::pt256::t256;

/// Values in allocation order.
///
/// The values of the shared table's seed blocks pass through here, so the buffer is wiped when it
/// is dropped (best effort). Moving the values on, as a [`super::super::app::Segment`] does, goes
/// through [`Values::into_vec`], which hands over the buffer without leaving a copy behind.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Values(pub Vec<t256::Scalar>);

impl Drop for Values {
  fn drop(&mut self) {
    crate::nymauth_vega::engine::app::wipe(&mut self.0);
  }
}

impl std::fmt::Debug for Values {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "Values({} values, redacted)", self.0.len())
  }
}

impl Values {
  /// The values as a vector, transferred: the caller owns (and must wipe) the buffer.
  pub fn into_vec(mut self) -> Vec<t256::Scalar> {
    std::mem::take(&mut self.0)
  }

  pub fn with_capacity(capacity: usize) -> Self {
    Values(Vec::with_capacity(capacity))
  }

  pub fn push(&mut self, value: t256::Scalar) {
    self.0.push(value);
  }

  /// A bit, as one or zero.
  pub fn bit(&mut self, bit: bool) {
    self.0.push(if bit { t256::Scalar::ONE } else { t256::Scalar::ZERO });
  }

  /// Bits in their order.
  pub fn bits(&mut self, bits: &[bool]) {
    self.0.extend(bits.iter().map(|&b| if b { t256::Scalar::ONE } else { t256::Scalar::ZERO }));
  }

  /// The `n` low bits of `v`, least significant first, as bellpepper's `UInt32` allocates a sum.
  pub fn low_bits(&mut self, v: u64, n: usize) {
    self
      .0
      .extend((0..n).map(|i| if (v >> i) & 1 == 1 { t256::Scalar::ONE } else { t256::Scalar::ZERO }));
  }

  /// The bits of bytes, most significant first, as [`super::bits::bits`] splits the integer they
  /// write.
  pub fn byte_bits(&mut self, bytes: &[u8]) {
    for byte in bytes {
      self
        .0
        .extend((0..8).rev().map(|i| if (byte >> i) & 1 == 1 { t256::Scalar::ONE } else { t256::Scalar::ZERO }));
    }
  }

  /// The `n` low bits of a field element's integer, most significant first, as
  /// [`super::bits::bits`] splits it.
  pub fn field_bits(&mut self, x: &t256::Scalar, n: usize) {
    let repr = x.to_repr();
    let le = repr.as_ref();
    self.0.extend((0..n).rev().map(|i| {
      if (le[i / 8] >> (i % 8)) & 1 == 1 {
        t256::Scalar::ONE
      } else {
        t256::Scalar::ZERO
      }
    }));
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::nymauth_vega::engine::app::{Segment, WIPED};

  fn wiped() -> usize {
    WIPED.with(|w| w.get())
  }

  #[test]
  fn dropping_values_wipes_every_value_and_into_vec_hands_the_buffer_over() {
    let before = wiped();
    let mut v = Values::with_capacity(16);
    for _ in 0..8 {
      v.push(t256::Scalar::from(5u64));
    }
    drop(v);
    assert_eq!(wiped() - before, 8, "the dropped buffer was wiped");

    // Transferred values are not wiped by the transfer, and the emptied shell wipes nothing...
    let before = wiped();
    let mut w = Values::default();
    w.bit(true);
    w.push(t256::Scalar::from(7u64));
    let vec = w.into_vec();
    assert_eq!(wiped() - before, 0);
    assert_eq!(vec, vec![t256::Scalar::ONE, t256::Scalar::from(7u64)]);
    // ...because the new owner wipes them: a Segment wipes its values when dropped.
    let before = wiped();
    drop(Segment {
      private: vec,
      public: vec![t256::Scalar::ONE],
    });
    assert_eq!(wiped() - before, 3);
  }

  #[test]
  fn values_print_no_numbers() {
    let mut v = Values::default();
    v.push(t256::Scalar::from(123456789u64));
    assert_eq!(format!("{v:?}"), "Values(1 values, redacted)");
  }
}
