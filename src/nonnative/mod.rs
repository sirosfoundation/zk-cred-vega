//! In-circuit foreign-field ("non-native") big-integer arithmetic.
//!
//! Ported and trimmed from `microsoft/Nova`'s `src/gadgets/nonnative/` (MIT
//! licensed; Nova's own header credits `bellman-bignat`
//! (https://github.com/alex-ozdemir/bellman-bignat), also MIT). Nova needs
//! this to let a recursive IVC circuit do arithmetic mod a "foreign"
//! modulus belonging to the other curve in its 2-cycle; we need it for the
//! same underlying reason: our circuit's native field is P-256's *base*
//! field (`p`), but ECDSA-P256 verification's `u1 = z*s^-1 mod n`/
//! `u2 = r*s^-1 mod n` steps are arithmetic mod P-256's *order* (`n`), a
//! different, non-native modulus. See `crate::p256_ecc` for the point-
//! arithmetic half (which *is* native, for the same 2-cycle reason).
//!
//! Trimmed relative to upstream: Nova's `util.rs` also carries a second
//! half (`fingerprint_bignat`, `absorb_bignat_in_ro*`) used only by its own
//! IVC folding-transcript machinery, and `bignat.rs`'s `fold_bn`/`inputize`
//! likewise. None of that applies here (we're not building a recursive
//! folding scheme), so it's omitted rather than ported unused.

use bellpepper_core::SynthesisError;
use ff::PrimeField;

trait OptionExt<T> {
  fn grab(&self) -> Result<&T, SynthesisError>;
}

impl<T> OptionExt<T> for Option<T> {
  fn grab(&self) -> Result<&T, SynthesisError> {
    self.as_ref().ok_or(SynthesisError::AssignmentMissing)
  }
}

trait BitAccess {
  fn get_bit(&self, i: usize) -> Option<bool>;
}

impl<Scalar: PrimeField> BitAccess for Scalar {
  fn get_bit(&self, i: usize) -> Option<bool> {
    if i as u32 >= Scalar::NUM_BITS {
      return None;
    }

    let (byte_pos, bit_pos) = (i / 8, i % 8);
    let byte = self.to_repr().as_ref()[byte_pos];
    let bit = (byte >> bit_pos) & 1;
    Some(bit == 1)
  }
}

pub mod bignat;
pub mod util;
