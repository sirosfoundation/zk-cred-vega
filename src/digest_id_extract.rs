//! Extracts and validates an ISO 18013-5 `digestID` field from an
//! `IssuerSignedItem`'s raw (tag(24)-wrapped) bytes, in-circuit.
//!
//! ## Why this exists
//!
//! A real verifier looks up `valueDigests[namespace][digestID]` using the
//! `digestID` embedded *inside* the disclosed item itself, and checks it
//! equals `SHA-256(item bytes)`. This crate's circuit previously hardcoded
//! the MSO's `valueDigests` map keys as `0..MAX_CLAIMS_V1`, with nothing
//! tying that to what's actually inside the claim bytes being hashed —
//! self-consistent for credentials this crate mints itself, but not
//! genuine interop with an arbitrary real credential (see `HANDOFF.md`'s
//! digestID-binding writeup). This module closes that gap: it extracts
//! the real, witnessed `digestID` value directly from the claim bytes and
//! produces the exact CBOR bytes to reuse — verbatim — as the MSO's map
//! key, so the two are provably the same value, not just conventionally
//! kept in sync by whoever built the witness.
//!
//! ## Byte layout assumption (v1 scope)
//!
//! `digestID` is assumed to be the *first* field of the `IssuerSignedItem`
//! map, in CDDL declaration order (`digestID`, `random`,
//! `elementIdentifier`, `elementValue`) — confirmed against a real signed
//! test vector by `mso.rs`'s own module doc, and independently corroborated
//! by `zk-cred-longfellow`'s real production circuit interface docs,
//! which document the *same* byte-14 starting offset for a real item
//! whose CBOR byte-string length uses the 2-byte header form (true for
//! every realistic item size this crate supports — see
//! [`DIGEST_ID_OFFSET_BYTES`]'s doc). A real issuer that instead uses
//! canonical (sorted-key) or another field order for `IssuerSignedItem`
//! is out of this v1's scope, same kind of limitation as this crate's
//! fixed claim count and single namespace. `zk-cred-longfellow`'s own
//! circuit witnesses field order explicitly for exactly this reason (real
//! issuers vary) — a real generalization path if this ever needs to widen.

use crate::cbor_uint::{self, MAX_CBOR_UINT_BYTES};
use bellpepper_core::{
  boolean::{AllocatedBit, Boolean},
  ConstraintSystem, LinearCombination, SynthesisError,
};
use ff::PrimeField;

/// Byte offset (from the start of the tag(24)-wrapped `IssuerSignedItem`)
/// where `digestID`'s CBOR-encoded *value* begins: 2 bytes for the
/// `#6.24` tag, 2 bytes for the enclosing byte string's 2-byte-length
/// CBOR header (`0x58 XX` — correct whenever the item's inner map is
/// 24-255 bytes, true for every claim size this crate supports, real or
/// padding), 1 byte for the 4-entry map header (`0xa4`), and 9 bytes for
/// the literal key `"digestID"` (`0x68` + 8 ASCII bytes). Matches
/// `zk-cred-longfellow`'s own documented offset for the same real-world
/// byte shape (see module doc).
pub const DIGEST_ID_OFFSET_BYTES: usize = 2 + 2 + 1 + 9;

/// The extracted, validated `digestID`: its decoded numeric value (32
/// bits, MSB-first) and the exact CBOR bytes that encode it (fixed
/// [`MAX_CBOR_UINT_BYTES`]-byte window, masked to all-zero beyond the
/// real encoding's width) — the latter is what gets spliced verbatim into
/// the MSO's `valueDigests` map key, guaranteeing byte-for-byte agreement
/// with what's embedded in the claim.
pub struct ExtractedDigestId {
  pub value_bits: Vec<Boolean>,
  pub encoded_bits: Vec<Boolean>,
}

/// Constrains that `item_bits[offset_bytes*8 .. (offset_bytes+5)*8]`
/// encodes `digest_id` as a canonical CBOR major-type-0 unsigned integer
/// (see `cbor_uint`'s module doc), for one of this crate's four supported
/// length classes. `item_bits` must be long enough to cover that window;
/// `digest_id` is a native witness value (already checked
/// `<= cbor_uint::MAX_DIGEST_ID` by the caller — see `ClaimWitness`'s doc).
#[allow(clippy::needless_range_loop)] // indices double as the numeric `c`/`byte_idx`/`bit_idx` the formulas reason about
pub fn extract_digest_id<Scalar, CS>(
  mut cs: CS,
  item_bits: &[Boolean],
  offset_bytes: usize,
  digest_id: u32,
) -> Result<ExtractedDigestId, SynthesisError>
where
  Scalar: PrimeField,
  CS: ConstraintSystem<Scalar>,
{
  assert!(
    item_bits.len() >= (offset_bytes + MAX_CBOR_UINT_BYTES) * 8,
    "item_bits too short to cover the digestID window"
  );
  assert!(digest_id <= cbor_uint::MAX_DIGEST_ID, "digestID must be < 2^31");

  let window_bits: &[Boolean] = &item_bits[offset_bytes * 8..(offset_bytes + MAX_CBOR_UINT_BYTES) * 8];
  let window_byte_bits = |byte_idx: usize| -> &[Boolean] { &window_bits[byte_idx * 8..(byte_idx + 1) * 8] };

  let real_class = cbor_uint::length_class(digest_id);
  // Constant CBOR "argument follows" marker for classes 1-3; class 0 has
  // no separate marker (the value IS the initial byte).
  const CLASS_MARKERS: [u8; 4] = [0, 0x18, 0x19, 0x1a];
  // 1. One-hot `class_selector[c] == 1` iff `real_class == c`.
  let mut class_selector: Vec<Boolean> = Vec::with_capacity(4);
  for c in 0..4 {
    let bit = AllocatedBit::alloc(cs.namespace(|| format!("digest_id class {c}")), Some(c == real_class))?;
    class_selector.push(Boolean::from(bit));
  }
  {
    let mut lc = LinearCombination::<Scalar>::zero();
    for b in &class_selector {
      lc = lc + &b.lc(CS::one(), Scalar::ONE);
    }
    cs.enforce(
      || "digest_id class_selector is one-hot",
      |_| lc,
      |lc| lc + CS::one(),
      |lc| lc + CS::one(),
    );
  }

  // 2. `active(byte_idx)` — is this byte of the 5-byte window part of the
  // real encoding for the selected class — as a linear combination over
  // class_selector (compile-time-known which classes make byte_idx
  // active), same technique as sha256_var's msg_active.
  let byte_active_in_class = |byte_idx: usize, class: usize| -> bool { byte_idx < cbor_uint::class_byte_width(class) };
  let mut active: Vec<Boolean> = Vec::with_capacity(MAX_CBOR_UINT_BYTES);
  for byte_idx in 0..MAX_CBOR_UINT_BYTES {
    let mut lc = LinearCombination::<Scalar>::zero();
    for c in 0..4 {
      if byte_active_in_class(byte_idx, c) {
        lc = lc + &class_selector[c].lc(CS::one(), Scalar::ONE);
      }
    }
    let value = byte_active_in_class(byte_idx, real_class);
    let bit = AllocatedBit::alloc(cs.namespace(|| format!("digest_id byte {byte_idx} active")), Some(value))?;
    cs.enforce(
      || format!("digest_id byte {byte_idx} active matches selector sum"),
      |_| lc,
      |lc| lc + CS::one(),
      |lc| lc + bit.get_variable(),
    );
    active.push(Boolean::from(bit));
  }

  // 3. Witness digest_id's own 32 bits directly (MSB-first) — this, not
  // anything derived from the window bits, is the authoritative exposed
  // value. Steps 4-5 below constrain the window bits to match IT (via
  // class_selector), the reverse direction of a naive "extract from
  // bits" approach — matching this crate's established "witness the
  // answer, constrain consistency" pattern (e.g. `s_inv` in `ecdsa.rs`).
  let mut value_bits: Vec<Boolean> = Vec::with_capacity(32);
  for i in 0..32 {
    let bit_val = (digest_id >> (31 - i)) & 1 == 1;
    let bit = AllocatedBit::alloc(cs.namespace(|| format!("digest_id value bit {i}")), Some(bit_val))?;
    value_bits.push(Boolean::from(bit));
  }

  // Maps a window byte index (that's a "value byte", i.e. not the class
  // 1-3 marker at byte_idx 0) to its position in `value_be_bytes`/
  // `value_bits` for a given class — e.g. class 3 (5-byte form) has
  // value bytes at window indices 1,2,3,4, corresponding to
  // value_be_bytes[0,1,2,3] (all four); class 1 (2-byte form) has a
  // single value byte at window index 1, corresponding to
  // value_be_bytes[3] (the low byte) — always right-aligned.
  let value_byte_out_pos = |c: usize, byte_idx: usize| -> Option<usize> {
    let width = cbor_uint::class_byte_width(c);
    if byte_idx >= width {
      return None;
    }
    let value_byte_indices: Vec<usize> = if c == 0 { vec![0] } else { (1..width).collect() };
    let pad = 4 - value_byte_indices.len();
    value_byte_indices.iter().position(|&x| x == byte_idx).map(|pos| pad + pos)
  };

  // 4. For every (byte_idx, bit_idx) in the window, build `expected_bit`
  // — an OR-of-ANDs over classes, each term explicitly gated by
  // `class_selector[c]` (never relying on masking alone to establish
  // exclusivity, which was this function's original, real bug: masking
  // zeroes byte content but doesn't stop a *different* class's
  // contribution from being read in the first place unless it's
  // explicitly ANDed with that class's own selector). Each term is
  // either the class's constant marker bit (weighted by class_selector,
  // a plain linear term) or `class_selector[c] AND value_bits[bit]` (a
  // real product of two witnessed booleans) for a value byte.
  let mut encoded_bits: Vec<Boolean> = Vec::with_capacity(MAX_CBOR_UINT_BYTES * 8);
  for byte_idx in 0..MAX_CBOR_UINT_BYTES {
    for bit_idx in 0..8usize {
      let mut acc: Option<Boolean> = None;
      for (c, &marker) in CLASS_MARKERS.iter().enumerate() {
        if !byte_active_in_class(byte_idx, c) {
          continue;
        }
        let term = if byte_idx == 0 && c != 0 {
          if (marker >> (7 - bit_idx)) & 1 == 1 {
            class_selector[c].clone()
          } else {
            Boolean::constant(false)
          }
        } else {
          let out_pos = value_byte_out_pos(c, byte_idx).expect("byte_idx active in c implies a value-byte mapping");
          let vbit = &value_bits[out_pos * 8 + bit_idx];
          Boolean::and(
            cs.namespace(|| format!("digest_id expected byte {byte_idx} bit {bit_idx} class {c}")),
            &class_selector[c],
            vbit,
          )?
        };
        acc = Some(match acc {
          None => term,
          Some(prev) => Boolean::or(
            cs.namespace(|| format!("digest_id expected-or byte {byte_idx} bit {bit_idx} class {c}")),
            &prev,
            &term,
          )?,
        });
      }
      let expected_bit = acc.unwrap_or(Boolean::constant(false));
      let window_bit = &window_byte_bits(byte_idx)[bit_idx];

      // Enforce window_bit == expected_bit, gated by active[byte_idx]:
      // (window_bit - expected_bit) * active[byte_idx] == 0 — forces
      // equality only when this byte matters for the selected class;
      // vacuous (window_bit unconstrained by this check) otherwise,
      // since bytes beyond the real encoding's width are genuinely
      // don't-care filler from later fields in the real item, not zero.
      cs.enforce(
        || format!("digest_id window byte {byte_idx} bit {bit_idx} matches expected encoding when active"),
        |_| window_bit.lc(CS::one(), Scalar::ONE) - &expected_bit.lc(CS::one(), Scalar::ONE),
        |_| active[byte_idx].lc(CS::one(), Scalar::ONE),
        |lc| lc,
      );

      encoded_bits.push(Boolean::and(
        cs.namespace(|| format!("digest_id mask byte {byte_idx} bit {bit_idx}")),
        window_bit,
        &active[byte_idx],
      )?);
    }
  }

  // 5. Class-0-specific range check: since class 0 has no marker byte,
  // steps above already force window byte 0 == value_be_bytes[3]
  // (digest_id's low byte) when class 0 is selected — but that alone
  // doesn't prevent a class-0 selection for a digest_id >= 24 (the
  // circuit would just also force window byte 0 to be that too-large
  // value, which is a valid witness value for an 8-bit byte, just not a
  // valid class-0 CBOR encoding). Explicitly reject digest_id >= 24 with
  // class 0 selected: any of the top 3 bits set, or both bit16 and bit8
  // set, gated by class_selector[0].
  {
    let byte0 = window_byte_bits(0);
    let bit128_or_64 = Boolean::or(cs.namespace(|| "digest_id class0 top3 or a"), &byte0[0], &byte0[1])?;
    let top3_nonzero = Boolean::or(cs.namespace(|| "digest_id class0 top3 or b"), &bit128_or_64, &byte0[2])?;
    let bit16_and_8 = Boolean::and(cs.namespace(|| "digest_id class0 bit16 and bit8"), &byte0[3], &byte0[4])?;
    let too_big = Boolean::or(cs.namespace(|| "digest_id class0 too_big"), &top3_nonzero, &bit16_and_8)?;
    cs.enforce(
      || "digest_id class0 value < 24 when class 0 selected",
      |_| too_big.lc(CS::one(), Scalar::ONE),
      |_| class_selector[0].lc(CS::one(), Scalar::ONE),
      |lc| lc,
    );
  }
  // 6. Class-3 spec bound: value < 2^31 (ISO 18013-5 §9.1.2.4) — the top
  // bit of the first argument byte (window byte 1) must be 0 whenever
  // class 3 is selected.
  {
    let arg0_top_bit = &window_byte_bits(1)[0];
    cs.enforce(
      || "digest_id class3 value < 2^31 when class 3 selected",
      |_| arg0_top_bit.lc(CS::one(), Scalar::ONE),
      |_| class_selector[3].lc(CS::one(), Scalar::ONE),
      |lc| lc,
    );
  }

  Ok(ExtractedDigestId { value_bits, encoded_bits })
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::Engine_;
  use bellpepper_core::test_cs::TestConstraintSystem;
  use vega_prover::traits::Engine;

  type Scalar = <Engine_ as Engine>::Scalar;
  const ITEM_BITS_LEN: usize = (DIGEST_ID_OFFSET_BYTES + MAX_CBOR_UINT_BYTES + 4) * 8;

  fn alloc_item_bits<CS: ConstraintSystem<Scalar>>(cs: &mut CS, bytes: &[u8]) -> Vec<Boolean> {
    assert_eq!(bytes.len(), ITEM_BITS_LEN / 8);
    bytes
      .iter()
      .flat_map(|byte| (0..8).rev().map(move |i| (byte >> i) & 1u8 == 1u8))
      .enumerate()
      .map(|(i, b)| {
        AllocatedBit::alloc(cs.namespace(|| format!("item bit {i}")), Some(b))
          .map(Boolean::from)
          .expect("alloc")
      })
      .collect()
  }

  fn bits_to_bytes(bits: &[Boolean]) -> Vec<u8> {
    bits
      .chunks(8)
      .map(|byte_bits| {
        byte_bits.iter().enumerate().fold(0u8, |byte, (i, bit)| {
          if bit.get_value().expect("has a value") {
            byte | (1 << (7 - i))
          } else {
            byte
          }
        })
      })
      .collect()
  }

  /// Builds a fake item buffer: `DIGEST_ID_OFFSET_BYTES` bytes of
  /// arbitrary (non-zero, non-matching-any-marker) filler, then
  /// `digest_id`'s real CBOR encoding, then more arbitrary filler —
  /// exercising that only the known offset is ever read.
  fn build_item(digest_id: u32) -> Vec<u8> {
    let mut item = vec![0xAAu8; DIGEST_ID_OFFSET_BYTES];
    let encoded = cbor_uint::encode_cbor_uint(digest_id);
    item.extend_from_slice(&encoded);
    item.resize(ITEM_BITS_LEN / 8, 0xBBu8);
    item
  }

  fn boundary_values() -> Vec<u32> {
    vec![0, 1, 23, 24, 255, 256, 65535, 65536, cbor_uint::MAX_DIGEST_ID]
  }

  #[test]
  fn extracts_the_correct_value_and_encoding_across_all_classes() {
    for digest_id in boundary_values() {
      let item = build_item(digest_id);
      let mut cs = TestConstraintSystem::<Scalar>::new();
      let item_bits = alloc_item_bits(&mut cs, &item);

      let extracted = extract_digest_id::<Scalar, _>(
        cs.namespace(|| format!("digest_id={digest_id}")),
        &item_bits,
        DIGEST_ID_OFFSET_BYTES,
        digest_id,
      )
      .expect("synthesis");

      if let Some(reason) = cs.which_is_unsatisfied() {
        panic!("digest_id={digest_id}: constraint system unsatisfied at: {reason}");
      }
      assert!(cs.is_satisfied(), "digest_id={digest_id}");

      let got_value_bytes = bits_to_bytes(&extracted.value_bits);
      assert_eq!(got_value_bytes, digest_id.to_be_bytes().to_vec(), "digest_id={digest_id}: value mismatch");

      let got_encoded = bits_to_bytes(&extracted.encoded_bits);
      let mut expected_encoded = cbor_uint::encode_cbor_uint(digest_id);
      expected_encoded.resize(MAX_CBOR_UINT_BYTES, 0u8);
      assert_eq!(got_encoded, expected_encoded, "digest_id={digest_id}: encoded bytes mismatch");
    }
  }

  #[test]
  fn ignores_bytes_outside_the_known_window() {
    let digest_id = 100u32; // class 1, 2 bytes
    let base = build_item(digest_id);
    let mut changed = base.clone();
    // Flip filler bytes before and after the digestID window.
    changed[0] ^= 0xFF;
    let last = changed.len() - 1;
    changed[last] ^= 0xFF;

    for bytes in [&base, &changed] {
      let mut cs = TestConstraintSystem::<Scalar>::new();
      let item_bits = alloc_item_bits(&mut cs, bytes);
      let extracted =
        extract_digest_id::<Scalar, _>(cs.namespace(|| "extract"), &item_bits, DIGEST_ID_OFFSET_BYTES, digest_id)
          .expect("synthesis");
      assert!(cs.is_satisfied());
      assert_eq!(bits_to_bytes(&extracted.value_bits), digest_id.to_be_bytes().to_vec());
    }
  }

  /// A witness claiming `digest_id` doesn't match what's actually in the
  /// bytes at the known offset must fail to satisfy the constraints —
  /// rules out a vacuously-satisfiable extraction.
  #[test]
  fn rejects_a_mismatched_witness() {
    let real_digest_id = 26u32; // real value used in mso.rs's own reference vector
    let claimed_digest_id = 27u32; // circuit told to expect a different value
    let item = build_item(real_digest_id);

    let mut cs = TestConstraintSystem::<Scalar>::new();
    let item_bits = alloc_item_bits(&mut cs, &item);
    let _ = extract_digest_id::<Scalar, _>(
      cs.namespace(|| "mismatched"),
      &item_bits,
      DIGEST_ID_OFFSET_BYTES,
      claimed_digest_id,
    )
    .expect("synthesis itself succeeds -- it's the constraints that must fail");

    assert!(!cs.is_satisfied(), "a witness claiming the wrong digest_id must not satisfy the constraints");
  }

  #[test]
  fn rejects_a_malformed_marker_byte() {
    // Corrupt the marker byte to something not in {0..23, 0x18, 0x19, 0x1a}.
    let digest_id = 100u32;
    let mut item = build_item(digest_id);
    item[DIGEST_ID_OFFSET_BYTES] = 0xFF; // was 0x18 for class 1

    let mut cs = TestConstraintSystem::<Scalar>::new();
    let item_bits = alloc_item_bits(&mut cs, &item);
    let _ = extract_digest_id::<Scalar, _>(cs.namespace(|| "malformed"), &item_bits, DIGEST_ID_OFFSET_BYTES, digest_id)
      .expect("synthesis itself succeeds");
    assert!(!cs.is_satisfied(), "a malformed marker byte must not satisfy the constraints");
  }
}
