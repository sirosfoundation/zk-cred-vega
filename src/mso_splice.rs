//! Assembles the whole variable-length MSO `Sig_structure`: a fixed
//! prefix, 4 `valueDigests` entries (each `digestID` — 1, 2, 3, or 5 CBOR
//! bytes, per `cbor_uint` — immediately followed by a fixed-width tail,
//! `0x58 0x20` bstr header + the 32-byte digest itself, back to back with
//! no padding), and a fixed suffix (`deviceKeyInfo`/`validityInfo`) —
//! matching a real issuer's exact bytes so the whole thing's SHA-256
//! comes out byte-identical (see the digestID-binding
//! writeup). `mso.rs` builds the actual prefix/entries/suffix content;
//! this module owns only the variable-width placement math.
//!
//! The circuit shape must stay fixed regardless of which widths are
//! chosen (NeutronNova folds instances of identical R1CS shape), so this
//! can't be "shift bytes around a buffer" at synthesis time — every
//! output wire's value is instead computed directly, for the *specific*
//! witnessed widths, from one-hot selectors chained via
//! [`crate::onehot_cursor`]. Each subsequent entry's (and the suffix's)
//! start position depends on the sum of all preceding widths; naively
//! tracking every `(w0,w1,w2,w3)` combination is `4^4 = 256` states by
//! the last entry — `onehot_cursor::convolve_sum` collapses that to the
//! much smaller set of *distinct achievable offsets* (at most 17 by the
//! last entry) by deduplicating combinations that land on the same value.

use crate::cbor_uint::{self, MAX_CBOR_UINT_BYTES};
use crate::onehot_cursor::{alloc_one_hot, convolve_sum};
use bellpepper_core::{
  boolean::{AllocatedBit, Boolean},
  ConstraintSystem, SynthesisError,
};
use ff::PrimeField;

/// The four canonical CBOR major-type-0 widths a `digestID` can take
/// (see `cbor_uint::length_class`).
pub const DIGEST_ID_WIDTHS: [usize; 4] = [1, 2, 3, 5];

/// `0x58 0x20` (bstr, 2-byte length header, 32) + the 32-byte digest
/// itself — always fully real, no padding, for every entry.
pub const ENTRY_TAIL_LEN: usize = 2 + 32;

/// Number of digestID entries this section supports — matches
/// `MAX_CLAIMS_V1`. Kept as a local constant (rather than importing
/// `crate::MAX_CLAIMS_V1`) so this module's own tests can exercise it
/// independently; the two must agree wherever this is wired into `mso.rs`.
pub const NUM_ENTRIES: usize = 4;

/// Upper bound on the `valueDigests` entries' total byte length: every
/// entry at its widest (5-byte digestID + fixed tail). Excludes the
/// surrounding prefix/suffix, whose lengths are caller-determined.
pub const MAX_DIGEST_SECTION_BYTES: usize = NUM_ENTRIES * (MAX_CBOR_UINT_BYTES + ENTRY_TAIL_LEN);

/// One entry's witness: the claim digest's numeric `digestID` (native —
/// used to compute its CBOR encoding and one-hot width selector) and its
/// tail content, already allocated as exactly `ENTRY_TAIL_LEN*8` bits
/// (`0x58 0x20` + the 32 digest bytes).
pub struct DigestIdEntry {
  pub digest_id: u32,
  pub tail_bits: Vec<Boolean>,
}

/// Allocates `bytes` as `bytes.len()*8` witnessed `Boolean`s, MSB-first
/// per byte — the same convention used throughout this crate.
pub(crate) fn alloc_byte_bits<Scalar, CS>(mut cs: CS, bytes: &[u8]) -> Result<Vec<Boolean>, SynthesisError>
where
  Scalar: PrimeField,
  CS: ConstraintSystem<Scalar>,
{
  bytes
    .iter()
    .flat_map(|byte| (0..8).rev().map(move |i| (byte >> i) & 1u8 == 1u8))
    .enumerate()
    .map(|(i, b)| AllocatedBit::alloc(cs.namespace(|| format!("byte-bit {i}")), Some(b)).map(Boolean::from))
    .collect()
}

/// Native reference matching [`assemble_mso_sig_structure`] exactly:
/// `prefix` and `suffix` are always fully real, `tails[i]` must be
/// exactly [`ENTRY_TAIL_LEN`] bytes (`0x58 0x20` + the 32-byte digest).
/// Returns the assembled bytes and that real length (== the input bytes'
/// total length here, since nothing native is padded).
pub fn native_mso_sig_structure_bytes(prefix: &[u8], digest_ids: &[u32; NUM_ENTRIES], tails: &[[u8; ENTRY_TAIL_LEN]; NUM_ENTRIES], suffix: &[u8]) -> Vec<u8> {
  let mut out = Vec::with_capacity(prefix.len() + MAX_DIGEST_SECTION_BYTES + suffix.len());
  out.extend_from_slice(prefix);
  for i in 0..NUM_ENTRIES {
    out.extend_from_slice(&cbor_uint::encode_cbor_uint(digest_ids[i]));
    out.extend_from_slice(&tails[i]);
  }
  out.extend_from_slice(suffix);
  out
}

/// One placement source contributing to the assembled output buffer.
/// Every output byte is covered by at most one *active* placement for any
/// given witness (the cursors are constructed so ranges never overlap) —
/// each is an `OR`-of-`AND`s over `cursor_values` (and, for `Variable`,
/// also `width_values`), so summing them at the end is safe.
enum Placement<'a> {
  /// `content` (padded to `MAX_CBOR_UINT_BYTES` bytes) contributes its
  /// first `width` bytes at output offset `cursor`, for the active
  /// `(cursor, width)` pair.
  Variable {
    cursor_onehot: &'a [Boolean],
    cursor_values: &'a [usize],
    width_onehot: &'a [Boolean],
    content: &'a [Boolean],
  },
  /// `content` (always fully real, fixed length) contributes at output
  /// offset `cursor`, for the active `cursor` value.
  Fixed { cursor_onehot: &'a [Boolean], cursor_values: &'a [usize], content: &'a [Boolean] },
}

/// Builds `output_len_bytes*8` output bits from `placements` (covering
/// byte offsets `[range.0, range.1)`; bytes outside that range are left
/// `Boolean::constant(false)` placeholders for the caller to overwrite
/// directly — used here so the always-real, single-valued `prefix` region
/// can be copied straight in without paying for a trivial one-hot AND).
/// For each bit in range, `OR`s together every placement's contribution
/// (each already exclusive within itself via one-hot cursors/widths), so
/// unions across *different* placements are safe exactly when their
/// ranges never overlap for any witness — true here because entry `i+1`
/// (and the suffix) never starts before entry `i` ends.
fn assemble_from_placements<Scalar, CS>(mut cs: CS, output_len_bytes: usize, range: (usize, usize), placements: &[Placement]) -> Result<Vec<Boolean>, SynthesisError>
where
  Scalar: PrimeField,
  CS: ConstraintSystem<Scalar>,
{
  let mut out: Vec<Boolean> = Vec::with_capacity(output_len_bytes * 8);
  for p_byte in 0..output_len_bytes {
    if p_byte < range.0 || p_byte >= range.1 {
      out.extend(std::iter::repeat_n(Boolean::constant(false), 8));
      continue;
    }
    for bit_idx in 0..8 {
      let mut acc: Option<Boolean> = None;
      for (p_idx, placement) in placements.iter().enumerate() {
        match placement {
          Placement::Variable {
            cursor_onehot,
            cursor_values,
            width_onehot,
            content,
          } => {
            for (k, &c) in cursor_values.iter().enumerate() {
              for (w_idx, &w) in DIGEST_ID_WIDTHS.iter().enumerate() {
                if p_byte < c || p_byte >= c + w {
                  continue;
                }
                let rel_byte = p_byte - c;
                let content_bit = &content[rel_byte * 8 + bit_idx];
                let both = Boolean::and(
                  cs.namespace(|| format!("splice p{p_idx} byte{p_byte} bit{bit_idx} k{k} w{w_idx} cursor-width")),
                  &cursor_onehot[k],
                  &width_onehot[w_idx],
                )?;
                let term = Boolean::and(
                  cs.namespace(|| format!("splice p{p_idx} byte{p_byte} bit{bit_idx} k{k} w{w_idx} content")),
                  &both,
                  content_bit,
                )?;
                acc = Some(match acc {
                  None => term,
                  Some(prev) => Boolean::or(
                    cs.namespace(|| format!("splice-or p{p_idx} byte{p_byte} bit{bit_idx} k{k} w{w_idx}")),
                    &prev,
                    &term,
                  )?,
                });
              }
            }
          }
          Placement::Fixed {
            cursor_onehot,
            cursor_values,
            content,
          } => {
            let content_len_bytes = content.len() / 8;
            for (k, &c) in cursor_values.iter().enumerate() {
              if p_byte < c || p_byte >= c + content_len_bytes {
                continue;
              }
              let rel_byte = p_byte - c;
              let content_bit = &content[rel_byte * 8 + bit_idx];
              let term = Boolean::and(
                cs.namespace(|| format!("splice p{p_idx} byte{p_byte} bit{bit_idx} k{k} content")),
                &cursor_onehot[k],
                content_bit,
              )?;
              acc = Some(match acc {
                None => term,
                Some(prev) => Boolean::or(cs.namespace(|| format!("splice-or p{p_idx} byte{p_byte} bit{bit_idx} k{k}")), &prev, &term)?,
              });
            }
          }
        }
      }
      out.push(acc.unwrap_or(Boolean::constant(false)));
    }
  }
  Ok(out)
}

/// Assembles the whole `Sig_structure` (see module doc): `prefix_bits`
/// unconditionally at offset 0, then the 4 `valueDigests` entries, then
/// `suffix_bits` immediately after the last entry's tail — returning the
/// fixed-size (`(prefix_bits.len() + MAX_DIGEST_SECTION_BYTES*8 +
/// suffix_bits.len())`-bit) buffer and the native real (non-don't-care)
/// length in bytes. The latter feeds `sha256_var_sized`'s `real_len` for
/// hashing this buffer.
pub fn assemble_mso_sig_structure<Scalar, CS>(
  mut cs: CS,
  prefix_bits: &[Boolean],
  entries: &[DigestIdEntry; NUM_ENTRIES],
  suffix_bits: &[Boolean],
) -> Result<(Vec<Boolean>, usize), SynthesisError>
where
  Scalar: PrimeField,
  CS: ConstraintSystem<Scalar>,
{
  assert_eq!(prefix_bits.len() % 8, 0);
  assert_eq!(suffix_bits.len() % 8, 0);
  for e in entries {
    assert_eq!(e.tail_bits.len(), ENTRY_TAIL_LEN * 8, "tail_bits must be exactly ENTRY_TAIL_LEN bytes");
    assert!(e.digest_id <= cbor_uint::MAX_DIGEST_ID, "digestID must be < 2^31");
  }
  let prefix_len = prefix_bits.len() / 8;
  let suffix_len = suffix_bits.len() / 8;
  let output_len_bytes = prefix_len + MAX_DIGEST_SECTION_BYTES + suffix_len;

  // Per-entry: encode digest_id's real bytes (padded to MAX_CBOR_UINT_BYTES),
  // allocate as witnessed bits, and a one-hot width selector.
  let mut encoded_content: Vec<Vec<Boolean>> = Vec::with_capacity(NUM_ENTRIES);
  let mut width_onehots: Vec<Vec<Boolean>> = Vec::with_capacity(NUM_ENTRIES);
  let mut real_widths = [0usize; NUM_ENTRIES];
  for (i, e) in entries.iter().enumerate() {
    let mut encoded = cbor_uint::encode_cbor_uint(e.digest_id);
    real_widths[i] = encoded.len();
    encoded.resize(MAX_CBOR_UINT_BYTES, 0u8);
    let bits = alloc_byte_bits::<Scalar, _>(cs.namespace(|| format!("digest_id {i} encoded bytes")), &encoded)?;
    encoded_content.push(bits);
    let onehot = alloc_one_hot::<Scalar, _>(cs.namespace(|| format!("digest_id {i} width")), &DIGEST_ID_WIDTHS, real_widths[i])?;
    width_onehots.push(onehot);
  }

  // Cursor chaining: `start_i` is entry i's digestID start offset
  // (absolute, i.e. already includes `prefix_len`); `end_i` is where its
  // tail starts (== start_i + real width). `start_0` is the trivial
  // single-value `{prefix_len}` selector (`Boolean::constant(true)` — no
  // allocation, no convolution needed since there's nothing preceding it
  // to sum with). Every cursor distribution is computed up front into
  // owned, function-lifetime `Vec`s so the `Placement`s built below can
  // borrow from them with ordinary (non-`unsafe`) lifetimes.
  let mut start_onehots: Vec<Vec<Boolean>> = Vec::with_capacity(NUM_ENTRIES);
  let mut start_values_list: Vec<Vec<usize>> = Vec::with_capacity(NUM_ENTRIES);
  let mut end_onehots: Vec<Vec<Boolean>> = Vec::with_capacity(NUM_ENTRIES);
  let mut end_values_list: Vec<Vec<usize>> = Vec::with_capacity(NUM_ENTRIES);

  start_onehots.push(vec![Boolean::constant(true)]);
  start_values_list.push(vec![prefix_len]);

  for i in 0..NUM_ENTRIES {
    let (end_onehot, end_values) = if start_values_list[i].len() == 1 {
      // No convolution needed: summing a single-valued selector with
      // width_onehot is exactly width_onehot itself, shifted by
      // start_values_list[i][0].
      let shifted: Vec<usize> = DIGEST_ID_WIDTHS.iter().map(|&w| w + start_values_list[i][0]).collect();
      (width_onehots[i].clone(), shifted)
    } else {
      convolve_sum::<Scalar, _>(
        cs.namespace(|| format!("entry {i} end cursor")),
        &start_onehots[i],
        &start_values_list[i],
        &width_onehots[i],
        &DIGEST_ID_WIDTHS,
      )?
    };
    // Always compute the next start (used by entry i+1, or — for the
    // last entry — by the suffix placement below).
    start_onehots.push(end_onehot.clone());
    start_values_list.push(end_values.iter().map(|&v| v + ENTRY_TAIL_LEN).collect());
    end_onehots.push(end_onehot);
    end_values_list.push(end_values);
  }
  let suffix_cursor_onehot = &start_onehots[NUM_ENTRIES];
  let suffix_cursor_values = &start_values_list[NUM_ENTRIES];

  let mut placements: Vec<Placement> = Vec::with_capacity(NUM_ENTRIES * 2 + 1);
  for i in 0..NUM_ENTRIES {
    placements.push(Placement::Variable {
      cursor_onehot: &start_onehots[i],
      cursor_values: &start_values_list[i],
      width_onehot: &width_onehots[i],
      content: &encoded_content[i],
    });
  }
  for i in 0..NUM_ENTRIES {
    placements.push(Placement::Fixed {
      cursor_onehot: &end_onehots[i],
      cursor_values: &end_values_list[i],
      content: &entries[i].tail_bits,
    });
  }
  placements.push(Placement::Fixed {
    cursor_onehot: suffix_cursor_onehot,
    cursor_values: suffix_cursor_values,
    content: suffix_bits,
  });

  let real_digest_section_len: usize = real_widths.iter().sum::<usize>() + NUM_ENTRIES * ENTRY_TAIL_LEN;
  let real_len = prefix_len + real_digest_section_len + suffix_len;

  let mut assembled = assemble_from_placements::<Scalar, _>(
    cs.namespace(|| "assemble"),
    output_len_bytes,
    (prefix_len, prefix_len + MAX_DIGEST_SECTION_BYTES + suffix_len),
    &placements,
  )?;
  assembled[0..prefix_bits.len()].clone_from_slice(prefix_bits);
  Ok((assembled, real_len))
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::Engine_;
  use bellpepper_core::test_cs::TestConstraintSystem;
  use vega_prover::traits::Engine;

  type Scalar = <Engine_ as Engine>::Scalar;

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

  fn make_tail(fill: u8) -> [u8; ENTRY_TAIL_LEN] {
    let mut t = [fill; ENTRY_TAIL_LEN];
    t[0] = 0x58;
    t[1] = 0x20;
    t
  }

  fn run_case(digest_ids: [u32; NUM_ENTRIES]) {
    let prefix = b"PREFIX-CONTENT".to_vec();
    let suffix = b"SUFFIX-TAIL-CONTENT-AFTER-DIGESTS".to_vec();
    let tails: [[u8; ENTRY_TAIL_LEN]; NUM_ENTRIES] = std::array::from_fn(|i| make_tail(0x10 + i as u8));
    let mut cs = TestConstraintSystem::<Scalar>::new();

    let prefix_bits = alloc_byte_bits::<Scalar, _>(cs.namespace(|| "prefix"), &prefix).expect("alloc prefix");
    let suffix_bits = alloc_byte_bits::<Scalar, _>(cs.namespace(|| "suffix"), &suffix).expect("alloc suffix");
    let entries: [DigestIdEntry; NUM_ENTRIES] = std::array::from_fn(|i| {
      let tail_bits = alloc_byte_bits::<Scalar, _>(cs.namespace(|| format!("tail {i}")), &tails[i]).expect("alloc tail");
      DigestIdEntry {
        digest_id: digest_ids[i],
        tail_bits,
      }
    });

    let (assembled, real_len) =
      assemble_mso_sig_structure::<Scalar, _>(cs.namespace(|| "assemble"), &prefix_bits, &entries, &suffix_bits).expect("assemble");

    if let Some(reason) = cs.which_is_unsatisfied() {
      panic!("digest_ids={digest_ids:?}: unsatisfied at {reason}");
    }
    assert!(cs.is_satisfied(), "digest_ids={digest_ids:?}");

    let expected_bytes = native_mso_sig_structure_bytes(&prefix, &digest_ids, &tails, &suffix);
    assert_eq!(real_len, expected_bytes.len(), "digest_ids={digest_ids:?}");
    let got_bytes = bits_to_bytes(&assembled);
    assert_eq!(&got_bytes[..real_len], &expected_bytes[..], "digest_ids={digest_ids:?}");
    assert_eq!(got_bytes.len(), prefix.len() + MAX_DIGEST_SECTION_BYTES + suffix.len());
  }

  #[test]
  fn assembles_correctly_when_every_entry_is_the_narrowest_width() {
    run_case([0, 1, 2, 3]);
  }

  #[test]
  fn assembles_correctly_when_every_entry_is_the_widest_width() {
    run_case([cbor_uint::MAX_DIGEST_ID, cbor_uint::MAX_DIGEST_ID - 1, 70000, 100000]);
  }

  #[test]
  fn assembles_correctly_for_mixed_widths_across_all_four_classes() {
    // widths 1,2,3,5 in one combination, and a rotation of it, to exercise
    // the cursor chain in more than one order.
    run_case([5, 26, 300, 70000]);
    run_case([70000, 300, 26, 5]);
  }

  #[test]
  fn assembles_correctly_for_a_real_reference_vector_style_case() {
    // Matches mso.rs's own reference-vector digestIDs (0-3 range) plus one
    // realistic larger value, confirming both the old narrow-range case
    // and genuine spec-range interop still work through the same code path.
    run_case([0, 1, 2, 39]);
  }

  #[test]
  fn assembles_correctly_with_an_empty_prefix_or_suffix() {
    let digest_ids = [5u32, 26, 300, 70000];
    let tails: [[u8; ENTRY_TAIL_LEN]; NUM_ENTRIES] = std::array::from_fn(|i| make_tail(0x10 + i as u8));
    let mut cs = TestConstraintSystem::<Scalar>::new();
    let entries: [DigestIdEntry; NUM_ENTRIES] = std::array::from_fn(|i| {
      let tail_bits = alloc_byte_bits::<Scalar, _>(cs.namespace(|| format!("tail {i}")), &tails[i]).expect("alloc tail");
      DigestIdEntry {
        digest_id: digest_ids[i],
        tail_bits,
      }
    });
    let (assembled, real_len) = assemble_mso_sig_structure::<Scalar, _>(cs.namespace(|| "assemble"), &[], &entries, &[]).expect("assemble");
    assert!(cs.is_satisfied());
    let expected_bytes = native_mso_sig_structure_bytes(&[], &digest_ids, &tails, &[]);
    assert_eq!(real_len, expected_bytes.len());
    let got_bytes = bits_to_bytes(&assembled);
    assert_eq!(&got_bytes[..real_len], &expected_bytes[..]);
  }
}
