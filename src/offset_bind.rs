//! Structural binding for offset-based mdoc circuits.
//!
//! # Why this module exists
//!
//! [`crate::mso`] proves things about an mdoc by *reconstructing* the
//! issuer's `Sig_structure` byte-exactly: every `valueDigests` entry gets
//! its own splice slot, so the circuit's shape is fixed at exactly
//! `MAX_CLAIMS_V1` attributes. That is affordable for a 4-attribute mDL
//! and hopeless for a spec-conformant EUDI PID, which carries 34.
//!
//! The alternative — the shape Longfellow uses — is to witness the signed
//! bytes as an opaque blob, hash them once, and prove each fact about a
//! *witnessed offset* into that blob. Hashing is then paid once for the
//! whole credential regardless of how many attributes it has, and the
//! per-attribute splice disappears entirely.
//!
//! What that shape does **not** get for free is soundness, and this
//! module is that missing piece.
//!
//! # The attack this defends against
//!
//! "The 32 bytes at offset `k` equal `SHA-256(item)`" is on its own a
//! useless statement, because it does not say *where* those bytes are.
//!
//! An mdoc's MSO is small and carries no attribute **values** at all —
//! only `docType`, `version`, `validityInfo`, the table of digests,
//! `deviceKeyInfo` and `digestAlgorithm`. Everything in it is chosen by
//! the issuer, with exactly one exception: the holder's own `deviceKey`,
//! whose two 32-byte coordinates are whatever the holder asked to have
//! bound at issuance.
//!
//! So a holder can put 32 bytes of their choosing into the issuer's
//! signed bytes. Set them to `SHA-256` of a fabricated `birth_date` item
//! and an unconstrained offset proof attests to a birthdate the issuer
//! never asserted. The holder does not even need the matching private
//! key, because an age proof never exercises device authentication —
//! they register a public key they cannot use and it works anyway.
//!
//! `tests/pid_offset_binding.rs` carries this out against a real,
//! correctly issued PID and checks that this module is what stops it.
//!
//! # How it is pinned
//!
//! Both ends of the region are anchored to literal CBOR that only the
//! issuer's own MSO structure can produce:
//!
//! * **Start.** At a witnessed offset the bytes must read
//!   `6C "valueDigests" A1 <tstr namespace> <map header>`. That is 38
//!   fixed bytes for a 23-character namespace plus the map header, and
//!   the region begins immediately after it.
//! * **End.** At a witnessed offset the bytes must read
//!   `6D "deviceKeyInfo"` — the MSO key that canonically follows
//!   `valueDigests` (shorter-key-first ordering puts the six MSO keys in
//!   the order `docType`, `version`, `validityInfo`, `valueDigests`,
//!   `deviceKeyInfo`, `digestAlgorithm`). The region ends there.
//!
//! Neither anchor can be forged by planting bytes in an attribute value,
//! because the anchors are only ever *read from inside the region's own
//! neighbourhood in the signed bytes*, and the signature already fixes
//! those bytes. Making a second copy of a 38-byte anchor appear inside a
//! run of SHA-256 outputs is a ~2^304 problem.
//!
//! # What is deliberately *not* proved
//!
//! The offset is bound to the region but **not** to an entry boundary
//! within it. Proving alignment would mean walking all N entries and
//! reading a byte at each derived offset — real cost, for no security:
//! a misaligned 32-byte window inside the region spans fragments of two
//! issuer-computed digests and an entry header, and forcing that to equal
//! `SHA-256` of an attacker-chosen item is a preimage problem. Range
//! binding is what carries the weight; alignment would be decoration.
//!
//! This module is a **prototype for a construction that has not been
//! independently reviewed**. See the crate README.
//!
//! # Scope
//!
//! Single-namespace `valueDigests` only, which is what the EUDI PID
//! rulebook defines (`eu.europa.ec.eudi.pid.1`). A multi-namespace mdoc
//! whose requested namespace is not the last one would need its region
//! terminated by the next namespace's `tstr` header rather than by
//! `deviceKeyInfo`; [`bind_digest_region`] rejects that case rather than
//! binding the wrong range.

use bellpepper_core::{
  boolean::Boolean,
  num::AllocatedNum,
  ConstraintSystem, LinearCombination, SynthesisError,
};
use ff::PrimeField;

/// Bytes packed per field element. 16 bytes is 128 bits, comfortably
/// inside every scalar field this crate targets, and lets a 32-byte
/// digest be compared in two multiplications instead of thirty-two.
pub const BYTES_PER_PACK: usize = 16;

/// The literal that opens the digest region, minus the namespace and the
/// map header: `6C "valueDigests" A1`.
const VALUE_DIGESTS_OPEN: &[u8] = b"\x6cvalueDigests\xa1";

/// The literal that closes it: `6D "deviceKeyInfo"`.
const DEVICE_KEY_INFO: &[u8] = b"\x6ddeviceKeyInfo";

/// `67 "docType"`.
const DOC_TYPE_KEY: &[u8] = b"\x67docType";

/// A byte's value as a linear combination of its eight big-endian bits,
/// scaled by `scale`. Free: no constraint, just a re-weighting of
/// variables the caller has already allocated for the hash.
pub fn byte_lc<Scalar: PrimeField>(
  bits: &[Boolean],
  one: bellpepper_core::Variable,
  byte_idx: usize,
  scale: Scalar,
) -> LinearCombination<Scalar> {
  let mut lc = LinearCombination::zero();
  for j in 0..8 {
    let mut coeff = scale;
    for _ in 0..(7 - j) {
      coeff = coeff.double();
    }
    lc = lc + &bits[byte_idx * 8 + j].lc(one, coeff);
  }
  lc
}

/// `bytes[start .. start+len]` packed big-endian into
/// `ceil(len / BYTES_PER_PACK)` linear combinations. Free.
fn pack_at<Scalar: PrimeField>(
  bits: &[Boolean],
  one: bellpepper_core::Variable,
  start: usize,
  len: usize,
  total_bytes: usize,
) -> Vec<LinearCombination<Scalar>> {
  let packs = len.div_ceil(BYTES_PER_PACK);
  (0..packs)
    .map(|p| {
      let lo = p * BYTES_PER_PACK;
      let hi = (lo + BYTES_PER_PACK).min(len);
      let mut acc = LinearCombination::zero();
      for i in lo..hi {
        let mut coeff = Scalar::ONE;
        for _ in 0..(hi - 1 - i) {
          coeff *= Scalar::from(256u64);
        }
        let idx = start + i;
        if idx < total_bytes {
          acc = acc + &byte_lc::<Scalar>(bits, one, idx, coeff);
        }
      }
      acc
    })
    .collect()
}

fn pack_constant<Scalar: PrimeField>(window: &[u8]) -> Vec<Scalar> {
  window
    .chunks(BYTES_PER_PACK)
    .map(|c| c.iter().fold(Scalar::ZERO, |acc, &b| acc * Scalar::from(256u64) + Scalar::from(b as u64)))
    .collect()
}

/// The result of selecting a window at a witnessed offset.
pub struct SelectedWindow<Scalar: PrimeField> {
  /// The window's bytes, packed [`BYTES_PER_PACK`] at a time.
  pub packs: Vec<AllocatedNum<Scalar>>,
  /// The selected offset itself, as a linear combination of the one-hot
  /// selector. Free to use in arithmetic.
  pub offset: LinearCombination<Scalar>,
}

/// Selects the `window_len`-byte window starting at `real_offset`, where
/// the offset is constrained to lie in `candidates`.
///
/// Cost is `candidates.len() * (1 + ceil(window_len / 16))` constraints,
/// not `* window_len`: the packing is a free re-weighting of bits the
/// circuit has already allocated for the hash, so a 32-byte digest costs
/// two multiplications per candidate rather than thirty-two.
pub fn select_window<Scalar, CS>(
  mut cs: CS,
  bits: &[Boolean],
  native: &[u8],
  candidates: &[usize],
  real_offset: usize,
  window_len: usize,
) -> Result<SelectedWindow<Scalar>, SynthesisError>
where
  Scalar: PrimeField,
  CS: ConstraintSystem<Scalar>,
{
  assert!(candidates.contains(&real_offset), "real offset {real_offset} is not among the candidates");
  let one_hot = crate::onehot_cursor::alloc_one_hot::<Scalar, _>(cs.namespace(|| "offset"), candidates, real_offset)?;
  let n_packs = window_len.div_ceil(BYTES_PER_PACK);

  let mut packs = Vec::with_capacity(n_packs);
  for p in 0..n_packs {
    let lo = p * BYTES_PER_PACK;
    let hi = (lo + BYTES_PER_PACK).min(window_len);
    let value = {
      let mut acc = Scalar::ZERO;
      for i in lo..hi {
        let byte = native.get(real_offset + i).copied().unwrap_or(0);
        acc = acc * Scalar::from(256u64) + Scalar::from(byte as u64);
      }
      acc
    };
    let out = AllocatedNum::alloc(cs.namespace(|| format!("pack {p}")), || Ok(value))?;

    // sum_k one_hot[k] * pack_k == out
    let mut acc = LinearCombination::<Scalar>::zero();
    for (k, &cand) in candidates.iter().enumerate() {
      let w = pack_at::<Scalar>(bits, CS::one(), cand, window_len, native.len())[p].clone();
      let term = AllocatedNum::alloc(cs.namespace(|| format!("term {p} {k}")), || {
        Ok(if cand == real_offset { value } else { Scalar::ZERO })
      })?;
      cs.enforce(
        || format!("select {p} {k}"),
        |lc| lc + &one_hot[k].lc(CS::one(), Scalar::ONE),
        |lc| lc + &w,
        |lc| lc + term.get_variable(),
      );
      acc = acc + term.get_variable();
    }
    cs.enforce(|| format!("pack {p} is the selected window"), |lc| lc + &acc, |lc| lc + CS::one(), |lc| lc + out.get_variable());
    packs.push(out);
  }

  let mut offset = LinearCombination::zero();
  for (k, &cand) in candidates.iter().enumerate() {
    offset = offset + &one_hot[k].lc(CS::one(), Scalar::from(cand as u64));
  }

  Ok(SelectedWindow { packs, offset })
}

/// Constrains a selected window to equal a fixed byte string.
pub fn enforce_window_equals<Scalar, CS>(mut cs: CS, window: &SelectedWindow<Scalar>, expected: &[u8]) -> Result<(), SynthesisError>
where
  Scalar: PrimeField,
  CS: ConstraintSystem<Scalar>,
{
  let packed = pack_constant::<Scalar>(expected);
  assert_eq!(packed.len(), window.packs.len(), "window length disagrees with the expected literal");
  for (p, (var, expect)) in window.packs.iter().zip(packed).enumerate() {
    cs.enforce(
      || format!("window pack {p} matches literal"),
      |lc| lc + var.get_variable(),
      |lc| lc + CS::one(),
      |lc| lc + (expect, CS::one()),
    );
  }
  Ok(())
}

/// Constrains `value - floor >= 0` by witnessing the difference and
/// proving it fits in `bits_needed` bits — the standard R1CS
/// less-than-or-equal, since a negative difference would wrap to a
/// field element far too large to decompose.
pub fn enforce_ge<Scalar, CS>(
  mut cs: CS,
  value: &LinearCombination<Scalar>,
  floor: &LinearCombination<Scalar>,
  native_difference: usize,
  bits_needed: usize,
) -> Result<(), SynthesisError>
where
  Scalar: PrimeField,
  CS: ConstraintSystem<Scalar>,
{
  let mut recomposed = LinearCombination::<Scalar>::zero();
  let mut coeff = Scalar::ONE;
  for i in 0..bits_needed {
    let bit = bellpepper_core::boolean::AllocatedBit::alloc(
      cs.namespace(|| format!("difference bit {i}")),
      Some((native_difference >> i) & 1 == 1),
    )?;
    recomposed = recomposed + (coeff, bit.get_variable());
    coeff = coeff.double();
  }
  cs.enforce(
    || "difference is exactly the decomposed bits",
    |lc| lc + value - floor,
    |lc| lc + CS::one(),
    |lc| lc + &recomposed,
  );
  Ok(())
}

/// Everything [`bind_digest_region`] establishes about where a
/// credential's digests live.
pub struct RegionBinding<Scalar: PrimeField> {
  /// Offset of the first byte of the first `valueDigests` entry.
  pub region_start: LinearCombination<Scalar>,
  /// Offset one past the region's last byte — the `deviceKeyInfo` key.
  pub region_end: LinearCombination<Scalar>,
  /// The credential's `docType`, read from the signed bytes so a verifier
  /// learns which document type the proof is about.
  pub doc_type: Vec<AllocatedNum<Scalar>>,
}

/// Native (out-of-circuit) landmarks the prover supplies as witness.
/// A prover that lies about any of them fails the anchor checks.
#[derive(Clone, Copy, Debug)]
pub struct Landmarks {
  /// Offset of the `6C "valueDigests"` key.
  pub value_digests_key: usize,
  /// Offset of the first entry — the byte after the namespace map header.
  pub region_start: usize,
  /// Offset of the `6D "deviceKeyInfo"` key.
  pub device_key_info: usize,
  /// Offset of the `67 "docType"` key.
  pub doc_type_key: usize,
}

/// Proves that `region_start .. region_end` really is the requested
/// namespace's digest region inside the signed bytes, and reads out the
/// credential's `docType`.
///
/// `candidates` bounds where each landmark may sit; passing every byte
/// offset is sound but pays for candidates a real MSO can never use, so
/// callers should pass a realistic window.
pub fn bind_digest_region<Scalar, CS>(
  mut cs: CS,
  bits: &[Boolean],
  native: &[u8],
  namespace: &str,
  doc_type_len: usize,
  num_entries: usize,
  landmarks: Landmarks,
) -> Result<RegionBinding<Scalar>, SynthesisError>
where
  Scalar: PrimeField,
  CS: ConstraintSystem<Scalar>,
{
  assert!(num_entries < 256, "this binding encodes the namespace map header as 1 or 2 bytes");

  // ---- Start anchor: `6C "valueDigests" A1 <tstr ns> <map hdr>` ----
  let mut open = VALUE_DIGESTS_OPEN.to_vec();
  assert!(namespace.len() < 24, "namespace tstr header is assumed to be one byte");
  open.push(0x60 | namespace.len() as u8);
  open.extend_from_slice(namespace.as_bytes());
  if num_entries < 24 {
    open.push(0xa0 | num_entries as u8);
  } else {
    open.push(0xb8);
    open.push(num_entries as u8);
  }
  let open_len = open.len();

  // A real MSO puts `valueDigests` after docType, version and
  // validityInfo, all of which are short and bounded; a generous window
  // still costs far less than the hash it sits beside.
  let start_candidates: Vec<usize> = (0..native.len().saturating_sub(open_len)).collect();
  let open_window = select_window::<Scalar, _>(
    cs.namespace(|| "valueDigests anchor"),
    bits,
    native,
    &start_candidates,
    landmarks.value_digests_key,
    open_len,
  )?;
  enforce_window_equals(cs.namespace(|| "valueDigests literal"), &open_window, &open)?;

  // The region starts immediately after the anchor.
  let region_start = open_window.offset.clone() + (Scalar::from(open_len as u64), CS::one());

  // ---- End anchor: `6D "deviceKeyInfo"` ----------------------------
  let end_candidates: Vec<usize> = (0..native.len().saturating_sub(DEVICE_KEY_INFO.len())).collect();
  let end_window = select_window::<Scalar, _>(
    cs.namespace(|| "deviceKeyInfo anchor"),
    bits,
    native,
    &end_candidates,
    landmarks.device_key_info,
    DEVICE_KEY_INFO.len(),
  )?;
  enforce_window_equals(cs.namespace(|| "deviceKeyInfo literal"), &end_window, DEVICE_KEY_INFO)?;
  let region_end = end_window.offset.clone();

  // The region must be non-empty and must not run backwards. Without
  // this a prover could claim an end anchor that precedes the start and
  // then satisfy the digest range check vacuously.
  assert!(landmarks.device_key_info > landmarks.region_start, "landmarks describe an empty or inverted region");
  enforce_ge(
    cs.namespace(|| "region end follows region start"),
    &region_end,
    &region_start,
    landmarks.device_key_info - landmarks.region_start,
    16,
  )?;

  // ---- docType, read out for the verifier --------------------------
  let doc_type_window_len = DOC_TYPE_KEY.len() + 1 + doc_type_len;
  let doc_candidates: Vec<usize> = (0..native.len().saturating_sub(doc_type_window_len)).collect();
  let doc_window = select_window::<Scalar, _>(
    cs.namespace(|| "docType"),
    bits,
    native,
    &doc_candidates,
    landmarks.doc_type_key,
    doc_type_window_len,
  )?;
  // Only the `67 "docType"` key and the value's tstr header are fixed;
  // the value itself is what the verifier learns.
  let mut key_prefix = DOC_TYPE_KEY.to_vec();
  key_prefix.push(0x60 | doc_type_len as u8);
  // Constrain the key bytes by comparing the first pack against a
  // literal built from the real prefix plus the real docType bytes: the
  // docType value is public output, so there is nothing to hide in it.
  let doc_type_bytes = &native[landmarks.doc_type_key..landmarks.doc_type_key + doc_type_window_len];
  assert_eq!(&doc_type_bytes[..key_prefix.len()], key_prefix.as_slice(), "docType landmark does not point at the docType key");
  enforce_window_equals(cs.namespace(|| "docType literal"), &doc_window, doc_type_bytes)?;

  Ok(RegionBinding { region_start, region_end, doc_type: doc_window.packs })
}

#[cfg(test)]
mod tests {
  use super::*;
  use bellpepper_core::{boolean::AllocatedBit, test_cs::TestConstraintSystem};

  type Scalar = <crate::Engine_ as vega_prover::traits::Engine>::Scalar;

  fn alloc_bits<CS: ConstraintSystem<Scalar>>(cs: &mut CS, bytes: &[u8]) -> Vec<Boolean> {
    bytes
      .iter()
      .flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1 == 1))
      .enumerate()
      .map(|(i, b)| AllocatedBit::alloc(cs.namespace(|| format!("bit {i}")), Some(b)).map(Boolean::from).unwrap())
      .collect()
  }

  #[test]
  fn selects_the_window_at_the_witnessed_offset() {
    let data: Vec<u8> = (0..64u8).collect();
    let mut cs = TestConstraintSystem::<Scalar>::new();
    let bits = alloc_bits(&mut cs, &data);
    let cands: Vec<usize> = (0..32).collect();
    let w = select_window::<Scalar, _>(cs.namespace(|| "w"), &bits, &data, &cands, 7, 16).unwrap();
    enforce_window_equals(cs.namespace(|| "eq"), &w, &data[7..23]).unwrap();
    assert!(cs.is_satisfied());
  }

  #[test]
  fn rejects_a_window_that_does_not_match_the_literal() {
    let data: Vec<u8> = (0..64u8).collect();
    let mut cs = TestConstraintSystem::<Scalar>::new();
    let bits = alloc_bits(&mut cs, &data);
    let cands: Vec<usize> = (0..32).collect();
    let w = select_window::<Scalar, _>(cs.namespace(|| "w"), &bits, &data, &cands, 7, 16).unwrap();
    // Ask it to prove the window at offset 7 is the window at offset 8.
    enforce_window_equals(cs.namespace(|| "eq"), &w, &data[8..24]).unwrap();
    assert!(!cs.is_satisfied(), "a mismatched literal must not be satisfiable");
  }

  #[test]
  fn enforce_ge_accepts_a_real_ordering_and_rejects_an_inverted_one() {
    for (a, b, want) in [(100usize, 40usize, true), (40, 100, false)] {
      let mut cs = TestConstraintSystem::<Scalar>::new();
      let hi = AllocatedNum::alloc(cs.namespace(|| "hi"), || Ok(Scalar::from(a as u64))).unwrap();
      let lo = AllocatedNum::alloc(cs.namespace(|| "lo"), || Ok(Scalar::from(b as u64))).unwrap();
      let diff = a.wrapping_sub(b);
      enforce_ge(
        cs.namespace(|| "ge"),
        &(LinearCombination::zero() + hi.get_variable()),
        &(LinearCombination::zero() + lo.get_variable()),
        diff & 0xffff,
        16,
      )
      .unwrap();
      assert_eq!(cs.is_satisfied(), want, "ordering {a} >= {b} should be {want}");
    }
  }
}
