//! Variable-length SHA-256 for a fixed-shape circuit.
//!
//! [`crate::ClaimDigestStepCircuit`] previously hashed every claim
//! zero-padded to a fixed [`crate::MAX_CLAIM_BYTES_V1`] width — cheap and
//! simple, but `SHA-256(padded bytes)` is a different value from
//! `SHA-256(real bytes)` for any message that isn't already exactly that
//! width, which is every real ISO 18013-5 `IssuerSignedItem` (see
//! `HANDOFF.md`'s "real-interop gap" writeup). This module computes the
//! real digest of a real, witnessed-length message instead, while still
//! keeping the circuit's R1CS shape independent of that length (required
//! for NeutronNova folding across step instances).
//!
//! ## The core idea
//!
//! A message of `n` bytes, real SHA-256-padded, occupies
//! `terminal_block_for_len(n)` 512-bit blocks: `n` bytes of real content,
//! then a single `0x80` marker byte, then zero bytes, then the message's
//! bit-length as a big-endian `u64`, with the marker/zero/length tail
//! always ending exactly at a block boundary. This module:
//!
//! 1. Witnesses `real_len` as a **one-hot** selector (`len_selector[k] ==
//!    1` iff `real_len == k`) rather than as a plain number — this turns
//!    every downstream "does this apply for this real_len" question into
//!    a *linear combination* over `len_selector` with **compile-time**
//!    coefficients (computed by [`injected_byte`], pure Rust, no circuit
//!    involved), not a multiplication of two witnessed values. The only
//!    genuine multiplication needed anywhere in this construction is
//!    "is this byte position still real message content" (`msg_active`)
//!    times the actual message bit — structurally the same one
//!    multiplication-per-bit pattern already used and reviewed for
//!    [`crate::ClaimDigestStepCircuit`]'s disclosure masking.
//! 2. Builds the full, fixed-size (`BUFFER_BYTES`), correctly-padded
//!    buffer bit-by-bit from that selector.
//! 3. Runs [`bellpepper::gadgets::sha256::sha256_compression_function`]
//!    over all [`NUM_BLOCKS`] blocks *unconditionally* (fixed R1CS shape),
//!    collecting the intermediate state after each block.
//! 4. Selects the state after the *real* terminal block — again via a
//!    linear combination over the same one-hot selector, not a
//!    multiplication of two witnessed block indices.
//!
//! This is the standard "select via one-hot length" technique used by
//! variable-length hash circuits elsewhere (e.g. `noway/sha256-var-circom`
//! for Circom); the implementation here is our own from first principles
//! rather than a direct port, since reviewing that reference closely
//! raised a question about whether it independently constrains bytes
//! beyond the witnessed length to be well-formed, or relies on a caller
//! to have already zeroed them — precisely the kind of ambiguity this
//! crate's practice is to resolve by writing (and testing) our own
//! version rather than trusting silently.
//!
//! **This is genuinely novel, soundness-critical circuit code and has NOT
//! had an independent review yet** — flag it for one before trusting it
//! beyond this crate's own test suite, same as the ECDSA gadget was
//! before its review found two critical bugs.

use bellpepper::gadgets::sha256::sha256_compression_function;
use bellpepper_core::{
  boolean::{AllocatedBit, Boolean},
  ConstraintSystem, LinearCombination, SynthesisError,
};
use bellpepper::gadgets::uint32::UInt32;
use ff::PrimeField;

/// SHA-256's standard initialization vector (FIPS 180-4 §5.3.3) —
/// hardcoded here because `bellpepper`'s own copy (`get_sha256_iv`) is
/// private to its crate.
const SHA256_IV: [u32; 8] = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Maximum real message length this gadget supports. Chosen to
/// comfortably fit real ISO 18013-5 `IssuerSignedItemBytes` for ordinary
/// attributes (measured 79-95 bytes against a real signed test vector —
/// see `HANDOFF.md`), with headroom. Large binary values (portraits,
/// `signature_usual_mark`) are out of scope for this claim-byte budget,
/// same kind of v1/v2 scoping limitation as `MAX_CLAIMS_V1`.
pub const MAX_VAR_MESSAGE_BYTES: usize = 128;

/// Number of 512-bit blocks this gadget always processes, regardless of
/// the real message length — the fixed R1CS shape NeutronNova folding
/// requires. Must be >= `terminal_block_for_len(MAX_VAR_MESSAGE_BYTES)`;
/// see that function's doc for the arithmetic.
pub const NUM_BLOCKS: usize = 3;

/// Physical buffer size in bytes (`NUM_BLOCKS` blocks of 64 bytes each).
pub const BUFFER_BYTES: usize = NUM_BLOCKS * 64;

/// How many 512-bit blocks a real SHA-256 padding of an `n`-byte message
/// occupies: `n` bytes of message, one `0x80` marker byte, zero-padding,
/// and an 8-byte big-endian bit-length, with the whole thing rounded up
/// to the next multiple of 64 bytes (512 bits) — RFC 6234 §4.1.
///
/// Monotonically non-decreasing in `n` (more message bytes never need
/// fewer blocks), so the maximum over `0..=MAX_VAR_MESSAGE_BYTES` is
/// `terminal_block_for_len(MAX_VAR_MESSAGE_BYTES)`, which is what
/// [`NUM_BLOCKS`] must be at least.
pub fn terminal_block_for_len(n: usize) -> usize {
  let total_bits = n * 8 + 1 + 64;
  total_bits.div_ceil(512)
}

/// The exact byte value SHA-256 padding places at `buffer[byte_idx]` for
/// a message of length `real_len`, *given that `byte_idx >= real_len`*
/// (i.e. this position is not real message content for this `real_len`)
/// — `0x80` at the marker position, `0x00` in the zero-padding gap, or
/// the appropriate byte of `real_len * 8` (big-endian `u64`) within the
/// terminal block's last 8 bytes. Returns `None` if `byte_idx < real_len`
/// (a real message byte — the caller supplies that value instead) or if
/// `byte_idx` is outside the buffer entirely for this `real_len` (can't
/// happen when called correctly, kept as a safety net).
///
/// Pure Rust, no circuit — this is where all the position arithmetic
/// lives, so it can be unit-tested directly and reused identically by
/// both the native buffer builder (for witnessing) and the in-circuit
/// linear-combination builder (for constraining), guaranteeing they
/// can't drift apart.
pub fn injected_byte(byte_idx: usize, real_len: usize) -> Option<u8> {
  if byte_idx < real_len {
    return None;
  }
  if byte_idx == real_len {
    return Some(0x80);
  }
  let terminal_block = terminal_block_for_len(real_len);
  let len_field_start = terminal_block * 64 - 8;
  if byte_idx < len_field_start {
    return Some(0x00);
  }
  if byte_idx < len_field_start + 8 {
    let len_bits: u64 = (real_len as u64) * 8;
    let offset = byte_idx - len_field_start;
    return Some(len_bits.to_be_bytes()[offset]);
  }
  // Beyond the terminal block entirely — never read (the block-selection
  // step only looks at the state after `terminal_block`), value doesn't
  // matter, but 0 keeps things well-defined.
  Some(0x00)
}

/// Builds the full, correctly-padded buffer for a real message, natively
/// (for witness generation) — the same value the in-circuit construction
/// is constrained to equal. `max_message_bytes`/`num_blocks` size the
/// buffer the same way [`sha256_var_sized`]'s do — see that function.
#[allow(clippy::needless_range_loop)] // `byte_idx` is the value being reasoned about, not just an index
pub fn native_padded_buffer_sized(message: &[u8], real_len: usize, max_message_bytes: usize, num_blocks: usize) -> Vec<u8> {
  assert!(real_len <= message.len(), "real_len exceeds supplied message length");
  assert!(real_len <= max_message_bytes, "real_len exceeds max_message_bytes");
  let buffer_bytes = num_blocks * 64;
  let mut buf = vec![0u8; buffer_bytes];
  buf[..real_len].copy_from_slice(&message[..real_len]);
  for byte_idx in real_len..buffer_bytes {
    buf[byte_idx] = injected_byte(byte_idx, real_len).expect("byte_idx >= real_len by loop range");
  }
  buf
}

/// [`native_padded_buffer_sized`] fixed to this module's claim-sized
/// constants ([`MAX_VAR_MESSAGE_BYTES`]/[`NUM_BLOCKS`]).
pub fn native_padded_buffer(message: &[u8], real_len: usize) -> [u8; BUFFER_BYTES] {
  native_padded_buffer_sized(message, real_len, MAX_VAR_MESSAGE_BYTES, NUM_BLOCKS)
    .try_into()
    .expect("native_padded_buffer_sized returns num_blocks*64 bytes")
}

/// The in-circuit gadget, generalized over the maximum message size —
/// [`sha256_var`] is this fixed to the claim-sized constants
/// ([`MAX_VAR_MESSAGE_BYTES`]/[`NUM_BLOCKS`]); the MSO's own
/// (differently, larger-sized) variable-length hash reuses this same
/// function with its own constants rather than duplicating the
/// technique — see this module's doc for why duplicating it would be
/// risky (two independent copies of the same intricate logic that could
/// silently drift apart).
///
/// Constrains `digest` to be the real SHA-256 of `raw_bits[0..real_len*8]`
/// (MSB-first per byte), where `real_len` is a witnessed length rather
/// than a compile-time constant — see this module's doc for the
/// technique. `raw_bits` must be exactly `max_message_bytes * 8` long;
/// bits at or beyond `real_len*8` are never read (don't-care in the
/// caller's witness). `num_blocks` must be `>= terminal_block_for_len(
/// max_message_bytes)` (the caller's responsibility — see
/// [`terminal_block_for_len`]'s doc).
///
/// Returns `(digest_bits, msg_active_bits)`: the 256-bit digest, and —
/// for callers that need to know which byte positions were real message
/// content (e.g. to mask a plaintext-disclosure output the same way) —
/// one `Boolean` per byte in `0..max_message_bytes`, `true` iff that
/// byte was part of the real (`real_len`-byte) message. Reuse these
/// rather than recomputing "is this byte real" a second, independent
/// way — see this function's own internal comment on why.
#[allow(clippy::needless_range_loop)] // indices double as the numeric `n`/`byte_idx`/`bit_idx` the formulas reason about
pub fn sha256_var_sized<Scalar, CS>(
  mut cs: CS,
  raw_bits: &[Boolean],
  real_len: usize,
  max_message_bytes: usize,
  num_blocks: usize,
) -> Result<(Vec<Boolean>, Vec<Boolean>), SynthesisError>
where
  Scalar: PrimeField,
  CS: ConstraintSystem<Scalar>,
{
  assert_eq!(raw_bits.len(), max_message_bytes * 8, "raw_bits must be max_message_bytes*8 long");
  assert!(real_len <= max_message_bytes, "real_len exceeds max_message_bytes");
  let buffer_bytes = num_blocks * 64;

  // 1. One-hot `len_selector[n] == 1` iff `real_len == n`.
  let mut len_selector: Vec<AllocatedBit> = Vec::with_capacity(max_message_bytes + 1);
  for n in 0..=max_message_bytes {
    let bit = AllocatedBit::alloc(cs.namespace(|| format!("len_selector {n}")), Some(n == real_len))?;
    len_selector.push(bit);
  }
  {
    let mut lc = LinearCombination::<Scalar>::zero();
    for b in &len_selector {
      lc = lc + b.get_variable();
    }
    cs.enforce(
      || "len_selector is one-hot (sums to exactly 1)",
      |_| lc,
      |lc| lc + CS::one(),
      |lc| lc + CS::one(),
    );
  }

  // 2. Build the padded buffer bits, and along the way collect
  // `msg_active[byte_idx]` for byte_idx in 0..max_message_bytes — "is
  // this byte position real message content" — for the caller to reuse
  // (e.g. for plaintext-disclosure masking) rather than recomputing the
  // same fact a second, independent way. Recomputing it separately
  // would risk exactly the "two things that should agree silently
  // drift apart" bug class an earlier review flagged.
  let mut buffer_bits: Vec<Boolean> = Vec::with_capacity(buffer_bytes * 8);
  let mut msg_active_bits: Vec<Boolean> = Vec::with_capacity(max_message_bytes);
  for byte_idx in 0..buffer_bytes {
    // msg_active(byte_idx) = "is this byte position still real message
    // content for the witnessed real_len" = sum over n > byte_idx of
    // len_selector[n] (a pure linear combination — see module doc).
    // Only possible at all when byte_idx < max_message_bytes (no
    // raw_bits exist beyond that, and real_len can never exceed it).
    let msg_active: Option<Boolean> = if byte_idx < max_message_bytes {
      let mut lc = LinearCombination::<Scalar>::zero();
      for n in (byte_idx + 1)..=max_message_bytes {
        lc = lc + len_selector[n].get_variable();
      }
      let value = byte_idx < real_len;
      let bit = AllocatedBit::alloc(cs.namespace(|| format!("msg_active {byte_idx}")), Some(value))?;
      cs.enforce(
        || format!("msg_active {byte_idx} matches selector sum"),
        |_| lc,
        |lc| lc + CS::one(),
        |lc| lc + bit.get_variable(),
      );
      let b = Boolean::from(bit);
      msg_active_bits.push(b.clone());
      Some(b)
    } else {
      None
    };

    for bit_idx in 0..8usize {
      // injected_lc = sum, over every n <= byte_idx for which
      // injected_byte(byte_idx, n) has this bit set, of len_selector[n]
      // — again a pure linear combination with compile-time-computed
      // coefficients (0 or 1), since `injected_byte` only depends on
      // `byte_idx`/`n`, both known when building the circuit.
      let mut injected_lc = LinearCombination::<Scalar>::zero();
      for n in 0..=byte_idx.min(max_message_bytes) {
        if let Some(v) = injected_byte(byte_idx, n)
          && (v >> (7 - bit_idx)) & 1 == 1
        {
          injected_lc = injected_lc + len_selector[n].get_variable();
        }
      }

      let (combined_lc, expected_value) = match &msg_active {
        Some(active) => {
          let raw_bit = &raw_bits[byte_idx * 8 + bit_idx];
          let msg_contrib = Boolean::and(
            cs.namespace(|| format!("msg contribution byte {byte_idx} bit {bit_idx}")),
            active,
            raw_bit,
          )?;
          let expected = if byte_idx < real_len {
            raw_bit.get_value()
          } else {
            Some(injected_byte(byte_idx, real_len).expect("byte_idx >= real_len") >> (7 - bit_idx) & 1 == 1)
          };
          (msg_contrib.lc(CS::one(), Scalar::ONE) + &injected_lc, expected)
        }
        None => {
          let expected =
            Some(injected_byte(byte_idx, real_len).expect("byte_idx >= real_len for byte_idx >= max") >> (7 - bit_idx) & 1 == 1);
          (injected_lc, expected)
        }
      };

      let out_bit = AllocatedBit::alloc(
        cs.namespace(|| format!("buffer bit {byte_idx} {bit_idx}")),
        expected_value,
      )?;
      cs.enforce(
        || format!("buffer bit {byte_idx} {bit_idx} matches combination"),
        |_| combined_lc,
        |lc| lc + CS::one(),
        |lc| lc + out_bit.get_variable(),
      );
      buffer_bits.push(Boolean::from(out_bit));
    }
  }

  // 3. Run the fixed num_blocks compression rounds unconditionally,
  // recording the state after each block.
  let mut state: Vec<UInt32> = SHA256_IV.iter().map(|&v| UInt32::constant(v)).collect();
  let mut block_states: Vec<Vec<UInt32>> = Vec::with_capacity(num_blocks);
  for i in 0..num_blocks {
    let block = &buffer_bits[i * 512..(i + 1) * 512];
    state = sha256_compression_function(cs.namespace(|| format!("compress block {i}")), block, &state)?;
    block_states.push(state.clone());
  }

  // 4. Select the state after the *real* terminal block, again via a
  // one-hot-derived linear combination (`in_block[k]`), then an
  // OR-of-ANDs per output bit across the (small, num_blocks-sized) set of
  // candidate states — mutually exclusive by construction, so exactly one
  // AND term is ever nonzero.
  let mut in_block: Vec<Boolean> = Vec::with_capacity(num_blocks);
  for k in 1..=num_blocks {
    let mut lc = LinearCombination::<Scalar>::zero();
    for n in 0..=max_message_bytes {
      if terminal_block_for_len(n) == k {
        lc = lc + len_selector[n].get_variable();
      }
    }
    let value = terminal_block_for_len(real_len) == k;
    let bit = AllocatedBit::alloc(cs.namespace(|| format!("in_block {k}")), Some(value))?;
    cs.enforce(
      || format!("in_block {k} matches selector sum"),
      |_| lc,
      |lc| lc + CS::one(),
      |lc| lc + bit.get_variable(),
    );
    in_block.push(Boolean::from(bit));
  }

  let per_block_bits: Vec<Vec<Boolean>> = block_states.into_iter().map(|s| s.into_iter().flat_map(|w| w.into_bits_be()).collect()).collect();

  let mut digest_bits: Vec<Boolean> = Vec::with_capacity(256);
  for bit_idx in 0..256 {
    let mut acc: Option<Boolean> = None;
    for k in 0..num_blocks {
      let term = Boolean::and(
        cs.namespace(|| format!("select digest bit {bit_idx} block {k}")),
        &in_block[k],
        &per_block_bits[k][bit_idx],
      )?;
      acc = Some(match acc {
        None => term,
        Some(prev) => Boolean::or(
          cs.namespace(|| format!("select-or digest bit {bit_idx} block {k}")),
          &prev,
          &term,
        )?,
      });
    }
    digest_bits.push(acc.expect("num_blocks >= 1"));
  }

  Ok((digest_bits, msg_active_bits))
}

/// [`sha256_var_sized`] fixed to this module's claim-sized constants
/// ([`MAX_VAR_MESSAGE_BYTES`]/[`NUM_BLOCKS`]) — what
/// [`crate::ClaimDigestStepCircuit`] uses.
pub fn sha256_var<Scalar, CS>(
  cs: CS,
  raw_bits: &[Boolean],
  real_len: usize,
) -> Result<(Vec<Boolean>, Vec<Boolean>), SynthesisError>
where
  Scalar: PrimeField,
  CS: ConstraintSystem<Scalar>,
{
  sha256_var_sized(cs, raw_bits, real_len, MAX_VAR_MESSAGE_BYTES, NUM_BLOCKS)
}

/// Native (non-circuit) reference implementation: the real SHA-256 digest
/// of `message[..real_len]`, computed by feeding
/// [`native_padded_buffer`]'s first `terminal_block_for_len(real_len)`
/// blocks through the standard compression function — i.e. exactly what
/// the in-circuit gadget below is supposed to compute, but without any
/// circuit involved. Used by this module's own tests to confirm the
/// buffer/block-count math against `sha2`'s independent implementation
/// before any constraint-writing risk is introduced.
#[cfg(test)]
fn native_reference_digest(message: &[u8], real_len: usize) -> [u8; 32] {
  use sha2::{Digest, Sha256};
  Sha256::digest(&message[..real_len]).into()
}

#[cfg(test)]
mod native_tests {
  use super::*;

  /// Every length from 0 to MAX, plus the exact block-boundary crossings
  /// (55/56, 119/120) where `terminal_block_for_len` steps up — these are
  /// exactly the values most likely to expose an off-by-one.
  fn interesting_lengths() -> Vec<usize> {
    let mut v: Vec<usize> = (0..=MAX_VAR_MESSAGE_BYTES).collect();
    v.dedup();
    v
  }

  #[test]
  fn terminal_block_for_len_matches_hand_derived_boundaries() {
    // n*8 + 65 bits must fit in terminal_block_for_len(n) * 512 bits.
    // Hand-derived boundaries: 1 block up to n=55, 2 blocks 56..=119,
    // 3 blocks 120..=183.
    assert_eq!(terminal_block_for_len(0), 1);
    assert_eq!(terminal_block_for_len(55), 1);
    assert_eq!(terminal_block_for_len(56), 2);
    assert_eq!(terminal_block_for_len(119), 2);
    assert_eq!(terminal_block_for_len(120), 3);
    assert_eq!(terminal_block_for_len(183), 3);
    assert!(terminal_block_for_len(MAX_VAR_MESSAGE_BYTES) <= NUM_BLOCKS);
  }

  #[test]
  fn native_padded_buffer_matches_real_sha256_for_every_length() {
    // A message long enough to cover MAX_VAR_MESSAGE_BYTES, with no
    // repeated byte value (so a bit-order or offset bug shows up as a
    // wrong digest, not an accidental match).
    let message: Vec<u8> = (0..MAX_VAR_MESSAGE_BYTES).map(|i| (i * 7 + 3) as u8).collect();

    for real_len in interesting_lengths() {
      let buf = native_padded_buffer(&message, real_len);
      let blocks = terminal_block_for_len(real_len);
      let prefix = &buf[..blocks * 64];

      // Feed exactly the prefix through the standard compression chain,
      // independent of sha2, to confirm our buffer is a byte-for-byte
      // valid SHA-256 padding — not just "produces the right hash" via
      // some other coincidence.
      use sha2::compress256;
      use sha2::digest::generic_array::GenericArray;
      use sha2::digest::typenum::U64;
      let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
      ];
      for block in prefix.chunks(64) {
        let ga: GenericArray<u8, U64> = GenericArray::clone_from_slice(block);
        compress256(&mut state, &[ga]);
      }
      let mut digest = [0u8; 32];
      for (i, word) in state.iter().enumerate() {
        digest[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
      }

      let expected = native_reference_digest(&message, real_len);
      assert_eq!(
        digest, expected,
        "native_padded_buffer mismatch at real_len={real_len} (blocks={blocks})"
      );
    }
  }

  #[test]
  fn injected_byte_is_none_exactly_for_real_message_positions() {
    for real_len in interesting_lengths() {
      for byte_idx in 0..BUFFER_BYTES {
        let injected = injected_byte(byte_idx, real_len);
        if byte_idx < real_len {
          assert!(injected.is_none(), "byte_idx={byte_idx} real_len={real_len}");
        } else {
          assert!(injected.is_some(), "byte_idx={byte_idx} real_len={real_len}");
        }
      }
    }
  }

  #[test]
  fn injected_byte_marker_and_length_field_positions_are_consistent() {
    for real_len in interesting_lengths() {
      // Marker byte.
      assert_eq!(injected_byte(real_len, real_len), Some(0x80));
      // Length field, reconstructed byte-by-byte, must equal real_len*8.
      let terminal_block = terminal_block_for_len(real_len);
      let len_field_start = terminal_block * 64 - 8;
      let mut len_bytes = [0u8; 8];
      for (i, b) in len_bytes.iter_mut().enumerate() {
        *b = injected_byte(len_field_start + i, real_len).unwrap();
      }
      assert_eq!(u64::from_be_bytes(len_bytes), (real_len as u64) * 8);
      // Strictly between marker and length field: zero, if any such gap exists.
      for byte_idx in (real_len + 1)..len_field_start {
        assert_eq!(injected_byte(byte_idx, real_len), Some(0x00));
      }
    }
  }
}

#[cfg(test)]
mod circuit_tests {
  use super::*;
  use crate::Engine_;
  use bellpepper_core::{boolean::AllocatedBit, test_cs::TestConstraintSystem};
  use sha2::{Digest, Sha256};
  use vega_prover::traits::Engine;

  type Scalar = <Engine_ as Engine>::Scalar;

  fn alloc_raw_bits<CS: ConstraintSystem<Scalar>>(cs: &mut CS, message: &[u8]) -> Vec<Boolean> {
    assert_eq!(message.len(), MAX_VAR_MESSAGE_BYTES);
    message
      .iter()
      .flat_map(|byte| (0..8).rev().map(move |i| (byte >> i) & 1u8 == 1u8))
      .enumerate()
      .map(|(i, b)| {
        AllocatedBit::alloc(cs.namespace(|| format!("raw bit {i}")), Some(b))
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
          if bit.get_value().expect("bit has a value") {
            byte | (1 << (7 - i))
          } else {
            byte
          }
        })
      })
      .collect()
  }

  /// The real, load-bearing test: for a spread of real_len values
  /// (including every block-count boundary), the circuit's digest must
  /// equal the real SHA-256 of exactly the first `real_len` bytes of the
  /// message — not the zero-padded stand-in this gadget replaces.
  #[test]
  fn sha256_var_matches_real_sha256_across_all_lengths() {
    // No repeated byte value, so a bit-order or offset bug can't hide
    // behind an accidentally-symmetric input.
    let message: Vec<u8> = (0..MAX_VAR_MESSAGE_BYTES).map(|i| (i * 7 + 11) as u8).collect();

    let mut lengths: Vec<usize> = vec![0, 1, 54, 55, 56, 57, 63, 64, 65, 79, 83, 94, 95, 118, 119, 120, 121, 127];
    lengths.push(MAX_VAR_MESSAGE_BYTES);
    lengths.sort_unstable();
    lengths.dedup();

    for real_len in lengths {
      let mut cs = TestConstraintSystem::<Scalar>::new();
      let raw_bits = alloc_raw_bits(&mut cs, &message);
      let (digest_bits, _msg_active) = sha256_var(cs.namespace(|| format!("sha256_var real_len={real_len}")), &raw_bits, real_len)
        .expect("sha256_var synthesis");

      if let Some(reason) = cs.which_is_unsatisfied() {
        panic!("real_len={real_len}: constraint system unsatisfied at: {reason}");
      }
      assert!(cs.is_satisfied(), "real_len={real_len}: constraints must be satisfied");

      let got = bits_to_bytes(&digest_bits);
      let expected: [u8; 32] = Sha256::digest(&message[..real_len]).into();
      assert_eq!(
        got,
        expected.to_vec(),
        "real_len={real_len}: circuit digest must equal SHA-256 of exactly the first {real_len} bytes"
      );
    }
  }

  /// A tampered message byte within `real_len` must change the digest —
  /// the positive test alone can't rule out a vacuously-satisfiable
  /// circuit (e.g. one where `raw_bits` isn't actually wired into the
  /// output at all).
  #[test]
  fn sha256_var_is_sensitive_to_every_real_message_byte() {
    let real_len = 90;
    let base: Vec<u8> = (0..MAX_VAR_MESSAGE_BYTES).map(|i| (i * 3 + 5) as u8).collect();
    let mut tampered = base.clone();
    tampered[real_len - 1] ^= 0x01; // flip a bit in the LAST real byte

    let mut cs = TestConstraintSystem::<Scalar>::new();
    let raw_bits = alloc_raw_bits(&mut cs, &base);
    let (digest_base, _) = sha256_var(cs.namespace(|| "base"), &raw_bits, real_len).expect("synthesis");
    assert!(cs.is_satisfied());

    let mut cs2 = TestConstraintSystem::<Scalar>::new();
    let raw_bits2 = alloc_raw_bits(&mut cs2, &tampered);
    let (digest_tampered, _) = sha256_var(cs2.namespace(|| "tampered"), &raw_bits2, real_len).expect("synthesis");
    assert!(cs2.is_satisfied());

    assert_ne!(
      bits_to_bytes(&digest_base),
      bits_to_bytes(&digest_tampered),
      "flipping a bit within the real message must change the digest"
    );
  }

  /// A change to bytes strictly BEYOND `real_len` (the "don't care"
  /// region) must NOT change the digest — confirms `msg_active` really
  /// gates on `real_len`, not on the raw buffer's incidental content.
  #[test]
  fn sha256_var_ignores_bytes_beyond_real_len() {
    let real_len = 40;
    let base: Vec<u8> = (0..MAX_VAR_MESSAGE_BYTES).map(|i| (i * 5 + 1) as u8).collect();
    let mut changed_tail = base.clone();
    for b in changed_tail.iter_mut().skip(real_len) {
      *b ^= 0xFF;
    }

    let mut cs = TestConstraintSystem::<Scalar>::new();
    let raw_bits = alloc_raw_bits(&mut cs, &base);
    let (digest_base, _) = sha256_var(cs.namespace(|| "base"), &raw_bits, real_len).expect("synthesis");

    let mut cs2 = TestConstraintSystem::<Scalar>::new();
    let raw_bits2 = alloc_raw_bits(&mut cs2, &changed_tail);
    let (digest_changed, _) = sha256_var(cs2.namespace(|| "changed"), &raw_bits2, real_len).expect("synthesis");

    assert_eq!(
      bits_to_bytes(&digest_base),
      bits_to_bytes(&digest_changed),
      "bytes beyond real_len must never affect the digest"
    );
  }

  /// `msg_active_bits` is a public output callers (e.g.
  /// `ClaimDigestStepCircuit`'s plaintext-disclosure masking) will rely
  /// on directly — confirm it's exactly `[true; real_len] ++
  /// [false; MAX_VAR_MESSAGE_BYTES - real_len]` for a spread of lengths.
  #[test]
  fn msg_active_bits_matches_real_len_exactly() {
    let message: Vec<u8> = vec![0xAB; MAX_VAR_MESSAGE_BYTES];
    for real_len in [0, 1, 56, 90, 127, MAX_VAR_MESSAGE_BYTES] {
      let mut cs = TestConstraintSystem::<Scalar>::new();
      let raw_bits = alloc_raw_bits(&mut cs, &message);
      let (_, msg_active) = sha256_var(cs.namespace(|| format!("real_len={real_len}")), &raw_bits, real_len)
        .expect("synthesis");
      assert_eq!(msg_active.len(), MAX_VAR_MESSAGE_BYTES);
      for (byte_idx, active) in msg_active.iter().enumerate() {
        assert_eq!(
          active.get_value().expect("has a value"),
          byte_idx < real_len,
          "real_len={real_len} byte_idx={byte_idx}"
        );
      }
    }
  }

  /// Confirms the generalization behind `sha256_var_sized` (extracted so
  /// the MSO's own, much larger, variable-length hash can reuse the exact
  /// same technique instead of a second, independently-written copy) is
  /// correct at a genuinely different size from the claim use case above
  /// — not just re-testing the same constants under a new name.
  #[test]
  fn sha256_var_sized_matches_real_sha256_at_a_different_scale() {
    const MAX: usize = 300;
    const BLOCKS: usize = 5; // terminal_block_for_len(300) == 5
    assert_eq!(terminal_block_for_len(MAX), BLOCKS);

    let message: Vec<u8> = (0..MAX).map(|i| (i * 11 + 17) as u8).collect();
    let lengths = [0, 1, 55, 56, 119, 120, 183, 184, 250, MAX];

    for real_len in lengths {
      let mut cs = TestConstraintSystem::<Scalar>::new();
      let raw_bits = message
        .iter()
        .flat_map(|byte| (0..8).rev().map(move |i| (byte >> i) & 1u8 == 1u8))
        .enumerate()
        .map(|(i, b)| {
          AllocatedBit::alloc(cs.namespace(|| format!("raw bit {i}")), Some(b))
            .map(Boolean::from)
            .expect("alloc")
        })
        .collect::<Vec<_>>();

      let (digest_bits, msg_active) =
        sha256_var_sized(cs.namespace(|| format!("real_len={real_len}")), &raw_bits, real_len, MAX, BLOCKS)
          .expect("synthesis");

      if let Some(reason) = cs.which_is_unsatisfied() {
        panic!("real_len={real_len}: constraint system unsatisfied at: {reason}");
      }
      assert!(cs.is_satisfied());
      assert_eq!(msg_active.len(), MAX);

      let got = bits_to_bytes(&digest_bits);
      let expected: [u8; 32] = Sha256::digest(&message[..real_len]).into();
      assert_eq!(got, expected.to_vec(), "real_len={real_len}");
    }
  }
}
