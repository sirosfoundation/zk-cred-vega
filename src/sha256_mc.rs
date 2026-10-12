//! Multi-circuit length-hiding SHA-256, per §4.2 of the Vega paper.
//!
//! # Why
//!
//! The single-circuit form unrolls every SHA-256 compression into one
//! R1CS. For r13's 40-block budget that is 1,033,600 constraints — 77% of
//! the circuit — and the setup, and therefore the published key, is sized
//! by it. Our measured keys are **614 MB**.
//!
//! The paper's multi-circuit form instead sets up *one* compression and
//! folds ℓ instances of it:
//!
//! > "VegaMC reduces setup latency by 92% because only one SHA-256
//! > sub-circuit must be set up, as opposed to setting up the constraints
//! > for each iteration of the SHA-256 computation."
//!
//! Figure 10 of the paper reports 6,588 kB → 464 kB keys for the same
//! statement, a 14× reduction, with setup 12× and prove/verify 1.7×
//! faster.
//!
//! # How the steps are bound to each other
//!
//! A step circuit proves one transition `H_{i+1} = Compress(H_i, M_i)`.
//! On its own that says nothing about *which* blocks were hashed or in
//! what order, and publishing the intermediate digests to chain them
//! would leak a stable per-credential fingerprint — the exact class of
//! leak that made the previous circuit revision linkable.
//!
//! Instead the blocks and digests live in the **shared** witness segment.
//! `vega_mc_zkp::prove` propagates the core's `comm_W_shared` to every
//! step instance and verification hoists it back to a single commitment,
//! so one commitment covers all ℓ steps *and* the core. A step reads its
//! block and digests out of that shared vector by a one-hot over its
//! public index; the core selects the canonical digest from the same
//! vector. Nothing about the message becomes public.
//!
//! # Packing
//!
//! The shared vector is packed 16 bytes to a field element rather than
//! stored as bits. A one-hot readout costs one multiplication per
//! candidate *per element*, so a 64-byte block read as bits would cost
//! 512ℓ multiplications per step — 819k across 40 steps, worse than the
//! unrolled circuit it replaces. Packed it is 4ℓ.
//!
//! # Multiple messages
//!
//! §4.2.1: several independent messages share one step set by resetting
//! the chaining value to the IV at each message boundary. The budgets are
//! fixed at setup, so which indices are boundaries is public and folds
//! into the same one-hot — no change to the step circuit's shape.
//!
//! **Unreviewed.** See the crate README.

use bellpepper::gadgets::{sha256::sha256_compression_function, uint32::UInt32};
use bellpepper_core::{
  boolean::{AllocatedBit, Boolean},
  num::AllocatedNum,
  ConstraintSystem, LinearCombination, SynthesisError,
};
use ff::PrimeField;

/// Bytes per packed field element, as elsewhere in this crate.
pub const BYTES_PER_PACK: usize = 16;
/// Field elements per 64-byte block.
pub const PACKS_PER_BLOCK: usize = 64 / BYTES_PER_PACK;
/// Field elements per 32-byte digest.
pub const PACKS_PER_DIGEST: usize = 32 / BYTES_PER_PACK;

/// SHA-256's initial chaining value.
pub const IV: [u32; 8] = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA-256's compression function, out of circuit.
///
/// Needed natively to build the shared witness: the prover must know the
/// intermediate digests before it can commit to them.
pub fn compress_native(mut h: [u32; 8], block: &[u8; 64]) -> [u32; 8] {
  const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];
  let mut w = [0u32; 64];
  for i in 0..16 {
    w[i] = u32::from_be_bytes([block[i * 4], block[i * 4 + 1], block[i * 4 + 2], block[i * 4 + 3]]);
  }
  for i in 16..64 {
    let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
    let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
  }
  let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
    (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
  for i in 0..64 {
    let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
    let ch = (e & f) ^ ((!e) & g);
    let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
    let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
    let maj = (a & b) ^ (a & c) ^ (b & c);
    let t2 = s0.wrapping_add(maj);
    hh = g; g = f; f = e; e = d.wrapping_add(t1);
    d = c; c = b; b = a; a = t1.wrapping_add(t2);
  }
  for (i, v) in [a, b, c, d, e, f, g, hh].into_iter().enumerate() {
    h[i] = h[i].wrapping_add(v);
  }
  h
}

/// The layout of one credential's hashing work: how many 512-bit blocks
/// each independent message gets. Fixed at setup, so it is public.
#[derive(Clone, Debug)]
pub struct HashLayout {
  pub message_blocks: Vec<usize>,
}

impl HashLayout {
  pub fn total_blocks(&self) -> usize {
    self.message_blocks.iter().sum()
  }
  /// Index of the first block of each message — where the chaining value
  /// resets to the IV rather than continuing from the previous digest.
  pub fn is_first_of_message(&self, block: usize) -> bool {
    let mut at = 0;
    for &n in &self.message_blocks {
      if block == at {
        return true;
      }
      at += n;
    }
    false
  }
  /// First block index of message `m`.
  pub fn message_start(&self, m: usize) -> usize {
    self.message_blocks[..m].iter().sum()
  }
}

fn pack_be<Scalar: PrimeField>(bytes: &[u8]) -> Scalar {
  bytes.iter().fold(Scalar::ZERO, |a, &b| a * Scalar::from(256u64) + Scalar::from(b as u64))
}

/// Allocates the shared witness: every block, then every block's output
/// digest, each packed 16 bytes to an element.
///
/// **This must produce an identical vector in the step and core
/// circuits.** The proof system commits to it once and reuses that
/// commitment across both, so a layout difference is not a mismatch it
/// can detect — it is a wrong proof.
pub fn alloc_shared<Scalar, CS>(
  cs: &mut CS,
  blocks: &[[u8; 64]],
  digests: &[[u8; 32]],
) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError>
where
  Scalar: PrimeField,
  CS: ConstraintSystem<Scalar>,
{
  let mut out = Vec::with_capacity(blocks.len() * PACKS_PER_BLOCK + digests.len() * PACKS_PER_DIGEST);
  for (j, b) in blocks.iter().enumerate() {
    for k in 0..PACKS_PER_BLOCK {
      let v = pack_be::<Scalar>(&b[k * BYTES_PER_PACK..(k + 1) * BYTES_PER_PACK]);
      out.push(AllocatedNum::alloc(cs.namespace(|| format!("block {j} pack {k}")), || Ok(v))?);
    }
  }
  for (j, d) in digests.iter().enumerate() {
    for k in 0..PACKS_PER_DIGEST {
      let v = pack_be::<Scalar>(&d[k * BYTES_PER_PACK..(k + 1) * BYTES_PER_PACK]);
      out.push(AllocatedNum::alloc(cs.namespace(|| format!("digest {j} pack {k}")), || Ok(v))?);
    }
  }
  Ok(out)
}

fn block_pack(total_blocks: usize, j: usize, k: usize) -> usize {
  let _ = total_blocks;
  j * PACKS_PER_BLOCK + k
}
fn digest_pack(total_blocks: usize, j: usize, k: usize) -> usize {
  total_blocks * PACKS_PER_BLOCK + j * PACKS_PER_DIGEST + k
}

/// One-hot selector over `0..n` for a public index.
fn one_hot<Scalar, CS>(mut cs: CS, n: usize, real: usize) -> Result<Vec<AllocatedBit>, SynthesisError>
where
  Scalar: PrimeField,
  CS: ConstraintSystem<Scalar>,
{
  let mut bits = Vec::with_capacity(n);
  let mut sum = LinearCombination::<Scalar>::zero();
  for j in 0..n {
    let b = AllocatedBit::alloc(cs.namespace(|| format!("sel {j}")), Some(j == real))?;
    sum = sum + b.get_variable();
    bits.push(b);
  }
  cs.enforce(|| "one-hot sums to one", |lc| lc + &sum, |lc| lc + CS::one(), |lc| lc + CS::one());
  Ok(bits)
}

/// Reads `Σ_j sel[j] * value(j)` out of the shared vector.
fn readout<Scalar, CS>(
  mut cs: CS,
  sel: &[AllocatedBit],
  shared: &[AllocatedNum<Scalar>],
  index_of: impl Fn(usize) -> Option<usize>,
  constant_for: impl Fn(usize) -> Option<Scalar>,
  tag: &str,
) -> Result<AllocatedNum<Scalar>, SynthesisError>
where
  Scalar: PrimeField,
  CS: ConstraintSystem<Scalar>,
{
  let mut acc = LinearCombination::<Scalar>::zero();
  let mut value = Some(Scalar::ZERO);
  for (j, s) in sel.iter().enumerate() {
    let term_value = match (index_of(j), constant_for(j)) {
      (_, Some(c)) => Some(c),
      (Some(idx), None) => shared[idx].get_value(),
      (None, None) => Some(Scalar::ZERO),
    };
    let live = s.get_value().unwrap_or(false);
    let t = AllocatedNum::alloc(cs.namespace(|| format!("{tag} term {j}")), || {
      Ok(if live { term_value.ok_or(SynthesisError::AssignmentMissing)? } else { Scalar::ZERO })
    })?;
    // sel[j] * value(j) == t
    match (index_of(j), constant_for(j)) {
      (_, Some(c)) => cs.enforce(
        || format!("{tag} select {j}"),
        |lc| lc + s.get_variable(),
        |lc| lc + (c, CS::one()),
        |lc| lc + t.get_variable(),
      ),
      (Some(idx), None) => cs.enforce(
        || format!("{tag} select {j}"),
        |lc| lc + s.get_variable(),
        |lc| lc + shared[idx].get_variable(),
        |lc| lc + t.get_variable(),
      ),
      (None, None) => cs.enforce(
        || format!("{tag} select {j}"),
        |lc| lc + s.get_variable(),
        |lc| lc,
        |lc| lc + t.get_variable(),
      ),
    }
    if live {
      value = term_value;
    }
    acc = acc + t.get_variable();
  }
  let out = AllocatedNum::alloc(cs.namespace(|| format!("{tag} value")), || {
    value.ok_or(SynthesisError::AssignmentMissing)
  })?;
  cs.enforce(|| format!("{tag} sums"), |lc| lc + &acc, |lc| lc + CS::one(), |lc| lc + out.get_variable());
  Ok(out)
}

/// Decomposes a packed element into `BYTES_PER_PACK * 8` bits, MSB-first.
fn unpack<Scalar, CS>(mut cs: CS, p: &AllocatedNum<Scalar>, tag: &str) -> Result<Vec<Boolean>, SynthesisError>
where
  Scalar: PrimeField,
  CS: ConstraintSystem<Scalar>,
{
  let native = p.get_value().map(|v| {
    let r = v.to_repr();
    let b = r.as_ref()[..BYTES_PER_PACK].to_vec();
    b.into_iter().rev().collect::<Vec<u8>>() // little-endian repr -> big-endian bytes
  });
  let mut bits = Vec::with_capacity(BYTES_PER_PACK * 8);
  let mut recomposed = LinearCombination::<Scalar>::zero();
  for i in 0..BYTES_PER_PACK * 8 {
    let b = AllocatedBit::alloc(cs.namespace(|| format!("{tag} bit {i}")), native.as_ref().map(|n| (n[i / 8] >> (7 - i % 8)) & 1 == 1))?;
    let mut coeff = Scalar::ONE;
    for _ in 0..(BYTES_PER_PACK * 8 - 1 - i) {
      coeff = coeff.double();
    }
    recomposed = recomposed + (coeff, b.get_variable());
    bits.push(Boolean::from(b));
  }
  cs.enforce(|| format!("{tag} recomposes"), |lc| lc + &recomposed, |lc| lc + CS::one(), |lc| lc + p.get_variable());
  Ok(bits)
}

/// Packs bits (MSB-first) back into one field element, as a free linear
/// combination.
fn repack<Scalar: PrimeField>(bits: &[Boolean], one: bellpepper_core::Variable) -> LinearCombination<Scalar> {
  let mut lc = LinearCombination::zero();
  for (i, b) in bits.iter().enumerate() {
    let mut coeff = Scalar::ONE;
    for _ in 0..(bits.len() - 1 - i) {
      coeff = coeff.double();
    }
    lc = lc + &b.lc(one, coeff);
  }
  lc
}

/// One step: proves `H_{i+1} = Compress(H_i, M_i)` for the public index
/// `step`, reading everything out of the shared witness.
///
/// Every step circuit instance has this identical shape, which is what
/// lets the folding scheme aggregate them.
pub fn synthesize_step<Scalar, CS>(
  cs: &mut CS,
  shared: &[AllocatedNum<Scalar>],
  layout: &HashLayout,
  step: usize,
) -> Result<(), SynthesisError>
where
  Scalar: PrimeField,
  CS: ConstraintSystem<Scalar>,
{
  let one = CS::one();
  let n = layout.total_blocks();
  let sel = one_hot::<Scalar, _>(cs.namespace(|| "step index"), n, step)?;

  // The block being compressed.
  let mut block_bits = Vec::with_capacity(512);
  for k in 0..PACKS_PER_BLOCK {
    let p = readout(
      cs.namespace(|| format!("block pack {k}")),
      &sel,
      shared,
      |j| Some(block_pack(n, j, k)),
      |_| None,
      &format!("M{k}"),
    )?;
    block_bits.extend(unpack(cs.namespace(|| format!("block bits {k}")), &p, &format!("M{k}"))?);
  }

  // The incoming chaining value: the IV at a message boundary, otherwise
  // the previous block's digest. Which indices are boundaries is public,
  // so this folds into the same selector.
  let mut state_bits = Vec::with_capacity(256);
  for k in 0..PACKS_PER_DIGEST {
    let iv_pack = {
      let mut bytes = Vec::with_capacity(32);
      for w in IV {
        bytes.extend_from_slice(&w.to_be_bytes());
      }
      pack_be::<Scalar>(&bytes[k * BYTES_PER_PACK..(k + 1) * BYTES_PER_PACK])
    };
    let p = readout(
      cs.namespace(|| format!("state pack {k}")),
      &sel,
      shared,
      |j| if layout.is_first_of_message(j) { None } else { Some(digest_pack(n, j - 1, k)) },
      |j| if layout.is_first_of_message(j) { Some(iv_pack) } else { None },
      &format!("Hin{k}"),
    )?;
    state_bits.extend(unpack(cs.namespace(|| format!("state bits {k}")), &p, &format!("Hin{k}"))?);
  }
  let state: Vec<UInt32> = state_bits.chunks(32).map(UInt32::from_bits_be).collect();

  let out = sha256_compression_function(cs.namespace(|| "compress"), &block_bits, &state)?;
  let out_bits: Vec<Boolean> = out.into_iter().flat_map(|w| w.into_bits_be()).collect();

  // The result must equal this block's shared digest. Comparing the two
  // packed elements costs two constraints rather than 256.
  for k in 0..PACKS_PER_DIGEST {
    let expected = readout(
      cs.namespace(|| format!("digest pack {k}")),
      &sel,
      shared,
      |j| Some(digest_pack(n, j, k)),
      |_| None,
      &format!("Hout{k}"),
    )?;
    let got = repack::<Scalar>(&out_bits[k * BYTES_PER_PACK * 8..(k + 1) * BYTES_PER_PACK * 8], one);
    cs.enforce(
      || format!("compression output matches shared digest {k}"),
      |lc| lc + &got,
      |lc| lc + one,
      |lc| lc + expected.get_variable(),
    );
  }
  Ok(())
}

/// Core side: ties a padded message buffer to the shared blocks the step
/// circuits hash.
///
/// Without this the steps would be proving compressions over blocks
/// unrelated to the credential. It is cheap because both sides are
/// already packed the same way: one constraint per 16 bytes, so 4 per
/// block, rather than one per bit.
pub fn bind_message_to_shared<Scalar, CS>(
  cs: &mut CS,
  shared: &[AllocatedNum<Scalar>],
  layout: &HashLayout,
  message: usize,
  padded_bits: &[Boolean],
) -> Result<(), SynthesisError>
where
  Scalar: PrimeField,
  CS: ConstraintSystem<Scalar>,
{
  let one = CS::one();
  let n = layout.total_blocks();
  let budget = layout.message_blocks[message];
  let start = layout.message_start(message);
  if padded_bits.len() != budget * 512 {
    return Err(SynthesisError::Unsatisfiable);
  }
  for b in 0..budget {
    for k in 0..PACKS_PER_BLOCK {
      let lo = b * 512 + k * BYTES_PER_PACK * 8;
      let got = repack::<Scalar>(&padded_bits[lo..lo + BYTES_PER_PACK * 8], one);
      cs.enforce(
        || format!("message {message} block {b} pack {k} matches shared"),
        |lc| lc + &got,
        |lc| lc + one,
        |lc| lc + shared[block_pack(n, start + b, k)].get_variable(),
      );
    }
  }
  Ok(())
}

/// Core side: selects message `message`'s canonical digest from the
/// shared vector, given the private terminal-block index within that
/// message.
///
/// The selector is over that message's block budget — ℓ entries, not one
/// per byte. §4.1.1: "Practically, this entails two R1CS constraints,
/// plus the standard per-bit Booleanity checks."
pub fn select_digest<Scalar, CS>(
  cs: &mut CS,
  shared: &[AllocatedNum<Scalar>],
  layout: &HashLayout,
  message: usize,
  terminal_block: usize,
  length_selector: Option<&[AllocatedBit]>,
) -> Result<Vec<Boolean>, SynthesisError>
where
  Scalar: PrimeField,
  CS: ConstraintSystem<Scalar>,
{
  let n = layout.total_blocks();
  let budget = layout.message_blocks[message];
  if terminal_block >= budget {
    return Err(SynthesisError::Unsatisfiable);
  }
  let start = layout.message_start(message);
  let sel = one_hot::<Scalar, _>(cs.namespace(|| "terminal block"), budget, terminal_block)?;

  // MC-03. Tie the block selected to the padding boundary.
  //
  // Both are witnesses an honest prover derives from one length, but
  // nothing related them: the padding said block `d` was terminal while
  // the selection could pick block `t != d`. That was safe only by an
  // argument about what an earlier block's digest is good for -- a
  // Merkle-Damgard intermediate needs either an issuer signature over it
  // or a `valueDigests` entry equal to it. Safe by argument is worse than
  // safe by construction, and this costs one constraint: both sides are
  // linear combinations whose coefficients are known at circuit-build
  // time.
  if let Some(len_sel) = length_selector {
    let mut from_selection = LinearCombination::<Scalar>::zero();
    for (j, s) in sel.iter().enumerate() {
      from_selection = from_selection + (Scalar::from(j as u64), s.get_variable());
    }
    let mut from_padding = LinearCombination::<Scalar>::zero();
    for (n, s) in len_sel.iter().enumerate() {
      let block = crate::sha256_var::terminal_block_for_len(n).saturating_sub(1);
      from_padding = from_padding + (Scalar::from(block as u64), s.get_variable());
    }
    cs.enforce(
      || "selected block is the padding boundary",
      |lc| lc + &from_selection - &from_padding,
      |lc| lc + CS::one(),
      |lc| lc,
    );
  }

  let mut bits = Vec::with_capacity(256);
  for k in 0..PACKS_PER_DIGEST {
    let p = readout(
      cs.namespace(|| format!("selected digest pack {k}")),
      &sel,
      shared,
      |j| Some(digest_pack(n, start + j, k)),
      |_| None,
      &format!("D{k}"),
    )?;
    bits.extend(unpack(cs.namespace(|| format!("selected digest bits {k}")), &p, &format!("D{k}"))?);
  }
  Ok(bits)
}

#[cfg(test)]
mod tests {
  use super::*;
  use bellpepper_core::test_cs::TestConstraintSystem;
  use sha2::{Digest, Sha256};

  type S = <crate::Engine_ as vega_prover::traits::Engine>::Scalar;

  /// Runs the real SHA-256 chain natively, so the circuit has something
  /// to be checked against rather than only against itself.
  fn native_chain(messages: &[&[u8]], layout: &HashLayout) -> (Vec<[u8; 64]>, Vec<[u8; 32]>) {
    let mut blocks = Vec::new();
    let mut digests = Vec::new();
    for (m, msg) in messages.iter().enumerate() {
      let budget = layout.message_blocks[m];
      let mut padded = msg.to_vec();
      padded.push(0x80);
      while (padded.len() + 8) % 64 != 0 {
        padded.push(0);
      }
      padded.extend_from_slice(&((msg.len() as u64) * 8).to_be_bytes());
      assert!(padded.len() / 64 <= budget);
      padded.resize(budget * 64, 0);

      let mut state = IV;
      for b in padded.chunks(64) {
        let mut blk = [0u8; 64];
        blk.copy_from_slice(b);
        state = compress_native(state, &blk);
        let mut d = [0u8; 32];
        for (i, w) in state.iter().enumerate() {
          d[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        blocks.push(blk);
        digests.push(d);
      }
    }
    (blocks, digests)
  }



  /// Every step verifies, and the core selects a digest equal to the real
  /// SHA-256 of the message — across two independent messages sharing one
  /// step set, which is §4.2.1's claim.
  #[test]
  fn steps_and_selection_reproduce_real_sha256_for_two_messages() {
    let m1: Vec<u8> = (0..200u8).collect();
    let m2 = b"a second, independent message".to_vec();
    let layout = HashLayout { message_blocks: vec![6, 2] };
    let (blocks, digests) = native_chain(&[&m1, &m2], &layout);
    assert_eq!(blocks.len(), layout.total_blocks());

    // Each step, against the same shared witness.
    for step in 0..layout.total_blocks() {
      let mut cs = TestConstraintSystem::<S>::new();
      let shared = alloc_shared(&mut cs, &blocks, &digests).unwrap();
      synthesize_step(&mut cs, &shared, &layout, step).unwrap();
      assert!(cs.is_satisfied(), "step {step} unsatisfied at {:?}", cs.which_is_unsatisfied());
    }

    // And the core picks the canonical digest for each message.
    for (m, (msg, terminal)) in [(&m1[..], 3usize), (&m2[..], 0usize)].into_iter().enumerate() {
      let mut cs = TestConstraintSystem::<S>::new();
      let shared = alloc_shared(&mut cs, &blocks, &digests).unwrap();
      let bits = select_digest(&mut cs, &shared, &layout, m, terminal, None).unwrap();
      assert!(cs.is_satisfied(), "selection unsatisfied at {:?}", cs.which_is_unsatisfied());
      let got: Vec<u8> = bits
        .chunks(8)
        .map(|c| c.iter().fold(0u8, |a, b| (a << 1) | u8::from(b.get_value().unwrap())))
        .collect();
      let want: [u8; 32] = Sha256::digest(msg).into();
      assert_eq!(&got[..], &want[..], "message {m}: selected digest is not SHA-256 of it");
    }
  }

  /// The step circuit's shape is identical for every index, which is what
  /// the folding scheme requires.
  #[test]
  fn every_step_has_the_same_shape() {
    let layout = HashLayout { message_blocks: vec![6, 2] };
    let (blocks, digests) = native_chain(&[&(0..200u8).collect::<Vec<_>>()[..], b"second"], &layout);
    let mut shapes = Vec::new();
    for step in 0..layout.total_blocks() {
      let mut cs = TestConstraintSystem::<S>::new();
      let shared = alloc_shared(&mut cs, &blocks, &digests).unwrap();
      synthesize_step(&mut cs, &shared, &layout, step).unwrap();
      shapes.push((cs.num_constraints(), cs.num_inputs()));
    }
    assert!(shapes.windows(2).all(|w| w[0] == w[1]), "step shapes differ: {shapes:?}");
    println!("one step = {} constraints", shapes[0].0);
  }
}

#[cfg(test)]
mod core_tests {
  use super::*;
  use bellpepper_core::{boolean::AllocatedBit, test_cs::TestConstraintSystem};
  use sha2::{Digest, Sha256};

  type S = <crate::Engine_ as vega_prover::traits::Engine>::Scalar;

  /// The whole core-side path: pad a witnessed-length message, bind it to
  /// the shared blocks, and select its digest — and get real SHA-256 out,
  /// with no compression in this circuit at all.
  #[test]
  fn core_binds_and_selects_without_any_compression() {
    const MAXB: usize = 6 * 64 - 9;
    const BLOCKS: usize = 6;
    let msg: Vec<u8> = (0..137u8).collect();
    let layout = HashLayout { message_blocks: vec![BLOCKS] };

    // Native chain for the shared witness.
    let padded = crate::sha256_var::native_padded_buffer_sized(&msg, msg.len(), MAXB, BLOCKS);
    let mut blocks = Vec::new();
    let mut digests = Vec::new();
    let mut state = IV;
    for b in padded.chunks(64) {
      let mut blk = [0u8; 64];
      blk.copy_from_slice(b);
      state = compress_native(state, &blk);
      let mut d = [0u8; 32];
      for (i, w) in state.iter().enumerate() {
        d[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
      }
      blocks.push(blk);
      digests.push(d);
    }

    let mut cs = TestConstraintSystem::<S>::new();
    let shared = alloc_shared(&mut cs, &blocks, &digests).unwrap();
    let base = cs.num_constraints();

    let mut raw = msg.clone();
    raw.resize(MAXB, 0);
    let raw_bits: Vec<Boolean> = raw
      .iter()
      .flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1 == 1))
      .enumerate()
      .map(|(i, b)| AllocatedBit::alloc(cs.namespace(|| format!("raw {i}")), Some(b)).map(Boolean::from).unwrap())
      .collect();
    let (buffer_bits, _, len_sel) =
      crate::sha256_var::padded_buffer_bits(&mut cs, &raw_bits, msg.len(), MAXB, BLOCKS).unwrap();
    bind_message_to_shared(&mut cs, &shared, &layout, 0, &buffer_bits).unwrap();
    let terminal = crate::sha256_var::terminal_block_for_len(msg.len()) - 1;
    let bits = select_digest(&mut cs, &shared, &layout, 0, terminal, Some(&len_sel)).unwrap();
    let core_cost = cs.num_constraints() - base;

    assert!(cs.is_satisfied(), "unsatisfied at {:?}", cs.which_is_unsatisfied());
    let got: Vec<u8> = bits
      .chunks(8)
      .map(|c| c.iter().fold(0u8, |a, b| (a << 1) | u8::from(b.get_value().unwrap())))
      .collect();
    assert_eq!(&got[..], &Sha256::digest(&msg)[..], "core must select the real SHA-256");

    println!("core-side hashing for {BLOCKS} blocks = {core_cost} constraints (no compression)");
    println!("  single-circuit equivalent would be {}", BLOCKS * 25_840);
  }
}
