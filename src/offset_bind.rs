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
//! # Scope and what is deliberately left unproved
//!
//! Three anchors are pinned, not two:
//!
//! 1. `6C "valueDigests" <namespace-count map header>` — opens the table.
//! 2. `<tstr target namespace><entry-count map header>` — opens the
//!    requested namespace's own sub-map, somewhere inside the table.
//! 3. `6D "deviceKeyInfo"` — the MSO key that canonically follows
//!    `valueDigests`, closing the table.
//!
//! A digest offset must sit at or after (2) and strictly before (3). That
//! is a **lower** bound at the requested namespace and a **hard upper**
//! bound at the end of the whole table.
//!
//! The upper bound is the one carrying the security weight, because
//! everything past it is `deviceKeyInfo` — see the attack above. The
//! lower bound rules out an earlier namespace. What is *not* proved is
//! that the offset falls before the *next* namespace begins, so a digest
//! in a later namespace of the same credential would also satisfy this.
//!
//! That gap is deliberate, and it does not weaken an age statement: the
//! prover must still exhibit a preimage of the digest they point at, and
//! the only preimage they have for any entry is the `IssuerSignedItem`
//! the issuer actually signed. To exploit a later namespace they would
//! need the issuer to have signed a *second* `birth_date` item, with a
//! different date, in that namespace. None of the three document types
//! this targets does that. Closing it properly means walking the entry
//! chain, which costs real constraints for no reachable attack today.
//!
//! An earlier revision pinned only one namespace and anchored the
//! region's end directly on `deviceKeyInfo`, which assumed the requested
//! namespace was the *last* one. ISO/IEC 23220-4 Photo ID breaks that:
//! `birth_date` lives in `org.iso.23220.1`, which sorts first of its
//! three namespaces, so its entries are followed by another namespace
//! rather than by `deviceKeyInfo`.

use bellpepper_core::{
  boolean::Boolean,
  num::AllocatedNum,
  ConstraintSystem, LinearCombination, SynthesisError,
};
use ff::PrimeField;

/// Rejects a malformed witness instead of aborting.
///
/// Every check in this module that used to be an `assert!` funnels
/// through here. That matters more for this crate than for a pure-Rust
/// library: it is built as `cdylib`/`staticlib` and linked into an
/// Android AAR and a Go cgo binary, so a panic does not unwind into a
/// caller that can handle it — it takes the host process down. A wallet
/// should reject a malformed credential, not crash.
///
/// `SynthesisError` has no variant carrying a message, and these are
/// exactly the checks that catch an integration wiring its landmarks up
/// wrongly — which is how two bugs in this module's own development were
/// found. So the reason goes to stderr under `debug_assertions` and the
/// caller gets `Unsatisfiable`; a release build prints nothing.
pub(crate) fn reject(reason: impl core::fmt::Display) -> SynthesisError {
  #[cfg(debug_assertions)]
  eprintln!("zk-cred-vega: rejecting malformed witness: {reason}");
  #[cfg(not(debug_assertions))]
  let _ = reason;
  SynthesisError::Unsatisfiable
}

/// Bytes packed per field element. 16 bytes is 128 bits, comfortably
/// inside every scalar field this crate targets, and lets a 32-byte
/// digest be compared in two multiplications instead of thirty-two.
pub const BYTES_PER_PACK: usize = 16;

/// The `valueDigests` map key. The namespace-count header follows it and
/// is built from the witnessed count, so a credential with one namespace
/// (mDL, EU PID) and one with three (Photo ID) differ only in that byte.
const VALUE_DIGESTS_OPEN_KEY: &[u8] = b"\x6cvalueDigests";

/// The canonical CBOR map header for a map of `n` entries, one byte below
/// 24 and two from 24 to 255.
fn map_header(n: usize) -> Vec<u8> {
  if n < 24 {
    vec![0xa0 | n as u8]
  } else {
    vec![0xb8, n as u8]
  }
}

/// The literal that closes it: `6D "deviceKeyInfo"`.
const DEVICE_KEY_INFO: &[u8] = b"\x6ddeviceKeyInfo";

/// `67 "docType"`.
const DOC_TYPE_KEY: &[u8] = b"\x67docType";

/// The canonical CBOR text-string header for a string of `len` bytes.
///
/// One byte below 24, two from 24 to 255. This matters more than it
/// looks: `eu.europa.ec.eudi.pid.1` is exactly 23 characters, one short
/// of needing the wider form, while several of its siblings in the same
/// family — `eu.europa.ec.eudi.hiid.1`, `.iban.1`, `.ehic.1` at 24, and
/// `.msisdn.1` at 26 — are already over it. An earlier revision assumed
/// the one-byte form throughout, which happened to be right for the one
/// document type it was tested against and wrong for the next one.
fn tstr_header(len: usize) -> Result<Vec<u8>, SynthesisError> {
  if len >= 256 {
    return Err(reject(format!("text-string header for {len} bytes needs more than two bytes")));
  }
  Ok(if len < 24 {
    vec![0x60 | len as u8]
  } else {
    vec![0x78, len as u8]
  })
}

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

/// Largest anchor literal this module will select.
///
/// Anchor searches use a candidate set sized by *this* constant rather
/// than by the literal's own length, so that the number of candidates --
/// and therefore the number of constraints -- does not depend on how long
/// a credential's `docType` or namespace happens to be. Deriving it from
/// the literal leaked the document type into the circuit shape: an mDL
/// and an EU PID differed by 24 constraints, which under a fixed-setup
/// folding system means two setups for what is meant to be one circuit.
pub const MAX_ANCHOR_WINDOW: usize = 48;

/// The candidate offsets every anchor search uses. Constant for a given
/// buffer size, independent of the literal being searched for.
pub fn anchor_offsets(buffer_len: usize) -> Vec<usize> {
  window_offsets(buffer_len, MAX_ANCHOR_WINDOW)
}

/// Every offset at which a `window_len`-byte window fits entirely inside
/// `len` bytes — that is `0..=len - window_len`, **inclusive** of the
/// last one. Getting this wrong by one silently excludes a legal offset,
/// and `select_window`'s own assertion then rejects an honest prover.
pub fn window_offsets(len: usize, window_len: usize) -> Vec<usize> {
  if window_len > len {
    return Vec::new();
  }
  (0..=len - window_len).collect()
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
  if !candidates.contains(&real_offset) {
    return Err(reject(format!("offset {real_offset} is not among the {} candidate offsets", candidates.len())));
  }
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

/// Selects and pins an anchor literal, with a candidate set and pack
/// count that are both independent of the literal's content.
///
/// A `select_window` call emits one selection constraint per candidate per
/// pack, so a literal that rounds to a different number of packs changes
/// the circuit's shape. Each anchor therefore declares the pack count it
/// must always occupy — the counts differ between anchors, which is fine;
/// what matters is that none of them varies with the *document*.
///
/// That is a real restriction on which document types this circuit can
/// serve without a new setup, so it is enforced rather than assumed: a
/// `docType` or namespace long enough to spill into another pack has to
/// be caught here, not discovered as a shape mismatch after the artifact
/// ships. The three target types sit comfortably inside their bands --
/// namespace windows run 18 to 26 bytes and `docType` windows 30 to 32,
/// both two packs.
pub fn select_anchor<Scalar, CS>(
  mut cs: CS,
  bits: &[Boolean],
  native: &[u8],
  real_offset: usize,
  expected: &[u8],
  expected_packs: usize,
  label: &str,
) -> Result<SelectedWindow<Scalar>, SynthesisError>
where
  Scalar: PrimeField,
  CS: ConstraintSystem<Scalar>,
{
  let packs = expected.len().div_ceil(BYTES_PER_PACK);
  if packs != expected_packs {
    return Err(reject(format!(
      "{label} anchor is {} bytes ({packs} packs) but this circuit's shape fixes it at \
       {expected_packs}, so such a credential would need its own setup",
      expected.len()
    )));
  }
  let window = select_window::<Scalar, _>(
    cs.namespace(|| "select"),
    bits,
    native,
    &anchor_offsets(native.len()),
    real_offset,
    expected.len(),
  )?;
  enforce_window_equals(cs.namespace(|| "literal"), &window, expected)?;
  Ok(window)
}

/// Constrains a selected window to equal a fixed byte string.
pub fn enforce_window_equals<Scalar, CS>(mut cs: CS, window: &SelectedWindow<Scalar>, expected: &[u8]) -> Result<(), SynthesisError>
where
  Scalar: PrimeField,
  CS: ConstraintSystem<Scalar>,
{
  let packed = pack_constant::<Scalar>(expected);
  if packed.len() != window.packs.len() {
    // Unlike the other checks here this one signals a caller bug rather
    // than a bad credential — the literal's length has to match the
    // window the caller already selected. It still returns instead of
    // panicking, because across the FFI boundary a panic is a host
    // process abort either way.
    return Err(reject(format!(
      "expected literal packs into {} field elements but the window has {}",
      packed.len(),
      window.packs.len()
    )));
  }
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
  /// Offset of the first entry of the **requested namespace's** sub-map:
  /// the lower bound a digest offset must meet.
  pub region_start: LinearCombination<Scalar>,
  /// Offset of the `deviceKeyInfo` key, which closes the whole
  /// `valueDigests` table: the hard upper bound.
  pub region_end: LinearCombination<Scalar>,
  /// The credential's `docType`, read from the signed bytes so a verifier
  /// learns which document type the proof is about.
  pub doc_type: Vec<AllocatedNum<Scalar>>,
}

/// What the prover claims the credential *is*, as opposed to where its
/// parts sit. Pinned to the signed bytes by the anchors, so a prover
/// cannot name a document type, namespace or table shape the issuer did
/// not sign.
#[derive(Clone, Copy, Debug)]
pub struct CredentialShape<'a> {
  /// The namespace whose digests the proof is about — `org.iso.18013.5.1`
  /// for an mDL, `org.iso.23220.1` for a Photo ID's `birth_date`.
  pub namespace: &'a str,
  /// The credential's `docType`, which for an mDL is neither equal to nor
  /// the same length as its namespace.
  pub doc_type: &'a str,
  /// How many namespaces the `valueDigests` table holds: one for an mDL
  /// or EU PID, three for a Photo ID.
  pub num_namespaces: usize,
  /// How many entries the requested namespace's own map holds.
  pub num_entries: usize,
}

/// Native (out-of-circuit) landmarks the prover supplies as witness.
/// A prover that lies about any of them fails the anchor checks.
#[derive(Clone, Copy, Debug)]
pub struct Landmarks {
  /// Offset of the `6C "valueDigests"` key.
  pub value_digests_key: usize,
  /// Offset of the requested namespace's own `tstr` key inside the
  /// `valueDigests` table. For a single-namespace credential this sits
  /// immediately after the table header; for Photo ID it is one of
  /// three.
  pub namespace_key: usize,
  /// Offset of the requested namespace's first entry — the byte after
  /// its entry-count map header.
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
/// Each landmark is searched over *every* offset where its window fits.
/// A real MSO puts all three in the first couple of hundred bytes, so a
/// narrower candidate set would be cheaper — but it would also bake an
/// assumption about issuer layout into the circuit shape, and the saving
/// is a fraction of a percent against the hash this sits beside. If that
/// ever becomes worth it, the bound belongs in a parameter here rather
/// than hard-coded inside.
pub fn bind_digest_region<Scalar, CS>(
  mut cs: CS,
  bits: &[Boolean],
  native: &[u8],
  shape: CredentialShape<'_>,
  landmarks: Landmarks,
) -> Result<RegionBinding<Scalar>, SynthesisError>
where
  Scalar: PrimeField,
  CS: ConstraintSystem<Scalar>,
{
  if shape.num_entries >= 256 {
    return Err(reject(format!("{} valueDigests entries needs a wider map header than this binding encodes", shape.num_entries)));
  }
  if shape.num_namespaces >= 256 {
    return Err(reject(format!("{} namespaces needs a wider map header than this binding encodes", shape.num_namespaces)));
  }

  // ---- Anchor 1: `6C "valueDigests" <namespace-count map header>` ---
  // Opens the table. Pinning the namespace count here stops a prover
  // claiming a table of a different shape than the issuer signed.
  let mut open = VALUE_DIGESTS_OPEN_KEY.to_vec();
  open.extend_from_slice(&map_header(shape.num_namespaces));
  let open_len = open.len();
  let table_window = select_anchor::<Scalar, _>(
    cs.namespace(|| "valueDigests anchor"),
    bits,
    native,
    landmarks.value_digests_key,
    &open,
    1,
    "valueDigests",
  )?;

  // ---- Anchor 2: `<tstr namespace><entry-count map header>` --------
  // The requested namespace's own sub-map, somewhere inside the table.
  // For a single-namespace credential this sits immediately after anchor
  // 1; for Photo ID it is one of three, and `org.iso.23220.1` -- where
  // `birth_date` lives -- sorts first rather than last.
  let mut ns_open = tstr_header(shape.namespace.len())?;
  ns_open.extend_from_slice(shape.namespace.as_bytes());
  ns_open.extend_from_slice(&map_header(shape.num_entries));
  let ns_open_len = ns_open.len();
  let ns_window = select_anchor::<Scalar, _>(
    cs.namespace(|| "namespace anchor"),
    bits,
    native,
    landmarks.namespace_key,
    &ns_open,
    2,
    "namespace",
  )?;

  // The namespace's entries begin right after its own header.
  let region_start = ns_window.offset.clone() + (Scalar::from(ns_open_len as u64), CS::one());

  // The namespace sub-map must sit inside the table, not before it.
  if landmarks.namespace_key < landmarks.value_digests_key + open_len {
    return Err(reject(format!(
      "the namespace key at {} precedes the end of the valueDigests header at {}",
      landmarks.namespace_key,
      landmarks.value_digests_key + open_len
    )));
  }
  enforce_ge(
    cs.namespace(|| "namespace sits inside the table"),
    &ns_window.offset,
    &(table_window.offset.clone() + (Scalar::from(open_len as u64), CS::one())),
    landmarks.namespace_key - (landmarks.value_digests_key + open_len),
    16,
  )?;

  // ---- Anchor 3: `6D "deviceKeyInfo"` ------------------------------
  // Closes the whole table. This is the bound doing the security work:
  // everything past it is the holder's own deviceKey.
  let end_window = select_anchor::<Scalar, _>(
    cs.namespace(|| "deviceKeyInfo anchor"),
    bits,
    native,
    landmarks.device_key_info,
    DEVICE_KEY_INFO,
    1,
    "deviceKeyInfo",
  )?;
  let region_end = end_window.offset.clone();

  // The span must be non-empty and must not run backwards. Without this
  // a prover could claim an end anchor preceding the start and satisfy
  // the digest range check vacuously.
  if landmarks.device_key_info <= landmarks.region_start {
    return Err(reject(format!(
      "landmarks describe an empty or inverted digest region: starts at {}, ends at {}",
      landmarks.region_start, landmarks.device_key_info
    )));
  }
  enforce_ge(
    cs.namespace(|| "region end follows region start"),
    &region_end,
    &region_start,
    landmarks.device_key_info - landmarks.region_start,
    16,
  )?;

  // ---- docType, read out for the verifier --------------------------
  let doc_type_header = tstr_header(shape.doc_type.len())?;
  let doc_type_window_len = DOC_TYPE_KEY.len() + doc_type_header.len() + shape.doc_type.len();

  // The whole window is pinned to a literal: the key, the value's tstr
  // header, and the value itself. The docType is a public output, so
  // there is nothing in it to hide — and pinning it to the bytes that
  // were actually signed is what stops a prover naming a document type
  // the issuer did not.
  let mut expected = DOC_TYPE_KEY.to_vec();
  expected.extend_from_slice(&doc_type_header);
  expected.extend_from_slice(shape.doc_type.as_bytes());
  let doc_type_end = landmarks.doc_type_key + doc_type_window_len;
  if doc_type_end > native.len() {
    return Err(reject(format!(
      "docType landmark at {} plus a {doc_type_window_len}-byte window runs past the {}-byte buffer",
      landmarks.doc_type_key,
      native.len()
    )));
  }
  let doc_type_bytes = &native[landmarks.doc_type_key..doc_type_end];
  if doc_type_bytes != expected.as_slice() {
    return Err(reject(format!(
      "the docType landmark at {} does not point at `{}` in the signed bytes",
      landmarks.doc_type_key, shape.doc_type
    )));
  }
  let doc_window = select_anchor::<Scalar, _>(
    cs.namespace(|| "docType anchor"),
    bits,
    native,
    landmarks.doc_type_key,
    &expected,
    2,
    "docType",
  )?;

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
