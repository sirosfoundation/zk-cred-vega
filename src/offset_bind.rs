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

/// The literal that closes the table, extended through the holder's
/// COSE_Key header: `6D "deviceKeyInfo" A1 69 "deviceKey" A4 01 02 20 01
/// 21 58 20`.
///
/// Carrying the COSE header in the anchor does three jobs at once. It
/// closes the digest table, it proves the key is an EC2 P-256 key
/// (`kty: 2`, `crv: 1`) rather than something whose coordinates sit
/// elsewhere, and it fixes the byte positions of `x` and `y` at constant
/// deltas so the holder-binding gadget can read them without a second
/// search. COSE's canonical integer-key order puts the labels at
/// `01 < 20 < 21 < 22`, so this layout is the only one a conformant
/// encoder produces for a P-256 key.
const DEVICE_KEY_INFO: &[u8] = b"\x6ddeviceKeyInfo\xa1\x69deviceKey\xa4\x01\x02\x20\x01\x21\x58\x20";

/// `x` starts immediately after [`DEVICE_KEY_INFO`].
const DEVICE_KEY_X_DELTA: usize = DEVICE_KEY_INFO.len();
/// `y` follows `x`'s 32 bytes plus its own `22 58 20` label and header.
const DEVICE_KEY_Y_DELTA: usize = DEVICE_KEY_X_DELTA + 32 + 3;

/// The whole `validityInfo` block, which sits before `valueDigests` in
/// canonical MSO key order. Its layout is fully fixed for a conformant
/// issuer, so one anchored window covers all of it:
///
/// ```text
/// 6c "validityInfo" a3 66 "signed" c0 74   23 bytes  (anchor literal)
/// <signed, 20 ASCII>                       20
/// 69 "validFrom" c0 74                     12
/// <validFrom, 20 ASCII>                    20
/// 6a "validUntil" c0 74                    13
/// <validUntil, 20 ASCII>                   20
/// ```
///
/// The `74` in each `c0 74` is a `tstr` header for exactly 20 bytes, so
/// pinning these literals also pins every timestamp to the 20-character
/// RFC 3339 UTC form `YYYY-MM-DDTHH:MM:SSZ`. An issuer emitting
/// fractional seconds or a numeric offset produces a longer string, a
/// different header byte, and an honest credential this circuit cannot
/// prove -- a completeness limit, not a soundness one, and the reason it
/// is spelled out here.
pub const VALIDITY_OPEN: &[u8] = b"\x6cvalidityInfo\xa3\x66signed\xc0\x74";
const VALIDITY_MID_FROM: &[u8] = b"\x69validFrom\xc0\x74";
const VALIDITY_MID_UNTIL: &[u8] = b"\x6avalidUntil\xc0\x74";
/// Timestamps are `YYYY-MM-DDTHH:MM:SSZ`.
pub const TIMESTAMP_LEN: usize = 20;
/// Offset of `validFrom`'s first character from the anchor.
pub const VALID_FROM_DELTA: usize = 23 + TIMESTAMP_LEN + 12;
/// Offset of `validUntil`'s first character from the anchor.
pub const VALID_UNTIL_DELTA: usize = VALID_FROM_DELTA + TIMESTAMP_LEN + 13;
/// Everything above, as one window.
pub const VALIDITY_WINDOW_LEN: usize = VALID_UNTIL_DELTA + TIMESTAMP_LEN;

/// Decomposes a selected window's packs back into bits, eight per byte,
/// most-significant first.
///
/// Returns bits rather than byte values on purpose. `AllocatedNum`'s own
/// `to_bits_le` decomposes to the *field's* full width -- 256 constraints
/// per byte, or about 27k for a window this size -- whereas allocating
/// eight bits and checking one recomposition per pack costs roughly 130
/// per pack. Callers comparing or matching bytes want the bits anyway.
pub fn unpack_window_bits<Scalar, CS>(
  mut cs: CS,
  window: &SelectedWindow<Scalar>,
  total_len: usize,
) -> Result<Vec<Boolean>, SynthesisError>
where
  Scalar: PrimeField,
  CS: ConstraintSystem<Scalar>,
{
  let mut out = Vec::with_capacity(total_len * 8);
  for (p, pack) in window.packs.iter().enumerate() {
    let lo = p * BYTES_PER_PACK;
    let n = (total_len - lo).min(BYTES_PER_PACK);
    let value = pack.get_value();
    let mut recomposed = LinearCombination::<Scalar>::zero();
    for i in 0..n {
      // Big-endian within the pack, matching `pack_at`'s weighting:
      // `to_repr` is little-endian, so big-endian byte `i` of an
      // `n`-byte number sits at little-endian index `n - 1 - i`.
      let shift = n - 1 - i;
      let native = value.map(|v| v.to_repr().as_ref()[shift]);
      for bit_idx in 0..8 {
        let b = bellpepper_core::boolean::AllocatedBit::alloc(
          cs.namespace(|| format!("pack {p} byte {i} bit {bit_idx}")),
          native.map(|byte| (byte >> (7 - bit_idx)) & 1 == 1),
        )?;
        let mut coeff = Scalar::ONE;
        for _ in 0..shift {
          coeff *= Scalar::from(256u64);
        }
        for _ in 0..(7 - bit_idx) {
          coeff = coeff.double();
        }
        recomposed = recomposed + (coeff, b.get_variable());
        out.push(Boolean::from(b));
      }
    }
    // Booleanity is enforced by `AllocatedBit::alloc`; this ties the bits
    // to the pack, so they cannot be chosen independently of the window.
    cs.enforce(
      || format!("pack {p} recomposes from its bits"),
      |lc| lc + &recomposed,
      |lc| lc + CS::one(),
      |lc| lc + pack.get_variable(),
    );
  }
  Ok(out)
}

/// The eight bits of a byte-valued number, most-significant first.
///
/// Also *bounds* the value to a byte: the recomposition constraint plus
/// `AllocatedBit`'s own booleanity leave no other satisfying assignment.
/// Used instead of `AllocatedNum::to_bits_le`, which decomposes to the
/// field's full 256-bit width and costs thirty times as much.
pub fn byte_bits<Scalar, CS>(mut cs: CS, byte: &AllocatedNum<Scalar>) -> Result<Vec<Boolean>, SynthesisError>
where
  Scalar: PrimeField,
  CS: ConstraintSystem<Scalar>,
{
  let native = byte.get_value().map(|v| v.to_repr().as_ref()[0]);
  let mut bits = Vec::with_capacity(8);
  let mut recomposed = LinearCombination::<Scalar>::zero();
  for i in 0..8 {
    let b = bellpepper_core::boolean::AllocatedBit::alloc(
      cs.namespace(|| format!("bit {i}")),
      native.map(|n| (n >> (7 - i)) & 1 == 1),
    )?;
    let mut coeff = Scalar::ONE;
    for _ in 0..(7 - i) {
      coeff = coeff.double();
    }
    recomposed = recomposed + (coeff, b.get_variable());
    bits.push(Boolean::from(b));
  }
  cs.enforce(|| "byte recomposes from its bits", |lc| lc + &recomposed, |lc| lc + CS::one(), |lc| lc + byte.get_variable());
  Ok(bits)
}

/// A credential's validity window, twenty ASCII characters each.
pub type ValidityWindow<Scalar> = (Vec<AllocatedNum<Scalar>>, Vec<AllocatedNum<Scalar>>);

/// Reads the credential's validity window out of the signed bytes.
///
/// Returns `(validFrom, validUntil)` as twenty byte-values each. Both
/// stay private: a verifier needs to know the credential *is* valid now,
/// not when it was issued or when it expires -- those are a stable
/// per-credential fingerprint, and publishing them is one of the leaks
/// that made the previous circuit revision linkable.
pub fn bind_validity<Scalar, CS>(
  mut cs: CS,
  bits: &[Boolean],
  native: &[u8],
  validity_info_offset: usize,
) -> Result<ValidityWindow<Scalar>, SynthesisError>
where
  Scalar: PrimeField,
  CS: ConstraintSystem<Scalar>,
{
  if validity_info_offset + VALIDITY_WINDOW_LEN > native.len() {
    return Err(reject(format!(
      "validityInfo at {validity_info_offset} plus {VALIDITY_WINDOW_LEN} bytes runs past the {}-byte buffer",
      native.len()
    )));
  }
  // One window over the whole block: one selector instead of five, since
  // every field inside sits at a constant delta from the anchor.
  let window = select_window::<Scalar, _>(
    cs.namespace(|| "validityInfo"),
    bits,
    native,
    &anchor_offsets(native.len()),
    validity_info_offset,
    VALIDITY_WINDOW_LEN,
  )?;
  let wb = unpack_window_bits(cs.namespace(|| "validity bytes"), &window, VALIDITY_WINDOW_LEN)?;

  // Pin the three literal segments. Together they prove this really is
  // `validityInfo` and that each timestamp is exactly twenty characters.
  let mut literals: Vec<(usize, u8)> = Vec::new();
  for (i, &b) in VALIDITY_OPEN.iter().enumerate() {
    literals.push((i, b));
  }
  for (i, &b) in VALIDITY_MID_FROM.iter().enumerate() {
    literals.push((VALIDITY_OPEN.len() + TIMESTAMP_LEN + i, b));
  }
  for (i, &b) in VALIDITY_MID_UNTIL.iter().enumerate() {
    literals.push((VALID_FROM_DELTA + TIMESTAMP_LEN + i, b));
  }
  for (at, expect) in literals {
    for bit in 0..8 {
      let want = (expect >> (7 - bit)) & 1 == 1;
      cs.enforce(
        || format!("validityInfo literal byte {at} bit {bit}"),
        |lc| lc + &wb[at * 8 + bit].lc(CS::one(), Scalar::ONE) - if want { (Scalar::ONE, CS::one()) } else { (Scalar::ZERO, CS::one()) },
        |lc| lc + CS::one(),
        |lc| lc,
      );
    }
  }

  let take = |cs: &mut CS, delta: usize, tag: &str| -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
    (0..TIMESTAMP_LEN)
      .map(|i| {
        let mut lc = LinearCombination::<Scalar>::zero();
        let mut coeff = Scalar::from(128u64);
        for bit in 0..8 {
          lc = lc + &wb[(delta + i) * 8 + bit].lc(CS::one(), coeff);
          coeff *= Scalar::from(2u64).invert().unwrap();
        }
        let v = AllocatedNum::alloc(cs.namespace(|| format!("{tag} {i}")), || {
          let mut acc = 0u8;
          for bit in 0..8 {
            if wb[(delta + i) * 8 + bit].get_value().ok_or(SynthesisError::AssignmentMissing)? {
              acc |= 1 << (7 - bit);
            }
          }
          Ok(Scalar::from(acc as u64))
        })?;
        cs.enforce(|| format!("{tag} {i} value"), |l| l + &lc, |l| l + CS::one(), |l| l + v.get_variable());
        Ok(v)
      })
      .collect()
  };
  let from = take(&mut cs, VALID_FROM_DELTA, "validFrom")?;
  let until = take(&mut cs, VALID_UNTIL_DELTA, "validUntil")?;
  Ok((from, until))
}

/// Smallest number of bytes that can follow the `deviceKeyInfo` key in a
/// conformant MSO: the key's own value (`A1 69 "deviceKey"` + a 75-byte
/// P-256 COSE_Key) plus `digestAlgorithm` and its value. Measured against
/// real fixtures, which put `deviceKeyInfo` exactly 124 bytes from the
/// end of the `Sig_structure`.
const MIN_BYTES_AFTER_DEVICE_KEY_INFO: usize = 124;

// CIRCUIT-02. The device-key windows are read at a constant delta from
// the `deviceKeyInfo` anchor, but anchors may only be searched over
// `0..=len - MAX_ANCHOR_WINDOW`. If a credential pushes `deviceKeyInfo`
// late enough, `y` lands past the last candidate and an *honest*
// credential is rejected -- a completeness failure no honest-path test
// would catch, because it only appears near the size budget.
//
// These two constants were chosen independently and the margin between
// them was 8 bytes. Assert it, so raising `MAX_ANCHOR_WINDOW` or moving
// the COSE layout fails the build instead of silently shrinking the
// usable credential size.
const _: () = assert!(
  MAX_ANCHOR_WINDOW + DEVICE_KEY_Y_DELTA + 32 <= MIN_BYTES_AFTER_DEVICE_KEY_INFO + 32,
  "a credential near the byte budget would push the deviceKey y window past the last \
   anchor candidate, rejecting an honest credential"
);

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
  /// The holder's device public key, read out of the issuer-signed bytes.
  ///
  /// **Keep these private.** They are the holder binding's input, not its
  /// output: proving possession of the matching private key is what makes
  /// a presentation unforgeable, while publishing the key itself is a
  /// stable per-credential identifier and destroys unlinkability. An
  /// earlier circuit revision inputized exactly these two values.
  pub device_key: (AllocatedNum<Scalar>, AllocatedNum<Scalar>),
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
  /// Offset of the `6C "validityInfo"` key.
  pub validity_info: usize,
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
    3,
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

  // ---- The holder's device key, read but NOT revealed ---------------
  // Both coordinates sit at constant deltas from the anchor, so their
  // windows are selected and then *pinned* to those deltas rather than
  // trusted: a free offset would let a prover read 32 bytes of their
  // choosing and call them the device key.
  let mut coords = Vec::with_capacity(2);
  for (label, delta) in [("device key x", DEVICE_KEY_X_DELTA), ("device key y", DEVICE_KEY_Y_DELTA)] {
    let at = landmarks.device_key_info + delta;
    if at + 32 > native.len() {
      return Err(reject(format!("{label} at {at} runs past the {}-byte buffer", native.len())));
    }
    let w = select_window::<Scalar, _>(
      cs.namespace(|| label),
      bits,
      native,
      &anchor_offsets(native.len()),
      at,
      32,
    )?;
    cs.enforce(
      || format!("{label} sits at +{delta} from deviceKeyInfo"),
      |lc| lc + &w.offset - &end_window.offset - (Scalar::from(delta as u64), CS::one()),
      |lc| lc + CS::one(),
      |lc| lc,
    );
    // Two 16-byte packs recombine into one 256-bit coordinate. A valid
    // P-256 x or y is below the base field's modulus, so this cannot
    // wrap for a well-formed credential -- and `check_on_curve` in the
    // signature gadget rejects anything that is not a curve point.
    let mut shift = Scalar::ONE;
    for _ in 0..16 {
      shift *= Scalar::from(256u64);
    }
    let value = w.packs[0].get_value().and_then(|hi| w.packs[1].get_value().map(|lo| hi * shift + lo));
    let coord = AllocatedNum::alloc(cs.namespace(|| format!("{label} value")), || {
      value.ok_or(SynthesisError::AssignmentMissing)
    })?;
    cs.enforce(
      || format!("{label} recombines its packs"),
      |lc| lc + (shift, w.packs[0].get_variable()) + w.packs[1].get_variable(),
      |lc| lc + CS::one(),
      |lc| lc + coord.get_variable(),
    );
    coords.push(coord);
  }
  let device_key = (coords[0].clone(), coords[1].clone());

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

  Ok(RegionBinding { region_start, region_end, doc_type: doc_window.packs, device_key })
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
