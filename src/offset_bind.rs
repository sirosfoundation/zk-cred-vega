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
  // `checked_add`, not `+`: the offset is a prover-supplied witness, so a
  // value near `usize::MAX` would overflow on the way to the rejection
  // this check exists to produce — panicking in debug, and in release
  // wrapping to a small number that passes.
  let window_end = validity_info_offset.checked_add(VALIDITY_WINDOW_LEN);
  if window_end.is_none_or(|end| end > native.len()) {
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

/// How many bytes `<tstr header><namespace><entry-count map header>`
/// occupies — the offset from the namespace anchor to the first digest
/// entry.
///
/// Published, so prover and verifier must agree on it exactly. One
/// function rather than three copies: it is computed here to build the
/// anchor, in `mdoc_age_circuit`'s `public_values` to declare it, and
/// checked against the verifier's own namespace in
/// `check_public_values`.
pub fn namespace_prefix_len(namespace: &str, num_entries: usize) -> Result<usize, SynthesisError> {
  if num_entries >= 256 {
    return Err(reject(format!(
      "{num_entries} valueDigests entries needs a wider map header than this binding encodes"
    )));
  }
  Ok(tstr_header(namespace.len())?.len() + namespace.len() + map_header(num_entries).len())
}

/// Most entries one `valueDigests` namespace may hold.
///
/// A shape constant, so it bounds every document this circuit serves,
/// not just the ones in the fixtures: the entry walk below emits
/// [`MAX_NAMESPACE_ENTRIES`] steps whatever the credential holds, and
/// masks the ones past the real count. The largest real namespace we
/// target is an mDL's 35.
pub const MAX_NAMESPACE_ENTRIES: usize = 64;

/// `58 20` plus 32 bytes: a `valueDigests` entry's value is a
/// `bstr .size 32` in every profile this circuit serves.
const DIGEST_VALUE_LEN: usize = 34;

/// The window each walk step reads: the `digestID`'s head plus enough to
/// reach the `58 20` that opens its value at any canonical width.
const ENTRY_HEAD_WINDOW: usize = 7;

/// The four canonical CBOR `uint` widths a `digestID` can take, with the
/// head byte that selects each.
///
/// ISO 18013-5 §9.1.2.4 puts `digestID` below 2^31, so the eight-byte
/// form cannot occur; and canonical CBOR (RFC 8949 §4.2.1) makes the
/// encoding unique, which is what lets one head byte determine the width
/// rather than merely be consistent with it.
const DIGEST_ID_WIDTHS: [(usize, Option<u8>); 4] = [(1, None), (2, Some(0x18)), (3, Some(0x19)), (5, Some(0x1a))];

/// Walks the requested namespace's entries and returns where its sub-map
/// ends.
///
/// # Why this is not just `deviceKeyInfo`
///
/// It was, and that was a soundness break. `deviceKeyInfo` closes the
/// whole `valueDigests` table. For a single-namespace mDL or EU PID the
/// two offsets coincide, but `org.iso.23220.1` sorts *first* of a Photo
/// ID's three namespaces, so its entries are followed by 1,096 bytes of
/// two other namespaces — and every digest in those satisfied a range
/// check bounded by the table's end. A credential carrying `birth_date`
/// in two namespaces could prove the favourable one while publishing the
/// name of the other; `a_digest_from_a_later_namespace_is_rejected`
/// carries that exploit, with a thirteen-year-old passing an
/// eighteen-plus check.
///
/// # Why a walk
///
/// The sub-map's end is determined by its content and nothing else. An
/// entry is a `digestID` `uint` followed by `58 20` and 32 bytes, so the
/// only thing that varies is the `digestID`'s width — one, two, three or
/// five bytes, decided uniquely by its head byte under canonical CBOR.
/// Summing `width + 34` over the entries gives the end exactly.
///
/// Bounding it instead by a width *range* (`34n ..= 38n`) narrows the
/// hole without closing it: the next namespace's first digests still land
/// inside. Anchoring on "a namespace key sorting after this one" does not
/// close it either, because a prover wants a *larger* region and any
/// later namespace satisfies that. The end has to be the immediate
/// successor, and only the content says where that is.
///
/// # Cost
///
/// One `ENTRY_HEAD_WINDOW`-byte selection per step. Seven bytes rather
/// than one so that a single window reaches both the head byte and the
/// `58 20` that must follow it at whichever width the head declares —
/// checking the value's header as well as the key's costs nothing extra
/// this way, and leaves the step sound by construction rather than by an
/// appeal to what the CDDL says a well-formed MSO contains.
#[allow(clippy::too_many_arguments)]
pub fn walk_namespace_entries<Scalar, CS>(
  mut cs: CS,
  bits: &[Boolean],
  native: &[u8],
  region_start: &LinearCombination<Scalar>,
  region_start_native: usize,
  num_entries: usize,
) -> Result<(LinearCombination<Scalar>, AllocatedNum<Scalar>), SynthesisError>
where
  Scalar: PrimeField,
  CS: ConstraintSystem<Scalar>,
{
  if num_entries == 0 || num_entries > MAX_NAMESPACE_ENTRIES {
    return Err(reject(format!(
      "the requested namespace holds {num_entries} entries, outside this circuit's fixed        1..={MAX_NAMESPACE_ENTRIES}"
    )));
  }
  let one = CS::one();

  // How many entries, as a one-hot over a constant candidate set. The
  // count is also published, and the verifier checks it against the
  // entry-count map header in the namespace window it already parses —
  // so a prover cannot shorten the walk to stop early.
  let mut count_sel = Vec::with_capacity(MAX_NAMESPACE_ENTRIES);
  let mut count_sum = LinearCombination::<Scalar>::zero();
  let mut count_lc = LinearCombination::<Scalar>::zero();
  for n in 1..=MAX_NAMESPACE_ENTRIES {
    let b = bellpepper_core::boolean::AllocatedBit::alloc(
      cs.namespace(|| format!("count {n}")),
      Some(n == num_entries),
    )?;
    count_sum = count_sum + b.get_variable();
    count_lc = count_lc + (Scalar::from(n as u64), b.get_variable());
    count_sel.push(b);
  }
  cs.enforce(|| "exactly one entry count", |lc| lc + &count_sum, |lc| lc + one, |lc| lc + one);
  let entries = AllocatedNum::alloc(cs.namespace(|| "entry count"), || Ok(Scalar::from(num_entries as u64)))?;
  cs.enforce(
    || "the published entry count is the one that bounds the walk",
    |lc| lc + &count_lc,
    |lc| lc + one,
    |lc| lc + entries.get_variable(),
  );

  let mut here = region_start.clone();
  let mut here_native = region_start_native;
  for i in 0..MAX_NAMESPACE_ENTRIES {
    let mut cs = cs.namespace(|| format!("entry {i}"));
    // Live while `i` is inside the real count: a free sum over the
    // counts that reach past entry `i`.
    let mut live = LinearCombination::<Scalar>::zero();
    for (n, b) in count_sel.iter().enumerate() {
      if n + 1 > i {
        live = live + b.get_variable();
      }
    }
    let is_live = i < num_entries;

    // Past the last entry `here` is the sub-map's end, which is a
    // namespace key or `deviceKeyInfo` — real bytes either way, so the
    // window still selects; its content is simply not constrained.
    let at = if here_native + ENTRY_HEAD_WINDOW <= native.len() { here_native } else { 0 };
    let head = select_window::<Scalar, _>(
      cs.namespace(|| "head"),
      bits,
      native,
      &window_offsets(native.len(), ENTRY_HEAD_WINDOW),
      at,
      ENTRY_HEAD_WINDOW,
    )?;
    cs.enforce(
      || "the step reads where the walk has reached",
      |lc| lc + &head.offset - &here,
      |lc| lc + &live,
      |lc| lc,
    );
    let head_bits = unpack_window_bits(cs.namespace(|| "head bits"), &head, ENTRY_HEAD_WINDOW)?;

    // Which `digestID` width this entry uses. `live` rather than one, so
    // every constraint below falls away past the last entry.
    let mut width_sel = Vec::with_capacity(DIGEST_ID_WIDTHS.len());
    let mut width_sum = LinearCombination::<Scalar>::zero();
    let real_width = if is_live { digest_id_width(native, here_native)? } else { 0 };
    for (w, _) in DIGEST_ID_WIDTHS {
      let b = bellpepper_core::boolean::AllocatedBit::alloc(
        cs.namespace(|| format!("width {w}")),
        Some(is_live && w == real_width),
      )?;
      width_sum = width_sum + b.get_variable();
      width_sel.push(b);
    }
    cs.enforce(|| "one width while live", |lc| lc + &width_sum, |lc| lc + one, |lc| lc + &live);

    let byte = |j: usize| byte_lc::<Scalar>(&head_bits, one, j, Scalar::ONE);
    for (k, (w, head_byte)) in DIGEST_ID_WIDTHS.into_iter().enumerate() {
      let sel = width_sel[k].get_variable();
      match head_byte {
        // The one-byte form: major type 0 and an argument below 24.
        // Canonical CBOR makes the short form mandatory there, so the
        // three top bits being zero and `!(b4 & b3)` is exactly it.
        None => {
          for bit in [0usize, 1, 2] {
            cs.enforce(
              || format!("width {w}: head bit {bit} is zero"),
              |lc| lc + sel,
              |lc| lc + &head_bits[bit].lc(one, Scalar::ONE),
              |lc| lc,
            );
          }
          let b4 = &head_bits[3];
          let b3 = &head_bits[4];
          let both = Boolean::and(cs.namespace(|| "argument is 24 or more"), b4, b3)?;
          cs.enforce(
            || format!("width {w}: the argument is below 24"),
            |lc| lc + sel,
            |lc| lc + &both.lc(one, Scalar::ONE),
            |lc| lc,
          );
        }
        Some(expect) => cs.enforce(
          || format!("width {w}: head byte is {expect:#04x}"),
          |lc| lc + sel,
          |lc| lc + &byte(0) - (Scalar::from(expect as u64), one),
          |lc| lc,
        ),
      }
      // And the value really is a 32-byte byte string, so the entry
      // really is `width + 34` long.
      for (rel, expect) in [(0usize, 0x58u8), (1, 0x20)] {
        cs.enforce(
          || format!("width {w}: value header byte {rel} is {expect:#04x}"),
          |lc| lc + sel,
          |lc| lc + &byte(w + rel) - (Scalar::from(expect as u64), one),
          |lc| lc,
        );
      }
    }

    // Advance by `width + 34` while live, and stand still after.
    let mut step = LinearCombination::<Scalar>::zero();
    for (k, (w, _)) in DIGEST_ID_WIDTHS.into_iter().enumerate() {
      step = step + (Scalar::from((w + DIGEST_VALUE_LEN) as u64), width_sel[k].get_variable());
    }
    here = here + &step;
    if is_live {
      here_native += real_width + DIGEST_VALUE_LEN;
    }
  }

  Ok((here, entries))
}

/// Where the requested namespace's entries end, natively — the same sum
/// `walk_namespace_entries` constrains, computed out of circuit so the
/// prover can supply the range check's witness.
pub fn native_region_end_of(native: &[u8], region_start: usize, num_entries: usize) -> Result<usize, SynthesisError> {
  native_region_end(native, region_start, num_entries)
}

fn native_region_end(native: &[u8], region_start: usize, num_entries: usize) -> Result<usize, SynthesisError> {
  let mut at = region_start;
  for _ in 0..num_entries {
    at = at
      .checked_add(digest_id_width(native, at)? + DIGEST_VALUE_LEN)
      .ok_or_else(|| reject(format!("the namespace's entries overflow from {region_start}")))?;
  }
  Ok(at)
}

/// The canonical CBOR `uint` width at `at`, natively.
fn digest_id_width(native: &[u8], at: usize) -> Result<usize, SynthesisError> {
  match native.get(at) {
    Some(&b) if b < 0x18 => Ok(1),
    Some(0x18) => Ok(2),
    Some(0x19) => Ok(3),
    Some(0x1a) => Ok(5),
    other => Err(reject(format!(
      "the valueDigests entry at {at} opens with {other:?}, which is not a canonical digestID"
    ))),
  }
}

/// `at + len`, rejecting rather than overflowing or running past the
/// buffer.
///
/// Every landmark in [`Landmarks`] is a prover-supplied witness, so each
/// one of these additions takes an arbitrary `usize`. Plain `+` panics in
/// debug and wraps in release, and the wrap is the dangerous half: an
/// offset near `usize::MAX` wraps to a small number that *passes* the
/// bounds check it was supposed to fail.
fn window_end(at: usize, len: usize, native_len: usize, label: &str) -> Result<usize, SynthesisError> {
  match at.checked_add(len) {
    Some(end) if end <= native_len => Ok(end),
    _ => Err(reject(format!("{label} at {at} plus {len} bytes runs past the {native_len}-byte buffer"))),
  }
}

/// How many bytes the `docType` entry `67 "docType" <tstr>` occupies —
/// the published prefix of that anchor's window.
pub fn doc_type_prefix_len(doc_type: &str) -> Result<usize, SynthesisError> {
  Ok(DOC_TYPE_KEY.len() + tstr_header(doc_type.len())?.len() + doc_type.len())
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

/// Width of the two anchors whose *content* depends on the document: the
/// requested namespace's sub-map header and the `docType` entry.
///
/// Fixed, and that is the whole point. An anchor sized to its own
/// literal makes the window's linear combinations span a
/// document-dependent set of message bits, and comparing it to a literal
/// puts document-dependent *constants* in the matrices. Neither changes
/// the constraint count, so a count-only shape test sees nothing — and a
/// proving key set up from one document type then does not fit another,
/// which is the opposite of this circuit's reason to exist.
///
/// These two windows are therefore selected at a constant width and
/// published verbatim; the verifier parses them. 40 bytes covers
/// `67 "docType" 78 <len> <docType>` for a 30-character `docType` and
/// `<tstr ns> <ns> <map header>` for a 36-character namespace, against
/// the longest in use today at 23.
pub const ANCHOR_TEXT_WINDOW: usize = 40;

/// Field elements an [`ANCHOR_TEXT_WINDOW`] window packs into.
pub const ANCHOR_TEXT_PACKS: usize = ANCHOR_TEXT_WINDOW.div_ceil(BYTES_PER_PACK);

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

/// Selects a fixed-width window at `real_offset`, blanks everything past
/// `prefix_len`, and returns the masked window alongside `prefix_len`
/// itself as a bound variable.
///
/// This is how the two anchors whose content depends on the document —
/// the `docType` entry and the requested namespace's sub-map header —
/// reach the verifier. Three things have to hold at once, and only this
/// shape gets all three.
///
/// **The width must be constant.** Sizing a window to its own literal
/// makes its packs span a document-dependent set of message bits, and
/// comparing it to that literal writes the literal into the matrices.
/// Neither shows up in the constraint count, so an mDL, an EU PID and a
/// Photo ID produced three different R1CS instances that a count-only
/// shape test called identical.
///
/// **The tail must not be published.** A constant-width window overruns
/// its literal, and in the namespace's case what follows is the start of
/// the digest table — a `digestID` and part of a 32-byte digest. Those
/// are stable per-credential identifiers, and publishing them is the
/// linkability leak that made r12 unusable. So every byte at or past
/// `prefix_len` is forced to zero before the window is packed.
///
/// **`prefix_len` must be bound to that mask.** It is where the caller
/// takes the digest region to begin, so a prover free to misdeclare it
/// is a prover free to move the region. Deriving the mask and the
/// published length from one one-hot makes them the same quantity rather
/// than two that happen to agree.
pub fn select_masked_text_anchor<Scalar, CS>(
  mut cs: CS,
  bits: &[Boolean],
  native: &[u8],
  real_offset: usize,
  prefix_len: usize,
  label: &str,
) -> Result<(Vec<AllocatedNum<Scalar>>, AllocatedNum<Scalar>), SynthesisError>
where
  Scalar: PrimeField,
  CS: ConstraintSystem<Scalar>,
{
  if prefix_len == 0 || prefix_len > ANCHOR_TEXT_WINDOW {
    return Err(reject(format!(
      "{label} prefix is {prefix_len} bytes, outside this circuit's fixed \
       1..={ANCHOR_TEXT_WINDOW}-byte anchor window"
    )));
  }
  let window = select_window::<Scalar, _>(
    cs.namespace(|| "select"),
    bits,
    native,
    &anchor_offsets(native.len()),
    real_offset,
    ANCHOR_TEXT_WINDOW,
  )?;
  let window_bits = unpack_window_bits(cs.namespace(|| "unpack"), &window, ANCHOR_TEXT_WINDOW)?;

  // One-hot over every length the window admits — a constant candidate
  // set, so the shape does not move with the document.
  let mut len_sel = Vec::with_capacity(ANCHOR_TEXT_WINDOW);
  let mut sum = LinearCombination::<Scalar>::zero();
  let mut len_lc = LinearCombination::<Scalar>::zero();
  for n in 1..=ANCHOR_TEXT_WINDOW {
    let b = bellpepper_core::boolean::AllocatedBit::alloc(
      cs.namespace(|| format!("length {n}")),
      Some(n == prefix_len),
    )?;
    sum = sum + b.get_variable();
    len_lc = len_lc + (Scalar::from(n as u64), b.get_variable());
    len_sel.push(b);
  }
  cs.enforce(|| "exactly one length", |lc| lc + &sum, |lc| lc + CS::one(), |lc| lc + CS::one());
  let prefix = AllocatedNum::alloc(cs.namespace(|| "prefix length"), || Ok(Scalar::from(prefix_len as u64)))?;
  cs.enforce(
    || "the published length is the one that masks the window",
    |lc| lc + &len_lc,
    |lc| lc + CS::one(),
    |lc| lc + prefix.get_variable(),
  );

  // `active[j]` is 1 while `j < prefix_len`: a free sum over the lengths
  // that reach past byte `j`.
  let one = CS::one();
  let mut masked_bytes = Vec::with_capacity(ANCHOR_TEXT_WINDOW);
  for j in 0..ANCHOR_TEXT_WINDOW {
    let mut active = LinearCombination::<Scalar>::zero();
    for (i, b) in len_sel.iter().enumerate() {
      if i + 1 > j {
        active = active + b.get_variable();
      }
    }
    let byte = byte_lc::<Scalar>(&window_bits, one, j, Scalar::ONE);
    let keep = j < prefix_len;
    let value = if keep { native.get(real_offset + j).copied().unwrap_or(0) } else { 0 };
    let out = AllocatedNum::alloc(cs.namespace(|| format!("masked byte {j}")), || Ok(Scalar::from(value as u64)))?;
    cs.enforce(
      || format!("byte {j} survives only inside the prefix"),
      |lc| lc + &byte,
      |lc| lc + &active,
      |lc| lc + out.get_variable(),
    );
    masked_bytes.push(out);
  }

  // Repack the masked bytes the way `pack_at` weights a window, so the
  // verifier reassembles them with one rule.
  let mut packs = Vec::with_capacity(ANCHOR_TEXT_PACKS);
  for p in 0..ANCHOR_TEXT_PACKS {
    let lo = p * BYTES_PER_PACK;
    let n = (ANCHOR_TEXT_WINDOW - lo).min(BYTES_PER_PACK);
    let mut lc = LinearCombination::<Scalar>::zero();
    let mut value = Some(Scalar::ZERO);
    for i in 0..n {
      let mut coeff = Scalar::ONE;
      for _ in 0..(n - 1 - i) {
        coeff *= Scalar::from(256u64);
      }
      lc = lc + (coeff, masked_bytes[lo + i].get_variable());
      value = value.and_then(|a| masked_bytes[lo + i].get_value().map(|b| a + coeff * b));
    }
    let out = AllocatedNum::alloc(cs.namespace(|| format!("masked pack {p}")), || {
      value.ok_or(SynthesisError::AssignmentMissing)
    })?;
    cs.enforce(
      || format!("masked pack {p} recombines"),
      |lc2| lc2 + &lc,
      |lc2| lc2 + CS::one(),
      |lc2| lc2 + out.get_variable(),
    );
    packs.push(out);
  }

  Ok((packs, prefix))
}

/// Selects a window and pins it to a literal that is **the same for
/// every document type**.
///
/// Only for those. A literal that varies with the document — a
/// namespace, a `docType`, an entry count — must not come through here:
/// the comparison puts its bytes into matrix coefficients and the window
/// length decides which message bits each row spans, so two documents
/// get two different R1CS instances with the same constraint count. Use
/// a fixed [`ANCHOR_TEXT_WINDOW`] window and publish it instead, and let
/// the verifier check the content.
///
/// `expected_packs` is still declared and enforced, because a literal
/// that rounds to a different number of packs changes the constraint
/// count too, and a mismatch should fail here rather than show up as an
/// unusable artifact later.
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
  /// The credential's `docType` entry — `67 "docType"`, the value's
  /// `tstr` header and the value — read from the signed bytes at a fixed
  /// [`ANCHOR_TEXT_WINDOW`] width, so a verifier learns which document
  /// type the proof is about and this circuit's shape does not depend on
  /// which that is. Trailing bytes past the `docType` value are whatever
  /// the MSO has there; the verifier checks the prefix.
  pub doc_type: Vec<AllocatedNum<Scalar>>,
  /// The requested namespace's sub-map header, the same way: the `tstr`
  /// header, the namespace itself and its entry-count map header, at a
  /// fixed width.
  pub namespace: Vec<AllocatedNum<Scalar>>,
  /// How many bytes of [`Self::namespace`] that header occupies, so
  /// `region_start` can be `namespace_offset + this` without a
  /// document-dependent constant. Published: a verifier that knows which
  /// namespace it asked for knows what this must be, and checking it is
  /// what stops a prover shifting the digest region by misdeclaring it.
  pub namespace_prefix_len: AllocatedNum<Scalar>,
  /// How many entries the requested namespace holds, as bound by the
  /// entry walk. Published: the verifier reads the same number out of
  /// the entry-count map header in [`Self::namespace`], and checking the
  /// two agree is what stops a prover ending the walk early and
  /// shrinking — or lengthening — the region.
  pub num_entries: AllocatedNum<Scalar>,
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
  /// How many entries the requested namespace's own map holds. Used only
  /// to size the namespace sub-map header natively — it feeds an
  /// allocated variable, never a matrix coefficient.
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

  // ---- Anchor 1: `6C "valueDigests"` -------------------------------
  // Opens the table. The same thirteen bytes in every MSO, so it stays a
  // literal comparison.
  //
  // An earlier revision appended `map_header(num_namespaces)` to pin the
  // table's own shape. That byte is `A1` for an mDL and `A3` for a Photo
  // ID, so it put the *document* into a matrix coefficient — and it
  // bought nothing: the count is used nowhere else, and the only thing
  // this anchor has to establish is a lower bound for where the
  // requested namespace's sub-map may begin. Since a CBOR map header is
  // at least one byte, `+ 14` is a sound lower bound whatever the count,
  // and the sub-map itself is pinned independently by anchor 2.
  let open_len = VALUE_DIGESTS_OPEN_KEY.len() + 1;
  let table_window = select_anchor::<Scalar, _>(
    cs.namespace(|| "valueDigests anchor"),
    bits,
    native,
    landmarks.value_digests_key,
    VALUE_DIGESTS_OPEN_KEY,
    1,
    "valueDigests",
  )?;

  // ---- Anchor 2: `<tstr namespace><entry-count map header>` --------
  // The requested namespace's own sub-map, somewhere inside the table.
  // For a single-namespace credential this sits immediately after anchor
  // 1; for Photo ID it is one of three, and `org.iso.23220.1` -- where
  // `birth_date` lives -- sorts first rather than last.
  //
  // Selected at a fixed width and *published* rather than compared to a
  // literal, because the literal is the namespace and would otherwise
  // reach the matrices. The verifier knows which namespace it asked
  // for, so checking the prefix is its job, and it is free there.
  let mut ns_open = tstr_header(shape.namespace.len())?;
  ns_open.extend_from_slice(shape.namespace.as_bytes());
  ns_open.extend_from_slice(&map_header(shape.num_entries));
  let ns_open_len = ns_open.len();
  if ns_open_len > ANCHOR_TEXT_WINDOW {
    return Err(reject(format!(
      "the namespace sub-map header for `{}` is {ns_open_len} bytes, over this circuit's \
       fixed {ANCHOR_TEXT_WINDOW}-byte anchor window",
      shape.namespace
    )));
  }
  window_end(landmarks.namespace_key, ANCHOR_TEXT_WINDOW, native.len(), "the namespace landmark")?;
  let ns_literal_end = window_end(landmarks.namespace_key, ns_open_len, native.len(), "the namespace header")?;
  if &native[landmarks.namespace_key..ns_literal_end] != ns_open.as_slice() {
    return Err(reject(format!(
      "the namespace landmark at {} does not point at `{}` in the signed bytes",
      landmarks.namespace_key, shape.namespace
    )));
  }
  let ns_offset = select_window::<Scalar, _>(
    cs.namespace(|| "namespace offset"),
    bits,
    native,
    &anchor_offsets(native.len()),
    landmarks.namespace_key,
    1,
  )?
  .offset;
  let (ns_packs, ns_prefix_len) = select_masked_text_anchor::<Scalar, _>(
    cs.namespace(|| "namespace anchor"),
    bits,
    native,
    landmarks.namespace_key,
    ns_open_len,
    "namespace",
  )?;

  // The namespace's entries begin right after its own header. The length
  // is a variable, not a constant: as a constant it is 18 for an mDL and
  // 25 for an EU PID, and that difference alone is a different R1CS.
  let region_start = ns_offset.clone() + ns_prefix_len.get_variable();

  // The namespace sub-map must sit inside the table, not before it.
  let table_body = landmarks
    .value_digests_key
    .checked_add(open_len)
    .ok_or_else(|| reject(format!("the valueDigests landmark at {} overflows", landmarks.value_digests_key)))?;
  if landmarks.namespace_key < table_body {
    return Err(reject(format!(
      "the namespace key at {} precedes the end of the valueDigests header at {table_body}",
      landmarks.namespace_key
    )));
  }
  enforce_ge(
    cs.namespace(|| "namespace sits inside the table"),
    &ns_offset,
    &(table_window.offset.clone() + (Scalar::from(open_len as u64), CS::one())),
    landmarks.namespace_key - table_body,
    16,
  )?;

  // ---- Anchor 3: `6D "deviceKeyInfo"` ------------------------------
  // Closes the whole table. Everything past it is the holder's own
  // deviceKey, which is what makes it the right place to read that key.
  //
  // It is *not* the digest region's upper bound. It was, and that was a
  // soundness break — see `walk_namespace_entries`. It stays as the
  // table's outer limit, which the walk's end must respect.
  let end_window = select_anchor::<Scalar, _>(
    cs.namespace(|| "deviceKeyInfo anchor"),
    bits,
    native,
    landmarks.device_key_info,
    DEVICE_KEY_INFO,
    3,
    "deviceKeyInfo",
  )?;

  // ---- The requested namespace's own end ---------------------------
  if landmarks.device_key_info <= landmarks.region_start {
    return Err(reject(format!(
      "landmarks describe an empty or inverted digest region: starts at {}, ends at {}",
      landmarks.region_start, landmarks.device_key_info
    )));
  }
  let (region_end, num_entries) = walk_namespace_entries::<Scalar, _>(
    cs.namespace(|| "namespace entries"),
    bits,
    native,
    &region_start,
    landmarks.region_start,
    shape.num_entries,
  )?;

  // The walk cannot run past the table. A credential whose sub-map ends
  // beyond `deviceKeyInfo` is malformed, and without this the walk's
  // arithmetic alone would not say so.
  let walked_native = native_region_end(native, landmarks.region_start, shape.num_entries)?;
  if walked_native > landmarks.device_key_info {
    return Err(reject(format!(
      "the namespace's {} entries end at {walked_native}, past deviceKeyInfo at {}",
      shape.num_entries, landmarks.device_key_info
    )));
  }
  enforce_ge(
    cs.namespace(|| "the namespace ends inside the table"),
    &end_window.offset,
    &region_end,
    landmarks.device_key_info - walked_native,
    16,
  )?;

  // ---- The holder's device key, read but NOT revealed ---------------
  // Both coordinates sit at constant deltas from the anchor, so their
  // windows are selected and then *pinned* to those deltas rather than
  // trusted: a free offset would let a prover read 32 bytes of their
  // choosing and call them the device key.
  let mut coords = Vec::with_capacity(2);
  for (label, delta) in [("device key x", DEVICE_KEY_X_DELTA), ("device key y", DEVICE_KEY_Y_DELTA)] {
    let at = landmarks
      .device_key_info
      .checked_add(delta)
      .ok_or_else(|| reject(format!("the deviceKeyInfo landmark at {} overflows", landmarks.device_key_info)))?;
    window_end(at, 32, native.len(), label)?;
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
  // Selected at the same fixed width as the namespace anchor, and for
  // the same reason: `org.iso.18013.5.1.mDL` and
  // `eu.europa.ec.eudi.pid.1` are different lengths *and* different
  // bytes, so a literal comparison here writes the document type into
  // the matrices. The window is published instead — the `docType` was
  // always a public output, so a literal comparison was only ever
  // duplicating a check the verifier has to do anyway.
  let mut expected = DOC_TYPE_KEY.to_vec();
  expected.extend_from_slice(&tstr_header(shape.doc_type.len())?);
  expected.extend_from_slice(shape.doc_type.as_bytes());
  if expected.len() > ANCHOR_TEXT_WINDOW {
    return Err(reject(format!(
      "the docType entry for `{}` is {} bytes, over this circuit's fixed \
       {ANCHOR_TEXT_WINDOW}-byte anchor window",
      shape.doc_type,
      expected.len()
    )));
  }
  window_end(landmarks.doc_type_key, ANCHOR_TEXT_WINDOW, native.len(), "the docType landmark")?;
  let doc_literal_end = window_end(landmarks.doc_type_key, expected.len(), native.len(), "the docType entry")?;
  if &native[landmarks.doc_type_key..doc_literal_end] != expected.as_slice() {
    return Err(reject(format!(
      "the docType landmark at {} does not point at `{}` in the signed bytes",
      landmarks.doc_type_key, shape.doc_type
    )));
  }
  let (doc_packs, _) = select_masked_text_anchor::<Scalar, _>(
    cs.namespace(|| "docType anchor"),
    bits,
    native,
    landmarks.doc_type_key,
    expected.len(),
    "docType",
  )?;

  Ok(RegionBinding {
    region_start,
    region_end,
    doc_type: doc_packs,
    namespace: ns_packs,
    namespace_prefix_len: ns_prefix_len,
    num_entries,
    device_key,
  })
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
