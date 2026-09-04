//! An offset-based age proof over a spec-conformant EUDI PID.
//!
//! # The statement
//!
//! > I hold a credential of document type `D`, signed by the issuer whose
//! > public key is `Q`, one of whose `valueDigests` entries is the digest
//! > of an `IssuerSignedItem` whose `elementIdentifier` is `birth_date`
//! > and whose `elementValue` is a `full-date` no later than `cutoff`.
//!
//! Nothing else is revealed: not the birthdate, not which of the
//! credential's digest slots was used, not any other attribute, not the
//! `digestID`. The verifier learns `D`, `Q`, `cutoff`, and one bit.
//!
//! # Why `cutoff` and not "age over 18"
//!
//! The threshold is a **verifier-supplied public input** — today's date
//! minus the age threshold, as a `YYYY-MM-DD` string. That keeps calendar
//! arithmetic (leap years, month lengths, time zones) entirely out of the
//! circuit: `full-date` is fixed-width and zero-padded, so ASCII
//! lexicographic order *is* chronological and the comparison is bytewise.
//!
//! It also means this circuit does not depend on an `age_over_18`
//! boolean. Those are computed by the issuer at issuance time and go
//! stale the moment the holder crosses a threshold, which makes any proof
//! built on them only as fresh as the credential. Deriving the answer
//! from `birth_date` makes it correct for any threshold, on any date,
//! from a credential issued at any time.
//!
//! # Why this shape rather than [`crate::mso`]'s
//!
//! [`crate::mso`] reconstructs the issuer's `Sig_structure` byte-exactly,
//! which needs a splice slot per `valueDigests` entry and so fixes the
//! circuit at exactly `MAX_CLAIMS_V1` attributes. A real EUDI PID has 34.
//! Here the signed bytes are witnessed as an opaque blob and hashed once,
//! so cost is set by the credential's *size*, not its attribute count —
//! and one circuit serves any PID that fits the byte budget, instead of
//! one circuit per attribute count.
//!
//! What that shape gives up is the free structural soundness
//! reconstruction provides; [`crate::offset_bind`] is what buys it back,
//! and its module docs are the ones to read for the threat model.
//!
//! **Unreviewed.** This is a novel construction that has not had
//! independent cryptographic review. See the crate README.

use bellpepper_core::{
  boolean::{AllocatedBit, Boolean},
  num::AllocatedNum,
  ConstraintSystem, LinearCombination, SynthesisError,
};
use ff::PrimeFieldBits;

use crate::offset_bind::{self, Landmarks};

/// Byte budget for the signed `Sig_structure`. 28 SHA-256 blocks; a
/// 34-attribute PID with full-width (5-byte) `digestID`s is 1668 bytes,
/// so this leaves room for a handful more attributes without a new
/// circuit and a new setup.
pub const MAX_SIG_STRUCTURE_BYTES: usize = 28 * 64 - 9;
/// SHA-256 blocks covering [`MAX_SIG_STRUCTURE_BYTES`].
pub const SIG_STRUCTURE_BLOCKS: usize = 28;

/// Offset of the `6c "elementValue"` key inside an `IssuerSignedItem`,
/// before the `digestID`'s own width is added.
///
/// The canonical key order is `random`(6) < `digestID`(8) <
/// `elementValue`(12) < `elementIdentifier`(17), so the layout is
/// `d8 18 58 LL a4 66"random" 58 20 <32 salt> 68"digestID" <uint>` — 55
/// bytes — and everything after it shifts by the `digestID`'s CBOR width.
const ITEM_VALUE_KEY_OFFSET: usize = 55;

/// The four canonical CBOR major-type-0 widths a spec-conformant issuer
/// may choose for a `digestID` (ISO 18013-5 §9.1.2.4 bounds it below
/// 2^31, and directs issuers to spread values across that range).
const DIGEST_ID_WIDTHS: [usize; 4] = [1, 2, 3, 5];

/// Everything the prover holds.
#[derive(Clone, Debug)]
pub struct PidAgeWitness {
  /// The issuer's `Sig_structure` bytes, exactly as signed.
  pub sig_structure: Vec<u8>,
  /// Where the digest region and `docType` sit within them.
  pub landmarks: Landmarks,
  /// The namespace whose digests the proof is about.
  pub namespace: String,
  /// The credential's `docType`, revealed to the verifier.
  pub doc_type: String,
  /// How many entries the namespace's `valueDigests` map holds.
  pub num_entries: usize,
  /// The `birth_date` `IssuerSignedItem`, tag(24)-wrapped, as signed.
  pub item_bytes: Vec<u8>,
  /// Offset of that item's digest within `sig_structure`.
  pub digest_offset: usize,
}

/// What the circuit establishes, for a caller to `inputize` as it sees
/// fit.
pub struct PidAgeOutputs<Scalar: ff::PrimeField> {
  /// The credential's `docType` key and value, packed 16 bytes at a time.
  pub doc_type: Vec<AllocatedNum<Scalar>>,
  /// True iff the holder's birthdate is at or before `cutoff`.
  pub old_enough: Boolean,
}

fn alloc_bits<CS: ConstraintSystem<Scalar>, Scalar: ff::PrimeField>(
  cs: &mut CS,
  bytes: &[u8],
  tag: &str,
) -> Result<Vec<Boolean>, SynthesisError> {
  bytes
    .iter()
    .flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1 == 1))
    .enumerate()
    .map(|(i, b)| AllocatedBit::alloc(cs.namespace(|| format!("{tag} {i}")), Some(b)).map(Boolean::from))
    .collect()
}

/// Reads the ten ASCII date bytes out of a `birth_date` item, proving as
/// it goes that the item really *is* a `birth_date` item carrying a
/// `full-date`.
///
/// Without this the proof would say only "some attribute's digest is in
/// the credential and I know its preimage", which is true of every
/// attribute and says nothing about anyone's age.
fn extract_birth_date<Scalar, CS>(
  mut cs: CS,
  item_bits: &[Boolean],
  item_bytes: &[u8],
  real_width: usize,
) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError>
where
  Scalar: ff::PrimeField,
  CS: ConstraintSystem<Scalar>,
{
  let one = CS::one();
  let widths = DIGEST_ID_WIDTHS.to_vec();
  let sel = crate::onehot_cursor::alloc_one_hot::<Scalar, _>(cs.namespace(|| "digestID width"), &widths, real_width)?;

  // `elementValue` key, then the value's own `#6.1004(tstr(10))` header,
  // then the `elementIdentifier` key and the literal `"birth_date"`.
  let mut literals: Vec<(usize, u8)> = Vec::new();
  for (i, &b) in b"\x6celementValue".iter().enumerate() {
    literals.push((ITEM_VALUE_KEY_OFFSET + i, b));
  }
  for (i, &b) in [0xd9u8, 0x03, 0xec, 0x6a].iter().enumerate() {
    literals.push((ITEM_VALUE_KEY_OFFSET + 13 + i, b));
  }
  for (i, &b) in b"\x71elementIdentifier\x6abirth_date".iter().enumerate() {
    literals.push((ITEM_VALUE_KEY_OFFSET + 27 + i, b));
  }

  for (w_idx, &w) in widths.iter().enumerate() {
    for &(rel, expect) in &literals {
      cs.enforce(
        || format!("width {w} literal at {rel}"),
        |lc| lc + &sel[w_idx].lc(one, Scalar::ONE),
        |lc| lc + &offset_bind::byte_lc::<Scalar>(item_bits, one, rel + w, Scalar::ONE) - (Scalar::from(expect as u64), one),
        |lc| lc,
      );
    }
  }

  let mut out = Vec::with_capacity(10);
  for j in 0..10 {
    let value = Scalar::from(item_bytes[ITEM_VALUE_KEY_OFFSET + 17 + real_width + j] as u64);
    let d = AllocatedNum::alloc(cs.namespace(|| format!("date byte {j}")), || Ok(value))?;
    let mut acc = LinearCombination::<Scalar>::zero();
    for (w_idx, &w) in widths.iter().enumerate() {
      let term = AllocatedNum::alloc(cs.namespace(|| format!("date {j} term {w}")), || {
        Ok(if w == real_width { value } else { Scalar::ZERO })
      })?;
      cs.enforce(
        || format!("date {j} select {w}"),
        |lc| lc + &sel[w_idx].lc(one, Scalar::ONE),
        |lc| lc + &offset_bind::byte_lc::<Scalar>(item_bits, one, ITEM_VALUE_KEY_OFFSET + 17 + w + j, Scalar::ONE),
        |lc| lc + term.get_variable(),
      );
      acc = acc + term.get_variable();
    }
    cs.enforce(|| format!("date {j} is the selected byte"), |lc| lc + &acc, |lc| lc + one, |lc| lc + d.get_variable());
    out.push(d);
  }
  Ok(out)
}

/// `date <= cutoff`, bytewise over ten ASCII characters, MSB-first with a
/// running "all earlier bytes equal" flag.
fn date_not_after<Scalar, CS>(mut cs: CS, date: &[AllocatedNum<Scalar>], cutoff: &[u8; 10]) -> Result<Boolean, SynthesisError>
where
  Scalar: PrimeFieldBits,
  CS: ConstraintSystem<Scalar>,
{
  let mut still_equal = Boolean::constant(true);
  let mut is_before = Boolean::constant(false);
  for i in 0..10 {
    let d_bits = date[i].to_bits_le(cs.namespace(|| format!("date bits {i}")))?;
    let mut lt = Boolean::constant(false);
    let mut eq_so_far = Boolean::constant(true);
    for b in (0..8).rev() {
      let cbit = (cutoff[i] >> b) & 1 == 1;
      let dbit = &d_bits[b];
      if cbit {
        let nd = dbit.not();
        let t = Boolean::and(cs.namespace(|| format!("lt {i} {b}")), &eq_so_far, &nd)?;
        lt = Boolean::or(cs.namespace(|| format!("lt or {i} {b}")), &lt, &t)?;
      }
      let same = Boolean::xor(cs.namespace(|| format!("x {i} {b}")), dbit, &Boolean::constant(cbit))?.not();
      eq_so_far = Boolean::and(cs.namespace(|| format!("eq {i} {b}")), &eq_so_far, &same)?;
    }
    let contributes = Boolean::and(cs.namespace(|| format!("c {i}")), &still_equal, &lt)?;
    is_before = Boolean::or(cs.namespace(|| format!("acc {i}")), &is_before, &contributes)?;
    still_equal = Boolean::and(cs.namespace(|| format!("se {i}")), &still_equal, &eq_so_far)?;
  }
  Boolean::or(cs.namespace(|| "le"), &is_before, &still_equal)
}

/// Synthesises the whole statement.
///
/// `cutoff` is the verifier's date, not the prover's, and belongs in the
/// public input.
pub fn synthesize<Scalar, CS>(
  cs: &mut CS,
  witness: &PidAgeWitness,
  ecdsa: &crate::ecdsa::EcdsaP256Witness<Scalar>,
  cutoff: &[u8; 10],
) -> Result<PidAgeOutputs<Scalar>, SynthesisError>
where
  Scalar: PrimeFieldBits,
  CS: ConstraintSystem<Scalar>,
{
  assert!(
    witness.sig_structure.len() <= MAX_SIG_STRUCTURE_BYTES,
    "Sig_structure is {} bytes, over the {MAX_SIG_STRUCTURE_BYTES}-byte budget",
    witness.sig_structure.len()
  );
  let one = CS::one();

  // 1. The signed bytes, witnessed opaquely and hashed once.
  let mut padded = witness.sig_structure.clone();
  padded.resize(MAX_SIG_STRUCTURE_BYTES, 0);
  let sig_bits = alloc_bits(cs, &padded, "sig")?;
  let (z_bits, _) = crate::sha256_var::sha256_var_sized(
    cs.namespace(|| "mso hash"),
    &sig_bits,
    witness.sig_structure.len(),
    MAX_SIG_STRUCTURE_BYTES,
    SIG_STRUCTURE_BLOCKS,
  )?;

  // 2. The issuer's signature over *that* hash — derived in-circuit, so
  //    the signature and the bytes every later step reads cannot diverge.
  let qx = AllocatedNum::alloc(cs.namespace(|| "qx"), || Ok(ecdsa.qx))?;
  let qy = AllocatedNum::alloc(cs.namespace(|| "qy"), || Ok(ecdsa.qy))?;
  let z_bn = crate::mdoc_core::bits_be_to_bignat::<Scalar, CS>(&z_bits)?;
  crate::ecdsa::verify_ecdsa_p256_with_digest(cs.namespace(|| "ecdsa"), &qx, &qy, &ecdsa.r, &ecdsa.s, &ecdsa.s_inv, &z_bn)?;

  // 3. Where this credential's digests actually live.
  let binding = offset_bind::bind_digest_region::<Scalar, _>(
    cs.namespace(|| "region"),
    &sig_bits,
    &padded,
    &witness.namespace,
    witness.doc_type.len(),
    witness.num_entries,
    witness.landmarks,
  )?;

  // 4. The claimed digest, pinned inside that region. Without both range
  //    checks this whole proof would accept a digest planted anywhere in
  //    the signed bytes — see `offset_bind`'s module docs.
  let candidates: Vec<usize> = (0..MAX_SIG_STRUCTURE_BYTES - 32).collect();
  let located = offset_bind::select_window::<Scalar, _>(
    cs.namespace(|| "locate digest"),
    &sig_bits,
    &padded,
    &candidates,
    witness.digest_offset,
    32,
  )?;
  offset_bind::enforce_ge(
    cs.namespace(|| "digest starts inside the region"),
    &located.offset,
    &binding.region_start,
    witness.digest_offset.wrapping_sub(witness.landmarks.region_start) & 0xffff,
    16,
  )?;
  offset_bind::enforce_ge(
    cs.namespace(|| "digest ends inside the region"),
    &binding.region_end,
    &(located.offset.clone() + (Scalar::from(32u64), one)),
    witness.landmarks.device_key_info.wrapping_sub(witness.digest_offset + 32) & 0xffff,
    16,
  )?;

  // 5. The item behind that digest.
  let mut item_padded = witness.item_bytes.clone();
  item_padded.resize(crate::MAX_CLAIM_BYTES_V1, 0);
  let item_bits = alloc_bits(cs, &item_padded, "item")?;
  let (item_digest_bits, _) =
    crate::sha256_var::sha256_var(cs.namespace(|| "item hash"), &item_bits, witness.item_bytes.len())?;
  for (p, pack) in located.packs.iter().enumerate() {
    let mut lc = LinearCombination::<Scalar>::zero();
    for i in 0..offset_bind::BYTES_PER_PACK {
      let mut coeff = Scalar::ONE;
      for _ in 0..(offset_bind::BYTES_PER_PACK - 1 - i) {
        coeff *= Scalar::from(256u64);
      }
      lc = lc + &offset_bind::byte_lc::<Scalar>(&item_digest_bits, one, p * offset_bind::BYTES_PER_PACK + i, coeff);
    }
    cs.enforce(|| format!("item digest pack {p}"), |l| l + &lc, |l| l + one, |l| l + pack.get_variable());
  }

  // 6. That item is a `birth_date` carrying a `full-date`.
  let width = crate::cbor_uint::class_byte_width(crate::cbor_uint::length_class(
    // The item's own digestID, read natively only to pick which of the
    // four width cases is the live one; the circuit constrains all four.
    read_item_digest_id(&item_padded),
  ));
  let date = extract_birth_date(cs.namespace(|| "extract"), &item_bits, &item_padded, width)?;

  // 7. The predicate.
  let old_enough = date_not_after(cs.namespace(|| "age"), &date, cutoff)?;

  Ok(PidAgeOutputs { doc_type: binding.doc_type, old_enough })
}

/// The `digestID` embedded in an `IssuerSignedItem`, read natively. It
/// begins at [`ITEM_VALUE_KEY_OFFSET`]; the `elementValue` key follows it
/// once its own width is known.
fn read_item_digest_id(item: &[u8]) -> u32 {
  let at = ITEM_VALUE_KEY_OFFSET;
  match item[at] {
    b if b < 24 => b as u32,
    0x18 => item[at + 1] as u32,
    0x19 => u16::from_be_bytes([item[at + 1], item[at + 2]]) as u32,
    0x1a => u32::from_be_bytes([item[at + 1], item[at + 2], item[at + 3], item[at + 4]]),
    head => panic!("digestID head {head:#04x} is not a canonical CBOR uint — the item is not canonically encoded"),
  }
}
