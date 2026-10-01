//! An offset-based age proof over a real mdoc credential.
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
//! # One circuit, three document types
//!
//! The statement is the same for every ISO 18013-5-shaped credential that
//! carries a `birth_date`, so the document type is witness data rather
//! than circuit structure:
//!
//! | credential | `docType` | `birth_date` namespace |
//! |---|---|---|
//! | mDL | `org.iso.18013.5.1.mDL` | `org.iso.18013.5.1` |
//! | EU PID 1.8 | `eu.europa.ec.eudi.pid.1` | `eu.europa.ec.eudi.pid.1` |
//! | Photo ID | `org.iso.23220.photoid.1` | `org.iso.23220.1` |
//!
//! Each of those rows breaks an assumption the single-document version
//! made. The mDL's namespace is not its `docType` and is a different
//! length. Photo ID carries three namespaces, and the one holding
//! `birth_date` sorts *first*, so its entries are followed by another
//! namespace rather than by `deviceKeyInfo` — see [`crate::offset_bind`].
//!
//! # Salt length is witnessed, not assumed
//!
//! An `IssuerSignedItem`'s `random` salt shifts every field after it.
//! ISO 18013-5 requires at least 16 bytes and real issuers differ: 32 is
//! common, and our own `MSOBuilder` emits 16 to stay inside Longfellow's
//! smaller item ceiling. A fixed offset is therefore an interoperability
//! bug, not a simplification — and it was a live one: a hardcoded
//! 32-byte assumption made every claim of a real device presentation fail
//! `InvalidSumcheckProof`, because the circuit was reading the issuer's
//! bytes at the wrong place.
//!
//! The salt length is now part of the witness. Together with the
//! `digestID`'s own CBOR width it determines where `elementValue` starts,
//! so the two collapse into a single selector over the offsets they can
//! jointly produce — 22 of them across salts of 16 to 32 bytes, rather
//! than the 68 combinations taken separately.
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

/// Byte budget for the signed `Sig_structure`, in SHA-256 blocks.
///
/// Sized for the largest of the three document types rather than the
/// most common one, because one circuit serving all three means one
/// setup and one published artifact:
///
/// | credential | `Sig_structure` | blocks |
/// |---|---|---|
/// | EU PID 1.8, 34 entries | 1542 B | 25 |
/// | mDL, 35 entries | 1570 B | 25 |
/// | Photo ID, 56 entries over 3 namespaces | 2343 B | 37 |
///
/// Photo ID is the outlier: three namespaces and 56 digests, where the
/// other two carry one namespace each. 40 blocks leaves headroom for a
/// few more attributes without a new setup.
///
/// This is the one parameter that is baked into the setup artifact and
/// cannot be changed without a new circuit revision, so it is sized
/// deliberately rather than tightly. The cost is real and falls on every
/// document type: the SHA-256 over the credential is ~80% of the circuit,
/// and 40 blocks costs about 310k more constraints than 28 would. Issuing
/// two size tiers would claw that back for mDL and PID at the price of a
/// second setup and a second artifact to keep in the catalog.
pub const SIG_STRUCTURE_BLOCKS: usize = 40;
/// Largest `Sig_structure` that still fits [`SIG_STRUCTURE_BLOCKS`].
pub const MAX_SIG_STRUCTURE_BYTES: usize = SIG_STRUCTURE_BLOCKS * 64 - 9;

/// Smallest and largest `random` salt this circuit accepts. ISO 18013-5
/// §9.1.2.5 requires at least 16 bytes; 32 is the largest any issuer we
/// target emits, and is also the largest that keeps a `birth_date` item
/// inside [`crate::MAX_CLAIM_BYTES_V1`].
pub const MIN_SALT_BYTES: usize = 16;
pub const MAX_SALT_BYTES: usize = 32;

/// The four canonical CBOR major-type-0 widths a spec-conformant issuer
/// may choose for a `digestID` (ISO 18013-5 §9.1.2.4 bounds it below
/// 2^31, and directs issuers to spread values across that range).
const DIGEST_ID_WIDTHS: [usize; 4] = [1, 2, 3, 5];

/// Byte offset of the `6c "elementValue"` key inside a canonically
/// encoded `IssuerSignedItem`, for a given salt length and `digestID`
/// width.
///
/// The layout is `d8 18` (2) `58 LL` (2) `a4` (1) `66 "random"` (7)
/// `<salt header><salt>` `68 "digestID"` (9) `<digestID>`, and the salt's
/// own bstr header is one byte below 24 and two above — so a 16-byte salt
/// puts `digestID` at 38 and a 32-byte salt puts it at 55.
pub fn element_value_key_offset(salt_bytes: usize, digest_id_width: usize) -> usize {
  let salt_header = if salt_bytes < 24 { 1 } else { 2 };
  2 + 2 + 1 + 7 + salt_header + salt_bytes + 9 + digest_id_width
}

/// Every offset `element_value_key_offset` can produce, deduplicated.
/// Different (salt, width) pairs collide — a 23-byte salt with a 3-byte
/// `digestID` lands where a 24-byte salt with a 1-byte one does — so the
/// selector is over 22 offsets rather than 17x4 combinations.
pub fn candidate_value_key_offsets() -> Vec<usize> {
  let mut v: Vec<usize> = (MIN_SALT_BYTES..=MAX_SALT_BYTES)
    .flat_map(|s| DIGEST_ID_WIDTHS.iter().map(move |&w| element_value_key_offset(s, w)))
    .collect();
  v.sort_unstable();
  v.dedup();
  v
}

/// `6c "elementValue"` is 13 bytes; everything else sits at a delta from
/// the end of it that depends on how the date is encoded.
const VALUE_KEY_LEN: usize = 13;

/// How an issuer encodes a `birth_date` `elementValue`.
///
/// mDL and EU PID use a bare `full-date`. ISO/IEC 23220-2 §6.3.1.1.3
/// instead allows Photo ID to wrap it in a map, so that a partially
/// unknown date can carry an `approximate_mask` alongside it:
///
/// ```text
/// birth date = { "birth_date": full-date, ? "approximate_mask": tstr }
/// ```
///
/// Both shapes are real, so the circuit constrains both and the prover
/// witnesses which one the issuer used. Treating the wrapped form as if
/// it were bare would read the map header as the date's first characters.
///
/// The `approximate_mask` variant is deliberately **not** accepted: a
/// masked date is not a date this circuit can compare, and silently
/// proving an age against one would be worse than refusing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DateEncoding {
  /// `d9 03 ec 6a <10 ASCII bytes>` — mDL, EU PID.
  Bare,
  /// `a1 6a "birth_date" d9 03 ec 6a <10 ASCII bytes>` — Photo ID.
  PhotoIdMap,
}

impl DateEncoding {
  /// The literal bytes between the `elementValue` key and the ten ASCII
  /// date characters.
  fn prefix(self) -> &'static [u8] {
    match self {
      DateEncoding::Bare => &[0xd9, 0x03, 0xec, 0x6a],
      DateEncoding::PhotoIdMap => b"\xa1\x6abirth_date\xd9\x03\xec\x6a",
    }
  }
  fn date_rel(self) -> usize {
    VALUE_KEY_LEN + self.prefix().len()
  }
  fn identifier_rel(self) -> usize {
    self.date_rel() + 10
  }
  /// Total `IssuerSignedItem` length for this encoding, given where the
  /// `elementValue` key starts.
  pub fn item_len(self, value_key_offset: usize) -> usize {
    value_key_offset + self.identifier_rel() + b"\x71elementIdentifier\x6abirth_date".len()
  }
  const ALL: [DateEncoding; 2] = [DateEncoding::Bare, DateEncoding::PhotoIdMap];
}

/// Everything the prover holds.
#[derive(Clone, Debug)]
pub struct MdocAgeWitness {
  /// The issuer's `Sig_structure` bytes, exactly as signed.
  pub sig_structure: Vec<u8>,
  /// Where the digest region and `docType` sit within them.
  pub landmarks: Landmarks,
  /// The namespace whose digests the proof is about.
  pub namespace: String,
  /// The credential's `docType`.
  ///
  /// This is a *claim about* the signed bytes, not an input the verifier
  /// takes on trust: [`crate::offset_bind::bind_digest_region`] pins the
  /// whole `67 "docType" <tstr>` window in the credential to this exact
  /// string, so naming a document type the issuer did not sign fails the
  /// anchor. What reaches the verifier is the window read out of the
  /// signed bytes, returned as [`MdocAgeOutputs::doc_type`].
  pub doc_type: String,
  /// How many namespaces the credential's `valueDigests` table holds.
  /// One for an mDL or an EU PID, three for a Photo ID.
  pub num_namespaces: usize,
  /// How many entries the requested namespace's own map holds.
  pub num_entries: usize,
  /// The `birth_date` `IssuerSignedItem`, tag(24)-wrapped, as signed.
  pub item_bytes: Vec<u8>,
  /// Offset of that item's digest within `sig_structure`.
  pub digest_offset: usize,
  /// Offset of the `6c "elementValue"` key inside `item_bytes`. Absorbs
  /// the issuer's salt length and the `digestID`'s CBOR width; see
  /// [`element_value_key_offset`] for how to compute it.
  pub element_value_key_offset: usize,
  /// How the issuer encoded the date -- bare `full-date`, or the map
  /// form ISO/IEC 23220-2 allows for Photo ID.
  pub date_encoding: DateEncoding,
}

/// What the circuit establishes.
///
/// **Every field here must be `inputize`d by the caller.** They are
/// returned rather than made public inside [`synthesize`] so that a
/// `VegaCircuit` implementation can control the public-input *order*,
/// which the folding layer requires to be stable — but a caller that
/// forgets one silently weakens the statement:
///
/// * without `issuer_qx`/`issuer_qy` the proof says "signed by *some*
///   key whose private half I know", which any prover can satisfy with a
///   key they generated themselves;
/// * without `cutoff` the verifier cannot tell which threshold was
///   actually compared against;
/// * without `doc_type` it cannot tell an mDL from a PID;
/// * without `old_enough` it learns nothing at all.
pub struct MdocAgeOutputs<Scalar: ff::PrimeField> {
  /// The credential's `docType` key and value, packed 16 bytes at a time.
  pub doc_type: Vec<AllocatedNum<Scalar>>,
  /// The issuer public key the signature was verified against. A
  /// verifier must check this is an issuer it actually trusts.
  pub issuer_qx: AllocatedNum<Scalar>,
  /// The issuer public key the signature was verified against.
  pub issuer_qy: AllocatedNum<Scalar>,
  /// The ten ASCII bytes of the threshold date the comparison used.
  pub cutoff: Vec<AllocatedNum<Scalar>>,
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
///
/// `value_key_offset` is witnessed, not derived: it absorbs both the
/// salt length and the `digestID` width (see
/// [`element_value_key_offset`]). A prover who claims the wrong one has
/// to make 56 bytes of `elementValue`/`full-date`/`elementIdentifier`
/// literal appear at that position instead, which is a preimage problem.
fn extract_birth_date<Scalar, CS>(
  mut cs: CS,
  item_bits: &[Boolean],
  item_bytes: &[u8],
  value_key_offset: usize,
  encoding: DateEncoding,
) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError>
where
  Scalar: ff::PrimeField,
  CS: ConstraintSystem<Scalar>,
{
  let one = CS::one();
  // One selector over (offset, encoding) pairs rather than two selectors
  // multiplied together, which would make every literal check degree 3.
  let candidates: Vec<(usize, DateEncoding)> = candidate_value_key_offsets()
    .into_iter()
    .flat_map(|o| DateEncoding::ALL.into_iter().map(move |e| (o, e)))
    .collect();
  let Some(real) = candidates.iter().position(|&c| c == (value_key_offset, encoding)) else {
    return Err(offset_bind::reject(format!(
      "elementValue key offset {value_key_offset} is not reachable from any salt in \
       {MIN_SALT_BYTES}..={MAX_SALT_BYTES} with a canonical digestID width"
    )));
  };
  let indices: Vec<usize> = (0..candidates.len()).collect();
  let sel = crate::onehot_cursor::alloc_one_hot::<Scalar, _>(
    cs.namespace(|| "elementValue offset and encoding"),
    &indices,
    real,
  )?;

  for (k, &(base, enc)) in candidates.iter().enumerate() {
    let mut literals: Vec<(usize, u8)> = Vec::new();
    for (i, &b) in b"\x6celementValue".iter().enumerate() {
      literals.push((i, b));
    }
    for (i, &b) in enc.prefix().iter().enumerate() {
      literals.push((VALUE_KEY_LEN + i, b));
    }
    for (i, &b) in b"\x71elementIdentifier\x6abirth_date".iter().enumerate() {
      literals.push((enc.identifier_rel() + i, b));
    }
    for (rel, expect) in literals {
      cs.enforce(
        || format!("cand {k} literal at +{rel}"),
        |lc| lc + &sel[k].lc(one, Scalar::ONE),
        |lc| lc + &offset_bind::byte_lc::<Scalar>(item_bits, one, base + rel, Scalar::ONE) - (Scalar::from(expect as u64), one),
        |lc| lc,
      );
    }
  }

  let mut out = Vec::with_capacity(10);
  for j in 0..10 {
    let value = Scalar::from(item_bytes[value_key_offset + encoding.date_rel() + j] as u64);
    let d = AllocatedNum::alloc(cs.namespace(|| format!("date byte {j}")), || Ok(value))?;
    let mut acc = LinearCombination::<Scalar>::zero();
    for (k, &(base, enc)) in candidates.iter().enumerate() {
      let term = AllocatedNum::alloc(cs.namespace(|| format!("date {j} term {k}")), || {
        Ok(if k == real { value } else { Scalar::ZERO })
      })?;
      cs.enforce(
        || format!("date {j} select {k}"),
        |lc| lc + &sel[k].lc(one, Scalar::ONE),
        |lc| lc + &offset_bind::byte_lc::<Scalar>(item_bits, one, base + enc.date_rel() + j, Scalar::ONE),
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
///
/// **Both operands are circuit variables.** An earlier revision took the
/// cutoff as `&[u8; 10]` and folded its bits in as `Boolean::constant`,
/// which was wrong in a way that would not have shown up in any test:
/// the constant bits changed *which constraints were emitted at all*, so
/// every threshold date produced a different R1CS. Under a
/// fixed-setup folding system that means a separate setup and a separate
/// published artifact per cutoff — i.e. per day. Allocating the cutoff
/// makes the shape identical for every date, at the cost of the few
/// constraints the constant-folding used to save.
fn date_not_after<Scalar, CS>(
  mut cs: CS,
  date: &[AllocatedNum<Scalar>],
  cutoff: &[AllocatedNum<Scalar>],
) -> Result<Boolean, SynthesisError>
where
  Scalar: PrimeFieldBits,
  CS: ConstraintSystem<Scalar>,
{
  let mut still_equal = Boolean::constant(true);
  let mut is_before = Boolean::constant(false);
  for i in 0..10 {
    let d_bits = date[i].to_bits_le(cs.namespace(|| format!("date bits {i}")))?;
    let c_bits = cutoff[i].to_bits_le(cs.namespace(|| format!("cutoff bits {i}")))?;
    let mut lt = Boolean::constant(false);
    let mut eq_so_far = Boolean::constant(true);
    for b in (0..8).rev() {
      let dbit = &d_bits[b];
      let cbit = &c_bits[b];
      // lt |= eq_so_far & !dbit & cbit
      let nd = dbit.not();
      let t = Boolean::and(cs.namespace(|| format!("lt {i} {b} a")), &eq_so_far, &nd)?;
      let t = Boolean::and(cs.namespace(|| format!("lt {i} {b} b")), &t, cbit)?;
      lt = Boolean::or(cs.namespace(|| format!("lt or {i} {b}")), &lt, &t)?;
      let same = Boolean::xor(cs.namespace(|| format!("x {i} {b}")), dbit, cbit)?.not();
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
/// `cutoff` is the verifier's date, not the prover's. It is allocated as
/// a circuit variable and returned in [`MdocAgeOutputs`] for the caller to
/// `inputize`; see that type's docs for why every returned field has to
/// be made public.
pub fn synthesize<Scalar, CS>(
  cs: &mut CS,
  witness: &MdocAgeWitness,
  ecdsa: &crate::ecdsa::EcdsaP256Witness<Scalar>,
  cutoff: &[u8; 10],
) -> Result<MdocAgeOutputs<Scalar>, SynthesisError>
where
  Scalar: PrimeFieldBits,
  CS: ConstraintSystem<Scalar>,
{
  if witness.sig_structure.len() > MAX_SIG_STRUCTURE_BYTES {
    return Err(offset_bind::reject(format!(
      "Sig_structure is {} bytes, over the {MAX_SIG_STRUCTURE_BYTES}-byte budget this circuit was set up for",
      witness.sig_structure.len()
    )));
  }
  if witness.item_bytes.len() > crate::MAX_CLAIM_BYTES_V1 {
    return Err(offset_bind::reject(format!(
      "the birth_date item is {} bytes, over the {}-byte claim budget",
      witness.item_bytes.len(),
      crate::MAX_CLAIM_BYTES_V1
    )));
  }
  // No *lower* bound is checked, deliberately. The item is padded to
  // `MAX_CLAIM_BYTES_V1` before anything reads it and the extraction
  // touches at most index 115, so a short item cannot index out of
  // range — it simply hashes to something other than the located digest
  // and leaves the circuit unsatisfied, which is the right answer. An
  // earlier revision did add a lower bound, computed by eye rather than
  // from the offsets, and it rejected a legitimate 112-byte item.
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
  let issuer_qx = AllocatedNum::alloc(cs.namespace(|| "qx"), || Ok(ecdsa.qx))?;
  let issuer_qy = AllocatedNum::alloc(cs.namespace(|| "qy"), || Ok(ecdsa.qy))?;
  let z_bn = crate::mdoc_core::bits_be_to_bignat::<Scalar, CS>(&z_bits)?;
  crate::ecdsa::verify_ecdsa_p256_with_digest(
    cs.namespace(|| "ecdsa"),
    &issuer_qx,
    &issuer_qy,
    &ecdsa.r,
    &ecdsa.s,
    &ecdsa.s_inv,
    &z_bn,
  )?;

  // 3. Where this credential's digests actually live.
  let binding = offset_bind::bind_digest_region::<Scalar, _>(
    cs.namespace(|| "region"),
    &sig_bits,
    &padded,
    offset_bind::CredentialShape {
      namespace: &witness.namespace,
      doc_type: &witness.doc_type,
      num_namespaces: witness.num_namespaces,
      num_entries: witness.num_entries,
    },
    witness.landmarks,
  )?;

  // 4. The claimed digest, pinned inside that region. Without both range
  //    checks this whole proof would accept a digest planted anywhere in
  //    the signed bytes — see `offset_bind`'s module docs.
  let candidates = offset_bind::window_offsets(MAX_SIG_STRUCTURE_BYTES, 32);
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
  let date = extract_birth_date(
    cs.namespace(|| "extract"),
    &item_bits,
    &item_padded,
    witness.element_value_key_offset,
    witness.date_encoding,
  )?;

  // 7. The predicate, against a cutoff the verifier chose.
  let cutoff_vars = cutoff
    .iter()
    .enumerate()
    .map(|(i, &b)| AllocatedNum::alloc(cs.namespace(|| format!("cutoff byte {i}")), || Ok(Scalar::from(b as u64))))
    .collect::<Result<Vec<_>, _>>()?;
  let old_enough = date_not_after(cs.namespace(|| "age"), &date, &cutoff_vars)?;

  Ok(MdocAgeOutputs {
    doc_type: binding.doc_type,
    issuer_qx,
    issuer_qy,
    cutoff: cutoff_vars,
    old_enough,
  })
}
