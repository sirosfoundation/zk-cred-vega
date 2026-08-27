//! Feasibility prototype for an offset-based age-proof circuit.
//!
//! The question this answers: our current architecture *reconstructs* the
//! MSO byte-exactly, so it needs a digest slot for every attribute in
//! `valueDigests` -- 33 of them for a spec-conformant EUDI PID, even
//! though an age proof cares about exactly one. Longfellow instead takes
//! the credential as a witness, hashes it once, and proves each field sits
//! at a *witnessed offset* inside it. This measures whether that second
//! shape is actually cheap enough, using a synthetic but spec-shaped PID.
//!
//! Analysis tool, not library code. The gadgets here are prototypes for
//! costing, not reviewed constructions.

use bellpepper_core::{
  boolean::Boolean,
  num::AllocatedNum,
  test_cs::TestConstraintSystem,
  ConstraintSystem, LinearCombination, SynthesisError,
};
use ff::Field;
use zk_cred_vega::Engine_;

type Scalar = <Engine_ as vega_prover::traits::Engine>::Scalar;

// ---- Synthetic, spec-shaped EUDI PID -------------------------------

/// The 33 claims the PID type metadata declares (vctm_pid.json).
const PID_CLAIMS: [&str; 33] = [
  "family_name", "given_name", "birth_date", "birth_place", "nationality",
  "personal_administrative_number", "picture", "birth_family_name",
  "birth_given_name", "sex", "email_address", "mobile_phone_number",
  "resident_address", "resident_street_address", "resident_house_number",
  "resident_postal_code", "resident_city", "resident_state", "resident_country",
  "age_over_14", "age_over_16", "age_over_18", "age_over_21", "age_over_65",
  "age_in_years", "age_birth_year", "issuing_authority", "issuing_country",
  "expiry_date", "issuance_date", "document_number", "issuing_jurisdiction",
  "trust_anchor",
];

fn cbor_len(major: u8, len: usize) -> Vec<u8> {
  let m = major << 5;
  if len < 24 { vec![m | len as u8] }
  else if len < 256 { vec![m | 24, len as u8] }
  else { let mut v = vec![m | 25]; v.extend((len as u16).to_be_bytes()); v }
}
fn tstr(s: &str) -> Vec<u8> { let mut v = cbor_len(3, s.len()); v.extend_from_slice(s.as_bytes()); v }
fn bstr(b: &[u8]) -> Vec<u8> { let mut v = cbor_len(2, b.len()); v.extend_from_slice(b); v }

/// `valueDigests` for a PID: one `digestID -> bstr(32)` entry per claim.
/// Enough to size the MSO realistically; the exact key order doesn't
/// change the byte count, which is what we're measuring.
fn pid_value_digests(n: usize) -> Vec<u8> {
  let mut out = cbor_len(5, n); // map(n)
  for i in 0..n {
    out.extend(zk_cred_vega::cbor_uint::encode_cbor_uint((i as u32) * 977 + 13));
    out.extend(bstr(&[0xAB; 32]));
  }
  out
}

/// A whole PID MSO, sized as a real one would be.
fn synthetic_pid_mso(n_claims: usize) -> Vec<u8> {
  let mut mso = cbor_len(5, 6); // map(6)
  mso.extend(tstr("docType"));
  mso.extend(tstr("eu.europa.ec.eudi.pid.1"));
  mso.extend(tstr("version"));
  mso.extend(tstr("1.0"));
  mso.extend(tstr("validityInfo"));
  {
    let mut vi = cbor_len(5, 3);
    for k in ["signed", "validFrom", "validUntil"] {
      vi.extend(tstr(k));
      vi.extend(vec![0xc0]); // tag(0)
      vi.extend(tstr("2026-08-27T00:00:00Z"));
    }
    mso.extend(vi);
  }
  mso.extend(tstr("valueDigests"));
  {
    let mut vd = cbor_len(5, 1);
    vd.extend(tstr("eu.europa.ec.eudi.pid.1"));
    vd.extend(pid_value_digests(n_claims));
    mso.extend(vd);
  }
  mso.extend(tstr("deviceKeyInfo"));
  {
    let mut dk = cbor_len(5, 1);
    dk.extend(tstr("deviceKey"));
    let mut k = cbor_len(5, 4);
    k.extend(vec![0x01, 0x02, 0x20, 0x01, 0x21]);
    k.extend(bstr(&[0x11; 32]));
    k.extend(vec![0x22]);
    k.extend(bstr(&[0x22; 32]));
    dk.extend(k);
    mso.extend(dk);
  }
  mso.extend(tstr("digestAlgorithm"));
  mso.extend(tstr("SHA-256"));

  // Sig_structure = ["Signature1", protected, h'', payload]
  let mut sig = vec![0x84];
  sig.extend(tstr("Signature1"));
  sig.extend(bstr(&[0xa1, 0x01, 0x26]));
  sig.extend(bstr(&[]));
  let mut payload = vec![0xd8, 0x18];
  payload.extend(bstr(&mso));
  sig.extend(bstr(&payload));
  sig
}

// ---- Prototype gadget: prove a 32-byte digest sits at a witnessed offset

/// Packs `bytes[start..start+32]` into two field elements (16 bytes each,
/// so neither can overflow the scalar field). Pure linear combination over
/// already-allocated byte variables -- costs no constraints.
fn pack_window(bytes: &[AllocatedNum<Scalar>], start: usize) -> [LinearCombination<Scalar>; 2] {
  let mut halves = [LinearCombination::zero(), LinearCombination::zero()];
  for (h, half) in halves.iter_mut().enumerate() {
    let mut coeff = Scalar::ONE;
    let two56 = Scalar::from(256u64);
    for i in (0..16).rev() {
      let idx = start + h * 16 + i;
      if idx < bytes.len() {
        *half = half.clone() + (coeff, bytes[idx].get_variable());
      }
      coeff *= two56;
    }
  }
  halves
}

/// Prove: the 32-byte digest `target` appears in `bytes` starting at the
/// witnessed offset `real_offset`, where the offset ranges over
/// `0..n_offsets`.
///
/// The cheap part is packing: each candidate 32-byte window collapses into
/// two field elements for free (linear combinations of already-allocated
/// byte variables), so the one-hot selection costs 2 multiplications per
/// candidate rather than 32.
fn prove_digest_at_offset<CS: ConstraintSystem<Scalar>>(
  mut cs: CS,
  bytes: &[AllocatedNum<Scalar>],
  n_offsets: usize,
  real_offset: usize,
  target: &[u8; 32],
) -> Result<(), SynthesisError> {
  let offsets: Vec<usize> = (0..n_offsets).collect();
  let onehot = zk_cred_vega::onehot_cursor::alloc_one_hot::<Scalar, _>(
    cs.namespace(|| "offset"), &offsets, real_offset)?;

  let tgt: [Scalar; 2] = {
    let mut t = [Scalar::ZERO; 2];
    for (h, half) in t.iter_mut().enumerate() {
      let mut acc = Scalar::ZERO;
      for i in 0..16 {
        acc = acc * Scalar::from(256u64) + Scalar::from(target[h * 16 + i] as u64);
      }
      *half = acc;
    }
    t
  };

  // For each half: sum_k onehot[k] * window_k == target_half.
  // One multiplication per candidate offset per half.
  for (h, &tgt_half) in tgt.iter().enumerate() {
    let mut acc = LinearCombination::<Scalar>::zero();
    for (k, &off) in offsets.iter().enumerate() {
      let w = pack_window(bytes, off)[h].clone();
      let prod = AllocatedNum::alloc(cs.namespace(|| format!("prod {h} {k}")), || {
        Ok(if off == real_offset { tgt_half } else { Scalar::ZERO })
      })?;
      cs.enforce(
        || format!("select {h} {k}"),
        |lc| lc + &onehot[k].lc(CS::one(), Scalar::ONE),
        |lc| lc + &w,
        |lc| lc + prod.get_variable(),
      );
      acc = acc + prod.get_variable();
    }
    cs.enforce(|| format!("half {h} matches target"), |lc| lc + &acc, |lc| lc + CS::one(),
      |lc| lc + (tgt_half, CS::one()));
  }
  Ok(())
}

// ---- Prototype gadget: birth_date <= cutoff (10 ASCII bytes) --------

/// `YYYY-MM-DD` is fixed-width and zero-padded, so ASCII lexicographic
/// order is chronological -- the comparison is a plain bytewise one, with
/// no date arithmetic in-circuit. The verifier supplies `cutoff` (today
/// minus the age threshold) as a public input, which keeps leap-year
/// handling in ordinary code.
fn prove_date_not_after<CS: ConstraintSystem<Scalar>>(
  mut cs: CS,
  date: &[AllocatedNum<Scalar>],
  cutoff: &[u8; 10],
) -> Result<Boolean, SynthesisError> {
  // Walk the bytes MSB-first, tracking "all earlier bytes equal".
  let mut still_equal = Boolean::constant(true);
  let mut is_before = Boolean::constant(false);
  for i in 0..10 {
    let d_bits = date[i].to_bits_le(cs.namespace(|| format!("date bits {i}")))?;
    // byte < cutoff[i] : compare the 8 bits MSB-first.
    let mut lt = Boolean::constant(false);
    let mut eq_so_far = Boolean::constant(true);
    for b in (0..8).rev() {
      let cbit = (cutoff[i] >> b) & 1 == 1;
      let dbit = &d_bits[b];
      // lt |= eq_so_far & !dbit & cbit
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
  // birth_date <= cutoff  ==  before OR equal
  Boolean::or(cs.namespace(|| "le"), &is_before, &still_equal)
}

fn alloc_bytes<CS: ConstraintSystem<Scalar>>(cs: &mut CS, b: &[u8], tag: &str) -> Vec<AllocatedNum<Scalar>> {
  b.iter().enumerate().map(|(i, &x)| {
    AllocatedNum::alloc(cs.namespace(|| format!("{tag} {i}")), || Ok(Scalar::from(x as u64))).unwrap()
  }).collect()
}

fn main() {
  const COMP: usize = 25_840; // measured cost of one SHA-256 compression

  let sig = synthetic_pid_mso(PID_CLAIMS.len());
  let blocks = zk_cred_vega::sha256_var::terminal_block_for_len(sig.len());
  println!("\nSynthetic spec-shaped EUDI PID ({} claims)", PID_CLAIMS.len());
  println!("  Sig_structure   : {} bytes -> {} SHA-256 blocks", sig.len(), blocks);

  // --- offset-based costs ---
  let mut cs = TestConstraintSystem::<Scalar>::new();
  let bytes = alloc_bytes(&mut cs, &sig, "mso");
  let n_offsets = sig.len().saturating_sub(32);
  let base = cs.num_constraints();
  let target = [0xABu8; 32];
  prove_digest_at_offset(cs.namespace(|| "loc"), &bytes, n_offsets, 100, &target).unwrap();
  let locate = cs.num_constraints() - base;

  let mut cs2 = TestConstraintSystem::<Scalar>::new();
  let date = alloc_bytes(&mut cs2, b"1990-05-15", "d");
  let base2 = cs2.num_constraints();
  let ok = prove_date_not_after(cs2.namespace(|| "age"), &date, b"2008-08-27").unwrap();
  let predicate = cs2.num_constraints() - base2;
  assert!(cs2.is_satisfied(), "age gadget must be satisfiable");
  assert!(ok.get_value().unwrap(), "1990-05-15 is before the 18y cutoff");

  let mso_hash = blocks * COMP;
  let claim_hash = 3 * COMP;   // one IssuerSignedItem
  let blinding = COMP;         // one blinding, 23-byte nonce
  let ecdsa = 10_000;
  let offset_total = mso_hash + claim_hash + blinding + ecdsa + locate + predicate;

  println!("\n  OFFSET-BASED age proof over the full PID");
  println!("    MSO SHA-256 ({blocks} blocks)      {mso_hash:>9}");
  println!("    one claim SHA-256 (3 blocks)  {claim_hash:>9}");
  println!("    one blinding                  {blinding:>9}");
  println!("    ECDSA-P256                    {ecdsa:>9}");
  println!("    locate digest at offset       {locate:>9}");
  println!("    birth_date <= cutoff          {predicate:>9}");
  println!("    {:<29} {:>9}", "TOTAL", offset_total);

  // --- reconstruct-based cost for the same credential ---
  let n = PID_CLAIMS.len();
  let steps = n * 112_605;
  let core_blind = n * COMP;
  let recon_total = steps + mso_hash + core_blind + 400_000 + ecdsa;
  println!("\n  RECONSTRUCT-BASED (current architecture), same PID");
  println!("    {n} step circuits             {steps:>9}");
  println!("    MSO SHA-256 ({blocks} blocks)      {mso_hash:>9}");
  println!("    {n} core blindings            {core_blind:>9}");
  println!("    mso_splice (est.)             {:>9}", 400_000);
  println!("    ECDSA-P256                    {ecdsa:>9}");
  println!("    {:<29} {:>9}", "TOTAL", recon_total);

  println!("\n  ratio: {:.1}x  (today's 4-claim mDL circuit is 842,591)",
    recon_total as f64 / offset_total as f64);
  println!();
}
