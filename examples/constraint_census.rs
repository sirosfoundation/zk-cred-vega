//! Counts R1CS constraints per component, so optimisation effort can be
//! aimed at what actually dominates rather than at what looks expensive.
//!
//! Analysis tool, not part of the library or its test suite. Uses
//! `TestConstraintSystem`, which builds the same constraints the real
//! prover does but without proving, so it's fast enough to iterate on.

use bellpepper_core::{
  boolean::{AllocatedBit, Boolean},
  test_cs::TestConstraintSystem,
  ConstraintSystem,
};
use zk_cred_vega::{mso_splice::ENTRY_TAIL_LEN, Engine_};

type Scalar = <Engine_ as vega_prover::traits::Engine>::Scalar;

fn alloc_bits<CS: ConstraintSystem<Scalar>>(cs: &mut CS, bytes: &[u8], tag: &str) -> Vec<Boolean> {
  bytes
    .iter()
    .flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1u8 == 1u8))
    .enumerate()
    .map(|(i, b)| {
      AllocatedBit::alloc(cs.namespace(|| format!("{tag} {i}")), Some(b))
        .map(Boolean::from)
        .unwrap()
    })
    .collect()
}

fn row(label: &str, n: usize, total: usize) {
  let pct = if total > 0 { (n as f64) * 100.0 / (total as f64) } else { 0.0 };
  println!("  {label:<46} {n:>9}  {pct:>5.1}%");
}

fn main() {
  // ---- Baseline: one bare SHA-256 compression ----------------------
  {
    use bellpepper::gadgets::sha256::sha256_compression_function;
    use bellpepper::gadgets::uint32::UInt32;
    let mut cs = TestConstraintSystem::<Scalar>::new();
    let block = alloc_bits(&mut cs, &[0x5Au8; 64], "blk");
    let state: Vec<UInt32> = (0..8).map(|i| UInt32::constant(i as u32)).collect();
    let base = cs.num_constraints();
    let _ = sha256_compression_function(cs.namespace(|| "c"), &block, &state).unwrap();
    println!("\n  one SHA-256 compression = {} constraints", cs.num_constraints() - base);
  }
  {
    // Exactly how both circuits blind: sha256(digest||nonce), 64 bytes in.
    use bellpepper::gadgets::sha256::sha256;
    let mut cs = TestConstraintSystem::<Scalar>::new();
    let inp = alloc_bits(&mut cs, &[0x11u8; 64], "bl");
    let base = cs.num_constraints();
    let _ = sha256(cs.namespace(|| "b"), &inp).unwrap();
    println!("  blinding sha256(32B digest||32B nonce) = {} constraints", cs.num_constraints() - base);
    // What it would cost if the nonce were 23 bytes (55B total = 1 block).
    let mut cs = TestConstraintSystem::<Scalar>::new();
    let inp = alloc_bits(&mut cs, &[0x11u8; 55], "bs");
    let base = cs.num_constraints();
    let _ = sha256(cs.namespace(|| "b"), &inp).unwrap();
    println!("  blinding sha256(32B digest||23B nonce) = {} constraints", cs.num_constraints() - base);
  }

  // ---- Sub-gadget: per-claim variable-length SHA-256 -----------------
  let claim_len = 95usize; // representative real IssuerSignedItem size
  let msg: Vec<u8> = (0..zk_cred_vega::MAX_CLAIM_BYTES_V1).map(|i| (i * 7 + 3) as u8).collect();

  let mut cs = TestConstraintSystem::<Scalar>::new();
  let raw = alloc_bits(&mut cs, &msg, "m");
  let base_alloc = cs.num_constraints();
  let _ = zk_cred_vega::sha256_var::sha256_var(cs.namespace(|| "h"), &raw, claim_len).unwrap();
  let sha_claim = cs.num_constraints() - base_alloc;

  // ---- Sub-gadget: digestID extraction ------------------------------
  let mut cs = TestConstraintSystem::<Scalar>::new();
  let item: Vec<u8> = (0..zk_cred_vega::MAX_CLAIM_BYTES_V1).map(|i| (i * 3 + 1) as u8).collect();
  let bits = alloc_bits(&mut cs, &item, "i");
  let base = cs.num_constraints();
  let _ = zk_cred_vega::digest_id_extract::extract_digest_id(
    cs.namespace(|| "d"),
    &bits,
    zk_cred_vega::digest_id_extract::DIGEST_ID_OFFSET_BYTES,
    26,
  );
  let digest_id_extract = cs.num_constraints() - base;

  // ---- Sub-gadget: MSO splice assembly ------------------------------
  let mut cs = TestConstraintSystem::<Scalar>::new();
  let prefix = alloc_bits(&mut cs, &[0xAA; 90], "p");
  let suffix = alloc_bits(&mut cs, &[0xBB; 200], "s");
  let entries: [zk_cred_vega::mso_splice::DigestIdEntry; 4] = std::array::from_fn(|i| {
    let tail = vec![0x11u8; ENTRY_TAIL_LEN];
    zk_cred_vega::mso_splice::DigestIdEntry {
      digest_id: [5u32, 26, 300, 70000][i],
      tail_bits: alloc_bits(&mut cs, &tail, &format!("t{i}")),
    }
  });
  let base = cs.num_constraints();
  let _ = zk_cred_vega::mso_splice::assemble_mso_sig_structure::<Scalar, _>(
    cs.namespace(|| "a"),
    &prefix,
    &entries,
    &suffix,
  )
  .unwrap();
  let splice = cs.num_constraints() - base;

  // ---- Sub-gadget: whole-MSO variable-length SHA-256 ----------------
  let mso_max = zk_cred_vega::mso::MAX_SIG_STRUCTURE_BYTES;
  let blocks = zk_cred_vega::mso::SIG_STRUCTURE_NUM_BLOCKS;
  let mut cs = TestConstraintSystem::<Scalar>::new();
  let buf: Vec<u8> = (0..mso_max).map(|i| (i % 251) as u8).collect();
  let raw = alloc_bits(&mut cs, &buf, "b");
  let base = cs.num_constraints();
  let _ = zk_cred_vega::sha256_var::sha256_var_sized(
    cs.namespace(|| "H"),
    &raw,
    mso_max - 20,
    mso_max,
    blocks,
  )
  .unwrap();
  let sha_mso = cs.num_constraints() - base;

  println!("\nzk-cred-vega constraint census");
  println!("  MAX_CLAIMS={} MAX_CLAIM_BYTES={} MSO_MAX={} MSO_BLOCKS={}",
    zk_cred_vega::MAX_CLAIMS_V1, zk_cred_vega::MAX_CLAIM_BYTES_V1, mso_max, blocks);

  let step_total = sha_claim + digest_id_extract;
  let core_est = splice + sha_mso;
  let grand = step_total * zk_cred_vega::MAX_CLAIMS_V1 + core_est;

  println!("\n  --- per-claim step gadgets (x{}) ---", zk_cred_vega::MAX_CLAIMS_V1);
  row("sha256_var (claim digest)", sha_claim, grand);
  row("digest_id_extract", digest_id_extract, grand);
  row("=> one step circuit", step_total, grand);
  row("=> all steps", step_total * zk_cred_vega::MAX_CLAIMS_V1, grand);

  println!("\n  --- core circuit gadgets ---");
  row("mso_splice::assemble", splice, grand);
  row("sha256_var_sized (whole MSO)", sha_mso, grand);
  println!("  (ECDSA measured separately below)");

  // ---- Whole circuits, so ECDSA and glue are included -------------
  use num_bigint::{BigInt, Sign};
  use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey, VerifyingKey};
  use sha2::{Digest, Sha256};
  use vega_prover::traits::circuit::VegaCircuit;

  let body = zk_cred_vega::mso::MsoBodyWitness {
    device_x: [0x11; 32],
    device_y: [0x22; 32],
    signed_ts: *b"2026-08-20T00:00:00Z",
    valid_from_ts: *b"2026-08-20T00:00:00Z",
    valid_until_ts: *b"2036-08-20T00:00:00Z",
  };
  let digest_ids = [5u32, 26, 300, 70000];
  let claim_digests: Vec<[u8; 32]> = (0..4).map(|i| [(i as u8) + 0xE0; 32]).collect();
  let nonce = [0x5Au8; zk_cred_vega::BLIND_NONCE_BYTES];

  let sig_struct = zk_cred_vega::mso::native_sig_structure_bytes(&digest_ids, &claim_digests, &body);
  let z: [u8; 32] = Sha256::digest(&sig_struct).into();
  let sk = SigningKey::from_bytes(&[42u8; 32].into()).unwrap();
  let vk = VerifyingKey::from(&sk);
  let sig: Signature = sk.sign_prehash(&z).unwrap();
  let r = BigInt::from_bytes_be(Sign::Plus, &sig.r().to_bytes());
  let sv = BigInt::from_bytes_be(Sign::Plus, &sig.s().to_bytes());
  let n = zk_cred_vega::p256_ecc::p256_order();
  let s_inv = sv.modpow(&(n.clone() - BigInt::from(2)), &n);
  let enc = vk.to_encoded_point(false);
  let qx = zk_cred_vega::nonnative::util::nat_to_f::<Scalar>(&BigInt::from_bytes_be(Sign::Plus, enc.x().unwrap())).unwrap();
  let qy = zk_cred_vega::nonnative::util::nat_to_f::<Scalar>(&BigInt::from_bytes_be(Sign::Plus, enc.y().unwrap())).unwrap();

  let core = zk_cred_vega::mdoc_core::MdocCoreCircuit::<Engine_>::new(
    qx, qy, r, sv, s_inv, digest_ids, claim_digests, body, nonce);
  let mut cs = TestConstraintSystem::<Scalar>::new();
  let shared = core.shared(&mut cs).unwrap();
  let _ = core.precommitted(&mut cs, &shared).unwrap();
  let core_total = cs.num_constraints();

  let step = zk_cred_vega::ClaimDigestStepCircuit::<Engine_>::new(
    msg.clone(), claim_len, true, 26, nonce);
  let mut cs2 = TestConstraintSystem::<Scalar>::new();
  let sh2 = step.shared(&mut cs2).unwrap();
  let _ = step.precommitted(&mut cs2, &sh2).unwrap();
  let step_total_real = cs2.num_constraints();

  let real_grand = step_total_real * zk_cred_vega::MAX_CLAIMS_V1 + core_total;
  println!("\n  === WHOLE CIRCUITS (measured) ===");
  row("one step circuit", step_total_real, real_grand);
  row("all steps", step_total_real * zk_cred_vega::MAX_CLAIMS_V1, real_grand);
  row("core circuit (incl. ECDSA)", core_total, real_grand);
  row("  of which mso_splice", splice, real_grand);
  row("  of which sha256_var_sized(MSO)", sha_mso, real_grand);
  row("  => ECDSA + glue (remainder)", core_total.saturating_sub(splice + sha_mso), real_grand);
  row("TOTAL", real_grand, real_grand);

  // ---- ECDSA in isolation, as the core circuit invokes it ---------
  {
    use bellpepper_core::num::AllocatedNum;
    use zk_cred_vega::nonnative::bignat::BigNat;
    let mut cs = TestConstraintSystem::<Scalar>::new();
    let qxn = AllocatedNum::alloc(cs.namespace(|| "qx"), || Ok(qx)).unwrap();
    let qyn = AllocatedNum::alloc(cs.namespace(|| "qy"), || Ok(qy)).unwrap();
    let zbn = BigNat::alloc_from_nat(
      cs.namespace(|| "z"),
      || Ok(BigInt::from_bytes_be(Sign::Plus, &z)),
      64, 4).unwrap();
    let base = cs.num_constraints();
    let n2 = zk_cred_vega::p256_ecc::p256_order();
    let sv2 = BigInt::from_bytes_be(Sign::Plus, &sig.s().to_bytes());
    let si2 = sv2.modpow(&(n2.clone() - BigInt::from(2)), &n2);
    let r2 = BigInt::from_bytes_be(Sign::Plus, &sig.r().to_bytes());
    let _ = zk_cred_vega::ecdsa::verify_ecdsa_p256_with_digest(
      cs.namespace(|| "e"), &qxn, &qyn, &r2, &sv2, &si2, &zbn);
    println!("\n  ECDSA-P256 verify gadget            {:>9}", cs.num_constraints() - base);
  }

  println!("\n  public values/instance:");
  println!("    step public values : {}", step.public_values().unwrap().len());
  println!("    core public values : {}", core.public_values().unwrap().len());
  println!("    total across 4 steps + core : {}",
    step.public_values().unwrap().len() * 4 + core.public_values().unwrap().len());
  println!();
}
