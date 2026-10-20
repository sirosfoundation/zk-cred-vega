//! Measures the circuit against each performance lever in the Vega paper,
//! so the decision to adopt one is made from this circuit's own numbers
//! rather than the paper's ratios. Analysis tool.

use bellpepper_core::{
  ConstraintSystem,
  boolean::{AllocatedBit, Boolean},
  test_cs::TestConstraintSystem,
};
use zk_cred_vega::Engine_;
type S = <Engine_ as vega_prover::traits::Engine>::Scalar;

fn bits<CS: ConstraintSystem<S>>(cs: &mut CS, n: usize, tag: &str) -> Vec<Boolean> {
  (0..n * 8)
    .map(|i| {
      AllocatedBit::alloc(cs.namespace(|| format!("{tag} {i}")), Some(i % 3 == 0))
        .map(Boolean::from)
        .unwrap()
    })
    .collect()
}

fn main() {
  const COMP: usize = 25_840;
  let max = zk_cred_vega::mdoc_age::MAX_SIG_STRUCTURE_BYTES;
  let blocks = zk_cred_vega::mdoc_age::SIG_STRUCTURE_BLOCKS;

  // --- Lever A: length-hiding overhead on top of the compressions ---
  let mut cs = TestConstraintSystem::<S>::new();
  let b = bits(&mut cs, max, "m");
  let base = cs.num_constraints();
  let _ = zk_cred_vega::sha256_var::sha256_var_sized(cs.namespace(|| "h"), &b, 1570, max, blocks).unwrap();
  let total = cs.num_constraints() - base;
  let compressions = blocks * COMP;
  println!("\n  A. length-hiding SHA-256 over {max} B / {blocks} blocks");
  println!("     total                       {total:>9}");
  println!("     of which compressions       {compressions:>9}");
  println!(
    "     length-hiding overhead      {:>9}  ({:.1}% of the hash)",
    total - compressions,
    (total - compressions) as f64 * 100.0 / total as f64
  );
  println!("     selector is over bytes      {:>9} bits", max + 1);
  println!("     paper 4.1.1 selects blocks  {blocks:>9} bits");

  // --- Lever B: cost of one anchored window selection ---
  let mut cs = TestConstraintSystem::<S>::new();
  let b = bits(&mut cs, max, "w");
  let native = vec![0u8; max];
  let cands = zk_cred_vega::offset_bind::anchor_offsets(max);
  let base = cs.num_constraints();
  let _ = zk_cred_vega::offset_bind::select_window::<S, _>(cs.namespace(|| "win"), &b, &native, &cands, 100, 32).unwrap();
  let one_window = cs.num_constraints() - base;
  println!("\n  B. one 32-byte anchored window ({} candidates)", cands.len());
  println!("     cost                        {one_window:>9}");
  println!("     r13 selects 7 such windows  {:>9}", one_window * 7);
  println!("     (valueDigests, namespace, deviceKeyInfo, docType,");
  println!("      device x, device y, validityInfo, digest locate)");
}

// appended: folded-core measurement
