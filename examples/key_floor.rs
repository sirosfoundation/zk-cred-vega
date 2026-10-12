//! What does a key cost before any of our circuit is in it?
//!
//! The folded arithmetization shrank r13's shape 6x but the serialized
//! keys only 1.46x, which says the key is not dominated by our circuit.
//! This measures the floor directly: setup over a circuit with a handful
//! of constraints. Analysis tool.

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::Field;
use vega_prover::traits::{circuit::VegaCircuit, snark::R1CSSNARKTrait, Engine};
use vega_prover::vega_sc_zkp::VegaZkSNARK;
use zk_cred_vega::Engine_;

#[derive(Clone)]
struct Tiny {
  n: usize,
}

impl<E: Engine> VegaCircuit<E> for Tiny {
  fn public_values(&self) -> Result<Vec<E::Scalar>, SynthesisError> {
    Ok(vec![E::Scalar::ONE])
  }
  fn shared<CS: ConstraintSystem<E::Scalar>>(&self, _cs: &mut CS) -> Result<Vec<AllocatedNum<E::Scalar>>, SynthesisError> {
    Ok(vec![])
  }
  fn precommitted<CS: ConstraintSystem<E::Scalar>>(&self, _cs: &mut CS, _s: &[AllocatedNum<E::Scalar>]) -> Result<Vec<AllocatedNum<E::Scalar>>, SynthesisError> {
    Ok(vec![])
  }
  fn num_challenges(&self) -> usize {
    0
  }
  fn synthesize<CS: ConstraintSystem<E::Scalar>>(
    &self,
    cs: &mut CS,
    _s: &[AllocatedNum<E::Scalar>],
    _p: &[AllocatedNum<E::Scalar>],
    _c: Option<&[E::Scalar]>,
  ) -> Result<(), SynthesisError> {
    let one = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(E::Scalar::ONE))?;
    one.inputize(cs.namespace(|| "inputize x"))?;
    let mut prev = one;
    for i in 0..self.n {
      let next = AllocatedNum::alloc(cs.namespace(|| format!("y{i}")), || Ok(E::Scalar::ONE))?;
      cs.enforce(|| format!("c{i}"), |lc| lc + prev.get_variable(), |lc| lc + CS::one(), |lc| lc + next.get_variable());
      prev = next;
    }
    Ok(())
  }
}

/// Same constraint count as `Tiny`, but each constraint's B row is a
/// linear combination over `width` variables rather than one — which is
/// what a one-hot window selection over a byte buffer produces.
#[derive(Clone)]
struct Dense {
  n: usize,
  width: usize,
}

impl<E: Engine> VegaCircuit<E> for Dense {
  fn public_values(&self) -> Result<Vec<E::Scalar>, SynthesisError> {
    Ok(vec![E::Scalar::ONE])
  }
  fn shared<CS: ConstraintSystem<E::Scalar>>(&self, _cs: &mut CS) -> Result<Vec<AllocatedNum<E::Scalar>>, SynthesisError> { Ok(vec![]) }
  fn precommitted<CS: ConstraintSystem<E::Scalar>>(&self, _cs: &mut CS, _s: &[AllocatedNum<E::Scalar>]) -> Result<Vec<AllocatedNum<E::Scalar>>, SynthesisError> { Ok(vec![]) }
  fn num_challenges(&self) -> usize { 0 }
  fn synthesize<CS: ConstraintSystem<E::Scalar>>(
    &self, cs: &mut CS, _s: &[AllocatedNum<E::Scalar>], _p: &[AllocatedNum<E::Scalar>], _c: Option<&[E::Scalar]>,
  ) -> Result<(), SynthesisError> {
    let one = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(E::Scalar::ONE))?;
    one.inputize(cs.namespace(|| "inputize x"))?;
    let row: Vec<_> = (0..self.width)
      .map(|i| AllocatedNum::alloc(cs.namespace(|| format!("w{i}")), || Ok(E::Scalar::ZERO)).unwrap())
      .collect();
    for i in 0..self.n {
      let t = AllocatedNum::alloc(cs.namespace(|| format!("t{i}")), || Ok(E::Scalar::ZERO))?;
      cs.enforce(
        || format!("d{i}"),
        |lc| lc + one.get_variable(),
        |lc| row.iter().fold(lc, |acc, v| acc + v.get_variable()),
        |lc| lc + t.get_variable(),
      );
    }
    Ok(())
  }
}

fn main() {
  for n in [1usize, 1_000, 100_000, 528_000, 1_684_884] {
    let (pk, vk) = VegaZkSNARK::<Engine_>::setup(Tiny { n }).expect("setup");
    let p = bincode::serialize(&pk).map(|v| v.len()).unwrap_or(0);
    let v = bincode::serialize(&vk).map(|v| v.len()).unwrap_or(0);
    println!("  ~{n:>7} constraints -> pk {:>8.2} MB   vk {:>8.2} MB", p as f64 / 1e6, v as f64 / 1e6);
  }
  println!("\n  r13 single-circuit (1,684,884) measured 1153.07 MB");
  println!("  r13 folded        (~528k shape)  measured  908.37 MB");
  // Both have grown twice now, and each time by far more than the
  // constraint count did:
  //
  //   constant-width masked anchors   +0.8% constraints   614 ->  728 MB
  //   the namespace entry walk       +24.4% constraints   728 -> 1153 MB
  //
  // Each added selection windows -- rows spanning 56 to 320 bit
  // variables -- rather than arithmetic. Two independent confirmations
  // that the artifact is a function of row density, not of count, and
  // the reason the folded form no longer helps much: the walk lives in
  // the core, which is not folded.
  for (n, width) in [(100_000usize, 1usize), (100_000, 64), (100_000, 256)] {
    let (pk, _vk) = VegaZkSNARK::<Engine_>::setup(Dense { n, width }).expect("setup");
    let p = bincode::serialize(&pk).map(|v| v.len()).unwrap_or(0);
    println!("  {n} constraints, B-row width {width:>4} -> pk {:>8.2} MB", p as f64 / 1e6);
  }

  println!("\n  If a content-free circuit of the same size costs the same, the key is");
  println!("  a function of constraint COUNT alone and no circuit change will shrink it.");
}
