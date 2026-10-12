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

fn main() {
  for n in [1usize, 1_000, 100_000] {
    let (pk, vk) = VegaZkSNARK::<Engine_>::setup(Tiny { n }).expect("setup");
    let p = bincode::serialize(&pk).map(|v| v.len()).unwrap_or(0);
    let v = bincode::serialize(&vk).map(|v| v.len()).unwrap_or(0);
    println!("  ~{n:>7} constraints -> pk {:>8.2} MB   vk {:>8.2} MB", p as f64 / 1e6, v as f64 / 1e6);
  }
  println!("\n  r13 single-circuit (1,343,074) was 614.44 MB");
  println!("  r13 folded        (224,119 shape) is 420.11 MB");
}
