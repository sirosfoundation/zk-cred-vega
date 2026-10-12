//! r13 as a folded multi-circuit, per §4.2 of the Vega paper.
//!
//! Same statement as [`crate::mdoc_age_circuit`], different arithmetization:
//! every SHA-256 compression becomes an instance of one small step circuit
//! folded against a shared witness, and the core keeps no compression at
//! all. The paper's Figure 9b describes exactly that core — field
//! extraction, freshness checks, and two ECDSA verifications.
//!
//! The point is key size. Setup encodes one step circuit plus one core
//! rather than an unrolled hash, so it stops scaling with credential
//! length:
//!
//! > "Setup cost grows with input length in VegaSC ... while remaining
//! > nearly constant in VegaMC because the constraints for only one
//! > SHA-256 per-step circuit need to be set up."
//!
//! Both messages r13 hashes — the issuer's `Sig_structure` and the
//! `birth_date` `IssuerSignedItem` — share one step set, with the
//! chaining value resetting to the IV at the boundary (§4.2.1).
//!
//! **Unreviewed.** See the crate README.

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::{Field, PrimeFieldBits};
use vega_prover::traits::{circuit::VegaCircuit, Engine};

use crate::mdoc_age::{self, Hasher, MdocAgeWitness, NAMESPACE_OUT_BYTES};
use crate::sha256_mc::{self, HashLayout};

/// The two messages, in the order their blocks appear in the shared
/// witness. Fixed at setup, so the boundary is public.
pub fn layout() -> HashLayout {
  HashLayout {
    message_blocks: vec![mdoc_age::SIG_STRUCTURE_BLOCKS, crate::sha256_var::NUM_BLOCKS],
  }
}
const SIG_MESSAGE: usize = 0;
const ITEM_MESSAGE: usize = 1;

/// The blocks and intermediate digests both circuits commit to.
///
/// Derived natively from the witness. Both the step and core circuits
/// must allocate *identical* shared vectors: the proof system commits
/// once and reuses that commitment across both, so a mismatch is not an
/// error it can detect.
#[derive(Clone, Debug)]
pub struct HashWitness {
  pub blocks: Vec<[u8; 64]>,
  pub digests: Vec<[u8; 32]>,
}

impl HashWitness {
  pub fn from_witness(w: &MdocAgeWitness) -> Self {
    let l = layout();
    let mut blocks = Vec::new();
    let mut digests = Vec::new();
    for (m, (msg, max)) in [
      (&w.sig_structure[..], mdoc_age::MAX_SIG_STRUCTURE_BYTES),
      (&w.item_bytes[..], crate::MAX_CLAIM_BYTES_V1),
    ]
    .into_iter()
    .enumerate()
    {
      let n = l.message_blocks[m];
      let padded = crate::sha256_var::native_padded_buffer_sized(msg, msg.len(), max, n);
      let mut state = sha256_mc::IV;
      for b in padded.chunks(64) {
        let mut blk = [0u8; 64];
        blk.copy_from_slice(b);
        state = sha256_mc::compress_native(state, &blk);
        let mut d = [0u8; 32];
        for (i, word) in state.iter().enumerate() {
          d[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        blocks.push(blk);
        digests.push(d);
      }
    }
    Self { blocks, digests }
  }
}

/// One folded step: a single SHA-256 compression at a public index.
#[derive(Clone)]
pub struct StepCircuit<E: Engine> {
  pub hash: HashWitness,
  pub step: usize,
  pub _marker: std::marker::PhantomData<E>,
}

impl<E: Engine> VegaCircuit<E> for StepCircuit<E>
where
  E::Scalar: PrimeFieldBits,
{
  fn public_values(&self) -> Result<Vec<E::Scalar>, SynthesisError> {
    Ok(vec![E::Scalar::from(self.step as u64)])
  }

  fn shared<CS: ConstraintSystem<E::Scalar>>(
    &self,
    cs: &mut CS,
  ) -> Result<Vec<AllocatedNum<E::Scalar>>, SynthesisError> {
    sha256_mc::alloc_shared(cs, &self.hash.blocks, &self.hash.digests)
  }

  fn precommitted<CS: ConstraintSystem<E::Scalar>>(
    &self,
    _cs: &mut CS,
    _shared: &[AllocatedNum<E::Scalar>],
  ) -> Result<Vec<AllocatedNum<E::Scalar>>, SynthesisError> {
    Ok(vec![])
  }

  fn num_challenges(&self) -> usize {
    0
  }

  fn synthesize<CS: ConstraintSystem<E::Scalar>>(
    &self,
    cs: &mut CS,
    shared: &[AllocatedNum<E::Scalar>],
    _precommitted: &[AllocatedNum<E::Scalar>],
    _challenges: Option<&[E::Scalar]>,
  ) -> Result<(), SynthesisError> {
    let idx = AllocatedNum::alloc(cs.namespace(|| "step index"), || Ok(E::Scalar::from(self.step as u64)))?;
    idx.inputize(cs.namespace(|| "inputize step index"))?;
    sha256_mc::synthesize_step(cs, shared, &layout(), self.step)
  }
}

/// The core: everything that is not a SHA-256 compression.
#[derive(Clone)]
pub struct CoreCircuit<E: Engine> {
  pub hash: HashWitness,
  pub witness: MdocAgeWitness,
  pub ecdsa: crate::ecdsa::EcdsaP256Witness<E::Scalar>,
  pub cutoff: [u8; 10],
  pub now: [u8; crate::offset_bind::TIMESTAMP_LEN],
  pub device_auth_digest: [u8; 32],
}

/// Public inputs, same contract and order as the single-circuit form.
pub const PUBLIC_INPUT_LEN: usize = crate::mdoc_age_circuit::PUBLIC_INPUT_LEN;
const PUBLIC_FROM_PRECOMMITTED: usize = 2 + 2 + NAMESPACE_OUT_BYTES;

impl<E: Engine> VegaCircuit<E> for CoreCircuit<E>
where
  E::Scalar: PrimeFieldBits,
{
  fn public_values(&self) -> Result<Vec<E::Scalar>, SynthesisError> {
    crate::mdoc_age_circuit::MdocAgeCircuit::<E> {
      witness: self.witness.clone(),
      ecdsa: self.ecdsa.clone(),
      cutoff: self.cutoff,
      now: self.now,
      device_auth_digest: self.device_auth_digest,
    }
    .public_values()
  }

  fn shared<CS: ConstraintSystem<E::Scalar>>(
    &self,
    cs: &mut CS,
  ) -> Result<Vec<AllocatedNum<E::Scalar>>, SynthesisError> {
    // Byte-for-byte the same allocation as the step circuit's.
    sha256_mc::alloc_shared(cs, &self.hash.blocks, &self.hash.digests)
  }

  fn precommitted<CS: ConstraintSystem<E::Scalar>>(
    &self,
    cs: &mut CS,
    shared: &[AllocatedNum<E::Scalar>],
  ) -> Result<Vec<AllocatedNum<E::Scalar>>, SynthesisError> {
    let l = layout();
    let cred = mdoc_age::synthesize_credential(
      cs,
      &self.witness,
      &self.ecdsa,
      &Hasher::Folded { shared, layout: &l, message: SIG_MESSAGE },
      &Hasher::Folded { shared, layout: &l, message: ITEM_MESSAGE },
    )?;
    let mut out = vec![cred.issuer_qx, cred.issuer_qy];
    out.extend(cred.doc_type);
    out.extend(cred.namespace);
    out.push(cred.device_key.0);
    out.push(cred.device_key.1);
    out.extend(cred.birth_date);
    out.extend(cred.valid_from);
    out.extend(cred.valid_until);
    Ok(out)
  }

  fn num_challenges(&self) -> usize {
    0
  }

  fn synthesize<CS: ConstraintSystem<E::Scalar>>(
    &self,
    cs: &mut CS,
    _shared: &[AllocatedNum<E::Scalar>],
    precommitted: &[AllocatedNum<E::Scalar>],
    _challenges: Option<&[E::Scalar]>,
  ) -> Result<(), SynthesisError> {
    const TS: usize = crate::offset_bind::TIMESTAMP_LEN;
    for (i, p) in precommitted[..PUBLIC_FROM_PRECOMMITTED].iter().enumerate() {
      p.inputize(cs.namespace(|| format!("inputize credential value {i}")))?;
    }
    let bd = PUBLIC_FROM_PRECOMMITTED + 2;
    let device_key = (
      precommitted[PUBLIC_FROM_PRECOMMITTED].clone(),
      precommitted[PUBLIC_FROM_PRECOMMITTED + 1].clone(),
    );
    let sess = mdoc_age::synthesize_session(
      cs,
      &device_key,
      &precommitted[bd..bd + 10],
      &precommitted[bd + 10..bd + 10 + TS],
      &precommitted[bd + 10 + TS..bd + 10 + 2 * TS],
      &self.witness.device_auth,
      &self.cutoff,
      &self.now,
      &self.device_auth_digest,
    )?;
    for (i, c) in sess.cutoff.iter().enumerate() {
      c.inputize(cs.namespace(|| format!("inputize cutoff {i}")))?;
    }
    for (i, n) in sess.now.iter().enumerate() {
      n.inputize(cs.namespace(|| format!("inputize now {i}")))?;
    }
    for (i, p) in sess.device_auth_digest.iter().enumerate() {
      p.inputize(cs.namespace(|| format!("inputize device auth {i}")))?;
    }
    let old = AllocatedNum::alloc(cs.namespace(|| "old_enough"), || {
      sess
        .old_enough
        .get_value()
        .map(|b| if b { E::Scalar::ONE } else { E::Scalar::ZERO })
        .ok_or(SynthesisError::AssignmentMissing)
    })?;
    cs.enforce(
      || "old_enough is the predicate's own result",
      |lc| lc + &sess.old_enough.lc(CS::one(), E::Scalar::ONE),
      |lc| lc + CS::one(),
      |lc| lc + old.get_variable(),
    );
    old.inputize(cs.namespace(|| "inputize old_enough"))?;
    Ok(())
  }
}

/// Builds the step instances and the core for one presentation.
pub fn build(
  witness: &MdocAgeWitness,
  ecdsa: &crate::ecdsa::EcdsaP256Witness<<crate::Engine_ as Engine>::Scalar>,
  cutoff: [u8; 10],
  now: [u8; crate::offset_bind::TIMESTAMP_LEN],
  device_auth_digest: [u8; 32],
) -> (Vec<StepCircuit<crate::Engine_>>, CoreCircuit<crate::Engine_>) {
  let hash = HashWitness::from_witness(witness);
  let steps = (0..layout().total_blocks())
    .map(|step| StepCircuit { hash: hash.clone(), step, _marker: std::marker::PhantomData })
    .collect();
  let core = CoreCircuit {
    hash,
    witness: witness.clone(),
    ecdsa: ecdsa.clone(),
    cutoff,
    now,
    device_auth_digest,
  };
  (steps, core)
}

// ---- Keys, proving and acceptance ----------------------------------

use vega_prover::vega_mc_zkp::{VegaMcProverKey, VegaMcVerifierKey, VegaMcZkSNARK};

/// The folded form's keys. Sized by one step circuit plus one core,
/// not by the credential's length.
pub struct AgeKeys {
  pub pk: VegaMcProverKey<crate::Engine_>,
  pub vk: VegaMcVerifierKey<crate::Engine_>,
}

/// Runs setup for the folded shape.
pub fn setup(
  step_proto: &StepCircuit<crate::Engine_>,
  core_proto: &CoreCircuit<crate::Engine_>,
) -> Result<AgeKeys, crate::VegaMdocError> {
  let (pk, vk) = VegaMcZkSNARK::<crate::Engine_>::setup(step_proto, core_proto, layout().total_blocks())?;
  Ok(AgeKeys { pk, vk })
}

/// Proves one presentation.
pub fn prove(
  pk: &VegaMcProverKey<crate::Engine_>,
  steps: &[StepCircuit<crate::Engine_>],
  core: &CoreCircuit<crate::Engine_>,
) -> Result<VegaMcZkSNARK<crate::Engine_>, crate::VegaMdocError> {
  let prep = VegaMcZkSNARK::<crate::Engine_>::prep_prove(pk, steps, core, false)?;
  let (proof, _next) = VegaMcZkSNARK::<crate::Engine_>::prove(pk, steps, core, prep, false)?;
  Ok(proof)
}

/// Verifies and enforces every caller obligation, exactly as the
/// single-circuit [`crate::mdoc_age_circuit::verify_age`] does. The
/// arithmetization differs; the accepted statement does not.
pub fn verify_age(
  proof: &VegaMcZkSNARK<crate::Engine_>,
  vk: &VegaMcVerifierKey<crate::Engine_>,
  expected: &crate::mdoc_age_circuit::ExpectedContext,
) -> Result<crate::mdoc_age_circuit::VerifiedAgeProof, crate::VegaMdocError> {
  let (step_values, core_values) = proof.verify(vk, layout().total_blocks())?;

  // Each folded step must have proven the index it claims, in order.
  // Without this a prover could fold the same block repeatedly and leave
  // others unproven.
  if step_values.len() != layout().total_blocks() {
    return Err(crate::VegaMdocError::Circuit(SynthesisError::Unsatisfiable));
  }
  for (i, v) in step_values.iter().enumerate() {
    if v.len() != 1 || v[0] != <<crate::Engine_ as Engine>::Scalar as From<u64>>::from(i as u64) {
      return Err(crate::VegaMdocError::Circuit(SynthesisError::Unsatisfiable));
    }
  }
  crate::mdoc_age_circuit::check_public_values(&core_values, expected)
}
