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
//! # The folded form's one hard obligation
//!
//! `vega_mc_zkp::verify` checks how *many* step instances a proof carries
//! and never what they claim. Nothing in the proof system requires the
//! folded steps to be indices `0..n-1`.
//!
//! That matters: a prover folding `n` copies of step 0 proves one
//! compression and leaves every other block's shared digest
//! unconstrained — including the one [`crate::sha256_mc::select_digest`]
//! hands to the ECDSA check as the signed message. Choosing that freely
//! lets one credential's bytes be paired with another credential's
//! genuine issuer signature. Such a proof **can be generated under the
//! real proving key**; `mc01_folding_the_wrong_indices_is_caught_by_the_acceptance_path`
//! does exactly that.
//!
//! The fix cannot live inside a circuit. "Every block index is covered
//! exactly once" is a property of the *set* of folded instances, and no
//! single circuit sees the set — only the verifier does. So it is
//! necessarily a verifier-side check, and the thing that can be fixed is
//! making it unskippable.
//!
//! [`FoldedAgeProof`] is therefore opaque: it holds the proof but does
//! not hand out the inner `VegaMcZkSNARK`, so within this crate's API
//! there is no way to reach public values except through [`verify_age`],
//! which performs the check. That turns a documented obligation into one
//! the type system keeps.
//!
//! **Unreviewed.** See the crate README.

use bellpepper_core::{ConstraintSystem, SynthesisError, num::AllocatedNum};
use ff::{Field, PrimeFieldBits};
use vega_prover::traits::{Engine, circuit::VegaCircuit};

use crate::mdoc_age::{self, Hasher, MdocAgeWitness};
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
  /// Checks the vectors are the shape the layout demands.
  ///
  /// `blocks` and `digests` are public fields, so a caller can hand
  /// either circuit a short one. `alloc_shared` accepts whatever it is
  /// given, and `synthesize_step` then indexes past the end — a panic,
  /// across an FFI boundary where that aborts the host, instead of the
  /// `Unsatisfiable` a malformed witness is supposed to produce. Both
  /// `shared` implementations call this first.
  pub fn check(&self) -> Result<(), SynthesisError> {
    let n = layout().total_blocks();
    if self.blocks.len() != n || self.digests.len() != n {
      return Err(SynthesisError::Unsatisfiable);
    }
    Ok(())
  }

  /// Fallible: this is witness generation, so there is no constraint yet
  /// to be unsatisfied, and the crate crosses an FFI boundary where a
  /// panic aborts the host process. An over-budget `sig_structure` or
  /// `IssuerSignedItem` is a credential to reject, not a reason to take
  /// the wallet down with it — the circuit's own malformed-witness
  /// checks already return `Unsatisfiable`, and this must reach them
  /// rather than panic on the way.
  pub fn from_witness(w: &MdocAgeWitness) -> Result<Self, SynthesisError> {
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
      let padded = crate::sha256_var::native_padded_buffer_sized(msg, msg.len(), max, n)?;
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
    Ok(Self { blocks, digests })
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

  fn shared<CS: ConstraintSystem<E::Scalar>>(&self, cs: &mut CS) -> Result<Vec<AllocatedNum<E::Scalar>>, SynthesisError> {
    self.hash.check()?;
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
    // The index is allocated, inputized *and* bound to the one-hot
    // selector inside `synthesize_step`. Doing it here instead left the
    // published index and the selected block unrelated — see that
    // function's doc.
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
use crate::mdoc_age_circuit::PUBLIC_FROM_PRECOMMITTED;

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

  fn shared<CS: ConstraintSystem<E::Scalar>>(&self, cs: &mut CS) -> Result<Vec<AllocatedNum<E::Scalar>>, SynthesisError> {
    // Byte-for-byte the same allocation as the step circuit's.
    self.hash.check()?;
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
      &Hasher::Folded {
        shared,
        layout: &l,
        message: SIG_MESSAGE,
      },
      &Hasher::Folded {
        shared,
        layout: &l,
        message: ITEM_MESSAGE,
      },
    )?;
    // Same packer as the single-circuit form, deliberately: the two
    // halves of this layout — the order of the values and how many of
    // them are public — are one fact and must not be stated twice.
    crate::mdoc_age_circuit::pack_precommitted(cred)
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
    if precommitted.len() != crate::mdoc_age_circuit::PRECOMMITTED_LEN {
      return Err(SynthesisError::Unsatisfiable);
    }
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
) -> Result<(Vec<StepCircuit<crate::Engine_>>, CoreCircuit<crate::Engine_>), SynthesisError> {
  let hash = HashWitness::from_witness(witness)?;
  let steps = (0..layout().total_blocks())
    .map(|step| StepCircuit {
      hash: hash.clone(),
      step,
      _marker: std::marker::PhantomData,
    })
    .collect();
  let core = CoreCircuit {
    hash,
    witness: witness.clone(),
    ecdsa: ecdsa.clone(),
    cutoff,
    now,
    device_auth_digest,
  };
  Ok((steps, core))
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
pub fn setup(step_proto: &StepCircuit<crate::Engine_>, core_proto: &CoreCircuit<crate::Engine_>) -> Result<AgeKeys, crate::VegaMdocError> {
  let (pk, vk) = VegaMcZkSNARK::<crate::Engine_>::setup(step_proto, core_proto, layout().total_blocks())?;
  Ok(AgeKeys { pk, vk })
}

/// A folded proof, deliberately opaque.
///
/// It does not expose the inner `VegaMcZkSNARK`, because that type's own
/// `verify` returns public values **without** checking which block
/// indices the folded steps claimed — and a proof that folds the wrong
/// indices leaves the signed digest free. See this module's header.
///
/// Serialization goes through this wrapper, so a stored proof keeps the
/// same property when it comes back.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct FoldedAgeProof(VegaMcZkSNARK<crate::Engine_>);

/// Proves one presentation.
pub fn prove(
  pk: &VegaMcProverKey<crate::Engine_>,
  steps: &[StepCircuit<crate::Engine_>],
  core: &CoreCircuit<crate::Engine_>,
) -> Result<FoldedAgeProof, crate::VegaMdocError> {
  let prep = VegaMcZkSNARK::<crate::Engine_>::prep_prove(pk, steps, core, false)?;
  let (proof, _next) = VegaMcZkSNARK::<crate::Engine_>::prove(pk, steps, core, prep, false)?;
  Ok(FoldedAgeProof(proof))
}

/// Verifies and enforces every caller obligation, exactly as the
/// single-circuit [`crate::mdoc_age_circuit::verify_age`] does. The
/// arithmetization differs; the accepted statement does not.
pub fn verify_age(
  proof: &FoldedAgeProof,
  vk: &VegaMcVerifierKey<crate::Engine_>,
  expected: &crate::mdoc_age_circuit::ExpectedContext,
) -> Result<crate::mdoc_age_circuit::VerifiedAgeProof, crate::VegaMdocError> {
  let n = layout().total_blocks();
  let (step_values, core_values) = proof.0.verify(vk, n)?;

  // MC-01. Every block index must be claimed exactly once, in order.
  //
  // The proof system checks only how many instances there are, so
  // without this a prover folds n copies of one step, proves a single
  // compression, and leaves every other block's shared digest free --
  // including the one `select_digest` hands to the ECDSA check as the
  // signed message. Rejecting duplicates is the point; rejecting a
  // permutation as well costs nothing and keeps the rule simple enough
  // to state.
  if step_values.len() != n {
    return Err(crate::VegaMdocError::Circuit(SynthesisError::Unsatisfiable));
  }
  for (i, v) in step_values.iter().enumerate() {
    if v.len() != 1 || v[0] != <<crate::Engine_ as Engine>::Scalar as From<u64>>::from(i as u64) {
      return Err(crate::VegaMdocError::Circuit(SynthesisError::Unsatisfiable));
    }
  }
  crate::mdoc_age_circuit::check_public_values(&core_values, expected)
}
