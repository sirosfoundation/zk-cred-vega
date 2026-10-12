//! The deployable circuit around [`crate::mdoc_age`], and the only
//! acceptance path a relying party should use.
//!
//! # Why this exists as well as the gadget
//!
//! [`crate::mdoc_age::synthesize`] builds the relation. It does not say
//! which values become public, in what order, or what a verifier is
//! obliged to check once a proof verifies. Those three things are where
//! an otherwise-sound circuit gets deployed unsoundly, so they live here
//! rather than in every caller.
//!
//! # The split, and why it is not cosmetic
//!
//! `vega_sc_zkp` commits to `shared` and `precommitted` witnesses once in
//! `prep_prove` and reuses them across `prove` calls. That is the whole
//! point of the fold-and-reuse design: a wallet prepares once per
//! credential and proves once per verifier.
//!
//! So the credential-bound half of the statement — the signed bytes,
//! their hash, the issuer signature, the region binding, the item, the
//! birthdate — goes in `precommitted`, and the session-bound half — the
//! verifier's `DeviceAuthentication` digest, the holder's signature over
//! it, and the threshold comparison — goes in `synthesize`. Putting the
//! digest or the cutoff on the precommitted side would invalidate the
//! cache on every request and quietly destroy the design's only
//! performance argument.
//!
//! # Public input order
//!
//! Fixed, and [`MdocAgeCircuit::public_values`] must reproduce it exactly
//! or verification fails.
//!
//! Every `inputize` call lives in `synthesize`, including the ones for
//! credential-bound values allocated in `precommitted`. That is forced by
//! the proof system rather than chosen: `prove` re-runs only `synthesize`
//! against the cached prep state, so public IO declared during
//! `precommitted` never reaches the instance. Declaring it there yields
//! a shape whose `num_public` exceeds the instance's actual input count
//! and a slice-range panic inside the prover, which is how this was
//! found.
//!
//! `precommitted` therefore *returns* the values destined to be public
//! and `synthesize` publishes them, in this order:
//!
//! | # | values | count |
//! |---|---|---|
//! | 1 | issuer `qx`, `qy` | 2 |
//! | 2 | `docType`, packed 16 bytes at a time | 2 |
//! | 3 | namespace, NUL-padded | 32 |
//! | 4 | `cutoff`, one byte per element | 10 |
//! | 5 | `DeviceAuthentication` digest, packed | 2 |
//! | 6 | `old_enough` | 1 |
//!
//! Deliberately absent: the device key, the validity timestamps and the
//! `digestID`s. See [`crate::mdoc_age::MdocAgeOutputs`].
//!
//! **Unreviewed.** See the crate README.

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::{Field, PrimeField, PrimeFieldBits};
use vega_prover::traits::{circuit::VegaCircuit, Engine};

use crate::mdoc_age::{self, MdocAgeWitness, NAMESPACE_OUT_BYTES};

/// Number of public inputs, in the order documented above.
pub const PUBLIC_INPUT_LEN: usize =
  2 + 2 + NAMESPACE_OUT_BYTES + 10 + crate::offset_bind::TIMESTAMP_LEN + 2 + 1;

/// How many of `precommitted`'s returned values become public inputs:
/// issuer `qx`/`qy`, the packed `docType`, and the padded namespace.
/// How many of `precommitted`'s returned values become public inputs.
/// Shared with [`crate::mdoc_age_mc`] rather than duplicated: two copies
/// that must agree are two copies that can drift, and a drift here breaks
/// verification for one arithmetization only.
pub const PUBLIC_FROM_PRECOMMITTED: usize = 2 + 2 + NAMESPACE_OUT_BYTES;

/// Everything `precommitted` returns: the public prefix above, then the
/// device key and the ten birthdate characters, which stay private.
const PRECOMMITTED_LEN: usize =
  PUBLIC_FROM_PRECOMMITTED + 2 + 10 + 2 * zk_cred_vega_timestamp_len();

/// `offset_bind::TIMESTAMP_LEN`, usable in a `const` expression.
const fn zk_cred_vega_timestamp_len() -> usize {
  crate::offset_bind::TIMESTAMP_LEN
}

/// Everything one presentation needs.
#[derive(Clone)]
pub struct MdocAgeCircuit<E: Engine> {
  pub witness: MdocAgeWitness,
  pub ecdsa: crate::ecdsa::EcdsaP256Witness<E::Scalar>,
  /// The verifier's threshold date, `YYYY-MM-DD`.
  pub cutoff: [u8; 10],
  /// The verifier's clock, `YYYY-MM-DDTHH:MM:SSZ`. The credential must be
  /// live at this instant or no proof exists.
  pub now: [u8; crate::offset_bind::TIMESTAMP_LEN],
  /// The verifier's own `DeviceAuthentication` digest.
  pub device_auth_digest: [u8; 32],
}

fn pack16<Scalar: PrimeField>(bytes: &[u8]) -> Vec<Scalar> {
  bytes
    .chunks(16)
    .map(|c| c.iter().fold(Scalar::ZERO, |a, &b| a * Scalar::from(256u64) + Scalar::from(b as u64)))
    .collect()
}

impl<E: Engine> VegaCircuit<E> for MdocAgeCircuit<E>
where
  E::Scalar: PrimeFieldBits,
{
  /// Must match the allocation order in `precommitted` then `synthesize`.
  fn public_values(&self) -> Result<Vec<E::Scalar>, SynthesisError> {
    let mut v = vec![self.ecdsa.qx, self.ecdsa.qy];

    let mut doc = b"\x67docType".to_vec();
    doc.push(if self.witness.doc_type.len() < 24 {
      0x60 | self.witness.doc_type.len() as u8
    } else {
      0x78
    });
    if self.witness.doc_type.len() >= 24 {
      doc.push(self.witness.doc_type.len() as u8);
    }
    doc.extend_from_slice(self.witness.doc_type.as_bytes());
    v.extend(pack16::<E::Scalar>(&doc));

    let mut ns = self.witness.namespace.as_bytes().to_vec();
    ns.resize(NAMESPACE_OUT_BYTES, 0);
    v.extend(ns.iter().map(|&b| E::Scalar::from(b as u64)));

    v.extend(self.cutoff.iter().map(|&b| E::Scalar::from(b as u64)));
    v.extend(self.now.iter().map(|&b| E::Scalar::from(b as u64)));
    v.extend(pack16::<E::Scalar>(&self.device_auth_digest));

    // The predicate's real value. A prover cannot choose it: the circuit
    // computes it from the issuer-signed birthdate.
    let old_enough = self.witness.birth_date_bytes().map(|d| d[..] <= self.cutoff[..]).unwrap_or(false);
    v.push(if old_enough { E::Scalar::ONE } else { E::Scalar::ZERO });

    debug_assert_eq!(v.len(), PUBLIC_INPUT_LEN);
    Ok(v)
  }

  fn shared<CS: ConstraintSystem<E::Scalar>>(
    &self,
    _cs: &mut CS,
  ) -> Result<Vec<AllocatedNum<E::Scalar>>, SynthesisError> {
    Ok(vec![])
  }

  /// The credential-bound half, committed once and reused across
  /// presentations of the same credential.
  fn precommitted<CS: ConstraintSystem<E::Scalar>>(
    &self,
    cs: &mut CS,
    _shared: &[AllocatedNum<E::Scalar>],
  ) -> Result<Vec<AllocatedNum<E::Scalar>>, SynthesisError> {
    let cred = mdoc_age::synthesize_credential(
      cs,
      &self.witness,
      &self.ecdsa,
      &mdoc_age::Hasher::SingleCircuit,
      &mdoc_age::Hasher::SingleCircuit,
    )?;

    // Returned, not inputized — see this module's note on why. The
    // first `PUBLIC_FROM_PRECOMMITTED` are published by `synthesize`;
    // the rest (device key, birthdate) stay private and are only
    // consumed there.
    let mut out = vec![cred.issuer_qx, cred.issuer_qy];
    out.extend(cred.doc_type);
    out.extend(cred.namespace);
    out.push(cred.device_key.0);
    out.push(cred.device_key.1);
    out.extend(cred.birth_date);
    out.extend(cred.valid_from);
    out.extend(cred.valid_until);
    debug_assert_eq!(out.len(), PRECOMMITTED_LEN);
    Ok(out)
  }

  fn num_challenges(&self) -> usize {
    0
  }

  /// The session-bound half, re-run for every verifier.
  fn synthesize<CS: ConstraintSystem<E::Scalar>>(
    &self,
    cs: &mut CS,
    _shared: &[AllocatedNum<E::Scalar>],
    precommitted: &[AllocatedNum<E::Scalar>],
    _challenges: Option<&[E::Scalar]>,
  ) -> Result<(), SynthesisError> {
    if precommitted.len() != PRECOMMITTED_LEN {
      return Err(SynthesisError::Unsatisfiable);
    }
    // Publish the credential-bound half first, in the documented order.
    for (i, p) in precommitted[..PUBLIC_FROM_PRECOMMITTED].iter().enumerate() {
      p.inputize(cs.namespace(|| format!("inputize credential value {i}")))?;
    }

    let device_key = (
      precommitted[PUBLIC_FROM_PRECOMMITTED].clone(),
      precommitted[PUBLIC_FROM_PRECOMMITTED + 1].clone(),
    );
    const TS: usize = crate::offset_bind::TIMESTAMP_LEN;
    let bd = PUBLIC_FROM_PRECOMMITTED + 2;
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
      sess.old_enough.get_value().map(|b| if b { E::Scalar::ONE } else { E::Scalar::ZERO }).ok_or(SynthesisError::AssignmentMissing)
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

// ---- Keys, proving, and the acceptance path -------------------------

use vega_prover::{
  traits::snark::R1CSSNARKTrait,
  vega_sc_zkp::{VegaProverKey, VegaVerifierKey, VegaZkSNARK},
};

/// The keys a deployment distributes.
pub struct AgeKeys {
  pub pk: VegaProverKey<crate::Engine_>,
  pub vk: VegaVerifierKey<crate::Engine_>,
}

/// Runs setup for this circuit's shape.
///
/// Any satisfying witness produces the same shape — that is what
/// `all_document_types_produce_an_identical_circuit_shape` asserts across
/// mDL, EU PID and Photo ID, both salt lengths and both date encodings —
/// so `prototype` may be built from any valid credential, including a
/// synthetic fixture. Keys are randomized, so a deterministic source
/// build does **not** reproduce them; provenance has to be recorded when
/// an artifact is published.
pub fn setup(prototype: MdocAgeCircuit<crate::Engine_>) -> Result<AgeKeys, crate::VegaMdocError> {
  let (pk, vk) = VegaZkSNARK::<crate::Engine_>::setup(prototype)?;
  Ok(AgeKeys { pk, vk })
}

/// Produces a proof for one presentation.
pub fn prove(
  pk: &VegaProverKey<crate::Engine_>,
  circuit: MdocAgeCircuit<crate::Engine_>,
) -> Result<VegaZkSNARK<crate::Engine_>, crate::VegaMdocError> {
  let prep = VegaZkSNARK::<crate::Engine_>::prep_prove(pk, circuit.clone(), false)?;
  let (proof, _next) = VegaZkSNARK::<crate::Engine_>::prove(pk, circuit, prep, false)?;
  Ok(proof)
}

/// What the verifier demanded. Every field is checked against the proof,
/// so a mismatch is a rejection rather than something the caller has to
/// notice.
pub struct ExpectedContext {
  /// The digest this verifier issued for this session.
  pub device_auth_digest: [u8; 32],
  /// The threshold this verifier asked about.
  pub cutoff: [u8; 10],
  /// This verifier's clock. The credential was proven live against it.
  pub now: [u8; crate::offset_bind::TIMESTAMP_LEN],
}

/// What a caller learns from an accepted proof.
pub struct VerifiedAgeProof {
  /// Check this against your issuer trust list. The proof says the
  /// credential was signed by this key; it does not say the key is one
  /// you trust.
  pub issuer_qx: <crate::Engine_ as Engine>::Scalar,
  pub issuer_qy: <crate::Engine_ as Engine>::Scalar,
  pub doc_type: String,
  pub namespace: String,
}

/// Verifies a proof **and** enforces every obligation that would
/// otherwise fall on the caller.
///
/// This is the only acceptance path a relying party should use, and the
/// reason it exists rather than leaving callers to read public values is
/// CIRCUIT-04: a circuit proving that a hidden age flag *exists* does not
/// prove the flag is *true*. A caller reading `old_enough` out of the
/// public values and forgetting to require 1 accepts every holder, and
/// the proof is equally valid either way. So this function returns
/// `Err` unless:
///
/// * the proof verifies under `vk`;
/// * `old_enough` is exactly 1;
/// * the `DeviceAuthentication` digest is the one *this* verifier issued,
///   which is what makes the proof fresh and audience-bound rather than
///   replayed;
/// * the cutoff is the one this verifier asked about, so a prover cannot
///   answer an easier question than the one posed.
///
/// There is deliberately no accessor that hands back a raw predicate bit.
pub fn verify_age(
  proof: &VegaZkSNARK<crate::Engine_>,
  vk: &VegaVerifierKey<crate::Engine_>,
  expected: &ExpectedContext,
) -> Result<VerifiedAgeProof, crate::VegaMdocError> {

  let v = proof.verify(vk)?;
  check_public_values(&v, expected)
}

/// Decodes a verified proof's public values and enforces every caller
/// obligation. Shared by both arithmetizations — the single-circuit form
/// and the folded one in [`crate::mdoc_age_mc`] accept the same
/// statement, so they must not drift into checking it differently.
pub fn check_public_values(
  v: &[<crate::Engine_ as Engine>::Scalar],
  expected: &ExpectedContext,
) -> Result<VerifiedAgeProof, crate::VegaMdocError> {
  type S = <crate::Engine_ as Engine>::Scalar;
  let reject = || crate::VegaMdocError::Circuit(SynthesisError::Unsatisfiable);
  if v.len() != PUBLIC_INPUT_LEN {
    return Err(reject());
  }

  let issuer_qx = v[0];
  let issuer_qy = v[1];
  let doc_packs = &v[2..4];
  let ns_bytes = &v[4..4 + NAMESPACE_OUT_BYTES];
  const TS: usize = crate::offset_bind::TIMESTAMP_LEN;
  let c0 = 4 + NAMESPACE_OUT_BYTES;
  let cutoff = &v[c0..c0 + 10];
  let now = &v[c0 + 10..c0 + 10 + TS];
  let digest_packs = &v[c0 + 10 + TS..c0 + 12 + TS];
  let old_enough = v[c0 + 12 + TS];

  // CIRCUIT-04. Not "read the bit" — require it.
  if old_enough != S::ONE {
    return Err(reject());
  }
  // Freshness and audience: this must be *our* session.
  if digest_packs != pack16::<S>(&expected.device_auth_digest).as_slice() {
    return Err(reject());
  }
  // And our question, not an easier one.
  if cutoff != expected.cutoff.iter().map(|&b| S::from(b as u64)).collect::<Vec<_>>().as_slice() {
    return Err(reject());
  }
  // And our clock: the circuit proves the credential was live at this
  // instant, so a prover who picked their own would be proving nothing.
  if now != expected.now.iter().map(|&b| S::from(b as u64)).collect::<Vec<_>>().as_slice() {
    return Err(reject());
  }

  let byte = |s: &S| -> u8 { s.to_repr().as_ref()[0] };
  let namespace = String::from_utf8(ns_bytes.iter().map(byte).take_while(|&b| b != 0).collect())
    .map_err(|_| reject())?;
  // docType arrives packed 16 bytes at a time, and the final pack holds
  // only the remainder — `pack16` right-aligns it rather than padding,
  // matching how `offset_bind::pack_at` weights a short trailing chunk.
  // Reading it as a padded 16 bytes inserts NULs mid-string, which is
  // exactly what the end-to-end test caught. So parse the length out of
  // the first pack and take only that many bytes from the second.
  let unpack = |p: &S, n: usize| -> Vec<u8> {
    let r = p.to_repr();
    r.as_ref()[..n].iter().rev().copied().collect()
  };
  let head = unpack(&doc_packs[0], 16);
  if head[..8] != *b"\x67docType" {
    return Err(reject());
  }
  let (value_start, len) = match head[8] {
    h if (0x60..0x78).contains(&h) => (9usize, (h & 0x1f) as usize),
    0x78 => (10usize, head[9] as usize),
    _ => return Err(reject()),
  };
  let total = value_start + len;
  if !(16..=32).contains(&total) {
    return Err(reject());
  }
  let mut doc_bytes = head;
  doc_bytes.extend(unpack(&doc_packs[1], total - 16));
  let doc_type = String::from_utf8(doc_bytes[value_start..total].to_vec()).map_err(|_| reject())?;

  Ok(VerifiedAgeProof { issuer_qx, issuer_qy, doc_type, namespace })
}

