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
//! | 2 | the `docType` anchor window, packed 16 bytes at a time | 3 |
//! | 3 | the namespace anchor window, the same way | 3 |
//! | 4 | the namespace window's prefix length | 1 |
//! | 5 | the namespace's entry count | 1 |
//! | 6 | `cutoff`, one byte per element | 10 |
//! | 7 | `now`, one byte per element | 20 |
//! | 8 | `DeviceAuthentication` digest, packed | 2 |
//! | 9 | `old_enough` | 1 |
//!
//! Rows 4 and 5 are where the digest region begins and ends; the
//! verifier derives both from the namespace window in row 3 and requires
//! them to match, which is what stops a prover moving or stretching the
//! region. Rows 2 to 3 are the **windows as they appear in the signed bytes**,
//! not a reconstruction of the document type and namespace, and
//! [`check_public_values`] parses them. That is not a presentation
//! choice. Comparing an anchor to its literal in-circuit writes the
//! literal into the R1CS matrices and sizes the window to it, so an mDL,
//! an EU PID and a Photo ID produced three different matrices — with
//! *identical* constraint counts, which is why a count-only shape test
//! never saw it. Three matrices are three proving keys, and this circuit
//! exists to have one.
//!
//! Deliberately absent: the device key, the validity timestamps and the
//! `digestID`s. See [`crate::mdoc_age::MdocAgeOutputs`].
//!
//! **Unreviewed.** See the crate README.

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::{Field, PrimeField, PrimeFieldBits};
use vega_prover::traits::{circuit::VegaCircuit, Engine};

use crate::mdoc_age::{self, MdocAgeWitness, NAMESPACE_OUT_PACKS};

/// Field elements the published `docType` window occupies.
pub const DOC_TYPE_OUT_PACKS: usize = crate::offset_bind::ANCHOR_TEXT_PACKS;

/// Number of public inputs, in the order documented above.
pub const PUBLIC_INPUT_LEN: usize = PUBLIC_FROM_PRECOMMITTED + 10 + crate::offset_bind::TIMESTAMP_LEN + 2 + 1;

/// How many of `precommitted`'s returned values become public inputs:
/// issuer `qx`/`qy`, the `docType` window, the namespace window, that
/// window's prefix length and the namespace's entry count.
///
/// Shared with [`crate::mdoc_age_mc`] rather than duplicated: two copies
/// that must agree are two copies that can drift, and a drift here breaks
/// verification for one arithmetization only.
pub const PUBLIC_FROM_PRECOMMITTED: usize = 2 + DOC_TYPE_OUT_PACKS + NAMESPACE_OUT_PACKS + 2;

/// Everything `precommitted` returns: the public prefix above, then the
/// device key, the ten birthdate characters and the validity window,
/// which stay private.
pub const PRECOMMITTED_LEN: usize =
  PUBLIC_FROM_PRECOMMITTED + 2 + 10 + 2 * zk_cred_vega_timestamp_len();

/// Flattens a [`mdoc_age::CredentialBinding`] into the vector
/// `precommitted` returns, public prefix first.
///
/// Both arithmetizations call this rather than each building the vector
/// themselves. They did build it themselves, and the duplication cost a
/// day: adding one value to the credential-bound half left the folded
/// core's `synthesize` slicing the old layout, which surfaces as an
/// out-of-range panic inside the prover rather than as a verification
/// failure. The order here and [`PUBLIC_FROM_PRECOMMITTED`] are one
/// fact, so they live in one place.
pub fn pack_precommitted<Scalar: PrimeField>(
  cred: mdoc_age::CredentialBinding<Scalar>,
) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
  let mut out = vec![cred.issuer_qx, cred.issuer_qy];
  out.extend(cred.doc_type);
  out.extend(cred.namespace);
  out.push(cred.namespace_prefix_len);
  out.push(cred.num_entries);
  out.push(cred.device_key.0);
  out.push(cred.device_key.1);
  out.extend(cred.birth_date);
  out.extend(cred.valid_from);
  out.extend(cred.valid_until);
  if out.len() != PRECOMMITTED_LEN {
    return Err(SynthesisError::Unsatisfiable);
  }
  Ok(out)
}

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

    // Both anchors are published as the fixed-width windows the circuit
    // selected, read straight out of the signed bytes rather than
    // reconstructed — the circuit's value is whatever is *there*, and
    // reconstructing is how the two drift apart — and masked past the
    // prefix exactly as the circuit masks them, because the tail of the
    // namespace window is the start of the digest table.
    let masked = |at: usize, prefix: usize| -> Result<Vec<E::Scalar>, SynthesisError> {
      const W: usize = crate::offset_bind::ANCHOR_TEXT_WINDOW;
      // `at + W` would be evaluated before `get` could reject it, and
      // the landmark is a witness: near `usize::MAX` that panics in
      // debug and wraps in release, both before synthesis has run any of
      // the fallible landmark checks.
      let end = at.checked_add(W).ok_or(SynthesisError::Unsatisfiable)?;
      let bytes = self.witness.sig_structure.get(at..end).ok_or(SynthesisError::Unsatisfiable)?;
      if prefix > W {
        return Err(SynthesisError::Unsatisfiable);
      }
      let mut out = bytes.to_vec();
      out[prefix..].fill(0);
      Ok(pack16::<E::Scalar>(&out))
    };
    let ns_prefix = crate::offset_bind::namespace_prefix_len(&self.witness.namespace, self.witness.num_entries)?;
    v.extend(masked(
      self.witness.landmarks.doc_type_key,
      crate::offset_bind::doc_type_prefix_len(&self.witness.doc_type)?,
    )?);
    v.extend(masked(self.witness.landmarks.namespace_key, ns_prefix)?);
    v.push(E::Scalar::from(ns_prefix as u64));
    v.push(E::Scalar::from(self.witness.num_entries as u64));

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
    // the rest (device key, birthdate, validity window) stay private and
    // are only consumed there.
    pack_precommitted(cred)
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
/// Any satisfying witness produces the same R1CS — the same matrices,
/// not merely the same constraint count, which is what
/// `all_document_types_produce_an_identical_circuit_shape` asserts across
/// mDL, EU PID and Photo ID, both salt lengths and both date encodings by
/// comparing `TestConstraintSystem::hash`. So `prototype` may be built
/// from any valid credential, including a synthetic fixture. The
/// distinction is not pedantic: an earlier revision had all three
/// document types at 1,343,074 constraints and three different matrices,
/// so a key set up from the mDL prototype did not fit a PID proof. Keys are randomized, so a deterministic source
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
  /// The `(docType, namespace)` pairs this verifier will accept the
  /// answer from. Must be non-empty, and the proof's own pair must be
  /// one of them.
  ///
  /// This is not a convenience. The circuit proves a predicate over
  /// `birth_date` *in a particular namespace of a particular document*,
  /// and a credential may carry `birth_date` in more than one — ISO/IEC
  /// 23220-4's DTC namespace alongside `org.iso.23220.1`, for one, and
  /// nothing requires the two to agree. A holder can then prove the
  /// favourable one entirely honestly, publish its namespace truthfully,
  /// and a verifier who asked about the other and did not read the
  /// answer accepts it. `test-vectors/photo_id_cross_namespace.json` is
  /// that credential: thirteen years old in `org.iso.23220.1`, an adult
  /// in `org.iso.23220.dtc.1`.
  ///
  /// Returning the pair and trusting the caller to compare it is the
  /// mistake this module exists to prevent — the same shape as CIRCUIT-04,
  /// where returning `old_enough` and trusting the caller to require 1
  /// accepts every holder. So it is required here and checked, like the
  /// cutoff, the clock and the session digest.
  pub accepted: Vec<(String, String)>,
}

impl ExpectedContext {
  /// The common case: one document type, one namespace.
  pub fn new(
    device_auth_digest: [u8; 32],
    cutoff: [u8; 10],
    now: [u8; crate::offset_bind::TIMESTAMP_LEN],
    doc_type: &str,
    namespace: &str,
  ) -> Self {
    Self {
      device_auth_digest,
      cutoff,
      now,
      accepted: vec![(doc_type.to_string(), namespace.to_string())],
    }
  }
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
///   answer an easier question than the one posed;
/// * the `(docType, namespace)` the answer came from is one this verifier
///   named, so a prover cannot answer about a different attribute of the
///   same credential.
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
  let mut at = 2;
  let doc_packs = &v[at..at + DOC_TYPE_OUT_PACKS];
  at += DOC_TYPE_OUT_PACKS;
  let ns_packs = &v[at..at + NAMESPACE_OUT_PACKS];
  at += NAMESPACE_OUT_PACKS;
  let ns_prefix_len = v[at];
  let num_entries = v[at + 1];
  at += 2;
  debug_assert_eq!(at, PUBLIC_FROM_PRECOMMITTED);
  const TS: usize = crate::offset_bind::TIMESTAMP_LEN;
  let cutoff = &v[at..at + 10];
  let now = &v[at + 10..at + 10 + TS];
  let digest_packs = &v[at + 10 + TS..at + 12 + TS];
  let old_enough = v[at + 12 + TS];

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

  // Both anchors arrive as the fixed-width windows the circuit selected
  // out of the signed bytes, packed 16 bytes to an element with a short
  // trailing chunk right-aligned rather than padded — `offset_bind`
  // weights a short chunk the same way, and reading it as a padded 16
  // inserts NULs mid-string, which is what an end-to-end test caught
  // when the `docType` was two packs.
  //
  // Parsing them *here* rather than comparing them to a literal
  // in-circuit is what keeps the circuit's shape free of the document:
  // a literal comparison puts the namespace's own bytes into the R1CS
  // matrices, so a key set up for an mDL would not fit an EU PID. The
  // check is the same check; it is simply free on this side.
  let unpack_window = |packs: &[S]| -> Vec<u8> {
    let mut out = Vec::with_capacity(crate::offset_bind::ANCHOR_TEXT_WINDOW);
    let mut left = crate::offset_bind::ANCHOR_TEXT_WINDOW;
    for p in packs {
      let n = left.min(16);
      let r = p.to_repr();
      out.extend(r.as_ref()[..n].iter().rev().copied());
      left -= n;
    }
    out
  };

  /// Reads a canonical CBOR text string, returning it and the byte after it.
  fn read_tstr(bytes: &[u8], at: usize) -> Option<(String, usize)> {
    let (start, len) = match *bytes.get(at)? {
      h if (0x60..0x78).contains(&h) => (at + 1, (h & 0x1f) as usize),
      0x78 => (at + 2, *bytes.get(at + 1)? as usize),
      _ => return None,
    };
    // Canonical CBOR: the one-byte form is mandatory below 24, so a
    // two-byte header claiming a short length is a different encoding of
    // the same string and must not be accepted as equivalent.
    if start == at + 2 && len < 24 {
      return None;
    }
    let end = start.checked_add(len)?;
    Some((String::from_utf8(bytes.get(start..end)?.to_vec()).ok()?, end))
  }

  let doc_bytes = unpack_window(doc_packs);
  if doc_bytes.get(..8) != Some(&b"\x67docType"[..]) {
    return Err(reject());
  }
  let (doc_type, _) = read_tstr(&doc_bytes, 8).ok_or_else(reject)?;

  let ns_bytes = unpack_window(ns_packs);
  let (namespace, after_ns) = read_tstr(&ns_bytes, 0).ok_or_else(reject)?;
  // The namespace's entry-count map header follows it, and where it ends
  // is where the circuit took the digest region to begin. A prover free
  // to misdeclare that length is a prover free to move the region, so
  // this is derived from the window and required to match.
  let (map_header_len, entries) = match *ns_bytes.get(after_ns).ok_or_else(reject)? {
    h @ 0xa0..=0xb7 => (1usize, (h & 0x1f) as usize),
    0xb8 => (2usize, *ns_bytes.get(after_ns + 1).ok_or_else(reject)? as usize),
    _ => return Err(reject()),
  };
  // Canonical CBOR: the one-byte form is mandatory below 24, so the
  // two-byte form claiming a small count is a different encoding of the
  // same map and must not pass as equivalent.
  if map_header_len == 2 && entries < 24 {
    return Err(reject());
  }
  if ns_prefix_len != S::from((after_ns + map_header_len) as u64) {
    return Err(reject());
  }
  // Where the digest region *ends*. The circuit walks exactly this many
  // entries, so a prover who declared a different count would have
  // walked to a different offset — and the count is right here in the
  // namespace's own signed header.
  if num_entries != S::from(entries as u64) {
    return Err(reject());
  }

  // The answer has to be to the question that was asked. A credential
  // may carry `birth_date` in more than one namespace with different
  // values, so "some namespace of some document type" is a materially
  // weaker statement than the verifier believes it requested.
  if !expected.accepted.iter().any(|(d, n)| *d == doc_type && *n == namespace) {
    return Err(reject());
  }

  Ok(VerifiedAgeProof { issuer_qx, issuer_qy, doc_type, namespace })
}

