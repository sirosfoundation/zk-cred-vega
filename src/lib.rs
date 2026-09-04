//! zk-cred-vega: mdoc selective-disclosure circuits built on top of
//! Microsoft's `vega-prover` ZK engine (https://github.com/microsoft/vega-prover).
//!
//! `vega-prover` supplies the proving system (NeutronNova-folding Spartan
//! over R1CS, no trusted setup) but has zero credential-specific code. This
//! crate supplies the mdoc-shaped circuit and the mobile-facing API on top
//! of it: one `VegaCircuit` "step" per disclosed/checked mdoc element
//! (`ClaimDigestStepCircuit`, this file), verifying its SHA-256 digest and
//! — only when `ClaimWitness::disclose` is set — also exposing the
//! claim's plaintext bytes (masked to all-zero otherwise, see that type's
//! doc), and one "core" circuit (`mdoc_core::MdocCoreCircuit`) proving a
//! real ECDSA-P256 signature over those digests, folded together via
//! `vega_mc_zkp`. A further security-review pass and iOS packaging are
//! still open; see `ffi_api` for the UniFFI-exported surface consumed by
//! the native SDKs.

pub mod cbor_uint;
pub mod digest_id_extract;
pub mod ecdsa;
#[cfg(feature = "uniffi")]
pub mod ffi_api;
pub mod gadget_utils;
pub mod go_ffi;
pub mod mdoc_core;
pub mod mso;
pub mod mso_splice;
pub mod nonnative;
pub mod offset_bind;
pub mod onehot_cursor;
pub mod p256_ecc;
pub mod pid_age;
pub mod sha256_var;

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

use bellpepper_core::{
  ConstraintSystem, SynthesisError,
  boolean::{AllocatedBit, Boolean},
  num::AllocatedNum,
};
use ff::{Field, PrimeFieldBits};
use mdoc_core::MdocCoreCircuit;
use num_bigint::BigInt;
use sha2::{Digest, Sha256};
use std::marker::PhantomData;
use vega_prover::{
  provider::T256HyraxEngine,
  traits::{Engine, circuit::VegaCircuit},
  vega_mc_zkp::{VegaMcProverKey, VegaMcVerifierKey, VegaMcZkSNARK},
};

/// The curve/commitment engine this crate is built against. `T256HyraxEngine`
/// is `vega-prover`'s 2-cycle partner curve for `P256HyraxEngine`, chosen
/// upstream specifically to make in-circuit P-256 (mdoc/MSO's own signature
/// curve) arithmetic efficient — see Phase 2.
pub type Engine_ = T256HyraxEngine;

/// Maximum number of mdoc elements (namespace + value) one circuit instance
/// can check in a single presentation. Fixed per circuit "version", same as
/// Longfellow's own numAttributes-bound circuits — proving/verifying with a
/// different count requires a different `setup()` and a different published
/// artifact (see plan §5). Chosen small for the Phase 1 buildable skeleton;
/// revisit once real presentations are exercised.
pub const MAX_CLAIMS_V1: usize = 4;

/// Maximum real (unpadded) claim byte length this circuit supports —
/// re-exported from [`sha256_var`], the single source of truth for both
/// the buffer width and the max-length arithmetic. Real messages
/// shorter than this are hashed at their *real* length via
/// [`sha256_var::sha256_var`], not zero-padded before hashing — the
/// earlier zero-padding scheme silently could never match a real
/// issuer's `valueDigests` entry for any claim, at any size (see
/// the "real-interop gap" this closed, by referencing the
/// variable-length gadget). Large binary
/// values (portraits, `signature_usual_mark`) still exceed this budget
/// — a v1/v2 scoping limitation, not a bug, same as `MAX_CLAIMS_V1`.
pub const MAX_CLAIM_BYTES_V1: usize = sha256_var::MAX_VAR_MESSAGE_BYTES;

/// Bit width `real_len` is exposed as (`ClaimDigestStepCircuit`'s public
/// value, and `real_len as u8` when building it) — 8 bits covers
/// `0..=255`, comfortably more than `MAX_CLAIM_BYTES_V1`. Compile-time
/// checked below; bump this (and the `as u8` casts) if `MAX_CLAIM_BYTES_V1`
/// ever exceeds 255.
const REAL_LEN_BITS: usize = 8;

/// Length of the per-presentation digest-blinding nonce.
///
/// 23, not 32, and the exact value is load-bearing for performance:
/// `blind_digest_bytes` hashes `digest || nonce`, and SHA-256's padding
/// means a 55-byte message is the largest that still fits a *single*
/// 512-bit block. 32 + 23 = 55; 32 + 32 = 64 spills into a second block
/// and costs a whole extra compression (measured: 44,874 vs 25,589
/// constraints per blinding, and there are eight blindings per
/// presentation -- four in the step circuits, four in the core).
///
/// 23 bytes is still 184 bits of entropy for a value that only needs to
/// be unpredictable and non-repeating across presentations, so this
/// trades nothing security-relevant for ~15% of the whole circuit. Note
/// this is *not* the issuer's `random` salt inside an `IssuerSignedItem`
/// (32 bytes, ISO 18013-5 requires >= 16, part of the signed credential
/// and not ours to choose) -- it is purely this proof system's internal
/// blinding value.
pub const BLIND_NONCE_BYTES: usize = 23;
const _: () = assert!(32 + BLIND_NONCE_BYTES <= 55, "digest||nonce must fit one SHA-256 block");
const _: () = assert!(MAX_CLAIM_BYTES_V1 <= u8::MAX as usize, "MAX_CLAIM_BYTES_V1 must fit in a u8 for REAL_LEN_BITS=8");

/// Errors from this crate's circuit/proving layer.
#[derive(Debug, thiserror::Error)]
pub enum VegaMdocError {
  #[error("expected at most {max} claims, got {got}")]
  TooManyClaims { max: usize, got: usize },
  #[error("claim bytes exceed the fixed {max}-byte circuit width, got {got}")]
  ClaimTooLong { max: usize, got: usize },
  #[error(transparent)]
  Circuit(#[from] SynthesisError),
  #[error(transparent)]
  Vega(#[from] vega_prover::errors::VegaError),
  #[error("failed to generate a fresh digest-blinding nonce: {0}")]
  Rng(getrandom::Error),
}

/// One mdoc element to be digest-checked: the exact bytes that were hashed
/// to produce the corresponding `valueDigests` entry in the MSO (i.e. the
/// CBOR-encoded `IssuerSignedItem`), and whether this element is being
/// disclosed (its plaintext value revealed in `public_values`) or merely
/// proved-consistent (digest checked, value kept private).
#[derive(Clone, Debug)]
pub struct ClaimWitness {
  pub issuer_signed_item_bytes: Vec<u8>,
  pub disclose: bool,
  /// This claim's real, spec-legal (`< 2^31`) `digestID` — see
  /// `cbor_uint`'s module doc. Must genuinely be the `digestID` CBOR-
  /// encoded inside `issuer_signed_item_bytes` at the offset
  /// `digest_id_extract::DIGEST_ID_OFFSET_BYTES` documents — a mismatch
  /// leaves `ClaimDigestStepCircuit`'s own constraints unsatisfied (see
  /// `digest_id_extract`'s doc), and `crate::verify_and_check_binding`
  /// separately cross-checks this value against what the core circuit
  /// witnessed for the same claim.
  pub digest_id: u32,
}

/// Step circuit: computes SHA-256 over one `IssuerSignedItem`'s bytes,
/// always exposing the digest as a public value, and — only when
/// `disclose` is true — also exposing the plaintext bytes themselves
/// (masked to all-zero otherwise). The corresponding
/// `valueDigests[namespace][digestID]` comparison against the exposed
/// digest is the core circuit's job (`MdocCoreCircuit`) — this keeps the
/// expensive per-claim SHA-256 work foldable across steps rather than
/// repeated in the core circuit.
///
/// The `disclosed` flag and masked plaintext are exposed *every* step
/// (never a variable-length/variable-count output) because NeutronNova
/// folds instances of identical R1CS shape — a step's public-value count
/// can't depend on its own witness. Masking (`plaintext_bit = claim_bit
/// AND disclosed`) rather than conditionally omitting bits is what keeps
/// that shape fixed.
///
/// The digest is now computed over the claim's *real* length via
/// [`sha256_var::sha256_var`] — see that module's doc — rather than
/// zero-padded to a fixed width, closing a real interop gap. `real_len` is exposed as a public value alongside the
/// digest for exactly that reason: without it, a verifier can't tell
/// how many of the (fixed-width) plaintext bytes are real content versus
/// padding, and [`crate::verify_and_check_binding`] can't re-derive
/// `SHA-256(plaintext) == digest` for a disclosed claim.
///
/// **Masking only withholds the plaintext, not the digest** — an
/// undisclosed claim's digest is *still* exposed (it must be, to bind
/// against `valueDigests` and to feed the core circuit's signed `z`).
/// This remains a real, separate, and still-open confidentiality/
/// unlinkability concern flagged by an independent review (real ISO
/// 18013-5 salts each element with ≥16 random bytes specifically so its
/// digest can't be dictionary-attacked, and per-credential digests are
/// stable across verifiers regardless of salting) — fixing the
/// real-length gap does not fix this on its own. Don't treat an
/// undisclosed claim's digest as safe to expose to a relying party until
/// that separate gap is closed too.
///
/// Also note: because [`Self::num_challenges`] is `0` and
/// [`Self::synthesize`] is a no-op, `vega-prover` takes its
/// `skip_synthesize` fast path and reads this circuit instance's public
/// IO **directly from [`Self::public_values`]**, not from constraints
/// built during synthesis — `public_values()` and `precommitted()` must
/// therefore agree exactly on count and order by construction, not by
/// any check either side makes. There's no framework-level guard against
/// the two drifting apart; a mismatch surfaces only as an opaque
/// `verify()` failure downstream. See `mdoc_core`'s module doc for the
/// same class of trap (`is_small`).
///
/// Modeled directly on `vega-prover`'s own `benches/sha256_vega_mc_zkp.rs`
/// `Sha256StepCircuit`, using the full-message `sha256` gadget (handles
/// padding/length internally) instead of the single-block compression
/// function, since mdoc elements vary in length.
#[derive(Clone, Debug)]
pub struct ClaimDigestStepCircuit<Eng: Engine> {
  /// Fixed-width buffer (`MAX_CLAIM_BYTES_V1` bytes) — only the first
  /// `real_len` bytes are meaningful; the rest is don't-care filler (see
  /// `sha256_var`'s module doc).
  bytes: Vec<u8>,
  real_len: usize,
  disclose: bool,
  /// The claimed `digestID` for this claim — constrained (via
  /// `digest_id_extract`) to genuinely match the `digestID` field
  /// embedded inside `bytes` itself, and exposed as a public value so
  /// `crate::verify_and_check_binding` can cross-check it against the
  /// core circuit's own `digest_ids` witness. This is the check that
  /// closes the interop gap `mdoc_core::MdocCoreCircuit`'s doc flags:
  /// without it, a prover could witness one `digest_id` to the core
  /// circuit (determining the MSO's byte layout) while a claim's real
  /// bytes embed a different one.
  digest_id: u32,
  /// Per-*presentation* (not per-credential) fresh random blinding value —
  /// see this file's `blind_digest_bytes` doc for why exposing a claim's
  /// raw SHA-256 digest, even when undisclosed, is a real confidentiality/
  /// unlinkability bug this field closes. Generated fresh by [`prove`] on
  /// every call (never reused across presentations of the same
  /// credential) and shared with [`mdoc_core::MdocCoreCircuit`] for the
  /// same presentation — never itself exposed by this circuit (see
  /// `blinded_digest_bits`'s doc for why that's still sound).
  nonce: [u8; BLIND_NONCE_BYTES],
  _p: PhantomData<Eng>,
}

impl<Eng: Engine> ClaimDigestStepCircuit<Eng> {
  /// `bytes` must be exactly `MAX_CLAIM_BYTES_V1` long; `real_len` (<=
  /// `MAX_CLAIM_BYTES_V1`) marks how many of those bytes are the real
  /// claim content.
  pub fn new(bytes: Vec<u8>, real_len: usize, disclose: bool, digest_id: u32, nonce: [u8; BLIND_NONCE_BYTES]) -> Self {
    assert_eq!(bytes.len(), MAX_CLAIM_BYTES_V1, "bytes must be exactly MAX_CLAIM_BYTES_V1 long");
    assert!(real_len <= MAX_CLAIM_BYTES_V1, "real_len exceeds MAX_CLAIM_BYTES_V1");
    Self {
      bytes,
      real_len,
      disclose,
      digest_id,
      nonce,
      _p: PhantomData,
    }
  }

  fn digest_bytes(&self) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&self.bytes[..self.real_len]);
    hasher.finalize().into()
  }

  /// The value actually exposed publicly in place of the raw digest — see
  /// `blind_digest_bytes`'s doc.
  fn blinded_digest_bits(&self) -> Vec<bool> {
    bytes_to_bool_bits(&blind_digest_bytes(&self.digest_bytes(), &self.nonce))
  }
}

/// `SHA-256(digest || nonce)` — see `ClaimDigestStepCircuit::nonce`'s doc.
///
/// **The bug this closes**: `ClaimDigestStepCircuit` previously exposed a
/// claim's raw SHA-256 digest publicly *regardless of `disclose`* (flagged
/// by an independent human reviewer directly against this file's old
/// `public_values`). Real ISO 18013-5 salts each `IssuerSignedItem` with
/// ≥16 random bytes specifically so a *disclosed* digest can't be
/// dictionary-attacked — but an *undisclosed* claim's raw digest, once
/// exposed, is a **stable value across every future presentation of the
/// same credential**: any two relying parties who both see it can trivially
/// confirm "same credential, same undisclosed value" without ever seeing
/// the plaintext, and (worse) a low-entropy field like `age_over_18`
/// (2 possible values) is trivially dictionary-attackable in isolation
/// even *with* salting, once its own digest is singled out and exposed on
/// its own (unlike the combined `z` over every claim at once, which
/// remains a much harder joint search). Blinding with a nonce that's fresh
/// on *every* `prove()` call (never reused across presentations, unlike
/// the credential data itself) makes the exposed value look independently
/// random each time, closing both the per-field dictionary-attack surface
/// and the stable cross-presentation correlation.
///
/// **Why `nonce` itself never needs to be exposed for this to be sound**:
/// the binding check (`verify_and_check_binding`) only ever compares two
/// *already-blinded* values for equality — it never needs to invert the
/// blinding to recover a claimed digest. Two independently-chosen
/// `(digest, nonce)` pairs colliding under SHA-256 is a first-preimage-
/// level break (~2^256), not a mere collision (~2^128), *even* granting a
/// dishonest prover full freedom to pick both halves on each side
/// independently — so equality of the blinded outputs still implies
/// equality of the real digests with overwhelming probability, whether or
/// not `nonce` is ever made public. `MdocCoreCircuit` exposes `nonce`
/// anyway (cheap, and it's uniformly random so doing so leaks nothing) so
/// the disclosed-plaintext defense-in-depth check in
/// `verify_and_check_binding` can still work natively.
pub(crate) fn blind_digest_bytes(digest: &[u8; 32], nonce: &[u8; BLIND_NONCE_BYTES]) -> [u8; 32] {
  let mut hasher = Sha256::new();
  hasher.update(digest);
  hasher.update(nonce);
  hasher.finalize().into()
}

/// Big-endian bit expansion, MSB-first per byte — the plain (non-circuit)
/// counterpart of `mdoc_core::native_bytes_to_bits`, but returning `bool`s
/// rather than field elements (this crate's step-circuit code works in
/// `bool`/`Boolean` up to the point it's packed into a public value, unlike
/// `mdoc_core`'s field-element-native style).
fn bytes_to_bool_bits(bytes: &[u8]) -> Vec<bool> {
  bytes.iter().flat_map(|&byte| (0..8).rev().map(move |i| (byte >> i) & 1 == 1)).collect()
}

impl<Eng: Engine> VegaCircuit<Eng> for ClaimDigestStepCircuit<Eng>
where
  Eng::Scalar: PrimeFieldBits,
{
  fn public_values(&self) -> Result<Vec<Eng::Scalar>, SynthesisError> {
    // Blinded, not the raw digest -- see `blind_digest_bytes`'s doc.
    let mut values: Vec<Eng::Scalar> = self
      .blinded_digest_bits()
      .into_iter()
      .map(|b| if b { Eng::Scalar::ONE } else { Eng::Scalar::ZERO })
      .collect();
    values.push(if self.disclose { Eng::Scalar::ONE } else { Eng::Scalar::ZERO });
    // real_len as REAL_LEN_BITS bits, MSB-first -- but MASKED to zero when
    // the claim isn't disclosed. An undisclosed claim's byte length
    // correlates with its value (a longer name makes a longer item), so
    // with a known `elementIdentifier` set and a fixed-size salt, leaking
    // it narrows the hidden value. Nothing needs it for an undisclosed
    // claim: the blinded digest is what binds, and the length of a
    // *disclosed* claim is evident from the bytes the caller supplies.
    let len_byte = if self.disclose { self.real_len as u8 } else { 0u8 };
    for i in (0..REAL_LEN_BITS).rev() {
      values.push(if (len_byte >> i) & 1 == 1 { Eng::Scalar::ONE } else { Eng::Scalar::ZERO });
    }
    // The claim's plaintext is deliberately NOT a public value any more.
    // The disclosed bytes travel beside the proof and are bound by the
    // blinded digest instead -- see `verify_and_check_binding`. This is
    // the model BBS (`ProofVerify(..., disclosed_messages, ...)`) and
    // Longfellow (`PublicAttribute` fed into the statement) both use, and
    // it drops MAX_CLAIM_BYTES_V1*8 public values per claim slot whether
    // or not anything is actually disclosed.
    // digest_id, 32 bits MSB-first -- must match precommitted()'s
    // digest_id_extract().value_bits exactly (that's the whole point:
    // the exposed value is provably read out of `bytes` itself, not just
    // echoed from this field).
    values.extend(mdoc_core::native_u32_to_bits::<Eng::Scalar>(self.digest_id));
    Ok(values)
  }

  fn shared<CS: ConstraintSystem<Eng::Scalar>>(
    &self,
    _cs: &mut CS,
  ) -> Result<Vec<AllocatedNum<Eng::Scalar>>, SynthesisError> {
    Ok(vec![])
  }

  fn precommitted<CS: ConstraintSystem<Eng::Scalar>>(
    &self,
    cs: &mut CS,
    _shared: &[AllocatedNum<Eng::Scalar>],
  ) -> Result<Vec<AllocatedNum<Eng::Scalar>>, SynthesisError> {
    let input_bits: Vec<Boolean> = self
      .bytes
      .iter()
      .flat_map(|byte| (0..8).rev().map(move |i| (byte >> i) & 1u8 == 1u8))
      .enumerate()
      .map(|(i, b)| {
        AllocatedBit::alloc(cs.namespace(|| format!("claim byte-bit {i}")), Some(b)).map(Boolean::from)
      })
      .collect::<Result<Vec<_>, _>>()?;

    let (digest_bits, msg_active_bits) =
      sha256_var::sha256_var(cs.namespace(|| "sha256_var(issuer_signed_item)"), &input_bits, self.real_len)?;

    // Blind the digest before exposing it -- NEVER inputize digest_bits
    // directly (see `blind_digest_bytes`'s doc for why the raw digest,
    // even for an undisclosed claim, was a real confidentiality/
    // unlinkability bug). Fixed 64-byte input (32-byte digest || 32-byte
    // nonce), so the plain fixed-length `sha256` gadget is used here, not
    // `sha256_var`'s variable-length machinery.
    let nonce_bits: Vec<Boolean> = self
      .nonce
      .iter()
      .flat_map(|byte| (0..8).rev().map(move |i| (byte >> i) & 1u8 == 1u8))
      .enumerate()
      .map(|(i, b)| AllocatedBit::alloc(cs.namespace(|| format!("nonce byte-bit {i}")), Some(b)).map(Boolean::from))
      .collect::<Result<Vec<_>, _>>()?;
    let mut blind_input = digest_bits.clone();
    blind_input.extend(nonce_bits);
    let blinded_digest_bits = bellpepper::gadgets::sha256::sha256(cs.namespace(|| "blind(digest, nonce)"), &blind_input)?;
    mdoc_core::inputize_bits::<Eng::Scalar, CS>(cs, &blinded_digest_bits, "digest")?;

    let disclose_bit = Boolean::from(AllocatedBit::alloc(
      cs.namespace(|| "disclose"),
      Some(self.disclose),
    )?);
    mdoc_core::inputize_bits::<Eng::Scalar, CS>(cs, std::slice::from_ref(&disclose_bit), "disclose")?;

    // real_len as REAL_LEN_BITS bits — allocated directly (not derived
    // from sha256_var's internal one-hot selector, which is private to
    // that module); must match public_values()'s MSB-first order exactly.
    // Masked by `disclose`, matching public_values() -- see there for why
    // an undisclosed claim's length must not leak.
    let real_len_bits: Vec<Boolean> = (0..REAL_LEN_BITS)
      .rev()
      .map(|i| {
        let bit_val = (self.real_len >> i) & 1 == 1;
        AllocatedBit::alloc(cs.namespace(|| format!("real_len bit {i}")), Some(bit_val)).map(Boolean::from)
      })
      .collect::<Result<Vec<_>, _>>()?;
    let masked_real_len_bits: Vec<Boolean> = real_len_bits
      .iter()
      .enumerate()
      .map(|(i, b)| Boolean::and(cs.namespace(|| format!("mask real_len bit {i}")), b, &disclose_bit))
      .collect::<Result<Vec<_>, _>>()?;
    mdoc_core::inputize_bits::<Eng::Scalar, CS>(cs, &masked_real_len_bits, "real_len")?;

    // The plaintext is no longer inputized at all (see public_values()),
    // so `msg_active_bits` -- which only existed to mask it -- is unused.
    let _ = msg_active_bits;

    // Extract digest_id directly from the claim's own bytes and expose
    // it -- see this struct's `digest_id` field doc for why this is the
    // check that closes the interop gap. `extract_digest_id` constrains
    // the window at DIGEST_ID_OFFSET_BYTES to genuinely encode
    // `self.digest_id`; `value_bits` is what gets exposed.
    let extracted = digest_id_extract::extract_digest_id(
      cs.namespace(|| "digest_id_extract"),
      &input_bits,
      digest_id_extract::DIGEST_ID_OFFSET_BYTES,
      self.digest_id,
    )?;
    mdoc_core::inputize_bits::<Eng::Scalar, CS>(cs, &extracted.value_bits, "digest_id")?;

    Ok(vec![])
  }

  fn num_challenges(&self) -> usize {
    0
  }

  fn synthesize<CS: ConstraintSystem<Eng::Scalar>>(
    &self,
    _cs: &mut CS,
    _shared: &[AllocatedNum<Eng::Scalar>],
    _precommitted: &[AllocatedNum<Eng::Scalar>],
    _challenges: Option<&[Eng::Scalar]>,
  ) -> Result<(), SynthesisError> {
    Ok(())
  }
}

/// The ECDSA-P256 signature + issuer-key half of a presentation's witness
/// (see `mdoc_core::MdocCoreCircuit`) — everything the core circuit needs
/// beyond the per-claim digests already carried by `ClaimWitness`.
#[derive(Clone, Debug)]
pub struct MdocEcdsaWitness {
  pub qx: <Engine_ as Engine>::Scalar,
  pub qy: <Engine_ as Engine>::Scalar,
  pub r: BigInt,
  pub s: BigInt,
  pub s_inv: BigInt,
}

/// A real, valid P-256 ECDSA signature over the real MSO `Sig_structure`
/// (`crate::mso`) for setup's own all-zero `claim_digests` prototype and
/// [`setup_prototype_mso_body`] below — i.e. genuinely satisfying the
/// ECDSA relation for exactly the `z` that
/// `MdocCoreCircuit::native_z_bytes` computes for that prototype —
/// generated once via RustCrypto's `p256` crate and frozen here as
/// constants. Used only as [`setup`]'s prototype circuit witness.
///
/// Genuinely satisfying the relation (not just "non-degenerate") matters:
/// an internally-inconsistent prototype (valid-looking scalars that don't
/// actually satisfy the signed relation) was tried first and produced a
/// setup whose real proofs failed PCS verification (`InvalidPCS: Inner
/// product argument verify: First equation failed`) despite the same
/// proofs' own R1CS constraints being individually satisfied — i.e. an
/// unsatisfiable *prototype* witness can still poison the derived prover
/// key in a way that doesn't surface until a real `verify()` call, not at
/// `setup()` itself. Don't assume "any non-degenerate values work here"
/// without a real round-trip test backing it, per this crate's own
/// `full_presentation_verifies_and_binds` test.
fn setup_prototype_ecdsa_witness() -> MdocEcdsaWitness {
  use crate::nonnative::util::nat_to_f;
  let parse = |s: &str| s.parse::<BigInt>().expect("valid decimal constant");
  MdocEcdsaWitness {
    qx: nat_to_f(&parse(
      "51206722373641483558790322998827362250192835690568432297698399643535245670501",
    ))
    .unwrap(),
    qy: nat_to_f(&parse(
      "107332639522564059748513735225121084070027309383763098932131650999881938986788",
    ))
    .unwrap(),
    r: parse("111142013211556514970479643709817588854004335857781381385833107319892960023198"),
    s: parse("76862587808802066344087557197401376424252937358072577297572652819487433674663"),
    s_inv: parse(
      "78445439557468585260457937215718822506055505801566399563185238095534357761252",
    ),
  }
}

/// The (fixed, arbitrary) MSO body data [`setup_prototype_ecdsa_witness`]'s
/// signature was actually computed over — see that function's doc for why
/// this must genuinely match, not just be "non-degenerate".
fn setup_prototype_mso_body() -> crate::mso::MsoBodyWitness {
  crate::mso::MsoBodyWitness {
    device_x: [0u8; 32],
    device_y: [0u8; 32],
    signed_ts: *b"2026-08-20T00:00:00Z",
    valid_from_ts: *b"2026-08-20T00:00:00Z",
    valid_until_ts: *b"2036-08-20T00:00:00Z",
  }
}

/// Prover/verifier keys for a fixed `MAX_CLAIMS_V1`-step circuit, produced
/// once by [`setup`] and published to `go-zk-circuits` per plan §5.
pub struct VegaMdocKeys {
  pub pk: VegaMcProverKey<Engine_>,
  pub vk: VegaMcVerifierKey<Engine_>,
}

/// Runs `VegaMcZkSNARK::setup` for the fixed claim-count circuit shape.
pub fn setup() -> Result<VegaMdocKeys, VegaMdocError> {
  // Fixed, not `fresh_nonce()` -- setup() is deliberately fully
  // deterministic (see `setup_prototype_ecdsa_witness`'s doc): the nonce
  // only affects circuit *witness values*, never the circuit *shape*
  // `setup()` derives keys from, so any fixed value works here, and using
  // one keeps that determinism property intact (real `go-zk-circuits`
  // published keys must be reproducible from source, not seeded by an RNG
  // at build time).
  let proto_nonce = [0u8; BLIND_NONCE_BYTES];
  let step_proto = ClaimDigestStepCircuit::<Engine_>::new(vec![0u8; MAX_CLAIM_BYTES_V1], 0, false, 0, proto_nonce);
  let w = setup_prototype_ecdsa_witness();
  let core_proto = MdocCoreCircuit::<Engine_>::new(
    w.qx,
    w.qy,
    w.r,
    w.s,
    w.s_inv,
    [0u32; MAX_CLAIMS_V1],
    vec![[0u8; 32]; MAX_CLAIMS_V1],
    setup_prototype_mso_body(),
    proto_nonce,
  );
  let (pk, vk) = VegaMcZkSNARK::<Engine_>::setup(&step_proto, &core_proto, MAX_CLAIMS_V1)?;
  Ok(VegaMdocKeys { pk, vk })
}

/// SHA-256 of `bytes`, as a `[u8; 32]` — the same digest a
/// [`ClaimDigestStepCircuit`] over the same bytes exposes (bit-for-bit,
/// modulo the bits-vs-bytes representation), used to build the core
/// circuit's `claim_digests` witness so the two actually agree.
fn claim_digest_bytes(bytes: &[u8]) -> [u8; 32] {
  let mut hasher = Sha256::new();
  hasher.update(bytes);
  hasher.finalize().into()
}

/// A [`ClaimWitness`] widened to the circuit's fixed `MAX_CLAIM_BYTES_V1`
/// buffer width, with its real (unpadded) length carried alongside —
/// `bytes[..real_len]` is the real claim content; `bytes[real_len..]` is
/// don't-care filler (see `sha256_var`'s module doc for why zero-filling
/// it is a convenience, not a requirement).
struct PaddedClaim {
  bytes: Vec<u8>,
  real_len: usize,
  disclose: bool,
  digest_id: u32,
}

/// Widens `bytes` to exactly `MAX_CLAIM_BYTES_V1` bytes (fixed circuit
/// width), returning the padded buffer and the real length; errors if
/// `bytes` is already longer than that.
fn fixed_width_claim_bytes(bytes: &[u8]) -> Result<(Vec<u8>, usize), VegaMdocError> {
  if bytes.len() > MAX_CLAIM_BYTES_V1 {
    return Err(VegaMdocError::ClaimTooLong {
      max: MAX_CLAIM_BYTES_V1,
      got: bytes.len(),
    });
  }
  let real_len = bytes.len();
  let mut padded = bytes.to_vec();
  padded.resize(MAX_CLAIM_BYTES_V1, 0u8);
  Ok((padded, real_len))
}

fn pad_claims(claims: &[ClaimWitness]) -> Result<Vec<PaddedClaim>, VegaMdocError> {
  if claims.len() > MAX_CLAIMS_V1 {
    return Err(VegaMdocError::TooManyClaims {
      max: MAX_CLAIMS_V1,
      got: claims.len(),
    });
  }
  let mut padded = claims
    .iter()
    .map(|c| {
      let (bytes, real_len) = fixed_width_claim_bytes(&c.issuer_signed_item_bytes)?;
      Ok(PaddedClaim {
        bytes,
        real_len,
        disclose: c.disclose,
        digest_id: c.digest_id,
      })
    })
    .collect::<Result<Vec<_>, VegaMdocError>>()?;
  while padded.len() < MAX_CLAIMS_V1 {
    padded.push(PaddedClaim {
      bytes: vec![0u8; MAX_CLAIM_BYTES_V1],
      real_len: 0,
      disclose: false,
      digest_id: 0,
    });
  }
  Ok(padded)
}

/// Builds the core circuit's `digest_ids` witness from a (pre-padding)
/// claim set, in the same padded order [`core_claim_digests`] uses — the
/// two must agree for [`verify_and_check_binding`] to pass.
pub(crate) fn core_digest_ids(claims: &[ClaimWitness]) -> Result<[u32; MAX_CLAIMS_V1], VegaMdocError> {
  let padded = pad_claims(claims)?;
  Ok(std::array::from_fn(|i| padded[i].digest_id))
}

/// Opaque prep state — the rerandomizable, per-credential cache that
/// `prove` reuses across presentations to different verifiers. This is
/// exactly what flows through `ZkProofSystem.priorState`/`nextState` at the
/// SDK layer (plan §Phase 3/6): serialize this out, hand it back in on the
/// next call for the same credential, and `prep_prove` is skipped.
pub struct VegaMdocPrepState(vega_prover::vega_mc_zkp::VegaMcPrepZkSNARK<Engine_>);

impl VegaMdocPrepState {
  /// Unwraps to the inner `vega-prover` type — used by `ffi_api` to
  /// (de)serialize the prep state to bytes for `ZkProofSystem`'s
  /// `priorState`/`nextState` fields.
  pub fn into_inner(self) -> vega_prover::vega_mc_zkp::VegaMcPrepZkSNARK<Engine_> {
    self.0
  }

  /// See [`Self::into_inner`].
  pub fn from_inner(inner: vega_prover::vega_mc_zkp::VegaMcPrepZkSNARK<Engine_>) -> Self {
    Self(inner)
  }
}

/// Builds the core circuit's `claim_digests` witness from a (pre-padding)
/// claim set, in the same padded order `prep_prove`/`prove` use for the
/// step circuits — the two must agree for `verify_and_check_binding` to
/// pass.
pub(crate) fn core_claim_digests(claims: &[ClaimWitness]) -> Result<Vec<[u8; 32]>, VegaMdocError> {
  let padded = pad_claims(claims)?;
  Ok(
    padded
      .iter()
      .map(|c| claim_digest_bytes(&c.bytes[..c.real_len]))
      .collect(),
  )
}

/// Fresh 32 bytes of OS randomness for a presentation's digest blinding —
/// see `blind_digest_bytes`'s doc. Callers mint one of these per
/// `prep_prove` call and must pass the SAME value into every `prove` call
/// against the resulting (and any later fold-and-reused) prep state —
/// `vega_mc_zkp` requires a step circuit's public values to stay identical
/// between `prep_prove` and every `prove` call that reuses that prep chain
/// (confirmed empirically: a differing nonce there fails with "Step
/// circuit N public values changed between prep_prove and prove"), so the
/// nonce is necessarily fixed for the lifetime of one prep chain, not
/// freshenable on every individual `prove` call the way it ideally would
/// be. **This is a real, currently-latent limitation**: today
/// `SirosWallet.kt` always calls `prep_prove` fresh per presentation (never
/// threads `priorState`/`nextState`), so every real presentation still gets
/// a genuinely fresh nonce — but if/when that fold-and-reuse optimization
/// is ever wired up, every presentation reusing the same prep chain would
/// share one nonce (and therefore one set of blinded digests), reopening
/// the cross-presentation correlation this fix closes. Revisit before
/// wiring up `priorState` reuse for real.
pub fn fresh_nonce() -> Result<[u8; BLIND_NONCE_BYTES], VegaMdocError> {
  let mut nonce = [0u8; BLIND_NONCE_BYTES];
  getrandom::getrandom(&mut nonce).map_err(VegaMdocError::Rng)?;
  Ok(nonce)
}

/// Runs `prep_prove` once for a given credential's claim set and ECDSA
/// witness. `mso_body` is the per-credential MSO data (device key,
/// validity timestamps) that isn't otherwise carried by `claims` or
/// `ecdsa_witness` — see `crate::mso`. `nonce` should be a fresh
/// [`fresh_nonce`] — see that function's doc for why the SAME value must
/// also be passed to every `prove` call against the state this returns.
pub fn prep_prove(
  pk: &VegaMcProverKey<Engine_>,
  claims: &[ClaimWitness],
  ecdsa_witness: &MdocEcdsaWitness,
  mso_body: &crate::mso::MsoBodyWitness,
  nonce: &[u8; BLIND_NONCE_BYTES],
) -> Result<VegaMdocPrepState, VegaMdocError> {
  let padded = pad_claims(claims)?;
  let step_circuits: Vec<ClaimDigestStepCircuit<Engine_>> = padded
    .iter()
    .map(|c| ClaimDigestStepCircuit::new(c.bytes.clone(), c.real_len, c.disclose, c.digest_id, *nonce))
    .collect();
  let core_circuit = MdocCoreCircuit::<Engine_>::new(
    ecdsa_witness.qx,
    ecdsa_witness.qy,
    ecdsa_witness.r.clone(),
    ecdsa_witness.s.clone(),
    ecdsa_witness.s_inv.clone(),
    core_digest_ids(claims)?,
    core_claim_digests(claims)?,
    mso_body.clone(),
    *nonce,
  );
  let prep = VegaMcZkSNARK::<Engine_>::prep_prove(pk, &step_circuits, &core_circuit, false)?;
  Ok(VegaMdocPrepState(prep))
}

/// Produces a proof, consuming and rerandomizing the prep state so it can
/// be reused for the next presentation of the same credential. `nonce`
/// MUST be the exact same value passed to the `prep_prove` call that
/// (possibly transitively, via earlier `prove` calls' `next_prep`)
/// produced `prep` — see [`fresh_nonce`]'s doc for why.
pub fn prove(
  pk: &VegaMcProverKey<Engine_>,
  claims: &[ClaimWitness],
  ecdsa_witness: &MdocEcdsaWitness,
  mso_body: &crate::mso::MsoBodyWitness,
  prep: VegaMdocPrepState,
  nonce: &[u8; BLIND_NONCE_BYTES],
) -> Result<(VegaMcZkSNARK<Engine_>, VegaMdocPrepState), VegaMdocError> {
  let padded = pad_claims(claims)?;
  let step_circuits: Vec<ClaimDigestStepCircuit<Engine_>> = padded
    .iter()
    .map(|c| ClaimDigestStepCircuit::new(c.bytes.clone(), c.real_len, c.disclose, c.digest_id, *nonce))
    .collect();
  let core_circuit = MdocCoreCircuit::<Engine_>::new(
    ecdsa_witness.qx,
    ecdsa_witness.qy,
    ecdsa_witness.r.clone(),
    ecdsa_witness.s.clone(),
    ecdsa_witness.s_inv.clone(),
    core_digest_ids(claims)?,
    core_claim_digests(claims)?,
    mso_body.clone(),
    *nonce,
  );
  let (proof, next_prep) =
    VegaMcZkSNARK::<Engine_>::prove(pk, &step_circuits, &core_circuit, prep.0, false)?;
  Ok((proof, VegaMdocPrepState(next_prep)))
}

/// Per-step public values, and the core circuit's public values.
pub type VerifiedPublicValues = (Vec<Vec<<Engine_ as Engine>::Scalar>>, Vec<<Engine_ as Engine>::Scalar>);

/// Verifies a proof against the fixed `MAX_CLAIMS_V1` step count.
pub fn verify(
  proof: &VegaMcZkSNARK<Engine_>,
  vk: &VegaMcVerifierKey<Engine_>,
) -> Result<VerifiedPublicValues, VegaMdocError> {
  Ok(proof.verify(vk, MAX_CLAIMS_V1)?)
}

/// Every public value this circuit ever inputizes is a `{0,1}`-constrained
/// bit (see `mdoc_core::inputize_bits`) — a genuinely-satisfied proof can
/// never expose anything else. `bits_to_bytes` below otherwise silently
/// treats any non-`ONE` value as `0`, so callers should check this first
/// rather than let a stray field element pass through unnoticed.
fn all_boolean(values: &[<Engine_ as Engine>::Scalar]) -> bool {
  values
    .iter()
    .all(|&v| v == <Engine_ as Engine>::Scalar::ONE || v == <Engine_ as Engine>::Scalar::ZERO)
}

/// Packs a public-value bit slice (each entry `Scalar::ONE`/`ZERO`,
/// big-endian, 8 per byte) back into bytes — the inverse of
/// `mdoc_core::native_bytes_to_bits`.
fn bits_to_bytes(bits: &[<Engine_ as Engine>::Scalar]) -> Vec<u8> {
  bits
    .chunks(8)
    .map(|byte_bits| {
      byte_bits.iter().enumerate().fold(0u8, |byte, (i, bit)| {
        if *bit == <Engine_ as Engine>::Scalar::ONE {
          byte | (1 << (7 - i))
        } else {
          byte
        }
      })
    })
    .collect()
}

/// One claim slot's verified disclosure outcome: whether it was disclosed,
/// its real (unpadded) byte length, and its plaintext `IssuerSignedItem`
/// bytes — always exactly `real_len` bytes long, meaningful only when
/// `disclosed` (all-zero otherwise, see `ClaimDigestStepCircuit`'s doc for
/// why it's masked rather than simply absent). `real_len` itself is
/// exposed regardless of `disclosed`.
///
/// `digest` is **only ever meaningful when `disclosed` is true** (and even
/// then it's redundant — any caller with `plaintext` can derive it
/// themselves): `[0u8; 32]` otherwise, same masking convention as
/// `plaintext`. This crate used to always populate it with the claim's
/// real SHA-256 digest regardless of disclosure — a real confidentiality/
/// unlinkability bug (see `blind_digest_bytes`'s doc) fixed by never
/// exposing (or, therefore, ever learning) an undisclosed claim's real
/// digest anywhere in this crate anymore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisclosedClaim {
  pub disclosed: bool,
  pub digest: [u8; 32],
  pub real_len: usize,
  pub plaintext: Vec<u8>,
  /// This claim's `digestID`, as exposed by the core circuit — see
  /// `mdoc_core::MdocCoreCircuit`'s doc for what this binding does and
  /// doesn't yet prove.
  pub digest_id: u32,
}

/// The fully verified, bound public output of a presentation — everything
/// [`verify_and_check_binding`] extracted from `verify`'s two return
/// values after confirming they're genuinely bound together.
#[derive(Debug, Clone)]
pub struct VerifiedPresentation {
  pub qx: <Engine_ as Engine>::Scalar,
  pub qy: <Engine_ as Engine>::Scalar,
  pub claims: Vec<DisclosedClaim>,
  pub device_x: [u8; 32],
  pub device_y: [u8; 32],
  pub signed_ts: [u8; mso::TIMESTAMP_LEN],
  pub valid_from_ts: [u8; mso::TIMESTAMP_LEN],
  pub valid_until_ts: [u8; mso::TIMESTAMP_LEN],
}

/// The step<->core binding check `mdoc_core`'s module doc describes: given
/// `verify`'s two outputs, confirms — for every claim slot — that the step
/// circuit's own blinded digest equals the core circuit's own blinded
/// digest for that same slot (both `SHA-256(digest || nonce)`, `nonce`
/// read from the core circuit's public output; see
/// `blind_digest_bytes`'s doc for why comparing only the *blinded* values,
/// never the raw digests, is still sound). This is the check that gives
/// "the ECDSA signature core proved is valid" and "these are the digests
/// step proved" any actual connection to each other — without it, a
/// prover could mix a valid core proof for one claim set with valid step
/// proofs for a *different* one. (An earlier version of this function
/// instead reconstructed the real MSO `Sig_structure` from the step
/// circuits' *raw* exposed digests and compared its hash against the
/// core's exposed `z` — that raw exposure was the actual bug being fixed
/// here; `z` and the real per-claim digests are no longer public at all,
/// so that reconstruction is no longer possible or needed.) Returns
/// everything a caller needs on success: `Q` (for trust-anchor checking),
/// each claim's disclosed plaintext (or just its digest, if undisclosed),
/// and the MSO-body fields (for expiry/device-binding checks) — see
/// `VerifiedPresentation`.
/// `disclosed_bytes[i]` must carry the real `IssuerSignedItem` bytes for
/// every claim slot the proof reports as disclosed, and `None` for every
/// slot it doesn't. Those bytes are no longer public values of the proof
/// (see `ClaimDigestStepCircuit::public_values`): they travel beside it
/// and are bound here, by checking `blind(SHA-256(bytes), nonce)` against
/// the blinded digest the circuit did expose. This is the same shape as
/// BBS's `ProofVerify(..., disclosed_messages, ...)` and Longfellow's
/// `PublicAttribute` statement inputs.
///
/// A caller that supplied attacker-chosen bytes would need a SHA-256
/// collision for this to pass, so the binding is unchanged -- but note
/// the check is now *this function's* job rather than something the
/// proof's public IO carries on its own. Callers must not skip it; the
/// FFI layer deliberately does not expose the raw scalars for this
/// reason (see `ffi_api`'s module doc).
pub fn verify_and_check_binding(
  step_public_values: &[Vec<<Engine_ as Engine>::Scalar>],
  core_public_values: &[<Engine_ as Engine>::Scalar],
  disclosed_bytes: &[Option<Vec<u8>>],
) -> Result<VerifiedPresentation, VegaMdocError> {
  if disclosed_bytes.len() != MAX_CLAIMS_V1 {
    return Err(VegaMdocError::Circuit(SynthesisError::Unsatisfiable));
  }
  // qx, qy, nonce(BLIND_NONCE_BYTES*8), device_x(256), device_y(256), signed_ts,
  // valid_from_ts, valid_until_ts (each mso::TIMESTAMP_LEN*8 bits), then
  // MAX_CLAIMS_V1 digestIDs (32 bits each), then MAX_CLAIMS_V1 blinded
  // per-claim digests (256 bits each) — must match
  // MdocCoreCircuit::public_values's exact order.
  const TS_BITS: usize = mso::TIMESTAMP_LEN * 8;
  const EXPECTED_LEN: usize = 2
    + BLIND_NONCE_BYTES * 8
    + 256
    + 256
    + TS_BITS
    + TS_BITS
    + TS_BITS
    + MAX_CLAIMS_V1 * 32
    + MAX_CLAIMS_V1 * 256;
  if core_public_values.len() != EXPECTED_LEN {
    return Err(VegaMdocError::Circuit(SynthesisError::Unsatisfiable));
  }
  // Only core_public_values[2..] are bits (qx/qy at [0]/[1] are the raw
  // P-256 coordinate field elements, not booleans).
  if !all_boolean(&core_public_values[2..]) {
    // Every bit-valued core public value really is a bit (see
    // mdoc_core's inputize_bits) — a genuinely-satisfied proof can never
    // produce anything else. Defence in depth: don't let bits_to_bytes
    // below silently coerce a stray non-{0,1} value to 0.
    return Err(VegaMdocError::Circuit(SynthesisError::Unsatisfiable));
  }
  let qx = core_public_values[0];
  let qy = core_public_values[1];
  let mut cursor = 2;
  let mut take = |len: usize| {
    let slice = &core_public_values[cursor..cursor + len];
    cursor += len;
    slice
  };
  let nonce: [u8; BLIND_NONCE_BYTES] =
    bits_to_bytes(take(BLIND_NONCE_BYTES * 8)).try_into().unwrap();
  let device_x: [u8; 32] = bits_to_bytes(take(256)).try_into().unwrap();
  let device_y: [u8; 32] = bits_to_bytes(take(256)).try_into().unwrap();
  let signed_ts: [u8; mso::TIMESTAMP_LEN] = bits_to_bytes(take(TS_BITS)).try_into().unwrap();
  let valid_from_ts: [u8; mso::TIMESTAMP_LEN] = bits_to_bytes(take(TS_BITS)).try_into().unwrap();
  let valid_until_ts: [u8; mso::TIMESTAMP_LEN] = bits_to_bytes(take(TS_BITS)).try_into().unwrap();
  let digest_ids: [u32; MAX_CLAIMS_V1] = std::array::from_fn(|_| {
    let bytes = bits_to_bytes(take(32));
    u32::from_be_bytes(bytes.try_into().unwrap())
  });
  let core_blinded_digests: [[u8; 32]; MAX_CLAIMS_V1] =
    std::array::from_fn(|_| bits_to_bytes(take(256)).try_into().unwrap());

  if step_public_values.len() != MAX_CLAIMS_V1 {
    return Err(VegaMdocError::Circuit(SynthesisError::Unsatisfiable));
  }
  // blinded_digest(256) + disclosed flag(1) + masked real_len(REAL_LEN_BITS)
  // + digest_id(32) per step — must match
  // ClaimDigestStepCircuit::public_values's exact order. The plaintext is
  // no longer here; see this function's doc.
  const STEP_LEN: usize = 256 + 1 + REAL_LEN_BITS + 32;
  let mut claims: Vec<DisclosedClaim> = Vec::with_capacity(step_public_values.len());
  for v in step_public_values {
    if v.len() != STEP_LEN {
      // A malformed/attacker-controlled proof could carry a step public
      // value vector of the wrong length — reject it instead of letting
      // the try_into below panic (a process abort across the UniFFI
      // boundary, not a rejected proof).
      return Err(VegaMdocError::Circuit(SynthesisError::Unsatisfiable));
    }
    if !all_boolean(v) {
      // Same defence-in-depth as above, for the digest/plaintext bits.
      return Err(VegaMdocError::Circuit(SynthesisError::Unsatisfiable));
    }
    let blinded_digest_bits = &v[0..256];
    let disclosed_scalar = v[256];
    let real_len_bits = &v[257..257 + REAL_LEN_BITS];
    let step_digest_id_bits = &v[257 + REAL_LEN_BITS..STEP_LEN];

    let step_blinded_digest: [u8; 32] = bits_to_bytes(blinded_digest_bits)
      .try_into()
      .map_err(|_| VegaMdocError::Circuit(SynthesisError::Unsatisfiable))?;
    let disclosed = disclosed_scalar == <Engine_ as Engine>::Scalar::ONE;
    let real_len = bits_to_bytes(real_len_bits)[0] as usize;
    if real_len > MAX_CLAIM_BYTES_V1 {
      // Can't happen for a genuinely-satisfied proof (real_len is only
      // ever built from a value <= MAX_CLAIM_BYTES_V1 — see
      // ClaimDigestStepCircuit::new's own assertion) — reject rather
      // than let the slice below panic.
      return Err(VegaMdocError::Circuit(SynthesisError::Unsatisfiable));
    }
    let step_digest_id_bytes = bits_to_bytes(step_digest_id_bits);
    let step_digest_id = u32::from_be_bytes(
      step_digest_id_bytes
        .try_into()
        .map_err(|_| VegaMdocError::Circuit(SynthesisError::Unsatisfiable))?,
    );

    // Free extra guard (found valuable by an independent review): for a
    // disclosed claim, the revealed plaintext is provably the blinded
    // SHA-256 preimage of `blinded_digest` by construction of the masking
    // circuit (`ClaimDigestStepCircuit`'s doc) — but re-deriving it here,
    // rather than trusting that invariant blindly, catches any future bug
    // where the two public-value groups silently diverge. Only possible
    // for disclosed claims: an undisclosed claim's real digest is, by
    // design, never learned by this function at all anymore.
    // The bytes now arrive from the caller rather than from the proof, so
    // this check is what binds them. A disclosed slot MUST have bytes and
    // an undisclosed slot MUST NOT -- a mismatch either way is a caller
    // error and is rejected rather than papered over.
    let supplied = &disclosed_bytes[claims.len()];
    let (digest, plaintext) = match (disclosed, supplied) {
      (true, Some(bytes)) => {
        let real_digest = claim_digest_bytes(bytes);
        if blind_digest_bytes(&real_digest, &nonce) != step_blinded_digest {
          return Err(VegaMdocError::Circuit(SynthesisError::Unsatisfiable));
        }
        // Free cross-check now that real_len is exposed only for disclosed
        // claims: the circuit's own view of the length must match the
        // bytes we were handed.
        if bytes.len() != real_len {
          return Err(VegaMdocError::Circuit(SynthesisError::Unsatisfiable));
        }
        (real_digest, bytes.clone())
      }
      (false, None) => ([0u8; 32], Vec::new()),
      _ => return Err(VegaMdocError::Circuit(SynthesisError::Unsatisfiable)),
    };

    // The binding check this whole field exists for: the step circuit's
    // own blinded digest must equal the core circuit's own blinded digest
    // for the same claim slot — see this function's own doc. Without it,
    // a prover could witness one set of claim digests to the core circuit
    // (determining the MSO's byte layout it signs) while the step
    // circuits prove a *different* set.
    if step_blinded_digest != core_blinded_digests[claims.len()] {
      return Err(VegaMdocError::Circuit(SynthesisError::Unsatisfiable));
    }

    // Same reasoning as the digest cross-check above, for digestID: the
    // step circuit's own digest_id (provably extracted from this claim's
    // real bytes — see ClaimDigestStepCircuit's doc) must equal what the
    // core circuit witnessed for the same claim slot.
    if step_digest_id != digest_ids[claims.len()] {
      return Err(VegaMdocError::Circuit(SynthesisError::Unsatisfiable));
    }

    claims.push(DisclosedClaim {
      disclosed,
      digest,
      real_len,
      plaintext,
      digest_id: step_digest_id,
    });
  }

  Ok(VerifiedPresentation {
    qx,
    qy,
    claims,
    device_x,
    device_y,
    signed_ts,
    valid_from_ts,
    valid_until_ts,
  })
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::nonnative::util::nat_to_f;
  use crate::p256_ecc::p256_order;
  use num_bigint::Sign;
  use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey, VerifyingKey};

  /// The disclosed-bytes argument `verify_and_check_binding` now takes:
  /// the real bytes for every slot the witness marks disclosed, `None`
  /// elsewhere. Mirrors what a real caller sends beside the proof.
  fn disclosed_for(claims: &[ClaimWitness]) -> Vec<Option<Vec<u8>>> {
    let padded = pad_claims(claims).expect("pad_claims");
    padded
      .iter()
      .map(|c| if c.disclose { Some(c.bytes[..c.real_len].to_vec()) } else { None })
      .collect()
  }

  fn test_mso_body() -> crate::mso::MsoBodyWitness {
    crate::mso::MsoBodyWitness {
      device_x: [0x11u8; 32],
      device_y: [0x22u8; 32],
      signed_ts: *b"2026-08-20T00:00:00Z",
      valid_from_ts: *b"2026-08-20T00:00:00Z",
      valid_until_ts: *b"2036-08-20T00:00:00Z",
    }
  }

  /// Builds claim bytes with `digest_id` genuinely CBOR-encoded at
  /// `digest_id_extract::DIGEST_ID_OFFSET_BYTES` (arbitrary filler before,
  /// `marker` after) -- since `ClaimDigestStepCircuit::precommitted` now
  /// constrains exactly that window (see its doc), any test that calls
  /// `precommitted`/goes through a real proof needs bytes shaped like
  /// this, not a bare string. `marker` keeps otherwise-identical claims
  /// distinguishable (different digests) in tests with multiple claims.
  fn claim_bytes_with_digest_id(digest_id: u32, marker: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0xAAu8; digest_id_extract::DIGEST_ID_OFFSET_BYTES];
    bytes.extend(cbor_uint::encode_cbor_uint(digest_id));
    bytes.extend_from_slice(marker);
    bytes
  }

  /// Signs the real MSO `Sig_structure` (`crate::mso`) over
  /// `claim_digests` and [`test_mso_body`] — matching
  /// `MdocCoreCircuit`'s own `native_z_bytes` exactly — with a fresh real
  /// P-256 key, and returns the resulting `MdocEcdsaWitness`.
  fn real_ecdsa_witness_over(digest_ids: &[u32; MAX_CLAIMS_V1], claim_digests: &[[u8; 32]]) -> MdocEcdsaWitness {
    let signing_key = SigningKey::from_bytes(&[42u8; 32].into()).expect("valid scalar");
    let verifying_key = VerifyingKey::from(&signing_key);

    let sig_structure = crate::mso::native_sig_structure_bytes(digest_ids, claim_digests, &test_mso_body());
    let z_bytes: [u8; 32] = Sha256::digest(&sig_structure).into();

    let signature: Signature = signing_key.sign_prehash(&z_bytes).expect("sign_prehash");
    let r = BigInt::from_bytes_be(Sign::Plus, &signature.r().to_bytes());
    let s = BigInt::from_bytes_be(Sign::Plus, &signature.s().to_bytes());

    let n = p256_order();
    let s_inv = s.modpow(&(n.clone() - BigInt::from(2)), &n);

    let encoded = verifying_key.to_encoded_point(false);
    let qx = BigInt::from_bytes_be(Sign::Plus, encoded.x().expect("uncompressed x"));
    let qy = BigInt::from_bytes_be(Sign::Plus, encoded.y().expect("uncompressed y"));

    MdocEcdsaWitness {
      qx: nat_to_f(&qx).unwrap(),
      qy: nat_to_f(&qy).unwrap(),
      r,
      s,
      s_inv,
    }
  }

  /// Direct, fast check of `ClaimDigestStepCircuit::public_values`'s
  /// shape and slice boundaries — independent of any real proof, so it
  /// catches a regression here without waiting on a full setup/prove/
  /// verify round trip. This is exactly the invariant the type's own doc
  /// flags as framework-enforced only by convention (the `skip_synthesize`
  /// fast path reads public IO straight from this function).
  #[test]
  fn claim_digest_step_circuit_public_values_has_the_expected_shape() {
    let real_bytes = b"family_name:Doe";
    let (bytes, real_len) = fixed_width_claim_bytes(real_bytes).expect("fits");
    // This test only calls public_values() (a plain, deterministic
    // function of `self.digest_id`), never precommitted() -- so this
    // digest_id doesn't need to genuinely appear in `real_bytes`'s own
    // CBOR framing (unlike the full-pipeline tests below, which do).
    let digest_id = 42u32;
    let nonce = [0x99u8; crate::BLIND_NONCE_BYTES];
    let disclosed = ClaimDigestStepCircuit::<Engine_>::new(bytes.clone(), real_len, true, digest_id, nonce)
      .public_values()
      .expect("public_values");
    let undisclosed = ClaimDigestStepCircuit::<Engine_>::new(bytes.clone(), real_len, false, digest_id, nonce)
      .public_values()
      .expect("public_values");

    const STEP_LEN: usize = 256 + 1 + REAL_LEN_BITS + 32;
    assert_eq!(disclosed.len(), STEP_LEN);
    assert_eq!(undisclosed.len(), STEP_LEN);

    // Position 0..256 holds the *blinded* digest (see `blind_digest_bytes`'s
    // doc) -- never the raw one, regardless of disclosure.
    let digest = claim_digest_bytes(real_bytes);
    let blinded_digest = blind_digest_bytes(&digest, &nonce);
    assert_eq!(
      bits_to_bytes(&disclosed[0..256]),
      blinded_digest,
      "disclosed[0..256] must be the claim's BLINDED digest (of the REAL bytes, not the padded buffer)"
    );
    assert_eq!(
      bits_to_bytes(&undisclosed[0..256]),
      blinded_digest,
      "the blinded digest slot must be exposed regardless of disclosure"
    );
    assert_eq!(disclosed[256], <Engine_ as Engine>::Scalar::ONE);
    assert_eq!(undisclosed[256], <Engine_ as Engine>::Scalar::ZERO);

    // real_len is exposed for a disclosed claim and MASKED TO ZERO for an
    // undisclosed one -- an undisclosed claim's length correlates with its
    // value, so leaking it narrows the hidden content.
    let real_len_end = 257 + REAL_LEN_BITS;
    assert_eq!(
      bits_to_bytes(&disclosed[257..real_len_end]),
      vec![real_len as u8],
      "real_len must be exposed for a disclosed claim"
    );
    assert_eq!(
      bits_to_bytes(&undisclosed[257..real_len_end]),
      vec![0u8],
      "an undisclosed claim's real_len must be masked to zero, not leaked"
    );

    // The plaintext is deliberately absent from the public values now --
    // it travels beside the proof and is bound by the blinded digest.
    assert_eq!(
      bits_to_bytes(&disclosed[real_len_end..STEP_LEN]),
      digest_id.to_be_bytes().to_vec(),
      "digest_id must follow real_len directly, with no plaintext block between"
    );
    assert_eq!(bits_to_bytes(&undisclosed[real_len_end..STEP_LEN]), digest_id.to_be_bytes().to_vec());
  }

  /// Independently computes the exact public-value vector
  /// `ClaimDigestStepCircuit::public_values` should produce for `bytes`/
  /// `disclose` — digest bits, then the disclosed flag, then the masked
  /// plaintext bits — without calling the circuit's own code, so a real
  /// implementation bug in any of the three parts shows up as a mismatch.
  fn expected_step_public_values(
    padded_bytes: &[u8],
    real_len: usize,
    disclose: bool,
    digest_id: u32,
    nonce: &[u8; BLIND_NONCE_BYTES],
  ) -> Vec<<Engine_ as Engine>::Scalar> {
    let mut hasher = Sha256::new();
    hasher.update(&padded_bytes[..real_len]);
    let digest: [u8; 32] = hasher.finalize().into();
    let blinded = blind_digest_bytes(&digest, nonce);
    let mut values: Vec<<Engine_ as Engine>::Scalar> = blinded
      .iter()
      .flat_map(|&byte| (0..8).rev().map(move |i| (byte >> i) & 1 == 1))
      .map(|b| if b { <Engine_ as Engine>::Scalar::ONE } else { <Engine_ as Engine>::Scalar::ZERO })
      .collect();
    values.push(if disclose { <Engine_ as Engine>::Scalar::ONE } else { <Engine_ as Engine>::Scalar::ZERO });
    // real_len is masked to zero when undisclosed, and the plaintext is
    // no longer a public value at all -- mirrors public_values().
    let len_byte = if disclose { real_len as u8 } else { 0u8 };
    for i in (0..REAL_LEN_BITS).rev() {
      values.push(if (len_byte >> i) & 1 == 1 { <Engine_ as Engine>::Scalar::ONE } else { <Engine_ as Engine>::Scalar::ZERO });
    }
    values.extend(mdoc_core::native_u32_to_bits::<<Engine_ as Engine>::Scalar>(digest_id));
    values
  }

  /// Note important for anyone signing the ECDSA verification path itself
  /// (independent of the mdoc-specific tests below): the P256 ECDSA
  /// gadget's own correctness is exercised directly in `ecdsa::tests`
  /// against RustCrypto vectors — these tests instead exercise the
  /// *composition*: real digests really flowing from the step circuits
  /// into the core circuit's signed message.
  #[test]
  fn round_trip_digest_only_proof() {
    let keys = setup().expect("setup");

    let claims = vec![
      ClaimWitness {
        issuer_signed_item_bytes: claim_bytes_with_digest_id(26, b"family_name:Doe"),
        disclose: true,
        digest_id: 26,
      },
      ClaimWitness {
        issuer_signed_item_bytes: claim_bytes_with_digest_id(300, b"given_name:Jane"),
        disclose: true,
        digest_id: 300,
      },
    ];
    let claim_digests = core_claim_digests(&claims).expect("core_claim_digests");
    let digest_ids = core_digest_ids(&claims).expect("core_digest_ids");
    let ecdsa_witness = real_ecdsa_witness_over(&digest_ids, &claim_digests);

    let call_nonce = fresh_nonce().expect("fresh_nonce");
    let prep = prep_prove(&keys.pk, &claims, &ecdsa_witness, &test_mso_body(), &call_nonce).expect("prep_prove");
    let (proof, _next_prep) =
      prove(&keys.pk, &claims, &ecdsa_witness, &test_mso_body(), prep, &call_nonce).expect("prove");
    let (step_public_values, core_public_values) = verify(&proof, &keys.vk).expect("verify");

    // Also independently extract the nonce the core circuit publicly
    // exposed (bits [2..258], right after qx/qy) and confirm it matches
    // `call_nonce` -- not just trust it, so `expected_step_public_values`
    // below blinds with a value confirmed to be what the real proof
    // actually used.
    let nonce: [u8; BLIND_NONCE_BYTES] =
      bits_to_bytes(&core_public_values[2..2 + BLIND_NONCE_BYTES * 8]).try_into().expect("nonce bytes");
    assert_eq!(nonce, call_nonce, "core circuit must expose exactly the nonce it was given");

    // Confirm the circuit is actually constraining the real values, not
    // vacuously satisfiable: the padded claim set is [Doe, Jane, pad, pad]
    // (see `pad_claims`), so check the exposed public values (blinded
    // digest + disclosed flag + masked plaintext + digest_id) for all four
    // slots equal an independently-computed expectation.
    let padded = pad_claims(&claims).expect("pad_claims");
    for (step_values, claim) in step_public_values.iter().zip(padded.iter()) {
      assert_eq!(
        step_values,
        &expected_step_public_values(&claim.bytes, claim.real_len, claim.disclose, claim.digest_id, &nonce),
        "step circuit's exposed public values must match blinded digest + disclosed flag + masked plaintext + digest_id"
      );
    }
  }

  /// Phase 3 goal: a full presentation — real per-claim digests (step
  /// circuits) *and* a real ECDSA-P256 signature genuinely computed over
  /// those exact digests (core circuit) — round-trips through
  /// setup/prep_prove/prove/verify, AND the verifier-side binding check
  /// (`verify_and_check_binding`) confirms the two halves actually agree.
  #[test]
  fn full_presentation_verifies_and_binds() {
    let keys = setup().expect("setup");

    let claims = vec![
      ClaimWitness {
        issuer_signed_item_bytes: claim_bytes_with_digest_id(5, b"family_name:Doe"),
        disclose: true,
        digest_id: 5,
      },
      ClaimWitness {
        issuer_signed_item_bytes: claim_bytes_with_digest_id(26, b"given_name:Jane"),
        disclose: true,
        digest_id: 26,
      },
      // Deliberately NOT disclosed — proves the claim exists and is
      // digest-committed, but its value stays private. Exercises the
      // masking path (`full_presentation_verifies_and_binds` previously
      // only ever exercised all-disclosed claims). digest_id spans a
      // third CBOR-uint length class (3 bytes), and the 4th (padding)
      // slot's digest_id defaults to 0 (class 0) -- together the full
      // padded set exercises every width this crate supports in one
      // real round trip.
      ClaimWitness {
        issuer_signed_item_bytes: claim_bytes_with_digest_id(70000, b"age_over_18:true"),
        disclose: false,
        digest_id: 70000,
      },
    ];
    let claim_digests = core_claim_digests(&claims).expect("core_claim_digests");
    let digest_ids = core_digest_ids(&claims).expect("core_digest_ids");
    let ecdsa_witness = real_ecdsa_witness_over(&digest_ids, &claim_digests);

    let call_nonce = fresh_nonce().expect("fresh_nonce");
    let prep = prep_prove(&keys.pk, &claims, &ecdsa_witness, &test_mso_body(), &call_nonce).expect("prep_prove");
    let (proof, next_prep) =
      prove(&keys.pk, &claims, &ecdsa_witness, &test_mso_body(), prep, &call_nonce).expect("prove");
    let (step_public_values, core_public_values) = verify(&proof, &keys.vk).expect("verify");

    let verified = verify_and_check_binding(&step_public_values, &core_public_values, &disclosed_for(&claims))
      .expect("binding check must pass for a genuinely-matching signature+digests");
    assert_eq!(verified.qx, ecdsa_witness.qx);
    assert_eq!(verified.qy, ecdsa_witness.qy);

    let padded = pad_claims(&claims).expect("pad_claims");
    assert_eq!(verified.claims.len(), padded.len());
    for (verified_claim, expected) in verified.claims.iter().zip(padded.iter()) {
      assert_eq!(verified_claim.disclosed, expected.disclose);
      // real_len is now masked for undisclosed claims (its length leaks
      // information about the hidden value), so only a disclosed claim
      // reports its true length.
      assert_eq!(
        verified_claim.real_len,
        if expected.disclose { expected.real_len } else { 0 },
        "an undisclosed claim's length must not leak"
      );
      assert_eq!(verified_claim.digest_id, expected.digest_id, "digestID must round-trip through the proof, at every CBOR-uint width class");
      if expected.disclose {
        assert_eq!(
          verified_claim.digest,
          claim_digest_bytes(&expected.bytes[..expected.real_len]),
          "a disclosed claim's digest is safe to expose (derivable from plaintext anyway) and must round-trip"
        );
        assert_eq!(
          verified_claim.plaintext,
          expected.bytes[..expected.real_len].to_vec(),
          "a disclosed claim's plaintext must round-trip through the proof"
        );
      } else {
        assert_eq!(
          verified_claim.digest,
          [0u8; 32],
          "an undisclosed claim's real digest must never be exposed -- masked to all-zero, same as plaintext"
        );
        assert!(
          verified_claim.plaintext.is_empty(),
          "an undisclosed claim carries no plaintext at all now -- not even a zero-run of its true length"
        );
      }
    }

    // The fold-and-reuse prep state must also work for a second
    // presentation of the same credential (a different verifier, say) —
    // exercising `nextState`'s round-trip, not just a single `prove` call.
    // MUST reuse `call_nonce`, not a fresh one -- see `fresh_nonce`'s doc
    // for why a nonce is tied to the lifetime of one prep chain, and why
    // that's a real, currently-latent limitation on real freshness.
    let (proof2, _next_prep2) = prove(&keys.pk, &claims, &ecdsa_witness, &test_mso_body(), next_prep, &call_nonce)
      .expect("second prove reusing prep state");
    let (step_public_values2, core_public_values2) = verify(&proof2, &keys.vk).expect("verify 2");
    verify_and_check_binding(&step_public_values2, &core_public_values2, &disclosed_for(&claims))
      .expect("binding check must also pass for the reused-prep-state proof");
  }

  /// The negative case `mdoc_core`'s module doc calls out explicitly:
  /// a core proof that's individually valid (real signature over *some*
  /// digests) must NOT bind against a step proof over *different* claims.
  ///
  /// This can't be expressed through `prep_prove`/`prove` (this crate's
  /// own wrapper functions always build the core circuit's digests from
  /// the same `claims` used for the step circuits — see
  /// `core_claim_digests`), so it drives `VegaMcZkSNARK` directly: step
  /// circuits genuinely, self-consistently prove `real_claims`; the core
  /// circuit genuinely, self-consistently signs `other_claims`' digests.
  /// Both circuits are individually valid (so `verify()` itself succeeds)
  /// — only `verify_and_check_binding`'s cross-circuit check should catch
  /// the mismatch.
  #[test]
  fn binding_check_rejects_mismatched_claims() {
    let keys = setup().expect("setup");

    let real_claims = vec![ClaimWitness {
      issuer_signed_item_bytes: claim_bytes_with_digest_id(5, b"family_name:Doe"),
      disclose: true,
      digest_id: 5,
    }];
    let other_claims = vec![ClaimWitness {
      issuer_signed_item_bytes: claim_bytes_with_digest_id(5, b"family_name:Smith"),
      disclose: true,
      digest_id: 5,
    }];

    // Deliberately the SAME nonce for both circuits below -- this test is
    // isolating the claim-digest mismatch specifically, not an incidental
    // nonce mismatch (which would also fail the binding check, but for the
    // wrong reason).
    let nonce = [0x77u8; BLIND_NONCE_BYTES];
    let padded = pad_claims(&real_claims).expect("pad_claims");
    let step_circuits: Vec<ClaimDigestStepCircuit<Engine_>> = padded
      .iter()
      .map(|c| ClaimDigestStepCircuit::new(c.bytes.clone(), c.real_len, c.disclose, c.digest_id, nonce))
      .collect();

    let mismatched_digests = core_claim_digests(&other_claims).expect("core_claim_digests");
    let mismatched_digest_ids = core_digest_ids(&other_claims).expect("core_digest_ids");
    let ecdsa_witness = real_ecdsa_witness_over(&mismatched_digest_ids, &mismatched_digests);
    let core_circuit = MdocCoreCircuit::<Engine_>::new(
      ecdsa_witness.qx,
      ecdsa_witness.qy,
      ecdsa_witness.r,
      ecdsa_witness.s,
      ecdsa_witness.s_inv,
      mismatched_digest_ids,
      mismatched_digests,
      test_mso_body(),
      nonce,
    );

    let prep = VegaMcZkSNARK::<Engine_>::prep_prove(&keys.pk, &step_circuits, &core_circuit, false)
      .expect("prep_prove");
    let (proof, _next_prep) =
      VegaMcZkSNARK::<Engine_>::prove(&keys.pk, &step_circuits, &core_circuit, prep, false)
        .expect("prove");
    let (step_public_values, core_public_values) =
      proof.verify(&keys.vk, MAX_CLAIMS_V1).expect("verify");

    assert!(
      verify_and_check_binding(&step_public_values, &core_public_values, &disclosed_for(&real_claims)).is_err(),
      "a proof whose core circuit signs different claims than its step circuits disclose must fail the binding check"
    );
  }

  /// The digest_id-specific analogue of the test above: a core proof
  /// that's individually valid (a real ECDSA signature over one digestID
  /// assignment) must NOT bind against a step proof whose own claim
  /// genuinely embeds a *different* digestID -- isolating the new
  /// `digest_id_extract`-based cross-check from the pre-existing
  /// claim-digest cross-check (both halves agree on `claim_digests`/`z`
  /// here; only the witnessed digestID differs). Without this check, a
  /// prover could witness one digestID to the core circuit (determining
  /// the MSO's byte layout) while a claim's real bytes embed another.
  #[test]
  fn binding_check_rejects_mismatched_digest_ids() {
    let keys = setup().expect("setup");

    // The step circuit genuinely, self-consistently proves this claim:
    // its own bytes really embed digest_id=7, and it witnesses exactly
    // that (digest_id_extract's own constraint requires this).
    let claims = vec![ClaimWitness {
      issuer_signed_item_bytes: claim_bytes_with_digest_id(7, b"family_name:Doe"),
      disclose: true,
      digest_id: 7,
    }];
    // Same nonce on both sides, deliberately -- see the analogous comment
    // in `binding_check_rejects_mismatched_claims`.
    let nonce = [0x88u8; BLIND_NONCE_BYTES];
    let padded = pad_claims(&claims).expect("pad_claims");
    let step_circuits: Vec<ClaimDigestStepCircuit<Engine_>> = padded
      .iter()
      .map(|c| ClaimDigestStepCircuit::new(c.bytes.clone(), c.real_len, c.disclose, c.digest_id, nonce))
      .collect();

    // The core circuit signs the SAME claim_digests (so the pre-existing
    // blinded-digest binding alone would pass) but under a DIFFERENT
    // digestID -- a genuinely valid signature over a differently-keyed MSO.
    let claim_digests = core_claim_digests(&claims).expect("core_claim_digests");
    let mut wrong_digest_ids = core_digest_ids(&claims).expect("core_digest_ids");
    wrong_digest_ids[0] = 8; // differs from the step circuit's real digest_id=7
    let ecdsa_witness = real_ecdsa_witness_over(&wrong_digest_ids, &claim_digests);
    let core_circuit = MdocCoreCircuit::<Engine_>::new(
      ecdsa_witness.qx,
      ecdsa_witness.qy,
      ecdsa_witness.r,
      ecdsa_witness.s,
      ecdsa_witness.s_inv,
      wrong_digest_ids,
      claim_digests,
      test_mso_body(),
      nonce,
    );

    let prep = VegaMcZkSNARK::<Engine_>::prep_prove(&keys.pk, &step_circuits, &core_circuit, false)
      .expect("prep_prove");
    let (proof, _next_prep) =
      VegaMcZkSNARK::<Engine_>::prove(&keys.pk, &step_circuits, &core_circuit, prep, false)
        .expect("prove");
    let (step_public_values, core_public_values) =
      proof.verify(&keys.vk, MAX_CLAIMS_V1).expect("verify");

    assert!(
      verify_and_check_binding(&step_public_values, &core_public_values, &disclosed_for(&claims)).is_err(),
      "a proof whose core circuit witnesses a different digestID than what a claim's own step circuit extracts must fail the binding check"
    );
  }
}
