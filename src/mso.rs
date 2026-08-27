//! Real ISO 18013-5 MobileSecurityObject (MSO) byte framing.
//!
//! Replaces `mdoc_core`'s earlier stand-in (`z = SHA-256` of the bare
//! concatenated claim digests) with the actual bytes a real issuer signs:
//! a CBOR-encoded `MobileSecurityObject`, wrapped in `#6.24(bstr .cbor
//! ...)`, wrapped again in a COSE_Sign1 `Sig_structure`
//! (`["Signature1", protected, external_aad, payload]`). `z =
//! SHA-256(Sig_structure bytes)`, exactly matching what ECDSA/ES256
//! actually signs.
//!
//! ## Byte-exact, not guessed
//!
//! Every fixed byte segment below was derived from, and verified against,
//! a **real signed mdoc issued by this stack's own `SUNET/vc` issuer**
//! (`pkg/mdoc.MSOBuilder.Build`, `sirosfoundation/vc`): running that exact
//! production code path (real `NewMSOBuilder`/`WithSigner`/`AddDataElement`
//! calls, a real generated P-256 issuer cert, real ECDSA signing) and
//! dumping the resulting `COSE_Sign1`'s `Protected`/`Payload` bytes
//! confirmed the exact construction: `Sig_structure = ["Signature1",
//! protected_bytes, h'', payload_bytes]` (CBOR array), `payload_bytes =
//! #6.24(bstr <MSO CBOR bytes>)`, `protected_bytes = {1: -7}` (ES256), and
//! -- importantly -- `unprotected` (which carries `x5chain`) is **not**
//! part of the signed bytes at all, matching COSE_Sign1's definition; the
//! issuer's public key reaches the verifier only via `x5chain`, checked
//! independently of this circuit (see `MdocCoreCircuit`'s module doc).
//!
//! This module previously derived its field order from a *different* real
//! mdoc (`zk-cred-longfellow`'s `v6_v7_1attr_issue_date.json`, an
//! OWF/multipaz test credential) and assumed CDDL declaration order
//! (`version`, `digestAlgorithm`, `docType`, `valueDigests`,
//! `deviceKeyInfo`, `validityInfo`) held generally. It doesn't: `vc`'s
//! `pkg/mdoc.NewCBOREncoder` sets `cbor.EncOptions{Sort:
//! cbor.SortCanonical}` (`fxamacker/cbor`'s RFC 7049 canonical CBOR --
//! shortest-key-first, then bytewise lexicographic among same-length
//! keys), and the MSO itself is built as a plain `map[string]any` (not a
//! tagged struct), so its declaration order in Go source is irrelevant --
//! only the canonical sort matters. For these 6 keys that sorts to
//! `docType`, `version`, `validityInfo`, `valueDigests`, `deviceKeyInfo`,
//! `digestAlgorithm` -- a different byte layout from the old assumption on
//! every field after the first two. Reconstructing the wrong layout still
//! produces a plausible-looking `z`, just not the one ECDSA actually
//! signed -- the exact "internally-inconsistent... valid-looking scalars"
//! failure class this crate's own `lib.rs` doc already warns about,
//! surfacing downstream as `InvalidSumcheckProof` at verify time with no
//! more specific diagnostic. Confirmed empirically: switching a live
//! end-to-end presentation from a `pid_mdoc`-docType credential to a new
//! `org.iso.18013.5.1.mDL`-docType credential (ruling out a docType/
//! namespace mismatch) still failed identically, which is what prompted
//! re-deriving this module's byte layout against the real issuer instead
//! of re-trusting the external OWF/multipaz reference.
//!
//! ## `digestID`s are real, variable-width CBOR uints -- not fixed 0..3
//!
//! ISO 18013-5 §9.1.2.4 bounds `digestID` at `< 2^31` and explicitly warns
//! issuers against small/correlated values (see `cbor_uint`'s module
//! doc) -- a real MSO's `valueDigests` keys are 1, 2, 3, or 5 CBOR bytes
//! each, not always the single byte `0..3` this module originally
//! hardcoded. [`crate::mso_splice`] assembles that variable-width section
//! (and the fixed prefix/suffix around it) into one flat, fixed-size
//! buffer for [`crate::sha256_var::sha256_var_sized`] to hash -- see that
//! module's doc for the one-hot-cursor technique this requires to keep
//! the circuit's shape fixed regardless of which widths are chosen.
//!
//! ## v1 scope: one docType, one namespace, a fixed claim count
//!
//! This module bakes in `docType = "org.iso.18013.5.1.mDL"`, a single
//! namespace `"org.iso.18013.5.1"`, `digestAlgorithm = "SHA-256"`, and
//! exactly [`crate::MAX_CLAIMS_V1`] digestIDs (each now independently
//! witnessed, any spec-legal value) -- the same fixed-shape convention
//! `MAX_CLAIM_BYTES_V1` already establishes elsewhere in this crate. The
//! real (canonical-CBOR) map key order is `docType`, `version`,
//! `validityInfo`, `valueDigests`, `deviceKeyInfo`, `digestAlgorithm` --
//! see above for why.
//!
//! Every "FIXED" segment below is therefore a compile-time constant byte
//! string, identical for every credential of this exact shape; only the
//! digestIDs/digest values, the device key, and the three validity
//! timestamps vary per credential and cross as witness bytes.
//!
//! This module reconstructs a real issuer's exact `Sig_structure` bytes
//! for *any* spec-legal digestID combination, not just the narrow
//! `0..MAX_CLAIMS_V1` range this crate used to mint itself. The
//! `digest_ids` witnessed here are still caller-supplied native values --
//! this module has no way to check them itself -- but they're no longer
//! trusted blindly end to end: [`crate::ClaimDigestStepCircuit`]
//! independently extracts each claim's real, embedded digestID via
//! [`crate::digest_id_extract`] and exposes it as a public value, and
//! [`crate::verify_and_check_binding`] cross-checks it against the
//! corresponding entry here, rejecting any proof where they disagree.

use crate::mso_splice::{self, DigestIdEntry, ENTRY_TAIL_LEN};
use bellpepper_core::{
  boolean::{AllocatedBit, Boolean},
  ConstraintSystem, SynthesisError,
};

/// One fixed-length ASCII timestamp, e.g. `"2026-08-20T00:00:00Z"` (the
/// `tdate` text form CBOR tag 0 wraps -- always exactly this length for a
/// UTC, whole-second, `Z`-suffixed RFC 3339 timestamp).
pub const TIMESTAMP_LEN: usize = 20;

/// From the start of the MSO body through `validityInfo.signed`'s tag(0) +
/// tstr(20) header -- `{"docType":"org.iso.18013.5.1.mDL","version":"1.0",
/// "validityInfo":{"signed":0(` -- a fixed 6-entry map header (`0xa6`)
/// since [`crate::MAX_CLAIMS_V1`] is a compile-time constant.
const SEG_PREFIX_BASE: &[u8] = &[
  0xa6, 0x67, 0x64, 0x6f, 0x63, 0x54, 0x79, 0x70, 0x65, 0x75, 0x6f, 0x72, 0x67, 0x2e, 0x69, 0x73,
  0x6f, 0x2e, 0x31, 0x38, 0x30, 0x31, 0x33, 0x2e, 0x35, 0x2e, 0x31, 0x2e, 0x6d, 0x44, 0x4c, 0x67,
  0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x63, 0x31, 0x2e, 0x30, 0x6c, 0x76, 0x61, 0x6c, 0x69,
  0x64, 0x69, 0x74, 0x79, 0x49, 0x6e, 0x66, 0x6f, 0xa3, 0x66, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x64,
  0xc0, 0x74,
];
/// Between `validityInfo.signed` and `.validFrom`: `,"validFrom":0("`.
const SEG_BETWEEN_SIGNED_VALIDFROM: &[u8] = &[
  0x69, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x46, 0x72, 0x6f, 0x6d, 0xc0, 0x74,
];
/// Between `validityInfo.validFrom` and `.validUntil`: `,"validUntil":0("`.
const SEG_BETWEEN_VALIDFROM_VALIDUNTIL: &[u8] = &[
  0x6a, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x55, 0x6e, 0x74, 0x69, 0x6c, 0xc0, 0x74,
];
/// After `validityInfo.validUntil`, through `valueDigests`'s inner
/// (namespace) map's own digest-map header -- `},"valueDigests":
/// {"org.iso.18013.5.1":{` -- fixed at 4 entries (`0xa4`) since
/// [`crate::MAX_CLAIMS_V1`] is a compile-time constant.
const SEG_BEFORE_DIGESTS: &[u8] = &[
  0x6c, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x44, 0x69, 0x67, 0x65, 0x73, 0x74, 0x73, 0xa1, 0x71, 0x6f,
  0x72, 0x67, 0x2e, 0x69, 0x73, 0x6f, 0x2e, 0x31, 0x38, 0x30, 0x31, 0x33, 0x2e, 0x35, 0x2e, 0x31,
  0xa4,
];
/// After the last digest, through `deviceKeyInfo.deviceKey`'s `x`
/// coordinate's `bstr` header -- `},"deviceKeyInfo":{"deviceKey":{1:2,-1:1,
/// -2:<bstr header>`.
const SEG_AFTER_DIGESTS: &[u8] = &[
  0x6d, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x4b, 0x65, 0x79, 0x49, 0x6e, 0x66, 0x6f, 0xa1, 0x69,
  0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x4b, 0x65, 0x79, 0xa4, 0x01, 0x02, 0x20, 0x01, 0x21, 0x58,
  0x20,
];
/// Between device key `x` and `y`: `, -3: <bstr header>`.
const SEG_BETWEEN_XY: &[u8] = &[0x22, 0x58, 0x20];
/// After device key `y`, through the end of the MSO body --
/// `}},"digestAlgorithm":"SHA-256"}` -- the final, fixed field, closing
/// the map.
const SEG_AFTER_DEVICE_KEY: &[u8] = &[
  0x6f, 0x64, 0x69, 0x67, 0x65, 0x73, 0x74, 0x41, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d,
  0x67, 0x53, 0x48, 0x41, 0x2d, 0x32, 0x35, 0x36,
];

/// `#6.24(bstr <MSO>)` header, minus its 2-byte length value (which is now
/// witnessed, since the MSO body's length varies with the chosen
/// digestIDs' widths) -- `0xd8, 0x18` (tag 24) + `0x59` (bstr, 2-byte
/// length form; always this form since real totals stay well under
/// 65536).
const PAYLOAD_HEADER_NO_LEN: &[u8] = &[0xd8, 0x18, 0x59];
/// COSE_Sign1 protected header, `{1: -7}` (alg ES256/ECDSA-P256-SHA256).
pub const PROTECTED_HEADER: &[u8] = &[0xa1, 0x01, 0x26];
/// `["Signature1", <protected bstr>, h'', <payload bstr length marker>` --
/// minus its own 2-byte length value (witnessed, same reason as
/// [`PAYLOAD_HEADER_NO_LEN`]).
const SIG_STRUCTURE_PREFIX_NO_LEN: &[u8] = &[
  0x84, 0x6a, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31, 0x43, 0xa1, 0x01, 0x26,
  0x40, 0x59,
];

/// Fixed byte length of everything from the start of the MSO body through
/// (not including) the digestID section's own bytes -- [`SEG_PREFIX_BASE`]
/// plus the three witnessed `validityInfo` timestamps and the segments
/// between/after them -- computed once from the segment constants above
/// rather than hand-counted, so it can never silently drift from them.
fn prefix_fixed_len() -> usize {
  SEG_PREFIX_BASE.len() + TIMESTAMP_LEN + SEG_BETWEEN_SIGNED_VALIDFROM.len() + TIMESTAMP_LEN + SEG_BETWEEN_VALIDFROM_VALIDUNTIL.len() + TIMESTAMP_LEN + SEG_BEFORE_DIGESTS.len()
}

/// Fixed byte length of everything after the digestID section (device
/// key `x`/`y` + the constant text around and after them) -- computed
/// once from the segment constants above rather than hand-counted, so it
/// can never silently drift from them.
fn suffix_fixed_len() -> usize {
  SEG_AFTER_DIGESTS.len() + 32 + SEG_BETWEEN_XY.len() + 32 + SEG_AFTER_DEVICE_KEY.len()
}

/// `mso_body_len` (the MSO CBOR body's own byte length, i.e. what
/// [`PAYLOAD_HEADER_NO_LEN`]'s witnessed length field must carry) and
/// `payload_len` (`len(PAYLOAD_HEADER_NO_LEN) + 2 + mso_body_len`, what
/// [`SIG_STRUCTURE_PREFIX_NO_LEN`]'s witnessed length field must carry),
/// given the digestID section's real (already digestID-width-dependent)
/// byte length. Both values fit comfortably in a `u16` for any real
/// credential this crate supports (well under 65536), matching the
/// `0x59 XXXX` 2-byte-length CBOR form both headers use unconditionally.
fn compute_lengths(real_digest_section_len: usize) -> (u16, u16) {
  let mso_body_len = prefix_fixed_len() + real_digest_section_len + suffix_fixed_len();
  let payload_len = PAYLOAD_HEADER_NO_LEN.len() + 2 + mso_body_len;
  (
    u16::try_from(mso_body_len).expect("mso_body_len fits in a u16 for any real credential this crate supports"),
    u16::try_from(payload_len).expect("payload_len fits in a u16 for any real credential this crate supports"),
  )
}

/// Upper bound on the whole `Sig_structure`'s byte length: every
/// digestID at its widest, everything else at its (fixed) real length.
pub const MAX_SIG_STRUCTURE_BYTES: usize = SIG_STRUCTURE_PREFIX_NO_LEN.len()
  + 2
  + PAYLOAD_HEADER_NO_LEN.len()
  + 2
  + SEG_PREFIX_BASE.len()
  + TIMESTAMP_LEN * 3
  + SEG_BETWEEN_SIGNED_VALIDFROM.len()
  + SEG_BETWEEN_VALIDFROM_VALIDUNTIL.len()
  + SEG_BEFORE_DIGESTS.len()
  + mso_splice::MAX_DIGEST_SECTION_BYTES
  + SEG_AFTER_DIGESTS.len()
  + 32
  + SEG_BETWEEN_XY.len()
  + 32
  + SEG_AFTER_DEVICE_KEY.len();

/// Number of 512-bit SHA-256 blocks [`MAX_SIG_STRUCTURE_BYTES`] can occupy
/// at most -- what [`crate::sha256_var::sha256_var_sized`] must be called
/// with for this module's buffer.
pub const SIG_STRUCTURE_NUM_BLOCKS: usize = crate::sha256_var::terminal_block_for_len(MAX_SIG_STRUCTURE_BYTES);

/// The per-credential witness data this module's MSO template splices in.
/// Everything else (`docType`, the namespace, `digestAlgorithm`) is a
/// fixed constant for this circuit version; the digestIDs themselves are
/// carried alongside the claim digests by the caller (see
/// [`native_sig_structure_bytes`]/[`alloc_sig_structure_bits`]).
#[derive(Clone, Debug)]
pub struct MsoBodyWitness {
  /// The device's public key coordinates (`deviceKeyInfo.deviceKey`, a
  /// COSE_Key EC2/P-256 key) -- not otherwise checked by this circuit yet
  /// (no device-binding/deviceSigned verification), but part of the
  /// signed bytes regardless.
  pub device_x: [u8; 32],
  pub device_y: [u8; 32],
  /// `validityInfo.signed`/`validFrom`/`validUntil`, each an RFC 3339 UTC
  /// timestamp of exactly [`TIMESTAMP_LEN`] bytes, e.g.
  /// `"2026-08-20T00:00:00Z"`.
  pub signed_ts: [u8; TIMESTAMP_LEN],
  pub valid_from_ts: [u8; TIMESTAMP_LEN],
  pub valid_until_ts: [u8; TIMESTAMP_LEN],
}

fn byte_to_bits_be(byte: u8) -> impl Iterator<Item = bool> {
  (0..8).rev().map(move |i| (byte >> i) & 1 == 1)
}

fn make_tail(digest: &[u8; 32]) -> [u8; ENTRY_TAIL_LEN] {
  let mut t = [0u8; ENTRY_TAIL_LEN];
  t[0] = 0x58;
  t[1] = 0x20;
  t[2..].copy_from_slice(digest);
  t
}

/// Native (non-circuit) construction of the exact bytes ECDSA/ES256 signs
/// -- used to build real test signatures and to compute `z` natively for
/// `MdocCoreCircuit::public_values`. `digest_ids[i]` is the real,
/// spec-legal (`< 2^31`) digestID for `claim_digests[i]` -- see
/// `cbor_uint`'s module doc.
pub fn native_sig_structure_bytes(digest_ids: &[u32; mso_splice::NUM_ENTRIES], claim_digests: &[[u8; 32]], body: &MsoBodyWitness) -> Vec<u8> {
  assert_eq!(claim_digests.len(), mso_splice::NUM_ENTRIES, "this module's fixed byte template is for exactly MAX_CLAIMS_V1 digestIDs");
  let tails: [[u8; ENTRY_TAIL_LEN]; mso_splice::NUM_ENTRIES] = std::array::from_fn(|i| make_tail(&claim_digests[i]));
  let real_digest_section_len = digest_ids.iter().map(|&id| crate::cbor_uint::encode_cbor_uint(id).len()).sum::<usize>() + mso_splice::NUM_ENTRIES * ENTRY_TAIL_LEN;
  let (mso_body_len, payload_len) = compute_lengths(real_digest_section_len);

  let mut prefix = Vec::new();
  prefix.extend_from_slice(SIG_STRUCTURE_PREFIX_NO_LEN);
  prefix.extend_from_slice(&payload_len.to_be_bytes());
  prefix.extend_from_slice(PAYLOAD_HEADER_NO_LEN);
  prefix.extend_from_slice(&mso_body_len.to_be_bytes());
  prefix.extend_from_slice(SEG_PREFIX_BASE);
  prefix.extend_from_slice(&body.signed_ts);
  prefix.extend_from_slice(SEG_BETWEEN_SIGNED_VALIDFROM);
  prefix.extend_from_slice(&body.valid_from_ts);
  prefix.extend_from_slice(SEG_BETWEEN_VALIDFROM_VALIDUNTIL);
  prefix.extend_from_slice(&body.valid_until_ts);
  prefix.extend_from_slice(SEG_BEFORE_DIGESTS);

  let mut suffix = Vec::new();
  suffix.extend_from_slice(SEG_AFTER_DIGESTS);
  suffix.extend_from_slice(&body.device_x);
  suffix.extend_from_slice(SEG_BETWEEN_XY);
  suffix.extend_from_slice(&body.device_y);
  suffix.extend_from_slice(SEG_AFTER_DEVICE_KEY);

  mso_splice::native_mso_sig_structure_bytes(&prefix, digest_ids, &tails, &suffix)
}

/// The MSO-body witness fields' allocated bits, grouped by name -- used so
/// a caller can `inputize` these specific bits directly.
pub struct AllocatedMsoBodyBits {
  pub device_x: Vec<Boolean>,
  pub device_y: Vec<Boolean>,
  pub signed_ts: Vec<Boolean>,
  pub valid_from_ts: Vec<Boolean>,
  pub valid_until_ts: Vec<Boolean>,
}

fn push_fixed(bits: &mut Vec<Boolean>, bytes: &[u8]) {
  for &byte in bytes {
    for b in byte_to_bits_be(byte) {
      bits.push(Boolean::constant(b));
    }
  }
}

fn alloc_witness_bytes<F: ff::PrimeField, CS: ConstraintSystem<F>>(cs: &mut CS, bytes: &[u8], label: &str) -> Result<Vec<Boolean>, SynthesisError> {
  let mut out = Vec::with_capacity(bytes.len() * 8);
  for (byte_idx, &byte) in bytes.iter().enumerate() {
    for (bit_idx, b) in byte_to_bits_be(byte).enumerate() {
      let bit = AllocatedBit::alloc(cs.namespace(|| format!("{label} byte {byte_idx} bit {bit_idx}")), Some(b))?;
      out.push(Boolean::from(bit));
    }
  }
  Ok(out)
}

fn alloc_witness_u16<F: ff::PrimeField, CS: ConstraintSystem<F>>(cs: &mut CS, value: u16, label: &str) -> Result<Vec<Boolean>, SynthesisError> {
  alloc_witness_bytes(cs, &value.to_be_bytes(), label)
}

/// In-circuit construction of the same bytes as
/// [`native_sig_structure_bytes`], as a fixed-size
/// (`MAX_SIG_STRUCTURE_BYTES*8`-bit) `Boolean` buffer plus the native real
/// (non-don't-care) length in bytes -- ready for
/// [`crate::sha256_var::sha256_var_sized`] -- and the MSO-body witness bits
/// grouped by name (see [`AllocatedMsoBodyBits`]). Fixed segments become
/// `Boolean::constant` (no witness allocation -- the verifier already
/// knows these bytes, they're part of this circuit version's definition);
/// witness segments (digestIDs, digests, device key, timestamps, and the
/// two length fields) become real allocated bits.
pub fn alloc_sig_structure_bits<CS: ConstraintSystem<F>, F: ff::PrimeField>(
  cs: &mut CS,
  digest_ids: &[u32; mso_splice::NUM_ENTRIES],
  claim_digests: &[[u8; 32]],
  body: &MsoBodyWitness,
) -> Result<(Vec<Boolean>, usize, AllocatedMsoBodyBits), SynthesisError> {
  assert_eq!(claim_digests.len(), mso_splice::NUM_ENTRIES, "this module's fixed byte template is for exactly MAX_CLAIMS_V1 digestIDs");

  let real_digest_section_len =
    digest_ids.iter().map(|&id| crate::cbor_uint::encode_cbor_uint(id).len()).sum::<usize>() + mso_splice::NUM_ENTRIES * ENTRY_TAIL_LEN;
  let (mso_body_len, payload_len) = compute_lengths(real_digest_section_len);

  let mut prefix_bits = Vec::new();
  push_fixed(&mut prefix_bits, SIG_STRUCTURE_PREFIX_NO_LEN);
  prefix_bits.extend(alloc_witness_u16(cs, payload_len, "payload_len")?);
  push_fixed(&mut prefix_bits, PAYLOAD_HEADER_NO_LEN);
  prefix_bits.extend(alloc_witness_u16(cs, mso_body_len, "mso_body_len")?);
  push_fixed(&mut prefix_bits, SEG_PREFIX_BASE);

  let signed_ts_bits = alloc_witness_bytes(cs, &body.signed_ts, "signed_ts")?;
  let valid_from_ts_bits = alloc_witness_bytes(cs, &body.valid_from_ts, "valid_from_ts")?;
  let valid_until_ts_bits = alloc_witness_bytes(cs, &body.valid_until_ts, "valid_until_ts")?;

  prefix_bits.extend(signed_ts_bits.iter().cloned());
  push_fixed(&mut prefix_bits, SEG_BETWEEN_SIGNED_VALIDFROM);
  prefix_bits.extend(valid_from_ts_bits.iter().cloned());
  push_fixed(&mut prefix_bits, SEG_BETWEEN_VALIDFROM_VALIDUNTIL);
  prefix_bits.extend(valid_until_ts_bits.iter().cloned());
  push_fixed(&mut prefix_bits, SEG_BEFORE_DIGESTS);

  let device_x_bits = alloc_witness_bytes(cs, &body.device_x, "device_x")?;
  let device_y_bits = alloc_witness_bytes(cs, &body.device_y, "device_y")?;

  let mut suffix_bits = Vec::new();
  push_fixed(&mut suffix_bits, SEG_AFTER_DIGESTS);
  suffix_bits.extend(device_x_bits.iter().cloned());
  push_fixed(&mut suffix_bits, SEG_BETWEEN_XY);
  suffix_bits.extend(device_y_bits.iter().cloned());
  push_fixed(&mut suffix_bits, SEG_AFTER_DEVICE_KEY);

  let entries: [DigestIdEntry; mso_splice::NUM_ENTRIES] = {
    let mut built: Vec<DigestIdEntry> = Vec::with_capacity(mso_splice::NUM_ENTRIES);
    for i in 0..mso_splice::NUM_ENTRIES {
      let tail_bytes = make_tail(&claim_digests[i]);
      let tail_bits = alloc_witness_bytes(cs, &tail_bytes, &format!("entry {i} tail"))?;
      built.push(DigestIdEntry {
        digest_id: digest_ids[i],
        tail_bits,
      });
    }
    built.try_into().unwrap_or_else(|_| unreachable!())
  };

  let (assembled, real_len) = mso_splice::assemble_mso_sig_structure::<F, _>(cs.namespace(|| "mso sig_structure"), &prefix_bits, &entries, &suffix_bits)?;
  assert_eq!(assembled.len(), MAX_SIG_STRUCTURE_BYTES * 8);

  Ok((
    assembled,
    real_len,
    AllocatedMsoBodyBits {
      device_x: device_x_bits,
      device_y: device_y_bits,
      signed_ts: signed_ts_bits,
      valid_from_ts: valid_from_ts_bits,
      valid_until_ts: valid_until_ts_bits,
    },
  ))
}

#[cfg(test)]
mod tests {
  use super::*;

  fn test_body() -> MsoBodyWitness {
    MsoBodyWitness {
      device_x: [0xD0; 32],
      device_y: [0xD1; 32],
      signed_ts: *b"2026-08-20T00:00:00Z",
      valid_from_ts: *b"2026-08-20T00:00:00Z",
      valid_until_ts: *b"2036-08-20T00:00:00Z",
    }
  }

  /// Regression check against a real `vc`-issued MSO's bytes (see this
  /// module's doc for how these were captured): docType/version/
  /// validityInfo come first (fixed + witnessed timestamps), then the
  /// digest section, then deviceKeyInfo, then digestAlgorithm last.
  #[test]
  fn native_sig_structure_bytes_matches_real_vc_issued_mso_layout() {
    let digest_ids = [0u32, 1, 2, 3];
    let digests = [[0xE0u8; 32], [0xE1u8; 32], [0xE2u8; 32], [0xE3u8; 32]];
    let bytes = native_sig_structure_bytes(&digest_ids, &digests, &test_body());
    assert_eq!(bytes.len(), 473, "Sig_structure length must match the real reference (20 + 5 + 448)");
    assert_eq!(&bytes[..4], &[0x84, 0x6a, 0x53, 0x69], "must start with array(4), tstr(10) 'Si...'");
    assert_eq!(&bytes[20..25], &[0xd8, 0x18, 0x59, 0x01, 0xc0], "payload header + MSO body length");
    assert_eq!(&bytes[25..34], &[0xa6, 0x67, 0x64, 0x6f, 0x63, 0x54, 0x79, 0x70, 0x65], "MSO body must start with map(6), tstr(7) 'docType'");
    let signed_ts_start = 25 + SEG_PREFIX_BASE.len();
    assert_eq!(&bytes[signed_ts_start..signed_ts_start + 20], test_body().signed_ts, "signed_ts must sit right after SEG_PREFIX_BASE");
    let validfrom_key_start = signed_ts_start + 20;
    assert_eq!(&bytes[validfrom_key_start..validfrom_key_start + 12], SEG_BETWEEN_SIGNED_VALIDFROM, "\"validFrom\" key must follow signed_ts directly");
    let digest_section_start = 25 + prefix_fixed_len();
    assert_eq!(bytes[digest_section_start], 0x00, "first digest entry's digestID (class-0, single byte 0x00)");
  }

  /// The real point of this module's rewrite: a genuinely different
  /// digestID combination (spanning all four CBOR-uint length classes)
  /// produces a *longer* buffer, with lengths that self-consistently
  /// describe the new total -- not a fixed 473-byte result regardless of
  /// input.
  #[test]
  fn native_sig_structure_bytes_grows_with_wider_digest_ids() {
    let narrow = native_sig_structure_bytes(&[0, 1, 2, 3], &[[0xE0u8; 32], [0xE1u8; 32], [0xE2u8; 32], [0xE3u8; 32]], &test_body());
    let wide = native_sig_structure_bytes(&[5, 26, 300, 70000], &[[0xE0u8; 32], [0xE1u8; 32], [0xE2u8; 32], [0xE3u8; 32]], &test_body());
    // widths 1,2,3,5 = 11 bytes of digestIDs vs narrow's 4*1 = 4 bytes.
    assert_eq!(wide.len(), narrow.len() + 7);
    // The witnessed length fields must reflect the new total, not the old
    // one. payload_len is len(payload_bytes) = the whole Sig_structure
    // minus SIG_STRUCTURE_PREFIX_NO_LEN(18) + its own 2-byte length field.
    let payload_len = u16::from_be_bytes([wide[18], wide[19]]);
    assert_eq!(payload_len as usize, wide.len() - 20);
    let mso_body_len = u16::from_be_bytes([wide[23], wide[24]]);
    assert_eq!(mso_body_len as usize, wide.len() - 25);
  }
}
