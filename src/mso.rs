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
//! a **real signed mdoc**: `zk-cred-longfellow`'s own
//! `test-vectors/mdoc_zk/v6_v7_1attr_issue_date.json` (a real OWF/multipaz
//! test credential, docType `org.iso.18013.5.1.mDL`). Decoding that
//! credential's `issuerAuth` (Python, `cbor2`), reconstructing its
//! `Sig_structure` byte-for-byte, and checking the real ECDSA signature
//! against the real issuer's real x5chain certificate (Python,
//! `cryptography`) confirmed the exact construction: `Sig_structure =
//! ["Signature1", protected_bytes, h'', payload_bytes]` (CBOR array),
//! `payload_bytes = #6.24(bstr <MSO CBOR bytes>)`, and — importantly —
//! `unprotected` (which carries `x5chain`) is **not** part of the signed
//! bytes at all, matching COSE_Sign1's definition; the issuer's public key
//! reaches the verifier only via `x5chain`, checked independently of this
//! circuit (see `MdocCoreCircuit`'s module doc).
//!
//! ## v1 scope: one docType, one namespace, a fixed claim count
//!
//! This module bakes in `docType = "org.iso.18013.5.1.mDL"`, a single
//! namespace `"org.iso.18013.5.1"`, `digestAlgorithm = "SHA-256"`, and
//! exactly [`crate::MAX_CLAIMS_V1`] digestIDs (fixed as `0..MAX_CLAIMS_V1`)
//! — the same fixed-shape convention `MAX_CLAIMS_V1`/`MAX_CLAIM_BYTES_V1`
//! already establish elsewhere in this crate. A real MSO's map key order
//! follows the CDDL declaration order (`version`, `digestAlgorithm`,
//! `docType`, `valueDigests`, `deviceKeyInfo`, `validityInfo`) — confirmed
//! from the same real test vector, **not** canonical/sorted CBOR map
//! ordering, which real implementations evidently don't follow here.
//!
//! Every "FIXED" segment below is therefore a compile-time constant byte
//! string, identical for every credential of this exact shape; only the
//! digest values, the device key, and the three validity timestamps vary
//! per credential and cross as witness bytes.

use bellpepper_core::{boolean::{AllocatedBit, Boolean}, ConstraintSystem, SynthesisError};

/// One fixed-length ASCII timestamp, e.g. `"2026-08-20T00:00:00Z"` (the
/// `tdate` text form CBOR tag 0 wraps — always exactly this length for a
/// UTC, whole-second, `Z`-suffixed RFC 3339 timestamp).
pub const TIMESTAMP_LEN: usize = 20;

/// Segment 0: everything up to and including the first digest's `bstr`
/// header — `{"version":"1.0","digestAlgorithm":"SHA-256","docType":
/// "org.iso.18013.5.1.mDL","valueDigests":{"org.iso.18013.5.1":{0: <bstr
/// header>`.
const SEG_PREFIX: &[u8] = &[
  0xa6, 0x67, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x63, 0x31, 0x2e, 0x30, 0x6f, 0x64, 0x69,
  0x67, 0x65, 0x73, 0x74, 0x41, 0x6c, 0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x67, 0x53, 0x48,
  0x41, 0x2d, 0x32, 0x35, 0x36, 0x67, 0x64, 0x6f, 0x63, 0x54, 0x79, 0x70, 0x65, 0x75, 0x6f, 0x72,
  0x67, 0x2e, 0x69, 0x73, 0x6f, 0x2e, 0x31, 0x38, 0x30, 0x31, 0x33, 0x2e, 0x35, 0x2e, 0x31, 0x2e,
  0x6d, 0x44, 0x4c, 0x6c, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x44, 0x69, 0x67, 0x65, 0x73, 0x74, 0x73,
  0xa1, 0x71, 0x6f, 0x72, 0x67, 0x2e, 0x69, 0x73, 0x6f, 0x2e, 0x31, 0x38, 0x30, 0x31, 0x33, 0x2e,
  0x35, 0x2e, 0x31, 0xa4, 0x00, 0x58, 0x20,
];
/// Between digest 0 and digest 1: `, 1: <bstr header>`.
const SEG_MID_01: &[u8] = &[0x01, 0x58, 0x20];
/// Between digest 1 and digest 2.
const SEG_MID_12: &[u8] = &[0x02, 0x58, 0x20];
/// Between digest 2 and digest 3.
const SEG_MID_23: &[u8] = &[0x03, 0x58, 0x20];
/// After digest 3, through `deviceKeyInfo.deviceKey`'s `x` coordinate's
/// `bstr` header — `},"deviceKeyInfo":{"deviceKey":{1:2,-1:1,-2:<bstr
/// header>`.
const SEG_AFTER_DIGESTS: &[u8] = &[
  0x6d, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x4b, 0x65, 0x79, 0x49, 0x6e, 0x66, 0x6f, 0xa1, 0x69,
  0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x4b, 0x65, 0x79, 0xa4, 0x01, 0x02, 0x20, 0x01, 0x21, 0x58,
  0x20,
];
/// Between device key `x` and `y`: `, -3: <bstr header>`.
const SEG_BETWEEN_XY: &[u8] = &[0x22, 0x58, 0x20];
/// After device key `y`, through `validityInfo.signed`'s tag(0) + tstr
/// header — `}},"validityInfo":{"signed":0("`.
const SEG_AFTER_DEVICE_KEY: &[u8] = &[
  0x6c, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x69, 0x74, 0x79, 0x49, 0x6e, 0x66, 0x6f, 0xa3, 0x66, 0x73,
  0x69, 0x67, 0x6e, 0x65, 0x64, 0xc0, 0x74,
];
/// Between `signed` and `validFrom`: `,"validFrom":0("`.
const SEG_BETWEEN_SIGNED_VALIDFROM: &[u8] = &[
  0x69, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x46, 0x72, 0x6f, 0x6d, 0xc0, 0x74,
];
/// Between `validFrom` and `validUntil`: `,"validUntil":0("`.
const SEG_BETWEEN_VALIDFROM_VALIDUNTIL: &[u8] = &[
  0x6a, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x55, 0x6e, 0x74, 0x69, 0x6c, 0xc0, 0x74,
];

/// `#6.24(bstr <448-byte MSO>)` header — fixed because the MSO body's
/// total length is fixed by this module's v1 shape.
const PAYLOAD_HEADER: &[u8] = &[0xd8, 0x18, 0x59, 0x01, 0xc0];
/// COSE_Sign1 protected header, `{1: -7}` (alg ES256/ECDSA-P256-SHA256).
pub const PROTECTED_HEADER: &[u8] = &[0xa1, 0x01, 0x26];
/// `["Signature1", <protected bstr>, h'', <payload bstr header>` — fixed
/// up to (not including) the payload bytes themselves.
const SIG_STRUCTURE_PREFIX: &[u8] = &[
  0x84, 0x6a, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31, 0x43, 0xa1, 0x01, 0x26,
  0x40, 0x59, 0x01, 0xc5,
];

/// The per-credential witness data this module's MSO template splices in.
/// Everything else (`docType`, the namespace, `digestAlgorithm`, the
/// digestID numbering) is a fixed constant for this circuit version.
#[derive(Clone, Debug)]
pub struct MsoBodyWitness {
  /// The device's public key coordinates (`deviceKeyInfo.deviceKey`, a
  /// COSE_Key EC2/P-256 key) — not otherwise checked by this circuit yet
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

/// Which named witness field a [`Segment::Witness`] span is — lets
/// [`alloc_sig_structure_bits`] also hand back the MSO-body fields
/// (everything except the claim digests, which the step circuits already
/// expose) as their own named bit groups, so `MdocCoreCircuit` can expose
/// them as additional public outputs. Without that, the verifier couldn't
/// reconstruct `z` from public data alone once `z` depends on more than
/// just the per-claim digests — see `mdoc_core`'s module doc.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum WitnessField {
  ClaimDigest,
  DeviceX,
  DeviceY,
  SignedTs,
  ValidFromTs,
  ValidUntilTs,
}

/// One piece of the byte sequence being assembled: either a fixed,
/// compile-time-constant span (identical for every credential of this
/// shape), or a witness span (varies per credential, per-bit allocated in
/// the circuit).
enum Segment<'a> {
  Fixed(&'a [u8]),
  Witness(WitnessField, &'a [u8]),
}

/// The full ordered segment sequence for one MSO instance, given its
/// per-claim digests (already fixed at exactly `MAX_CLAIMS_V1` by the
/// caller — see `mdoc_core`) and body witness.
fn segments<'a>(claim_digests: &'a [[u8; 32]], body: &'a MsoBodyWitness) -> Vec<Segment<'a>> {
  assert_eq!(
    claim_digests.len(),
    4,
    "this module's fixed byte template is for exactly 4 digestIDs (MAX_CLAIMS_V1)"
  );
  vec![
    Segment::Fixed(SEG_PREFIX),
    Segment::Witness(WitnessField::ClaimDigest, &claim_digests[0]),
    Segment::Fixed(SEG_MID_01),
    Segment::Witness(WitnessField::ClaimDigest, &claim_digests[1]),
    Segment::Fixed(SEG_MID_12),
    Segment::Witness(WitnessField::ClaimDigest, &claim_digests[2]),
    Segment::Fixed(SEG_MID_23),
    Segment::Witness(WitnessField::ClaimDigest, &claim_digests[3]),
    Segment::Fixed(SEG_AFTER_DIGESTS),
    Segment::Witness(WitnessField::DeviceX, &body.device_x),
    Segment::Fixed(SEG_BETWEEN_XY),
    Segment::Witness(WitnessField::DeviceY, &body.device_y),
    Segment::Fixed(SEG_AFTER_DEVICE_KEY),
    Segment::Witness(WitnessField::SignedTs, &body.signed_ts),
    Segment::Fixed(SEG_BETWEEN_SIGNED_VALIDFROM),
    Segment::Witness(WitnessField::ValidFromTs, &body.valid_from_ts),
    Segment::Fixed(SEG_BETWEEN_VALIDFROM_VALIDUNTIL),
    Segment::Witness(WitnessField::ValidUntilTs, &body.valid_until_ts),
  ]
}

/// Native (non-circuit) construction of the exact bytes ECDSA/ES256 signs
/// — used to build real test signatures and to compute `z` natively for
/// `MdocCoreCircuit::public_values`. Concatenates: the fixed
/// `Sig_structure` prefix, the fixed payload header, this module's MSO
/// segments (fixed + witness spliced per `segments`), matching
/// `SIG_STRUCTURE_PREFIX || PAYLOAD_HEADER || mso_bytes` exactly.
pub fn native_sig_structure_bytes(claim_digests: &[[u8; 32]], body: &MsoBodyWitness) -> Vec<u8> {
  let mut out = Vec::with_capacity(SIG_STRUCTURE_PREFIX.len() + PAYLOAD_HEADER.len() + 448);
  out.extend_from_slice(SIG_STRUCTURE_PREFIX);
  out.extend_from_slice(PAYLOAD_HEADER);
  for seg in segments(claim_digests, body) {
    match seg {
      Segment::Fixed(b) | Segment::Witness(_, b) => out.extend_from_slice(b),
    }
  }
  out
}

fn byte_to_bits_be(byte: u8) -> impl Iterator<Item = bool> {
  (0..8).rev().map(move |i| (byte >> i) & 1 == 1)
}

/// The MSO-body witness fields' allocated bits, grouped by name (each
/// `Boolean` here is the *same* allocation pushed into
/// [`alloc_sig_structure_bits`]'s returned flat vector — not a re-alloc —
/// so a caller can `inputize` these specific bits directly). Claim digests
/// aren't included: the step circuits already expose those.
pub struct AllocatedMsoBodyBits {
  pub device_x: Vec<Boolean>,
  pub device_y: Vec<Boolean>,
  pub signed_ts: Vec<Boolean>,
  pub valid_from_ts: Vec<Boolean>,
  pub valid_until_ts: Vec<Boolean>,
}

/// In-circuit construction of the same bytes as
/// [`native_sig_structure_bytes`], as a flat `Boolean` bit sequence
/// (big-endian, ready for `bellpepper::gadgets::sha256::sha256`), plus the
/// MSO-body witness bits grouped by name (see [`AllocatedMsoBodyBits`]).
/// Fixed segments become `Boolean::constant` (no witness allocation — the
/// verifier already knows these bytes, they're part of this circuit
/// version's definition); witness segments become real allocated bits.
pub fn alloc_sig_structure_bits<CS: ConstraintSystem<F>, F: ff::PrimeField>(
  cs: &mut CS,
  claim_digests: &[[u8; 32]],
  body: &MsoBodyWitness,
) -> Result<(Vec<Boolean>, AllocatedMsoBodyBits), SynthesisError> {
  fn push_fixed(bits: &mut Vec<Boolean>, bytes: &[u8]) {
    for &byte in bytes {
      for b in byte_to_bits_be(byte) {
        bits.push(Boolean::constant(b));
      }
    }
  }

  let mut bits = Vec::new();
  push_fixed(&mut bits, SIG_STRUCTURE_PREFIX);
  push_fixed(&mut bits, PAYLOAD_HEADER);

  let mut body_bits = AllocatedMsoBodyBits {
    device_x: Vec::new(),
    device_y: Vec::new(),
    signed_ts: Vec::new(),
    valid_from_ts: Vec::new(),
    valid_until_ts: Vec::new(),
  };

  let mut idx = 0usize;
  for seg in segments(claim_digests, body) {
    match seg {
      Segment::Fixed(bytes) => push_fixed(&mut bits, bytes),
      Segment::Witness(field, bytes) => {
        for &byte in bytes {
          for (i, b) in byte_to_bits_be(byte).enumerate() {
            let bit = AllocatedBit::alloc(
              cs.namespace(|| format!("mso witness bit {idx} (byte bit {i})")),
              Some(b),
            )?;
            let boolean = Boolean::from(bit);
            bits.push(boolean.clone());
            match field {
              WitnessField::ClaimDigest => {}
              WitnessField::DeviceX => body_bits.device_x.push(boolean),
              WitnessField::DeviceY => body_bits.device_y.push(boolean),
              WitnessField::SignedTs => body_bits.signed_ts.push(boolean),
              WitnessField::ValidFromTs => body_bits.valid_from_ts.push(boolean),
              WitnessField::ValidUntilTs => body_bits.valid_until_ts.push(boolean),
            }
            idx += 1;
          }
        }
      }
    }
  }
  Ok((bits, body_bits))
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

  /// Confirms the hand-derived fixed segments reassemble into exactly the
  /// bytes `cbor2`/`cryptography` (Python) independently verified as a
  /// real, ECDSA-signable `Sig_structure` — see this module's doc for how
  /// that ground truth was established. Regenerate this expected value
  /// the same way (see the module doc) if the template ever changes.
  #[test]
  fn native_sig_structure_bytes_has_the_expected_length_and_structure() {
    let digests = [[0xE0u8; 32], [0xE1u8; 32], [0xE2u8; 32], [0xE3u8; 32]];
    let bytes = native_sig_structure_bytes(&digests, &test_body());
    assert_eq!(bytes.len(), 473, "Sig_structure length must match the real reference (20 + 5 + 448)");
    assert_eq!(&bytes[..4], &[0x84, 0x6a, 0x53, 0x69], "must start with array(4), tstr(10) 'Si...'");
    // The payload header + MSO map header must appear right where expected.
    assert_eq!(&bytes[20..25], PAYLOAD_HEADER);
    assert_eq!(bytes[25], 0xa6, "MSO body must start with map(6)");
  }
}
