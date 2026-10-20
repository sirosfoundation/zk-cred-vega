// SPDX-License-Identifier: BSD-2-Clause
//! The challenge the device key signs, as the nym_auth statement requires it.
//!
//! The rules verify the device key's ECDSA signature on a 256-bit digest that the verifier names
//! ([`crate::nymauth_vega::engine::presentation::Public::challenge`]), and they hash nothing for it. The verifier
//! computes the digest from values it knows. The wallet signs the message whose SHA-256 digest it
//! is, with ES256.
//!
//! The device signs DeviceAuthentication, as ISO/IEC 18013-5 (clause 9.1.3) and the
//! PID Rulebook require: the COSE_Sign1 Sig_structure (RFC 9052, clause 4.4) whose detached
//! payload is DeviceAuthenticationBytes, which holds the SessionTranscript, the docType and
//! empty DeviceNameSpaces ([`device_authentication`]).
//!
//! [`dc_api_session_transcript`] builds the SessionTranscript of an OpenID4VP presentation over
//! the Digital Credentials API (OpenID4VP 1.0, appendix B.2.6.2).
//!
//! [`derive`] and [`digest_of_transcript`] are the checked entry points: the way a verifier (and a
//! wallet) derives e2, the challenge digest the device key signs and the proof is bound to, and
//! the transcript seed (the SessionTranscript bytes), exactly per the nym_auth circuits' `SPEC.md`
//! section 3. Shared test vectors: `test-vectors/nymauth/challenge-vectors.json`.

use crate::nymauth_vega::engine::table::sha256;

/// The protected header of the device's COSE_Sign1: the map {1: −7}, the algorithm ES256.
pub const ES256_HEADER: [u8; 3] = [0xa1, 0x01, 0x26];

/// The head of a CBOR data item of major type `major` whose argument is `n` (RFC 8949, clause 3).
fn head(major: u8, n: usize) -> Vec<u8> {
  let m = major << 5;
  let n = n as u64;
  match n {
    0..24 => vec![m | n as u8],
    24..0x100 => vec![m | 24, n as u8],
    0x100..0x1_0000 => [&[m | 25][..], &(n as u16).to_be_bytes()].concat(),
    0x1_0000..0x1_0000_0000 => [&[m | 26][..], &(n as u32).to_be_bytes()].concat(),
    _ => [&[m | 27][..], &n.to_be_bytes()].concat(),
  }
}

/// A CBOR byte string.
fn bytes(content: &[u8]) -> Vec<u8> {
  [head(2, content.len()), content.to_vec()].concat()
}

/// A CBOR text string.
fn text(content: &str) -> Vec<u8> {
  [head(3, content.len()), content.as_bytes().to_vec()].concat()
}

/// Tag 24 on a byte string holding an encoded data item: `bstr .cbor`.
fn embedded(encoded: &[u8]) -> Vec<u8> {
  [head(6, 24), bytes(encoded)].concat()
}

/// The Sig_structure the device signs for an mdoc: `["Signature1", protected, h'', payload]`,
/// where the payload is DeviceAuthenticationBytes, tag 24 on the encoded
/// `["DeviceAuthentication", SessionTranscript, DocType, DeviceNameSpacesBytes]`, and
/// DeviceNameSpacesBytes is tag 24 on the empty map. `session_transcript` is encoded CBOR.
pub fn device_authentication(session_transcript: &[u8], doc_type: &str) -> Vec<u8> {
  let name_spaces = embedded(&[0xa0]);
  let authentication = [
    head(4, 4),
    text("DeviceAuthentication"),
    session_transcript.to_vec(),
    text(doc_type),
    name_spaces,
  ]
  .concat();
  let payload = embedded(&authentication);
  [head(4, 4), text("Signature1"), bytes(&ES256_HEADER), bytes(&[]), bytes(&payload)].concat()
}

/// The mdoc challenge: the digest of [`device_authentication`].
pub fn mdoc(session_transcript: &[u8], doc_type: &str) -> [u8; 32] {
  sha256(&device_authentication(session_transcript, doc_type))
}

/// The SessionTranscript `[null, null, OpenID4VPDCAPIHandover]` of a presentation over the Digital
/// Credentials API. The handover is `["OpenID4VPDCAPIHandover", h]`, where h is the SHA-256 of the
/// encoded `[origin, nonce, jwkThumbprint]`. The thumbprint is the one of the key that encrypts
/// the response, or null for an unencrypted response.
pub fn dc_api_session_transcript(origin: &str, nonce: &str, jwk_thumbprint: Option<&[u8; 32]>) -> Vec<u8> {
  let thumbprint = jwk_thumbprint.map_or(vec![0xf6], |t| bytes(t));
  let info = [head(4, 3), text(origin), text(nonce), thumbprint].concat();
  let handover = [head(4, 2), text("OpenID4VPDCAPIHandover"), bytes(&sha256(&info))].concat();
  [head(4, 3), vec![0xf6, 0xf6], handover].concat()
}

/// The shortest nonce [`derive`] accepts, in characters (96 bits at six bits a character).
pub const MIN_NONCE_CHARS: usize = 16;

/// The longest origin, nonce, docType or client_id accepted, in bytes.
pub const MAX_FIELD_BYTES: usize = 4096;

fn field(name: &str, v: &str) -> Result<(), String> {
  if v.is_empty() {
    return Err(format!("the {name} is empty"));
  }
  if v.len() > MAX_FIELD_BYTES {
    return Err(format!("the {name} is longer than {MAX_FIELD_BYTES} bytes"));
  }
  Ok(())
}

/// `verifier_input = SHA-256(client_id)`, the value the verifier names; refuses an empty or
/// over-long client_id.
pub fn verifier_input(client_id: &str) -> Result<[u8; 32], String> {
  field("client_id", client_id)?;
  Ok(sha256(client_id.as_bytes()))
}

/// The e2 and the transcript seed of one presentation request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
  /// The SessionTranscript bytes: Longfellow's Fiat-Shamir seed, and the input of e2.
  pub session_transcript: Vec<u8>,
  /// e2: SHA-256 of the COSE `Signature1` message the device key signs.
  pub digest: [u8; 32],
}

/// Derives e2 and the transcript seed for an mdoc presentation over the Digital Credentials API
/// (`SPEC.md` section 3): `SessionTranscript = [null, null, ["OpenID4VPDCAPIHandover",
/// SHA-256([origin, nonce, jwkThumbprint])]]`, then e2 = SHA-256 of the device-authentication
/// message for `doc_type`. `jwk_thumbprint` is the 32-byte thumbprint of the response-encryption
/// key, or `None` for CBOR null. Refuses an empty origin or docType, a nonce shorter than
/// [`MIN_NONCE_CHARS`] and a thumbprint that is not 32 bytes: a verifier that derives e2 from a
/// predictable request lets a proof be replayed.
pub fn derive(origin: &str, nonce: &str, doc_type: &str, jwk_thumbprint: Option<&[u8]>) -> Result<Challenge, String> {
  field("origin", origin)?;
  field("nonce", nonce)?;
  field("docType", doc_type)?;
  if nonce.chars().count() < MIN_NONCE_CHARS {
    return Err(format!("the nonce is shorter than {MIN_NONCE_CHARS} characters"));
  }
  let thumbprint: Option<[u8; 32]> = match jwk_thumbprint {
    None => None,
    Some(t) => Some(t.try_into().map_err(|_| format!("the JWK thumbprint is {} bytes, not 32", t.len()))?),
  };
  let session_transcript = dc_api_session_transcript(origin, nonce, thumbprint.as_ref());
  let digest = mdoc(&session_transcript, doc_type);
  Ok(Challenge { session_transcript, digest })
}

/// e2 for a SessionTranscript the caller already holds (a wallet is handed one): checks that it
/// is a definite CBOR array of three items with nothing after it, and that `doc_type` is not
/// empty, then returns the digest of the device-authentication message.
pub fn digest_of_transcript(session_transcript: &[u8], doc_type: &str) -> Result<[u8; 32], String> {
  use crate::nymauth_vega::engine::fixtures::cbor::Item;
  field("docType", doc_type)?;
  let item = Item::read(session_transcript).map_err(|e| format!("the SessionTranscript: {e}"))?;
  if item.bytes.len() != session_transcript.len() {
    return Err("the SessionTranscript has bytes after its end".into());
  }
  if item.major != 4 || item.argument != 3 {
    return Err("the SessionTranscript is not a CBOR array of three items".into());
  }
  Ok(mdoc(session_transcript, doc_type))
}
