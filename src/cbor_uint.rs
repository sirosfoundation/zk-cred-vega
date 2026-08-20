//! Variable-width CBOR unsigned-integer encoding, for ISO 18013-5's
//! `digestID` field.
//!
//! ISO/IEC 18013-5 §9.1.2.4 defines `DigestID = uint` and states: "the
//! value shall be smaller than 2^31," and explicitly directs issuers to
//! avoid correlating digestID assignment across MSOs for the same data
//! element — i.e. a real, spec-compliant issuer is expected to spread
//! digestIDs across the *full* legal range, not cluster them into a
//! small, convenient set. A real signed test vector (OWF/multipaz
//! reference credential) uses values up to 39 in one namespace; the spec
//! itself permits up to `2^31 - 1`.
//!
//! CBOR's major-type-0 (unsigned integer) encoding is inherently
//! variable-width: the value's magnitude determines whether it's 1, 2, 3,
//! or 5 bytes. This module implements exactly that encoding, canonical
//! (minimal-length) form only — this crate's v1 scope doesn't need to
//! accept or produce non-canonical (deliberately over-long) encodings.

/// Largest legal `digestID` value per ISO 18013-5 §9.1.2.4 ("the value
/// shall be smaller than 2^31").
pub const MAX_DIGEST_ID: u32 = (1u32 << 31) - 1;

/// Widest canonical CBOR uint encoding this module supports: `0x1a` +
/// 4 big-endian bytes.
pub const MAX_CBOR_UINT_BYTES: usize = 5;

/// Which of the four canonical CBOR major-type-0 length classes `value`
/// requires: `0` = 1 byte (value embedded in the initial byte, 0–23),
/// `1` = 2 bytes (`0x18` + 1 byte, 24–255), `2` = 3 bytes (`0x19` + 2
/// bytes, 256–65535), `3` = 5 bytes (`0x1a` + 4 bytes, 65536–2^31-1).
pub fn length_class(value: u32) -> usize {
  if value < 24 {
    0
  } else if value < 256 {
    1
  } else if value < 65536 {
    2
  } else {
    3
  }
}

/// Total byte width of length class `class` (`0..=3`, see [`length_class`]).
pub fn class_byte_width(class: usize) -> usize {
  [1, 2, 3, MAX_CBOR_UINT_BYTES][class]
}

/// The canonical (minimal-length) CBOR major-type-0 encoding of `value`.
///
/// Panics if `value > MAX_DIGEST_ID` — this module exists specifically
/// for ISO 18013-5 `digestID`, which the spec bounds; a caller with a
/// larger `uint` to encode needs a different (unbounded) implementation.
pub fn encode_cbor_uint(value: u32) -> Vec<u8> {
  assert!(value <= MAX_DIGEST_ID, "digestID must be < 2^31 per ISO 18013-5 §9.1.2.4, got {value}");
  match length_class(value) {
    0 => vec![value as u8],
    1 => vec![0x18, value as u8],
    2 => {
      let mut v = vec![0x19];
      v.extend((value as u16).to_be_bytes());
      v
    }
    _ => {
      let mut v = vec![0x1a];
      v.extend(value.to_be_bytes());
      v
    }
  }
}

/// Decodes a canonical CBOR major-type-0 unsigned integer at the start of
/// `bytes`, returning `(value, width_in_bytes)`. Returns `None` if the
/// marker byte isn't one of the four recognized forms (major type 0,
/// additional info `0..=23`, `24`, `25`, or `26`) or if `bytes` is too
/// short for the indicated width.
pub fn decode_cbor_uint(bytes: &[u8]) -> Option<(u32, usize)> {
  let marker = *bytes.first()?;
  if marker < 0x18 {
    return Some((marker as u32, 1));
  }
  match marker {
    0x18 => Some((*bytes.get(1)? as u32, 2)),
    0x19 => {
      let b = bytes.get(1..3)?;
      Some((u16::from_be_bytes([b[0], b[1]]) as u32, 3))
    }
    0x1a => {
      let b = bytes.get(1..5)?;
      Some((u32::from_be_bytes([b[0], b[1], b[2], b[3]]), 5))
    }
    _ => None,
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn boundary_values() -> Vec<u32> {
    vec![0, 1, 22, 23, 24, 25, 254, 255, 256, 257, 65534, 65535, 65536, 65537, MAX_DIGEST_ID - 1, MAX_DIGEST_ID]
  }

  #[test]
  fn round_trips_and_widths_match_class_byte_width_at_every_boundary() {
    for v in boundary_values() {
      let encoded = encode_cbor_uint(v);
      let class = length_class(v);
      assert_eq!(encoded.len(), class_byte_width(class), "value={v} class={class}");
      let (decoded, width) = decode_cbor_uint(&encoded).unwrap_or_else(|| panic!("failed to decode value={v}"));
      assert_eq!(decoded, v, "round-trip mismatch for value={v}");
      assert_eq!(width, encoded.len(), "decoded width mismatch for value={v}");
    }
  }

  #[test]
  fn length_class_partition_is_exhaustive_and_boundaries_are_exact() {
    assert_eq!(length_class(0), 0);
    assert_eq!(length_class(23), 0);
    assert_eq!(length_class(24), 1);
    assert_eq!(length_class(255), 1);
    assert_eq!(length_class(256), 2);
    assert_eq!(length_class(65535), 2);
    assert_eq!(length_class(65536), 3);
    assert_eq!(length_class(MAX_DIGEST_ID), 3);
  }

  #[test]
  fn decode_rejects_unrecognized_markers() {
    assert_eq!(decode_cbor_uint(&[0x1b, 0, 0, 0, 0, 0, 0, 0, 0]), None); // major type 0, 8-byte form: out of scope
    assert_eq!(decode_cbor_uint(&[0x40]), None); // major type 2 (bstr), not a uint at all
    assert_eq!(decode_cbor_uint(&[]), None);
  }

  #[test]
  fn decode_rejects_truncated_input() {
    assert_eq!(decode_cbor_uint(&[0x18]), None); // marker present, argument byte missing
    assert_eq!(decode_cbor_uint(&[0x19, 0x01]), None); // needs 2 argument bytes, only 1 present
    assert_eq!(decode_cbor_uint(&[0x1a, 0x01, 0x02, 0x03]), None); // needs 4, only 3 present
  }

  /// Known-answer test against hand-verified real CBOR bytes for a
  /// digestID value taken from the same real signed test vector `mso.rs`
  /// validates its own byte template against (digestID 26 appears there,
  /// encoded as a single byte since it's < 24... wait it's not - 26 >= 24,
  /// so it's the two-byte `0x18 0x1a` form). Cross-checked independently
  /// with Python's `cbor2.dumps(26)` before being hardcoded here.
  #[test]
  fn matches_a_real_cbor_encoder_for_a_real_digest_id_value() {
    assert_eq!(encode_cbor_uint(26), vec![0x18, 0x1a]);
    assert_eq!(decode_cbor_uint(&[0x18, 0x1a]), Some((26, 2)));
  }
}
