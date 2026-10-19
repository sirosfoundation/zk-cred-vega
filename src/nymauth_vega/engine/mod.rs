// SPDX-License-Identifier: BSD-2-Clause
//! The nym_auth statement for mdoc credentials, proved with Vega: the holder proves an age range
//! and reveals a verifier-specific pseudonym without showing the credential.
//!
//! Provenance: ported from the `vega-age` crate and the `nymauth-vega` reference program of our own
//! `nym-auth-circuits` archive (SPEC.md sections V1 to V6), mdoc only. It sits on top of the
//! Microsoft reference prover (`vega-prover`) and uses only its public API; see the README,
//! "The vega-prover boundary", and `tests/nymauth_boundary.rs`, which guards it.
//!
//! [`statement`] is the application-facing API: keys from the circuits as data, `prove` and
//! `verify` over plain bytes, and the table of approved circuit versions. The other modules are the
//! circuits and the witness it is built from, following the structure that the Vega specification
//! gives a computation:
//!
//! | Module | Role | Specification |
//! | --- | --- | --- |
//! | [`table`] | The shared table of signed blocks and hash states | 5.3, 5.4 |
//! | [`step`] | The step circuit, one SHA-256 compression at a public position | 4.2, 5.3 |
//! | [`mdoc`] | The core circuit, with the checks that happen once | 4.2, 5.3 |
//! | [`presentation`] | The presentation-specific rules and the public values of the core | 4.4, 5.4, 5.6 |
//! | [`request`] | The patterns of the credential type and the attribute name the verifier asks for | 4.4, 5.4 |
//! | [`app`] | Setup, the witness, proving and acceptance by the application | 4.3, 4.4, 5.6 |
//! | [`challenge`] | The challenge the device key signs (e2) and the transcript seed, from the verifier's values | |
//! | [`gadgets`] | Rules for bits, selection, byte windows and P-256, and the native values of the costly ones | 5.2, 5.3 |
//! | [`fixtures`] | Test credentials signed with test keys, and a CBOR reader for real ones | |
//!
//! The prover's engine is `vega_prover::provider::T256HyraxEngine`: the curve T-256 with Hyrax
//! commitments. The rules compute in its scalar field, `t256::Scalar` of
//! `vega_prover::provider::pt256`, which is the field of P-256 coordinates, so the rules compute
//! on P-256 points natively. The code names both types as the prover does, with no alias.

// Doctests forbid unsafe code too: `[lints]` does not reach them.
#![doc(test(attr(forbid(unsafe_code))))]

pub mod app;
pub mod challenge;
pub mod fixtures;
pub mod gadgets;
pub mod mdoc;
pub mod presentation;
pub mod pseudonym;
pub mod request;
pub mod statement;
pub mod step;
pub mod table;
