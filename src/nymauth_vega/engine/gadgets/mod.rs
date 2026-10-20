// SPDX-License-Identifier: BSD-2-Clause
//! Rules shared by the circuits.
//!
//! | Module | Rules |
//! | --- | --- |
//! | [`lc`] | Weighted sums with their values, products, equalities, choices |
//! | [`bits`] | Range constraints, bytes, comparisons with constants |
//! | [`select`] | The one-hot selector of clause 5.3 |
//! | [`window`] | Reading bytes of a signed message at a private offset |
//! | [`p256`] | P-256 point arithmetic and ECDSA verification |
//! | [`sha256`] | The values of bellpepper's SHA-256 compression, which the step circuit checks |
//! | [`values`] | Values in a witness generator's order, computed natively |

pub mod bits;
pub mod lc;
pub mod p256;
pub mod select;
pub mod sha256;
pub mod values;
pub mod window;
