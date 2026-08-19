# zk-cred-vega

mdoc selective-disclosure circuits and mobile (Kotlin first; Swift
deferred) bindings built on top of Microsoft's
[`vega-prover`](https://github.com/microsoft/vega-prover) ZK proving
engine (NeutronNova-folding Spartan over R1CS, no trusted setup).

`vega-prover` supplies the proving system but has zero credential-specific
code — no mdoc circuit, no ECDSA verifier, no mobile bindings, no
distribution mechanism. This crate supplies all of that:

- `ClaimDigestStepCircuit` (`src/lib.rs`) — one folded "step" per
  disclosed/checked mdoc element, hashing its `IssuerSignedItem` bytes and
  exposing the digest as a public value.
- `MdocCoreCircuit` (`src/mdoc_core.rs`) — a real, in-circuit ECDSA-P256
  signature verification (`src/ecdsa.rs`, `src/p256_ecc.rs`,
  `src/nonnative/`), binding those digests to the issuer's signature.
- `src/ffi_api.rs` — a UniFFI-exported surface (`feature = "uniffi"`) for
  the native SDKs, plus a `Makefile` for Android cross-compilation and AAR
  packaging (`cargo-ndk`, mirroring `zk-cred-longfellow`'s own).

## Status

**A full presentation proof round-trips through the real `vega-prover`
NeutronNova pipeline** (`setup → prep_prove → prove → verify`), verified
against a real P-256 signature, including the fold-and-reuse path
(`prep_prove` once, `prove` reused across presentations to different
verifiers) and a UniFFI round trip through the actual exported functions.
Android cross-compile, AAR packaging, and a `go-zk-circuits` catalog
publication (currently `--unpublished`) are done.

**Not yet done, and important if you're evaluating this crate:**

- **Not real ISO 18013-5 MSO framing.** The ECDSA message digest is
  currently `SHA-256` of the concatenated per-claim digests — a
  representative stand-in, not a real MSO `Sig_structure`/COSE_Sign1
  wrapper (no docType/digestAlgorithm/validityInfo/deviceKeyInfo framing,
  no `x5chain`-based issuer key). Proofs from this crate are **not**
  spec-compliant mdoc presentations yet. See `mdoc_core.rs`'s module doc.
- **No independent security review** of the ECDSA/BigNat/EC-point
  gadgets. Flagged explicitly in `ecdsa.rs`'s and `p256_ecc.rs`'s own
  module docs.
- **Fixed circuit shape**: exactly 4 claims, 64 bytes max per claim, one
  P-256 signer (`MAX_CLAIMS_V1`/`MAX_CLAIM_BYTES_V1` in `src/lib.rs`).
  Real mdoc elements exceeding 64 bytes (portraits, etc.) aren't
  supported by this circuit version.
- iOS/XCFramework packaging doesn't exist yet — Android only, per
  "Kotlin first."

`mdoc_core.rs`'s module doc also documents a real, previously-undocumented
`vega-prover` correctness gotcha found while building this
(`is_small` must be `false` once a circuit's witness includes large field
elements, or `verify()` silently fails despite every constraint being
individually satisfied) — worth reading before extending either circuit.

## Build

```
cargo build --lib
cargo test --release
```

`--release` matters for the tests: this proving system is slow in debug
builds.

To build the UniFFI layer and generate Kotlin bindings:

```
cargo build --release --features uniffi
make bindings-kotlin   # generates bindings/kotlin/ (gitignored, vendored by SDK repos)
make aar                # cross-compiles for Android + packages an AAR
```
