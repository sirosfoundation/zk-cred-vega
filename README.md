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

**Real ISO 18013-5 MSO/COSE_Sign1 byte framing.** The ECDSA signature
covers the actual signed structure a verifier checks against a real
mdoc: `Sig_structure(protected_header, external_aad,
payload=#6.24(bstr MSO))`, with the MSO body following its real CDDL
field order (`version`, `digestAlgorithm`, `docType`, `valueDigests`,
`deviceKeyInfo`, `validityInfo`). See `src/mso.rs`'s module doc for how
the byte template was derived and verified against a real signed test
vector, and `mdoc_core.rs`'s module doc for the fixed-template +
witness-splice circuit design (no in-circuit CBOR parser needed).
`x5chain`-based issuer-key trust still happens outside this circuit
(the issuer public key `Q` is a circuit input, not derived from a
certificate chain in-circuit) — same division of responsibility as
Longfellow.

**Not yet done, and important if you're evaluating this crate:**

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

To regenerate the `setup()` prover/verifier keys for publishing to
`go-zk-circuits` (needed any time the circuit shape changes — number of
claims, claim byte limit, or the MSO/ECDSA framing itself):

```
make dump-setup   # writes target/setup-artifacts/vega-mc-p256-v1-{prover,verifier}-key.bin
zstd -19 target/setup-artifacts/vega-mc-p256-v1-prover-key.bin -o ...   # then circuitctl add
```
