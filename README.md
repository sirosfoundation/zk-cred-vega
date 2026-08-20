# zk-cred-vega

mdoc selective-disclosure circuits and mobile (Kotlin first; Swift
deferred) bindings built on top of Microsoft's
[`vega-prover`](https://github.com/microsoft/vega-prover) ZK proving
engine (NeutronNova-folding Spartan over R1CS, no trusted setup).

`vega-prover` supplies the proving system but has zero credential-specific
code — no mdoc circuit, no ECDSA verifier, no mobile bindings, no
distribution mechanism. This crate supplies all of that:

- `ClaimDigestStepCircuit` (`src/lib.rs`) — one folded "step" per
  disclosed/checked mdoc element, hashing its real, variable-length
  `IssuerSignedItem` bytes (`src/sha256_var.rs`) and exposing the digest
  as a public value.
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

**Selective disclosure is real.** Each disclosed claim's plaintext bytes
are exposed as a public value (masked to all-zero when not disclosed);
undisclosed claims are digest-checked but never revealed in plaintext.

**Two independent security review passes have happened** and found real
bugs, all now fixed: two critical ECDSA-gadget soundness bugs (a free
`is_infinity` witness bit and an unbound public key — either alone was a
total signature-forgery break, see `ecdsa.rs`'s module doc) and a
truncation bug in the FFI layer's `qx`/`qy` encoding. Treat this as two
real passes, not a clean bill of health for the crate as a whole — see
below.

**The real-interop gap the second review found is now closed.** This
crate can now prove things about realistic, salted ISO 18013-5 claims —
not just self-fabricated short strings — verified end-to-end against a
generated realistic test mdoc (`test-vectors/`, see below):

- A new variable-length SHA-256 gadget (`src/sha256_var.rs`) computes
  each claim's digest over its *real*, witnessed length, matching a real
  issuer's `valueDigests` computation, rather than zero-padding to a
  fixed width first (which could never match, for any claim, at any
  size — the old bug). `MAX_CLAIM_BYTES_V1` is raised from 64 to 128,
  comfortably fitting real salted `IssuerSignedItemBytes` (measured
  79–95 bytes against a real signed test vector).
- `examples/gen_test_mdocs.rs` mints realistic test credentials (real
  CBOR framing, real ≥16-byte per-element salts, real ECDSA-P256
  signature over the real MSO `Sig_structure`) into `test-vectors/`;
  `tests/real_mdoc_fixtures.rs` drives the full `setup → prep_prove →
  prove → verify → verify_and_check_binding` pipeline against one and
  passes — the load-bearing proof this actually works now, not just the
  math checking out in isolation.

**`sha256_var` is genuinely novel, soundness-critical circuit code and
has NOT had an independent review yet** — flagged explicitly in its own
module doc. Treat it with the same caution the ECDSA gadget warranted
before its review found two critical bugs.

**Other known gaps:**

- **Selective disclosure only withholds plaintext, not the digest** — an
  undisclosed claim's digest is still exposed (needed for the signature
  binding). Real ISO 18013-5 salting (which this crate now correctly
  carries through, since real salted items fit) means this digest can't
  be trivially dictionary-attacked *if the salt is present* — but this is
  a separate confidentiality/unlinkability question (stable digests
  across verifiers/presentations) that the interop fix doesn't address
  on its own. See `HANDOFF.md`.
- **`mso.rs` hardcodes `digestID`s `0..MAX_CLAIMS_V1`**, and — a deeper
  issue than the literal values — nothing in the circuit currently binds
  the digestID used as an MSO map key to the `digestID` field embedded
  inside the corresponding `IssuerSignedItem`'s own CBOR bytes, which a
  real verifier does cross-check. `examples/gen_test_mdocs.rs` keeps the
  two consistent by construction (both come from the same loop index),
  but the circuit itself doesn't enforce it yet.
- **Fixed circuit shape**: exactly 4 claims, one P-256 signer
  (`MAX_CLAIMS_V1`/`MAX_CLAIM_BYTES_V1` in `src/lib.rs`).
- ECDSA `r`/`s` aren't range-checked to `[1, n-1]`, and the non-native
  mod-`n` reduction isn't provably unique — not exploitable for forgery
  given how this circuit is used, but a real gap versus "this fully
  implements FIPS 186 ECDSA verification."
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

To regenerate the realistic test mdoc fixture and run the full-pipeline
test against it:

```
cargo run --release --example gen_test_mdocs   # writes test-vectors/*.json
cargo test --release --test real_mdoc_fixtures
```

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
