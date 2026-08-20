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

**⚠️ The most important caveat, found by the second review: this crate
cannot yet prove anything about a real, already-issued mdoc.** Every
test here uses self-fabricated claim bytes the same test also signs.
Verified directly against a real signed test vector
(`zk-cred-longfellow/test-vectors/mdoc_zk/v6_v7_1attr_issue_date.json`):

- Real ISO 18013-5 `IssuerSignedItemBytes` (tag+bstr-wrapped, per spec)
  for ordinary attributes run **79–95 bytes** — every real attribute
  tested exceeds `MAX_CLAIM_BYTES_V1 = 64` and gets rejected outright.
  This isn't a "large fields like portraits excluded" limitation; it's
  *all* real attributes, because the mandatory ≥16-byte per-element salt
  plus CBOR overhead alone exceeds 64 bytes.
- Independent of that limit: this circuit hashes claim bytes *zero-
  padded* to a fixed width, while a real issuer hashes the *exact,
  unpadded* bytes for `valueDigests`. Raising the byte limit doesn't fix
  this — it only changes which items get a silently wrong digest instead
  of none of them. A real fix needs a variable-length-aware in-circuit
  SHA-256 (real length as a witness, SHA-256's own padding applied at
  the right position), not a bigger fixed buffer.
- `mso.rs` also hardcodes `digestID`s `0..MAX_CLAIMS_V1`; real credentials
  assign arbitrary issuer-chosen `digestID`s.
- This also has a confidentiality consequence: an *undisclosed* claim's
  digest is still exposed (it has to be, for the signature binding).
  Combined with the size limit above, the only claim shapes that
  currently fit this circuit are short, unsalted ones — exactly the
  shapes a digest dictionary-attack works against.

None of this is a soundness bug in the reviewed sense (a forged proof) —
it's a "this doesn't do the real-world job yet" gap. See `HANDOFF.md`
(or ask for it) for the full writeup and a recommended fix direction.

**Other known gaps:**

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
