# zk-cred-vega

mdoc selective-disclosure circuits and mobile (Kotlin/Swift) bindings built
on top of Microsoft's [`vega-prover`](https://github.com/microsoft/vega-prover)
ZK proving engine (NeutronNova-folding Spartan over R1CS, no trusted setup).

`vega-prover` supplies the proving system but has zero credential-specific
code — this crate supplies the mdoc-shaped circuit (one folded "step" per
disclosed/checked mdoc element, verified against the mobile security
object) and the FFI/packaging layer `vega-prover` doesn't ship.

See `~/.claude/plans/analyze-https-microsoft-github-io-vega-p-transient-karp.md`
for the full integration plan (Kotlin-first; Swift deferred).

## Status

**Phase 1 (this checkout): digest-matching circuit plumbing.** Each mdoc
element's `IssuerSignedItem` bytes are hashed in-circuit (SHA-256) and the
digest exposed as a public value, folded across up to `MAX_CLAIMS_V1`
elements via `vega-prover`'s `vega_mc_zkp` (NeutronNova) prover. The core
circuit that will bind these digests to a real, ECDSA-P256-verified MSO
signature is a stub — **a proof from this crate does not yet demonstrate a
validly-signed credential**, only knowledge of preimages matching claimed
digests. See `src/lib.rs`'s module doc and the plan's Phase 2 for the real
ECDSA-P256-in-circuit work still required before this is a credential
presentation proof.

## Build

```
cargo build --lib
cargo test --release
```

`--release` matters for the test: this proving system is slow in debug
builds.
