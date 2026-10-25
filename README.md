# zk-cred-vega

<div align="center">

[![CI](https://github.com/sirosfoundation/zk-cred-vega/actions/workflows/ci.yml/badge.svg)](https://github.com/sirosfoundation/zk-cred-vega/actions/workflows/ci.yml)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=sirosfoundation_zk-cred-vega&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=sirosfoundation_zk-cred-vega)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/sirosfoundation/zk-cred-vega/badge)](https://scorecard.dev/viewer/?uri=github.com/sirosfoundation/zk-cred-vega)
[![License: BSD-2-Clause](https://img.shields.io/badge/License-BSD--2--Clause-blue.svg)](LICENSE)

</div>

> [!WARNING]
> **Experimental. Do not use in production.**
>
> This is unaudited research code implementing novel zero-knowledge
> circuits. It has not had an independent security review, its proving
> parameters are not published for production use, and its on-disk and
> wire formats will change without notice. Do not rely on it to protect
> real credentials or real users.

Zero-knowledge selective disclosure for ISO/IEC 18013-5 mdoc credentials,
built on Microsoft's [`vega-prover`][vega] proving engine
(NeutronNova-folding Spartan over R1CS, no trusted setup).

`vega-prover` supplies the proof system but no credential-specific code.
This crate adds the mdoc parts:

- **Per-claim digest circuit** — one folded proof step per mdoc element,
  hashing its real, variable-length `IssuerSignedItem` bytes.
- **Issuer signature circuit** — in-circuit ECDSA-P256 verification over
  the real COSE_Sign1 `Sig_structure` a verifier checks, binding the
  claim digests to the issuer's signature.
- **Selective disclosure** — disclosed claims reveal their plaintext;
  undisclosed claims are proven consistent without being revealed.
- **Mobile bindings** — a UniFFI surface (`--features uniffi`) plus
  Android cross-compilation and AAR packaging.

[vega]: https://github.com/microsoft/vega-prover

## Build

```bash
cargo build --lib
cargo test --release   # --release matters; proving is slow in debug builds
```

UniFFI bindings and Android packaging:

```bash
cargo build --release --features uniffi
make bindings-kotlin   # generates bindings/kotlin/
make aar               # cross-compiles for Android and packages an AAR
```

Proving/verifying keys are produced by a one-off setup run:

```bash
make dump-setup        # writes target/setup-artifacts/
```

## nymauth (age range and pseudonym)

`zk_cred_vega::nymauth_vega` (exported through UniFFI as `nymauthVegaLoadKeys`, `nymauthVegaProve`,
`nymauthVegaVerify`, `nymauthDeriveChallenge`, `nymauthChallengeDigest`, `nymauthVerifierInput`, the same names and rules as zk-cred-longfellow) is the native
prover and verifier of the `vega-nymauth` catalog circuits: from an mdoc of docType
`eu.europa.ec.eudi.nym_auth.1` the holder proves an age range and reveals a verifier-specific
pseudonym. It is its own module, separate from the generic mdoc/age entry points above.

**Layout.** The engine (circuits, witness, `statement` API) is the module
`src/nymauth_vega/engine`, the FFI layer is `src/nymauth_vega.rs`, and the plain C ABI for Go is
`src/nymauth_go_ffi.rs` with `include/zk_cred_vega_nymauth_go.h` and a cgo wrapper in
`go/nymauth` (`make go-test-nymauth`). A module, not a workspace member: the Makefile and the
release workflow read `cargo metadata`'s first package, and one crate keeps every artifact
(AAR, XCFramework, Go library) built from one root. The module keeps the nymauth code apart from
the generic mdoc/age code, and `tests/nymauth_boundary.rs` enforces the separation.

**Provenance and licence.** Ported from the `vega-age` crate and the `nymauth-vega` reference
program of our own `nym-auth-circuits` archive (SPEC.md V1 to V6), mdoc only. BSD-2-Clause, as the
rest of this crate. The archive's SD-JWT circuits and fixtures were not ported (they are not
exposed: the SD-JWT challenge needs the request's nonce, client_id and origin).

### The vega-prover boundary

The nymauth code sits on top of Microsoft's reference prover and does not alter it: this crate
depends on `vega-prover` as a plain git dependency (no `path`, `[patch]` or `[replace]`), and the
engine uses only these public items:

| Item | Used for |
| --- | --- |
| `provider::T256HyraxEngine`, `provider::pt256::t256` | the engine and its scalar field (P-256 coordinates) |
| `traits::circuit::VegaCircuit` | the step and core circuits implement it |
| `bellpepper::{shape_cs::ShapeCS, r1cs::VegaShape, solver::SatisfyingAssignment}` | circuit shapes and the hand-written witness |
| `vega_mc_zkp::{VegaMcZkSNARK, VegaMcProverKey, VegaMcVerifierKey, VegaMcPrepZkSNARK}` | multi-circuit setup, prepare, prove, verify |
| `errors::VegaError` | the prover's error type |

`tests/nymauth_boundary.rs` fails if the engine names any other `vega_prover::` item, if engine
code refers to this crate's generic mdoc/age modules, or if `Cargo.toml` or `.cargo/config.toml`
overrides the prover (path, patch, replace) or `Cargo.lock` locks it from anywhere but git. Add an
item to that list, and to this table, only on purpose.

### Using it

- The catalog artifact is the circuit's *shapes*, not keys: `nymauthVegaLoadKeys(shapes)` runs setup
  once (about 0.1 s on 12 threads, 0.5 s on one) and returns the resident handle.
- `nymauthVegaProve(keys, statement, holder)` returns the proof (96,079 bytes) and the pseudonym; it
  refuses with a coarse code instead of making a proof no verifier would accept, and zeroes its copy
  of `secret_seed`. `nymauthVegaVerify(keys, statement, proof)` returns the pseudonym or a typed
  error.
- **Integration contract.** `time`, `challenge_digest` (e2) and `verifier_input` must be computed by
  the verifier (its clock, the request it issued, its own identifier), never taken from the holder
  or the presentation; `issuer_key_*` must be the key the verifier trusts for the issuer.
- **Deriving e2 and the transcript seed.** `nymauthDeriveChallenge(origin, nonce, docType,
  jwkThumbprint?)` returns the SessionTranscript (the transcript seed) and e2 exactly per the
  circuits' SPEC.md section 3; `nymauthChallengeDigest(sessionTranscript, docType)` gives e2
  for a transcript already in hand. They refuse an empty origin or docType, a nonce under 16
  characters, any field over 4096 bytes, a thumbprint that is not 32 bytes, and an empty or malformed
  (not one definite CBOR array of three items, nothing after it) transcript. `nymauthVerifierInput(clientId)`
  is SHA-256(client_id). Shared test
  vectors, byte-identical in zk-cred-longfellow: `test-vectors/nymauth/challenge-vectors.json` (the files of that directory are listed in its README.md; the redirect / QR handover vectors are in `derive_redirect` and `rejects_redirect`).
- **Pinned circuit, and adding a circuit version.** Only shapes whose SHA-256 is in
  `nymauth_vega::engine::statement::APPROVED_SHAPES` load (`UnknownCircuit` otherwise). The table
  entry holds everything circuit-specific: digest, layout, docType, birth-date and `ssc` element
  names. To approve a new circuit version, append one `ApprovedCircuit` entry there. Nothing else
  names a digest or docType. (A circuit whose code changed also needs the engine's circuit code to
  match; `statement::shapes()` builds the shapes of this repository's code and a test pins them to
  the first entry.)
- **Rulebook range.** With both age bounds given the window must be at least 365 days and
  `le >= ge`; otherwise `InvalidInput`.
- **Verification outcomes.** A proof past the cap, undecodable or with bytes after its end is
  `ProofEncoding`; one that does not verify, or whose step instance reports another position, is
  `ProofInvalid`; one that verifies for other public values than the named ones is `Mismatch`.
  These are the system rulebook's `proof_encoding`, `proof_invalid` and `public_input`.
- **Coarse refusals.** `Refused` carries `SeedMismatch`, `IssuerSignature`, `DeviceSignature` or
  `Credential`, never the broken rule (the rule path is available with `--features debug-rules`).
- **Issuer profile and key.** Attribute names are unique under the nym_auth issuance profile. The
  circuit does not check that the issuer key is a P-256 point (a gap for the circuit authors); the
  library checks it on the host.
- **Limits.** `IssuerSigned` at most 64 KiB, CBOR depth at most 32, proofs at most 512 KiB with no
  trailing bytes, shapes validated for consistency before any allocation. The witness's tables and
  value lists are wiped when dropped and the seed copy is zeroed; copies inside the prover's own
  state are not reachable from this crate.
- mdoc only.

### Go (cgo)

`make go-cabi` stages the library and both headers; `include/zk_cred_vega_nymauth_go.h` describes
the nymauth C ABI (`load_keys`, `verify`, `prove`, `derive_challenge`, `challenge_digest`, free
functions, status codes; every entry point is panic-safe and validates pointers and lengths).
`go/nymauth` wraps it for cgo; `make go-test-nymauth` runs its smoke test over the credential
fixtures (needs the `zstd` tool for `shapes.zst`).

### Coverage

CI measures coverage for SonarCloud (`.github/workflows/sonarcloud.yml`): Rust with
`cargo llvm-cov --lib --test 'nymauth_*'` (lcov, `sonar.rust.lcov.reportPaths`) and Go with
`go test -coverprofile` (`sonar.go.coverage.reportPaths`). Test helpers (`tests/`, `*_test.go`, the
`engine/fixtures` credential builders) are excluded from coverage. Locally:
`cargo llvm-cov --release --lib --test 'nymauth_*'`. Measured line coverage of the nymauth code:
94% (every non-fixture file at least 90%); Go wrapper 94%.

### Tests

`tests/nymauth_vega_e2e.rs` (binding over the fixtures), `tests/nymauth_engine_fixture.rs` and
`tests/nymauth_hardening.rs` (engine: tamper, pinning, range rule, parsing, residue),
`tests/nymauth_challenge_vectors.rs`, `tests/nymauth_go_abi.rs`, `tests/nymauth_boundary.rs`, and
`go/nymauth`. Fixtures: `test-vectors/nymauth/` (the reference credential, the published shapes and
the archive's own proof).

## License

[BSD-2-Clause](LICENSE).
