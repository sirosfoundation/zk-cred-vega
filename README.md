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

`zk_cred_vega::nymauth_vega` (exported through UniFFI as `nymauthVegaLoadKeys`,
`nymauthVegaProve`, `nymauthVegaVerify`) is the native prover and verifier of the `vega-nymauth`
catalog circuits: from an mdoc of docType `eu.europa.ec.eudi.nym_auth.1` the holder proves an
age range and reveals a verifier-specific pseudonym. It is its own module, separate from the
generic mdoc/age entry points above. The statement, circuits and witness live in the prover fork
(`vega-nymauth`, `nymauth/` of `sirosfoundation/vega-prover`); this crate is the typed FFI layer.

- The catalog artifact is the circuit's *shapes*, not keys: `nymauthVegaLoadKeys(shapes)` runs setup
  once (about 0.1 s on 12 threads, 0.5 s on one) and returns the resident handle.
- `nymauthVegaProve(keys, statement, holder)` returns the proof (96,079 bytes) and the pseudonym; it
  refuses with the first broken rule instead of making a proof no verifier would accept, and zeroes
  its copy of `secret_seed`.
- `nymauthVegaVerify(keys, statement, proof)` returns the pseudonym or a typed error.
- mdoc only; SD-JWT VC is out of scope (its challenge needs the request's nonce, client_id and
  origin).
- Tests: `tests/nymauth_vega_e2e.rs` over `test-vectors/nymauth/` (the reference credential, the
  published shapes and the archive's own proof).
- The dependency pins an unmerged commit of the fork; move it to a merged commit or tag before any
  release.

## License

[BSD-2-Clause](LICENSE).
