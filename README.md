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

## License

[BSD-2-Clause](LICENSE).
