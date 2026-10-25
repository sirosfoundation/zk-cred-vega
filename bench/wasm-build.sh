#!/usr/bin/env bash
# Builds the in-page nymauth prover (src/nymauth_vega/js_api.rs) as measured in the WASM benchmark.
#   bench/wasm-build.sh <st|wide|mt> <out dir>
# st: single-threaded; wide: single-threaded with +wide-arithmetic (i64.mul_wide_u, i64.add128, ...),
# which needs a runtime with WebAssembly wide arithmetic (Chromium 156: --js-flags=--wasm-wide-arithmetic);
# mt: rayon on Web Workers (feature wasm-threads), for a cross-origin isolated page.
# WASM_OPT must be binaryen 133 or later for the wide variant (binaryen 116 predates it).
set -euo pipefail
variant=$1 out=$2
cd "$(dirname "$0")/.."
extra=()
case $variant in
  st)   export RUSTFLAGS='' ;;
  wide) export RUSTFLAGS='-C target-feature=+wide-arithmetic' ;;
  # rustc 1.99 links wasm32-unknown-unknown + atomics with unshared memory unless the linker gets
  # the shared-memory and TLS arguments. build-std needs rust-src and nightly features. The
  # measured build declared 4 GiB; the prover peaked at 462 MiB, so 1 GiB is enough.
  mt)   export RUSTFLAGS='-C target-feature=+atomics,+bulk-memory -C link-arg=--shared-memory -C link-arg=--import-memory -C link-arg=--max-memory=4294967296 -C link-arg=--export=__wasm_init_tls -C link-arg=--export=__tls_size -C link-arg=--export=__tls_align -C link-arg=--export=__tls_base'
        export RUSTC_BOOTSTRAP=1 CARGO_UNSTABLE_BUILD_STD=panic_abort,std
        extra=(-- --features wasm-threads) ;;
  *) echo "variant must be st, wide or mt" >&2; exit 2 ;;
esac
export CARGO_TARGET_DIR="target-wasm-$variant"
wasm-pack build --release --no-opt --target web --out-dir "$out" --out-name vega "${extra[@]}"
"${WASM_OPT:-wasm-opt}" -O3 "$out/vega_bg.wasm" -o "$out/vega_bg.wasm"
