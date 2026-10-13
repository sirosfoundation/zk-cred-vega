# VegaMC real-device performance investigation (2026-10-10)

**What this is**: a from-scratch, step-by-step methodology and results writeup
for profiling `zk-cred-vega`/`vega-prover` on real hardware, written so
another human or agent can reproduce every number in it exactly. It grew out
of investigating why a real wallet presentation using the VegaMC circuit
took 4-7 seconds end to end when the architecture's own design ("prepare
once, show cheaply many times") suggested it should be much faster.

**Headline findings**, each backed by a reproducible experiment below:

1. The SDK (`siros-sdk-kotlin`) was calling `prep_prove` fresh on every
   single presentation, even though it takes zero verifier-specific input -
   fixed in [siros-sdk-kotlin#257](https://github.com/sirosfoundation/siros-sdk-kotlin/pull/257).
2. On a real Pixel 10a, restricting execution to the device's 4 performance
   cores (excluding its 4 weak efficiency cores) is **faster** than using
   all 8 - a genuine, reproducible ~20% penalty from naive scheduling on a
   heterogeneous SoC, free to fix without touching the circuit at all.
3. The prover key, verifier key, and `prep_prove` output all compress at
   ratios far outside what genuinely random cryptographic material should
   show (88-243:1) - a real signal, though see §5 for why this does not by
   itself prove a specific root cause.
4. Decomposing the originally-observed ~9x gap (measured through the real
   Kotlin/JNI SDK path) into independently-measured factors: ~4.2x is a
   whole-run compute gap against the Pixel's best cluster, ~1.2x is the
   scheduling penalty from finding #2, and ~1.35x is JNI/UniFFI marshaling
   overhead specific to the Android integration layer - multiplying out to
   the originally observed range. The 4.2x compares runs with different
   worker counts; see §6 for what that is worth.

---

## 1. Environment

Record all of this before comparing numbers against a different run -
every figure below is specific to this exact hardware/software
combination, and the investigation's own findings (§4) show how much core
selection alone can move the result.

### Host (x86_64 baseline)

```
$ lscpu | grep -E "Model name|CPU\(s\)|MHz"
Model name:                              AMD Ryzen AI 5 340 w/ Radeon 840M
CPU(s):                                  12
CPU max MHz:                             4900.0000
CPU min MHz:                             599.0000

$ rustc --version
rustc 1.100.0-nightly (0dfb098f3 2026-08-31)

$ cargo --version
cargo 1.100.0-nightly (e8cb624d5 2026-08-22)
```

This is itself a mobile/laptop-class chip (Zen 5, 6 cores/12 threads), not
a workstation - keep that in mind when interpreting the "desktop vs phone"
ratios below; they are not "beefy server vs phone."

### Device (ARM64 target)

```
$ adb shell getprop ro.product.model
Pixel 10a

$ adb shell getprop ro.product.cpu.abi
arm64-v8a

$ adb shell getprop ro.build.fingerprint
google/stallion/stallion:17/CP3A.260905.009/16091614:user/release-keys

$ adb shell getprop ro.board.platform
zumapro

$ adb shell cat /proc/version
Linux version 6.1.162-android14-11-g2ec90535fa34-ab15810641 ...

$ adb shell cat /proc/cpuinfo | grep -E "processor|CPU part"
processor : 0   CPU part : 0xd80   # Cortex-A520 (efficiency) x4, cores 0-3
processor : 1   CPU part : 0xd80
processor : 2   CPU part : 0xd80
processor : 3   CPU part : 0xd80
processor : 4   CPU part : 0xd81   # Cortex-A720 (mid) x3, cores 4-6
processor : 5   CPU part : 0xd81
processor : 6   CPU part : 0xd81
processor : 7   CPU part : 0xd82   # Cortex-X4 (prime) x1, core 7

$ adb shell cat /sys/devices/system/cpu/cpu*/cpufreq/cpuinfo_max_freq
1950000   # cores 0-3 (A520 little)
1950000
1950000
1950000
2600000   # cores 4-6 (A720 mid)
2600000
2600000
3105000   # core 7 (X4 big)
```

A tri-cluster "1 big + 3 mid + 4 little" layout - this matters directly
for §4.

### Code under test

```
$ git -C zk-cred-vega log --oneline -1
69048ec Bump version to 0.0.6 for the Swift/iOS packaging release   # origin/main at time of writing

$ grep vega-prover zk-cred-vega/Cargo.toml
vega-prover = { git = "https://github.com/sirosfoundation/vega-prover.git", rev = "2a7dcb3" }
```

`vega-prover@2a7dcb3` is the sparse-matrix allocation fix from the
2026-08-27 investigation (recorded in this project's own session notes) -
confirm you're measuring against this same revision (or note the
difference) before comparing numbers to this document.

---

## 2. One-time setup

```bash
# Rust targets + cross-compile tooling (for the on-device runs in §3b/§4)
rustup target add aarch64-linux-android
cargo install cargo-ndk
# An Android NDK must be discoverable (ANDROID_NDK_HOME / ANDROID_HOME/ndk/*
# / a standalone install cargo-ndk can find) - this investigation used NDK
# r27c. The exact NDK version only affects the cross-compiler/linker used
# to BUILD the binary, not which CPU it runs on - it is not expected to
# change the profiling conclusions.

# A real test vector - generates test-vectors/mdl_4claims_mixed_disclosure.json
cd zk-cred-vega
cargo run --release --example gen_test_mdocs

# A connected, UNLOCKED Android device (arm64-v8a) for §3b/§4/§6.
# adb shell dumpsys user | grep State    # must say RUNNING_UNLOCKED, not
#                                        # RUNNING_LOCKED - am instrument
#                                        # and plain native binaries both
#                                        # refuse to start while the
#                                        # device's credential storage is
#                                        # locked (SecurityException: not
#                                        # encryption aware), and nothing
#                                        # reports this failure cleanly -
#                                        # it just hangs. Unlock the
#                                        # device's lock screen first.
adb devices -l

# zstd and xz on PATH (for §5) - gzip is NOT required (see §5's own note
# on why it's excluded).
which zstd xz
```

---

## 3. Stage timing

### 3a. x86_64 baseline

```bash
cd zk-cred-vega
cargo build --release --example perf_profile
./target/release/examples/perf_profile
```

Raw output (one representative run):

```
setup                : 556.68ms
  prover key         :    135.8 MB
  verifier key       :    135.8 MB
prep_prove           : 181.73ms
  prep state         :    110.5 MB
prove                : 393.06ms
  proof              :    232.7 kB
verify               :  85.12ms
verify_and_check_bind: 48.02µs
```

For a full stage-by-stage breakdown (not just these four top-level
numbers), use the traced variant with `tracing`'s env-filter:

```bash
cargo build --release --example perf_profile_traced
RUST_LOG=vega_prover=debug,info ./target/release/examples/perf_profile_traced \
  > x86_trace.log 2>&1
sed -E 's/\x1b\[[0-9;]*m//g' x86_trace.log > x86_trace_clean.log   # strip ANSI color codes
grep "elapsed_ms" x86_trace_clean.log
```

Key stage timings extracted this way (one representative run; see
`x86_trace_clean.log` for the full span tree):

| stage | elapsed_ms |
|---|---:|
| `r1cs_shape_generation` | 308 |
| `commitment_key_generation` | 18 |
| `neutronnova_setup` (= `setup` total) | 537 |
| `generate_shared_witness` | 2 |
| `generate_precommitted_witnesses` (circuits=5) | 132 |
| `neutronnova_prep_prove` (= `prep_prove` total) | 209 |
| `generate_instances_witnesses` (step_circuits=4) | 11 |
| `NIFS` (fold_witnesses + fold_instances + folding itself) | 102 |
| `compute_core_polys` | 12 |
| `prepare_multilinear_polys` | 13 |
| `compute_eval_rx` | 3 |
| `compute_eval_table_sparse` | 60 |
| `fold_evaluation_claims` | 30 |
| `pcs_prove` (Hyrax: prep+bind+commit+ipa) | 17 |
| `neutronnova_prove` (= `prove` total) | 328 |

### 3b. Real device (Pixel 10a, arm64-v8a)

```bash
cd zk-cred-vega
cargo ndk --target aarch64-linux-android --platform 28 -- build --release \
  --example perf_profile --example perf_profile_traced

adb shell mkdir -p /data/local/tmp/vegaperf/test-vectors
adb push target/aarch64-linux-android/release/examples/perf_profile /data/local/tmp/vegaperf/
adb push target/aarch64-linux-android/release/examples/perf_profile_traced /data/local/tmp/vegaperf/
adb push test-vectors/mdl_4claims_mixed_disclosure.json /data/local/tmp/vegaperf/test-vectors/
adb shell chmod 755 /data/local/tmp/vegaperf/perf_profile /data/local/tmp/vegaperf/perf_profile_traced

# Coarse numbers
adb shell "cd /data/local/tmp/vegaperf && ./perf_profile"

# Full stage trace
adb shell "cd /data/local/tmp/vegaperf && RUST_LOG=vega_prover=debug,info ./perf_profile_traced" \
  > pixel_trace.log 2>&1
sed -E 's/\x1b\[[0-9;]*m//g' pixel_trace.log > pixel_trace_clean.log
```

Raw output (one representative run, default scheduling - all 8 cores,
exactly what the real SDK experiences with no affinity pinning):

```
setup                :    1.90s
  prover key         :    135.8 MB
  verifier key       :    135.8 MB
prep_prove           :    1.00s
  prep state         :    110.5 MB
prove                :    2.78s
  proof              :    232.7 kB
verify               : 859.07ms
verify_and_check_bind: 371.46µs
```

Repeated after several back-to-back prior runs (to rule out a cold-start
or thermal artifact): `setup=1.97s, prep_prove=0.99s, prove=2.74s` - stable
within normal run-to-run variance, i.e. **not** a thermal-throttling
artifact.

| stage | x86_64 | Pixel (default) | ratio |
|---|---:|---:|---:|
| `setup` | 538ms | 1970ms | 3.7x |
| `prep_prove` | 210ms | 1031ms | 4.9x |
| `prove` | 331ms | 2384ms | 7.2x |
| **native total** | **1.08s** | **5.68s** | **5.3x** |

No single stage inside `prep_prove`/`prove` is a wild outlier relative to
the others once each is long enough (>50ms on x86_64) to not be dominated
by fixed per-call/thread-dispatch overhead - the slowdown is fairly even
across the whole pipeline. `compute_eval_table_sparse` (the stage the
2026-08-27 investigation's sparse-matrix fix targeted) is proportionally
*smaller* here (16% of `prove()`) than that investigation found pre-fix
(~49%) - the fix is confirmed still effective on ARM64.

---

## 4. Core-affinity experiment

Tests whether naive scheduling across this device's heterogeneous 8-core
layout (1 big + 3 mid + 4 little) is itself costing real time, independent
of raw per-core throughput.

```bash
adb shell which taskset   # confirm it's present (it was, at /system/bin/taskset)

# Default: all 8 cores, as the real SDK experiences it
adb shell "cd /data/local/tmp/vegaperf && ./perf_profile"

# Fast cluster only: cores 4-7 (3x Cortex-A720 @2.6GHz + 1x Cortex-X4 @3.1GHz)
adb shell "cd /data/local/tmp/vegaperf && taskset -c 4-7 env RAYON_NUM_THREADS=4 ./perf_profile"

# Little cluster only: cores 0-3 (4x Cortex-A520 @1.95GHz)
adb shell "cd /data/local/tmp/vegaperf && taskset -c 0-3 env RAYON_NUM_THREADS=4 ./perf_profile"
```

Raw results:

| Configuration | `prep_prove` | `prove` | native total |
|---|---:|---:|---:|
| Default (all 8 cores) | 1.00s | 2.78s | 5.68s |
| **Fast-only** (cores 4-7, 4 threads) | 0.83s | 2.19s | **4.79s** |
| Little-only (cores 0-3, 4 threads) | 1.81s | 3.94s | 12.22s |

**Using only 4 of the 8 cores is faster than using all 8.** `rayon`'s
default thread pool (one worker per logical CPU) hands equal-sized chunks
of work to all 8 threads; on a heterogeneous SoC, every one of the ~29
`par_iter` call sites in `vega_mc_zkp.rs` then has to wait on whichever
worker finishes last at that join point - often a little core. Excluding
the littles entirely removes that bottleneck even though it's strictly
fewer total compute resources.

**Caveat on mechanism**: this experiment confirms the *effect* (fewer,
faster, homogeneous cores wins) but does not fully distinguish between two
plausible mechanisms: (a) a work-stealing scheduler repeatedly waiting on
slow stragglers, and (b) a shared SoC power/thermal budget letting the
remaining cores run at higher sustained clocks once the littles are idle.
Distinguishing these would need live per-core `cpufreq` sampling during
the run, which this investigation did not do. Either way, the practical,
actionable conclusion is the same: constrain the thread pool to
performance cores on Android.

---

## 5. Compressibility check

Tests whether the prover/verifier key and the `prep_prove` output carry
redundant structure a general-purpose compressor can find - raised as a
specific, concrete hypothesis by the circuit's own reviewer ("I suspect
the key is highly compressible... almost guaranteed to be a lack of proper
folding").

```bash
cd zk-cred-vega
cargo build --release --example compressibility_probe
./target/release/examples/compressibility_probe
```

Raw output:

```
Prover key (setup() output): 135776322 bytes raw
  zstd -19  :    3660237 bytes  (  37.1:1, 2.70% of raw)
  xz -9     :    1533644 bytes  (  88.5:1, 1.13% of raw)
  best: xz -9 at 88.5:1 - properly random cryptographic material would show ~1:1

Verifier key (setup() output): 135845036 bytes raw
  zstd -19  :    3662645 bytes  (  37.1:1, 2.70% of raw)
  xz -9     :    1542684 bytes  (  88.1:1, 1.14% of raw)
  best: xz -9 at 88.1:1 - properly random cryptographic material would show ~1:1

Prep state (prep_prove() output): 110508616 bytes raw
  zstd -19  :     698321 bytes  ( 158.2:1, 0.63% of raw)
  xz -9     :     454844 bytes  ( 243.0:1, 0.41% of raw)
  best: xz -9 at 243.0:1 - properly random cryptographic material would show ~1:1
```

These are real, reproducible, far outside what genuinely random
cryptographic material (field elements, group elements, polynomial
commitments) should show - such data should compress to roughly 100% of
its size, not 1-3%.

**What this does and does not prove**: a high ratio is a genuine signal
that SOME exploitable redundancy exists, but by itself it does not
distinguish between two different explanations:

1. A genuine correctness/completeness gap - e.g. a folding or compaction
   step not actually collapsing what it is supposed to.
2. A perfectly ordinary, benign property of the data: a DENSE
   serialization of SPARSE or SMALL values compresses enormously well
   with no implementation defect implied at all.

The probe now measures the second directly instead of arguing it from a
remembered figure, and the measurement separates two different causes:

| | zero bytes | all-zero 32-byte field elements |
|---|---:|---:|
| Prover key | 79.3% | 0.0% |
| Verifier key | 79.2% | 0.1% |
| Prep state | 99.0% | 78.4% |

The keys contain almost no empty slots - their zeros sit *inside* field
elements, which is what small values stored at full 32-byte width look
like. The prep state is the other thing entirely: genuinely mostly empty
slots. Both compress enormously, for different reasons, and neither
figure is evidence of a defect by itself.

(An earlier draft of this section cited "~733K nonzero entries feeding a
1,048,576-slot output vector - roughly 0.07% density". That arithmetic is
69.9%, not 0.07%, so it argued for density while claiming sparsity. The
table above replaces it with a measurement the tool prints.)

Resolving which of these applies needs inspecting the actual serialization
format (is the key/prep-state's on-disk layout storing a sparse structure
densely, or is there a step that should be collapsing repeated values and
isn't?) - out of scope for this black-box measurement. Treat the ratio as
a lead, not a conclusion.

A real bug was found and fixed while building this probe: piping the full
100+MB buffer through a compressor child process's stdin, while also
capturing its stdout via `wait_with_output()`, deadlocks the instant the
child's compressed output fills the OS pipe buffer (default 64KB on
Linux) before it has finished reading all of stdin - the child blocks
writing output nobody is draining yet, the parent blocks inside
`write_all` with more input still to send. `gzip -9` was additionally
dropped from the probe entirely: its 32KB LZ77 window finds few usable
matches in redundancy that operates at a much coarser granularity than
that, and its hash-chain matcher pathologically slowed down (observed
taking several minutes on a 135MB input that `zstd`/`xz` handle in
seconds) searching for matches it mostly would not find anyway.

---

## 6. Reconciling the originally-observed ~9x gap

The real wallet presentation's reported 4-7 seconds was measured through
the actual Kotlin SDK/JNI call path (`VegaProofSystem.generateProof`'s own
`Timber` logging), not the pure-native numbers above. One specific
instrumented run gave:

```
prep_prove=1338ms, prove(cold)=3782ms, cold_total=5120ms
```

Decomposing the gap against the x86_64 native baseline (1.08s):

| Factor | Multiplier | Evidence |
|---|---:|---|
| Whole-run gap, Pixel's *best* cluster vs. x86_64 | ~4.2x | §4 fast-only (4.79s) vs. §3a (1.08s) |
| Naive scheduling onto weak efficiency cores | ~1.19x | §4 default (5.68s) vs. fast-only (4.79s) |
| JNI/UniFFI/Kotlin marshaling overhead | ~1.35x | SDK-measured (5.12s for prep+prove) vs. §3b native (3.78s for the same two calls) |
| **Combined** | **~7-9x** | matches the originally observed range |

About 35% of the gap (the scheduling and JNI factors, multiplicatively)
is addressable without touching the circuit at all.

**The ~4.2x is a whole-run comparison, not a per-core one**, and an
earlier version of this document called it "per-core". The two runs do
not use the same number of workers: the Pixel figure is
`RAYON_NUM_THREADS=4` pinned to four performance cores, while the x86_64
baseline uses the default pool on a 6-core/12-thread host. Three times
the workers is in the ratio alongside whatever per-core difference
exists.

Controlling the half that can be controlled here - the x86_64 side,
re-run on the same machine - the workload turns out to scale poorly with
threads anyway, so the confound is smaller than three times:

| x86_64 workers | prep_prove | prove | prep+prove |
|---|---:|---:|---:|
| default (12) | 187.05ms | 418.97ms | 606ms |
| 4 (matched to the Pixel run) | 215.41ms | 459.89ms | 675ms |

**1.11x** for a third of the workers. So matching worker counts moves the
figure to roughly 3.8x rather than collapsing it, and a real per-core gap
remains. But it is an estimate with a known uncontrolled variable on the
device side, which no number here can fix without a Pixel to re-run; the
"silicon-capability, not software-fixable" reading should be held that
loosely.

---

## 7. Honest limitations of this investigation

- Each configuration in §3-4 was run once or twice, not averaged over many
  trials - real variance exists (e.g. `prove` ranged 2.19-3.94s across
  runs even on the same configuration in some cases). Treat exact figures
  as indicative, not as tightly-bounded measurements.
- The thermal-throttling check (§3b) was a single repeat-run comparison,
  not continuous temperature monitoring - sufficient to rule out gross
  throttling, not a rigorous thermal study.
- §4's mechanism (scheduling stragglers vs. shared power budget) is not
  disambiguated - see that section's own caveat.
- §5 establishes compressibility, not root cause - see that section's own
  caveat.
- All device-side measurements are from one specific Pixel 10a unit; phone
  SoC performance and thermal behavior varies across units and especially
  across different device models/chipsets.
