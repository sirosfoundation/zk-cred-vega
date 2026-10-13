//! Same pipeline as `perf_profile.rs`, but with `vega-prover`'s own existing
//! `tracing` instrumentation (61 call sites in `vega_mc_zkp.rs` alone)
//! surfaced via a real subscriber - a stage-by-stage breakdown INSIDE
//! `prep_prove`/`prove`, not just the two coarse top-level numbers.
//! Analysis tool, not part of the library.
//!
//! Run with `RUST_LOG=vega_prover=debug,info` (or `=trace` for everything)
//! to control verbosity. On Android, run as a plain native binary via
//! `adb shell` (no JVM/UniFFI/Zygote involved) so real CPU core affinity
//! (`taskset`) applies cleanly - see this crate's README/session notes for
//! the cross-compile command.

use std::time::Instant;
use tracing_subscriber::fmt::time::uptime;

#[path = "common/r12_fixture.rs"]
mod r12_fixture;

fn main() {
  tracing_subscriber::fmt()
    .with_timer(uptime())
    .with_target(true)
    .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
    .init();

  let r12_fixture::Presentation { claims, ecdsa, body, nonce } = r12_fixture::load();

  eprintln!("=== available parallelism: {:?} ===", std::thread::available_parallelism());

  let t = Instant::now();
  let keys = zk_cred_vega::setup().expect("setup");
  eprintln!("setup                : {:>8.2?}", t.elapsed());

  let t = Instant::now();
  let prep = zk_cred_vega::prep_prove(&keys.pk, &claims, &ecdsa, &body, &nonce).expect("prep_prove");
  eprintln!("prep_prove (total)   : {:>8.2?}", t.elapsed());

  let t = Instant::now();
  let (proof, _next) = zk_cred_vega::prove(&keys.pk, &claims, &ecdsa, &body, prep, &nonce).expect("prove");
  eprintln!("prove (total)        : {:>8.2?}", t.elapsed());

  let proof_bytes = bincode::serialize(&proof).unwrap().len();
  eprintln!("  proof              : {:>8.1} kB", proof_bytes as f64 / 1e3);
}
