//! Compressibility check for `setup()`'s key pair and `prep_prove()`'s
//! output - a cheap, black-box signal for "does this data carry redundant
//! structure a general-purpose compressor can find?"
//!
//! Cryptographic material that is genuinely random-looking (field elements,
//! group elements drawn uniformly) is computationally indistinguishable
//! from random bytes, so a general-purpose compressor buys nothing against
//! it - a properly-random 100MB blob compresses to roughly 100% of its
//! size. A HIGH ratio here means SOME kind of exploitable redundancy
//! exists, but by itself does not pin down which: it is equally consistent
//! with a genuine correctness gap (e.g. a folding/compaction step not
//! actually collapsing what it should) and with a perfectly ordinary,
//! benign property of the data: a DENSE serialization of SPARSE or
//! SMALL values compresses enormously well with no defect implied.
//!
//! So it measures that too, from the same bytes in the same run, rather
//! than arguing it from a remembered figure. The zero profile tells the
//! two apart, and for this circuit it says they are different things in
//! different places:
//!
//! ```text
//! prover key   : 79.3% zero bytes,  0.0% all-zero field elements
//! verifier key : 79.2% zero bytes,  0.1% all-zero field elements
//! prep state   : 99.0% zero bytes, 78.4% all-zero field elements
//! ```
//!
//! The keys hold almost no empty slots: their zeros are *inside* field
//! elements, which is what small values stored at full 32-byte width
//! look like. The prep state is the other thing — genuinely mostly
//! empty slots. Both compress; neither is evidence of a defect on its
//! own. Treat a high ratio as a lead to investigate against the actual
//! serialization format, not as a conclusion.
//!
//! Shells out to `zstd`/`xz` rather than adding compression crates as
//! dependencies, since this is a one-off diagnostic, not something the
//! library itself needs. Analysis tool, not part of the library.
//!
//! Requires `zstd` and `xz` on PATH (skips whichever is missing).

use std::process::{Command, Stdio};

#[path = "common/r12_fixture.rs"]
mod r12_fixture;

/// Passes `data` as a TEMP FILE path argument, never over stdin - piping
/// 100+MB through a child's stdin while also capturing its stdout via
/// `wait_with_output()` deadlocks the instant the child's compressed
/// output fills the OS pipe buffer (default 64KB on Linux) before it has
/// finished reading all of stdin: the child blocks writing output nobody
/// is draining yet, the parent blocks inside `write_all` with more input
/// still to send - each waiting on the other. Confirmed by hitting this
/// exact hang with a stdin-piped version of this function.
fn compressed_size(tool: &str, args: &[&str], data: &[u8]) -> Option<u64> {
  let tmp = std::env::temp_dir().join(format!("compressibility_probe_{}.bin", std::process::id()));
  std::fs::write(&tmp, data).ok()?;
  // `args` then `arg(&tmp)` rather than building a `Vec<&str>`: `Command`
  // takes `OsStr`, so converting the path to UTF-8 buys nothing and the
  // `?` on that conversion used to return *after* writing 100+ MB and
  // *before* the cleanup below — reporting the compressor as skipped and
  // leaving the file behind, on any system with a non-UTF-8 `TMPDIR`.
  let output = Command::new(tool)
    .args(args)
    .arg(&tmp)
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::null())
    .output()
    .ok();
  let _ = std::fs::remove_file(&tmp);
  let output = output?;
  if output.status.success() { Some(output.stdout.len() as u64) } else { None }
}

/// How much of a blob is literally zero, by byte and by 32-byte field
/// element.
///
/// The ratio alone cannot say *why* something compresses; "a dense
/// serialization of a sparse structure" is the benign explanation and
/// this is the measurement that supports or refutes it, from the same
/// bytes, in the same run. An earlier draft of this tool argued the
/// point from a remembered figure instead — "~733K nonzeros into a
/// 1,048,576-slot output, roughly 0.07% density" — which is 69.9%, not
/// 0.07%, and so argued for density while claiming sparsity.
fn zero_profile(raw: &[u8]) -> (f64, f64) {
  let zero_bytes = raw.iter().filter(|&&b| b == 0).count();
  let slots = raw.len() / 32;
  let zero_slots = (0..slots).filter(|i| raw[i * 32..(i + 1) * 32].iter().all(|&b| b == 0)).count();
  (
    100.0 * zero_bytes as f64 / raw.len() as f64,
    if slots == 0 { 0.0 } else { 100.0 * zero_slots as f64 / slots as f64 },
  )
}

fn report(label: &str, raw: &[u8]) {
  let raw_len = raw.len() as u64;
  println!("\n{label}: {raw_len} bytes raw");
  let (zb, zs) = zero_profile(raw);
  println!("  zero bytes: {zb:.1}%   all-zero 32-byte field elements: {zs:.1}%");
  // gzip deliberately excluded: its small (32KB) LZ77 window means it finds
  // few usable matches in data whose redundancy operates at a much coarser
  // granularity than that (repeated 32-byte field elements scattered across
  // 100+MB) - and its -9 hash-chain matcher pathologically slows down
  // searching for matches it mostly won't find, observed firsthand taking
  // several minutes on a 135MB input that zstd/xz handle in seconds. Its
  // ratio was uninteresting anyway (worse than both zstd and xz, as
  // expected from the smaller window) - not worth the wall-clock cost here.
  let candidates: &[(&str, &str, &[&str])] = &[("zstd -19", "zstd", &["-19", "-c"]), ("xz -9", "xz", &["-9", "-c"])];
  let mut best: Option<(&str, u64)> = None;
  for (name, tool, args) in candidates {
    match compressed_size(tool, args, raw) {
      Some(size) => {
        let ratio = raw_len as f64 / size as f64;
        let pct = size as f64 / raw_len as f64 * 100.0;
        println!("  {name:<10}: {size:>10} bytes  ({ratio:>6.1}:1, {pct:.2}% of raw)");
        if best.is_none_or(|(_, best_size)| size < best_size) {
          best = Some((name, size));
        }
      }
      None => println!("  {name:<10}: (tool not found or failed - skipped)"),
    }
  }
  if let Some((name, size)) = best {
    let ratio = raw_len as f64 / size as f64;
    println!("  best: {name} at {ratio:.1}:1 - properly random cryptographic material would show ~1:1");
  }
}

fn main() {
  let r12_fixture::Presentation { claims, ecdsa, body, nonce } = r12_fixture::load();

  let keys = zk_cred_vega::setup().expect("setup");
  let pk_bytes = bincode::serialize(&keys.pk).unwrap();
  let vk_bytes = bincode::serialize(&keys.vk).unwrap();
  report("Prover key (setup() output)", &pk_bytes);
  report("Verifier key (setup() output)", &vk_bytes);

  let prep = zk_cred_vega::prep_prove(&keys.pk, &claims, &ecdsa, &body, &nonce).expect("prep_prove");
  let prep_bytes = bincode::serialize(&prep.into_inner()).unwrap();
  report("Prep state (prep_prove() output)", &prep_bytes);
}
