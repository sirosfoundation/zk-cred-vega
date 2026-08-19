//! Runs `zk_cred_vega::setup()` and writes the bincode-serialized
//! prover/verifier keys to `target/setup-artifacts/`, for `zstd`-compressing
//! and publishing to `go-zk-circuits` (see README's "Publishing setup
//! artifacts" section). Re-run this any time the circuit shape changes —
//! the resulting bytes are tied to that exact shape and won't verify
//! proofs from a different one.

use std::io::Write;

fn main() {
  let out_dir = std::path::Path::new("target/setup-artifacts");
  std::fs::create_dir_all(out_dir).expect("create output dir");

  let keys = zk_cred_vega::setup().expect("setup");
  let pk_bytes = bincode::serialize(&keys.pk).expect("serialize pk");
  let vk_bytes = bincode::serialize(&keys.vk).expect("serialize vk");

  let pk_path = out_dir.join("vega-mc-p256-v1-prover-key.bin");
  let vk_path = out_dir.join("vega-mc-p256-v1-verifier-key.bin");
  std::fs::File::create(&pk_path)
    .and_then(|mut f| f.write_all(&pk_bytes))
    .expect("write pk");
  std::fs::File::create(&vk_path)
    .and_then(|mut f| f.write_all(&vk_bytes))
    .expect("write vk");

  println!("wrote {} ({} bytes)", pk_path.display(), pk_bytes.len());
  println!("wrote {} ({} bytes)", vk_path.display(), vk_bytes.len());
}
