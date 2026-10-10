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
//! benign property of the data (R1CS constraint matrices are typically
//! extremely sparse - one real circuit here has ~733K nonzeros into a
//! 1,048,576-slot output - and a DENSE serialization of a SPARSE structure
//! compresses enormously well precisely because it is mostly zeros, with
//! no implementation defect implied at all). Treat a high ratio as a lead
//! to investigate against the actual serialization format, not as a
//! conclusion on its own.
//!
//! Shells out to `zstd`/`xz` rather than adding compression crates as
//! dependencies, since this is a one-off diagnostic, not something the
//! library itself needs. Analysis tool, not part of the library.
//!
//! Requires `zstd` and `xz` on PATH (skips whichever is missing).

use std::process::{Command, Stdio};

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
  let mut full_args: Vec<&str> = args.to_vec();
  let path_str = tmp.to_str()?;
  full_args.push(path_str);
  let output = Command::new(tool)
    .args(&full_args)
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::null())
    .output()
    .ok();
  let _ = std::fs::remove_file(&tmp);
  let output = output?;
  if output.status.success() { Some(output.stdout.len() as u64) } else { None }
}

fn report(label: &str, raw: &[u8]) {
  let raw_len = raw.len() as u64;
  println!("\n{label}: {raw_len} bytes raw");
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
  let fixture =
    std::fs::read_to_string("test-vectors/mdl_4claims_mixed_disclosure.json").expect("fixture (run `cargo run --release --example gen_test_mdocs` first)");
  let f: serde_json::Value = serde_json::from_str(&fixture).unwrap();
  let hexb = |s: &str| hex::decode(s).unwrap();

  let claims: Vec<zk_cred_vega::ClaimWitness> = f["claims"]
    .as_array()
    .unwrap()
    .iter()
    .map(|c| zk_cred_vega::ClaimWitness {
      issuer_signed_item_bytes: hexb(c["issuer_signed_item_bytes_hex"].as_str().unwrap()),
      disclose: c["disclose"].as_bool().unwrap(),
      digest_id: c["digest_id"].as_u64().unwrap() as u32,
    })
    .collect();

  let w = &f["ecdsa_witness"];
  use num_bigint::{BigInt, Sign};
  let ecdsa = zk_cred_vega::MdocEcdsaWitness {
    qx: zk_cred_vega::nonnative::util::nat_to_f(&BigInt::from_bytes_be(Sign::Plus, &hexb(w["qx_hex"].as_str().unwrap()))).unwrap(),
    qy: zk_cred_vega::nonnative::util::nat_to_f(&BigInt::from_bytes_be(Sign::Plus, &hexb(w["qy_hex"].as_str().unwrap()))).unwrap(),
    r: BigInt::from_bytes_be(Sign::Plus, &hexb(w["r_hex"].as_str().unwrap())),
    s: BigInt::from_bytes_be(Sign::Plus, &hexb(w["s_hex"].as_str().unwrap())),
    s_inv: BigInt::from_bytes_be(Sign::Plus, &hexb(w["s_inv_hex"].as_str().unwrap())),
  };
  let m = &f["mso_body"];
  let fx = |s: &str| -> [u8; 32] { hexb(s).try_into().unwrap() };
  let body = zk_cred_vega::mso::MsoBodyWitness {
    device_x: fx(m["device_x_hex"].as_str().unwrap()),
    device_y: fx(m["device_y_hex"].as_str().unwrap()),
    signed_ts: m["signed_ts"].as_str().unwrap().as_bytes().try_into().unwrap(),
    valid_from_ts: m["valid_from_ts"].as_str().unwrap().as_bytes().try_into().unwrap(),
    valid_until_ts: m["valid_until_ts"].as_str().unwrap().as_bytes().try_into().unwrap(),
  };
  let nonce = [0x5Au8; zk_cred_vega::BLIND_NONCE_BYTES];

  let keys = zk_cred_vega::setup().expect("setup");
  let pk_bytes = bincode::serialize(&keys.pk).unwrap();
  let vk_bytes = bincode::serialize(&keys.vk).unwrap();
  report("Prover key (setup() output)", &pk_bytes);
  report("Verifier key (setup() output)", &vk_bytes);

  let prep = zk_cred_vega::prep_prove(&keys.pk, &claims, &ecdsa, &body, &nonce).expect("prep_prove");
  let prep_bytes = bincode::serialize(&prep.into_inner()).unwrap();
  report("Prep state (prep_prove() output)", &prep_bytes);
}
