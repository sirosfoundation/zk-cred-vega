// SPDX-License-Identifier: BSD-2-Clause
//! Guard for the boundary between vega-prover and the nymauth code (see the README, section
//! "The vega-prover boundary"): the nymauth engine (`src/nymauth_vega/engine`) consumes only the
//! listed PUBLIC items of vega-prover and none of this crate's generic mdoc/age code, and this
//! crate's manifest overrides the prover neither by path nor by patch.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The public items of vega-prover the nymauth engine may use. Adding a line here is a change to
/// the boundary and belongs in the README's list.
const ALLOWED: &[&str] = &[
  "bellpepper::r1cs::VegaShape",
  "bellpepper::shape_cs::ShapeCS",
  "bellpepper::solver::SatisfyingAssignment",
  "errors::VegaError",
  "provider::T256HyraxEngine",
  "provider::pt256::t256",
  "traits::circuit::VegaCircuit",
  "traits::snark::DigestHelperTrait",
  "vega_mc_zkp::VegaMcPrepZkSNARK",
  "vega_mc_zkp::VegaMcProverKey",
  "vega_mc_zkp::VegaMcVerifierKey",
  "vega_mc_zkp::VegaMcZkSNARK",
];

fn root() -> PathBuf {
  PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
  for e in std::fs::read_dir(dir).unwrap() {
    let p = e.unwrap().path();
    if p.is_dir() {
      rust_files(&p, out);
    } else if p.extension().is_some_and(|x| x == "rs") {
      out.push(p);
    }
  }
}

/// Flattens `a::{b, c::{d, e}}` into `a::b`, `a::c::d`, `a::c::e`.
fn flatten(prefix: &str, rest: &str, out: &mut Vec<String>) -> usize {
  // Returns the number of bytes of `rest` consumed.
  let mut consumed = 0;
  let mut item = String::new();
  let chars: Vec<char> = rest.chars().collect();
  let mut i = 0;
  while i < chars.len() {
    match chars[i] {
      '{' => {
        let tail: String = chars[i + 1..].iter().collect();
        let base = format!("{prefix}{item}");
        let n = flatten(&base, &tail, out);
        i += n + 1;
        item.clear();
        // skip to the next separator
        continue;
      }
      ',' | '}' | ';' => {
        let name = item.trim().to_string();
        if !name.is_empty() {
          out.push(format!("{prefix}{name}"));
        }
        item.clear();
        if chars[i] != ',' {
          consumed = i + 1;
          return consumed;
        }
      }
      c if c.is_whitespace() => {}
      c => item.push(c),
    }
    i += 1;
  }
  consumed
}

fn used_items(source: &str) -> Vec<String> {
  // Code only: drop line comments (doc comments name items in prose).
  let code: String = source.lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n");
  let mut found = Vec::new();
  let mut rest = code.as_str();
  while let Some(at) = rest.find("vega_prover::") {
    let after = &rest[at + "vega_prover::".len()..];
    let mut out = Vec::new();
    if let Some(open) = after.strip_prefix('{') {
      flatten("", open, &mut out);
    } else {
      let end = after
        .find(|c: char| !(c.is_alphanumeric() || c == '_' || c == ':' || c == '{'))
        .unwrap_or(after.len());
      let path = &after[..end];
      if path.contains('{') {
        let (head, group) = path.split_once('{').unwrap();
        // re-read the group from the full text
        let group_at = after.find('{').unwrap();
        flatten(head, &after[group_at + 1..], &mut out);
        let _ = group;
      } else {
        out.push(path.to_string());
      }
    }
    found.extend(out);
    rest = &rest[at + "vega_prover::".len()..];
  }
  found
}

#[test]
fn the_engine_uses_only_the_listed_public_items_of_vega_prover() {
  let mut files = Vec::new();
  rust_files(&root().join("src/nymauth_vega"), &mut files);
  files.push(root().join("src/nymauth_vega.rs"));
  files.push(root().join("src/nymauth_go_ffi.rs"));
  assert!(files.len() > 15);
  let allowed: BTreeSet<&str> = ALLOWED.iter().copied().collect();
  let mut seen = BTreeSet::new();
  for f in &files {
    for item in used_items(&std::fs::read_to_string(f).unwrap()) {
      assert!(
        allowed.contains(item.as_str()),
        "{} uses vega_prover::{item}, which is not in the boundary list",
        f.display()
      );
      seen.insert(item);
    }
  }
  // every allowed item is in use (the list stays honest), and the parser found the grouped imports
  for a in &allowed {
    assert!(seen.contains(*a), "{a} is listed but not used");
  }
}

#[test]
fn the_engine_depends_on_none_of_the_generic_mdoc_code_of_this_crate() {
  let mut files = Vec::new();
  rust_files(&root().join("src/nymauth_vega"), &mut files);
  for f in &files {
    let source = std::fs::read_to_string(f).unwrap();
    for (n, line) in source.lines().enumerate() {
      let code = line.split("//").next().unwrap();
      let mut rest = code;
      while let Some(at) = rest.find("crate::") {
        let after = &rest[at..];
        assert!(
          after.starts_with("crate::nymauth_vega::engine::"),
          "{}:{} reaches into the crate outside the engine: {line}",
          f.display(),
          n + 1
        );
        rest = &rest[at + 7..];
      }
      assert!(!code.contains("use super::super"), "{}:{}", f.display(), n + 1);
    }
  }
}

#[test]
fn the_manifest_does_not_override_the_prover() {
  let manifest = std::fs::read_to_string(root().join("Cargo.toml")).unwrap();
  let prover = manifest
    .lines()
    .find(|l| l.trim_start().starts_with("vega-prover"))
    .expect("a vega-prover dependency");
  assert!(
    prover.contains("git = ") && !prover.contains("path"),
    "vega-prover must be a git dependency: {prover}"
  );
  assert!(!manifest.contains("[patch"), "no [patch] section");
  assert!(!manifest.contains("[replace"), "no [replace] section");
  assert!(
    !manifest
      .lines()
      .any(|l| l.trim_start().starts_with("vega-nymauth") || l.trim_start().starts_with("vega-age")),
    "the engine lives in this crate, not in the prover"
  );
  let config = root().join(".cargo/config.toml");
  let config = std::fs::read_to_string(config).unwrap_or_default();
  assert!(!config.contains("[patch") && !config.contains("paths ="), "no cargo config override");
  let lock = std::fs::read_to_string(root().join("Cargo.lock")).unwrap();
  let at = lock.find("name = \"vega-prover\"").expect("vega-prover in the lock file");
  let block = &lock[at..at + 300];
  assert!(
    block.contains("source = \"git+https://github.com/sirosfoundation/vega-prover.git"),
    "the locked prover is the git one: {block}"
  );
}
