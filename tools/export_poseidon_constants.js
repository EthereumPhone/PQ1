#!/usr/bin/env node
/**
 * export_poseidon_constants.js
 *
 * Regenerates secure/src/zk/poseidon_constants.rs from the in-repo
 * poseidon-bls12381 npm package (circuits/node_modules/poseidon-bls12381).
 *
 * Extracts ROUND_CONSTANTS + MDS_MATRIX for each required arity and writes
 * them as 32-byte little-endian ScalarBytes arrays that the Rust
 * poseidon_bytes permutation can consume directly.
 *
 * Supported arities (all the ones the v3 CowSwap EIP-712 stack needs):
 *
 *   poseidon2  (t=3)  — binary Merkle internal-node hashing
 *   poseidon3  (t=4)  — legacy: Poseidon(64 B) = 3 blocks (unused after v3)
 *   poseidon5  (t=6)  — Poseidon(128 B readable) = 5 blocks
 *   poseidon6  (t=7)  — Poseidon(164 B canonical, v2) + Merkle leaf hash (6 fields)
 *   poseidon7  (t=8)  — Poseidon(204 B canonical, v3) = 7 blocks
 *
 * Run:  node tools/export_poseidon_constants.js
 */

"use strict";

const fs = require("fs");
const path = require("path");

const REPO_ROOT = path.join(__dirname, "..");
const POSEIDON_SRC = path.join(
  REPO_ROOT,
  "circuits/node_modules/poseidon-bls12381/src/instances",
);
const OUT_FILE = path.join(REPO_ROOT, "secure/src/zk/poseidon_constants.rs");

// BLS12-381 scalar field prime.
const PRIME =
  0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;

// bigint → 32-byte little-endian (for bls12_381::Scalar::from_bytes).
function scalarToLE32(n) {
  n = ((n % PRIME) + PRIME) % PRIME;
  const bytes = [];
  for (let i = 0; i < 32; i++) {
    bytes.push(Number(n & 0xffn));
    n >>= 8n;
  }
  return bytes;
}

// Parse ROUND_CONSTANTS and MDS_MATRIX out of a poseidonN.ts file.
function extractConstants(tsFile) {
  const src = fs.readFileSync(tsFile, "utf8");

  const rcMatch = src.match(/const ROUND_CONSTANTS\s*=\s*\[([\s\S]*?)\];/);
  if (!rcMatch) throw new Error("ROUND_CONSTANTS not found in " + tsFile);
  const rc = [...rcMatch[1].matchAll(/0x[0-9a-fA-F]+n/g)].map((m) =>
    BigInt(m[0].slice(0, -1)),
  );

  const mdsMatch = src.match(
    /const MDS_MATRIX\s*=\s*\[([\s\S]*?)\];\s*\n\s*export/,
  );
  if (!mdsMatch) throw new Error("MDS_MATRIX not found in " + tsFile);

  // Parse nested array of bigints: one row per `[...]` sub-match.
  const rowMatches = [...mdsMatch[1].matchAll(/\[([\s\S]*?)\]/g)];
  const mds = [];
  for (const rm of rowMatches) {
    const vals = [...rm[1].matchAll(/0x[0-9a-fA-F]+n/g)].map((m) =>
      BigInt(m[0].slice(0, -1)),
    );
    if (vals.length > 0) mds.push(vals);
  }
  return { rc, mds };
}

// Extract RF / RP from the poseidonPermutation(inputs, RF, RP, ...) call.
function extractRounds(tsFile) {
  const src = fs.readFileSync(tsFile, "utf8");
  const m = src.match(/poseidonPermutation\(inputs,\s*(\d+),\s*(\d+)/);
  if (!m) throw new Error("Cannot find RF/RP in " + tsFile);
  return { rf: parseInt(m[1], 10), rp: parseInt(m[2], 10) };
}

// Emit the `pub mod poseidonN { ... }` Rust block.
function generateModule(name, nInputs, rf, rp, rc, mds) {
  const t = nInputs + 1;
  const nConstants = rc.length;
  const lines = [];

  lines.push(
    `/// Poseidon constants for t=${t} (${nInputs} inputs), RF=${rf}, RP=${rp}`,
  );
  lines.push(`/// Generated from poseidon-bls12381 npm package`);
  lines.push(`pub mod ${name} {`);
  lines.push(`    use super::ScalarBytes;`);
  lines.push(``);
  lines.push(`    pub const T: usize = ${t};`);
  lines.push(`    pub const RF: usize = ${rf};`);
  lines.push(`    pub const RP: usize = ${rp};`);
  lines.push(`    pub const N_CONSTANTS: usize = ${nConstants};`);
  lines.push(``);

  lines.push(`    pub static RC: [ScalarBytes; ${nConstants}] = [`);
  for (let i = 0; i < rc.length; i++) {
    const le = scalarToLE32(rc[i]);
    lines.push(
      `        [${le
        .map((b) => "0x" + b.toString(16).padStart(2, "0"))
        .join(", ")}],`,
    );
  }
  lines.push(`    ];`);
  lines.push(``);

  lines.push(`    pub static MDS: [[ScalarBytes; ${t}]; ${t}] = [`);
  for (let i = 0; i < t; i++) {
    lines.push(`        [`);
    for (let j = 0; j < t; j++) {
      const le = scalarToLE32(mds[i][j]);
      lines.push(
        `            [${le
          .map((b) => "0x" + b.toString(16).padStart(2, "0"))
          .join(", ")}],`,
      );
    }
    lines.push(`        ],`);
  }
  lines.push(`    ];`);

  lines.push(`}`);
  return lines.join("\n");
}

function main() {
  // (mod_name, n_inputs, ts_filename)
  const TARGETS = [
    ["poseidon2", 2, "poseidon2.ts"],
    ["poseidon3", 3, "poseidon3.ts"],
    ["poseidon5", 5, "poseidon5.ts"],
    ["poseidon6", 6, "poseidon6.ts"],
    ["poseidon7", 7, "poseidon7.ts"],
  ];

  console.log("Reading Poseidon constants from", POSEIDON_SRC);

  const modules = [];
  for (const [name, nInputs, file] of TARGETS) {
    const tsPath = path.join(POSEIDON_SRC, file);
    const { rc, mds } = extractConstants(tsPath);
    const { rf, rp } = extractRounds(tsPath);
    const t = nInputs + 1;
    // Sanity: N_F = RF is always 8. Total constants = (RF + RP) * t.
    if (rc.length !== (rf + rp) * t) {
      throw new Error(
        `${name}: expected ${(rf + rp) * t} constants, got ${rc.length}`,
      );
    }
    if (mds.length !== t || mds[0].length !== t) {
      throw new Error(
        `${name}: expected ${t}x${t} MDS matrix, got ${mds.length}x${mds[0]?.length}`,
      );
    }
    console.log(
      `  ${name}: t=${t}, RF=${rf}, RP=${rp}, ${rc.length} constants`,
    );
    modules.push(generateModule(name, nInputs, rf, rp, rc, mds));
  }

  const header = `//! Auto-generated Poseidon constants for BLS12-381 scalar field.
//! Generated by tools/export_poseidon_constants.js — DO NOT EDIT.
//!
//! Source: circuits/node_modules/poseidon-bls12381 (HadeHash parameters)
//! Parameters: sage generate_params_poseidon.sage 1 0 255 t 5 128 <prime>

/// 32-byte little-endian representation of a BLS12-381 scalar field element.
pub type ScalarBytes = [u8; 32];
`;

  const out = header + "\n" + modules.join("\n\n") + "\n";
  fs.writeFileSync(OUT_FILE, out);
  console.log(
    `  → ${path.relative(REPO_ROOT, OUT_FILE)} (${(out.length / 1024).toFixed(1)} KB)`,
  );
}

main();
