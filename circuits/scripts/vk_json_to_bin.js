#!/usr/bin/env node
//
// vk_json_to_bin.js
//
// Convert a snarkjs `verification_key.json` (Groth16, BLS12-381, 2 public
// signals) into the 960-byte uncompressed binary layout consumed by the
// firmware's secure-world Groth16 verifier.
//
//   alpha   ( 96 B)  G1 uncompressed:  Fp(x, BE48) || Fp(y, BE48)
//   beta    (192 B)  G2 uncompressed:  Fq2(x).c1 || Fq2(x).c0 ||
//                                      Fq2(y).c1 || Fq2(y).c0   (each BE48)
//   gamma   (192 B)  G2 uncompressed: same layout
//   delta   (192 B)  G2 uncompressed: same layout
//   IC[0]   ( 96 B)  G1 uncompressed
//   IC[1]   ( 96 B)  G1 uncompressed
//   IC[2]   ( 96 B)  G1 uncompressed
//   total   (960 B)
//
// The c1-first ordering for G2 matches the `bls12_381` Rust crate's
// `G2Affine::from_uncompressed`. This is the same byte order used by
// `tools/export_zk_constants.js` (`g1Bytes`/`g2Bytes` helpers); the
// helpers are duplicated here for now so the new circuits/ pipeline is
// self-contained, and a follow-up (M2a) is expected to extract them
// into a shared module that both scripts can `require`.
//
// Usage:
//   node circuits/scripts/vk_json_to_bin.js \
//        --in <vk.json> \
//        --out <secure/data/vks/foo.vk.bin> \
//        [--n-public 2]
//

"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

// BLS12-381 base field prime (Fp).
const FP_PRIME = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn;

/** bigint → 48-byte big-endian Uint8Array for Fp. */
function fpToBE48(n) {
  n = ((n % FP_PRIME) + FP_PRIME) % FP_PRIME;
  const out = new Uint8Array(48);
  for (let i = 47; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

/**
 * G1 affine point as 96 bytes uncompressed: x (BE48) || y (BE48).
 * `point` is the snarkjs JSON form: ["xDecimal", "yDecimal", "1"].
 */
function g1Bytes(point) {
  if (!Array.isArray(point) || point.length < 2) {
    throw new Error("g1Bytes: malformed point: " + JSON.stringify(point));
  }
  const x = BigInt(point[0]);
  const y = BigInt(point[1]);
  const out = new Uint8Array(96);
  out.set(fpToBE48(x), 0);
  out.set(fpToBE48(y), 48);
  return out;
}

/**
 * G2 affine point as 192 bytes uncompressed:
 *   x.c1 (BE48) || x.c0 (BE48) || y.c1 (BE48) || y.c0 (BE48)
 *
 * `point` is the snarkjs JSON form:
 *   [["x.c0", "x.c1"], ["y.c0", "y.c1"], ["1", "0"]]
 *
 * The c1-first ordering matches the `bls12_381` Rust crate, NOT the order
 * snarkjs uses internally. The wallet's verifier expects this layout.
 */
function g2Bytes(point) {
  if (!Array.isArray(point) || point.length < 2) {
    throw new Error("g2Bytes: malformed point: " + JSON.stringify(point));
  }
  if (!Array.isArray(point[0]) || point[0].length < 2) {
    throw new Error("g2Bytes: malformed x: " + JSON.stringify(point[0]));
  }
  if (!Array.isArray(point[1]) || point[1].length < 2) {
    throw new Error("g2Bytes: malformed y: " + JSON.stringify(point[1]));
  }
  const xc0 = BigInt(point[0][0]);
  const xc1 = BigInt(point[0][1]);
  const yc0 = BigInt(point[1][0]);
  const yc1 = BigInt(point[1][1]);
  const out = new Uint8Array(192);
  out.set(fpToBE48(xc1), 0);
  out.set(fpToBE48(xc0), 48);
  out.set(fpToBE48(yc1), 96);
  out.set(fpToBE48(yc0), 144);
  return out;
}

/** Concatenate Uint8Arrays. */
function concat(parts) {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** Parse argv into a flat options object. */
function parseArgs(argv) {
  const opts = { in: null, out: null, nPublic: 2 };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--in") opts.in = argv[++i];
    else if (a === "--out") opts.out = argv[++i];
    else if (a === "--n-public") opts.nPublic = parseInt(argv[++i], 10);
    else if (a === "-h" || a === "--help") {
      printUsage();
      process.exit(0);
    } else {
      throw new Error("Unknown argument: " + a);
    }
  }
  if (!opts.in || !opts.out) {
    printUsage();
    throw new Error("Missing --in / --out");
  }
  if (!Number.isInteger(opts.nPublic) || opts.nPublic < 1) {
    throw new Error("--n-public must be a positive integer");
  }
  return opts;
}

function printUsage() {
  process.stderr.write([
    "Usage: node circuits/scripts/vk_json_to_bin.js \\",
    "         --in <verification_key.json> \\",
    "         --out <secure/data/vks/foo.vk.bin> \\",
    "         [--n-public 2]",
    "",
  ].join("\n"));
}

function main() {
  const opts = parseArgs(process.argv);

  const vkText = fs.readFileSync(opts.in, "utf8");
  const vk = JSON.parse(vkText);

  if (vk.protocol !== "groth16") {
    throw new Error(`vk.protocol = ${JSON.stringify(vk.protocol)}, expected "groth16"`);
  }
  if (vk.curve !== "bls12381") {
    throw new Error(`vk.curve = ${JSON.stringify(vk.curve)}, expected "bls12381"`);
  }
  if (vk.nPublic !== opts.nPublic) {
    throw new Error(
      `vk.nPublic = ${vk.nPublic}, expected ${opts.nPublic} (--n-public)`
    );
  }
  if (!Array.isArray(vk.IC) || vk.IC.length !== opts.nPublic + 1) {
    throw new Error(
      `vk.IC.length = ${vk.IC ? vk.IC.length : "undefined"}, expected ${opts.nPublic + 1}`
    );
  }

  // For the firmware's existing 960-byte layout, n_public must be exactly 2
  // (alpha, beta, gamma, delta + 3 IC = 96 + 192*3 + 96*3 = 960). Other
  // shapes need a different binary layout and a different parser on the
  // secure side.
  if (opts.nPublic !== 2) {
    throw new Error(
      `n_public = ${opts.nPublic} not yet supported by the firmware verifier ` +
      `(layout assumes n_public == 2; sizes wouldn't be 960 B)`
    );
  }

  const alpha = g1Bytes(vk.vk_alpha_1);   //  96 B
  const beta  = g2Bytes(vk.vk_beta_2);    // 192 B
  const gamma = g2Bytes(vk.vk_gamma_2);   // 192 B
  const delta = g2Bytes(vk.vk_delta_2);   // 192 B
  const ic0   = g1Bytes(vk.IC[0]);        //  96 B
  const ic1   = g1Bytes(vk.IC[1]);        //  96 B
  const ic2   = g1Bytes(vk.IC[2]);        //  96 B

  const blob = concat([alpha, beta, gamma, delta, ic0, ic1, ic2]);

  if (blob.length !== 960) {
    throw new Error(`internal: blob.length = ${blob.length}, expected 960`);
  }

  fs.mkdirSync(path.dirname(opts.out), { recursive: true });
  fs.writeFileSync(opts.out, blob);

  const sha = crypto.createHash("sha256").update(blob).digest("hex");
  process.stdout.write(`wrote ${opts.out} 960 B sha256=${sha}\n`);
}

try {
  main();
} catch (e) {
  process.stderr.write("vk_json_to_bin: " + e.message + "\n");
  process.exit(1);
}
