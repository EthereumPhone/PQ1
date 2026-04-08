#!/usr/bin/env node
//
// gen_cowswap_eip712_e2e_vector.js
//
// Generates a self-consistent e2e test vector for the
// `cowswap_eip712_order` circuit (M4):
//
//   1. Picks a representative GPv2Order (sell USDC for WETH).
//   2. Encodes it into the 164-byte packed canonical buffer the
//      circuit hashes via Poseidon6.
//   3. Builds the readable string the circuit's format function
//      enforces:
//
//        readable[ 0.. 8) = "CowSwap "
//        readable[ 8..12) = "SELL"  | "BUY "
//        readable[12..16) = "    "
//        readable[16..22) = "exp 0x"
//        readable[22..30) = ASCII upper-hex of validTo (4 BE bytes)
//        readable[30..32) = "  "
//        readable[32..64) = 0x00
//
//   4. Computes Poseidon255 hashes of both via the poseidon-bls12381
//      npm package (the same library the firmware's `poseidon_bytes`
//      reimplements).
//   5. Writes an `input.json` that drives the circom-compiled
//      witness generator under
//      `build/circuits/cowswap_eip712_order/circuit_js/`.
//   6. Runs the witness generator to produce a `witness.wtns`.
//   7. Runs `snarkjs groth16 prove` against the committed
//      `circuits/cowswap/eip712_order/circuit_final.zkey`.
//   8. Verifies the proof locally as a sanity check.
//   9. Converts proof.json into the firmware's uncompressed BLS12-381
//      byte layout (96 B G1, 192 B G2 with c1-first ordering).
//  10. Emits a Rust snippet ready to paste into
//      `nonsecure/src/e2e_test.rs` between AUTO-GENERATED markers.
//
// Unlike `gen_cowswap_e2e_vector.js`, this generator does NOT build
// an EIP-1559 envelope — there is no on-chain transaction in the
// EIP-712 flow, only a typed-data digest.
//
// Usage:
//   node circuits/scripts/gen_cowswap_eip712_e2e_vector.js
//
// Prereqs: `npm ci --prefix circuits` already done, and
// `build/circuits/cowswap_eip712_order/circuit_js/circuit.wasm` exists
// (produced by either `tools/build_vks.sh cowswap_eip712_order`
// running the full pipeline, or a one-shot direct `circom`
// invocation — see the shell snippet at the top of e2e_test.rs).

"use strict";

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

const REPO_ROOT = path.join(__dirname, "..", "..");
const CIRCUITS_DIR = path.join(REPO_ROOT, "circuits");
const BUILD_DIR = path.join(REPO_ROOT, "build", "circuits", "cowswap_eip712_order");
const ZKEY = path.join(CIRCUITS_DIR, "cowswap", "eip712_order", "circuit_final.zkey");
const WASM = path.join(BUILD_DIR, "circuit_js", "circuit.wasm");
const WITNESS_GEN = path.join(BUILD_DIR, "circuit_js", "generate_witness.js");
const NODE_MODULES = path.join(CIRCUITS_DIR, "node_modules");
const SNARKJS = path.join(NODE_MODULES, ".bin", "snarkjs");

// ── BLS12-381 helpers ──────────────────────────────────────────────────

const FP_PRIME = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn;

function fpToBE48(n) {
  n = ((n % FP_PRIME) + FP_PRIME) % FP_PRIME;
  const out = new Uint8Array(48);
  for (let i = 47; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

function g1Bytes(point) {
  const x = BigInt(point[0]);
  const y = BigInt(point[1]);
  return Buffer.concat([Buffer.from(fpToBE48(x)), Buffer.from(fpToBE48(y))]);
}

function g2Bytes(point) {
  const xc0 = BigInt(point[0][0]);
  const xc1 = BigInt(point[0][1]);
  const yc0 = BigInt(point[1][0]);
  const yc1 = BigInt(point[1][1]);
  return Buffer.concat([
    Buffer.from(fpToBE48(xc1)),
    Buffer.from(fpToBE48(xc0)),
    Buffer.from(fpToBE48(yc1)),
    Buffer.from(fpToBE48(yc0)),
  ]);
}

// ── Poseidon over byte chunks (matches circuit's PoseidonBytes) ──────

function poseidonBytes(bytes, nBytes, poseidonFn) {
  const nBlocks = Math.ceil(nBytes / 31);
  const padded = new Uint8Array(nBlocks * 31);
  padded.set(bytes.subarray(0, nBytes));
  const fields = [];
  for (let b = 0; b < nBlocks; b++) {
    let acc = 0n;
    for (let i = 0; i < 31; i++) {
      acc = acc * 256n + BigInt(padded[b * 31 + i]);
    }
    fields.push(acc);
  }
  return poseidonFn(fields);
}

function formatRustBytes(bytes, indent = "    ") {
  const lines = [];
  const perRow = 12;
  for (let i = 0; i < bytes.length; i += perRow) {
    const row = [];
    for (let j = i; j < Math.min(i + perRow, bytes.length); j++) {
      row.push("0x" + bytes[j].toString(16).padStart(2, "0"));
    }
    lines.push(indent + row.join(", ") + ",");
  }
  return lines.join("\n");
}

// ── Step 1: pick a representative GPv2Order ────────────────────────────

// USDC mainnet
const SELL_TOKEN = Buffer.from("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", "hex");
// WETH mainnet
const BUY_TOKEN  = Buffer.from("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", "hex");
// arbitrary recipient (same as the existing test vectors for visual consistency)
const RECEIVER   = Buffer.from("742d35cc6634c0532925a3b844bc454e4438f44e", "hex");

// 1000.000000 USDC (USDC has 6 decimals → 1000 * 10^6 = 1_000_000_000)
const SELL_AMOUNT = 1_000_000_000n;
// 0.5 WETH (WETH has 18 decimals → 0.5 * 10^18 = 500_000_000_000_000_000)
const BUY_AMOUNT  = 500_000_000_000_000_000n;
// fee = 0
const FEE_AMOUNT  = 0n;

// validTo = 0x68000000 (an arbitrary far-future Unix timestamp,
// matches the existing M3 vector for visual consistency)
const VALID_TO = 0x68000000;

// kind = 0 (sell), partiallyFillable = 0, sellTokenBalance = 0 (erc20),
// buyTokenBalance = 0 (erc20)
const KIND = 0;
const PARTIALLY_FILLABLE = 0;
const SELL_TOKEN_BALANCE = 0;
const BUY_TOKEN_BALANCE = 0;

function uint256BE(value) {
  const out = new Uint8Array(32);
  let v = value;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

// ── Step 2: build the 164-byte canonical buffer ────────────────────────
//
//   [  0..  20)  sellToken
//   [ 20..  40)  buyToken
//   [ 40..  60)  receiver
//   [ 60..  92)  sellAmount  (uint256 BE)
//   [ 92.. 124)  buyAmount   (uint256 BE)
//   [124.. 156)  feeAmount   (uint256 BE)
//   [156.. 160)  validTo     (uint32 BE)
//   [160]        kind
//   [161]        partiallyFillable
//   [162]        sellTokenBalance
//   [163]        buyTokenBalance

const canonical = Buffer.alloc(164);
SELL_TOKEN.copy(canonical, 0);
BUY_TOKEN.copy(canonical, 20);
RECEIVER.copy(canonical, 40);
Buffer.from(uint256BE(SELL_AMOUNT)).copy(canonical, 60);
Buffer.from(uint256BE(BUY_AMOUNT)).copy(canonical, 92);
Buffer.from(uint256BE(FEE_AMOUNT)).copy(canonical, 124);
canonical.writeUInt32BE(VALID_TO, 156);
canonical[160] = KIND;
canonical[161] = PARTIALLY_FILLABLE;
canonical[162] = SELL_TOKEN_BALANCE;
canonical[163] = BUY_TOKEN_BALANCE;

// ── Step 3: build the readable string ──────────────────────────────────

const readable = Buffer.alloc(64);
const kindStr = KIND === 0 ? "SELL" : "BUY ";
const validToHex = VALID_TO.toString(16).padStart(8, "0").toUpperCase();
const line1 = "CowSwap " + kindStr + "    ";       // 16 chars
const line2 = "exp 0x" + validToHex + "  ";        // 16 chars
const headerStr = line1 + line2;
if (headerStr.length !== 32) {
  throw new Error(`readable header is ${headerStr.length} chars, expected 32`);
}
Buffer.from(headerStr, "ascii").copy(readable, 0);

// ── Step 4: compute Poseidon hashes ────────────────────────────────────

const { poseidon3, poseidon6 } = require(path.join(NODE_MODULES, "poseidon-bls12381"));

const H_tx = poseidonBytes(canonical, 164, poseidon6);
const H_str = poseidonBytes(readable, 64, poseidon3);

process.stdout.write("canonical = " + canonical.toString("hex") + "\n");
process.stdout.write("readable  = " + readable.toString("hex") + "\n");
process.stdout.write("readable ascii = " + JSON.stringify(headerStr) + "\n");
process.stdout.write("H_tx      = " + H_tx.toString() + "\n");
process.stdout.write("H_str     = " + H_str.toString() + "\n");

// ── Step 5: write input.json ──────────────────────────────────────────

const input = {
  H_tx: H_tx.toString(),
  H_str: H_str.toString(),
  canonical: Array.from(canonical).map(b => b.toString()),
  human_string: Array.from(readable).map(b => b.toString()),
};
const inputPath = path.join(BUILD_DIR, "e2e_input.json");
fs.mkdirSync(BUILD_DIR, { recursive: true });
fs.writeFileSync(inputPath, JSON.stringify(input, null, 2));
process.stdout.write("wrote " + inputPath + "\n");

// ── Step 6: run the witness generator ─────────────────────────────────

if (!fs.existsSync(WASM)) {
  process.stderr.write(
    "error: " + WASM + " not found.\n" +
    "run `circom circuits/cowswap/eip712_order/circuit.circom " +
    "--r1cs --wasm --sym --prime bls12381 " +
    "--output build/circuits/cowswap_eip712_order/ " +
    "-l circuits/node_modules` first.\n"
  );
  process.exit(2);
}

const witnessPath = path.join(BUILD_DIR, "e2e_witness.wtns");
execSync(`node "${WITNESS_GEN}" "${WASM}" "${inputPath}" "${witnessPath}"`, {
  stdio: "inherit",
});

// ── Step 7: groth16 prove + verify ─────────────────────────────────────

const proofPath = path.join(BUILD_DIR, "e2e_proof.json");
const publicPath = path.join(BUILD_DIR, "e2e_public.json");
execSync(`"${SNARKJS}" groth16 prove "${ZKEY}" "${witnessPath}" "${proofPath}" "${publicPath}"`, {
  stdio: "inherit",
});
const vkJsonPath = path.join(BUILD_DIR, "verification_key.json");
if (!fs.existsSync(vkJsonPath)) {
  execSync(`"${SNARKJS}" zkey export verificationkey "${ZKEY}" "${vkJsonPath}"`);
}
execSync(`"${SNARKJS}" groth16 verify "${vkJsonPath}" "${publicPath}" "${proofPath}"`, {
  stdio: "inherit",
});

// ── Step 8: convert to firmware proof byte layout ─────────────────────

const proof = JSON.parse(fs.readFileSync(proofPath, "utf8"));
const pi_a = g1Bytes(proof.pi_a);
const pi_b = g2Bytes(proof.pi_b);
const pi_c = g1Bytes(proof.pi_c);
if (pi_a.length !== 96) throw new Error("pi.A size mismatch");
if (pi_b.length !== 192) throw new Error("pi.B size mismatch");
if (pi_c.length !== 96) throw new Error("pi.C size mismatch");
const proofBytes = Buffer.concat([pi_a, pi_b, pi_c]);

const pubSignals = JSON.parse(fs.readFileSync(publicPath, "utf8"));
if (BigInt(pubSignals[0]) !== H_tx || BigInt(pubSignals[1]) !== H_str) {
  process.stderr.write("error: public signals do not match computed Poseidon hashes\n");
  process.exit(3);
}

// ── Step 9: emit Rust snippet ─────────────────────────────────────────

const SENTINEL = "0x9008D19f58AAbD9eD0D60971565AA8510560ab42";
const sentinelBytes = Buffer.from(SENTINEL.slice(2), "hex");

const rustSnippet =
  `// === AUTO-GENERATED by circuits/scripts/gen_cowswap_eip712_e2e_vector.js ===
// Inputs:
//   sellToken = 0x${SELL_TOKEN.toString("hex")} (USDC mainnet)
//   buyToken  = 0x${BUY_TOKEN.toString("hex")}  (WETH mainnet)
//   receiver  = 0x${RECEIVER.toString("hex")}
//   sellAmount = ${SELL_AMOUNT.toString()}  (1000.000000 USDC, 6 decimals)
//   buyAmount  = ${BUY_AMOUNT.toString()}    (0.5 WETH, 18 decimals)
//   feeAmount  = 0
//   validTo    = 0x${VALID_TO.toString(16).padStart(8, "0")}
//   kind       = ${KIND === 0 ? "SELL" : "BUY"}
//   partiallyFillable = ${PARTIALLY_FILLABLE}
//   sellTokenBalance / buyTokenBalance = erc20 / erc20
//   readable   = ${JSON.stringify(headerStr)}
//   sentinel addr (DB lookup key) = ${SENTINEL}
//
// Regenerate by running:
//   node circuits/scripts/gen_cowswap_eip712_e2e_vector.js
// and pasting the output back into this file.

#[rustfmt::skip]
static EIP712_PROOF: [u8; 384] = [
${formatRustBytes(proofBytes)}
];

#[rustfmt::skip]
static EIP712_CANONICAL: [u8; 164] = [
${formatRustBytes(canonical)}
];

#[rustfmt::skip]
static EIP712_READABLE: [u8; 64] = [
${formatRustBytes(readable)}
];

const COWSWAP_EIP712_SENTINEL_MAINNET: [u8; 20] = [
${formatRustBytes(sentinelBytes)}
];
`;

const rustOut = path.join(BUILD_DIR, "e2e_vector.rs");
fs.writeFileSync(rustOut, rustSnippet);
process.stdout.write("\n\n=== Rust snippet written to " + rustOut + " ===\n");
process.stdout.write("Paste its contents into nonsecure/src/e2e_test.rs\n");
process.stdout.write(rustSnippet);
