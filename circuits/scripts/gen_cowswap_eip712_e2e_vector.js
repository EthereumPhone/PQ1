#!/usr/bin/env node
//
// gen_cowswap_eip712_e2e_vector.js
//
// Generates a self-consistent e2e test vector for the
// `cowswap_eip712_order` circuit (M4, v2):
//
//   1. Picks a representative GPv2Order (sell USDC for WETH).
//   2. Encodes it into the 164-byte packed canonical buffer the
//      circuit hashes via Poseidon6.
//   3. Builds the readable string the circuit's format function
//      enforces, using the same in-tree ERC20 registry layout that
//      `circuits/lib/erc20_registry.circom` bakes in:
//
//        Line 0 (16): "CowSwap SELL    "  / "CowSwap BUY     "
//        Line 1 (16): "  XXXXXX.YYYY SSSS"  ← sell amount + symbol
//        Line 2 (16): "for at least:   "
//        Line 3 (16): "  XXXXXX.YYYY SSSS"  ← buy amount + symbol
//
//      Total = 64 bytes; matches the circuit's STRING_LEN.
//
//   4. Computes Poseidon255 hashes of both via the poseidon-bls12381
//      npm package (the same library the firmware's `poseidon_bytes`
//      reimplements).
//   5. Writes an `input.json` that drives the circom-compiled
//      witness generator.
//   6. Runs the witness generator to produce a `witness.wtns`.
//   7. Runs `snarkjs groth16 prove` against the committed
//      `circuits/cowswap/eip712_order/circuit_final.zkey`.
//   8. Verifies the proof locally as a sanity check.
//   9. Converts proof.json into the firmware's uncompressed BLS12-381
//      byte layout (96 B G1, 192 B G2 with c1-first ordering).
//  10. Emits a Rust snippet ready to paste into
//      `nonsecure/src/e2e_test.rs` between AUTO-GENERATED EIP712 markers.
//
// Usage:
//   node circuits/scripts/gen_cowswap_eip712_e2e_vector.js
//
// Prereqs: `npm ci --prefix circuits` already done, and
// `build/circuits/cowswap_eip712_order/circuit_js/circuit.wasm` exists.

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

// ── Format constants — MUST match circuits/lib/format.circom and
//    circuits/cowswap/eip712_order/circuit.circom ─────────────────────
const MAX_INT_DIGITS = 6;
const FRAC_DIGITS    = 4;
const MAX_DECIMALS   = 18;
const SYMBOL_LEN     = 4;

// ── ERC20 registry — MUST match circuits/lib/erc20_registry.circom ──
const REGISTRY = [
  { idx: 0, addr: "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", decimals: 6,  symbol: "USDC" },
  { idx: 1, addr: "dac17f958d2ee523a2206206994597c13d831ec7", decimals: 6,  symbol: "USDT" },
  { idx: 2, addr: "6b175474e89094c44da98b954eedeac495271d0f", decimals: 18, symbol: "DAI " },
  { idx: 3, addr: "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", decimals: 18, symbol: "WETH" },
  { idx: 4, addr: "2260fac5e5542a773aa44fbcfedf7c193bc2c599", decimals: 8,  symbol: "WBTC" },
  { idx: 5, addr: "514910771af9ca656af840dff83e8264ecf986ca", decimals: 18, symbol: "LINK" },
  { idx: 6, addr: "7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9", decimals: 18, symbol: "AAVE" },
  { idx: 7, addr: "1f9840a85d5af5bf1d1762f925bdaddc4201f984", decimals: 18, symbol: "UNI " },
];

function lookupToken(addrHex) {
  const k = addrHex.toLowerCase().replace(/^0x/, "");
  const t = REGISTRY.find(r => r.addr === k);
  if (!t) throw new Error(`token not in registry: 0x${k}`);
  return t;
}

// ── BLS12-381 helpers ──────────────────────────────────────────────────
const FP_PRIME = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaabn;

function fpToBE48(n) {
  n = ((n % FP_PRIME) + FP_PRIME) % FP_PRIME;
  const out = new Uint8Array(48);
  for (let i = 47; i >= 0; i--) { out[i] = Number(n & 0xffn); n >>= 8n; }
  return out;
}
function g1Bytes(point) {
  const x = BigInt(point[0]); const y = BigInt(point[1]);
  return Buffer.concat([Buffer.from(fpToBE48(x)), Buffer.from(fpToBE48(y))]);
}
function g2Bytes(point) {
  const xc0 = BigInt(point[0][0]); const xc1 = BigInt(point[0][1]);
  const yc0 = BigInt(point[1][0]); const yc1 = BigInt(point[1][1]);
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
    for (let i = 0; i < 31; i++) acc = acc * 256n + BigInt(padded[b * 31 + i]);
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

// ── Witness builders for FormatTrimmedAmount ─────────────────────────
//
// Mirror the circuit equation:
//
//   raw_amount * scale_factor
//     == int_value * 10^MAX_DECIMALS
//      + frac_value * 10^(MAX_DECIMALS - FRAC_DIGITS)
//      + remainder
//
// We need to produce int_digits[6], frac_digits[4], n_leading_zeros,
// and remainder so the circuit accepts the witness AND the resulting
// ASCII string matches what the readable layout demands.
function buildAmountWitness(rawAmount, decimals) {
  const POW_MAX  = 10n ** BigInt(MAX_DECIMALS);
  const POW_SKIP = 10n ** BigInt(MAX_DECIMALS - FRAC_DIGITS);
  const SCALE    = 10n ** BigInt(MAX_DECIMALS - decimals);

  const scaled = BigInt(rawAmount) * SCALE;
  const intValue  = scaled / POW_MAX;
  const intRem    = scaled % POW_MAX;
  const fracValue = intRem / POW_SKIP;
  const remainder = intRem % POW_SKIP;

  const POW_INT_MAX = 10n ** BigInt(MAX_INT_DIGITS);
  if (intValue >= POW_INT_MAX) {
    throw new Error(
      `amount ${rawAmount} (decimals=${decimals}) exceeds MAX_INT_DIGITS=${MAX_INT_DIGITS}`
    );
  }

  // BE int digits (most significant at index 0), padded to MAX_INT_DIGITS.
  const intDigits = [];
  for (let i = 0; i < MAX_INT_DIGITS; i++) {
    const place = 10n ** BigInt(MAX_INT_DIGITS - 1 - i);
    intDigits.push(Number((intValue / place) % 10n));
  }
  // BE frac digits (most significant at index 0), padded to FRAC_DIGITS.
  const fracDigits = [];
  for (let i = 0; i < FRAC_DIGITS; i++) {
    const place = 10n ** BigInt(FRAC_DIGITS - 1 - i);
    fracDigits.push(Number((fracValue / place) % 10n));
  }

  // Count leading zeros, but always leave at least one visible digit
  // (the format helper ranges n_lz strictly less than MAX_INT_DIGITS).
  let nLz = 0;
  while (nLz < MAX_INT_DIGITS - 1 && intDigits[nLz] === 0) nLz++;

  // Reproduce the ASCII the circuit will produce (caller uses this
  // to compose the readable string).
  const asciiBytes = [];
  for (let i = 0; i < MAX_INT_DIGITS; i++) {
    asciiBytes.push(i < nLz ? 0x20 : 0x30 + intDigits[i]);
  }
  asciiBytes.push(0x2e); // '.'
  for (let i = 0; i < FRAC_DIGITS; i++) {
    asciiBytes.push(0x30 + fracDigits[i]);
  }

  return {
    int_digits: intDigits,
    frac_digits: fracDigits,
    n_leading_zeros: nLz,
    remainder: remainder.toString(),
    ascii: asciiBytes,
  };
}

// ── Step 1: pick a representative GPv2Order ────────────────────────────
const SELL = lookupToken("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"); // USDC
const BUY  = lookupToken("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"); // WETH
const RECEIVER = Buffer.from("742d35cc6634c0532925a3b844bc454e4438f44e", "hex");

// 1000.0000 USDC sell, 0.5000 WETH min buy.
//   USDC has 6 decimals: 1000.0000 USDC → display "1000.0000",
//   raw = 1000 * 10^6 = 1_000_000_000.
//   WETH has 18 decimals: 0.5000 WETH → display "0.5000",
//   raw = 0.5 * 10^18 = 500_000_000_000_000_000.
const SELL_AMOUNT = 1_000_000_000n;
const BUY_AMOUNT  = 500_000_000_000_000_000n;
const FEE_AMOUNT  = 0n;
const VALID_TO    = 0x68000000;
const KIND        = 0; // sell
const PARTIALLY_FILLABLE = 0;
const SELL_TOKEN_BALANCE = 0;
const BUY_TOKEN_BALANCE  = 0;

function uint256BE(value) {
  const out = new Uint8Array(32);
  let v = value;
  for (let i = 31; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}

// ── Step 2: build the 164-byte canonical buffer ────────────────────────
const canonical = Buffer.alloc(164);
Buffer.from(SELL.addr, "hex").copy(canonical, 0);
Buffer.from(BUY.addr,  "hex").copy(canonical, 20);
RECEIVER.copy(canonical, 40);
Buffer.from(uint256BE(SELL_AMOUNT)).copy(canonical, 60);
Buffer.from(uint256BE(BUY_AMOUNT)).copy(canonical, 92);
Buffer.from(uint256BE(FEE_AMOUNT)).copy(canonical, 124);
canonical.writeUInt32BE(VALID_TO, 156);
canonical[160] = KIND;
canonical[161] = PARTIALLY_FILLABLE;
canonical[162] = SELL_TOKEN_BALANCE;
canonical[163] = BUY_TOKEN_BALANCE;

// ── Step 3: build the readable string + amount witnesses ─────────────
const sellW = buildAmountWitness(SELL_AMOUNT, SELL.decimals);
const buyW  = buildAmountWitness(BUY_AMOUNT,  BUY.decimals);

const readable = Buffer.alloc(64);

// Line 0
const LINE0 = KIND === 0 ? "CowSwap SELL    " : "CowSwap BUY     ";
Buffer.from(LINE0, "ascii").copy(readable, 0);

// Line 1: <sell ascii (11)> ' ' <symbol (4)>
for (let i = 0; i < sellW.ascii.length; i++) readable[16 + i] = sellW.ascii[i];
readable[16 + sellW.ascii.length] = 0x20;
Buffer.from(SELL.symbol, "ascii").copy(readable, 16 + sellW.ascii.length + 1);

// Line 2
const LINE2 = "for at least:   ";
Buffer.from(LINE2, "ascii").copy(readable, 32);

// Line 3
for (let i = 0; i < buyW.ascii.length; i++) readable[48 + i] = buyW.ascii[i];
readable[48 + buyW.ascii.length] = 0x20;
Buffer.from(BUY.symbol, "ascii").copy(readable, 48 + buyW.ascii.length + 1);

// Sanity-check: every byte slot is filled (no padding zeros).
for (let i = 0; i < 64; i++) {
  if (readable[i] === 0) throw new Error(`readable[${i}] is null — layout bug`);
}

const headerStr = readable.toString("ascii");

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
  sell_token_idx: SELL.idx.toString(),
  buy_token_idx:  BUY.idx.toString(),
  sell_int_digits:  sellW.int_digits.map(String),
  sell_frac_digits: sellW.frac_digits.map(String),
  sell_n_lz:        sellW.n_leading_zeros.toString(),
  sell_remainder:   sellW.remainder,
  buy_int_digits:   buyW.int_digits.map(String),
  buy_frac_digits:  buyW.frac_digits.map(String),
  buy_n_lz:         buyW.n_leading_zeros.toString(),
  buy_remainder:    buyW.remainder,
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
execSync(`node "${WITNESS_GEN}" "${WASM}" "${inputPath}" "${witnessPath}"`, { stdio: "inherit" });

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
if (pi_a.length !== 96)  throw new Error("pi.A size mismatch");
if (pi_b.length !== 192) throw new Error("pi.B size mismatch");
if (pi_c.length !== 96)  throw new Error("pi.C size mismatch");
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
//   sellToken = 0x${SELL.addr} (${SELL.symbol.trim()})
//   buyToken  = 0x${BUY.addr}  (${BUY.symbol.trim()})
//   receiver  = 0x${RECEIVER.toString("hex")}
//   sellAmount = ${SELL_AMOUNT.toString()}  (${SELL_AMOUNT.toString().slice(0,-SELL.decimals) || "0"}.* ${SELL.symbol.trim()})
//   buyAmount  = ${BUY_AMOUNT.toString()}  (${BUY_AMOUNT.toString().padStart(BUY.decimals+1,"0").slice(0,-BUY.decimals)}.* ${BUY.symbol.trim()})
//   feeAmount  = 0
//   validTo    = 0x${VALID_TO.toString(16).padStart(8, "0")}
//   kind       = ${KIND === 0 ? "SELL" : "BUY"}
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
