#!/usr/bin/env node
//
// gen_cowswap_eip712_e2e_vector.js
//
// Generates a self-consistent e2e test vector for the
// `cowswap_eip712_order` circuit (M4, v3):
//
//   1. Picks a representative GPv2Order (sell USDC for WETH, mainnet).
//   2. Looks up the sell + buy token entries in
//      `circuits/generated/erc20_poseidon_tree.json` (built by
//      `cargo run -p dbgen`). This gives us the Merkle root, each
//      token's leaf index, and the sibling hashes along the inclusion
//      path — everything the circuit's `MerkleErc20Registry` expects.
//   3. Encodes the order into the 204-byte canonical buffer the
//      circuit hashes via Poseidon7. Layout:
//
//        [  0..  8)  chain_id          (u64 BE)
//        [  8.. 28)  sellToken
//        [ 28.. 48)  buyToken
//        [ 48.. 68)  receiver
//        [ 68..100)  sellAmount        (uint256 BE)
//        [100..132)  buyAmount         (uint256 BE)
//        [132..164)  feeAmount         (uint256 BE)
//        [164..168)  validTo           (u32 BE)
//        [168]       kind
//        [169]       partiallyFillable
//        [170]       sellTokenBalance
//        [171]       buyTokenBalance
//        [172..204)  appData           (bytes32)
//
//   4. Builds the 128-byte readable string (8 × 16 = 128) the circuit
//      enforces:
//
//        Line 0: "CowSwap SELL    " / "CowSwap BUY     "
//        Line 1: "SELL:           "
//        Line 2: " XXXXXXXXXX.YYYY"  (1 pad + 10 int + '.' + 4 frac)
//        Line 3: "          SSSSSS"  (10 pad + 6-char symbol)
//        Line 4: "for at least:   "
//        Line 5: " XXXXXXXXXX.YYYY"
//        Line 6: "          SSSSSS"
//        Line 7: "                "
//
//   5. Computes Poseidon255(7) of the canonical → H_tx and
//      Poseidon255(5) of the readable → H_str. H_root comes straight
//      from the Poseidon tree JSON and is the third public signal.
//   6. Writes `input.json` driving the circom-compiled witness
//      generator, runs it, runs `snarkjs groth16 prove`, and verifies.
//   7. Converts proof.json into the firmware's uncompressed BLS12-381
//      byte layout (96 B G1, 192 B G2 with c1-first ordering).
//   8. Emits a Rust snippet ready to paste into
//      `nonsecure/src/e2e_test.rs` between AUTO-GENERATED markers.
//
// Usage:
//   node circuits/scripts/gen_cowswap_eip712_e2e_vector.js
//
// Prereqs:
//   - `npm ci --prefix circuits` done
//   - `cargo run -p dbgen` run at least once (so the Poseidon tree
//     JSON exists and the committed zkey matches the current Merkle root)
//   - `build/circuits/cowswap_eip712_order/circuit_js/circuit.wasm`
//     built via circom

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
const POSEIDON_TREE_JSON = path.join(
  CIRCUITS_DIR,
  "generated",
  "erc20_poseidon_tree.json",
);

// ── Format constants — MUST match circuits/cowswap/eip712_order/circuit.circom
const CANONICAL_LEN  = 204;
const STRING_LEN     = 128;
const MAX_INT_DIGITS = 10;
const FRAC_DIGITS    = 4;
const MAX_DECIMALS   = 18;
const SYMBOL_LEN     = 6;
const TREE_HEIGHT    = 8;
const AMOUNT_ASCII   = MAX_INT_DIGITS + 1 + FRAC_DIGITS; // 15

// ── BLS12-381 helpers (same as v2) ────────────────────────────────
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

// ── Rust-byte-array emitter (12 bytes/row) ──────────────────────────
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

// ── Load the Poseidon-Merkle tree export from dbgen ────────────────
if (!fs.existsSync(POSEIDON_TREE_JSON)) {
  process.stderr.write(
    "error: " + POSEIDON_TREE_JSON + " not found.\n" +
    "run `cargo run -p dbgen` first to generate it.\n",
  );
  process.exit(2);
}
const TREE = JSON.parse(fs.readFileSync(POSEIDON_TREE_JSON, "utf8"));
if (TREE.depth !== TREE_HEIGHT) {
  throw new Error(
    `dbgen tree depth ${TREE.depth} !== circuit TREE_HEIGHT ${TREE_HEIGHT}`,
  );
}
const H_root_dec = TREE.root; // decimal string; used as pub input

function lookupEntry(chainId, addrHex) {
  const key = addrHex.toLowerCase().replace(/^0x/, "");
  const entry = TREE.entries.find(
    (e) => e.chain_id === chainId && e.address.toLowerCase() === key,
  );
  if (!entry) {
    throw new Error(
      `no poseidon entry for (chain_id=${chainId}, address=0x${key})`,
    );
  }
  return entry;
}

// ── Witness builders for FormatTrimmedAmount (strict: remainder===0) ─
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
      `amount ${rawAmount} (decimals=${decimals}) exceeds MAX_INT_DIGITS=${MAX_INT_DIGITS}`,
    );
  }
  if (remainder !== 0n) {
    throw new Error(
      `amount ${rawAmount} (decimals=${decimals}) has sub-10^-${FRAC_DIGITS} precision — v3 rejects`,
    );
  }

  const intDigits = [];
  for (let i = 0; i < MAX_INT_DIGITS; i++) {
    const place = 10n ** BigInt(MAX_INT_DIGITS - 1 - i);
    intDigits.push(Number((intValue / place) % 10n));
  }
  const fracDigits = [];
  for (let i = 0; i < FRAC_DIGITS; i++) {
    const place = 10n ** BigInt(FRAC_DIGITS - 1 - i);
    fracDigits.push(Number((fracValue / place) % 10n));
  }

  let nLz = 0;
  while (nLz < MAX_INT_DIGITS - 1 && intDigits[nLz] === 0) nLz++;

  // Reproduce the ASCII the circuit emits (10 int + '.' + 4 frac = 15).
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
    remainder: "0",
    ascii: asciiBytes,
  };
}

// Build the sell/buy registry witness inputs from a TREE entry.
// `symbol_bytes` is padded on the right with ASCII 0x20 up to SYMBOL_LEN.
// `path_sel[i]` = bit i of leaf_idx (leaf-up ordering).
function buildRegistryWitness(entry) {
  const symBytes = [];
  for (let i = 0; i < SYMBOL_LEN; i++) {
    symBytes.push(i < entry.symbol.length ? entry.symbol.charCodeAt(i) : 0x20);
  }
  let idx = entry.leaf_idx;
  const pathSel = [];
  for (let i = 0; i < TREE_HEIGHT; i++) {
    pathSel.push(idx & 1);
    idx >>= 1;
  }
  return {
    decimals: entry.decimals.toString(),
    symbol_bytes: symBytes.map(String),
    symbol_len: entry.symbol.length.toString(),
    path_sel: pathSel.map(String),
    siblings: entry.proof, // already decimal strings
  };
}

// ── Pick a representative order ────────────────────────────────────
const CHAIN_ID = 1; // Mainnet
const SELL_ADDR = "a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"; // USDC
const BUY_ADDR  = "c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"; // WETH
const RECEIVER = Buffer.from("742d35cc6634c0532925a3b844bc454e4438f44e", "hex");

const SELL_ENTRY = lookupEntry(CHAIN_ID, SELL_ADDR);
const BUY_ENTRY  = lookupEntry(CHAIN_ID, BUY_ADDR);

// 1000.0000 USDC sell, 0.5000 WETH min buy (same vector shape as v2).
//   USDC 6 dec: 1000.0000 → raw 1e9
//   WETH 18 dec: 0.5000 → raw 5e17
const SELL_AMOUNT = 1_000_000_000n;
const BUY_AMOUNT  = 500_000_000_000_000_000n;
const FEE_AMOUNT  = 0n;
const VALID_TO    = 0x68000000;
const KIND        = 0; // sell
const PARTIALLY_FILLABLE = 0;
const SELL_TOKEN_BALANCE = 0;
const BUY_TOKEN_BALANCE  = 0;
// Real-world CowSwap orders pin an appCode hash here. For the e2e
// vector we use keccak256("cowswap-zk-clear-signing-v3-test") so the
// test covers a NON-zero appData — proving the fix for v2's
// "appData pinned to bytes32(0)" limitation.
const APP_DATA_HEX = "83b9dcb2316e54fc04c10f74c9a3d5dd66a9e4c43c04ccefb9c0c03e61e5fb28";

function uint256BE(value) {
  const out = new Uint8Array(32);
  let v = value;
  for (let i = 31; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}

// ── Build the 204-byte canonical ─────────────────────────────────
const canonical = Buffer.alloc(CANONICAL_LEN);
canonical.writeBigUInt64BE(BigInt(CHAIN_ID), 0);
Buffer.from(SELL_ADDR, "hex").copy(canonical, 8);
Buffer.from(BUY_ADDR,  "hex").copy(canonical, 28);
RECEIVER.copy(canonical, 48);
Buffer.from(uint256BE(SELL_AMOUNT)).copy(canonical, 68);
Buffer.from(uint256BE(BUY_AMOUNT)).copy(canonical, 100);
Buffer.from(uint256BE(FEE_AMOUNT)).copy(canonical, 132);
canonical.writeUInt32BE(VALID_TO, 164);
canonical[168] = KIND;
canonical[169] = PARTIALLY_FILLABLE;
canonical[170] = SELL_TOKEN_BALANCE;
canonical[171] = BUY_TOKEN_BALANCE;
Buffer.from(APP_DATA_HEX, "hex").copy(canonical, 172);

// ── Build the 128-byte readable ─────────────────────────────────
const sellW = buildAmountWitness(SELL_AMOUNT, SELL_ENTRY.decimals);
const buyW  = buildAmountWitness(BUY_AMOUNT,  BUY_ENTRY.decimals);

const readable = Buffer.alloc(STRING_LEN);
const SELL_HEADER = "CowSwap SELL    ";
const BUY_HEADER  = "CowSwap BUY     ";
const LINE1_TEXT  = "SELL:           ";
const LINE4_TEXT  = "for at least:   ";
const LINE7_TEXT  = "                ";

function writeLine(rowIdx, text) {
  Buffer.from(text, "ascii").copy(readable, rowIdx * 16);
}
function padRowSpaces(rowIdx) {
  for (let i = 0; i < 16; i++) readable[rowIdx * 16 + i] = 0x20;
}
function symbolBytesForRow(entry) {
  const out = new Uint8Array(SYMBOL_LEN);
  for (let i = 0; i < SYMBOL_LEN; i++) {
    out[i] = i < entry.symbol.length ? entry.symbol.charCodeAt(i) : 0x20;
  }
  return out;
}

// Line 0: kind
writeLine(0, KIND === 0 ? SELL_HEADER : BUY_HEADER);
// Line 1
writeLine(1, LINE1_TEXT);
// Line 2: " XXXXXXXXXX.YYYY" — 1 pad + 15-char amount
padRowSpaces(2);
readable[32] = 0x20;
for (let i = 0; i < AMOUNT_ASCII; i++) readable[33 + i] = sellW.ascii[i];
// Line 3: "          SSSSSS" — 10 pad + symbol
padRowSpaces(3);
const sellSym = symbolBytesForRow(SELL_ENTRY);
for (let i = 0; i < SYMBOL_LEN; i++) readable[48 + 10 + i] = sellSym[i];
// Line 4
writeLine(4, LINE4_TEXT);
// Line 5
padRowSpaces(5);
readable[80] = 0x20;
for (let i = 0; i < AMOUNT_ASCII; i++) readable[81 + i] = buyW.ascii[i];
// Line 6
padRowSpaces(6);
const buySym = symbolBytesForRow(BUY_ENTRY);
for (let i = 0; i < SYMBOL_LEN; i++) readable[96 + 10 + i] = buySym[i];
// Line 7
writeLine(7, LINE7_TEXT);

// Sanity-check: no stray null bytes.
for (let i = 0; i < STRING_LEN; i++) {
  if (readable[i] === 0) throw new Error(`readable[${i}] is null — layout bug`);
}

// ── Compute Poseidon hashes ────────────────────────────────────────
const { poseidon5, poseidon7 } = require(path.join(NODE_MODULES, "poseidon-bls12381"));

const H_tx  = poseidonBytes(canonical, CANONICAL_LEN, poseidon7);
const H_str = poseidonBytes(readable, STRING_LEN, poseidon5);

process.stdout.write("canonical = " + canonical.toString("hex") + "\n");
process.stdout.write("readable  = " + readable.toString("hex") + "\n");
process.stdout.write("readable  = " + JSON.stringify(readable.toString("ascii")) + "\n");
process.stdout.write("H_tx      = " + H_tx.toString() + "\n");
process.stdout.write("H_str     = " + H_str.toString() + "\n");
process.stdout.write("H_root    = " + H_root_dec + "\n");

// ── Build registry witnesses ───────────────────────────────────────
const sellReg = buildRegistryWitness(SELL_ENTRY);
const buyReg  = buildRegistryWitness(BUY_ENTRY);

// ── input.json ─────────────────────────────────────────────────────
const input = {
  H_tx: H_tx.toString(),
  H_str: H_str.toString(),
  H_root: H_root_dec,
  canonical: Array.from(canonical).map((b) => b.toString()),
  human_string: Array.from(readable).map((b) => b.toString()),

  sell_decimals: sellReg.decimals,
  sell_symbol_bytes: sellReg.symbol_bytes,
  sell_symbol_len: sellReg.symbol_len,
  sell_path_sel: sellReg.path_sel,
  sell_siblings: sellReg.siblings,

  buy_decimals: buyReg.decimals,
  buy_symbol_bytes: buyReg.symbol_bytes,
  buy_symbol_len: buyReg.symbol_len,
  buy_path_sel: buyReg.path_sel,
  buy_siblings: buyReg.siblings,

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

// ── Witness gen ────────────────────────────────────────────────────
if (!fs.existsSync(WASM)) {
  process.stderr.write(
    "error: " + WASM + " not found.\n" +
    "run `circom circuits/cowswap/eip712_order/circuit.circom " +
    "--r1cs --wasm --sym --prime bls12381 " +
    "--output build/circuits/cowswap_eip712_order/ " +
    "-l circuits/node_modules` first.\n",
  );
  process.exit(2);
}

const witnessPath = path.join(BUILD_DIR, "e2e_witness.wtns");
execSync(`node "${WITNESS_GEN}" "${WASM}" "${inputPath}" "${witnessPath}"`, {
  stdio: "inherit",
});

// ── Prove + verify ─────────────────────────────────────────────────
const proofPath = path.join(BUILD_DIR, "e2e_proof.json");
const publicPath = path.join(BUILD_DIR, "e2e_public.json");
execSync(
  `"${SNARKJS}" groth16 prove "${ZKEY}" "${witnessPath}" "${proofPath}" "${publicPath}"`,
  { stdio: "inherit" },
);
const vkJsonPath = path.join(BUILD_DIR, "verification_key.json");
if (!fs.existsSync(vkJsonPath)) {
  execSync(`"${SNARKJS}" zkey export verificationkey "${ZKEY}" "${vkJsonPath}"`);
}
execSync(
  `"${SNARKJS}" groth16 verify "${vkJsonPath}" "${publicPath}" "${proofPath}"`,
  { stdio: "inherit" },
);

// ── Firmware proof byte layout ─────────────────────────────────────
const proof = JSON.parse(fs.readFileSync(proofPath, "utf8"));
const pi_a = g1Bytes(proof.pi_a);
const pi_b = g2Bytes(proof.pi_b);
const pi_c = g1Bytes(proof.pi_c);
if (pi_a.length !== 96)  throw new Error("pi.A size mismatch");
if (pi_b.length !== 192) throw new Error("pi.B size mismatch");
if (pi_c.length !== 96)  throw new Error("pi.C size mismatch");
const proofBytes = Buffer.concat([pi_a, pi_b, pi_c]);

const pubSignals = JSON.parse(fs.readFileSync(publicPath, "utf8"));
if (
  BigInt(pubSignals[0]) !== H_tx ||
  BigInt(pubSignals[1]) !== H_str ||
  BigInt(pubSignals[2]) !== BigInt(H_root_dec)
) {
  process.stderr.write(
    "error: public signals do not match (H_tx, H_str, H_root)\n" +
    "  expected: " + H_tx.toString() + " " + H_str.toString() + " " + H_root_dec + "\n" +
    "  got:      " + pubSignals.join(" ") + "\n",
  );
  process.exit(3);
}

// ── Emit Rust snippet ─────────────────────────────────────────────
const SENTINEL = "0x9008D19f58AAbD9eD0D60971565AA8510560ab42";
const sentinelBytes = Buffer.from(SENTINEL.slice(2), "hex");

const sellHuman = (Number(SELL_AMOUNT) / 10 ** SELL_ENTRY.decimals).toFixed(FRAC_DIGITS);
const buyHuman  = (Number(BUY_AMOUNT)  / 10 ** BUY_ENTRY.decimals ).toFixed(FRAC_DIGITS);

const rustSnippet =
  `// === AUTO-GENERATED by circuits/scripts/gen_cowswap_eip712_e2e_vector.js ===
// Inputs:
//   chain_id   = ${CHAIN_ID}
//   sellToken  = 0x${SELL_ADDR} (${SELL_ENTRY.symbol})
//   buyToken   = 0x${BUY_ADDR}  (${BUY_ENTRY.symbol})
//   receiver   = 0x${RECEIVER.toString("hex")}
//   sellAmount = ${SELL_AMOUNT.toString()}  (${sellHuman} ${SELL_ENTRY.symbol})
//   buyAmount  = ${BUY_AMOUNT.toString()}  (${buyHuman} ${BUY_ENTRY.symbol})
//   feeAmount  = 0
//   validTo    = 0x${VALID_TO.toString(16).padStart(8, "0")}
//   kind       = ${KIND === 0 ? "SELL" : "BUY"}
//   appData    = 0x${APP_DATA_HEX}
//   readable   = ${JSON.stringify(readable.toString("ascii"))}
//   sentinel addr (DB lookup key) = ${SENTINEL}
//
// Regenerate by running:
//   make rebuild-cowswap-v3-vector
// (or manually: cargo run -p dbgen && circom … && node this script)

#[rustfmt::skip]
static EIP712_PROOF: [u8; 384] = [
${formatRustBytes(proofBytes)}
];

#[rustfmt::skip]
static EIP712_CANONICAL: [u8; ${CANONICAL_LEN}] = [
${formatRustBytes(canonical)}
];

#[rustfmt::skip]
static EIP712_READABLE: [u8; ${STRING_LEN}] = [
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
