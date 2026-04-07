#!/usr/bin/env node
//
// gen_cowswap_e2e_vector.js
//
// Generates a self-consistent e2e test vector for the
// `cowswap_set_pre_signature` circuit:
//
//   1. Picks a representative orderUid (56 bytes), constructs the
//      `setPreSignature(bytes orderUid, bool signed=1)` calldata
//      (164 bytes total).
//   2. Builds the static readable string "Pre-sign CowSwap order"
//      padded to 64 bytes with 0x00.
//   3. Computes Poseidon255 hashes of both via the `poseidon-bls12381`
//      npm package (the same library the firmware's `poseidon_bytes`
//      reimplements bit-for-bit).
//   4. Writes an `input.json` that drives the circom-compiled
//      witness generator under
//      `build/circuits/cowswap_set_pre_signature/circuit_js/`.
//   5. Runs the witness generator to produce a `witness.wtns`.
//   6. Runs `snarkjs groth16 prove` against the committed
//      `circuits/cowswap/set_pre_signature/circuit_final.zkey`.
//   7. Converts proof.json + public.json into the firmware's
//      uncompressed BLS12-381 byte layout (96 B G1, 192 B G2 with
//      c1-first ordering).
//   8. RLP-encodes a minimal EIP-1559 envelope wrapping the calldata,
//      pointing at `GPv2Settlement` on Mainnet (chain_id=1, value=0).
//   9. Emits a Rust snippet ready to paste into
//      `nonsecure/src/e2e_test.rs` as COWSWAP_PROOF / COWSWAP_CALLDATA
//      / COWSWAP_READABLE / COWSWAP_TX.
//
// Groth16 prove is intrinsically randomised (the `r`, `s` blinding
// scalars), so successive runs produce different valid proofs. The
// test vector is committed as static bytes in e2e_test.rs — if you
// re-run this script and commit the new output, the e2e test keeps
// working but the committed proof bytes change. That's expected.
//
// Usage:
//   node circuits/scripts/gen_cowswap_e2e_vector.js
//
// Prereqs: `npm ci --prefix circuits` must have populated node_modules,
// and `build/circuits/cowswap_set_pre_signature/circuit_js/circuit.wasm`
// must exist (produced by either `tools/build_vks.sh cowswap_set_pre_signature`
// running the full pipeline, or a one-shot direct `circom` invocation
// — see the shell commands at the top of the e2e workflow docs).

"use strict";

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

const REPO_ROOT = path.join(__dirname, "..", "..");
const CIRCUITS_DIR = path.join(REPO_ROOT, "circuits");
const BUILD_DIR = path.join(REPO_ROOT, "build", "circuits", "cowswap_set_pre_signature");
const ZKEY = path.join(CIRCUITS_DIR, "cowswap", "set_pre_signature", "circuit_final.zkey");
const WASM = path.join(BUILD_DIR, "circuit_js", "circuit.wasm");
const WITNESS_GEN = path.join(BUILD_DIR, "circuit_js", "generate_witness.js");
const NODE_MODULES = path.join(CIRCUITS_DIR, "node_modules");
const SNARKJS = path.join(NODE_MODULES, ".bin", "snarkjs");

// ── Helpers ────────────────────────────────────────────────────────────

// BLS12-381 base field prime (Fp).
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

// Pack bytes into 31-byte chunks (big-endian) → field elements, then
// apply Poseidon. Matches circuits/aave_v3/clear_signing_proof.circom::PoseidonBytes
// and secure/src/zk/poseidon.rs::poseidon_bytes.
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

// ── Step 1: build calldata ─────────────────────────────────────────────

// Representative 56-byte orderUid. Not from any real order — picked so
// that every byte is distinct for easy visual inspection in hex dumps.
// Structure (per CowSwap):
//   [0..32)  orderDigest (keccak256 of the GPv2Order struct)
//   [32..52) owner       (20-byte address)
//   [52..56) validTo     (uint32 big-endian)
const ORDER_UID = Buffer.from(
  // orderDigest (32 bytes)
  "aabbccddeeff00112233445566778899" +
  "00112233445566778899aabbccddeeff" +
  // owner (20 bytes)
  "742d35cc6634c0532925a3b844bc454e4438f44e" +
  // validTo (uint32 BE) = 0x6800_0000 (some future unix timestamp)
  "68000000",
  "hex"
);
if (ORDER_UID.length !== 56) throw new Error("orderUid must be exactly 56 bytes");

// setPreSignature(bytes orderUid, bool signed) calldata layout:
//   [0..4)      selector      = 0xec6cb13f
//   [4..36)     bytes offset  = 0x40 (BE uint256)
//   [36..68)    bool signed   = 1   (BE uint256)
//   [68..100)   bytes length  = 56  (BE uint256)
//   [100..164)  bytes data    = orderUid (56 B) + 8 B zero padding
const calldata = Buffer.alloc(164);
calldata.writeUInt32BE(0xec6cb13f, 0);      // selector
calldata[35] = 0x40;                         // bytes offset low byte; rest already 0
calldata[67] = 0x01;                         // bool signed = 1
calldata[99] = 56;                           // bytes length = 56
ORDER_UID.copy(calldata, 100);               // orderUid (bytes 100..156)
// bytes 156..164 stay 0x00 (padding)

// ── Step 2: build the static readable string ───────────────────────────

const READABLE_TEXT = "Pre-sign CowSwap order"; // 22 chars
const readable = Buffer.alloc(64);
Buffer.from(READABLE_TEXT, "ascii").copy(readable, 0);
// bytes 22..64 stay 0x00

// ── Step 3: compute Poseidon hashes ────────────────────────────────────

const { poseidon3, poseidon6 } = require(path.join(NODE_MODULES, "poseidon-bls12381"));

const H_tx = poseidonBytes(calldata, 164, poseidon6);
const H_str = poseidonBytes(readable, 64, poseidon3);

process.stdout.write("calldata  = " + calldata.toString("hex") + "\n");
process.stdout.write("readable  = " + readable.toString("hex") + "\n");
process.stdout.write("readable ascii = " + JSON.stringify(READABLE_TEXT) + "\n");
process.stdout.write("H_tx      = " + H_tx.toString() + "\n");
process.stdout.write("H_str     = " + H_str.toString() + "\n");

// ── Step 4: write input.json for the witness generator ────────────────

const input = {
  H_tx: H_tx.toString(),
  H_str: H_str.toString(),
  calldata: Array.from(calldata).map(b => b.toString()),
  human_string: Array.from(readable).map(b => b.toString()),
};
const inputPath = path.join(BUILD_DIR, "e2e_input.json");
fs.writeFileSync(inputPath, JSON.stringify(input, null, 2));
process.stdout.write("wrote " + inputPath + "\n");

// ── Step 5: run the witness generator ─────────────────────────────────

if (!fs.existsSync(WASM)) {
  process.stderr.write(
    "error: " + WASM + " not found.\n" +
    "run `circom circuits/cowswap/set_pre_signature/circuit.circom " +
    "--r1cs --wasm --sym --prime bls12381 " +
    "--output build/circuits/cowswap_set_pre_signature/ " +
    "-l circuits/node_modules` first.\n"
  );
  process.exit(2);
}

const witnessPath = path.join(BUILD_DIR, "e2e_witness.wtns");
execSync(`node "${WITNESS_GEN}" "${WASM}" "${inputPath}" "${witnessPath}"`, {
  stdio: "inherit",
});

// ── Step 6: run groth16 prove ──────────────────────────────────────────

const proofPath = path.join(BUILD_DIR, "e2e_proof.json");
const publicPath = path.join(BUILD_DIR, "e2e_public.json");
execSync(`"${SNARKJS}" groth16 prove "${ZKEY}" "${witnessPath}" "${proofPath}" "${publicPath}"`, {
  stdio: "inherit",
});
// Verify it locally against the committed VK as a sanity check.
const vkJsonPath = path.join(BUILD_DIR, "verification_key.json");
if (!fs.existsSync(vkJsonPath)) {
  execSync(`"${SNARKJS}" zkey export verificationkey "${ZKEY}" "${vkJsonPath}"`);
}
execSync(`"${SNARKJS}" groth16 verify "${vkJsonPath}" "${publicPath}" "${proofPath}"`, {
  stdio: "inherit",
});

// ── Step 7: convert proof.json → 384-byte uncompressed layout ─────────

const proof = JSON.parse(fs.readFileSync(proofPath, "utf8"));
const pi_a = g1Bytes(proof.pi_a);
const pi_b = g2Bytes(proof.pi_b);
const pi_c = g1Bytes(proof.pi_c);
if (pi_a.length !== 96) throw new Error("pi.A size mismatch");
if (pi_b.length !== 192) throw new Error("pi.B size mismatch");
if (pi_c.length !== 96) throw new Error("pi.C size mismatch");
const proofBytes = Buffer.concat([pi_a, pi_b, pi_c]);

// Sanity: verify public signals match H_tx, H_str
const pubSignals = JSON.parse(fs.readFileSync(publicPath, "utf8"));
if (BigInt(pubSignals[0]) !== H_tx || BigInt(pubSignals[1]) !== H_str) {
  process.stderr.write("error: public signals do not match computed Poseidon hashes\n");
  process.stderr.write("  public[0] = " + pubSignals[0] + "\n");
  process.stderr.write("  H_tx      = " + H_tx + "\n");
  process.stderr.write("  public[1] = " + pubSignals[1] + "\n");
  process.stderr.write("  H_str     = " + H_str + "\n");
  process.exit(3);
}

// ── Step 8: RLP-encode the EIP-1559 envelope ──────────────────────────

const ethers = require(path.join(NODE_MODULES, "ethers"));
const { RLP } = ethers.utils;

const GPV2_SETTLEMENT = "0x9008D19f58AAbD9eD0D60971565AA8510560ab41";

// EIP-1559 fields (same layout as the Aave test: chain_id=1, nonce=0,
// mfpg=2 gwei, mfpg_cap=50 gwei, gas_limit=200000, to, value=0, data, al=[])
const fields = [
  "0x01",                        // chain_id
  "0x",                          // nonce = 0 (encoded as empty bytes in EIP-1559 RLP)
  "0x77359400",                  // max_priority_fee_per_gas = 2 gwei
  "0x0ba43b7400",                // max_fee_per_gas = 50 gwei
  "0x030d40",                    // gas_limit = 200000 (0x30d40)
  GPV2_SETTLEMENT,               // to
  "0x",                          // value = 0
  "0x" + calldata.toString("hex"),  // data
  [],                            // access_list
];
const rlpEncoded = RLP.encode(fields);
const envelope = Buffer.concat([
  Buffer.from([0x02]),
  Buffer.from(rlpEncoded.slice(2), "hex"), // strip "0x"
]);
process.stdout.write("tx envelope (" + envelope.length + " bytes) = " + envelope.toString("hex") + "\n");

// ── Step 9: emit Rust snippet ─────────────────────────────────────────

const rustSnippet =
  `// === AUTO-GENERATED by circuits/scripts/gen_cowswap_e2e_vector.js ===
// Inputs:
//   orderUid = 0x${ORDER_UID.toString("hex")}
//   readable = "${READABLE_TEXT}"
//   to       = ${GPV2_SETTLEMENT} (GPv2Settlement, chain_id=1)
// Regenerate by running:
//   node circuits/scripts/gen_cowswap_e2e_vector.js
// and pasting the output back into this file.

#[rustfmt::skip]
static COWSWAP_PROOF: [u8; 384] = [
${formatRustBytes(proofBytes)}
];

#[rustfmt::skip]
static COWSWAP_CALLDATA: [u8; 164] = [
${formatRustBytes(calldata)}
];

#[rustfmt::skip]
static COWSWAP_READABLE: [u8; 64] = [
${formatRustBytes(readable)}
];

#[rustfmt::skip]
static COWSWAP_TX: [u8; ${envelope.length}] = [
${formatRustBytes(envelope)}
];

const COWSWAP_GPV2_SETTLEMENT_MAINNET: [u8; 20] = [
${formatRustBytes(Buffer.from(GPV2_SETTLEMENT.slice(2), "hex"))}
];
`;

const rustOut = path.join(BUILD_DIR, "e2e_vector.rs");
fs.writeFileSync(rustOut, rustSnippet);
process.stdout.write("\n\n=== Rust snippet written to " + rustOut + " ===\n");
process.stdout.write("Paste its contents into nonsecure/src/e2e_test.rs\n");
process.stdout.write(rustSnippet);
