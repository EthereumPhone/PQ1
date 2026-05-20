# Companion App / Extension Guide — Make Clear Signing Actually Work

This is the **canonical, single-source-of-truth implementation guide**
for any companion that wants to make ERC-7730 clear signing work
end-to-end against PQSigner OS firmware on the `clear-sign-rebased`
branch.

It is the doc to follow if you're building:

- A browser extension (MetaMask-style) that talks to PQSigner over
  WebHID and proxies dapp `eth_sendTransaction` /
  `eth_signTypedData_v4` / `personal_sign` requests.
- A native companion (Electron / Tauri / mobile WebUSB) that does
  the same.
- An RPC bridge that batches sign requests for a server-side signer.

The wire format is **frozen on this branch**; only the companion-side
code is missing. Two other docs cover narrower slices and remain
useful as references — this guide subsumes both for implementation
purposes:

- `docs/erc7730-integration.md` — what the firmware does after it
  receives the trailer.
- `docs/companion-erc7730-integration.md` — earlier draft, narrower
  scope; superseded by this guide for new companion work.

Read this top-to-bottom before writing code. Most pitfalls below were
discovered the hard way during bring-up; the order they appear is the
order they will bite you.

## Table of contents

1. [Mental model](#1-mental-model)
2. [What the companion must ship](#2-what-the-companion-must-ship)
3. [Catalog file format (`erc7730_db.bin`)](#3-catalog-file-format-erc7730_dbbin)
4. [Lookup algorithm](#4-lookup-algorithm)
5. [Trailer assembly](#5-trailer-assembly)
6. [Where the trailer goes in each command](#6-where-the-trailer-goes-in-each-command)
   - [6.1 CMD_SIGN_USEROP (0x30)](#61-cmd_sign_userop-0x30)
   - [6.2 CMD_SIGN_USEROP_BATCH (0x32)](#62-cmd_sign_userop_batch-0x32)
   - [6.3 CMD_SIGN_OFFCHAIN (0x62) — kind=2 EIP-712 typed](#63-cmd_sign_offchain-0x62--kind2-eip-712-typed)
   - [6.4 CMD_SIGN_OFFCHAIN — kind=0 / kind=1 fingerprint pages](#64-cmd_sign_offchain--kind0--kind1-fingerprint-pages)
7. [Worked examples](#7-worked-examples)
   - [7.1 USDT transfer on mainnet](#71-usdt-transfer-on-mainnet)
   - [7.2 USDT approve unlimited](#72-usdt-approve-unlimited)
   - [7.3 WETH deposit (zero-arg, value from envelope)](#73-weth-deposit-zero-arg-value-from-envelope)
   - [7.4 USDC TransferWithAuthorization (EIP-712 typed)](#74-usdc-transferwithauthorization-eip-712-typed)
   - [7.5 Atomic batch (Type 1 + Type 2 in one user confirm)](#75-atomic-batch-type-1--type-2-in-one-user-confirm)
8. [Firmware response handling](#8-firmware-response-handling)
9. [Failure modes and how to test them](#9-failure-modes-and-how-to-test-them)
10. [Versioning and root rotation](#10-versioning-and-root-rotation)
11. [Pre-flight checklist before shipping](#11-pre-flight-checklist-before-shipping)
12. [Known bugs / blockers](#12-known-bugs--blockers)

## 1. Mental model

The firmware can sign any transaction the user approves on its own
OLED. By default that approval is "blind sign" — a hex calldata
fingerprint and a button press. **Clear signing replaces the hex with
a human-readable rendering** ("Send 100 USDT to alice.eth") whose
correctness is provable because the rendering rules came from a
Merkle-verified ERC-7730 descriptor pinned at firmware-build time.

There is exactly one trust transfer in this design: **the firmware
trusts the Merkle root**. Everything else flows from that:

- The root commits to a set of ERC-7730 descriptors that passed the
  host-side ERC-8176 attestation policy at firmware-build time.
- The companion ships the same descriptor set as a `*.bin` blob
  whose first 32 bytes are the same root.
- For each sign request, the companion picks the matching descriptor,
  produces a Merkle proof against the root, and ships it as an
  optional "trailer" on the sign command.
- The firmware re-verifies the proof, binds the descriptor to the tx
  via `(chain_id, to_address)` or `(chain_id, verifyingContract,
  domain_separator)`, and renders.

If the companion ships no trailer, the firmware silently falls back
to blind-sign. If it ships a wrong / malformed / mis-bound trailer,
the firmware refuses the descriptor and falls back to blind-sign
with a brief status-line banner. **Clear signing is never required —
it is an enhancement layer the companion is free to skip per-tx.**

## 2. What the companion must ship

Three things in the companion bundle:

1. **The catalog blob** at `tools/companion-stub/erc7730_db.bin`
   produced by `cargo run -p dbgen` against the firmware's seed
   corpus + policy.

   - Production blob: 10,919 B, 20 leaves (8 source JSONs expanded
     across multi-chain deployments).
   - E2E fixture: 1,444 B, 4 leaves (WETH + USDT only).

   Both ship a 32-byte Merkle root in the first 32 bytes of the file
   header — see §3.

2. **A descriptor lookup function** keyed on `(chain_id, contract,
   ?primary_type_hash)`. See §4.

3. **A trailer assembler** that produces the exact byte layout the
   firmware's `verify_erc7730_bundle` consumes. See §5.

You can copy the Python reference at
`tools/companion-stub/erc7730_trailer.py` for a 200-line working
implementation, or port it directly to TypeScript / Rust / Swift.

## 3. Catalog file format (`erc7730_db.bin`)

```
offset  size  field
---------------------------------------------------------
  0      4    magic                "P730"  (ASCII)
  4      1    schema_ver           1
  5      1    entry_cnt_lo         (entry_cnt as u32 LE)
  6      1    entry_cnt_b1
  7      1    entry_cnt_b2
  8      1    entry_cnt_b3
  9      1    ir_pool_off_lo       (u32 LE — offset of IR pool)
 10..12       ir_pool_off_b{1,2,3}
 13      1    ir_pool_size_lo      (u32 LE)
 14..16       ir_pool_size_b{1,2,3}
 17      1    reserved_b0          (must be 0)
 18..23       reserved_b{1..6}
 24      4    proof_depth          (u32 LE)
 28      4    proofs_off           (u32 LE — offset of proof pool)

 32             root                 [u8; 32]  ← firmware-pinned

 64    72×N    entries[N]           (one 72-byte record per leaf):
                  chain_id           u64 LE
                  contract           [u8; 20]
                  primary_type_hash  [u8; 32]  (zero for contract-context)
                  context_kind       u8        (1 = CTX_CONTRACT,
                                                2 = CTX_EIP712)
                  ir_off             u32 LE    (offset into IR pool)
                  ir_len             u16 LE
                  leaf_index         u32 LE    (position in Merkle tree)
                  _pad               u8

 ir_pool_off    IR pool bytes        (concatenated IR records)
 proofs_off     proof pool bytes     (entry_cnt × proof_depth × 32 bytes,
                                      laid out in leaf-index order)
```

Endian note: this file is **little-endian** because it's produced by a
host-side tool and consumed only by other host-side tools (the
companion). The on-the-wire trailer flips to **big-endian** because
that's what the firmware verifier expects (matches every other
on-device protocol field in PQSigner OS).

Sanity-check at companion startup:

- `magic == "P730"`
- `schema_ver == 1`
- `entry_cnt ≥ 1`
- `proof_depth ≤ 32` (firmware `ERC7730_PROOF_MAX_DEPTH`)
- File size ≥ `proofs_off + entry_cnt * proof_depth * 32`
- The blob's `root` field matches the firmware's compiled-in root
  (query via `GET_DEVICE_INFO` once the firmware exposes it, or just
  hard-code it per firmware release for now).

If any of these fail: refuse to ship trailers. Every sign request
will simply blind-sign — the user keeps signing, just without
clear-sign pages.

## 4. Lookup algorithm

For a UserOp on chain `chain_id` calling contract `to`:

```pseudo
entry = entries.find(e =>
  e.context_kind == CTX_CONTRACT
  && e.chain_id == chain_id
  && e.contract == to)
```

For an EIP-712 typed-data sign whose canonical message is:

```
domain         = { name, version, chainId, verifyingContract, ?salt }
primaryType    = "TransferWithAuthorization"
message        = { from, to, value, ... }
```

```pseudo
domain_separator = keccak256(EIP712Domain_typehash || encode(domain))
primary_type_hash = keccak256(primaryType_string)

entry = entries.find(e =>
  e.context_kind == CTX_EIP712
  && e.chain_id == chainId
  && e.contract == verifyingContract
  && e.primary_type_hash[..4] == primary_type_hash[..4])
```

Notes:

- **The firmware compares the first 4 bytes of `primary_type_hash`
  only** — that's the format selector key inside the IR. The catalog
  stores the full 32-byte hash for companion-side disambiguation;
  the firmware never reads past byte 3.
- A descriptor with two formats (e.g. tokens with both
  `Permit` and `TransferWithAuthorization`) appears as ONE catalog
  entry per `(chain_id, contract)` — the format-table-walk inside the
  on-device IR resolves which format applies. So for EIP-712, your
  match key is `(chain_id, verifyingContract)` and the firmware does
  the per-primaryType dispatch internally. The catalog's
  `primary_type_hash` field carries the **first** format's hash for
  human-readable lookup but is not load-bearing for the wire
  protocol.
- On a miss: return `None`. Ship the sign request without a trailer.
  The firmware blind-signs.

## 5. Trailer assembly

A "trailer" is an outer 2-byte length prefix wrapping an inner
"bundle":

```
trailer = u16_be(len(bundle)) || bundle
```

The bundle is what `pqsigner_erc7730::bundle::verify_erc7730_bundle`
parses byte-for-byte:

```
bundle =
  u16_be(ir_len)
  || ir[ir_len]
  || u32_be(leaf_index)
  || u32_be(proof_depth)
  || proof[proof_depth * 32]
```

Where:

- `ir` is the IR bytes for the entry (extracted from
  `erc7730_db.bin[ir_pool_off + e.ir_off .. + e.ir_len]`).
- `leaf_index` is the entry's position in the Merkle tree (header
  field; same as the entry's `leaf_index` value).
- `proof_depth` is the catalog's `proof_depth` value (same for every
  leaf).
- `proof` is the entry's proof, extracted from
  `erc7730_db.bin[proofs_off + leaf_index * proof_depth * 32 ..
   + proof_depth * 32]`.

Trailer size bounds:

- `ir_len` ≤ 4096 (firmware `ERC7730_IR_MAX`)
- `proof_depth` ≤ 32
- Total bundle ≤ 4096 + 10 + 32 × 32 = 5130 (firmware
  `ERC7730_MAX_TRAILER_LEN`)

If your assembled trailer is longer than 5130 B, you've packed the
wrong thing — re-check `ir_len` against the catalog entry.

TypeScript reference (≈ 30 lines):

```typescript
function assembleTrailer(blob: Uint8Array, entry: CatalogEntry): Uint8Array {
  const proofDepth = readU32LE(blob, 24);
  const proofsOff  = readU32LE(blob, 28);
  const irPoolOff  = readU32LE(blob, 9);

  const ir = blob.subarray(irPoolOff + entry.irOff, irPoolOff + entry.irOff + entry.irLen);
  const proofBase = proofsOff + entry.leafIndex * proofDepth * 32;
  const proof = blob.subarray(proofBase, proofBase + proofDepth * 32);

  const bundleLen = 2 + ir.length + 4 + 4 + proof.length;
  const bundle = new Uint8Array(bundleLen);
  let p = 0;
  writeU16BE(bundle, p, ir.length); p += 2;
  bundle.set(ir, p); p += ir.length;
  writeU32BE(bundle, p, entry.leafIndex); p += 4;
  writeU32BE(bundle, p, proofDepth); p += 4;
  bundle.set(proof, p);

  const trailer = new Uint8Array(2 + bundle.length);
  writeU16BE(trailer, 0, bundle.length);
  trailer.set(bundle, 2);
  return trailer;
}
```

## 6. Where the trailer goes in each command

This is the part most companions get wrong on the first try, because
each of the three sign commands has a different trailer position. The
wire layout is positional — trailers are NOT keyed by tag; their
presence and order is fixed by the firmware parser.

### 6.1 CMD_SIGN_USEROP (0x30)

The unified Type 1 / Type 2 sign command. Header is 330 fixed bytes
(see `docs/usb-protocol-v2.md §0x30`); after the inner calldata, a
chain of optional trailers follows. All trailers use the same `[u16
BE len][payload]` framing; absent trailers go in as `[u16 BE 0]`.

The trailer chain in order, with the ERC-7730 trailer slot
**bolded**:

```
sign_userop_payload =
    base_header[330]
 || data[data_len]                                       // inner calldata
 || u16_be(erc20_bundle_len)         || erc20_bundle     // optional
 || u16_be(zk_v1_bundle_len)         || zk_v1_bundle     // optional
 || u16_be(zk_v3_bundle_len)         || zk_v3_bundle     // optional
 || u16_be(safe_v1_bundle_len)       || safe_v1_bundle   // optional
 || u16_be(selector_bundle_len)      || selector_bundle  // optional
 || u16_be(self_attest_bundle_len)   || self_attest      // optional
 || **u16_be(erc7730_bundle_len)     || erc7730_bundle** // OPTIONAL ERC-7730 trailer ⟵
 || names_section                                        // 1-B count + bundles
```

If the companion sends nothing for slot N but a non-empty slot N+1,
slot N MUST still be `[u16 BE 0]`. There is no "skip" — the parser
walks the chain sequentially.

If the companion has no trailers at all, the chain collapses to:

```
sign_userop_payload = base_header[330] || data[data_len] || names_section
```

(every `u16_be(...)` slot becomes `[0x00, 0x00]`)

**Important:** the firmware also expects a `names_section` after the
last trailer. It's `[u8 count][bundle_0 ... bundle_{count-1}]`,
`count ≤ 4`, each bundle `[u16 BE len][payload]`. If you don't have
any names to attach, send `[0x00]`. Never omit the count byte — the
parser reads it unconditionally.

### 6.2 CMD_SIGN_USEROP_BATCH (0x32)

The atomic multi-UserOp sign command. The firmware accepts **one
per-batch ERC-7730 trailer at the end of the payload**, after the
last inner-tx record. Per-tx trailers are deferred (would require a
wire-format extension); for now the rules are:

- If the batch contains exactly one tx whose `to` matches an
  ERC-7730 descriptor: attach the trailer, the firmware renders that
  one tx with clear-sign pages and blind-signs the others.
- If the batch contains multiple txs with descriptors: attach the
  trailer for the **first** matching tx. The others blind-sign.
- If no tx in the batch has a descriptor: send no trailer
  (`[u16 BE 0]` at the end).

Wire layout (the batch-header + per-tx records are documented in
`docs/companion-batch-sign-integration.md`; the trailer slot is
appended at the very end):

```
batch_payload =
    batch_header
 || per_tx_record_0
 || per_tx_record_1
 || ...
 || per_tx_record_{n-1}
 || u16_be(erc7730_bundle_len) || erc7730_bundle    // optional
```

The firmware cross-checks the descriptor against AT LEAST ONE inner
tx's `(chain_id, to)`; if zero match, the entire batch is rejected
with `"7730 binding fail"`. Make sure your lookup matches at least
one inner tx before attaching.

### 6.3 CMD_SIGN_OFFCHAIN (0x62) — kind=2 EIP-712 typed

EIP-712 typed signs have their OWN dedicated payload shape — the
trailer is the LAST element, not interleaved with anything:

```
header = u8(account) | u8_be(chain) | u32_be(slot) | u8(kind=2) | u16_be(payload_len) | u8(flags)
                                                                                       ^ bit 0 = account_deployed

payload =
    u16_be(1)                          // domain_sep_present (must be 1)
 || u8[32] domain_separator             // EIP-712 EIP712Domain hash
 || u8[32] primary_type_hash            // keccak256(typeString)
 || u16_be(encoded_data_len)            // ≤ 512 (MAX_OFFCHAIN_EIP712_ENCODED_DATA_LEN)
 || u8[encoded_data_len] encoded_data   // viem::encodeAbiParameters(types, message)
 || u16_be(trailer_len)                 // ≤ 5130 (ERC7730_MAX_TRAILER_LEN)
 || u8[trailer_len] trailer             // ERC-7730 bundle (§5)
```

Constraints the firmware enforces:

- `domain_sep_present` must be `1`. The pre-EIP-712 codepath (sign
  the bare 32-byte `primaryType` hash without a domain) is rejected.
- `encoded_data` is the **struct body only**. Do NOT prepend
  `primary_type_hash` — the firmware concatenates it internally.
  This is what `viem.encodeAbiParameters(types, message)` produces;
  ethers users want `AbiCoder.defaultAbiCoder().encode(types,
  values)`.
- `trailer_len > 0`. Sending kind=2 without a trailer fails with
  `"7730 bundle fail"`. The kind=2 codepath has no blind-sign fallback
  inside the firmware — it expects clear-sign info or it bails.

If you can't find a descriptor for an EIP-712 sign, **route the user
through `kind=0` (raw32) or `kind=1` (personal_sign) instead** by
pre-hashing on the companion side. The firmware will show the
fingerprint page and require button confirm; the dapp gets an
EIP-1271 sig back the same way.

### 6.4 CMD_SIGN_OFFCHAIN — kind=0 / kind=1 fingerprint pages

For `kind=0` (raw32) and `kind=1` (personal_sign), no ERC-7730
trailer slot exists in the payload — the firmware just renders the
fixed banner pages plus the ERC-8213 fingerprint of the hash being
signed. No companion-side action needed for clear-sign; do attach a
names section if you want the wallet name resolved.

## 7. Worked examples

These examples assume:

- `chain_id = 1` (Ethereum mainnet).
- Wallet is already deployed (no `FLAG_INCLUDE_INIT_CODE`).
- Slot 0 is already registered (no `FLAG_REGISTER_SLOT`).
- `flags = 0` for the outer userop header.

### 7.1 USDT transfer on mainnet

Dapp request:

```javascript
eth_sendTransaction({
  from: walletAddr,
  to:   "0xdAC17F958D2ee523a2206206994597C13D831ec7",  // USDT mainnet
  value: "0x0",
  data: "0xa9059cbb" +                                  // transfer(address,uint256)
        "0000000000000000000000003333333333333333333333333333333333333333" +
        "0000000000000000000000000000000000000000000000000000000005f5e100",  // 100.00 USDT
})
```

Companion-side flow:

1. **Lookup.** Walk `entries[]`:
   ```
   find e where e.context_kind == 1 && e.chain_id == 1
              && e.contract == 0xdAC17F958D2ee523a2206206994597C13D831ec7
   ```
   Found: `tether-usdt.json` mainnet entry.

2. **Assemble trailer** per §5.

3. **Build the SIGN_USEROP payload:**
   ```
   header (330 B)
   data (68 B = 4-byte selector + 32-byte to + 32-byte amount)
   u16_be(0)         // erc20 (absent)
   u16_be(0)         // zk_v1 (absent)
   u16_be(0)         // zk_v3 (absent)
   u16_be(0)         // safe_v1 (absent)
   u16_be(0)         // selector (absent)
   u16_be(0)         // self_attest (absent)
   u16_be(len) || trailer   // ERC-7730 trailer ⟵
   u8(0)             // names_section count = 0
   ```

4. **Send.** The firmware will show:
   ```
   Page 0: "Sign: Send" / "Tether Limited" / "Tether USD" / "> next"
   Page 1: "Amount" / "100" / "USDT" / "> next"
   Page 2: "To" / "0x333333…" / "..." / "> next"
   Page 3: chain / fee / nonce envelope pages...
   Page N: "8213 Fingerprint" / "CalldataDigest" / "> verify off-dev"
   Page N+1: <full 32-byte hex hash>
   Page N+2: "Cancel / Confirm"
   ```

5. **Receive** the response, ABI-encode the type2 wrapper, wrap into
   a v0.6 `PackedUserOperation` with `callData =
   executeWithOffchainCount(1, new_offchain_count, USDT, 0, data)`,
   ship to the bundler.

### 7.2 USDT approve unlimited

Dapp request:

```javascript
eth_sendTransaction({
  to:   "0xdAC17F958D2ee523a2206206994597C13D831ec7",
  data: "0x095ea7b3" +                                  // approve(address,uint256)
        "0000000000000000000000004444444444444444444444444444444444444444" +
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",  // U256::MAX
})
```

Lookup hits the same `tether-usdt.json` entry. The descriptor sets a
`threshold` parameter on the amount field; the renderer compares the
value to that threshold and prints `"unlimited"` instead of the full
digit count.

Expected display:

```
Page 0: "Sign: Approve" / "Tether Limited" / "Tether USD" / "> next"
Page 1: "Spender" / "0x444444…" / "..." / "> next"
Page 2: "Amount" / "unlimited" / "" / "> next"
Page 3+: envelope + fingerprint + confirm
```

### 7.3 WETH deposit (zero-arg, value from envelope)

Dapp request:

```javascript
eth_sendTransaction({
  to:    "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",  // WETH9 mainnet
  value: "0x6f05b59d3b20000",   // 0.5 ETH
  data:  "0xd0e30db0",          // deposit()
})
```

Lookup: `weth.json` mainnet entry.

This is the **`@.value` container path** case. The descriptor's
single "Amount" field has `"path": "@.value"`, which the firmware
resolves to the UserOp envelope's `value` field — NOT the calldata
(there's no calldata, deposit() is zero-arg).

Expected display:

```
Page 0: "Sign: Wrap" / "WETH" / "WETH" / "> next"
Page 1: "Amount" / "0.5 ETH" / "" / "> next"
Page 2+: envelope + fingerprint + confirm
```

### 7.4 USDC TransferWithAuthorization (EIP-712 typed)

Dapp request:

```javascript
eth_signTypedData_v4({
  domain: {
    name:    "USD Coin",
    version: "2",
    chainId: 1,
    verifyingContract: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
  },
  types: {
    EIP712Domain: [...],
    TransferWithAuthorization: [
      { name: "from",         type: "address" },
      { name: "to",           type: "address" },
      { name: "value",        type: "uint256" },
      { name: "validAfter",   type: "uint256" },
      { name: "validBefore",  type: "uint256" },
      { name: "nonce",        type: "bytes32" },
    ],
  },
  primaryType: "TransferWithAuthorization",
  message: { from, to, value, validAfter, validBefore, nonce },
})
```

Companion-side:

1. **Compute `domain_separator`** via `keccak256(EIP712Domain_typehash
   || encode(domain))`. For viem: `getDomainSeparator(domain)`.
2. **Compute `primary_type_hash`** via
   `keccak256("TransferWithAuthorization(address from,...)")`. For
   viem: `getTypesHash(types, "TransferWithAuthorization")`.
3. **Encode the struct body**: `viem.encodeAbiParameters(typesArr,
   valuesArr)` where `typesArr` is the field-type list and
   `valuesArr` is the message values in declaration order.
4. **Look up** the descriptor:
   ```
   find e where e.context_kind == 2 && e.chain_id == 1
              && e.contract == 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
              && e.primary_type_hash[..4] == computed_primary_type_hash[..4]
   ```
5. **Assemble the kind=2 payload** per §6.3.
6. **Send** as `CMD_SIGN_OFFCHAIN` with `kind=2`.

Expected display:

```
Page 0: "Sign: Authorize" / "Circle" / "USD Coin" / "> next"
Page 1: "From" / <from addr> / "" / "> next"
Page 2: "To" / <to addr> / "" / "> next"
Page 3: "Amount" / <value> "USDC" / "" / "> next"
Page 4: "Valid after" / <date UTC> / "" / "> next"
Page 5: "Valid before" / <date UTC> / "" / "> next"
Page 6: "Nonce" / <hex> / "" / "> next"
Page 7+: fingerprint + confirm
```

The output is byte-identical to a `kind=0` raw32 sign of the EIP-712
final hash — the companion can wrap as `abi.encode(uint256
ownerIndex, bytes c10Sig)` and pass to
`wallet.isValidSignature(rawHash, wrappedSig)`. Off-chain
verification works through any EIP-1271-aware verifier.

### 7.5 Atomic batch (Type 1 + Type 2 in one user confirm)

When the wallet's slot 0 is not yet registered on a new chain, a
fresh registration UserOp must be bundled before the user's call.
The batch sign command does this atomically (one user confirm for
both UserOps).

If the user-call is an ERC-7730-described action (e.g. their first
USDT transfer on Optimism after deriving the slot), attach the
trailer **at the very end of the batch payload** (§6.2). The
firmware will render:

```
Page 0: "Batch sign" / "2 UserOps" / "" / "> next"
[Type 1 wrapper pages]
[Type 2 user-tx pages, rendered with clear-sign]
[Batch summary: combined fingerprint hash]
Page N: "Cancel / Confirm"
```

Attaching the trailer only changes the Type 2 rendering; the Type 1
slot-registration UserOp is always rendered as `"Register slot N
(once-only)"` boilerplate regardless.

## 8. Firmware response handling

The firmware's `CMD_SIGN_USEROP` response is identical regardless of
whether a trailer was attached:

```
[new_offchain_count u64 BE]
[init_code_len u32 BE] [init_code]      // 4280 B if FLAG_INCLUDE_INIT_CODE
[type1_len u32 BE]     [type1_wrapper]  // 4128 B if FLAG_REGISTER_SLOT
[type2_len u32 BE]     [type2_wrapper]  // always 4128 B
```

The `new_offchain_count` is what `executeWithOffchainCount(...)` will
write to `offchainSigCount[i]` on-chain — bake it into the Type 2
callData.

The `CMD_SIGN_OFFCHAIN` response (any kind):

```
[new_local_offchain_count u64 BE]
[c10_sig u8; 4008]                       // total 4016 B for deployed
                                         // or 8616 B for counterfactual
                                         // (ERC-6492 blob)
```

For ERC-1271 verification on-chain, wrap as:

```
abi.encode(uint256 ownerIndex, bytes c10Sig)
```

where `ownerIndex = slot + 1` (slot 0 = ownerIndex 1, since
ownerIndex 0 is reserved for the bootstrap key).

## 9. Failure modes and how to test them

Build a test corpus of one tx per category and assert what the user
sees on the screen. The firmware's host-test suite at
`secure/src/display_under_test/erc7730_render_pure_tests.rs` does
exactly this — read it for the test-pattern reference; mirror it
companion-side.

| Scenario                                          | Expected outcome                                                                                                                                                |
|---------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Descriptor matches, well-formed bundle            | Clear-sign pages + fingerprint + confirm.                                                                                                                       |
| Descriptor matches, tampered proof                | Status: `"7730 bundle fail"`. Blind-sign pages instead.                                                                                                         |
| Descriptor matches, wrong chain_id in trailer     | Status: `"7730 binding fail"`. Blind-sign pages.                                                                                                                |
| Descriptor matches, wrong contract in trailer     | Status: `"7730 binding fail"`. Blind-sign pages.                                                                                                                |
| EIP-712 sign with mismatched domain_separator     | Status: `"7730 binding fail"`. NO blind-sign fallback for kind=2 — error returned to dapp.                                                                      |
| Companion ships no trailer                        | Silently blind-signs. No status banner.                                                                                                                         |
| Bundle > 5130 bytes                               | Firmware rejects the entire sign with `"erc7730 too big"`. Fix the companion's lookup.                                                                          |
| Selector in calldata not in descriptor's formats  | `RenderErr::NoFormat` → blind-sign fallback. NOT an error. Send anyway and let it fall through, OR don't ship the trailer in the first place to save bandwidth. |
| Root in `*_db.bin` ≠ firmware's pinned root       | EVERY trailer fails `"7730 bundle fail"`. Companion-side root parity check at startup catches this.                                                             |

Test the failure modes too. A companion that does not gracefully
fall back when the firmware rejects the trailer is a companion that
will brick its users on the day the firmware ships a new root.

## 10. Versioning and root rotation

The `ERC7730_DESCRIPTORS_ROOT` is a firmware-build constant. Every
firmware update can change it — when descriptors are added, removed,
or modified, the root changes deterministically.

**Companion update flow** when the firmware rolls a new root:

1. New firmware ships with new `ERC7730_DESCRIPTORS_ROOT`.
2. Companion release pipeline regenerates `erc7730_db.bin` via
   `cargo run -p dbgen` against the same seed corpus + policy.
3. Companion package ships with the new blob.
4. On startup, companion reads the firmware's `GET_DEVICE_INFO`
   (or a future dedicated `GET_ERC7730_ROOT` endpoint), compares to
   the blob's root, and:
   - **Match:** use clear-sign normally.
   - **Mismatch:** disable clear-sign trailers globally; every sign
     blind-signs. Surface a banner in the companion UI: "Update
     companion to re-enable clear-signing on this firmware."

The companion MUST NOT ship trailers that won't verify — every
mis-rooted trailer is a wasted USB chunk + a status banner the user
sees as noise.

For development against bring-up firmware built with
`erc7730-dev-unattested`: the descriptor on every render adds a
`** DEV BUILD ** Unattested` page so the user can't miss the
relaxed gate. The Cargo feature is `compile_error!`-fenced against
`mode-production`, so a shipping firmware will never carry it.

## 11. Pre-flight checklist before shipping

Companion-side pre-release:

- [ ] Catalog blob matches the firmware's pinned root (sanity-check
      first 32 B at startup).
- [ ] Every entry in the catalog is reachable via the lookup
      function — round-trip every leaf through assemble-and-verify
      against the bundle parser at companion-side test time. Mirror
      the firmware's `dbgen/tests/erc7730_roundtrip.rs` flow on the
      companion language.
- [ ] Wire ordering matches §6 for all three commands (test against
      QEMU firmware: `make e2e` Scenarios 5m/5n/5p exercise this).
- [ ] Trailer assembly produces ≤ 5130 B for every catalog entry.
- [ ] Graceful fallback when the firmware returns
      `"7730 bundle fail"` or `"7730 binding fail"` (status banner,
      blind-sign proceeds, user can still confirm).
- [ ] No trailer attached when the lookup misses (don't ship a
      "default" trailer — that triggers binding-fail on every sign).
- [ ] Names section count byte present even when empty (`0x00`).
- [ ] EIP-712 kind=2 path passes `encoded_data` as struct body
      ONLY (no type-hash prefix) — viem
      `encodeAbiParameters(types, message)` is correct; ethers
      `_TypedDataEncoder.hashStruct()` is **NOT** (that prepends the
      type hash and computes the hash, which is the wrong shape).

Firmware-side smoke (run on QEMU before each release):

- [ ] `make e2e` — Scenarios 5m + 5n + 5p all green.
- [ ] `cargo test -p sphincs-tz-secure --tests --no-default-features
      --features mock-se,debug-log,ui-semihosting
      erc7730_render` — 9 render tests + 1 diagnostic (ignored).
- [ ] `cargo test -p dbgen --test erc7730_roundtrip` — 9 round-trip
      tests.
- [ ] `xtask gen-erc7730-descriptors --check` — catalog parity
      against checked-in artifacts.

## 12. Known bugs / blockers

These are issues we know about on `clear-sign-rebased`. They do NOT
need companion-side workarounds (the firmware will degrade
gracefully) but a companion shipping today should expect users to
report them.

### 12.1 `path_off == 0` collides with the "no path" sentinel

`dbgen::erc7730::Pool::new()` starts empty. The first interned path
program lands at pool offset 0. The on-device renderer
(`secure/src/tx/display/erc7730/formatters.rs::resolve_path`) treats
`path_off == 0` as the "field has no path" sentinel and rejects with
`RenderErr::Reject("7730 missing path")`. Every descriptor whose
first interned path program ends up at offset 0 silently degrades
to blind-sign.

**Affected leaves** in the current seed corpus (from
`diagnostic_dump_seed_corpus_path_offsets` in the host-test suite):

- `weth.json` / `deposit()` — Amount path_off = 0
- `tether-usdt.json` / `transfer(address,uint256)` — To path_off = 0
- `tether-usdt.json` / `approve(address,uint256)` — Spender path_off = 0
- `aave-v3-pool.json` / first field — path_off = 0
- `circle-usdc-twa.json` / `circle-usdc-rwa.json` — From path_off = 0

**Companion impact**: the dapp shows the user a sign request; the
device shows "blind-sign + 7730 missing path" status banner instead
of clear-sign pages. The sign still works; the user just doesn't get
the human-readable rendering.

**Fix candidates** (out of scope for the companion — track in
firmware backlog):

- **Host fix**: have `dbgen::erc7730::Pool::new()` push a 1-byte
  sentinel so offset 0 is unreachable. Bumps every interned offset
  by 1; changes the IR layout → bumps the root → every companion
  must re-ship the blob. One-time pain.
- **Device fix**: replace the `path_off == 0` sentinel with an
  `Option<u16>` or a dedicated `NO_PATH` constant outside the
  reachable pool range. Touches the wire format.

The host-test suite at `secure/src/display_under_test/
erc7730_render_pure_tests.rs` has three `#[should_panic(expected =
"7730 missing path")]` tests pinning the current bug. When the bug
is fixed, those tests will start failing — that's the signal to
remove the `should_panic` markers and re-enable the full
string-assertion bodies they ship with.

### 12.2 `interpolatedIntent` is unimplemented

Descriptors that use `interpolatedIntent` (e.g. `"intent": "Send
{amount} {token}"`) render literally as `Send {amount} {token}` on
the device, braces and all. The seed corpus avoids this; the first
registry descriptor that uses it will look broken. Phase 5+ wires
the path-lookup-and-format substitution; until then, avoid
`interpolatedIntent` descriptors in the catalog or accept the ugly
rendering.

### 12.3 Nested calldata stubs out

`Calldata` formatter (0x0A) rejects with `Reject("7730 nested
calldata p5")` and falls through. Safe v1's `execTransaction` uses
this in the registry but is handled by a dedicated `safe_display`
renderer; generic descriptors that use `nestedSelector` will degrade
to blind-sign.

### 12.4 NFT collection names not resolved

`NftName` formatter (0x09) renders the raw token id as a decimal +
"(NFT token id)" hint. Collection-name lookup needs an on-device
NFT-name DB which is not yet wired. Phase 5+ scope.

### 12.5 Dynamic ABI types out of scope

`render_erc7730_pages` walks paths assuming **static types**
(uint256, address, bool, bytes32, static tuples). Dynamic types
(`bytes`, `string`, dynamic arrays, dynamic tuples) read the slot
as a BE offset rather than the value — formatters that try to
render them will surface garbage. The seed corpus avoids these
except for OpenSea Wyvern's `calldata`, which routes through the
nested-calldata stub (§12.3) and falls back to blind-sign.

Phase 5+ wire-format extension (shape-descriptor byte in the IR
header) closes the gap. The on-device walker proper
(`pqsigner_erc7730::walker::resolve_path`) already supports
dynamic types via an `AbiView` tree — the gap is just in plumbing
type info through the IR.

## See also

- `docs/erc7730-integration.md` — what the firmware does after
  receiving the trailer (verify → bind → render → fingerprint →
  confirm).
- `docs/usb-protocol-v2.md` — full USB-HID wire layout, all
  commands, all kinds.
- `docs/companion-app-integration.md` — broader companion
  architecture (PIN entry, unlock, slot management).
- `docs/companion-batch-sign-integration.md` — batch sign per-tx
  record format.
- `tools/companion-stub/erc7730_trailer.py` — Python reference
  implementation of §4–§5.
- `dbgen/tests/erc7730_roundtrip.rs` — host-side round-trip test
  showing the catalog → trailer → on-device verifier flow
  byte-for-byte.
- `secure/src/display_under_test/erc7730_render_pure_tests.rs` —
  host-side render-string tests. Mirror these companion-side.
