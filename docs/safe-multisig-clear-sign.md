# Safe-multisig `approveHash` clear-signing (`safe_v1`)

> Status: landed 2026-04-26. Validated end-to-end through QEMU; companion-side
> trailer assembler in `~/Documents/pq1-companion` is the matching follow-up.
> Targets Safe contracts v1.3.0 and later (the dominant deployments on
> mainnet and L2s today).

## Why this exists

A Safe multisig transaction is normally signed in one of two ways:

1. **Off-chain EIP-712 signature** — every owner produces an ECDSA signature
   over the SafeTx EIP-712 digest, and these signatures are passed to
   `execTransaction`.
2. **On-chain `approveHash(bytes32)`** — an owner sends a transaction
   that records `approvedHashes[owner][safeTxHash] = 1` on the Safe.
   Later anyone can call `execTransaction` with the pre-approvals
   counted toward the threshold.

PQSigner is a post-quantum smart account. It signs SLH-DSA (SPHINCS+C10),
not ECDSA, so path (1) is not consumable by Safe contracts today.
Path (2) works perfectly: the wallet just sends a normal UserOp whose
inner calldata is `approveHash(safeTxHash)`. The on-chain Safe doesn't
care what kind of signature got the wallet to that point — once the
`approvedHashes` slot flips, the approval counts toward the threshold.

The problem is that the `bytes32` argument to `approveHash` is
**opaque to the user**. Without help, the OLED would render
`"Sign call to 0xSAFE… data 0xd4d9bdcd 0x1a2b3c4d…"` and the user has
no idea what SafeTx is being approved. That's blind signing, which is
the exact thing this firmware is built to avoid.

`safe_v1` solves this by having the companion attach an optional
trailer to `CMD_SIGN_USEROP` that brings the *plaintext* SafeTx fields
on-device. The firmware re-derives the `safeTxHash` natively, byte-
compares it against the calldata's `bytes32`, and only then renders a
clear-signed view. No Groth16, no proof — the bind is just keccak.

## Why no Groth16 (the difference from CowSwap)

CowSwap setPreSignature carries a 56-byte opaque `orderUid` in the
calldata. The order's actual fields (sell/buy token, amounts, validTo)
are nowhere on chain — they live in CoW's off-chain orderbook. To
display them on the OLED with cryptographic guarantee, the firmware
needs them brought on-device *and* a proof that they really do hash to
the orderUid the chain will see. That's what the v3 Groth16 proof
buys: it binds a companion-supplied "readable" string to a packed
canonical, in-circuit, via Poseidon.

Safe is structurally different. The on-chain `approveHash(bytes32)`
calldata carries the EIP-712 digest itself. So:

| | CowSwap v3 | Safe `safe_v1` |
|---|---|---|
| What's in calldata | 56-byte opaque `orderUid` | 32-byte `safeTxHash` |
| Can firmware re-derive natively? | Yes (keccak chain), but the *readable* still needs binding | Yes (keccak chain), and the firmware *itself* renders from trusted bytes |
| Need a proof? | Yes — to bind the human-readable string to the canonical (keeps decimal-formatting out of the secure world) | **No** — the firmware reuses its existing `(to, value, data)` decoder once the canonical is bound |
| Trailer overhead | ~2 KB (proof + canonical + readable + VK bundle) | ~283 B (canonical + 2-byte raw_data length) + raw_data |

So Safe gets clear-signing at a fraction of the implementation +
runtime cost — and reuses every existing display primitive the
firmware already has for plain UserOps.

## Wire format

The trailer is appended to the standard `CMD_SIGN_USEROP` payload after
the v3 CoW trailer and before the names section. Its length-prefix
follows the same `[u16 BE len][payload]` framing every other trailer
uses.

### Payload layout (variable, ≤ ~4.4 KB)

```
[u16 BE total_len]
  [281 B canonical SafeTx]
  [u16 BE raw_data_len]
  [raw_data ≤ MAX_TX_LEN = 4096]
```

### Canonical SafeTx (281 bytes, big-endian)

```
[  0..  8) chain_id           u64 BE
[  8.. 28) safe_address       20 B
[ 28.. 48) to                 20 B
[ 48.. 80) value              uint256 BE
[ 80..112) data_hash          keccak256(raw_data) — verified by firmware
[112]      operation          0=Call, 1=DelegateCall (refused in v1)
[113..145) safe_tx_gas        uint256 BE
[145..177) base_gas           uint256 BE
[177..209) gas_price          uint256 BE
[209..229) gas_token          20 B
[229..249) refund_receiver    20 B
[249..281) nonce              uint256 BE
```

Field offsets are exposed as `SAFE_OFF_*` constants in
`shared/src/lib.rs` so the companion side can write directly into the
matching offsets without recomputing them.

### Outer UserOp shape

For a Safe approval, the companion fills the regular `CMD_SIGN_USEROP`
header so that:

- `to_address = safe_address` (the wallet's UserOp targets the Safe).
- `value = 0`.
- `inner_data = APPROVE_HASH_SELECTOR (0xd4d9bdcd) || safeTxHash` — exactly
  36 bytes.
- The trailer described above is attached.

That's it. The signing path is otherwise identical to a regular Type-2
SLH-DSA UserOp.

## What the firmware does

`secure/src/nsc/cmd_sign_userop.rs`, after parsing trailers, dispatches
to `crate::tx::eip712::safe::verify_and_bind_trailer` which runs the
following 8-step pipeline. First failure wins; the trailer is then
treated as absent and the downgrade gate (below) rejects the UserOp.

1. **Trailer length / framing** — at least `281 + 2` bytes; declared
   `raw_data_len` fits inside the supplied bundle and is `≤ MAX_TX_LEN`.
2. **Selector** — `inner_data[..4] == 0xd4d9bdcd` (`approveHash(bytes32)`).
3. **Calldata length** — `inner_data.len() == 36`.
4. **Chain pinning** — `canonical.chain_id == userop.chain_id`. Prevents
   replaying a Mainnet canonical against a UserOp on a different chain.
5. **Safe-address pinning** — `canonical.safe_address == userop.to`. The
   UserOp must call `approveHash` on the same Safe whose hash we're
   approving.
6. **Operation gate** — only `0` (Call) accepted in v1. DelegateCall
   (`1`) is refused outright (see "DelegateCall" below).
7. **Data-hash bind** — `keccak256(raw_data) == canonical.data_hash`.
   The raw inner-call bytes the firmware will render must hash to what
   Safe will check.
8. **safeTxHash bind** — natively recompute the EIP-712 digest from the
   canonical (Safe v1.3.0+ domain separator, struct hash) and byte-
   compare against `inner_data[4..36]`. If those don't match, the
   canonical we'd display and the hash that gets approved would describe
   different transactions.

After all 8 steps pass, the firmware has cryptographically-bound
`(to, value, raw_data, operation, nonce, …)` and hands the
`VerifiedSafeV1` to the renderer.

### Downgrade-mitigation gate

Symmetric to the CoW gate: if `inner_data.len() == 36 && inner_data[..4]
== APPROVE_HASH_SELECTOR && safe_v1_verified.is_none()`, the firmware
aborts the sign with status `InvalidPointer` and the OLED shows
`"Safe sign / safe_v1 required"`. Without this gate, a hostile NS could
strip the trailer and coerce the user into blind-signing the bytes32
hash with no visibility into the SafeTx it commits to.

## What the user sees on the OLED

The renderer (`secure/src/tx/display/safe_display.rs`) builds a sequence
of 4-row × 16-column pages. Layout depends on the inner-tx flavor.

### Header pages (always 3)

```
┌────────────────┐    ┌────────────────┐    ┌────────────────┐
│Approve Safe TX │    │Safe:           │    │SafeTx Nonce: 17│
│Chain: 11155111 │    │0x5afe000000000 │    │Op: Call        │
│(Sepolia)       │    │0000000000000000│    │Inner: ERC-20   │
│> next          │    │0000000001      │    │> next          │
└────────────────┘    └────────────────┘    └────────────────┘
```

The "Inner:" hint on page 3 tells the user up-front what kind of inner
call they're about to inspect:

| Inner kind | Hint line |
|---|---|
| `EmptyCall` (no calldata, no value) | `(empty call)` |
| `PlainEth` (no calldata, value > 0) | `Inner: ETH xfer` |
| `Erc20Known` (recognised ERC-20 + matching metadata bundle) | `Inner: ERC-20` |
| `Erc20Unknown` (recognised ERC-20 but no metadata) | `Inner: ERC-20?` |
| `Blind` (unknown calldata) | `! Inner: opaque` |

If the metadata bundle's contract address doesn't match `canonical.to`,
the firmware silently drops to `Erc20Unknown` — a Safe call to USDC
carries USDC metadata; metadata for some other token is ignored, never
spoofed onto the inner display.

### Inner-tx pages (variable)

#### Plain ETH transfer (2 pages)

```
┌────────────────┐    ┌────────────────┐
│Inner to:       │    │Send ETH:       │
│0xabababababab… │    │1.500000        │
│ababababababab… │    │ETH             │
│ababababab      │    │> next          │
└────────────────┘    └────────────────┘
```

#### ERC-20 known (4 pages — token symbol + decimals from the registry)

```
┌────────────────┐    ┌────────────────┐    ┌────────────────┐    ┌────────────────┐
│Send USDC       │    │Recipient:      │    │Amount:         │    │Contract:       │
│USD Coin        │    │0xabababababab… │    │250.000000      │    │0xa0b86991c621… │
│                │    │ababababababab… │    │USDC            │    │d19d4a2e9eb0ce… │
│> next          │    │ababababab      │    │> next          │    │3606eb48        │
└────────────────┘    └────────────────┘    └────────────────┘    └────────────────┘
```

For `approve(spender, unlimited)` the amount page reads `unlimited`
verbatim instead of a 78-digit number — a hostile dapp can't slip an
unlimited approval past the user.

#### ERC-20 unknown (4 pages — same shape, no symbol/decimals)

```
┌────────────────┐    ┌────────────────┐    ┌────────────────┐    ┌────────────────┐
│ERC-20 call     │    │Recipient:      │    │Raw amount:     │    │Contract:       │
│(unverified)    │    │0xabababababab… │    │0x000000000000… │    │0xa0b86991c621… │
│                │    │ababababababab… │    │... 000ee6b280  │    │d19d4a2e9eb0ce… │
│> next          │    │ababababab      │    │> next          │    │3606eb48        │
└────────────────┘    └────────────────┘    └────────────────┘    └────────────────┘
```

The amount renders as a hex tail (first 7 + last 6 bytes) so the user
can compare it byte-for-byte against what the dapp shows.

#### Blind sign (3 pages — unknown inner calldata)

```
┌────────────────┐    ┌────────────────┐    ┌────────────────┐
│! BLIND SIGN    │    │Inner to:       │    │Sel: 0xdeadbeef │
│Unknown call    │    │0xabababababab… │    │Data: 1024 B    │
│Verify on dapp  │    │ababababababab… │    │                │
│> next          │    │ababababab      │    │0x1234567890ab…│
└────────────────┘    └────────────────┘    └────────────────┘
```

The data-hash page on blind-sign uses `canonical.data_hash` (which the
firmware proved equals `keccak256(raw_data)` in step 7), so the user
can compare it against what the dapp claims.

### Confirm page

```
┌────────────────┐
│Long-press to   │
│                │
│L=Cancel        │
│R=Confirm       │
└────────────────┘
```

Long-press right confirms; long-press left cancels. The same physical-
button gate every other sign flow uses.

## End-to-end flow

```
Companion (~/Documents/pq1-companion)             Device secure world
─────────────────────────────────────────────     ──────────────────────────────────────
1. Build SafeTx struct from user intent           
2. encode_canonical(...)             → 281 B      
3. keccak256(raw_data)               → data_hash  
4. compute_safe_tx_hash(canonical)   → 32 B       
5. Pack trailer:                                  
   [u16 total_len]                                
   [281 B canonical]                              
   [u16 raw_data_len][raw_data]                   
6. Outer UserOp:                                  
   to = safe_address                              
   value = 0                                      
   inner_data = APPROVE_HASH_SELECTOR ||          
                safe_tx_hash (36 B)               
7. CMD_SIGN_USEROP(payload)        ──────────►   8.  TOCTOU snap into SRAM
                                                  9.  Parse header, inner_data, trailers
                                                  10. safe_v1 verify pipeline (8 steps)
                                                  11. pick_sign_pages → render_safe_v1_pages
                                                  12. OLED renders header + inner pages
                                                  13. confirm() blocks for user button
                                                  14. SLH-DSA-C10 sign UserOp
                                       ◄──────    15. Return Type-2 wrapper (4128 B)
16. Submit UserOp via EntryPoint v0.6              
17. EntryPoint runs PQSmartWallet.validateUserOp   
18. Wallet calls Safe.approveHash(safe_tx_hash)    
    → approvedHashes[wallet][safe_tx_hash] = 1    
19. Other Safe owners approve via their own paths
20. Anyone calls Safe.execTransaction(...) once    
    threshold is reached. The pre-approval counts.
```

The on-chain Safe records the approval; from then on, anyone can call
`execTransaction` with the threshold of approvals (one of which is now
the PQSigner wallet's pre-signature). The Safe itself doesn't care
*how* the wallet got there — `approvedHashes[wallet][hash]` is enough.

This means the wallet can be a fully PQ Safe owner today, with no
on-chain changes to Safe contracts and no ECDSA fallback path on the
device.

## DelegateCall

Refused outright in v1. A delegatecall through a Safe replaces the
Safe's code for the duration of the call — module installation, guard
swaps, owner changes via library calls, all routed through this hatch.
There's no honest way to clear-sign that for a non-expert user, so the
verify pipeline rejects `operation == 1` with the same `None` return
as any other failure mode.

When the verify rejects, the downgrade gate fires and the user sees
`"Safe sign / safe_v1 required"` with no further detail — they can
look at the companion's logs to see *why* the trailer was rejected
(the companion knows what canonical it sent), but the device's outward
behavior is "this transaction can't be clear-signed; refuse to
proceed."

A future v2 could add a dedicated trusted-UI scary-warning primitive
plus explicit user opt-in for delegatecalls, but that's its own threat
model and is out of scope for this version.

## What's *not* supported in v1

- **Companion app changes** — `~/Documents/pq1-companion` needs a
  `pq1-safe` crate that mirrors the firmware's canonical encoding and
  EIP-712 digest, plus integration into the sign-request builder.
  Tracked as a separate, post-firmware milestone.
- **`multiSend` recursive decoding** — Safe's `multiSend` packs N inner
  txs into one calldata blob. v1 renders multiSend bundles via the
  blind-sign fallback (just shows the calldata hash + length). v2 will
  teach the inner-tx renderer to traverse the multiSend payload and
  surface each sub-call.
- **Safe v1.1.x and earlier** — used a domain separator without
  `chainId`. They self-police: our recomputed `safeTxHash` will not
  match the calldata's `bytes32` and the trailer is silently rejected.
  Companion is responsible for refusing to send a `safe_v1` trailer
  for an incompatible Safe contract.
- **DelegateCall** — refused (see above).
- **Token-list integration for inner txs** — reuses the existing
  top-level ERC-20 metadata bundle; if Safe inner-tx token resolution
  conflicts with outer name resolution in some future scenario, a
  second-level bundle scoped specifically to Safe inner calls is a
  possible v2.

## Test surface

Unit tests in `secure/src/tx/eip712/safe/test_vectors.rs` cover:

- `safe_domain_typehash_matches_preimage` — `SAFE_DOMAIN_TYPEHASH` byte
  array equals `keccak256(preimage)`.
- `safe_tx_typehash_matches_preimage` — same for `SAFE_TX_TYPEHASH`.
- `happy_path_verifies` — canonical + raw_data + calldata triple
  verified end-to-end.
- 9 cross-check failure modes, one per pipeline step:
  - `rejects_wrong_selector`
  - `rejects_wrong_calldata_length`
  - `rejects_chain_id_mismatch`
  - `rejects_safe_address_mismatch`
  - `rejects_delegatecall`
  - `rejects_data_hash_mismatch`
  - `rejects_safe_tx_hash_mismatch`
  - `rejects_truncated_bundle`
  - `rejects_oversized_raw_data_len`
  - `rejects_zero_raw_data_when_canonical_has_data_hash`
- `decode_rejects_bad_operation` — the canonical decoder rejects
  `operation > 1` before the digest pipeline runs.

Run with:

```bash
cargo test -p sphincs-tz-secure --bin sphincs-tz-secure tx::eip712::safe
```

End-to-end QEMU validation lives in `nonsecure/src/e2e_test.rs`
Scenario 5: assembles a synthetic Safe `transfer(0xRECIPIENT, 250 USDC)`,
sends it through the gateway with the Safe trailer attached, and
asserts the sign succeeds. The OLED logs from QEMU show the user-visible
pages line by line — `make e2e` displays `"Approve Safe TX / SafeTx
Nonce: 17 / Op: Call / Inner: ERC-20?"` and a 4128-byte Type-2
wrapper is returned. (The `make e2e` recipe will currently FAIL on
Scenario 6, the brute-force PIN-lockout test — that failure is
pre-existing on master and unrelated to this work.)

## Key files

| Path | Purpose |
|---|---|
| `shared/src/lib.rs` | Wire constants: `APPROVE_HASH_SELECTOR`, `SAFE_*_TYPEHASH`, `SAFE_V1_*`, `SAFE_OFF_*`. |
| `secure/src/tx/eip712/safe/mod.rs` | Native `compute_safe_tx_hash` + `decode_canonical`; typehash preimage tests. |
| `secure/src/tx/eip712/safe/verify.rs` | `verify_and_bind_trailer` — the 8-step pipeline. |
| `secure/src/tx/eip712/safe/test_vectors.rs` | Happy-path + 9 failure-mode tests (host-only). |
| `secure/src/tx/display/safe_display.rs` | `render_safe_v1_pages` — header pages + inner-tx dispatch. |
| `secure/src/nsc/cmd_sign_userop.rs` | Trailer parse stage, verify call, downgrade gate, dispatch. |
| `secure/src/tx/display/mod.rs` | `pick_sign_pages` priority ladder + inner-ERC20-metadata routing. |
| `nonsecure/src/e2e_test.rs` | Scenario 5 — QEMU end-to-end smoke test (`build_safe_canonical`, `compute_safe_tx_hash`, `append_safe_v1_trailer`). |

## Threat-model invariants this preserves

1. **All secrets stay in TrustZone secure world.** The trailer carries
   no secret material; the `raw_data` field is plaintext intended for
   on-chain execution. NS sees nothing it didn't already have.
2. **One signature primitive, post-quantum only.** The signature path
   is unchanged — the wallet still emits SLH-DSA C10 over the UserOp's
   SHA-256 sphincs digest. The Safe contract checks `approvedHashes`,
   not a signature. No ECDSA, no classical fallback.
3. **No flash state added.** The trailer is a pure SRAM transient.
   The wallet's per-chain bootstrap/slot counters tick the same way
   they would for any other UserOp.
4. **Hardware-level PIN gating preserved.** The trailer is parsed
   inside `cmd_sign_userop`, which already requires `pin_verified`
   before doing any work. A locked wallet never reaches the Safe path.
5. **Downgrade-attack resistance.** The mandatory-trailer gate when
   `inner_data` looks like `approveHash` mirrors the CoW v3 gate; both
   are essential to defeating "strip the trailer to coerce
   blind-signing" attacks.
