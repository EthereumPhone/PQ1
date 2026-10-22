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

PQSigner is a post-quantum smart account. It signs SPHINCS+C10,
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
trailer to `CMD_SIGN_USEROP` that brings the canonical SafeTx fields
on-device. The firmware re-derives the `safeTxHash` natively, byte-
compares it against the calldata's `bytes32`, and only then renders a
clear-signed view.

## Native binding in both Safe and CoW

CoW `setPreSignature` carries a 56-byte opaque `orderUid`; the companion
therefore supplies the 204-byte canonical GPv2Order. Secure world recomputes
its EIP-712 digest and renders the fields natively. Safe likewise recomputes
the SafeTx digest from its canonical fields. Neither path trusts
companion-supplied display text.

Safe is structurally different. The on-chain `approveHash(bytes32)`
calldata carries the EIP-712 digest itself. So:

| | CowSwap v3 | Safe `safe_v1` |
|---|---|---|
| What's in calldata | 56-byte opaque `orderUid` | 32-byte `safeTxHash` |
| Can firmware re-derive natively? | Yes; canonical GPv2Order → EIP-712 digest | Yes; canonical SafeTx → EIP-712 digest |
| Native binding | EIP-712 digest + orderUid cross-check | EIP-712 digest + approveHash cross-check |
| Trailer overhead | 204..=2448 B (canonical + optional ERC-20 bundles) | ~283 B (canonical + 2-byte raw_data length) + raw_data |

So Safe gets clear-signing at a fraction of the implementation +
runtime cost — and reuses every existing display primitive the
firmware already has for plain UserOps.

## Wire format & verifier — companion reference

The companion-facing spec for the `safe_v1` trailer is owned by
**[companion-safe-tx-integration.md](companion-safe-tx-integration.md)** — read
it for the wire detail and don't duplicate it here. In brief, that doc defines:

- the **281-byte canonical SafeTx** layout (`chain_id / safe_address / to /
  value / data_hash / operation / gas fields / nonce`), framed as
  `[u16 total_len][281 B canonical][u16 raw_data_len][raw_data ≤ SAFE_V1_RAW_DATA_MAX = 4096]`,
  with `SAFE_OFF_*` field offsets in `shared/src/lib.rs`;
- the **outer UserOp shape** — `to = safe_address`, `value = 0`,
  `inner_data = APPROVE_HASH_SELECTOR (0xd4d9bdcd) || safeTxHash` (36 B), trailer
  attached; the signing path is otherwise a regular Type-2 SPHINCS+C10 UserOp;
- the **8-step `verify_and_bind_trailer` pipeline**
  (`secure/src/tx/eip712/safe/verify.rs`): framing → selector → calldata-len →
  chain-pin → safe-addr-pin → operation-gate → `keccak256(raw_data) == data_hash`
  → native `safeTxHash` re-derive + byte-compare;
- the **downgrade gate**: an `approveHash`-shaped `inner_data` with no verified
  trailer aborts with `"Safe sign / safe_v1 required"` (mirrors the CoW gate) so
  a hostile NS can't strip the trailer to coerce blind-signing.

The rest of *this* doc is the **firmware-side** view that doc doesn't cover: why
the approveHash design works, exactly what renders on the OLED, the gas-refund
drain surface, and the device test surface.

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
| `PlainEth` (no calldata, value > 0) | `Inner: <native ticker>` (for example `Inner: BNB`) |
| `Erc20Known` (recognised ERC-20 + matching metadata bundle) | `Inner: ERC-20` |
| `Erc20Unknown` (recognised ERC-20 but no metadata) | `Inner: ERC-20?` |
| `CowswapPresign` (inner call is `setPreSignature` on GPv2Settlement, CoW v3 trailer verified) | `Inner: CoW order` |
| `Blind` (unknown calldata) | `! Inner: opaque` |

If the metadata bundle's contract address doesn't match `canonical.to`,
the firmware silently drops to `Erc20Unknown` — a Safe call to USDC
carries USDC metadata; metadata for some other token is ignored, never
spoofed onto the inner display.

### Inner-tx pages (variable)

#### Plain ETH transfer (2 pages)

```
┌────────────────┐    ┌────────────────┐
│Inner to:       │    │Send <ticker>:  │
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

#### Blind sign (3 pages — genuinely unknown inner calldata)

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

Before these pages are allowed, firmware runs the same FI-hardened ERC-7730
non-membership proof on `(chain_id, inner.to, selector)`. If that opaque tuple
is present (or Bloom-positive) in the firmware catalogue, the whole Safe
request refuses instead of using this blind path.

#### CoW order pre-sign (1 context banner + 8 order-body pages)

When the SafeTx's inner call is CowSwap
`GPv2Settlement.setPreSignature(orderUid, true)` and the companion
attaches a verified CoW v3 trailer (see
**[Safe-wrapped CowSwap pre-sign](companion-safe-cowswap-presign.md)**),
the inner-tx pages become the full order intent instead of a blind-sign
page. The order is bound to *this* Safe: the firmware checks
`orderUid.owner == safe_address` and re-derives the orderDigest from the
v3 canonical, so the order shown is provably the one the Safe will act
on.

```
┌────────────────┐    ┌────────────────┐    ┌────────────────┐
│CowSwap order   │    │CowSwap SELL    │    │for at least    │
│for this Safe:  │    │0.20 USDC       │    │0.0004 WETH     │
│0x5afe00..000002│    │                │    │                │  …order body…
│> next          │    │                │    │                │
└────────────────┘    └────────────────┘    └────────────────┘
   context banner          native decoded order pages; each non-native
                           token also shows its full contract address
```

The context banner is the load-bearing linkage page: it names the Safe
(short form, cross-checkable against the full address on header page 2)
so the user can never confuse "a CoW order I'm placing personally" with
"a CoW order I'm placing for this multisig". The order-body pages are
the *same* renderer the direct CoW v3 flow uses
(`cowswap_display::append_order_body_pages`) — receiver `0x0` renders as
`(= the Safe)` because GPv2 routes proceeds to the order owner. Refund
pages (below) still render whenever the SafeTx configures a gas refund:
the combined view never hides a signed fact.

### Refund pages (2 pages, only when a gas refund is configured)

If any of `gasPrice` / `gasToken` / `refundReceiver` is non-zero, two
loud pages render between the metadata header and the inner-tx pages —
a *token* refund has no on-chain `gasPrice` cap, so a hidden refund is a
full-ERC-20-balance drain channel. The pages name the refund token (or
`ETH (native)`) and the recipient (or `tx.origin`).

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
                                                  14. SPHINCS+C10 sign UserOp
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

## Gas refund parameters (gasPrice / gasToken / refundReceiver)

A SafeTx carries five fields the inner-call semantics never surface:
`safeTxGas`, `baseGas`, `gasPrice`, `gasToken`, `refundReceiver`. When
`gasPrice > 0`, `execTransaction` pays the executor
`(gasUsed + baseGas) * gasPrice` of `gasToken` (native ETH when
`gasToken == 0`) to `refundReceiver` (or `tx.origin` when zero). All
five are folded into the EIP-712 `safeTxHash`, so they are tamper-bound
the moment the wallet signs — but being *bound* is not the same as being
*shown*.

The dangerous case is a **token refund** (`gasToken != address(0)`):
Safe applies no on-chain cap to `gasPrice` for token refunds (the
`min(gasPrice, tx.gasprice)` cap only applies to the native-ETH branch),
so an attacker can set `gasToken` to any ERC-20 the Safe holds,
`refundReceiver` to themselves, and `gasPrice`/`baseGas` so the refund
equals the Safe's entire balance of that token — all behind a SafeTx
whose inner call reads as a benign "transfer 1 USDC" or even an empty
call. For a 1-of-1 Safe the wallet's `approveHash` is sufficient
threshold; the attacker then calls `execTransaction` (step 20 above) and
the drain settles.

To keep the surface WYSIWYS, the renderer (`safe_display.rs`) surfaces a
loud two-page refund block on **both** the approveHash and
execTransaction paths whenever any of `gasPrice` / `gasToken` /
`refundReceiver` is non-zero:

```text
┌────────────────┐    ┌────────────────┐
│! GAS REFUND    │    │Refund to:      │
│Safe pays in:   │    │<refundReceiver │
│0xA0b8..6eB48   │    │ full addr /    │
│> next          │    │ tx.origin>     │
└────────────────┘    └────────────────┘
   token = gasToken        recipient
   ("ETH (native)"
    when gasToken == 0)
```

The exact refund *amount* is not shown — it depends on runtime `gasUsed`
the firmware cannot know — but the **token** and the **recipient** are
the WYSIWYS-critical facts (the user can recognise "that's my USDC going
to an address I don't know"). The SafeTx inner `value` (ETH the Safe
forwards to `to` on execution) is likewise surfaced on its own page for
every inner kind, not just plain native-currency transfers.

## DelegateCall

Refused outright **except** for one tightly-pinned shape: an
`operation == 1` (DELEGATECALL) whose target is one of the three
canonical `MultiSendCallOnly` deployments and whose calldata is a strict
`multiSend` batch (see the multiSend bullet under "What's *not* supported"
below, and `secure/src/tx/eip712/safe/multi_send.rs`). That batch is
decoded per-record and clear-signed; a DELEGATECALL is **never**
blind-signed. Every *other* delegatecall is refused: it replaces the
Safe's code for the duration of the call — module installation, guard
swaps, owner changes via library calls, all routed through this hatch.
There's no honest way to clear-sign an arbitrary delegatecall for a
non-expert user, so the verify pipeline rejects any non-allowlisted
`operation == 1` with the same `None` return as any other failure mode.

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
- **`multiSend` recursive decoding** — *now supported* (was a v1
  limitation). Safe's `multiSend` packs N inner txs into one calldata
  blob. Rather than the old blind-sign fallback (calldata hash + length),
  the inner-tx renderer traverses the `multiSend` payload and clear-signs
  each sub-call. `secure/src/tx/eip712/safe/multi_send.rs` strictly
  decodes the packed records (per-record `operation == 0`, ≤6 records,
  exact ABI framing) and accepts the enclosing `operation == 1`
  DELEGATECALL only against the three pinned canonical
  `MultiSendCallOnly` deployments; each record then routes through the
  same inner ladder (ERC-20 / ETH / Safe-mgmt / CoW / loud blind) with
  divider pages. Any rule violation or page-budget overflow refuses to
  sign.
- **Safe v1.1.x and earlier** — used a domain separator without
  `chainId`. They self-police: our recomputed `safeTxHash` will not
  match the calldata's `bytes32` and the trailer is silently rejected.
  Companion is responsible for refusing to send a `safe_v1` trailer
  for an incompatible Safe contract.
- **DelegateCall** — refused except for an allowlisted `MultiSendCallOnly` batch (see above).
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
   is unchanged — the wallet still emits SPHINCS+C10 over the UserOp's
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
