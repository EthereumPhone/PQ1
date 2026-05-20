# PQSigner Multi-Tx Batch Sign — Companion Integration

This doc is a delta against [`companion-app-integration.md`](companion-app-integration.md).
It assumes you already have a working companion that drives single-tx
`SIGN_USEROP` (INS `0x30`) end-to-end, and only describes what's new for
the atomic multi-call **batch sign** flow.

## TL;DR

* New gateway command: `CMD_SIGN_USEROP_BATCH = 30`.
* New USB v2 instruction: `INS_V2_SIGN_USEROP_BATCH = 0x32`.
* Same Type 1 / Type 2 / initCode response framing as `INS_V2_SIGN_USEROP`
  — the only on-chain difference is the resulting UserOp's `callData`,
  which is `executeBatchWithOffchainCount(...)` instead of
  `executeWithOffchainCount(...)`.
* The user reviews **each inner tx independently** on the OLED (clear-
  signing preserved per member) and then a final "Sign N txs?" gate.
* Hard caps: `MAX_BATCH_TXS = 4` inner calls per UserOp, each call's
  `data` ≤ `MAX_TX_LEN = 4096` bytes.
* Same flag layout as single-tx — `FLAG_INCLUDE_INIT_CODE`,
  `FLAG_REGISTER_SLOT`, `account_index`, `slot_index` all behave
  identically. Type 1 (addOwner / factorySig) UserOps remain
  single-call by construction; only the user-tx Type 2 is batched.

## When to use it

Use batch sign when you want the user to atomically authorise N inner
calls in a single UserOp — typical cases:

* `approve(token, router, amount)` + `swap(...)` + `transfer(...)`
* multi-leg rebalances (close A, open B, fee transfer)
* token approvals + DEX trade in one click
* claim + restake + transfer

If you only need one inner call, keep using `INS_V2_SIGN_USEROP` — the
single-tx path is cheaper on-chain (`executeWithOffchainCount` calldata
is smaller than `executeBatchWithOffchainCount` for `N=1`).

## Wire format (request payload, big-endian unless noted) — v2

```text
[ 0.. 8)  chain_id            u64 BE
[ 8..12)  flags               u32 BE  — same layout as SIGN_USEROP:
                                        bit 31 = FLAG_INCLUDE_INIT_CODE
                                        bit 30 = FLAG_REGISTER_SLOT
                                        bits 29..22 = account_index (8 bits)
                                        bits 21..0  = slot_index   (22 bits)
[12..32)  sender              20 B    — PQSmartWallet proxy address
[32..52)  entry_point         20 B
[52..84)  nonce               u256 BE — base nonce; if FLAG_REGISTER_SLOT
                                        is set the addOwner UserOp uses
                                        this nonce, the batch UserOp
                                        uses base+1
[84..116) call_gas_limit      u256 BE
[116..148) verification_gas   u256 BE
[148..180) pre_verification   u256 BE
[180..212) max_fee_per_gas    u256 BE
[212..244) max_prio_per_gas   u256 BE
[244..276) paymaster_and_data_hash  sha256 (SHA256_EMPTY = sha256("") when absent)
[276..277) wire_version       u8     — MUST equal SIGN_USEROP_BATCH_WIRE_VERSION (2)
[277..278) batch_count        u8     — 1..=MAX_BATCH_TXS (=4)
[278..  )  inner-tx blocks, repeated `batch_count` times:
             [20]  to_address
             [32]  value (u256 BE)
             [ 2]  data_len (u16 BE, 0..=MAX_TX_LEN)
             [N]   data
[...   )   TLV-tagged trailer list (see next section)
```

The `wire_version` byte was introduced when the TLV-tagged trailer list
landed (v1 → v2 cutover); the firmware refuses any payload with
`wire_version != 2` so a stale companion never silently mis-parses.

### TLV-tagged trailer list

After the last inner-tx block, the payload terminates in a
count-prefixed list of TLV records:

```text
[u8 trailer_count]                         — 0..=MAX_TRAILERS_PER_BATCH (32)
[trailer_count × {
    u8  kind                               — 1..=8 (see table below)
    u8  tx_idx                             — 0..batch_count-1 for kinds 1..=7;
                                             TRAILER_TX_IDX_BATCH_WIDE (0xff) for kind 8
    u16 BE len                             — bounded per-kind (see table)
    [len bytes]                            — trailer payload (the same bundle
                                             format the single-tx path consumes)
}]
```

Each per-tx kind binds via `tx_idx` to one inner transaction. The
firmware verifies the bundle, FI-cross-checks the binding, and feeds
the result into `pick_sign_pages` for that tx. Failed verifications
drop silently (parity with single-tx — clear-signing is an enhancement
layer that degrades gracefully) **except** for the two downgrade-
mitigation gates below, which abort the whole batch with
`InvalidPointer`. Kind 8 trailers accumulate batch-wide into a single
`NameResolver` shared across renders.

| `kind` | symbol | max bytes | verifier | applies to |
|-------:|--------|----------:|----------|------------|
| 1 | `TRAILER_KIND_ERC20`         | 1120 | `erc20::bundle::verify_erc20_bundle` (`ERC20_DB_ROOT`) | inner tx at `tx_idx` |
| 2 | `TRAILER_KIND_ZK_V1`         | 2660 | `zk::verify_and_bind_trailer_v1` (`VK_DB_ROOT`)        | inner tx at `tx_idx` |
| 3 | `TRAILER_KIND_ZK_V3`         | 2764 | `tx::eip712::cowswap::verify_and_bind_trailer`         | inner tx at `tx_idx` |
| 4 | `TRAILER_KIND_SAFE_V1`       | 4379 | `tx::eip712::safe::verify_and_bind_trailer`            | inner tx at `tx_idx` |
| 5 | `TRAILER_KIND_SEL_CURATED`   | 1156 | `selectors::verify_selector_bundle` (`SELECTOR_DB_ROOT`) | inner tx at `tx_idx` |
| 6 | `TRAILER_KIND_SEL_SELFATTEST`|   68 | `selectors::parse_self_attest_bundle` (keccak self-check) | inner tx at `tx_idx` |
| 7 | `TRAILER_KIND_ERC7730`       | 5130 | `tx::erc7730::verify_erc7730_bundle` (`ERC7730_DESCRIPTORS_ROOT`) | inner tx at `tx_idx` |
| 8 | `TRAILER_KIND_NAME`          | 1156 | `names::verify_name_bundle` (`NAMES_DB_ROOT`)          | batch-wide (`tx_idx == 0xff`) |

The firmware refuses at parse time:

* `trailer_count > MAX_TRAILERS_PER_BATCH (32)`.
* `kind == 0 || kind > 8`.
* `kind ∈ 1..=7` with `tx_idx >= batch_count` (out-of-range routing).
* `kind == 8` with `tx_idx != 0xff` (name bundle must be batch-wide).
* duplicate `(kind, tx_idx)` for kinds 1..=7.
* both `TRAILER_KIND_SEL_CURATED` and `TRAILER_KIND_SEL_SELFATTEST`
  present for the same `tx_idx` (mutually exclusive).
* more than `MAX_NAME_BUNDLES (4)` kind-8 records in the batch.
* per-kind `len > cap` from the table above.
* `Σ len > TRAILERS_TOTAL_MAX_LEN (24 576)` across all records.
* any trailing bytes past the last record.

### Downgrade-mitigation gates (per inner tx)

Mirroring the single-tx path: before `pick_sign_pages` runs for inner
tx `i`, the firmware refuses to sign with `InvalidPointer` if either
gate fires. Companions MUST emit the corresponding routed trailer in
these cases.

* **CoW v3**: if `inner.data[0..4] == 0xec6cb13f` (setPreSignature) AND
  `inner.to == GPV2_SETTLEMENT (0x9008…ab41)`, a kind 3 trailer with
  `tx_idx = i` is mandatory.
* **Safe v1**: if `inner.data[0..4] == 0xd4d9bdcd` (approveHash) AND
  `inner.data.length == 36`, a kind 4 trailer with `tx_idx = i` is
  mandatory.

### Migration from v1

The pre-v2 wire format placed `batch_count` at offset 276 and accepted
at most one optional `[u16 BE len][erc7730_bundle]` trailer at the tail.
The cutover is hard: the firmware refuses v1 payloads with
`InvalidPointer / "bad wire_version"`. Companions check device
protocol version (via `INS_GET_DEVICE_INFO`) before sending and
refuse to send v2 payloads to firmware that doesn't advertise v2 support.

## Wire format (response)

**Byte-identical to `CMD_SIGN_USEROP`'s response** — same parser:

```text
[new_offchain_count(8 BE)]
[init_code_len(4 BE)] [init_code...(0 or 4280 bytes)]
[type1_len(4 BE)]     [type1_wrapper...(0 or 4128 bytes)]
[type2_len(4 BE)]     [type2_wrapper...(4128 bytes)]
```

Each `wrapper` is `abi.encode(uint256 ownerIndex, bytes c10Sig)` — drop
it straight into the EntryPoint v0.6 `UserOperation.signature`.

`new_offchain_count` is the firmware's per-slot `local_offchain_count`
as committed to the just-signed batch UserOp. The companion uses this
to populate the `newOffchainCount` arg the on-chain
`executeBatchWithOffchainCount(...)` selector consumes — same logic as
the single-tx path.

## Building the on-chain UserOp

Once you have the device-emitted `(type1_wrapper?, type2_wrapper)`:

1. Compute the inner `callData` as
   ```solidity
   abi.encodeCall(
       wallet.executeBatchWithOffchainCount,
       (ownerIndex, newOffchainCount, targets, values, datas)
   )
   ```
   where `ownerIndex == slot_index + 1`, `targets[]/values[]/datas[]` are
   the same `(to, value, data)` triples you sent to the device, and
   `newOffchainCount` is the leading `u64` from the response.
2. Wrap into a `UserOperation06`:
   * `sender` = the wallet proxy address (same one you sent in).
   * `nonce` = `base_nonce` (or `base_nonce + 1` if Type 1 was emitted).
   * `initCode` = the device-emitted `init_code` bytes (only on first
     deploy, when you set `FLAG_INCLUDE_INIT_CODE`).
   * `callData` = the bytes from step 1.
   * `signature` = the device-emitted `type2_wrapper` (4128 bytes).
   * Gas + paymaster fields = the values you sent to the device.
3. Submit to the EntryPoint v0.6 bundler RPC like any other UserOp.

If `type1_wrapper` is also present (because you set `FLAG_REGISTER_SLOT`),
submit it as a **separate UserOp at `nonce = base_nonce`** with
`callData = abi.encodeCall(wallet.addOwnerBytes, (slotN_owner_bytes))`
and `signature = type1_wrapper`. The batch UserOp follows it at
`nonce = base_nonce + 1`. This is identical to the single-tx rotation
flow — the firmware just signs the rotation Type 1 and the batch Type 2
in one device round-trip.

## On-chain ABI

```solidity
function executeBatchWithOffchainCount(
    uint256 ownerIndex,
    uint256 newOffchainCount,
    address[] calldata targets,
    uint256[] calldata values,
    bytes[]   calldata datas
) external;
```

Selector: `0x7a389933` (= `bytes4(keccak256("executeBatchWithOffchainCount(uint256,uint256,address[],uint256[],bytes[])"))`).

The wallet's `_isSlotAllowedSelector` accepts both
`executeWithOffchainCount` and `executeBatchWithOffchainCount` for
slot-key (ownerIndex ≥ 1) UserOps. Bootstrap (ownerIndex == 0) is still
restricted to `addOwnerBytes`, so a batch UserOp signed under bootstrap
will be refused at `validateUserOp`.

The combined per-slot cap `slotUses[i] + offchainSigCount[i] ≤
MAX_SLOT_USES (= 65,536)` applies identically — every batch UserOp
bumps `slotUses[i]` by exactly 1, regardless of how many inner calls
it carried.

## USB transport (INS `0x32`)

* CLA = `APDU_CLA_V2 = 0xF0` (same as INS `0x30`).
* The payload typically exceeds the 253-byte APDU MTU (header alone is
  277 bytes), so the request **must** be sent via standard ISO 7816-4
  command chaining — same chunker your single-tx sign already uses.
  Use `P1 = P1_V2_MORE = 0x80` on every chunk except the last, and
  `P1 = P1_V2_LAST = 0x00` on the final.
* Response is also chunked via `GET_RESPONSE` chaining once the device
  has the bundle ready (typical response is ~4136 bytes Type 2 only,
  or ~8268 bytes when Type 1 + Type 2 are both emitted).
* Status word mapping is unchanged — `SW_OK (0x9000)` on success,
  `SW_INTERNAL_ERROR (0x6F00)` for `CryptoError` / `InvalidPointer`,
  `SW_SECURITY_NOT_SATISFIED` for `UserRejected` (cancel anywhere in
  the per-tx review chain), `SW_REFERENCED_DATA_INVALIDATED` for
  `IdleWipe`, etc. See `nsc_status_to_sw` in
  `nonsecure/src/usb/commands.rs`.

## UI behaviour the user sees

For an N-tx batch, the device renders, in order:

1. Banner: `BATCH SIGN` / `Tx 1 of N`
2. The same pages a single-tx sign would render for inner tx 1
   (value / ERC-20-shape / blind-sign).
3. Long-right (or cancel via long-left).
4. Banner: `Tx 2 of N` + tx 2 pages.
5. … repeat for each member …
6. Final summary page: `Sign N txs?` / `Long-right` / `to confirm`.
7. Long-right confirms; signing begins.

Cancel at **any** of the per-tx confirms or the final summary aborts
the entire signing operation — no inner tx is signed individually.
This is the trusted-display contract; it cannot be skipped from the
non-secure side.

## Constants

The companion can hard-code these or pull them from the shared
constants header (preferred):

| Constant | Value | Source |
|---|---|---|
| `INS_V2_SIGN_USEROP_BATCH` | `0x32` | `shared::INS_V2_SIGN_USEROP_BATCH` |
| `MAX_BATCH_TXS` | `4` | `shared::MAX_BATCH_TXS` |
| `SIGN_USEROP_BATCH_HEADER_LEN` | `277` | `shared::SIGN_USEROP_BATCH_HEADER_LEN` |
| `SIGN_USEROP_BATCH_TX_PREFIX_LEN` | `54` | `shared::SIGN_USEROP_BATCH_TX_PREFIX_LEN` |
| `EXECUTE_BATCH_SELECTOR` | `0x7a389933` | `shared::EXECUTE_BATCH_SELECTOR` |
| `MAX_TX_LEN` (per-tx data cap) | `4096` | `shared::MAX_TX_LEN` |
| `MAX_SLOT_USES` (combined cap) | `65,536` | `shared::MAX_SLOT_USES` |

## Reference implementation

* Wire-format builder + e2e scenarios:
  [`nonsecure/src/e2e_test.rs`](../nonsecure/src/e2e_test.rs)
  (`build_batch_payload` + Scenarios 5e/5f/5g/5h/5i).
* USB router glue:
  [`nonsecure/src/usb/commands.rs`](../nonsecure/src/usb/commands.rs)
  (`cmd_sign_userop_batch`).
* Secure-world handler:
  [`secure/src/nsc/cmd_sign_userop_batch.rs`](../secure/src/nsc/cmd_sign_userop_batch.rs).
* Calldata encoder + unit tests:
  [`secure/src/aa/userop.rs`](../secure/src/aa/userop.rs)
  (`reconstruct_execute_batch_calldata` + `tests::test_batch_*`).
* Foundry tests:
  [`contracts/smart-wallet/test/PQSmartWallet.t.sol`](../contracts/smart-wallet/test/PQSmartWallet.t.sol)
  (`test_batchSlotSignValidate`, `test_batchBootstrapForbidden`,
  `test_executeBatchWithOffchainCount_runsInnerCalls`, etc.).

## Migration checklist

If your companion already speaks INS `0x30`:

- [ ] Add `INS_V2_SIGN_USEROP_BATCH = 0x32` to your APDU constants.
- [ ] Mirror the wire layout above in your payload builder. The first
      277 bytes (everything up to and including `batch_count`) are
      identical to the SIGN_USEROP header except `to/value/data_len/data`
      are replaced by `batch_count + N inner-tx blocks`.
- [ ] Reuse your single-tx APDU chaining; only the INS byte and the
      payload shape change.
- [ ] Reuse your single-tx response parser — bundle layout is unchanged.
- [ ] Build `executeBatchWithOffchainCount(...)` calldata for the
      submitted UserOp instead of `executeWithOffchainCount(...)`. Use
      the same `(targets, values, datas)` you sent to the device.
- [ ] Surface a per-tx review prompt in the UI before sending — the
      device will demand the user click through every member, so the
      companion-side preview should already enumerate them.
- [ ] Honour `MAX_BATCH_TXS = 4`; refuse to send N=0 or N>4 client-side
      so the user gets a clean error instead of `SW_INTERNAL_ERROR`.

That's the entire integration delta.
