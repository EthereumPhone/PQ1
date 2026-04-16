# Phase 4 — USB handler cleanup + webhid_test.html rewrite

**Status:** not started.
**Depends on:** phase 3 (unified sign command must exist and respond with the
new Type 1/Type 2 bundle format).
**Blocks:** user-facing E2E testing from a browser.

## Why this phase exists

The USB layer currently exposes 14 INS codes spanning SLH-DSA, ZK clear-sign,
EIP-712, bootstrap, JARDÍN split commands, etc. After the cutover, there's
exactly one signing command (JARDÍN Type 1 + Type 2 bundle) plus a slot-info
query. Everything else goes.

The webhid_test.html tool (~1900 lines) currently has tabs for ETH / USDC /
Aave V3 (ZK clear-sign). After the cutover, ETH + USDC stay (now signed via
JARDÍN unified path), DeFi/Aave tab goes. The local OTS counter hack from an
earlier conversation turn goes (firmware now owns `next_q` via flash).

## Files to modify

| File | Action |
|---|---|
| `nonsecure/src/usb/commands.rs` | Delete 9 INS handlers + v1 protocol; rewrite 0x30 for unified payload |
| `nonsecure/src/nsc_api.rs` | Strip unused veneer decls/wrappers; keep sign_userop, get_jardin_slot_info, unlock/lock/status |
| `shared/src/lib.rs` | Remove deleted INS constants; update `MAX_JARDIN_RESPONSE_LEN` |
| `tools/webhid_test.html` | Major surgery: remove Aave tab, remove OTS localStorage, rewrite signing flow for bundle parsing + two-UserOp submission, add slot status panel |

## USB layer changes

### Keep

| INS  | Handler | Notes |
|------|---------|-------|
| 0x01 | `cmd_v2_get_device_info` | Update capability bitfield to report JARDÍN only |
| 0x02 | `cmd_v2_get_status` | Provisioned / locked state |
| 0x10 | `cmd_v2_unlock` | PIN unlock |
| 0x11 | `cmd_v2_lock` | Explicit lock |
| 0x30 | `cmd_v2_sign_userop` | **Rewrite** for new unified payload |
| 0x72 | `cmd_v2_get_jardin_slot_info` | Queries flash via new nsc_api::get_jardin_slot_info (reads from `jardin_flash::read_latest`) |
| 0xC0 | `cmd_v2_get_response` | Continuation of long responses |

### Delete

| INS  | Handler | Why |
|------|---------|-----|
| 0x20 | `cmd_v2_get_bootstrap_vk` | No bootstrap signer |
| 0x21 | `cmd_v2_get_main_vk` | No main SLH-DSA signer |
| 0x31 | `cmd_v2_sign_clear_userop` | No ZK clear-signing |
| 0x40 | `cmd_v2_sign_message` | No EIP-191 path (JARDÍN covers all signing) |
| 0x41 | `cmd_v2_sign_eip712` | No ZK EIP-712 path |
| 0x50 | `cmd_v2_sign_bootstrap` | No bootstrap signer |
| 0x60 | `cmd_v2_get_wallet_address` | Derive client-side via factory CREATE2 (webhid already has factory addr) |
| 0x70 | `cmd_v2_sign_jardin` (split) | Folded into 0x30 |
| 0x71 | `cmd_v2_register_jardin_slot` (split) | Folded into 0x30 |

### Delete entirely: v1 protocol (CLA 0xE0)

All v1 handlers are SLH-DSA-specific legacy. Strip the dispatcher and all
`cmd_v1_*` methods from `nonsecure/src/usb/commands.rs`.

### Rewrite INS 0x30 payload format

New input layout (matches phase 3's expected input):

```
offset  size  field
  0     8    chain_id (u64 BE)
  8     4    slot_index_hint (u32 BE)
 12    20    sender (zeroed if undeployed)
 32    32    nonce (u256 BE)
 64    32    call_gas_limit
 96    32    verification_gas_limit
128    32    pre_verification_gas
160    32    max_fee_per_gas
192    32    max_priority_fee_per_gas
224    32    paymaster_and_data_hash
256    20    to_address
276    32    value
308     2    data_len (u16 BE)
310     N    data
```

Pass through to `nsc_api::sign_userop()` unchanged; secure world parses
everything.

Response (to the companion, via chained APDU):
```
[type1_len(4 BE)][type1_bytes...][type2_len(4 BE)][type2_bytes...]
```

Max size: 8086 bytes. Current `sendChainedApdu` in webhid already handles
multi-chunk APDUs via the `0x61` continuation pattern; verify it can handle
8K responses.

## Webhid tool changes (`tools/webhid_test.html`)

### Strip

1. Remove `<button class="tab" data-tab="defi">Aave V3</button>` and its
   content div.
2. Remove `TransactionBuilder.aaveSupplyDemo` (~150 lines).
3. Remove all of `VK_AAVE_BUNDLE`, ZK proof constants.
4. Remove the `nextOtsIndex` / `setNextOtsIndex` / localStorage counter —
   this was a workaround for the old SLH-DSA OTS monotonicity rule;
   irrelevant now.
5. Remove `signClearUserOp`, `signEip712`, `signMessage`, `signBootstrap`
   DeviceAPI methods.
6. Remove the capability-bitfield branches for non-JARDÍN signers in the
   UI.

### Rewrite sign flow

```javascript
async function handleSign() {
    const tab = UI.getActiveTab();
    let payload;
    if (tab === 'eth') {
        // Build new v3 payload (see format above)
        payload = buildSignPayload({
            chainId: 1n,
            to: document.getElementById('ethTo').value,
            value: parseUnits(document.getElementById('ethAmount').value, 18),
            data: new Uint8Array(0),
            slotIndexHint: 0,
        });
    } else if (tab === 'erc20') {
        // Build ERC20 transfer payload
        const calldata = buildTransferCalldata(to, amount);
        payload = buildSignPayload({
            chainId: 1n,
            to: USDC_ADDRESS,
            value: 0n,
            data: calldata,
            slotIndexHint: 0,
        });
    }

    UI.showProgress('Signing', 'Confirm on device');
    try {
        const { sw, data } = await sendChainedApdu(INS_SIGN_USEROP, payload);
        if (sw !== SW_OK) throw new DeviceError(sw, 'Sign failed');

        // Parse bundle
        const type1Len = u32be(data[0], data[1], data[2], data[3]);
        let off = 4;
        let type1 = null;
        if (type1Len > 0) {
            type1 = data.slice(off, off + type1Len);
            off += type1Len;
        }
        const type2Len = u32be(data[off], data[off+1], data[off+2], data[off+3]);
        off += 4;
        const type2 = data.slice(off, off + type2Len);

        if (type1) {
            // Type 1 present → slot registration UserOp. Submit first.
            UI.setProgressSubtitle('Registering signing slot...');
            const type1UserOpHash = await submitTypeOneRegistration(type1);
            await waitForConfirmation(type1UserOpHash);
        }

        // Submit Type 2 user tx.
        UI.setProgressSubtitle('Broadcasting transaction...');
        const type2UserOpHash = await submitTypeTwoUserOp(type2);
        await waitForConfirmation(type2UserOpHash);

        UI.showSuccess({ type1UserOpHash, type2UserOpHash });
    } catch (e) {
        UI.toast(e.message, 'error');
    }
}
```

### Bundler integration

For submission you'll need a bundler RPC. SPHINCs-'s `jardin_userop.py` uses
Pimlico for Sepolia:
```
https://api.pimlico.io/v2/{chainId}/rpc?apikey={apiKey}
```

For the webhid tool, the bundler URL should be configurable (settings panel
in the UI, or hardcoded to a Sepolia test bundler for now). Submit pattern:

```javascript
async function submitUserOp(userOp, entryPoint) {
    const response = await fetch(BUNDLER_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            jsonrpc: '2.0',
            method: 'eth_sendUserOperation',
            params: [userOp, entryPoint],
            id: Date.now(),
        }),
    });
    const { result, error } = await response.json();
    if (error) throw new Error(error.message);
    return result; // userOpHash
}

async function waitForConfirmation(userOpHash) {
    for (let i = 0; i < 60; i++) {
        const receipt = await fetch(BUNDLER_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                jsonrpc: '2.0',
                method: 'eth_getUserOperationReceipt',
                params: [userOpHash],
                id: Date.now(),
            }),
        });
        const { result } = await receipt.json();
        if (result) return result;
        await new Promise(r => setTimeout(r, 2000));
    }
    throw new Error('UserOp not confirmed after 2 minutes');
}
```

### Slot status panel

Cosmetic only. After unlock, query `INS_V2_GET_JARDIN_SLOT_INFO (0x72)` and
display:

```
Slot 0 · 3 of 95 signatures used · 92 remaining
[progress bar]
```

Refresh after every successful sign.

## Frozen contracts

- The Type 1 / Type 2 byte formats are frozen by the on-chain verifier (see
  phase 5). Don't re-wrap, don't swap byte order, don't compress.
- The INS 0x30 input format must be understood by phase 3's payload parser.
  If you want to change the input layout, update both sides in the same
  commit.

## What NOT to do

- **Don't add a "Register Slot" button** in the UI. The whole point is that
  slot registration is invisible to the user; the firmware handles it
  transparently and the companion just submits two UserOps when `type1_len
  > 0`.
- **Don't reintroduce client-side `nextOtsIndex`** — the firmware is
  authoritative now. Remove the localStorage key and move on.
- **Don't split the bundle into two separate sign commands** at the USB
  layer. The atomicity of "flash-before-release" in phase 3 means the
  firmware commits to having incremented `next_q`; splitting at USB level
  creates a window where the companion could submit Type 2 without Type 1
  and leave the on-chain state unregistered.

## Verification

1. Build: `cargo build -p sphincs-tz-nonsecure` (no_std embedded).
2. QEMU e2e: `make e2e` — must pass new JARDÍN scenario.
3. Real hardware: `make flash-hw-se050-oled-standalone`. Unlock via
   webhid_test.html. Sign an ETH transfer: verify the webhid UI shows
   "Registering slot" → "Signing" progress, and that both UserOps land on
   Sepolia.
4. Sign a second ETH transfer immediately: verify `type1_len == 0` (no
   re-registration), only one UserOp submitted.
5. Verify no console errors, no stale localStorage hang-ups.
