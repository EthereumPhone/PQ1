# ERC-8213 Fingerprint Pages — Cross-Device Verification

The ERC-8213 spec (Ethereum Magicians thread #24295) standardises how
wallets display signature/calldata digests so users can cross-check the
on-device fingerprint against an independent tool. The PQSigner OS
firmware renders a 2-page fingerprint for every clear-signing path:
page F is the banner (`"8213 Fingerprint"` + kind label) and page F+1
is the full 32-byte hash split 4 rows × 8 hex bytes.

This document is the recipe for an external party (you, an auditor, a
support engineer) to regenerate the same hash from public inputs.

## Kind variants

The fingerprint that the firmware renders is keyed on the signing
mode. Helpers live in `pqsigner-tx-core::erc8213`:

| Kind             | Helper                                  | Wire input                                              |
|------------------|-----------------------------------------|---------------------------------------------------------|
| UserOpHash       | `userop_hash`                           | EntryPoint v0.6 UserOp                                  |
| Eip712Final      | `eip712_final_hash`                     | `(domain_separator, struct_hash)`                       |
| Eip1559Tx        | `pqsigner_tx_core::eip1559::sighash`    | RLP-encoded unsigned tx envelope                        |
| PersonalSign     | `pqsigner_aa::eip1271::replay_safe_hash`| `keccak256("\x19Ethereum Signed Message:\n<len><msg>")` |
| Raw32            | identity                                | already 32 bytes                                        |

## Recipe — `cast` (foundry)

```bash
# UserOpHash (EntryPoint v0.6)
cast keccak \
  $(cast abi-encode 'f(address,uint256,bytes32,bytes32,uint256,uint256,uint256,uint256,uint256,bytes32,address)' \
    <sender> <nonce> $(cast keccak <initCode>) $(cast keccak <callData>) \
    <callGasLimit> <verificationGasLimit> <preVerificationGas> \
    <maxFeePerGas> <maxPriorityFeePerGas> \
    $(cast keccak <paymasterAndData>) <entryPoint>)

# Eip712Final
cast keccak 0x1901$(printf %s <domain_separator><struct_hash> | sed 's/0x//g')

# Eip1559Tx — keccak256(0x02 || rlp([chain_id, nonce, ...]))
cast keccak --hex 02$(cast rlp <encoded_tx>)

# PersonalSign
cast keccak "$(printf '\x19Ethereum Signed Message:\n%d%s' ${#MSG} "$MSG")"
```

## Recipe — `viem` (TypeScript)

```ts
import { keccak256, encodeAbiParameters, toHex, concatHex } from 'viem'

// Eip712Final
const final = keccak256(concatHex(['0x1901', domainSeparator, structHash]))

// UserOpHash (v0.6) — re-uses viem's getUserOperationHash
import { getUserOperationHash } from 'viem/account-abstraction'
const uoHash = getUserOperationHash({ userOperation, entryPointAddress, entryPointVersion: '0.6', chainId })

// PersonalSign
import { hashMessage } from 'viem'
const pHash = hashMessage(message)
```

## Recipe — `safe-hash-rs` (host CLI)

```bash
safe-hash --chain sepolia --tx <typed-data-json>
```

The output's `hashStruct` matches the firmware's `Eip712Final`
fingerprint when the JSON's `domain` + `message` match what the
companion fed the firmware.

## Cross-checking on the device

1. Read the fingerprint hash off the OLED (page F+1 — 4 rows × 8 hex
   bytes each).
2. Run the matching recipe above against the dapp's public inputs
   (UserOp, EIP-712 message, RLP tx, signed message).
3. Compare byte-for-byte. A mismatch means EITHER the companion is
   sending the firmware different bytes than it told the dapp OR your
   recipe is computing the wrong hash. Reject the sign request and
   investigate.

## Implementation notes

- The 8213 spec mandates the FULL digest. Don't confuse the 2-page
  8213 fingerprint with the legacy single-page
  `write_calldata_hash_rows` which truncates to 14 hex chars (kept
  for non-8213 paths like blind-sign + selectors).
- Page budget: 2 pages × 22 page cap = ~6 pages of headroom after the
  longest existing renderer. No risk of bumping page count past
  `MAX_PAGES = 22`.
- Test vectors: every helper in `pqsigner-tx-core::erc8213` has
  pinned test vectors in `pqsigner-tx-core/src/erc8213.rs` —
  these run in the host test suite (`cargo test -p pqsigner-tx-core`).
  They catch wire-format drift but not cross-implementation drift
  (the parity gate that Cyfrin / viem / safe-hash-rs would each add;
  see `tools/cross_parity_erc8213.py` — stub deferred per handoff
  item 7).

## See also

- ERC-8213 Magicians thread: <https://ethereum-magicians.org/t/erc-8213-wallet-signature-and-calldata-digest-display/24295>
- `docs/erc7730-integration.md` — full ERC-7730 spec on-device.
- `tools/cross_parity_erc8213.py` — placeholder for the
  cross-implementation parity check.
