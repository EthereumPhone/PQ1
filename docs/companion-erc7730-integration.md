# Companion-side ERC-7730 Integration

The PQSigner OS firmware accepts ERC-7730 clear-signing descriptors as
an OPTIONAL trailer on every `CMD_SIGN_USEROP` /
`CMD_SIGN_USEROP_BATCH` / `CMD_SIGN_OFFCHAIN` request. The companion is
responsible for:

1. Looking up the right descriptor for the tx's `(chain_id, to_address)`
   or `(chain_id, verifying_contract, domain_separator)` tuple.
2. Assembling the trailer in the firmware-expected wire format.
3. Attaching it to the sign request.

This doc covers (1) and (2). The wire format itself + the on-device
verification path live in `docs/erc7730-integration.md`.

## Lookup against `erc7730_db.bin`

The companion ships `tools/companion-stub/erc7730_db.bin` — a binary
blob containing the same descriptor IRs the firmware was built with,
plus the Merkle proof for each leaf. The blob is regenerated whenever
the firmware's `ERC7730_DESCRIPTORS_ROOT` changes; companion releases
MUST track firmware releases byte-for-byte (the blob's first 32 bytes
are the root the companion validates against — if it doesn't match the
firmware's compiled-in root, the firmware rejects every trailer the
companion sends).

Schema:

```
header:
  magic         [u8; 4] = "E73D"
  schema_ver    u8 = 1
  reserved      [u8; 3]
  root          [u8; 32]
  leaf_count    u32 BE
  proof_depth   u32 BE
entries:
  [leaf_count × {
    chain_id          u64 BE
    contract_addr     [u8; 20]
    primary_type_hash [u8; 32]   (zero when contract-context)
    ir_off            u32 BE     (offset into the trailing IR pool)
    ir_len            u16 BE
    proof_off         u32 BE     (offset into the trailing proof pool)
  }]
ir_pool        [u8; *]
proof_pool     [u8; *]
```

The companion's lookup flow:

```
fn lookup(chain_id: u64, to: [u8; 20], dsep: Option<[u8; 32]>)
    -> Option<&Entry>
{
    // 1. Linear scan (or hash-keyed lookup) over `entries[]`.
    entries.iter().find(|e| {
        e.chain_id == chain_id
            && e.contract_addr == to
            && match dsep {
                // EIP-712 typed sign — compare descriptor's primary
                // type hash against the message's primaryTypeHash.
                Some(dsep) => e.primary_type_hash[..4]
                    == compute_pth(&dsep)[..4],
                // Contract-context — primary_type_hash is all-zero,
                // we don't look at it.
                None => e.primary_type_hash == [0u8; 32],
            }
    })
}
```

## Trailer assembly

Wire format (`docs/erc7730-integration.md` §"Trailer format"):

```
[u16 BE bundle_len]
[bundle: ir_len(2 BE) || ir || leaf_index(4 BE) || proof_depth(4 BE) || proof]
```

The companion takes the entry from the lookup and serialises:

```
fn assemble_trailer(entry: &Entry, ir_pool: &[u8], proof_pool: &[u8])
    -> Vec<u8>
{
    let ir = &ir_pool[entry.ir_off..entry.ir_off + entry.ir_len];
    let proof = &proof_pool[entry.proof_off..entry.proof_off + PROOF_LEN];
    let mut bundle = Vec::with_capacity(2 + ir.len() + 4 + 4 + proof.len());
    bundle.extend_from_slice(&(ir.len() as u16).to_be_bytes());
    bundle.extend_from_slice(ir);
    bundle.extend_from_slice(&entry.leaf_index.to_be_bytes());
    bundle.extend_from_slice(&PROOF_DEPTH.to_be_bytes());
    bundle.extend_from_slice(proof);
    let mut trailer = Vec::with_capacity(2 + bundle.len());
    trailer.extend_from_slice(&(bundle.len() as u16).to_be_bytes());
    trailer.extend_from_slice(&bundle);
    trailer
}
```

The trailer slots into the sign-input wire layout AFTER the
`self_attest` trailer and BEFORE the names section. Zero-length
placeholders go in any prior trailer slot the companion doesn't use:

```
sign_input = base_header ||
             [u16 = 0] ||  // erc20 trailer (absent)
             [u16 = 0] ||  // zk_v1 trailer (absent)
             [u16 = 0] ||  // zk_v3 trailer (absent)
             [u16 = 0] ||  // safe_v1 trailer (absent)
             [u16 = 0] ||  // selector trailer (absent)
             [u16 = 0] ||  // self_attest trailer (absent)
             trailer    ||  // erc7730 trailer (above)
             names_section
```

## EIP-712 typed sign (kind=2)

For `CMD_SIGN_OFFCHAIN` with `kind = OFFCHAIN_KIND_EIP712_TYPED = 2`,
the trailer is the LAST element of the payload (not interleaved with
other trailer slots — kind=2 has its own dedicated wire format):

```
[u16 BE = 1]                  // domain_sep_present (1 = yes)
[u8; 32] domain_separator
[u8; 32] primary_type_hash
[u16 BE] encoded_data_len
[u8; encoded_data_len] encoded_data
[u16 BE] trailer_len
[u8; trailer_len] erc7730_trailer
```

`encoded_data` is what `viem::encodeAbiParameters(types, message)`
produces (the EIP-712 struct body, NOT including the type hash).

## Attestation policy

`secure/data/erc7730/policy.toml` is the host-build attestation gate.
The companion DOES NOT enforce attestation — the firmware trusts the
Merkle root, which only contains descriptors that passed the policy
at `dbgen` time. The companion only needs to ship the same `*_db.bin`
that was built against the same root.

For pre-production / bring-up: when the secure firmware is built with
the `erc7730-dev-unattested` Cargo feature ON, every render prepends a
"** DEV BUILD ** Unattested descriptor" warning page so the developer
cannot miss the relaxed gate. The feature is `compile_error!`-fenced
against `mode-production` so a shipping build never carries it.

## Common pitfalls

1. **Sending a descriptor without verifying the root.** If the
   firmware's compiled-in `ERC7730_DESCRIPTORS_ROOT` doesn't match the
   `*_db.bin` blob's first 32 bytes, every trailer the companion
   sends will fail Merkle verification and the firmware logs `"7730
   bundle fail"`. Check root parity at companion startup.
2. **Pairing a descriptor with a transaction it doesn't describe.**
   The firmware's `cross_check_contract` / `cross_check_eip712` gates
   reject this with `"7730 binding fail"`. The companion's lookup
   step MUST use the actual tx's `(chain_id, to)` not any cached
   value.
3. **Sending an EIP-712 typed trailer for a contract-context
   descriptor.** The descriptor's `primary_type_hash` is all-zero for
   contract-context entries; the kind=2 path will mismatch on the
   selector lookup and fall through to blind-sign. Use kind=2 only
   when the descriptor has an `eip712` section with a deployment
   matching the message's `verifyingContract`.
4. **Forgetting the `flags` byte in the offchain header.** `flags = 1`
   = `OFFCHAIN_FLAG_ACCOUNT_DEPLOYED`; `flags = 0` = counterfactual
   ERC-6492 path. Setting bit 0 wrong returns either
   `"6492 needs slot 0"` (slot != 0 + counterfactual) or a wrong
   output buffer size.

## See also

- `docs/erc7730-integration.md` — on-device IR + verification.
- `docs/usb-protocol-v2.md` — sign-input wire layout + offchain kind=2.
- `docs/companion-app-integration.md` — companion-side architecture.
- `tools/companion-stub/erc7730_db_e2e.bin` — the e2e fixture the
  firmware test suite uses.
