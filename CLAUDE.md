# PQSigner OS — LLM Context

> **Agent process entry point:** Claude Code loads this file directly. Before
> non-trivial work, read [`AGENTS.md`](AGENTS.md), which routes current status,
> the planning/review workflow, and applicable adversarial-review playbooks.
> The project contract below remains authoritative for its stated scope.

Post-quantum ERC-4337 hardware wallet on **STM32U585 (Cortex-M33, TrustZone) + OPTIGA Trust M V3 + SE050**. **SPHINCS+C10 only** for signing — pure PQ, no ECDSA fallback. Account-abstraction smart account on **EntryPoint v0.6** (Coinbase-Smart-Wallet-compatible) — **frozen target, no v0.7/v0.8 migration**: the v0.6 instance address + ABI are baked into `initCode`, the userOpHash preimage, and the on-chain factory; switching EntryPoint versions would change the CREATE2 init-code hash and break invariant #6 (same 24 words → same address on every chain). v0.6 stays supported by EIP-4337 bundlers indefinitely; if v0.6 is ever sunset, the response is to keep using direct EOA-bundled execution against the same wallet contract, not to redeploy. Same 24 words → same on-chain address on every chain (CREATE2 salt = `sha256(masterPkSeed‖masterPkRoot)`). SHA-256 inside the PQ stack; Keccak-256 only for EVM-mandated hashes (userOpHash, EIP-712, EIP-1559, ERC-7201, CREATE2 opcode).

**Status (2026-04, pre-production bring-up).** All-C10 cutover complete: bootstrap **and** slot keys are C10 (`h=18, d=2, a=11, k=13, w=8, l=43, target_sum=205, sig=4008`). Boots on real B-U585I-IOT02A and QEMU mps2-an505. Both SE drivers + Tier-1 SAES-CMAC(DHUK) KDF working; three-way PIN-attempt consumption (MCU page 124 + OPTIGA E120 LUC + SE050 silicon UserID) and the 10-wrong-PIN brick/admin-wipe flow were validated end-to-end. Boot reconciliation has the narrower directional scope stated in invariant #2. On-chain caps: `MAX_BOOTSTRAP_USES = MAX_SLOT_USES = 65,536` (≈ 2^32 txns/chain). **Per-KEY margin, stated honestly (corrected 2026-07-26):** slot keys are chain-bound, so 65,536 is a true per-key cap (birthday floor 96 b). The **bootstrap key is chain-INDEPENDENT** (invariant #6 requires it for cross-chain address stability), so its per-key budget across `C` chains is `C x 65,536`, NOT 65,536 — its generic-multi-target floor degrades as `96 - 2*log2(C)` (94 b at 2 chains, 88 b at 16). This is the documented P14 caveat (`Quantitative.lean` P14 + `advantage_floor_within_bootstrap_cap_crosschain`); realistic bootstrap usage is tens of signatures (slot rotations only), so practical exposure is far below the cap. Firmware is **stateless w.r.t. slot selection** — companion supplies `(chain_id, slot_index, flags)` on every sign. Page 123 durably tracks each slot's off-chain count, reconciled UserOp count, generated UserOp-signature tally, and registration state.

**Shipping model (owner decision 2026-07-14 — work-todo #36).** The factory flashes the firmware and retains responsibility for SE-internal irreversible provisioning/lockdown on per-device *transport* keysets — S-1/S-2/S-3 metadata/object preparation, UserID/LUC, attestation objects, and the eventual OPTIGA lifecycle ratchets — then ships at **RDP-0** so anyone can verify flash + option bytes + OTP over SWD (connect-under-reset, **before first power**) against the reproducible build. On the **first field boot** the device self-locks to RDP-2 (only then is the per-die DHUK final), performs the BHK first write, and replaces the transport credentials before entering the seed wizard. The `rdp2-self-lock` candidate now implements the device-side journaled flow: transport→BHK-rooted SE050 SCP03/admin rotation and transport→persisted-TRNG-salted DHUK OPTIGA PBS rotation. That code is implementation evidence, not a production-approved ceremony. A batch-uniform/erased shipping image still lacks the reviewed authenticated per-unit factory handoff/receipt, authenticate-before-rotate contract, atomic durable old/new/KVN recovery proof, selected E140 lifecycle order, and silicon receipts. No migration protocol or irreversible ordering is authorized by this summary. There is **no factory/fixture RDP-2 burn** and no factory-held final pairing secret.

**Trusted-display clear-signing.** Every signable artifact is decoded and rendered inside the secure world before the user presses confirm — no blind-sign path for known shapes. (1) **Safe transactions:** the EIP-712 `SafeTx` typed-data hash is verified in S-world (`secure/src/tx/eip712/safe/`) and the inner `to/value/data/operation` is decoded locally — ERC-20 transfers and Safe owner/threshold/module/guard changes render on the LCD with full parameters; the companion never gets to substitute a hash. Safe `multiSend` batches (selector `0x8d80ff0a`, the shape the Safe web UI emits for anything multi-step) clear-sign per record: `operation=1` (DELEGATECALL) is accepted ONLY against the three pinned canonical `MultiSendCallOnly` deployments, the packed records are strictly decoded (`secure/src/tx/eip712/safe/multi_send.rs` — per-record op==0, ≤6 records, exact framing) and each record routes through the same inner ladder (ERC-20 / ETH / Safe-mgmt / CoW / loud per-record blind) with divider pages; any rule violation or page-budget overflow refuses to sign — a DELEGATECALL is never blind-signed. (`operation=0` calls to a MultiSend address stay loud blind-sign — under CALL the Safe isn't msg.sender for the records.) (2) **CoW Swap orders:** the EIP-712 `GPv2Order` is verified in S-world (`secure/src/tx/eip712/cowswap/`) and the order payload is decoded **on-device** — token name/symbol/decimals come from the firmware-pinned `ERC20_DB_ROOT` (the same Merkle root the ERC-20 transfer path uses), so the user sees the exact intent (e.g. `SELL 0.2 USDC for at least 0.0004 WETH`) rather than a 32-byte digest. ERC-7730 clear-sign descriptors and the typed-call ABI parser are likewise pure on-device decoders; incomplete registry-known formats are hard refusals. (3) **Safe-wrapped CoW orders:** when a SafeTx's inner call is CowSwap `GPv2Settlement.setPreSignature(orderUid, true)` — directly, or as a record inside an allowlisted `MultiSendCallOnly` batch (the Safe UI's actual `[approve(vault relayer), setPreSignature]` shape) — the same CoW v3 pipeline verifies the order bound to the presign calldata (the *record's* bytes for multiSend) with `orderUid.owner == the Safe` (not the wallet `sender`), and the render combines Safe context (banner, address, nonce, refund pages) with the full order intent — unmistakably "a CoW order for this specific Safe". One binding resolver (`secure/src/tx/eip712/safe/cow_binding.rs`) and the shared `cowswap_display::append_order_body_pages` keep all flows code-identical; see `docs/companion/companion-safe-cowswap-presign.md` (single-call + the folded-in multiSend-batch section).

**Scope of the clear-signing guarantee:** “no blind-sign path for known shapes” above applies to the structured on-chain and typed-data dispatchers. Explicit EIP-1271 `RAW32` is a separate, loudly-labelled blind off-chain tier; it is not a semantic fallback for a typed-data request. **Forced blind is likewise not clear signing.** If the default-off `erc7730-forced-blind` feature is implemented and enabled, only cleanly absent metadata for an exact member of the separately authenticated refused-known set `F = K \ C`, in the enumerated single steady-state Type-2 case for a slot already registered by the normal Type-1 rotation path, may enter its separate on-device ceremony. A tuple in the firmware's accepted clear set `C` either clear-signs or fatal-refuses: descriptor omission cannot downgrade it, and any present descriptor's validation, binding, or render failure is fatal. ERC-8176 may support catalogue admission into `C`; it grants no runtime signing authority and no semantic claim to forced raw pages. Feature-off and rollback behavior remain hard refusal, and all independent production-configuration, trusted-UI/FI, resource, provenance, rollback, and release gates remain required.

## Non-Negotiable Invariants

Production contract — every shipping build must respect ALL. Pre-production may temporarily violate one (note in next section).

1. **Dual-chip seed split.** BIP-39 entropy is XOR-split: `half_O` on OPTIGA, `half_E` on SE050. Neither chip alone reveals any bit. Never store full entropy on one chip or transmit a half across.
2. **Hardware PIN gating; three-way per-attempt consumption, directional boot cross-check.** PIN comparison stays in SE silicon. `gated_unlock` precharges MCU page 124; an ordinary wrong-PIN attempt then advances OPTIGA E120 and the SE050 UserID. Page 124 and SE050 enforce the user-facing 10-attempt bound; E120 is a separate 32-lifetime-attempt anti-extraction backstop. At boot firmware can read page 124 and E120 and wipes when `E120_used > page124_used`; an MCU lead is a conservatively charged power-cut/transport-error state. The production SE050 UserID policy denies attempt-attribute reads (`SW=0x6986`), so SE050 is not a boot-reconciliation input; `AuthMethodBlocked` still maps to `PinLocked` and the wipe path. Do not claim three-way boot reconciliation. Making that property genuinely three-way requires a separately reviewed SE050 policy/backend and silicon decision.
3. **E2E encrypted SE tunnels.** OPTIGA Shielded Connection uses TLS-PRF + AES-128-CCM-8; SE050 SCP03 uses AES-CMAC + AES-CBC. No plaintext secret crosses I2C. The `rdp2-self-lock` candidate contains the journaled transport→final device-side rotation: SE050 SCP03/admin move to the BHK axis, while OPTIGA PBS moves to a DHUK derivation bound to a persisted fresh-TRNG salt. Page 126 is exclusively the DHUK-wrapped SE050 BHK; page 127 owns the first-boot journal and salt. Production remains blocked until the authenticated per-unit factory handoff/receipt, authenticate-before-rotate rule, atomic durable old/new/KVN recovery adequacy, E140 ordering, and silicon evidence are reviewed and closed. The ML-KEM-1024 inner wrap was DESCOPED 2026-07-07 (owner decision, do not re-raise — see work-todo #9): both tunnels are symmetric-rooted (no Shor material on the bus), so the accepted residual is Grover-2⁶⁴ (Cat-1) key search against physically-tapped sessions; consequence: per-device final rotation is load-bearing for this acceptance.
4. **All secrets only in TrustZone secure world.** NS never sees PIN, entropy, signing key, or derived secret. NSC gateway returns opaque non-secret data. Validate NS pointers and copy NS buffers to S-stack before parse (TOCTOU).
5. **One signing primitive: SPHINCS+C10.** Both Type 1 (bootstrap → slot registration) and Type 2 (slot → user tx). No FORS+C, no classical signer (secp256k1, P-256, Ed25519). Wallet has a single `c10Verifier`. Host-only `dbgen` may verify externally mandated ERC-8176 EAS/secp256k1 signatures solely to admit catalogue inputs; its production verifier holds no signing key, creates no wallet/FW-update/on-chain authority, and is fenced by `make classical-crypto-boundary`.
6. **Bootstrap C10 keys immutable per-wallet (launch invariant).** CREATE2 salt depends only on `(masterPkSeed, masterPkRoot)`; rotating changes the address. No `rotateMasterKeys` and no ownership model that could introduce one.
7. **Per-chain caps monotonic, unresettable.** `bootstrapUses < 65,536`, `slotUses[i] + offchainSigCount[i] < 65,536`. No `reset*` or `increaseMax*` path. Exhausted chains stay frozen.
8. **Stateless slot selection.** Companion supplies `(chain_id, slot_index, flags)` on every sign. No flash slot store, no recovery state machine in S-world. Slot keys re-derived on demand and cached in SRAM only.
9. **Off-chain sig counter, combined cap.** Firmware tracks `local_offchain_count` + `last_userop_count` per slot in flash page 123 (log-structured, 16 B/increment, compaction). Refuses to sign past `MAX_OFFCHAIN_GAP = 100` unbacked sigs or past the combined cap. Post-restore, `CMD_SIGN_OFFCHAIN` for an unregistered slot is rejected — forces a Type 1 rotation via `CMD_SIGN_USEROP` first. The forced-blind steady Type-2 branch enforces the same registration prerequisite and cannot create registration through its tally write.
10. **Verify-once-physically trust chain (owner decision 2026-07-21).** The device's entire post-sale trust story is: (a) ship at RDP-0 so anyone can verify flash + option bytes (including staged WRP) + OTP over SWD, connect-under-reset **before first power**, against the reproducible build; (b) the verified image contains an FSBL whose pages are WRP-protected and which measures the active firmware slots and renders the 8-word fingerprint at boot; (c) first field boot self-locks to RDP-2, which freezes the option bytes forever — WRP on the FSBL range becomes physically permanent, so **no firmware update can ever modify, unprotect, or bypass the measuring code**; (d) from then on the boot-time fingerprint is proof of what is installed — the user never has to trust a firmware update again. Consequences that bind every future change: no runtime write path (fw_update or otherwise) may touch the FSBL range; the WRP-set → RDP-2 ordering is mandatory (RDP-2 with unprotected FSBL pages permanently forfeits the guarantee for that die); the FSBL must own the display for its fingerprint window (a later fake screen is the accepted residual — the *boot-time* window is the anchor, keep it visually distinctive); and the shipping image must actually flash the FSBL in the slot layout (monolithic builds are bench-only). Currently OPEN gates before this invariant is claimable: FSBL geometry (Draft 1.1 pages 0..4), both-bank WRP/option-byte ceremony, non-monolithic shipping image, FI-hardened FSBL image verify (EF-swarm F15), silicon receipts.

## Pre-Production Caveats

No devices shipped, no funds on-chain — domain tags / parameters are still renamable pre-launch. Known acceptable regressions:

- **⚠️ SHIP BLOCKERS — OPTIGA shipping-state lockdown (S-1, S-2, S-3 — all three required before any device leaves the bench).** S-1 is the unclosed F1D0 authorization/lifecycle ceremony: the candidate metadata uses `Auto(F1D0)`, but its irreversible ordering and silicon receipt are not production-approved. S-2 is the still-open type-`0x11` Protected-Update pool `{0xE0E8,0xE0E9,0xE0EF}` plus the device-certificate retype boundary. The observed `0xE0E3` is already a full type-`0x12` device certificate; the retired public-sample helper targeting it is a mis-targeted no-op, not the live anchor path. S-3 requires `optiga-hw-counter` and its production evidence. Compile-time fences prevent these candidates from masquerading as shipping closure: `OPTIGA_S2_PRODUCTION_BLOCKED` rejects every `mode-production + optiga-trust-m` build while S-2 is open, the retained helper emits no APDU, and the irreversible experimental feature pair is deliberately unbuildable. Ordinary pairing also never ratchets E140; that factory-side action remains OPEN relative to final credential rotation. **Owners:** GitHub issues [`label:ship-blocker`](https://github.com/EthereumPhone/PQ1/issues?q=label%3Aship-blocker) (production-todo retired 2026-07-19; original "OPTIGA Trust M V3 — LcsO transitions" at `docs/archive/production-todo-retired-2026-07-19.md`) and `docs/STATUS.md` §A. The SE-side blockers **S-5/S-6/S-7 are RESOLVED 2026-05-28** (`docs/security/security-review-2026-05.md` §§C-7/C-8/C-9 = Fixed); S-7d's on-silicon `VERIFY` status mapping is resolved as `0x6986` and recorded in `docs/STATUS.md`. The OPTIGA bring-up state is acceptable ONLY because nothing has shipped.

- **TZSC config (invariant #4):** regressed then fixed; enforcement **and** USB-coexistence **silicon-validated 2026-05-20** (`make gtzc-enforcement-hw` → 7/7 secure peripherals RAZ-fault on NS access; device still enumerates `1209:7051` over USB-C). `secure/src/sau.rs` wires `GTZC1_TZSC_SECCFGR{1,3}` (AHB2 AES/HASH/RNG/PKA/SAES + I2C1/2 SECURE; OTG stays NS). Only TAMP (in GTZC2) remains as a follow-up.
- **Debug instrumentation may ship in this branch.** `debug-log` allowed on hardware, `secure_log!` in the wizard, NS pre-USB register dumps, DHCSR-gated semihosting prints in `hw::hash::init_clock`. CI must still gate production on `debug-log` / `e2e-test` / `mock-se` OFF.
- **Domain tags are sticky-but-renamable.** Tag `"sphincs-c6-v1"` is historical (was a different parameter set when written; now C10). Don't rename mid-bring-up (re-provisions every bench board); coordinated cleanup pre-launch is fine.

When a task touches an invariant-adjacent subsystem (TZSC allowlist, gateway surface, SE provisioning, key derivation), respect the invariant. Pure bring-up wiring (clocks, GPIO, peripheral-init order) prioritises lighting up; note any regression here.

## Lifecycle

Boot → legacy bench FSBL verify slots + render 8-word fingerprint on the NV3007 LCD (~3 s; see `docs/security/measured-boot.md`) → branch into active slot → SAU/GTZC → SAES self-test → SE attest → PIN entry (S-world trusted UI) → unlock both SEs → reconstruct entropy in S-SRAM → active signing window (120 s idle timeout, S-only TIM; NS pings do NOT reset it) → zeroize on lock/tamper/brownout/inactivity. Treating the FSBL as an immutable production trust root remains contingent on the approved geometry, WRP/option-byte ceremony, production link/resource gates, and silicon receipts.

The FSBL fingerprint and the secure-world `measured_boot::run` screen show the SAME 8 words for the same active slot (both derived via `sphincs_tz_bip39::firmware_fingerprint_lines`). In the current bench implementation the FSBL row is the earlier measurement and the secure-world row is advisory; neither establishes production immutability. After the FSBL geometry/WRP/factory/silicon gates close, the FSBL row is intended to become the immutable trust root. Honest-row divergence is a strong defect/tamper signal.

**Sign dispatch** (`cmd_sign_userop.rs`, companion-driven; successful Type-2 releases are durably tallied on page 123):

```
parse {chain_id, flags{INCLUDE_INIT_CODE | REGISTER_SLOT | account_index | slot_index}, header, inner_tx}
  deploy:   INCLUDE_INIT_CODE, slot=0, !REGISTER_SLOT
            factory registers slot 0; emit initCode + Type-2 only
  rotation: REGISTER_SLOT, slot>=1, !INCLUDE_INIT_CODE
            emit bootstrap Type-1 + slot Type-2 (nonce base+1)
  normal:   neither flag; emit Type-2 only
  before release: durably commit the successful Type-2 tally
```

`SLOT_CACHE` in SRAM is keyed on `(account_index, chain_id, slot_index)` — slot keys are chain-bound, so a cross-chain hop at the same slot triggers a fresh <1 s keygen.

## Gateway Commands

`pqsigner_proto::CMD_*` is the source of truth (mirrored in `shared::CMD_*`).

| CMD | Name | Purpose |
|-----|------|---------|
| 1 | GET_REMAINING | min over MCU count + runtime SE-driver remaining-attempt mirrors; not a boot-reconciliation receipt |
| 2 | REQUEST_UNLOCK | trusted-UI PIN entry → `gated_unlock` |
| 7 | SIGN_USEROP | unified Type 1/Type 2 sign; flags drive `INCLUDE_INIT_CODE` and `REGISTER_SLOT` |
| 11 | IS_UNLOCKED | 1/0 |
| 12 | LOCK | zeroize cached secrets |
| 14 | GET_WALLET_ADDRESS | CREATE2-predicted ERC-1967 proxy address (<1 s on first call after unlock for master keygen, < 1 ms cached) |
| 15 | GET_INIT_CODE | pre-compute the 4280-B `initCode` for `(account_index, chain_id)` (companion gas-estimation) |
| 16 | SIGN_OFFCHAIN | EIP-1271 / ERC-6492 sig (4016 B deployed, 8616 B counterfactual via `flags` byte); refuses if slot unregistered (deployed path), gap ≥ `MAX_OFFCHAIN_GAP` (100), or combined cap exceeded |
| 17 | OFFCHAIN_STATUS | per-slot `(local_offchain_count, last_userop_count, registered)` |
| 20–24 | FW_BEGIN/CHUNK/COMMIT/STATUS/ABORT | streaming firmware update (PIN unlock required on every call) |
| 30 | SIGN_USEROP_BATCH | atomic multi-UserOp sign with single user confirm |
| 200 | TEST_PIN_LOCKOUT | E2E-only — burns a wrong-PIN cycle; compiled out of production |

CMDs 3, 5, 8, 9, 10, 13 are reserved in `proto` but not currently dispatched.

On STM32U585, NSC uses real CMSE `cmse-nonsecure-entry` veneers; on QEMU it's a shared-memory mailbox.

## Wire formats (frozen — on-chain verifier depends on them)

### Unified sign input (NSC + USB)

```
offset  size  field
  0     8    chain_id (u64 BE)
  8     4    flags (u32 BE: bit 31 INCLUDE_INIT_CODE, bit 30 REGISTER_SLOT,
                              bits 29..22 account_index (8b, 0..=255),
                              bits 21..0  slot_index    (22b))
 12    20    sender (PQSmartWallet address)
 32    20    entry_point (EntryPoint v0.6 address)
 52    32    nonce (u256 BE, base nonce for first UserOp in bundle)
 84   5x32   call_gas_limit, verification_gas_limit, pre_verification_gas,
             max_fee_per_gas, max_priority_fee_per_gas (u256 BE each)
244    32    paymaster_and_data_hash (sha256, SHA256_EMPTY when none)
276    20    to_address (inner tx recipient)
296    32    value (u256 BE)
328     2    data_len (u16 BE, 0..=4096)
330     N    data
```

### Unified sign output

```
[new_offchain_count(8 BE)]
[init_code_len(4 BE)][init_code...]      ← 4280 B when FLAG_INCLUDE_INIT_CODE, else 0
[type1_len(4 BE)][type1_wrapper...]      ← 4128 B when FLAG_REGISTER_SLOT, else 0
[type2_len(4 BE)][type2_wrapper...]      ← always 4128 B
```

`new_offchain_count` is the per-slot `local_offchain_count` baked into the Type 2 calldata via `executeWithOffchainCount(...)`. `type{1,2}_wrapper = abi.encode(uint256 ownerIndex, bytes c10Sig)`. `OWNER_BYTES_LEN = 64`, `C10_SIG_LEN = 4008`.

### Off-chain (EIP-1271 / ERC-6492) output

Input header is 17 B (`account(1) | chain(8) | slot(4) | kind(1) | payload_len(2) | flags(1)`); the new `flags` byte at offset 16 carries the EIP-6492 `account_deployed` bit (bit 0). The companion picks the bit by `eth_getCode`-ing the predicted CREATE2 address before calling.

- **`account_deployed = 1` (wallet on-chain):** firmware returns 4016 B = `[new_local_offchain_count(8 BE)][C10 sig (4008)]` — byte-identical to pre-EIP-6492 builds. Companion wraps as `abi.encode(uint256 ownerIndex, bytes c10Sig)` and the dapp calls `wallet.isValidSignature(rawHash, wrappedSig)`.
- **`account_deployed = 0` (counterfactual):** firmware returns 8616 B = `[new_local_offchain_count(8 BE)][ERC-6492 blob(8608)]`. The blob is `abi.encode(address factory, bytes factoryCalldata, bytes signatureWrapper) || EIP6492_MAGIC` (`0x6492…6492`, 32 B). `factory = PQ_SMART_WALLET_FACTORY`, `factoryCalldata = initCode[20..]` (i.e. the exact deploy bytes whose hash is baked into the CREATE2 address), and `signatureWrapper = abi.encode(1, c10Sig)` (ownerIndex 1 = slot 0). The dapp routes the blob through any EIP-6492-aware verifier (Solady `SignatureCheckerLib.isValidERC6492SignatureNow`, Ambire `UniversalSigValidator`, viem `verifyMessage`) which deploys-then-verifies in one `eth_call`. Constraints: `slot_index` MUST be `0` (the factory only seeds slot 0 at deploy); slot 0 is auto-registered (`local=last=0`) on the first counterfactual call to a never-used wallet.

In both modes the wallet recomputes `replaySafeHash(rawHash)` (Solady-nested EIP-712: `(name="PQSmartWallet", version="1", chainId, address(this))`) and verifies. **The firmware — never the companion — performs this `replaySafeHash` nesting, for every off-chain kind.** For `kind = RAW32` the companion sends the dapp's *raw* hash `H` (the value it passes to `isValidSignature`) and the firmware nests it via `aa::eip1271::replay_safe_hash` before signing; for `kind = PERSONAL_SIGN`/`EIP712_TYPED` the firmware likewise nests in S-world. This is a security invariant, not a convenience: the on-chain Type-1/Type-2 UserOp path verifies a *bare* slot/bootstrap C10 sig over a SHA-256 `sphincsDigest`, so a firmware that bare-signed a companion-chosen 32-byte value would be a UserOp-forgery oracle (`raw32(sphincsDigest(drainOp))` → valid Type-2 sig → drain behind a blind page). On-device keccak nesting keeps every off-chain signed value computationally separated from any `sphincsDigest` — equal images would require a keccak-256/SHA-256 cross-preimage (Lean discharges via `keccak_sha256_cross_separation`, an explicit `… ∨ BreaksHash` cross-function assumption, not a structural impossibility) (fixed 2026-06-11; was the pre-fix RAW32 design where the companion pre-nested).

`RAW32` remains intentionally opaque: replay-safe nesting prevents the UserOp-forgery oracle, but it cannot prove how a dapp obtained `H`. A hostile companion can submit the final hash of otherwise-supported typed data as `RAW32` and suppress its semantic pages; the device therefore shows `! BLIND RAW32` plus the complete hash. Companions MUST preserve the dapp-requested method and MUST NOT downgrade typed data to `RAW32`. Disabling `RAW32` in production remains the preferred policy unless an explicit compatibility decision accepts this residual.

### On-chain validation

`PQSmartWallet.validateUserOp` ABI-decodes `SignatureWrapper(uint256 ownerIndex, bytes signatureData)`:

- `ownerIndex == 0` (Type 1): check `bootstrapUses < MAX_BOOTSTRAP_USES`, verify bootstrap C10 sig over `userOpHash`, install slot pubkey at the wrapper's `ownerIndex`, bump `bootstrapUses`, emit `BootstrapKeyUsed`.
- `ownerIndex >= 1` (Type 2): check combined cap `slotUses[i] + offchainSigCount[i] < MAX_SLOT_USES`, verify slot C10 sig, bump `slotUses[i]`, emit `SlotKeyUsed`. The slot's `executeWithOffchainCount(ownerIndex, newOffchainCount, target, value, data)` runs in execution phase: monotonic update of `offchainSigCount[i]` (re-checks cap belt-and-braces) then dispatches the user's call. Does **not** bump `bootstrapUses`.
- `wallet.isValidSignature(hash, sig)` (EIP-1271): `view`-only, nests via Solady EIP-712, dispatches to the same C10 verifier. Returns `0x1626ba7e` / `0xffffffff`. No counter bump. Bootstrap key (`ownerIndex == 0`) **forbidden** here.

## Recovery / Key derivation

One seed → 256 wallets via `account_index ∈ [0, 255]`. Account 0 reproduces the pre-multi-account derivation byte-for-byte.

```
bip39_seed = PBKDF2-HMAC-SHA512(BIP-39(entropy_256), salt="mnemonic", iters=2048)   // 64 B

# Bootstrap master (SPHINCS+C10)
account_index == 0:  master = HMAC-SHA512("sphincs-c6-v1", bip39_seed)
account_index  > 0:  master = HMAC-SHA512("sphincs-c6-v1-acct", bip39_seed || account_index_be4)
masterSkSeed = sha256("sk_seed" || master[..32])
masterPkSeed = sha256("pk_seed" || master[..32]) & N_MASK   // top 16 B kept, bottom 16 zero
(masterSk, masterPkRoot) = c10::keygen(masterSkSeed, masterPkSeed[..16])

# Slot master entropy
account_index == 0:  slot_master = sha256("pqwallet-slot-master" || bip39_seed)
account_index  > 0:  slot_master = sha256("pqwallet-slot-master-acct" || bip39_seed || account_index_be4)

# Per-slot derivation (chain-bound, post-Coinbase-port: slot keys differ per chain)
slot_entropy   = sha256(slot_master || "slot_entropy" || chain_id_be8 || slot_index_be4)
slot_r         = sha256(slot_master || "slot_r"        || chain_id_be8 || slot_index_be4)
slot_sk_seed   = sha256("slot_c10_sk_seed" || slot_entropy)
slot_pk_seed   = sha256("slot_c10_pk_seed" || slot_entropy) & N_MASK
(slotSk, slotPkRoot) = c10::keygen(slot_sk_seed, slot_pk_seed[..16])

# On-chain wallet address (same on every chain, given account_index)
salt = sha256(masterPkSeed || masterPkRoot)            // we control the preimage
addr = CREATE2(factory, salt, keccak256(initCode))     // EVM hashes with keccak256
```

The `"sphincs-c6-v1"` tag is historical (was a different parameter set when written; now C10). **Do not rename mid-bring-up.**

## Build and Test

```bash
make play                    # interactive QEMU (arrow-key UI)
make run                     # non-interactive smoke (QEMU, mock SE)
make e2e                     # automated unified-sign e2e (QEMU)
make e2e-hw                  # e2e on real STM32U585 via probe-rs (see HW gotcha)
make play-hw-display         # interactive NV3007 LCD + arrow-key forwarding
make test-key-speed          # DWT-timed signing bench (no semihosting reads)
make measure                 # build + print 8 BIP-39 measurement words
make saes-self-test-hw       # SAES driver: SW + DHUK round-trip + fingerprint
make optiga-hw-counter-e2e   # provision E120 LUC + drive PIN cycles
make pin-gate-hw-counter-e2e # three-way per-attempt + in-run recovery; no reboot/reconcile coverage
make pin-gate-wipe-e2e       # 10 wrong PINs → assert factory-reset on both SEs
make wipe-for-wizard         # dev-only: wipe both SEs + page 124, halt; cold boot enters wizard
cd contracts/smart-wallet && forge test -vv
cargo test -p sphincs-tz-secure --tests --release
```

**Board targets (`BOARD=`).** Every hardware target builds for one of two physical boards. `BOARD=iota2` (**default**) is the ST B-U585I-IOT02A dev kit, STM32U585AII6 / 169-pin — what every bench flow has always assumed. `BOARD=pq1` is the AL_A66_MB_V10 production board, STM32U585CIU6 / 48-pin UFQFPN, which **bonds only PA0–15, PB0–15 and PC13** (no port D/E/…, and no PB11). `BOARD` sets both the cargo feature and the probe-rs chip name (`STM32U585AIIx` / `STM32U585CIUx`) — e.g. `make test-key-speed BOARD=pq1`. The pin maps live one-per-board in `secure/src/board/{iota2,pq1}.rs` and drivers read constants from there rather than hard-coding a port base.

**Naming a board is MANDATORY on every `stm32u585` build** — `secure/src/board/mod.rs` hard-errors when neither feature is set, and when both are. The earlier "opt-in to pq1, `board-iota2` is inert" model was retracted 2026-08-31: `#[cfg(feature = "board-pq1")] compile_error!` fences are *silent* when the feature is absent, so a recipe that omitted the board compiled the iota2 pin map with every pq1 fence quiet — which is how `build-hw-prodtest BOARD=pq1` came to put iota2 pins on pq1 silicon. `BOARD_FEATURE`/`CHIP` are `override`-derived from `BOARD` so they cannot be detached from each other, and a `FEATURES` board that disagrees with `BOARD` is a hard error.

**Ported:** debug console UART (iota2 USART1/PA9 → pq1 USART2/PA2, AF7 both); the secure-element path (OPTIGA keeps I2C1/PB8/PB9/AF4, SE050 moves to its own **I2C4 on PB6/PB7 AF5** — `board::SE_I2C_BUSES` is the bus *set*, so `i2c_hw` keeps a single `pub fn init`; OPTIGA reset PE0 → PA15; new `hw::se_power` asserts pq1's `LDO2_EN` (PA8) + `SE1_EN` (PB5) before any bus traffic); buttons; USB (pq1 hands only PA11/PA12 to NS — never PA15/PB5/PB15, which are `SE_RST`/`SE1_EN`/`LCM_EN` there); the OPTIGA reset *pulse* (`reset_pin::hard_pulse`, because the live path `pin_diag::run` hardcoded PA4/PD5/PE0 and would have strobed pq1's display CS); the SCA scope trigger (PD2 → PB3); and the **NV3007 LCD** — `spi_hw` + `lcd_nv3007` now derive every pin, the peripheral base and the AF number from `board::LCD_*`. pq1's panel is SPI1 on **PA4 (CS) / PA5 (SCK) / PA7 (MOSI)**, non-contiguous, below pin 8 (so AF nibbles are in `AFRL`, not `AFRH`) and with **no MISO** — PA6, the MISO position, is `NC` on the board. DC/RST/TE/backlight are PB0/PB1/PB2/PB15; pq1 gets a real hardware reset pulse where iota2 uses `SWRESET` (`board::LCD_RST_IS_DRIVABLE`).

`sau.rs` secures I2C4 (SECCFGR1 bit 16) on pq1, plus **UCPD1 (bit 19)** and **TIM2 (bit 0)** on both boards, under exact-equality `const assert!` arms. UCPD1 matters because it is a second handle on PA15/PB15 that `GPIOx_SECCFGR` does not cover; TIM2 because NS could otherwise clear `TIM2_CR1.CEN` and flat-line the production-mandatory consumption mask.

The **consumption mask** is ported too: pq1 runs it on **TIM3_CH1 / PA6 / AF2** because every TIM2_CH1 pin is taken there (PA0 `LEFT KEY`, PA5 the LCD `SCK`, PA15 `SE_RST`), and `sau.rs` secures TIM3 alongside TIM2 so NS cannot stop either. A `selftest_pin_toggles()` samples `IDR` to catch an AF number that is right for the peripheral but wrong for the pin — it passed on pq1 silicon. **What that does NOT establish:** neither board drives a load from the mask pin (iota2's PA5 is unclaimed, pq1's PA6 is `NC`), and a randomised *duty* only modulates power across a resistive load, so the mask's actual dilution is unmeasured on both — see `evt-silicon-validation.md` §9. Production forces this feature, so pq1 can now *build* a shipping image while that security property remains unevidenced; treat the fence as satisfied-by-construction, not demonstrated.

**Still iota2-only, each a loud `compile_error!` rather than a runtime trap:** `boot-pulse` (hardcodes PE13) and `pin-diag-boot` (sweeps the Arduino header and drives PA8 = pq1's SE rail enable). See `docs/hardware/evt-silicon-validation.md` §1–§2 for the verified as-built map. **Trap:** PA8 is the RIGHT button on iota2 and `LDO2_EN` — the enable for the rail powering *both* secure elements — on pq1.

**`make help`** lists the runnable top-level targets (self-documented from the `Makefile`, so it never drifts); **`make -C contracts/verification help`** lists the FV / spec-assurance gates (`verify-*`). The root `Makefile` has ~160 targets total — `make help` surfaces the ones you actually run; read the file for the build/flash variants, fsbl, release packaging, and optiga-reset internals it doesn't surface.

**HW probe-rs gotcha.** `probe-rs` does not implement semihosting `0x07 SYS_READC`. Any `ui-semihosting` PIN prompt on real silicon hangs in the polling loop with a storm of `Target wanted to run semihosting operation 0x7 ...` warnings. This hits `make e2e-hw` because the NS test driver still calls `CMD_REQUEST_UNLOCK` even when `e2e-test` pre-unlocks the secure side. QEMU is unaffected. Workarounds: `make test-key-speed` (no reads, prints `=== PASS ===`) or `make play-hw-display` (arrow keys via probe-rs `print` handshake).

**Expected timings on hardware** (with `hw-sha256`, auto under `stm32u585`): first-sign ≤ 3 s (master keygen + slot keygen + 2 signs); Type-2-only on cached slot ≈ 1.1 s; second-chain first-sign with cached slot ≈ 2.5 s. Substantially higher = HASH peripheral isn't being used.

**HW SHA-256 self-test.** `hw::hash::init_clock()` runs a `SHA-256("abc")` KAT. Look for `[S] hash: HW SHA-256 self-test PASS` early in boot — `FAIL — HALT` parks the CPU in `loop { wfe() }`.

**Targets / profile.** `thumbv8m.main-none-eabi` for both worlds. Release: `opt-level = "s"`, LTO, `codegen-units = 1`, `overflow-checks = true`. `sphincs-c10` / `sha2` / `hmac` always `opt-level = 3`.

## Feature flags

`secure/Cargo.toml` has ~50 flags. Active vocabulary:

- **Backend (mutually exclusive at top level):** `mock-se` · `optiga-trust-m` · `se050` · `dual-se` (implies optiga + se050). (The standalone TROPIC01 backend was removed 2026-07-14 — owner decision; dual-SE only.)
- **Platform / UI:** `stm32u585` (real hardware, implies `hw-sha256`) vs QEMU default. UI: `ui-semihosting` · `ui-lcd` (NV3007 SPI LCD — the only shipping display; the SSD1306 `ui-oled` backend was removed 2026-06-30) · `ui-noop` (silent for headless USB).
- **Mode profiles** (axis aliases): `mode-production` (no debug-log/e2e-test/mock-se) · `mode-bringup` (`debug-log`) · `mode-e2e` (`debug-log`+`e2e-test`+skip flags) · `mode-bench`.
- **Hardening / accelerators (compose):** `saes-dhuk` (Tier-1 KDF) · `saes-self-test` · `tamp` (Trezor-port; log-only by itself) · `tamp-wipe` (production escalation — fires `tzic::trigger_intrusion_wipe` on a confirmed tamper; default-off for bench safety, **forced ON for shipping dual-SE images** by the `nsc/mod.rs` ship-blocker fence alongside `tzic-wipe`) · `consumption-mask` (TIM2 CH1 PWM on PA5; caller must call `randomize()` periodically) · `usb`.
- **OPTIGA hardware counter:** `optiga-hw-counter` (E120 LUC bound to F1D0; immune to PBS extraction; **destructive on first provisioning** — rewrites F1D0 metadata).
- **First-boot self-lock candidate (work-todo #36):** `rdp2-self-lock` (implies `bhk`; **production-only**, forced ON for `mode-production` by the `nsc/mod.rs` S-1-style fence, incompatible with every dev/test feature, requires `dual-se`). Owns the candidate on-device flow in `secure/src/first_boot/`: Phase A verifies the ship option-byte profile + blank per-device pages 123–127 then programs RDP=0xCC (irreversible), Phase B journals a resumable BHK first-write + transport→final rotation of SE050 SCP03/admin + OPTIGA PBS. Absent from every bench/QEMU build (behaviour OFF is byte-identical). Compile-check: `make build-rdp2-self-lock`. This is not production authority; the handoff/recovery/E140-order/silicon gates above remain open. Refs: `docs/provisioning/first-boot-provisioning.md` (candidate responsibility split + field error codes + silicon runbook).
- **Dev / test (NEVER ship):** `debug-log` · `e2e-test` (fixed mnemonic + PIN, short-circuits every secure-side `confirm()`/`enter_pin()`) · `otp-hardcoded-master-key` (fixed ASCII OTP-master so re-flashed bench boards keep stable admin/SCP03/PBS bytes) · `ui-capture` (SHA-256 of every displayed frame).

CI must gate shipped firmware on `debug-log` / `e2e-test` / `mock-se` / `otp-hardcoded-master-key` / `ui-capture` OFF. The `compile_error!` fences in `nsc/mod.rs` and the `saes-self-test` runner enforce most of this.

## Code Conventions

- `#![no_std]`, no heap, no allocator. Stack-only. No `Vec` / `Box` / `String`.
- `zeroize::ZeroizeOnDrop` on every secret type with compiler fences.
- `subtle` for constant-time compares. No secret-dependent branches.
- Every `unsafe` block has a `// SAFETY:` comment. `#![deny(unsafe_op_in_unsafe_fn)]`, `#![warn(clippy::pedantic)]`.
- **`unsafe` taxonomy.** Five categories that are structurally required and one that is not. **Required:** (1) CMSE `unsafe extern "C"` veneers (TrustZone ABI); (2) NS pointer deref after `NsPtr<T>` validation in `secure/src/nsc/*` — and the same NS-pointer window-check + volatile-copy primitives extracted verbatim into `shared/src/ns_ptr_validate.rs` so they are Kani-proven + Miri-checked host-side (re-exported by `nsc/{ns_ptr,ptr_validate}.rs`); (3) `unsafe extern "C"` SHA-256 hooks consumed by `sphincs-c10` under `hw-sha256`; (4) FI volatile read/write helpers in `secure/src/fi.rs` — plus the FI stack-canary `read_volatile`/`write_volatile` in `pqsigner-erc7730/src/display/render/mod.rs` and double-render transcript-poison writes in `pqsigner-erc7730/src/display/mod.rs` that rode into the host crate with the render dispatch (all must stay `read_volatile`/`write_volatile` to defeat compiler folding; a `black_box` or ordinary-store swap is a silent FI-weakening); (5) `static mut` bookkeeping for the HASH peripheral's 4-byte merge buffer and similar single-threaded driver state. The `.semgrep` `no-unsafe-in-pure-logic-crates` gate excludes exactly those three host-relocated files (allowlist asserted by `make invariant-gates`); any *new* `unsafe` in a pure-logic crate is still a hard error. **Avoidable:** ad-hoc per-register MMIO `read_volatile`/`write_volatile` — funnel each peripheral's registers through `hw::mmio::{Reg32, RoReg32}`, which encapsulates the unsafe once at the address-binding step. UI/log code that materialises ASCII-by-construction buffers must use `crate::ui::ascii_str` rather than `core::str::from_utf8_unchecked`.
- NS pointer validation on every gateway call before any deref. NS buffers copied to S-stack before parse.
- Cross-world types in `shared/src/lib.rs` with `#[repr(C)]`.
- Secret types are `!Copy + !Clone`.
- FI-hardened signing on every Type 1 / Type 2 sig — `crypto::c10_sign_verified*` is a **double-compute → byte-compare → verify-before-release** chain (RFC 9814 §A.2 / Genêt TCHES 2023): sign twice over identical inputs, constant-time-compare the two 4008-B signatures (the *redundant-recomputation* countermeasure — verify-after-sign **alone is insufficient** against SPHINCS+ grafting faults, since a random faulted sig is more likely to still verify than to fail), then verify-before-release, all under an `fi::CfiCounter` 7-step gate with F-2 Hamming-distant sentinels, F-16 DPA shuffle, and fresh 3-source OptRand. Do **not** weaken this to verify-only (a known-insufficient FI gate).

## Key File Map

Pure-logic primitives live in standalone workspace crates so host signers / bench tooling can reuse them without secure-world hardware deps. Secure-side files at the same names are thin re-export shims.

### Workspace crates (pure logic)
| Path | Purpose |
|------|---------|
| `proto/src/lib.rs` | `pqsigner-proto` — protocol constants + enums + wire sizes. Source of truth for Solidity `PqsignerProto` (via `xtask gen-solidity-constants`). Zero deps. |
| `tx-core/src/{eip1559,hash,rlp}.rs` | RLP, EIP-1559 envelope, U256, keccak256. |
| `aa/src/{userop,eip1271}.rs` | EntryPoint v0.6 UserOp hash + Solady-nested EIP-712 PersonalSign. |
| `domain/src/lib.rs` | KDF, AES-GCM wrap, BIP-39 → C10 derivation, slot derivation. |
| `tx/src/{erc20,names,selectors}/` | Merkle-bundle verifiers + ERC-20 calldata decoder. `verify_*_bundle` takes `root: &[u8;32]`. |
| `hal/src/lib.rs` | Trait surface (`Rng`, `Sha256`, `Saes`, `Flash`, `Otp`, `Tamp`, `ConsumptionMask`, `I2cBus`, `SpiBus`, `Buttons`, `Uart`, `Platform`, `BootStage`). Driver impls deferred. |
| `shared/src/lib.rs` | Cross-world `#[repr(C)]` types, `NscStatus`, CMD constants. |
| `sphincs-c10/` | C10 signing — `SigningKey::keygen/sign`, `verify`, hypertree, wots, fors, merkle, address, hash, params. |
| `bip39/` | 24-word English BIP-39 (no_std). |
| `pqsigner-erc7730/src/{ir,walker,bundle,binding,abi}.rs` | ERC-7730 clear-signing — IR parser, path walker, Merkle bundle verifier, `(chain_id, contract, ds)` binding cross-checks. Host-runnable; firmware re-exports via `secure/src/tx/erc7730.rs`. |
| `pqsigner-erc7730/src/display/{mod,primitives}.rs` + `display/render/{mod,formatters,intent,nested,calldata_nested}.rs` | Shared display substrate (`Pages`/`MAX_PAGES`/`ascii_str` + byte-writer primitives) **and the full ERC-7730 renderer** (intent banner + 15 FormatOp dispatchers + nested-EIP-712/calldata descent) — moved here 2026-07-04 so the render dispatch is host-linkable/fuzzable/Kani-provable. |
| `pqsigner-erc7730/src/render/{params,visibility,resolve,array,enums}.rs` | TLV parameter parser, visibility evaluator (`should_render_with_mode`), path/offset resolvers — the Kani-proven pure half of the renderer. |

### Secure world
| Path | Purpose |
|------|---------|
| `secure/src/main.rs` | Entry: SAU → RCC → SAES self-test → provision → unlock → boot NS. |
| `secure/src/sau.rs` | SAU + GTZC config (TZSC enforcement silicon-validated 2026-05-20; only TAMP/GTZC2 follow-up open — see Pre-Production Caveats). |
| `secure/src/crypto.rs` | Re-export shim over `pqsigner-domain` + FI-hardened `c10_sign_verified*` + `WalletStore`-bound `provision_from_mnemonic` / `store_macd_encrypted`. |
| `secure/src/aa/mod.rs` | Re-export shim over `pqsigner-aa`. |
| `secure/src/tx/mod.rs` | Re-export shim over `pqsigner-tx-core` + display + EIP-712. |
| `secure/src/tx/display/*` | Trusted-UI page renderers (value transfer, ERC-20 known/unknown, contract creation, slot rotation, blind sign, batch, EIP-1271, Safe, typed_call). |
| `secure/src/tx/display/erc7730/mod.rs` | Re-export shim over `pqsigner_erc7730::display::render` (the renderer moved to the host crate 2026-07-04; `pick_sign_pages` stays in `tx/display/mod.rs` and calls the host entry). |
| `secure/src/tx/display/erc8213.rs` | ERC-8213 fingerprint pages (2-page banner + full 32-byte hash). |
| `secure/src/tx/erc7730_render/mod.rs` | Re-export shim over `pqsigner_erc7730::render` (params/visibility/resolve/array/enums + `RenderErr`). |
| `secure/src/tx/erc7730.rs` | Re-export shim over `pqsigner-erc7730` + the firmware-pinned `ERC7730_DESCRIPTORS_ROOT`. |
| `secure/src/tx/eip712/{cowswap,safe}/` | EIP-712 typed-data verifiers (test vectors + verify). |
| `secure/src/tx/typed_call/{abi,parser}.rs` | Solidity ABI typed-call parser. |
| `secure/src/{erc20,names,selectors}/mod.rs` | Re-export shims over `pqsigner-tx`; pass `crate::db_roots::*`. |
| `secure/src/db_roots.rs` | Compiled-in Merkle roots for trust-bundles. |
| `secure/src/fi.rs` | FI helpers: sentinel patterns + double-checked verify. |
| `secure/src/timeout.rs` | S-only TIM-driven inactivity timeout (NS pings do NOT reset). |
| `secure/src/offchain_state.rs` | Page-123 log-structured per-slot off-chain counter store + compaction. |
| `secure/src/dual_se.rs` | XOR entropy split; admin-wipe coordination. |
| `secure/src/measured_boot.rs` | Boot SHA-256 → 8 BIP-39 words on the NV3007 LCD. |
| `secure/src/fw_update/{staging,verify}.rs` | Streaming state machine BEGIN → CHUNK* → COMMIT. |

### NSC gateway
| Path | Purpose |
|------|---------|
| `secure/src/nsc/mod.rs` | Dispatcher + `gated_unlock` (page-124 attempt counter, FI-hardened pre-commit). |
| `secure/src/nsc/state.rs` | `SecureState` singleton: `pin_verified`, `master_secret`, `SLOT_CACHE` keyed on `slot_index`. |
| `secure/src/nsc/cmd_sign_userop.rs` | **Unified Type 1 / Type 2 sign handler** (1241 lines). |
| `secure/src/nsc/cmd_sign_userop_batch.rs` | Atomic multi-UserOp sign (766 lines). |
| `secure/src/nsc/cmd_sign_offchain.rs` | EIP-1271 sig + per-slot off-chain counter bump. |
| `secure/src/nsc/cmd_offchain_status.rs` | Per-slot counter readback. |
| `secure/src/nsc/cmd_request_unlock.rs` | PIN entry + dual-SE unlock. |
| `secure/src/nsc/cmd_get_wallet_address.rs` | CREATE2-predicted proxy address. |
| `secure/src/nsc/cmd_get_init_code.rs` | Pre-computed 4280-B `initCode`. |
| `secure/src/nsc/cmd_fw_*.rs` | Five firmware-update handlers. |
| `secure/src/nsc/cmd_test_pin_lockout.rs` | E2E-only wrong-PIN burner. |
| `secure/src/nsc/{ptr_validate,ns_ptr}.rs` | NS pointer validation; `NsPtr<T>` typestate yielding `ReadPtr<T>` / `WritePtr<T>` proofs. |

### Secure elements
| Path | Purpose |
|------|---------|
| `secure/src/optiga/{mod,ifx_i2c,apdu,shield,i2c}.rs` | OPTIGA Trust M driver (4-layer IFX I2C + Shielded Connection). OIDs: `0xE140` PBS, `0xE120` LUC, `0xF1D0` AuthRef, `0xF1D1` half_O, `0xF1D2` master, `0xF1D3` VK, `0xF1D4` bootstrap VK. E120 binding under `optiga-hw-counter`. |
| `secure/src/se050/{mod,scp03,apdu,t1oi2c,i2c}.rs` | SE050 driver (T=1' + SCP03 + UserID PIN). Admin UserID `max_attempts=0`; current OID range `0x7B0C_*`. |

### UI / hardware drivers
| Path | Purpose |
|------|---------|
| `secure/src/ui/{mod,lcd,semihosting,noop,capture,confirm,pin_entry,seed_wizard,secret_text}.rs` | `pub trait Ui` + backends (`lcd` = NV3007; the SSD1306 `oled` + RTT `mirror` backends were removed 2026-06-30). `confirm`/`pin_entry`/`seed_wizard` are the trusted-path dialogs. |
| `secure/src/hw/mmio.rs` | Typed `Reg32`/`RoReg32` MMIO handles. Encapsulates `unsafe { read_volatile/write_volatile }` once per address so peripheral drivers expose safe `.read()`/`.write()`/`.modify()` APIs. |
| `secure/src/hw/hash.rs` | STM32U585 HASH peripheral; `pqsigner_sha256_*` extern fns consumed by `sphincs-c10` under `hw-sha256`. Uses `mmio` for register access. |
| `secure/src/hw/saes.rs` | SAES driver (AES-256-ECB) under `KEYSEL ∈ {Software, DHUK, BHK, DHUK^BHK}`. |
| `secure/src/hw/saes_cmac.rs` | `cmac_dhuk(msg) -> tag` thin SAES adaptor. |
| `secure/src/hw/secret_keys.rs` | Current per-purpose key API. Factory transport SCP03/admin/PBS credentials derive from the factory-burned per-device OTP master. The candidate final OPTIGA PBS derives from DHUK plus the persisted TRNG salt; final SE050 SCP03/admin credentials derive from BHK. Explicit dev/legacy configurations use hardcoded or deterministic fallback roots. The first-boot implementation remains production-quarantined pending its named handoff, recovery, silicon, and ordering gates. |
| `secure/src/hw/otp.rs` | Rejected legacy unary rollback tally (bench-only, production-fenced) + device-master/factory legacy OTP regions. Draft 1.1 is a research candidate for the replacement typed floor API; its implementation, physical codec, ECC, interruption, and durability gates remain open. |
| `secure/src/hw/flash.rs` | Bank-2 writes, ICACHE invalidate, `pin_attempts_{read,bump,reset}` on page 124, admin-page (125) wipe-flag. |
| `secure/src/hw/tamp.rs` | TAMP (Trezor-port). Log-only by default; under `tamp-wipe` (production) escalates to `tzic::trigger_intrusion_wipe`. |
| `secure/src/hw/consumption_mask.rs` | TIM2 CH1 PWM on PA5, randomised duty cycle. |
| `secure/src/hw/uart.rs` | USART1 VCP (GPIOA AF7), used by SAES RDP1 self-test + dev logging. |
| `secure/src/hw/boot_state.rs` | Legacy try-once page (nonfunctional for the promised rollback contract and production-fenced). Draft 1.1 proposes replacement marker/journal interfaces but is not implementation-approved. |
| `secure/src/hw/{rcc,rng,usb_hw,buttons,spi,spi_hw,i2c,i2c_hw,i2c2_probe}.rs` | Bare-metal peripheral drivers. |

### Non-secure world / host tools
| Path | Purpose |
|------|---------|
| `nonsecure/src/main.rs` | NS entry (USB or interactive demo). |
| `nonsecure/src/nsc_api.rs` | NS-side gateway caller. |
| `nonsecure/src/usb/{commands,hid,transport}.rs` | APDU v2 router + USB HID. |
| `nonsecure/src/e2e_test.rs` | Non-interactive end-to-end test runner. |
| `fwmeasure/` | Host firmware measurement tool. |
| `fw-manifest/` | Legacy v0x02/PQFW_V1 manifest + verify chain (bench only). Draft 1.1 proposes manifest-v6/`PQFW_V6` with a 121-byte signed preimage; it is neither implemented nor implementation-approved. |
| `fwsign/` | Legacy bench release-signing CLI; production packaging is quarantined pending candidate approval and backend closure. |
| `fsbl/` | Legacy bench bootloader. It is not yet an immutable production trust root. Draft 1.1 keeps a 40-KiB candidate envelope; the physical FLASH LOAD-span, WRP/option-byte ceremony, and independent RAM/worst-case-stack gates remain OPEN. |
| `dbgen/` | Merkle-DB builder (ERC-20 / names / selectors / ERC-7730 descriptor roots). |
| `xtask/` | Host workspace tooling — codegen, doc-checks, release packaging. |
| `tools/webhid_test.html`, `tools/wallet_run_hw.py` | Browser companion + probe-rs arrow-key forwarder. |

### Contracts
| Path | Purpose |
|------|---------|
| `contracts/smart-wallet/src/PQSmartWallet.sol` | ERC-4337 v0.6 account behind ERC-1967 proxy; `validateUserOp` dispatches on `ownerIndex`. EIP-1271 via Solady (nested EIP-712, ERC-6492). |
| `contracts/smart-wallet/src/PQSmartWalletFactory.sol` | CREATE2 factory; `createAccount` requires bootstrap C10 sig over `addSlot0Digest(chainId, slot0PkSeed, slot0PkRoot)` (squat-defence). |
| `contracts/smart-wallet/src/PQMultiOwnable.sol` | ERC-7201 storage: `ownerAtIndex`, `bootstrapUses`, `slotUses[i]`, `offchainSigCount[i]` + bumps. |
| `contracts/smart-wallet/src/verifiers/SPHINCsC10Asm.sol` | Stateless Yul C10 verifier (SHA-256 precompile). Single immutable reused for Type 1 / Type 2 / EIP-1271. |
| `contracts/smart-wallet/src/verifiers/ISPHINCSVerifier.sol` | Verifier interface (test/prod swap). |

## What NOT to do

- **No classical signer** anywhere — firmware, contract, FW-update path. One algorithm in the wallet, one in the FSBL. No "just-in-case" fallback.
- **No secrets in NS world.** Not even temporarily.
- **No software PIN compare** — SE silicon only.
- **No plaintext secrets on I2C / SPI** — always Shielded Connection / SCP03 / Noise_KK1.
- **No full entropy on a single chip** — each SE gets one XOR half.
- **No heap.** Stack only. No `Vec` / `Box` / `String`.
- **No software PRNG** — hardware TRNG (STM32 TRNG / semihosting `/dev/urandom` on QEMU).
- **No casual KDF tag changes** (`"sphincs-c6-v1"`, `"sphincs-c6-v1-acct"`, `"pk_seed"`, `"sk_seed"`, `"pqwallet-slot-master"`, `"pqwallet-slot-master-acct"`, `"slot_entropy"`, `"slot_r"`, `"slot_c10_sk_seed"`, `"slot_c10_pk_seed"`). Account 0 must keep the original tags for cross-developer reproducibility.
- **No skipping verify-before-release** on Type 1 / Type 2 sigs.
- **No `rotateMasterKeys` / `resetBootstrapUses` / `resetSlotUses` / `increaseMax*`** in wallet or factory.
- **No EntryPoint v0.7 / v0.8 migration.** v0.6 is the frozen target. Its address and ABI are baked into `initCode`, the userOpHash preimage, and the factory; bumping the version would change the CREATE2 init-code hash and break invariant #6 (cross-chain address stability). If v0.6 bundlers are ever sunset, fall back to direct EOA-bundled execution against the same wallet — do not redeploy.
- **No new per-signature flash state** beyond the page-123 EIP-1271 counter.
- **NS does not control the inactivity timer** — only S-world button presses on confirm dialogs reset it.
- **No `debug-log` / `e2e-test` / `mock-se` / `otp-hardcoded-master-key` / `ui-capture` / `legacy-fw-rollback-unsafe`** in production builds. CI must gate.
- **Rollback manifest work is not implementation-approved.** Draft 0.9's V4/80-byte format is a preserved historical reference. Draft 1.1 proposes the exact 121-byte `PQFW_V6 || schema || physical_slot || release_version || security_epoch || secure_image_length || nonsecure_image_length || secure_image_hash || nonsecure_image_hash || vendor_key_fingerprint` preimage, but remains a research/review candidate with open backend, resource, ECC, release-policy, and silicon gates. Do not treat either layout as current implementation authority. Adoption or any schema change requires an exact approved specification digest, the required dual review, and an owner stage decision.
- **No "reset rollback floor" path.** OTP is one-way by design.
- **No runtime writes to the eventual approved FSBL range.** The current
  pages-0..3/32-KiB layout is legacy bench-only; Draft 1.1 proposes pages 0..4
  but leaves geometry, both-bank protection, factory, and silicon gates open.

## External review models (adversarial review / planning / advisory)

Two **non-Claude** models are wired on this box and may be used freely for **adversarial review, design
critique, planning, and advisory** roles — especially on FV/crypto-modeling decisions, before committing to a
multi-session approach, and as a second opinion on any claim you are about to bank as fact.

| Model | How to invoke | Notes |
|-------|---------------|-------|
| **GPT-5.6** | `mcp__codex__codex` MCP tool — pass `prompt`, `cwd`, `sandbox: "read-only"`, `approval-policy: "never"` | Agent with repo access; reads files itself. Long reviews get backgrounded (>120 s) and notify on completion. |
| **Kimi K3** | CLI: `export PATH="$HOME/.kimi-code/bin:$PATH"; kimi -p "<prompt>"` (run from the target repo) | **NOT an MCP.** `--auto`, `--yolo`, and `--plan` are each INCOMPATIBLE with `-p` (hard error). Agent with repo access; verbose — redirect to a file and read the tail. Very long runs: use `run_in_background`. |

**How to use them well** (learned 2026-07-19, when they jointly killed an unsound EasyCrypt reduction design
before it cost multiple sessions):

- Give them the **file paths and line numbers** and tell them explicitly to *read the actual code, not trust
  your summary* — their value comes from checking your framing against source.
- Ask them to **attack a specific decision**, state the failure mode you most fear, and demand a prioritized
  list of holes + a recommended action + "where is my read too optimistic". Vague "review this" wastes them.
- Say **"do not modify any file"** (both are agents and will edit if allowed), then `git status` afterwards.
- **Run both and compare.** Convergence on a disqualifier is strong evidence; divergence is where the real
  information is (in the 2026-07-19 review both found the same fatal flaw, but only one found the better fix,
  and only the other found the deeper foundations problem).
- **Verify their load-bearing citations yourself** before acting — treat their output as a lead, not a fact.

The `advisor` tool (stronger Claude reviewer, sees the full transcript) is complementary: use it for
calibration/honesty-of-claims and approach selection; use GPT-5.6 / Kimi K3 when you need an *independent*
model to check domain reasoning against the source.

## Work tracking

Action tracking lives on **GitHub Issues** (repo `EthereumPhone/PQ1`). `docs/work-todo.md` and `docs/production-todo.md` were retired 2026-07-19: their open items were migrated to issues labelled `source:work-todo` / `source:production-todo` (plus `priority:*`, `surface:*`, `ship-blocker`), and the full pre-migration content is archived at `docs/archive/work-todo-retired-2026-07-19.md` and `docs/archive/production-todo-retired-2026-07-19.md`. After completing implementation tasks, close the matching issue with the evidence (commit, tests, receipts) in the close comment. Historical `work-todo #N` / section references in this and other docs resolve through the archive copy.

**Docs hygiene — amend, don't duplicate.** Before creating a new doc, `grep`/`find` over `docs/` + `contracts/verification/docs/` (and the "Deep-dive docs" list below) for one that already covers the topic and update *that* instead. This repo has many overlapping docs (`STATUS.md`, `FV_VALUE_AND_GAPS.md`, `THE_CLAIM.md`, the `docs/*-sota-*.md` surveys, per-subsystem status/postmortem files), and a parallel new doc almost always duplicates an existing one and drifts stale. Prefer additive dated `UPDATE <date>` notes + a snapshot-date bump over rewriting (preserves the honest history the FV docs depend on). Create a new doc only when no existing one fits the scope.

## Deep-dive docs

- `README.md` — full architecture, threat model, shipping checklist
- `docs/architecture/architecture.md`, `docs/security/HARDENING.md`, `docs/firmware/firmware-update.md`, `docs/firmware/reproducible-builds.md`
- `docs/secure-elements/se050-userid-pin-auth.md`, `docs/secure-elements/optiga-bringup-status.md`, `docs/secure-elements/optiga-brick-postmortem.md`
- `docs/companion/companion-app-integration.md`, `docs/companion/companion-batch-sign-integration.md`, `docs/companion/usb-protocol-v2.md`
- `docs/archive/handoff-modularity-refactor.md` — workspace-crate extraction phases
- `docs/archive/handoff-unsafe-reduction.md` — per-peripheral migration of MMIO `read_volatile`/`write_volatile` to `hw::mmio::{Reg32, RoReg32}`; queue + footguns + irreducible categories
- `docs/hardware/dev-board-setup.md`, `docs/hardware/hardware_requirements.md`, `docs/architecture/trezor-comparison.md`
- `docs/secure-elements/se050-stress-harness.md` — `make se050-stress*` on-silicon stress runner; how to run, read output, add a test, and the S-5/S-6 silicon verifiers
