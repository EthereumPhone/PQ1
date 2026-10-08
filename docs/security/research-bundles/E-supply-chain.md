# Research Prompt E — Supply Chain and Provisioning Attestation

## Research question

Map the supply-chain + provisioning threat model for a hardware wallet
using SE050 + OPTIGA on TrustZone STM32U585, shipping through
conventional retail / e-commerce, and recommend a provisioning +
attestation protocol that defeats each attacker class.

Specifically:

1. Counterfeit STM32U5 supply in 2024-2025: are there confirmed
   clones (GD32/CS32/APM32 style) in the U5 family yet, or only
   older F/L-series? What boot-time probes reliably detect clones?
2. NXP's SE050 UID cert chain up to NXP root CA: how reliable for
   anti-clone? Threat model for SE050 extraction + re-implantation
   in a different physical wallet.
3. Same question for OPTIGA Trust M cert chain.
4. What do Ledger, Trezor, Coinkite, Foundation etc. do at
   provisioning to attest "genuine factory-sealed device" to a
   customer opening the box? Known failure modes (historical + 2024-
   2025).
5. Given our dual-SE architecture, is there an additional attestation
   advantage from cross-binding SE050-UID + OPTIGA-UID + STM32-UID
   in a signed manifest that must match at every boot?

Deliverables: ranked attacker list (opportunistic re-seller;
sophisticated interdictor; nation-state with factory access), the
attestation protocol that defeats each, and a specific "box-opening"
user ceremony that demonstrates genuineness without requiring the
customer to run an independent tool.


---

## Project context (condensed; current sources are linked in each bundle)

**What this is.** PQSigner OS: a post-quantum ERC-4337 smart-wallet
firmware for STM32U585 (Cortex-M33 + ARM TrustZone) on the
B-U585I-IOT02A Discovery board. Only external interface is USB-C. No
Bluetooth, no UART, no debug access in production (RDP Level 2
planned).

**Secure elements.** **Dual**-SE architecture, not single:
- **NXP SE050** (I2C1, addr `0x48`, EAL6+): stores `half_E` of XOR-
  split BIP-39 entropy. Hardware PIN gate via UserID (10 attempts).
- **Infineon OPTIGA Trust M V3** (I2C1, addr `0x30`, EAL6+): stores
  `half_O`. Shielded Connection (AES-128-CCM-8) for bus encryption.

Both chips are mandatory. Neither alone reveals any bit of the seed —
only `half_O XOR half_E = entropy`.

**Why signing must run on the Cortex-M33, not the SE.** Bootstrap and
slot signatures both use the project's **SPHINCS+C10** hash-based
post-quantum scheme; there is no classical or ML-DSA signer. No
commercial secure element currently computes it. The SEs are gated
storage, not signing accelerators. The seed
therefore transits STM32 secure-world SRAM during the active signing
window (~120 s idle timeout, then zeroize). TrustZone SAU+GTZC isolates
this from the non-secure world.

**TrustZone partition.** Secure world (flash bank 1, SRAM1) owns all
crypto, PIN, persistent secrets, transaction decoding, and the trusted
NV3007 LCD UI. Non-secure world owns USB transport. Crossings go through
the fixed NSC gateway with pointer validation and TOCTOU-safe copy-in.

**Power supervision state.** BOR, PVD, ECC (except SRAM1 which is
always-on), IWDG all at factory defaults. Stage 1 of a 5-stage brownout
roadmap added reset-cause classification + verified flash writes; the
rest is planned. `make stm32-harden-opts` is a one-time option-byte
setup target (sets BOR3 + SRAM2_RST=0) but has not been run yet. See
`docs/security/brownout-hardening.md` for the full plan.

**VBAT.** Production hardware uses a **0.47 F supercap** (not a
battery) on VBAT via Schottky from Vdd. Bounded retention (~12-24 h
after unplug). The dev board has an unpopulated CR1220 holder whose
pads can be reused for a tack-soldered supercap during validation.
Indefinite-retention tamper monitoring during long cold storage is
explicitly out of scope — the 24-word BIP-39 backup is the long-term
security anchor.

**Accepted trade-offs (research that contradicts these is not useful):**
1. Seed transits STM32 SRAM during signing. Unavoidable until SE can
   do SLH-DSA.
2. SE050's value is hardware PIN gate + XOR storage, not "seed never
   leaves silicon." Don't suggest "do all signing on SE050" — it
   can't.
3. USB-C is the only external interface.
4. Out of scope: EAL6+ invasive decapping attacks.

**Dark Skippy and similar nonce-exfil attacks do NOT apply.** Hash-
based SLH-DSA has no nonce. Don't chase this.

**Current SCP03 lifecycle.** The SE050 SCP03 channel is active (every TX
has CLA=0x84). Factory defaults are not an acceptable production state:
the factory transport credentials are derived from the per-device OTP master
burned for that handoff. After RDP2 self-lock and the BHK first write, the
implemented first-field candidate rotates SE050 SCP03/admin credentials to
the final BHK axis and rotates the OPTIGA E140 PBS to the final DHUK derivation
bound to a fresh TRNG salt persisted in the page-127 journal. Page 126 holds
only the DHUK-wrapped BHK. This candidate is not a production-approved
ceremony: authenticated per-unit handoff and authenticate-before-rotate,
durable old/new/KVN recovery, the exact E140 lifecycle-versus-final-rotation
order, and silicon receipts remain OPEN.

---

## Style guidance

- Cite specific RM0456 / AN5342 / ES0499 / UM11225 / Infineon doc
  sections where possible. Prefer "per AN5342" over inventing
  revision numbers you aren't sure of.
- Say "I don't know" on things not answerable from public sources,
  rather than guessing.
- Give concrete, implementable code / register values — hand-wave
  recommendations without specifics are not useful.
- Respect the architecture above. Suggestions that require signing
  on the SE are category errors for this project.

---


## Relevant design docs (code footprint small — feature not implemented)


### From `CLAUDE.md`

# PQSigner OS — LLM Context

> **Agent process entry point:** Claude Code loads this file directly. Before
> non-trivial work, read [`AGENTS.md`](../../../AGENTS.md), which routes current status,
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
10. **Verify-once-physically trust chain (owner decision 2026-07-21).** The device's entire post-sale trust story is: (a) ship at RDP-0 so anyone can verify flash + option bytes (including staged WRP) + OTP over SWD, connect-under-reset **before first power**, against the reproducible build; (b) the verified image contains an FSBL whose pages are WRP-protected and which measures the active firmware slots and renders the 8-word fingerprint at boot; (c) first field boot self-locks to RDP-2, which freezes the option bytes forever — WRP on the FSBL range becomes physically permanent, so **no firmware update can ever modify, unprotect, or bypass the measuring code**; (d) from then on the boot-time fingerprint is proof of what is installed — the user never has to trust a firmware update again. Consequences that bind every future change: no runtime write path (fw_update or otherwise) may touch the FSBL range; the WRP-set → RDP-2 ordering is mandatory (RDP-2 with unprotected FSBL pages permanently forfeits the guarantee for that die); the FSBL must own the display for its fingerprint window (a later fake screen is the accepted residual — the *boot-time* window is the anchor, keep it visually distinctive); and the shipping image must actually flash the FSBL in the slot layout (monolithic builds are bench-only). Currently OPEN gates before this invariant is claimable: geometry MIGRATION (the frozen registry — pages 0..4, 40,960 B, `FSBL_MAX_LOAD_SPAN` 38,912 — landed as the `pqsigner-geometry` crate (FA-1.1) and is CI-pinned, but the bench **linker is still 32 KiB** and the image occupies pages 0..3, so the cutover is outstanding: issue #540. `make fsbl` reports the derived range, and adopting 40 KiB before the cutover would freeze page 4 while empty. **UPDATE 2026-10-05:** at the `opt-level = "z"` release profile the FSBL span dropped to **19,708 B** and the image now fits **3** pages, so `make fsbl` reports that the declared 4-page range would freeze page 3 while empty — the same class of waste as the page-4 note, one page earlier), both-bank WRP/option-byte ceremony, non-monolithic shipping image, FI-hardened FSBL image verify (EF-swarm F15), silicon receipts. **Geometry MEASUREMENT is closed** (2026-09-01, `scripts/check_fsbl_geometry.py`, run by `make fsbl`): the gate reads the physical LOAD span from the program headers rather than `size -B` text+data (which undercounts by any inter-segment gap — 28,704 vs 28,700 when that was written; 19,708 at `z`, see above), fails on more than one LOAD segment, on a start address that is not the boot base, and on a span that exceeds the region, and **derives the WRP page range from the image instead of assuming it**. Stack is bounded rather than closed: `-Z emit-stack-sizes` gives 50 frames totalling 10,372 B of 16,384 B (the tz-1 tripwire, #366, added two frames and 352 B of flash), and since no acyclic path can exceed the sum of all frames that is a genuine upper bound — subject to the stated caveats (no recursion, functions that emit no frame, interrupt frames on top). A call-graph worst case still needs `cargo-call-stack`.

## Pre-Production Caveats

No devices shipped, no funds on-chain — domain tags / parameters are still renamable pre-launch. Known acceptable regressions:

- **⚠️ SHIP BLOCKERS — OPTIGA shipping-state lockdown (S-1, S-2, S-3 — all three required before any device leaves the bench).** S-1 is the unclosed F1D0 authorization/lifecycle ceremony: the candidate metadata uses `Auto(F1D0)`, but its irreversible ordering and silicon receipt are not production-approved. S-2 is the still-open type-`0x11` Protected-Update pool `{0xE0E8,0xE0E9,0xE0EF}` plus the device-certificate retype boundary. The observed `0xE0E3` is already a full type-`0x12` device certificate; the retired public-sample helper targeting it is a mis-targeted no-op, not the live anchor path. S-3 requires `optiga-hw-counter` and its production evidence. Compile-time fences prevent these candidates from masquerading as shipping closure: `OPTIGA_S2_PRODUCTION_BLOCKED` rejects every `mode-production + optiga-trust-m` build while S-2 is open, the retained helper emits no APDU, and the irreversible experimental feature pair is deliberately unbuildable. Ordinary pairing also never ratchets E140; that factory-side action remains OPEN relative to final credential rotation. **Owners:** GitHub issues [`label:ship-blocker`](https://github.com/EthereumPhone/PQ1/issues?q=label%3Aship-blocker) (production-todo retired 2026-07-19; original "OPTIGA Trust M V3 — LcsO transitions" at `docs/archive/production-todo-retired-2026-07-19.md`) and `docs/STATUS.md` §A. The SE-side blockers **S-5/S-6/S-7 are RESOLVED 2026-05-28** (`docs/security/security-review-2026-05.md` §§C-7/C-8/C-9 = Fixed); S-7d's on-silicon `VERIFY` status mapping is resolved as `0x6986` and recorded in `docs/STATUS.md`. The OPTIGA bring-up state is acceptable ONLY because nothing has shipped.

- **TZSC config (invariant #4):** regressed then fixed; enforcement **and** USB-coexistence **silicon-validated 2026-05-20** (`make gtzc-enforcement-hw` → 7/7 secure peripherals RAZ-fault on NS access; device still enumerates `1209:7051` over USB-C). `secure/src/sau.rs` wires `GTZC1_TZSC_SECCFGR{1,3}` (AHB2 AES/HASH/RNG/PKA/SAES + I2C1/2 SECURE; OTG stays NS). Only TAMP (in GTZC2) remains as a follow-up.
- **Debug instrumentation may ship in this branch.** `debug-log` allowed on hardware, `secure_log!` in the wizard, NS pre-USB register dumps, DHCSR-gated semihosting prints in `hw::hash::init_clock`. CI must still gate production on `debug-log` / `e2e-test` / `mock-se` OFF.
- **Pixel trusted-UI pilot (`ui-px`, owner decision 2026-09-22).** Under `ui-px` every sign dialog (Safe, single-UserOp, rotation, direct CoW, ERC-7730, off-chain, batch — port plan steps 1-3; `forced_blind` excepted) renders as PQ-UI design screens (`pqsigner-ui-px` crate, `secure/src/ui/px/`, `docs/ui/pixel-ui-pilot.md`) and arms the sign gesture (the two-button chord click — both down together, fires on release; hold-right is a no-op, hold-left declines; owner decision 2026-09-22 on the EVT) on the opening ask / `Confirm?` / returning ask per PQ-UI `DESIGN.md` § Input. **Scroll-to-end is ON (owner decision 2026-09-24, `PX_COMMIT_REQUIRES_SEEN_LAST = true`), superseding the 2026-09-22 decision to reverse it:** the chord arms only after the LAST screen has actually been painted, matching the legacy 16×4 dialogs and the 2026-06-26 gate. An ERC-20 transfer is 8 screens with the recipient on 3 and the amount on 4, so signing from the opening ask approved a destination and value that had never been displayed. `fsbl-tests/tests/paired_constants.rs` pins the two paths together. See `docs/security/HARDENING.md` §2.4. Do not re-litigate without new evidence. **Atlas in the NS slot (owner decision 2026-09-23, port plan § Flash):** the glyph atlas + marks (`nonsecure/assets/ui-px/atlas.pq1a`, 74 KB, NS feature `ui-px-atlas`) live at a fixed offset of the FSBL-measured NS flash slot, never in the secure image; the secure image pins their SHA-256 (`secure/src/ui/px/atlas_root.rs`, generated by `make ui-px-assets`) and `ui::px::assets` re-hashes the window before AND after every pixel dialog plus once more in the sign handler before release — a swapped glyph is a refusal, never a signature (a wrong font is a WYSIWYS input). Trailers are native screens (`tx/display/trailer_screens.rs`, one per proven trailer page, derived from the same page builders, per-slot + set proofs); no `Legacy` record exists on any pixel sign route. **Budget, re-measured 2026-10-05** (`make size-report-px BOARD=pq1`; physical span cross-checked against `readelf -l` LOAD, which is the method `check_fsbl_geometry.py` uses — `size` text+data undercounts by any inter-segment gap). Against the 466,944 B v6 secure slot (`geometry::SECURE_SLOT_SPAN`):

| build | span | vs slot |
|---|---:|---:|
| no `ui-px` (today's shipping shape) | 431,680 B | fits, 35,264 B spare |
| + `ui-px`, `opt-level = "s"` | 545,504 B | **78,560 B OVER** |
| + `ui-px`, secure `opt-level = "z"` | 481,376 B | **14,432 B over** (current setting) |
| + `ui-px`, everything `"z"` | 475,648 B | 8,704 B over — rejected on frame time, see below |

`z` on the non-UI firmware recovered 64,128 B — 82% of the gap — with no code deleted and no family dropped; crypto stays at opt-level 3 so signing throughput is untouched. **Frame time is NOT fenced off and is unmeasured at `z`:** `pqsigner-ui-px` stays at `"s"`, but the per-frame work is split and the slower half is in `sphincs-tz-secure`, which moved to `z` — `ui::px::lcd::{present_frame_ex, blit_strip}` is the measured 24 ms blit, while the raster left at `"s"` is only 8-11 ms. **FRAME TIME MEASURED ON THE PANEL 2026-10-05** (EVT screen unit, `ui-px-bench` + `ui-px-frametime` at 40 MHz `ui-px-spi40`, worst-case per second, render/blit/period ms): `pqsigner-ui-px` at `z` gives **15/20/36**, at `s` **11/19/31**. The whole difference is in RENDER (−4 ms, −27%) — that crate is the rasteriser; the blit is the SPI stream and does not move. `z` there cost ~4 ms against a **16 ms** pacing target for 5,984 B, so **it is reverted to `"s"`**; the parent profile stays at `z` and keeps its 64,128 B. **Neither setting meets the frame target** (31 ms ≈ 32 fps against `FRAME_PERIOD_MS` = 16 ms, `ui/px/lcd.rs:47` — i.e. roughly 2x over, not the 29% an earlier version of this line implied), and that is NOT an opt-level problem: see the SPI note below. **CORRECTION 2026-10-06:** this entry previously called 24 ms "the budget". That was a measured nine-strip blit COST (`ui/px/lcd.rs:62`) mislabelled as a target; `docs/ui/pixel-ui-pilot.md` states it correctly — "frame period ≈ 24 ms (≈ 40 fps; **the 16 ms cap never binds**)". Related: the 19-20 ms blit figures below are PARTIAL repaints — a full 428x142 panel at 40 MHz has a 24.31 ms wire floor, so no full repaint can read below it, and the full-panel blit has never actually been measured. **Security re-verified at `z`** (2026-10-05): `make checkct` proves kdf/fors/th/saes/ct_eq all `secure` on thumbv8m with the by-design-insecure fisher_yates control still firing (so non-vacuous) — and `tools/sca/checkct/Cargo.toml` deliberately MIRRORS the root `opt-level`, so it had to move to `z` too or the proof would have certified codegen the device does not ship; `make check-checkct-profile` now binds the pair. The FI double-compute is intact (`c10_sign_verified_with_progress_inner` still has 2 `sign_with_shuffle` calls + 2 FI verified-checks, same as at `s`), and the opt-level-3 crypto (sphincs-c10, sha2) is byte-identical across s/z. Caveat on the apparent FI-check drop elsewhere: `z` enables LLVM's MachineOutliner, which factors identical FI call sequences into `OUTLINED_FUNCTION_*` helpers (5 helpers hold 1 FI call each and are invoked 39 times), so STATIC FI call-site counts are not a valid metric at `z`. The FSBL is pinned back to `"s"`, but only ~756 B of its 8,996 B change reverted — a per-package override does not reach its dependencies — so the trust root is still largely `z` and its 18/18 silicon boot proof and the 10,372-B stack bound were both taken at all-`s` and have NOT been re-taken. **Why `ui-px` costs 113,824 B at `"s"`:** .text +103,584 / .rodata +9,472 — 91% is code, and the shared `tx::display` decode/classify modules actually SHRANK 1,482 B, so the decode logic is not the cost. Two presentation stacks coexist: for erc7730/userop/cow/offchain/trailer the pixel emitter ADAPTS the 16×4 painter's `Pages` (`erc7730_screens.rs` records that the in-renderer `Screens` sink was dropped so the audited renderer stays untouched), `safe_screens`/`batch_screens` are native, and `px_lift` (4,152 B) is the comparator proving the two agree. The remaining 14,432 B and the port's `PX_HEADROOM_MIN` of 40,960 B are an open owner decision; bank 1 has ZERO spare pages (the registry owns all 128) while the bank-2 NS slot has 275,100 B free (149,436 B image + 75,176 B atlas of 499,712 B), so the candidate levers are geometry, not diet. Every span above is a floor: `mode-production` + `rdp2-self-lock` are still absent (the S-2 fence blocks them). **The SHIPPING config has never been frame-time measured at all:** every number above is at 40 MHz, but `PX_SHIP_FEATURES` does not include `ui-px-spi40`, so the ship image drove the panel at 20 MHz where `hw/spi_hw.rs:221` documents a **~48 ms full repaint** — 3x the 16 ms target, before any render cost. **FIXED 2026-10-06** (`ee084e30`): the prescaler is now board-derived (`board::LCD_SPI_MBR`), so `BOARD=pq1` ships 40 MHz with no feature flag; iota2 stays at 20 MHz because its LD2 LED loads PE13 = SCK. The port plan's "≈ 40 fps on the sweep" describes a configuration we do not ship. Tracked separately, along with panel tearing (TE is mapped and enabled but never waited on) and the `PLAY_CAP_MS` freeze. `ui-px` stays out of `make release`; the CI budget step is informational until the lever lands.
- **Domain tags are sticky-but-renamable.** Tag `"sphincs-c6-v1"` is historical (was a different parameter set when written; now C10). Don't rename mid-bring-up (re-provisions every bench board); coordinated cleanup pre-launch is fine.

When a task touches an invariant-adjacent subsystem (TZSC allowlist, gateway surface, SE provisioning, key derivation), respect the invariant. Pure bring-up wiring (clocks, GPIO, peripheral-init order) prioritises lighting up; note any regression here.

## Lifecycle

Boot → legacy bench FSBL verify slots + render 8-word fingerprint on the NV3007 LCD (~6.9 s on pq1: 2.9 s verify MEASURED + a 4 s fingerprint reading window, the latter a policy constant set to match the secure world's long-standing `measured_boot::WORDS_MS`; the 4 s hold and the new total are EXPECTED, not yet re-measured on silicon — see `docs/security/measured-boot.md`) → branch into active slot → SAU/GTZC → SAES self-test → SE attest → PIN entry (S-world trusted UI) → unlock both SEs → reconstruct entropy in S-SRAM → active signing window (120 s idle timeout, S-only TIM; NS pings do NOT reset it) → zeroize on lock/tamper/brownout/inactivity. Treating the FSBL as an immutable production trust root remains contingent on the approved geometry, WRP/option-byte ceremony, production link/resource gates, and silicon receipts.

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

**Timings on hardware — measured, not the old targets (#699).** On pq1, 2026-09-18, `make test-key-speed BOARD=pq1`, with `[S] hash: HW SHA-256 self-test PASS` in the same boot: first sign (type1 + slot keygen + type2) ≈ 14–17 s; Type-2 on a cached slot ≈ 6.4–7.2 s (C10 target-sum grinding spreads single runs by ±1 s or more). The older "first-sign ≤ 3 s / cached ≈ 1.1 s" figures do not match this silicon. Do **not** read a slow sign as "HASH peripheral unused" — first check the boot log for the self-test PASS line.

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
- **Dev / test (NEVER ship):** `debug-log` · `e2e-test` (fixed mnemonic + PIN, short-circuits secure-side `confirm()` **and**, since a8961636, `enter_pin()`, which returns the e2e PIN `00000000`. Before that fix a panel-less board wedged forever in the PendSV idle re-unlock ~120 s after unlock; the fix was validated free-running on pq1 silicon 2026-09-18 across three idle deadlines. Caveat, #692: on these images every PendSV retry goes through `gated_unlock`, so a persistent SE fault burns the whole 10-attempt page-124 budget before the 46a30658 retry guard can fire) · `otp-hardcoded-master-key` (fixed ASCII OTP-master so re-flashed bench boards keep stable admin/SCP03/PBS bytes) · `ui-capture` (SHA-256 of every displayed frame).

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
| `fsbl/` | Legacy bench bootloader. It is not yet an immutable production trust root. The frozen 40-KiB registry (pages 0..4) landed as `pqsigner-geometry`; this crate still links against the legacy 32-KiB region, cutover #540. Carries the tz-1 option-byte read-back tripwire (`optbytes.rs`): reads only, halts on a persistent mismatch. The physical FLASH LOAD-span gate is CLOSED and the stack is bounded (`scripts/check_fsbl_geometry.py`, run by `make fsbl`); the WRP/option-byte ceremony and a call-graph worst-case stack remain OPEN. |
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
- **No software PRNG for secret or signature-reaching randomness** — BIP-39 entropy, seeds, signing keys, PIN material, SE handshake/session keys, OptRand, and every value that enters a signature, a KDF, a tunnel key or an on-chain artifact MUST come from the hardware TRNG (`rng::byte` / `rng::fill`, which fail loudly) or `rng_strong` — STM32 TRNG, or semihosting `/dev/urandom` on QEMU. **Narrow carve-out, non-secret countermeasure parameters only** (2026-10-08, after the research below): the *length* of an FI delay (`fi::wait_random`, and any future always-on RDI, #805) and the PWM duty of the consumption mask MAY be served from a hardware-TRNG-seeded deterministic generator, subject to **all** of: (a) seeded and reseeded only from the hardware TRNG under a documented bounded policy, failing loudly — never a fixed constant; (b) effective internal state ≥ 246 bits (BSI AIS 20/31 v3.0 DRG.2.3/3.3/4.3 class text) with the state treated as a secret — secure-world SRAM only, zeroized on lock/tamper/brownout, never reachable over NSC, seed *and* algorithm integrity- and confidentiality-protected (JIL v3.2.1 §182); (c) the instance serves that one parameter and nothing else — a second consumer voids the carve-out, which is also why such a generator must NOT live in `rng.rs` (the `negative_no_software_prng_seed_in_rng_module` gate keeps the secret path absolute); (d) the degraded path (contention, reseed failure, buffer miss) is bounded, loud, documented, and NOT the dominant path, with a **measured** fallback rate in the evidence record; (e) no approved/certified-RNG claim attaches — a ChaCha DRBG is not one of SP 800-90A's three mechanisms, so it is a non-approved algorithm with no security claimed; (f) the FSBL's deterministic delay stub is covered by the same rule or recorded as a known contract-vs-code gap.

  **Why this is scoped rather than absolute, and what the evidence does and does not say.** The absolute form was stricter than every certification scheme examined — *including for key material* — while the code already contained an undocumented instance of exactly this pattern (`hw/consumption_mask.rs` seeds an xorshift32 from the platform TRNG for PWM duty, reseeded ~1 s, fail-closed; its gate calls it "deliberate and documented… NOT a key-derivation RNG"). A 111-agent research pass (2026-10-08) established: **REQUIRED — nothing.** FIPS 140-3, the CMVP IG, SP 800-90A/C, CC/JIL and PP-0084 are *measurably silent* on countermeasure-timing randomness (zero occurrences of "random delay", "jitter", "desynchron", "dummy", "shuffl" across ~600 KB, with negative controls; FIPS 140-3's non-invasive sections are bare divider pages and SP 800-140F §6.2 reads "No additional requirements at this time"). Where the schemes *do* speak, a TRNG-seeded DRBG is the **normative construct, not a deviation**: every SP 800-90C RBG class contains a DRBG, CMVP IG C.H *requires* an approved DRBG for random IVs, AIS 20/31 calls DRG.3 suitable for all cryptographic applications bar those needing guaranteed fresh entropy, and an EAL6+ secure element (Goodix GSE20) ships a software DRG.3 as an evaluated function. **The counterweight, which is why the conditions above are not optional:** CC/JIL names DPA/SPA countermeasures among the consumers broken by an RNG attack and grants them **no lower tier** — "it is only a countermeasure" is supported by no source. **What is NOT established:** the research's sub-questions on threat-model quantification and on documented failures produced **zero** surviving claims, and the premise that DRBG output is indistinguishable from per-call TRNG bytes to an attacker who cannot read SRAM was **refuted 0–3**. Comparable-product practice was confirmed for **one** vendor (Trezor). So this carve-out rests on an *a fortiori* argument from certification practice — owner judgement on 2026-10-08, not a proven security equivalence. Re-run it if SP 800-140F is ever populated. Full evidence, citation corrections and amendment targets: #805.
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



### From `docs/security/HARDENING.md`

# Hardware Wallet Hardening Requirements

**Project:** SPHINCS+ hardware wallet on STM32U585 (B-U585I-IOT02A) + NXP EdgeLock SE050, Rust, TrustZone-M.

**Purpose:** Consolidated security requirements and invariants. Every item here is load-bearing. Skipping any of them weakens the whole chain.

---

## 1. Threat Model (Write This Down First)

Before writing code, commit to an explicit threat model. The design below targets:

- **In scope:** remote/software attackers, firmware exploits, stolen powered-off device, bus snooping, casual physical access, skilled physical attacker with bench equipment during or shortly after a legitimate unlock.
- **Out of scope (acknowledge explicitly):** nation-state lab attackers with unlimited FIB/SEM budget, coerced unlock (rubber-hose, shoulder-surf), supply-chain compromise of silicon vendors.
- **Partially mitigated:** fault injection, cold-boot attacks on SRAM, SE050 die-level invasive attacks.

Document your trust boundaries, your list of secrets, and where each secret is allowed to exist (which chip, which memory region, which lifetime). Enforce those invariants in the Rust type system.

---

## 2. Architecture Invariants

### 2.1 Secret Residency Rules

| Secret | Lives in | Never allowed in |
|---|---|---|
| BIP-39 entropy / seed | SE050 at rest; U585 Secure SRAM briefly during signing | U585 flash, NS world, logs, debug output |
| SPHINCS+ `SK.seed`, `SK.prf`, `PK.seed` | U585 Secure SRAM briefly during signing | Anywhere persistent on U585, NS world |
| SCP03 static keys | Factory transport keys derive from the factory-burned per-device OTP master. The candidate first-field flow replaces them with final keys derived from the BHK (no TRNG salt); production approval and recovery evidence remain OPEN | Flash as a standalone key blob, NS world, logs, debug output |
| PIN (raw) | U585 Secure SRAM for microseconds during stretching | Anywhere else, ever |
| Stretched PIN (AESKey credential) | U585 Secure SRAM for one SCP03 handshake | Persistent storage, NS world |
| SE050 attestation root cert | U585 Secure flash (hardcoded in image) | N/A (public) |

### 2.2 World Separation

- **Secure world owns:** I²C driver to SE050, SCP03 state, PIN stretching, SPHINCS+ implementation, all secret handling, the inactivity timer, the wipe routine.
- **Non-Secure world owns:** UI, keypad/touch, display, network (if any), everything else.
- **NSC boundary:** minimal surface. Entry points accept opaque requests (sign this hash, unlock with this PIN) and return only non-secret outputs (signatures, success/failure, public keys).

### 2.3 The Seed Never Crosses to NS

There is no legitimate NSC call that returns the seed, the mnemonic, the SPHINCS+ secret key, or any derivative from which they can be recovered. If you find yourself writing one, stop and redesign.

---

### 2.4 Trusted-display consent gate

Two consent policies coexist, by path, since 2026-09-22:

| Path | The sign gesture is armed… | Since |
|---|---|---|
| Legacy 16×4 page dialog (`ui::confirm`, `confirm_core::seen_last`) | only after the LAST page has been displayed (scroll-to-end; a premature long-right / chord is demoted to "advance one page") | `ccfa5f61`, 2026-06-26 (WYSIWYS audit: every spliced loud page — native value, gas, Safe refund, ERC-8213 — was skippable from page 0) |
| Pixel trusted UI (`ui-px`, `ui::px::confirm_px` / `px::lcd::run_flow`; every sign dialog since port step 3, 2026-09-23 — `forced_blind` excepted) | **only after the LAST screen has been painted** (scroll-to-end, `PX_COMMIT_REQUIRES_SEEN_LAST = true`), and then only on the opening ask, the auto-inserted `Confirm?` (6th screen when ≥ 7 details) or the returning ask; **never on a detail** | owner decision **2026-09-24** (see the UPDATE below), superseding 2026-09-22 |

**UPDATE 2026-09-23 (port plan step 3):** the pixel path now carries every
sign dialog — Safe, every single-UserOp route, the slot-rotation consent,
direct CoW, ERC-7730, the off-chain kinds (typed, `personal_sign`, RAW32) and
each batch member plus the batch's final ask — so the row above applies to
all of them under `ui-px`. `forced_blind` keeps its own ceremony; the legacy
row still governs every build without `ui-px`.

**UPDATE 2026-09-22 (later the same day, owner decision on the EVT):** on the
pixel path the sign gesture is the **two-button chord click** — both buttons
down together, the sign fires when both are released
(`InputFsm` → `Gesture::ChordClick` → `FlowDriver` `Gesture::Chord` →
`NavResult::Sign`) — not the design's 2 s hold-right, which is now a no-op
everywhere on that path (hold-left still declines everywhere). Rationale:
parity with the legacy dialog, whose `hw::buttons::wait_event` has always
synthesised the two-button chord as the confirm. Residual accepted: the sign
is an instantaneous gesture rather than a 2 s deliberate hold, so a squeeze
on a commit-armed screen signs; a chord formed from the post-tap window (one
side already up) never clicks, so a fast left-tap-then-right-tap cannot
sign, and details remain unarmed. The `FihBool` gate and single
`OK_SENTINEL` site are unchanged. PQ-UI `DESIGN.md` § Input (vendored) still
describes hold-right; the device deviates here and in `TAP_MAX_MS` (500 ms).

**SUPERSEDED 2026-09-24 — see the UPDATE below. The paragraph is kept because
the mitigations it lists are still real, and because the reasoning that was
accepted and then reversed is worth preserving.** ~~The pixel path
intentionally re-opens the class the 2026-06-26 fix closed for that path only:
a user can sign from the opening ask without paging through the details.~~
Mitigations the design supplies: declining is armed on every
screen (hold-left), the `Confirm?` early exit sits after five detail screens,
the returning ask is the demo's canonical hold point, and every value the
legacy pages showed is present in the transcript (host fact differential in
`safe_screens_render_pure_tests.rs`). The arming flag is a `FihBool`
re-derived from the record's `commit` byte (double read) on every screen
change; the `OK_SENTINEL` is minted at exactly one site.

**UPDATE 2026-09-24 — REVERSED, by owner decision: the gate is ON.**
`secure/src/ui/px/confirm_px.rs::PX_COMMIT_REQUIRES_SEEN_LAST` is now `true`.
Owner, asked directly whether the pixel path should still require paging past
the recipient and the amount: *"all screens should be viewed before the user
can sign."*

The concrete case that decided it: an ERC-20 transfer is EIGHT screens
(`tx::display::erc20_known`). The opening screen says "Send USDC"; the
RECIPIENT is screen 3 and the AMOUNT is screen 4. With the gate off, one chord
click on the opening ask approved a transfer whose destination and value had
never been displayed. The mitigations listed above (decline armed everywhere,
the `Confirm?` early exit after five details, the values present in the
transcript) are real but none of them puts the recipient in front of the user.

The evidence is a real paint, not an index: `FlowDriver::mark_rendered` is
called by the presenter immediately after `build_and_present` (`px/lcd.rs`) and
after `text::present` (`confirm_px.rs`), and sets `seen_last` only when
`cur + 1 == count` — the same "evidence of display, not merely an index
assignment" rule `confirm_core.rs` states for the legacy path. As this section
already noted, the loop maintains `seen_last` either way, so the constant was
the only change needed.

The two paths now AGREE, and `fsbl-tests/tests/paired_constants.rs` pins them
so they cannot drift apart silently again.

RESIDUAL, not closed by this change: on the legacy path `seen_last` is a
`FihBool` (complement pair + double read); on the pixel path it is a plain
`bool` feeding the `FihBool` arming flag. A stuck-at fault on the pixel
`seen_last` would defeat scroll-to-end without defeating arming. Worth
hardening; tracked separately.

Do not re-litigate without new evidence; record any change here and in
`CLAUDE.md` Pre-Production Caveats.

**Device input model (frozen 2026-09-23, port plan step 1).** The
device's gesture grammar on the pixel path is this table; the conformance
oracle is the vendored PQ-UI `handoff/spec/gestures.json` (an 80-row executed
truth table) + `traces.json`, and the deliberate deviations from it are the
single list `tools/pq-ui/PORT_DEVIATIONS.toml`, machine-checked against
`handoff/spec/motion.json` by `make pq-ui-port-diff` (an unrecorded drift is
a red build).

| Constant (`pqsigner-ui-px`) | Device | Reference | Note |
|---|---|---|---|
| `DEBOUNCE_MS` (`input.rs`) | 25 | — | SysTick ISR lockout per side, first edge exact; device-only |
| `TAP_MAX_MS` (`motion.rs`) | **500** | 250 | recorded deviation (EVT #1 2026-09-22: deliberate presses run 250–400 ms) |
| `DOUBLE_TAP_MS` | 250 | 250 | entry contexts only |
| `CHORD_MS` | 150 | 150 | the other side within this = the chord |
| `HOLD_COMMIT_MS` | 2000 | 2000 | hold-left decline fires here |
| `HOLD_SNAPBACK_MS` | 200 | 200 | early-release drain |
| `PRESS_FEEDBACK_MS` | 120 | 120 | chevron nudge |

| Screen kind | tap L / R | hold-left | hold-right | chord click (both down, fires on release) |
|---|---|---|---|---|
| Hero (opening / returning ask), `Confirm?` | navigate | decline | **no-op** (reference: sign) | **sign** (reference: unbound) |
| Detail / Value | navigate, page-turn | decline | no-op | ignored (never armed) |
| Status / film / ending | **input-dead**: edges are ignored while the film plays and its result holds; the inactivity deadline and idle wipe stay enforced | | | |

Input during a transit retargets the springs and is never dropped. The film
(`ui::px::lcd::film_*`) runs around the signer's FI chain, paced by its opaque
`fn(u8)` progress hook, and cannot change any decision: by the time it
starts, the `OK_SENTINEL` has been minted and re-proved. The upstream
catalogue (`handoff/catalog/actions/{hold-right-sign,unbound-gestures,
tap-navigate}.md`) still describes the reference grammar; a device-deviation
note for those pages is proposed upstream (see `tools/pq-ui/UPSTREAM.txt`).

## 3. SE050 Configuration

### 3.1 Authentication Object

- Type: **AESKey** (not UserID — UserID is plaintext on the I²C bus).
- `TAG_MAX_ATTEMPTS = 10`. Must be non-zero; zero means infinite.
- Credential is the *stretched* PIN output, never the raw PIN.
- Counter is pre-decremented in flash before verify — power-pull during verify does not grant a free retry.

### 3.2 Seed Storage Object

- Type: Binary file object containing the 16–32 bytes of BIP-39 entropy.
- Policy: `ALLOW_READ` **only** when authenticated by the specific Auth Object ID above.
- Policy: **no** access for Auth Object ID `0x00000000` (the "any user" pseudo-ID).
- Policy: **no** `ALLOW_WRITE` or `ALLOW_DELETE` except for a distinct admin auth object used only during provisioning.
- Consider storing the precomputed SPHINCS+ `PK.root` in a separate non-secret binary object to avoid recomputing on every boot.

### 3.3 Channel

- **SCP03** via AESKey or ECKey (FastSCP) auth. Prefer ECKey for cleaner at-rest posture (no shared symmetric secret in U585 flash).
- All communication with the SE050 after boot attestation must run inside an SCP03 session. No plaintext APDUs touching secrets, ever.

### 3.4 Boot-Time Attestation

On every boot, before trusting the SE050:

1. Generate a fresh random nonce in Secure world (from U585 TRNG or SE050 RNG — do not reuse).
2. Request an attested signature over the nonce using the SE050's NXP-provisioned attestation key.
3. Verify the signature chains to NXP's root certificate, hardcoded in the Secure image.
4. Verify the SE050's unique ID matches the value pinned at provisioning time. A genuine-but-different SE050 must be rejected.
5. Only then open the SCP03 session.
6. On any failure: refuse to proceed, display a tamper warning, do not accept a PIN.

### 3.5 Provisioning

- **Current lifecycle split (work-todo #36):** the factory burns the per-device OTP master and uses it to install the device's transport SCP03/admin/PBS credentials plus the required SE structure, policy, and attestation state. It then ships at RDP-0 so the owner can verify flash and option bytes before first power. It does not install the final pairing credentials, perform the BHK first write, create the wallet seed, or set RDP-2.
- On first field boot, after pre-power verification, the **secure app early-boot** candidate self-locks RDP-2 and performs the BHK first write. It then replaces SE050 transport credentials with unsalted BHK-derived final SCP03/admin credentials and replaces the OPTIGA transport PBS with a final value derived from the per-die DHUK plus a fresh TRNG salt persisted in the page-127 journal, before the seed wizard. The FSBL only authenticates and hands off the selected slot.
- That candidate is implemented behind `rdp2-self-lock`, but the authenticated handoff, authenticate-before-rotate rule, old/new/KVN recovery proof, exact E140 ordering, silicon receipts, and production approval remain OPEN. This document does not authorize an irreversible action; follow the `EthereumPhone/PQ1` production gates (labels `source:production-todo`, `ship-blocker`) and work-todo #36.
- The storage boundary is: flash page 126 holds only the DHUK-wrapped BHK; page 127 owns the first-boot journal and non-secret OPTIGA salt; final SE050 SCP03/admin material derives from the BHK and has no standalone flash key blob.
- Create the PIN-auth and seed objects only during the reviewed first-field ceremony after the final secure-channel rotation.
- Pin the SE050 unique ID to U585 Secure flash.
- Apply SE050 transport lock if applicable to your variant.
- U585 RDP Level 2 is the final MCU option-byte lockdown step before the final pairing rotation and seed wizard. **Irreversible; per work-todo #36 the candidate programs it from secure-app early boot on first field boot, not at the factory: devices ship at RDP-0 so users can verify flash, option bytes, and OTP over SWD before first power.**
- Consider NXP EdgeLock 2GO if you need to provision at volume.
- Provisioning must run in a clean-room environment. A compromised provisioning station compromises every device that passes through it.

---

## 4. STM32U585 Configuration

### 4.1 TrustZone & Memory Protection

- Enable TrustZone. Configure SAU and IDAU to partition flash, SRAM, and peripherals.
- **GTZC configuration is the #1 source of TrustZone-M leaks.** Budget real time for it and have it reviewed.
- Mark as Secure: I²C to SE050, TIM used for inactivity timer, TAMP, SAES, PKA, HASH, TRNG, BKPSRAM holding secrets.
- Block **all** DMA controllers from mastering into Secure SRAM unless the DMA instance is itself Secure.
- MPU regions covering Secret SRAM must be enforced in both S and NS worlds.

### 4.2 Debug & Readout Protection

- **RDP Level 2** in production. Irreversible. The current candidate self-programs it from secure-app early boot on first field boot — devices ship at RDP-0 for pre-first-power user verification (work-todo #36).
- Debug ports (SWD, JTAG) disabled by RDP-2.
- Boot from internal flash only. Disable bootloader access in option bytes.
- Verify the RDP level in boot code; refuse to run if debug build flags are set in a production image.

### 4.3 At-Rest Key Protection

- The candidate's factory transport PBS derives from the factory-burned per-device OTP master; its final OPTIGA PBS derives from the per-die DHUK plus the non-secret TRNG salt persisted in page 127. Legacy bench builds may still use deterministic DHUK or development roots.
- Flash page 126 stores only the BHK wrapped under the per-die DHUK; final SE050 SCP03/admin material derives from that BHK without the OPTIGA salt.
- A flash dump transplanted to another U585 must be useless.
- The candidate derivations are implemented, but first-field handoff/recovery, E140 ordering, silicon evidence, and production approval remain OPEN.

### 4.4 Hardware Peripherals to Use

- **TRNG**: for all nonces, challenges, and every value that is secret or reaches a signature. Audit that `rand_core` is wired to this, not to a software PRNG. **This line used to read "any randomness", which contradicted its own sibling in §"RNG" below ("Never a software PRNG *for secrets*") and did not match the code** — `hw/consumption_mask.rs` has always seeded an xorshift32 from the platform TRNG for PWM duty. Both are now scoped the same way, and the one narrow exception for non-secret countermeasure parameters, with its six mandatory conditions, is stated once in `CLAUDE.md` § "What NOT to do" rather than restated here (see #805).
- **HASH**: for SHA-256 acceleration inside SPHINCS+ (pick the SHA2 parameter set specifically to benefit from this).
- **SAES**: for DHUK/BHK derivation and BHK wrap/unwrap operations; the hardware roots never become CPU-visible.
- **TAMP**: wire any tamper inputs (case switch, mesh) into the wipe handler.
- **BOR**: set to a high threshold so brownout detection fires with enough headroom for the wipe ISR.

### 4.5 Inactivity Timer (2-Minute Seed Wipe)

- Timer runs on a **Secure** TIM instance. NS world cannot stop, reprogram, or observe it.
- "Activity" is defined by Secure world (e.g., completed signing operation). NS world opinion is ignored; a compromised NS image cannot keep the seed alive by spamming fake activity.
- On timeout: fire the wipe routine.
- Also fire the wipe on: tamper event, unexpected reset reason, low-power mode entry, integrity check failure, any NSC call returning an error, brownout interrupt.

### 4.6 Power-Loss Wipe

- External supervisor or programmable BOR trips above the minimum operating voltage, with enough margin for the wipe ISR to complete.
- Bulk capacitor sized to hold the U585 through the worst-case ISR runtime under full load. **Measure this on real hardware; don't estimate.**
- Wipe ISR: zeroize Secret SRAM regions, clear caches, clear CPU registers, write a "clean shutdown" flag.
- Wipe ISR is written defensively: loop twice, verify after, use DMA/SAES for bulk clearing if faster than software loop.
- Same ISR handler is invoked by TAMP events.

### 4.7 Temperature Sensing

- Use the internal temperature sensor to refuse operation below (e.g.) 0°C, mitigating cold-boot attacks that freeze SRAM to extend retention.
- Check temperature on boot and periodically during operation.

---

## 5. PIN Handling

### 5.1 Flow

1. NS UI collects PIN digits, passes a byte buffer into a Secure NSC entry point.
2. Secure world copies the PIN into a Secure-only buffer, zeroizes the NS-facing buffer immediately.
3. Secure world computes `PIN_key = KDF(PIN, device_salt)` where:
   - KDF is PBKDF2-HMAC-SHA256 with a high iteration count.
   - `device_salt` is a random per-device value stored on the SE050 as a non-secret binary object.
4. `PIN_key` is used as the AESKey credential to open an SCP03 session against the SE050's PIN auth object.
5. On success: read the seed binary object inside the SCP03 session.
6. Zeroize `PIN_key` and the raw PIN immediately after the SCP03 handshake completes.

### 5.2 Stretching Requirements

- Iteration count / memory parameter sized so that a single PIN guess takes hundreds of milliseconds on the U585. Users will feel it; that's the point.
- Even if the SE050's retry counter is somehow bypassed, per-guess CPU cost makes offline brute force painful.
- The stretched value is a 128-bit AES key, not a short PIN.

### 5.3 Consider

- **Duress PIN:** a second PIN that unlocks a decoy wallet or triggers a wipe. Architectural, not a bug, but worth deciding on.
- **Progressive delay:** increasing delay between attempts in Secure world before the SCP03 handshake is attempted, to make online brute force slower than the 10-strike limit would suggest.

---

## 6. SPHINCS+ Implementation

### 6.1 Parameter Set

- Use **SPHINCS+C10** (`h=18, d=2, a=11, k=13, w=8, l=43, target_sum=205`, 4008-byte signature) with SHA-256 on this platform. Rationale:
  - `f` variants are dramatically faster than `s` variants on Cortex-M33 (often 10-30×).
  - SHA2 lets you use the U585 HASH peripheral for the inner hash loop.
  - SHAKE and Haraka have no hardware acceleration on this chip.
- Benchmark on real hardware before committing. Paper numbers lie.
- Document the parameter set in your protocol spec with a domain separation tag; changing it later is a migration problem.

### 6.2 Derivation from BIP-39

1. Read 16–32 bytes of entropy from SE050 over SCP03.
2. Compute BIP-39 seed: `PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" + passphrase, 2048)` → 64 bytes.
3. Derive SPHINCS+ key material via HKDF-SHA256 with an explicit domain separation label, e.g. `"SPHINCS+C10/v1"`.
4. Extract `SK.seed`, `SK.prf`, `PK.seed` (3 × *n* bytes).
5. Run SPHINCS+ keygen to compute `PK.root`, or load it from the SE050 if precomputed.

**Question to resolve:** do you actually need BIP-39? If human-recoverable word lists aren't a product requirement, store the SPHINCS+ seed material directly on the SE050 and skip the BIP-39 layer. Simpler, less code, smaller attack surface.

### 6.3 Implementation Sourcing

- Candidates: `pqcrypto-sphincsplus` (PQClean via FFI), pure-Rust `sphincs-plus` crates.
- Audit whichever you pick. "Reference implementation" and "pure Rust" both mean "not necessarily constant-time or fault-hardened."
- Pin the version. Vendor the code if you can. Review every line that touches `SK.seed` or `SK.prf`.
- Run against NIST PQC test vectors in CI. Differential test against a second implementation if possible.

### 6.4 Side-Channel Hardening

- Constant-time execution for every secret-dependent operation. `subtle` crate for comparisons and conditional selects.
- No secret-dependent branches, no secret-dependent memory access patterns.
- Disable compiler optimizations that might introduce variable-time code (e.g., table lookups that become branches). Inspect the generated assembly for critical inner loops.
- Power analysis is a real threat on an unshielded board. Full DPA resistance is hard, but at minimum avoid the worst patterns (secret-dependent hash inputs without randomization).

### 6.5 Fault Hardening

- Redundant computation of critical steps (WOTS+ chains, FORS).
- **Verify the signature before releasing it.** If verification fails, zeroize and refuse. This catches fault injections that corrupted the signing process.
- Canary values checked at function boundaries.
- Control-flow integrity where practical.
- None of this is in PQClean or most pure-Rust crates by default. You add it.

### 6.6 Memory Budget

- Secret key material: up to 96 bytes.
- Signing working set: 8–64 KB of stack depending on parameter set.
- Signature buffer: 4008 bytes (SPHINCS+C10).
- Ensure Secure-world stack is sized accordingly. Default CubeIDE/CubeMX stacks are too small.
- All of this must be in Secure SRAM, GTZC-protected.

---

## 7. Rust-Specific Requirements

### 7.1 Toolchain & Targets

- Target: `thumbv8m.main-none-eabihf`.
- Stable Rust where possible. Nightly only if required for `cmse_nonsecure_entry` or similar — document the exact reason.
- Separate crates for Secure image and NS image; shared `nsc-interface` crate defining the ABI with `#[repr(C)]` types.
- Reproducible builds. Pin the toolchain version in `rust-toolchain.toml`.

### 7.2 Mandatory Crates

- **`zeroize`**: for every secret. Use `ZeroizeOnDrop` derives. Do not rely on plain `Drop` or manual assignment — the compiler will elide it.
- **`subtle`**: for constant-time operations.
- **`rand_core`** wired to U585 TRNG or SE050 RNG. Never a software PRNG for secrets.
- Audit every other dependency that touches secrets.

### 7.3 Lints & Build

- `#![deny(unsafe_op_in_unsafe_fn)]`
- `#![warn(clippy::pedantic, clippy::nursery)]`
- `#![deny(clippy::indexing_slicing)]` (forces explicit bounds handling)
- Every `unsafe` block has a `// SAFETY:` comment explaining the invariant. Reviewed explicitly in code review.
- `cargo audit` and `cargo deny` in CI. Fail the build on any advisory.
- `cargo-geiger` to track `unsafe` surface across dependencies.

### 7.4 Type System Enforcement

Lean into the type system to make invariants compile-time errors:

- `struct Seed([u8; 64])` with `ZeroizeOnDrop`, constructed only inside the unlock flow, consumed by signing.
- `struct UnlockedSession<'a>` that borrows from a live SCP03 session; signing functions take `&UnlockedSession` so they cannot be called without one.
- `struct NsPtr<T>` wrapping raw pointers from NS with a checked constructor that validates length and alignment. Rest of the Secure code only handles validated types.
- Mark secret-bearing types `!Copy` and `!Clone` so they can't be silently duplicated.

### 7.5 NSC Boundary

- Every NSC entry point validates every parameter. Treat NS as fully hostile.
- Length fields validated before use.
- Pointers validated to point into NS memory, not into Secure memory (prevents NS from tricking Secure into reading its own secrets through a "buffer").
- No panics across the NSC boundary. Set a panic handler that wipes secrets and resets.
- Return types expose only non-secret data.

### 7.6 What Rust Does Not Save You From

Say this out loud to yourself before every commit:

- Side-channel leaks. The borrow checker does not know what timing is.
- Fault injection. Rust compiles to the same machine code C does.
- Zeroization actually happening under optimization — use `zeroize`, not assignment.
- Stack frame ghosts after function return — minimize secret lifetime depth.
- GTZC/MPU/peripheral config bugs.
- Bugs in your dependencies.
- Provisioning and supply-chain problems.

---

## 8. Zeroization Discipline

- Every secret has a clear lifetime and a clear zeroization point.
- Use `zeroize::Zeroize` and `ZeroizeOnDrop` everywhere. Never plain `memset` or assignment.
- Compiler fences around zeroization calls (the `zeroize` crate handles this; verify).
- After sensitive operations, explicitly clear the stack region used. `zeroize` has helpers; if not, write a small assembly routine.
- Clear CPU registers after returning from crypto operations if the ABI allowed secrets into them.
- Cache flushes if secrets may have been cached.
- Verify zeroization in tests — write a test that runs a signing operation and then scans Secure SRAM for any byte pattern matching the test key. Fail loudly if found.

---

## 9. Provisioning Security

- Clean-room facility. No network on provisioning stations.
- HSM-backed generation of per-device SCP03 keys, or EdgeLock 2GO.
- Provisioning logs never contain secret material. Audit every log statement.
- Factory acceptance is a completion-flag check (`is_provisioned` + OTP sentinel read over probe-rs), not cryptographic per-unit attestation — a malicious provisioning station can forge it. Real per-unit attestation (SE050 ECKey attestation, #22 / S-G) is unbuilt. First-field acceptance, after owner verification, separately proves the RDP-2 self-lock, BHK first write, final secure-channel rotation, and seed-wizard completion.
- Tamper-evident packaging between facility and user.
- A provisioning station compromise compromises every device that passed through it during the compromise window. Have a plan.

---

## 10. Update Mechanism

Firmware update is its own project, outside the scope of this document, but note:

- Updates must be signed with a key held in an HSM, verified by the bootloader before any code runs.
- The verification key is stored in a region covered by RDP-2 and option bytes that prevent modification.
- Production anti-rollback remains quarantined. The legacy secure-flash and unary-OTP mechanisms are rejected; Draft 1.1 is a preserved, non-implementation-approved research candidate whose journal, OTP/ECC, resource, factory, and silicon gates remain OPEN. Follow `docs/STATUS.md`; no backend is selected here.
- Rollback plan for broken updates that doesn't involve unlocking RDP-2.
- Update process must not require exposing secrets.
- Test updates on field hardware before every release, not just in the lab.

---

## 11. Testing & Verification

- Unit tests for all cryptographic primitives against published test vectors (NIST PQC for SPHINCS+, BIP-39 spec vectors, etc.).
- Differential tests against a second implementation where available.
- Host-side tests with a mock SE050 for logic.
- On-device integration tests for hardware interaction.
- Fuzz every NSC entry point (`cargo fuzz`) with AFL-style mutation.
- Property-based tests (`proptest`) for anything with nontrivial invariants.
- Zeroization verification tests that scan SRAM after operations.
- Boot-time attestation negative tests: what happens if the SE050 responds with a wrong cert, a replayed nonce, a malformed APDU, no response at all.
- Timing tests on critical paths; flag any data-dependent variation.
- Power-loss tests on real hardware: cut power at many points during a signing operation and verify no secrets survive in any persistent memory.

---

## 12. Operational

### 12.1 Before Touching Real Funds

- **External security audit** from a firm with embedded/TrustZone/secure-element specialization (NCC Group, Trail of Bits, Quarkslab, Kudelski, etc.).
- Fault injection testing on real hardware (lab time).
- Public bug bounty with meaningful rewards.
- Gradual rollout: start with small amounts, wait months, scale up only if nothing surfaces.
- Do not store your own significant funds on it until it has been under public scrutiny for an extended period.

### 12.2 Incident Response

- Have a vulnerability disclosure policy before you ship.
- Have a plan for pushing updates fast when (not if) a flaw is found.
- Have a plan for informing users whose devices may be compromised.
- Reserve capacity to triage reports from researchers.

### 12.3 Documentation

- Threat model document, updated as the design evolves.
- Protocol specification covering every APDU, every NSC call, every crypto primitive and its parameters.
- A "known limitations" document listing what you *don't* protect against, so users can make informed decisions.

---

## 12.4 ERC-7730 Timing Channels

The on-device ERC-7730 clear-signing renderer walks a Merkle-verified
descriptor's `FormatHeader` field list, evaluates each field's
`Visibility` rule (`Always` / `Never` / `Optional` / `IfNotIn` /
`MustMatch`), and dispatches across fifteen wire operations. Enrolled nested
calldata uses the proof-set child path; encrypted operands and unenrolled
calldata hard-refuse. Two
sub-questions about timing channels:

1. **Are visibility-rule evaluation paths secret-dependent?** No.
   Descriptor bytes enter the firmware only after Merkle verification
   against the firmware-pinned `ERC7730_DESCRIPTORS_ROOT`. The bytes
   are public registry data, not key material. The walker's
   instruction trace is a function of the descriptor + the inbound tx
   bytes (`(chain_id, to_address, calldata)`), both of which the
   attacker already knows. There is no secret-dependent branch in the
   rule evaluator, the path walker, or any renderer route. → No
   `subtle::ConstantTimeEq` or branch-balanced
   rewrite is required for this surface.

2. **Stack-budget defence.** Nested calldata is limited to one child level;
   a child format containing another calldata field hard-refuses.
   `MAX_NESTED_DEPTH = 8` bounds nested EIP-712 struct descent and
   `pqsigner_erc7730::ir::MAX_NESTING = 8` bounds nested EIP-712 validation
   and path-program steps. Both
   `render_erc7730_pages` and `render_erc7730_eip712_pages` write a
   `STACK_CANARY = 0xDEAD_BEEF` to a stack-resident `u32` at entry and
   `assert!`-check it at exit (volatile read/write so LLVM cannot
   prove the value dead). A hostile descriptor that somehow defeats
   the depth cap and recurses unbounded smashes the canary →
   `assert!` panic → secure-world panic handler routes through
   `secure_log!` + halt. This is a belt-and-braces tripwire behind the
   independent structural bounds; those bounds are the primary defence.

3. **What this does NOT defend.** Stack canary is a single-fault
   detection mechanism. A multi-fault attack that simultaneously
   overflows the stack AND glitches the assert's compare instruction
   bypasses. Defence in depth: IR validation and the renderer independently
   enforce the path, EIP-712, and one-child calldata limits, while the `Pages`
   buffer's `MAX_PAGES = 31` bound caps page emission — neither path can grow
   without bound even if the canary is defeated.

---

## 13. Honest Caveats

Things that must be acknowledged plainly:

1. **Coerced unlock defeats everything.** No PIN-gated system survives a user being forced to unlock it. Architecturally unfixable without multi-party approval.
2. **Lab attacks on the SE050 die** are rare but not impossible. EAL 6+ is very high resistance, not absolute.
3. **The SRAM exposure window** during signing and during the 2-minute cache is the biggest remaining attack surface for a skilled physical attacker. Fault injection and cold-boot attacks both target this window. The 2-minute cache is a UX concession; consider whether your users need it.
4. **Implementation bugs are the most likely failure mode.** More likely than cryptographic breaks, more likely than hardware exploits. Every shipped wallet vulnerability in history proves this. Spend your paranoia budget on code review, not on exotic attacks.
5. **First-party custom hardware wallets have a poor track record.** Not because the builders were dumb. Because the attack surface is enormous and the economic incentive for attackers scales with the funds stored. Use an audited existing wallet if you can. Build custom only if you have a real reason the existing ones can't serve.
6. **SPHINCS+ is unusual for cryptocurrency.** Verify that your signing scheme actually matches what you need to sign. Don't build the wrong crypto stack.

---

## 14. The One-Line Summary

**Architecture is necessary but not sufficient. Execution is where wallets live or die. Assume every line of code is wrong until proven otherwise, minimize the time secrets exist in any form, and do not trust your own confidence.**



### From `docs/security/production-security.md`

# Production Security — synthesis of 2026-04-14 research round

This document consolidates findings from 4 parallel AI deep-research
sessions (bundles A, B, C, D — prompt E has not yet run) into a single
actionable reference. It is *not* the code; it is the distilled plan.
Implementation tasks track on `EthereumPhone/PQ1` (label `source:work-todo`, items #18-22).

Raw research results live under `docs/security/research-bundles/results/`. Each
finding below cites the responsible bundle plus any verification caveats.

**Scope of this doc:** threats, mitigations, and architectural decisions
that the research round surfaced. For the staged brownout-hardening
rollout see `docs/security/brownout-hardening.md`. For the SE050 PIN-lockout
factory-reset design see `docs/secure-elements/se050-factory-reset.md`.

---

## 1. Critical findings as found in the 2026-04 research round

This is a dated synthesis, not a current priority list. Resolved or superseded
items are marked in place; current authority lives in `docs/STATUS.md` and
the `EthereumPhone/PQ1` issue tracker (label `source:production-todo`).

1. **SLH-DSA verify-after-sign is inadequate**. Current code assumes
   signing the blob, re-verifying, and failing closed is enough. Per
   RFC 9814 and Genêt (TCHES 2023) a single fault during SLH-DSA
   signing produces a signature that often still verifies. Double-
   compute on disjoint SRAM regions + constant-time compare is the
   only defence. Cost: ~2 s per signature at C10 (double-compute) — acceptable.
   *Source: bundle A.*

2. **We are currently signing deterministically (OptRand = 0)**. This
   enables PRF(SK.seed) recovery via horizontal DPA on unprotected
   Cortex-M33 in 1-10 traces against Saarinen's 2024 TVLA baseline.
   Every signature must draw a fresh 16 B (128f) / 24 B (192f) from
   STM32 TRNG as OptRand. One-line fix with massive SCA impact.
   *Source: bundle C.*

3. **NXP SE050 SCP03 keys must not remain the published factory
   defaults.** The factory installs only per-device transport keysets and
   ships at RDP0. After owner verification, the first-field ceremony
   self-locks RDP2 and performs the BHK first write. The implemented candidate
   then rotates SE050 to unsalted BHK-rooted final SCP03/admin credentials and
   OPTIGA to a DHUK + page-127-TRNG-salt final PBS before the seed wizard. The exact E140
   ratchet-versus-final-rotation ordering remains OPEN and owner/silicon
   gated. *Source: bundle B and work-todo #36.*

4. **USB path has two concrete silicon-errata bugs** we have not
   addressed: DWC2 TxFIFO write atomicity (ES0499 §2.26.x) and ZLP
   race leaking stale FIFO data. The latter is a **data-leak** from
   the USB controller's own SRAM under specific SNAK/CNAK/EPENA
   timing. Both fixable in driver code. *Source: bundle D.*

5. **Masaryk University 2024/2025 thesis demonstrates 76% PIN-glitch
   bypass on STM32U5A9** — same Cortex-M33 family as our U585. Factory
   defaults (BOR=0, IWDG off, ECC off, TAMP off) are the attack
   surface. Our Stage 1 brownout work partially addresses this;
   Stage 2 needs to land before any talk of production. *Source:
   bundle A + C.*

6. **RESOLVED/SUPERSEDED — the original OPTIGA PBS flash seal mixed in
   `measured_boot::firmware_hash()` and bricked pairing after an update.**
   The bench failure remains valid historical evidence (§1 of
   `docs/secure-elements/optiga-brick-postmortem.md`), but the intermediate
   proposal to use the OTP master as the final PBS root is not current
   production architecture. The factory-burned OTP master is transport-only;
   the candidate final PBS derives from DHUK plus a page-127-persisted TRNG
   salt, with no secret PBS flash copy. Page 126 belongs only to the wrapped
   BHK. Handoff, recovery, ordering, silicon evidence, and production approval
   remain OPEN under work-todo #36. See the current-state override in §2.6. *Source: bench failure,
   2026-04-17; later lifecycle corrections.*

## 2. Per-topic summary

### 2.1 Fault injection (bundle A → todo #18)

**Threat model**: voltage glitch, EMFI, laser FI, Rowhammer. The U5 has
no public glitch bypass yet but sits on the same core as the demonstrated
Masaryk attack; presumed vulnerable until proven otherwise. We can't
rely on silicon.

**Mandatory mitigations**:

- **SLH-DSA double-compute** with disjoint SRAM regions for the two
  computations. Compare via constant-time compare; release only on
  match. Verify-after-sign does NOT substitute.
- **FihInt complement-storage** (0x1AAA_AAAA / 0x1555_5555 magic
  constants XOR'd with a mask) for every security-critical boolean:
  `pin_verified`, `blob_cached`, `match_ok`, signature-release gate.
- **PIN lockout fail-in**: current code is `if remaining == 0, wipe`
  — single glitch can skip. Invert to `if remaining != 0, continue;
  else wipe` so a skipped branch fails safe (wipes).
- **Volatile reads only** on security-critical values. `core::ptr::
  read_volatile` has a formal LLVM IR guarantee; `core::hint::
  black_box` explicitly has "no guarantees for cryptographic purposes"
  per Rust stdlib docs.
- **Hardware supervisor config** (overlaps with todo #21):
  - BOR_LEV = 3 or 4 in option bytes
  - IWDG_SW = 0 (hardware watchdog, 100-500 ms)
  - SRAM2_ECC = 1, SRAM3_ECC = 1 (ECC is OFF by default on U5)
  - SRAM2_RST = 0 (auto-erase on reset)
  - PVD enabled at highest threshold below 3.3 V
  - TAMP ITAMP1-3 enabled with automatic backup-domain erasure
  - CSS on HSE

**Strongly recommended**:

- Control-flow-integrity step counters (increment before critical
  call, decrement after, fail on mismatch).
- Random delays from TRNG before critical comparisons.
- Redundant volatile reads (2-3×) with OR-based fail-in logic.

**Cost**: ~2 s per signature (double-compute), +~5 instructions per
protected boolean (FihInt). Acceptable for a wallet UX.

### 2.2 Production key management (bundle B → todo #20)

**Historical proposal.** Trezor Safe 5 uses single-SE + binding; the
following retained research proposed dual-SE + signed binding record + OTP
anchor + monotonic counter. It is not current implementation or ceremony
authority.

> **UPDATE 2026-07-14 (work-todo #36 — ship-RDP-0 decision).** Retained as
> research input, but **stage 2 now executes ON-DEVICE at first field boot,
> not on the factory fixture**: devices ship at RDP-0 (batch-uniform image,
> user-verifiable over SWD via connect-under-reset before first power); the
> secure-app early boot self-locks to RDP-2, and only then — with the per-die
> DHUK final — does firmware do the BHK first-write, rotate SE050 SCP03/admin
> to unsalted BHK-rooted final credentials, and rotate OPTIGA PBS to DHUK plus
> a page-127-persisted fresh TRNG salt off the factory-installed
> OTP-master-derived *transport* credentials. Step 10
> ("Burn RDP Level 2") is no longer a fixture action. The historical stage-1
> FMK proposal is superseded; the candidate factory transport credentials all
> derive from the factory-burned per-device OTP master.

**Historical factory provisioning proposal — superseded by the current
transport-to-first-field lifecycle above:**

Stage 1 at RDP0 (debug attached):
1. Read all 3 UIDs (STM32 at `0x0BFA_0700`, SE050 via GetInfo, OPTIGA
   OID `0xE0C2`).
2. Derive per-device SCP03 keys: `enc = AES_CMAC(FMK, "SCP03-ENC" ||
   SE050_UID)`, similarly for MAC and DEK.
3. Rotate SE050 SCP03 via PUT KEY (INS=0xD8) from KVN=0x0B → KVN=0x11.
4. Provision OPTIGA PBS (TRNG ⊕ STM32 RNG, 64 bytes). Apply metadata
   lock: `LcsO=Operational`, `Read=Never`, `Change=Conf(0xE140)`.
   **Irreversible.**
5. Create binding record, ECDSA-P256 sign with provisioner key.
6. Store binding 3× (STM32 flash wrapped, SE050 object 0x10000001,
   OPTIGA OID 0xF1D1). SHA-256 anchor → OTP bytes 6-37.
7. Burn OTP provisioned flag.

Stage 2 at RDP1+ (after reset):
8. Wrap MasterKey with real DHUK via SAES. **DHUK at RDP0 is a known
   constant**; wrapping there achieves nothing.
9. Two-level wrap: DHUK-ECB(MasterKey) → HKDF(MasterKey, purpose) →
   AES-GCM(per-use key, SCP03/PBS/binding payload). Single-level ECB
   has no integrity.
10. Burn RDP Level 2 (permanent, irreversible).

**Boot-time anti-swap**:
- Read all 3 UIDs, verify signature, verify OTP anchor hash.
- Mismatch → erase Key Pages + wipe SE050 + permanent brick.
- Boot overhead ~500 ms – 1.2 s (acceptable).

**Cited NXP default SCP03 keys** (from AN12436, per research):
```
ENC = 85 2B 59 62 E9 CC E5 D0 BE 74 6B 83 3B CC 62 87
MAC = DB 0A A3 19 A4 08 69 6C 8E 10 7A B4 E3 C2 6B 47
DEK = 4C 2F 75 C6 A2 78 A4 AE E5 C9 AF 7C 50 EE A8 0C
```

⚠ **Verify against current AN12436** before using. Research cited
"Rev 2.4" which is unverified and may be wrong. Same caveat for SAES
register bit fields (`KEYSEL`, `KMOD`, `KEYSIZE`) — the research author
explicitly flagged those as uncertain; cross-check with CMSIS header
`stm32u585xx.h` before writing SAES code.

**Firmware upgrade path**: blob magic 0x504B4559 + version byte +
HKDF label. On boot, if `blob.version < current`, re-wrap with new
HKDF label and flash new format. STM32U585 DHUK does not rotate per
firmware, unlike STM32H5, so migration is simple.

**Historical anti-rollback proposal (superseded):** OPTIGA monotonic counter
at OID `0xF1E0`, Conf(0xE140)-protected. Production anti-rollback is currently
quarantined; Draft 1.1 is a preserved, non-implementation-approved research
candidate and no backend is selected until its OPEN resource, journal,
OTP/ECC, factory, and silicon gates close.

### 2.3 Side-channel (bundle C → todo #18)

**Threat surface**: PRF(SK.seed) leaks the master secret via horizontal
DPA on unprotected Cortex-M33. Saarinen's CRYPTO 2024 SLotH paper
reports t-stat = 24.5 at 1000 traces — catastrophic leakage.

**Mitigations that stack**:

- **OptRand mandatory** (see section 1). Breaks determinism,
  prevents chosen-message PRF recovery.
- **Signing rate limit + 2^16 rotation**: 1 sig/sec, 500/day, hard
  rotate after 2^16 signatures per key. ERC-4337 wallets unlikely to
  exceed 100 sigs/day.
- **WOTS chain + FORS tree shuffling** via Fisher-Yates, TRNG-seeded.
  Negligible perf cost (<2%); breaks trace alignment for profiled DPA.
- **Zeroize + DSB barrier** after every signing call. Use `zeroize`
  crate; follow with `core::sync::atomic::compiler_fence(SeqCst)` +
  `__dsb(0xF)` to prevent SRAM residue.
- **GTZC peripheral lockdown**: lock HASH / RNG / SAES to secure
  privileged mode so non-secure world cannot DMA-snoop (BUSted!
  style attacks). Affects every NSC gateway entry.

**Architectural decision pending — SHAKE vs SHA2-256 parameter set**
(historical framing; see closing note below):

| | SLH-DSA-SHA2 | SLH-DSA-SHAKE |
|---|---|---|
| HASH peripheral support | Yes (not DPA-resistant per UM3370) | No (software SHAKE required) |
| Masking cost | 3-5× (inefficient on Cortex-M33) | 1.5-2× (cleaner) |
| PRF-tree (Fluhrer 2024) | No | ⚠ **Citation unverified** — see §3 |
| Backward compat with on-chain verifier | Tied to current contract | Requires contract change |

Recommendation: evaluate SHAKE migration before Stage 2 implementation.
If on-chain verifier can be parameterised, SHAKE is the materially-
stronger SCA posture.

**⚠ Caveat on SHAKE migration analysis**: the Fluhrer ePrint 2024/500
"PRF-tree with 1.7× overhead, backward-compatible" citation that
bundle C used to argue for SHAKE is **not verifiable** per the
2026-04-15 verification round (see §3). Treat the SHAKE-vs-SHA2
decision as open — do NOT commit to SHAKE on the basis of Fluhrer's
claimed overhead figure. Independent analysis of SLH-DSA-SHAKE-128f
performance + masking cost on Cortex-M33 is needed before this
decision is production-ready. The qualitative argument (SHAKE is
easier to mask than SHA-256) still holds; the specific 1.7× overhead
number does not.

> **Update 2026-04-30 (audit overlay).** The all-C10 cutover (commit
> `7b2a339`, 2026-04-17) locked the parameter set to **SPHINCS+C10 over
> SHA-256** (`sig_len = 4008 B`, `h=18, d=2, a=11, k=13, w=8, l=43,
> target_sum=205`). The on-chain verifier (`SPHINCsC10Asm.sol`) is
> SHA-256-only and reuses the EVM SHA-256 precompile. SHAKE migration is
> therefore deferred indefinitely — it would require a fresh on-chain
> verifier, fresh wallet addresses (CREATE2 salt depends on master keys),
> and a factory redeploy. The qualitative SCA argument still motivates
> independent masking work on the SHA-256 path, not a primitive swap.

**HASH peripheral**: **provides zero DPA protection** per UM3370.
Useful for performance (~66 cycles/block) and timing-channel elimination
only. Software countermeasures remain mandatory.

**Caveats on numerical claims**: the research cites "SLotH" and
"SLasH-DSA 2025" papers with specific trace-count numbers. Author
plausibility and paper existence confirmed for SLotH; exact TVLA
numbers and the SLasH-DSA paper remain unverified per §3. The
qualitative conclusion (unprotected Cortex-M33 leaks PRF(SK.seed)
catastrophically) is defensible; the specific trace-count bounds
should not be cited as pinpoint figures.

### 2.4 USB hardening (bundle D → todo #19)

**Threat surface**: only external interface; primary remote attack
vector. Host computer is untrusted by design.

**DWC2 silicon bugs (STM32U5 errata ES0499)**:

- **§2.26.x TxFIFO write atomicity**: CPU must not access any other
  endpoint's CSR between successive 32-bit pushes to one TxFIFO.
  Violation corrupts `DIEPTSIZx.XFRSIZ` to zero. Mitigation: single-
  packet transfers (`DIEPTSIZ.XFRSIZ = DIEPCTL.MPSIZ`); no interleaving
  in ISR.
- **§2.26.x ZLP race**: under specific SNAK/CNAK/EPENA timing the
  controller sends a stale TX-FIFO data packet instead of a ZLP,
  **leaking data from a different session**. Mitigation: enforce
  AHB-cycle delays in the SNAK/CNAK/EPENA sequence per errata; flush
  all FIFOs on USB reset via `GRSTCTL.RXFFLSH | GRSTCTL.TXFFLSH`
  with TXFNUM=0x10.

⚠ Research cited exact §2.26.3 and §2.26.2 section numbers. These are
**plausible but unverified** — confirm against the actual ES0499 PDF
before citing in code comments. Treat the concrete advice (sequence
SNAK/CNAK/EPENA, flush FIFOs on reset, atomic TxFIFO writes) as sound
regardless of exact section numbering.

**USB stack hardening patterns**:

- **FI-resistant `min()` everywhere a control-transfer length is
  clamped**. Pattern:
  ```rust
  fn fi_min(a: usize, b: usize) -> usize {
      let r = core::cmp::min(a, b);
      if r > a || r > b {
          return if a < b { a } else { b };
      }
      r
  }
  ```
  Defeats Colin O'Flynn USENIX WOOT 2019 EMFI-on-branch attack.
  Post-transfer verification: assert `DIEPTSIZ.XFRSIZ` did not exceed
  declared length.
- **Bounded APDU reassembly**: enforce `4 ≤ declared_len ≤ 4096` at
  seq=0; 5 s timeout with buffer scrub; abort if seq=0 arrives
  mid-reassembly (sets anomaly counter for diagnostics).
- **HID OUT rate limiter**: token bucket, ~200 reports/sec sustained,
  bucket 64. NAK endpoint when empty.
- **APDU CLA/INS allowlist** at non-secure *before* any NSC gateway
  call. Reject malformed APDUs before they cross the trust boundary.
- **Response-buffer locking** for 17,088-byte SLH-DSA signatures.
  Chunked via ISO 7816 `SW=0x61xx` (GET_RESPONSE), 30 s timeout,
  scrub on anything other than GET_RESPONSE arriving.

**Runtime config**:
- `OTG_GUSBCFG.FDMOD = 1` (device-only).
- `OTG_GINTMSK`: disable SOFM (timing side-channel), MMISM (OTG),
  PRTIM (host). Enable WUIM / OEPINTM / IEPINTM / ENUMDNEM / USBRSTM
  / USBSUSPM / RXFLVLM.
- FIFO sizing per RM0456 formula with ≥30% safety margin.
- IWDG 2 s timeout, kicked per USB transaction.

**NSC gateway hygiene** (every command):
1. `cmse_check_address_range` on every NS pointer.
2. Copy-in to secure SRAM (TOCTOU defense).
3. Process secure copy, never trust original.
4. Copy-out result if needed.
5. Clear all registers before BXNS return.

**OTG_FS architectural advantage**: no DMA engine. All USB data is
CPU-mediated → TrustZone/GTZC memory protections apply to every byte.
Do NOT migrate to OTG_HS without re-doing the threat analysis — HS has
DMA and loses this property.

⚠ **Hallucination flagged**: the research cites `CVE-2026-4179` for a
"Zephyr STM32 USB device driver infinite loop." No such CVE exists in
the National Vulnerability Database as of the research cutoff — the
format is right but the ID is fabricated. Do **not** reference this
CVE in code comments or public docs. The structural advice (IWDG
timeout, bounded reassembly, rate limiter) stands regardless.

### 2.5 Supply-chain attestation (bundle E → todo #22)

Bundle E surfaces a **triple-UID binding manifest** as the load-bearing
defence — no shipping wallet currently does this, and it closes the
single-chip-replacement attack surface that has bitten every existing
wallet (Trezor Safe 3 via Ledger Donjon glitch on the STM32-OPTIGA
pre-shared secret; Ledger Snake demo via arbitrary MCU code while SE
attestation passed; ColdCard via firmware factory-reset without
changing the tamper bag). Bundle B (§2.2) already specified per-device
SCP03 rotation + OPTIGA PBS lock + ECDSA-P256 binding record; bundle E
**extends** that with SLH-DSA manifest replacement, firmware-hash
inclusion, transparency log, and a WebUSB user-verification ceremony.

**What Bundle E adds on top of Bundle B:**

1. **SLH-DSA-128s factory manifest** replaces Bundle B's ECDSA-P256
   binding record. Post-quantum resistant; signature is ~7.8 KB
   (fine — it's stored once, read on every boot). The factory HSM
   signing key runs through an M-of-N ceremony with geographically
   distributed shares.
2. **CBOR manifest schema** with explicit fields:
   ```
   {
     manifest_type:        "PQS-BIND-v1",
     se050_uid:            <18 B from SE050 IDENTIFY>,
     optiga_uid:           <27 B from OID 0xE0C2>,
     stm32_uid:            <12 B from 0x0BFA_0590>,
     firmware_hash:        SHA3-256(firmware_image),   // NEW vs Bundle B
     firmware_version:     <monotonic counter>,
     device_serial:        SHA3-256(se050_uid || optiga_uid || stm32_uid),
     production_ts:        <ISO 8601>,
     manifest_version:     1,
     factory_pubkey_fp:    SHA3-256(factory_pubkey)[:16]
   }
   ```
   Firmware-hash inclusion means the manifest also acts as a measured-
   boot anchor — ties chip identity to a specific firmware build.
3. **SE050 boot-time attestation** via `Se05x_API_ReadObject_W_Attst`
   with caller-supplied 16-byte freshness nonce. Returns 18-byte
   chipId + ECDSA-SHA256 signature over response. Verify signature
   chains to NXP root CA. ⚠ **Variant constraint**: only SE050 C/E/F
   have pre-provisioned attestation certs at OID `0xF0000013`; variants
   A/B/D have keys but no cert. Confirm we're on C/E/F before relying
   on attestation.
4. **OPTIGA boot-time attestation** via `optiga_crypt_ecdsa_sign` with
   key at OID `0xE0F0`, cert read from OID `0xE0E0`, chains to
   Infineon OPTIGA ECC Root CA 2. Same freshness nonce across both SEs.
5. **STM32U585 anti-counterfeit probes** at boot (detect remarked
   chips / clones):
   - CPUID / DBGMCU_IDCODE — expect Cortex-M33 r0p4, DEV_ID `0x482`.
     Read at `0xE0044000`.
   - UID register at `0x0BFA_0590`: validate lot bytes are printable
     ASCII (`0x20`..`0x7E`), wafer number < 25, UID not all-0 or
     all-0xFF.
   - DHUK probe via SAES: run a DHUK-gated op, verify output against
     factory-recorded expected value.
   - Errata fingerprinting: `DBGMCU_DBG_AUTH_DEVICE.AUTH_ID` reads
     zero at RDP0 (documented silicon quirk); a clone "fixing" this
     outs itself. MSI-frequency low-drift (up to 25%) and ICACHE/
     DCACHE behavior on Stop mode exit are mask-specific.
   - Flash ECC: AN5342 documents SEC-DED; test last-64KB-block of
     SRAM3 behavior.
6. **Transparency log**: append-only record of every device serial +
   manifest hash. Published (Merkle-anchored per the research's
   suggestion; exact scheme TBD). Enables detection of rogue
   production runs — any device with valid manifest but missing from
   log fails the ceremony, even if factory HSM is compromised.
7. **WebUSB box-opening ceremony** at `verify.pqsigner.io`:
   - Browser sends fresh random challenge via WebUSB.
   - Both SEs sign it (SE050 with NXP-attested key; OPTIGA with
     Infineon-attested key).
   - Website verifies both signatures independently chain to their
     respective pinned root CAs, and that the UIDs match the binding
     manifest, and the manifest's SLH-DSA signature verifies against
     the published factory pubkey.
   - Customer sees green-checkmark + device serial without installing
     any tool.

**Boot-time verification ceremony** (runs in secure world before
entropy reconstruction):
1. Read STM32 UID from `0x0BFA_0590`.
2. Load binding manifest from secure flash.
3. Verify SLH-DSA-128s signature with factory pubkey (stored in
   write-protected OTP).
4. Compare manifest.stm32_uid against hardware. Halt on mismatch.
5. Probe SE050 (I2C addr `0x48`, IoT applet AID), attested read with
   fresh nonce, extract chipId. Compare against manifest.se050_uid
   AND against SE050's own signed chipId. Halt on mismatch.
6. Probe OPTIGA (I2C addr `0x30`), read UID from `0xE0C2`, ECDSA-sign
   same nonce with `0xE0F0`. Compare to manifest.optiga_uid. Halt.
7. Compute SHA3-256 of firmware image; compare to
   manifest.firmware_hash. Halt on mismatch.
8. Check monotonic anti-rollback counter (from Bundle B).
9. Set ATTESTATION_PASSED; proceed to normal boot.

Failure at any step → permanent lockdown: neither SE releases entropy
half; USB reports specific failure reason (manifest invalid / UID
mismatch / firmware hash mismatch / etc.).

**Hallucination flags from Bundle E** (fold these into the verification
log in §3 below):

- **"Ledger Donjon March 2025 attack on Trezor Safe 3"** — cited as
  justification for the Tier B threat tier but no link / ticket /
  blog post reference. Future-dated relative to the AI's training
  cutoff (Feb 2025). **Treat as unverified**; the technical threat
  model holds regardless but this specific attack should not be cited
  as proof without verification.
- **"Trezor Safe 7"** — claimed to add TROPIC01 for dual attestation.
  Does not exist as a shipping product as of knowledge cutoff. Safe 5
  is the current Trezor flagship. **Omit from comparison tables**
  until it actually ships.
- **"Masaryk University 2024/2025 thesis by Oliver Simonik"** — 76%
  PIN-glitch on STM32U5A9. Plausible but unverified (no link /
  repository citation).
- **"BlaatSchaap research"** on STM32F103 clone detection — plausible
  but unverified pseudonymous researcher.
- **"TheCharlatan May 2020 ColdCard firmware-reset attack"** —
  plausible but unverified (no link).
- **ES0499 specific bit positions** cited in the chip-ID probe list
  (`AUTH_ID` bitfield behavior at RDP0, MSI frequency anomaly) —
  plausible but unverified; cross-check against current ES0499 PDF
  before implementing.
- **STM32U5 clone "do not exist as of early 2025"** — properly
  hedged as absence-of-evidence rather than evidence-of-absence.
  Treat as current best-available assessment, not a guarantee.

**ECDSA vs SLH-DSA binding signature decision**:
Bundle B used ECDSA-P256 for the binding record because it's small and
SE050/OPTIGA can do it natively. Bundle E argues SLH-DSA-128s is more
defensible long-term (PQ-resistant, no key-extraction from factory HSM
via Shor). Since we're already computing SLH-DSA on the MCU for
transaction signing, adding SLH-DSA verification of the manifest at
boot is free. Recommendation: **go with Bundle E's SLH-DSA manifest**;
retire Bundle B's ECDSA binding record design. This is a material
change to work-todo #20 scope.

### 2.6 Device root-key architecture (work-todo #24)

> **Current-state override (2026-07-14).** This section preserves the
> historical failure analysis and staged proposal; it is not the current page
> map or an implementation plan. The factory-burned OTP master derives only
> transport credentials. The candidate final OPTIGA PBS derives from DHUK plus
> the page-127-persisted TRNG salt and has no secret flash copy. Bank-1 page 126
> is exclusively the DHUK-wrapped SE050 BHK when `bhk` is enabled, and no
> persistent firmware-update failure counter remains. The historical route
> below that reused the OTP master as a final root is rejected for production.
> Current lifecycle and rollback authority stays with the `EthereumPhone/PQ1`
> production items (label `source:production-todo`), `docs/STATUS.md`, and the
> production-fenced rollback architecture record.

**Threat context.** The OPTIGA Trust M pairing-secret flow that landed
during early bring-up (`setup_pbs_no_handshake`, `hw/huk.rs`, flash page
126) has a concrete reliability failure: every legitimate firmware
update bricks the device. The bench chip that surfaced this is
permanently unpaired for Shielded Connection. Fixing the underlying
root-key architecture before silicon ships is a production gate.

Full root-cause analysis: `docs/secure-elements/optiga-brick-postmortem.md`.

**The bug in two sentences.** The Platform Binding Secret is generated
from the STM32 TRNG and persisted to flash page 126 under an AES-256-
GCM seal whose wrap key mixes in `measured_boot::firmware_hash()`. Any
firmware rebuild — a one-byte diff is enough — changes the hash,
changes the key, fails GCM authentication on next boot, leaves the
chip-side PBS (which is locked at LcsO=Operational) reachable only to
a PBS value the MCU can no longer reconstruct. One-way brick of the
bus-encryption path.

**Architectural response — Trezor's layered root-key model on STM32U5.**

Reading `~/repos/trezor-firmware/core/embed/sec/{secret_keys,secret,
secure_aes}/stm32u5/` shows Trezor stacks three keys:

| Layer | What | When generated | Software access | Survives FW update |
|---|---|---|---|---|
| **DHUK** | Factory-fused 256-bit per-chip key in ST silicon | At wafer test (ST) | SAES-only (`CRYP_KEYSEL_HW`); never in memory | Yes |
| **BHK** | 32 B of device TRNG in HDP-protected flash page, loaded into TAMP backup registers at boot | First boot, on-device | SAES-only after `TAMP_SECCFGR.BHKLOCK`; software can't read post-boot | Yes (regeneration = factory reset) |
| **OTP master** | 32 B of device TRNG in flash OTP block | First boot, on-device (`secret_keys.c:177-194`) | Readable by secure-world firmware | Yes (OTP is permanent per silicon) |

> **PQSigner current state (2026-07-20):** the BHK row above is Trezor's
> architecture; in PQSigner the HDP hide-protect layer is *deferred*, not
> current. The ship profile leaves HDP disabled (`HDP1EN = HDP2EN = 0`;
> nothing in `secure/src` writes `SECWM1R2`/`SECHDPCR`, and
> `verify_ship_profile` has no HDP field), so the implemented
> `bhk`-feature BHK sits in *ordinary* bank-1 flash page 126
> (`0x0C0F_C000`), DHUK-wrapped — a flash dump exposes only the wrapped
> blob. HDP1 (enable + `HDP1_PEND` covering the FSBL + `HDP1_ACCDIS` at
> boot-exit) is the tracked deferred item (`EthereumPhone/PQ1` issue #39);
> when it lands it also joins `verify_ship_profile`.

Trezor derives per-purpose keys (OPTIGA pairing, TROPIC01 pairing,
storage salt, NRF auth, MCU device-auth) from the OTP master via HMAC.
The DHUK and BHK additionally encrypt the OTP master and other secrets
at rest in the "secret" flash page, so a flash dump alone doesn't leak
raw key bytes.

**Our staged adoption plan.**

*Stage 1 — OTP-derived master with HKDF subkey layer* (this doc
landing + current implementation). Reserve bytes 128..160 of STM32U585
OTP (two quad-words past the rollback tally) for a 32-byte device
master key. On first secure-world boot, if the region is unburned,
fill 32 bytes from STM32 TRNG and program (irreversible). On every
subsequent boot, `read_device_master` returns those 32 bytes. A new
`secure/src/hw/secret_keys.rs` exposes domain-labelled HKDF-SHA256
subkeys: `optiga_pairing_secret`, `se050_scp03_enc_key`,
`se050_scp03_mac_key`, `tropic01_pairing_key`. `setup_pbs_no_handshake`
consumes `optiga_pairing_secret` instead of `rng::fill`; the flash-
page-126 AES-GCM seal is deleted outright. `hw/huk.rs::derive_device_
key` re-roots off the OTP master — the line that reads `h.update(&fw_
hash)` becomes `h.update(&hw::otp::read_device_master())`. `measured_
boot::firmware_hash()` is preserved unchanged: it still drives the 8-
BIP-39-word OLED attestation and will feed the #22 supply-chain
manifest; it just stops being an input to wrap-key derivation. Closes
the brick scenario.

*Stage 2 — SAES + BHK uplift* (merges with work-todo #7 HUK-SAES).
Port Trezor's BHK pattern: first-boot TRNG into an HDP-protected flash
page, load into TAMP backup registers at boot, set `TAMP_SECCFGR.BHKL
OCK` so secure-world code can only *use* the key via SAES, not read
it. Wrap the OTP master with DHUK at rest so a chip decap alone
doesn't yield the raw bytes. The `secret_keys::*` API surface stays
unchanged — OPTIGA / SE050 / Tropic drivers do not move.

**Why first-boot self-provisioning beats a factory-burn workflow** for
an open-source wallet: the TRNG output only ever exists on the user's
own hardware, never passes through the vendor's hands, and the factory
does not need to hold or protect any per-device secret. The customer
can independently verify on unboxing that OTP is still unburned before
powering the device up, which is a stronger property than trusting a
factory tamper-evident bag. This matches Trezor's `flash_otp_is_locked
? read : (fill + write + lock)` pattern exactly (`secret_keys.c:177-
194`). The residual supply-chain concern is that "first boot" must
happen on a device running our signed firmware — otherwise an attacker
who intercepts the device pre-first-boot could flash a key-exfiltrating
stub, boot once to capture TRNG, then restore the real firmware.
Defence stack: secure boot (work-todo #13) + tamper-evident packaging
+ a user-side verification script that confirms the binding manifest
(work-todo #22) matches the device before first power-on.

**Testing posture — hardcoded key during bring-up.** Until we are
confident the derivation is stable across rebuilds, we do *not* want
to burn real OTP on our dev bench. `secure/Cargo.toml` gains an
`otp-hardcoded-master-key` Cargo feature, OFF by default. When
enabled, `read_device_master` returns a fixed 32-byte constant
(deliberately distinctive byte pattern so it cannot be confused for a
real key in logs), `is_device_master_burned` returns true, and
`ensure_device_master` is a no-op. A loud boot-time warning via
`secure_log!` flags the insecure configuration. A `compile_error!`
guard fails the build if the feature is set without `debug-log` or
`e2e-test` also enabled (i.e. on a production profile). Flip the
feature off and the first-boot TRNG path takes over. We validate end-
to-end on a fresh OPTIGA chip only after the hardcoded path is proven
stable across reflashes with differing firmware hashes.

**Extraction cost across layers.**

| Attacker capability | Stage-1 OTP master | Stage-2 OTP master under SAES | Stage-2 BHK post-lock |
|---|---|---|---|
| Secure-world RCE, read memory | Reads the 32 bytes directly via `read_volatile(0x0BFA_0080)` | Same — OTP remains plain-readable; DHUK wrap protects only at rest | Cannot read; can only USE via SAES on this device |
| Flash-dump + transplant to second board | UID of target board is wrong → derived keys wrong anyway; not viable | Same, with DHUK also wrong → ciphertext undecipherable on target | Same, and BHK never lived in transferable flash |
| Debug port after RDP regression | OTP survives RDP regression | Same | BHK regeneration on RDP2→0 wipes TAMP-backed key |
| Decap + microprobe OTP cells | Feasible ($10–100K, destructive, single device) | Same, then attacker still needs DHUK from silicon | BHK lives transiently in TAMP; substantially harder |
| Supply-chain attacker between factory and user | No key on-device yet; attacker can substitute their own TRNG | Same | Same |

Stage 1 solves the brick. Stage 2 additionally raises the bar from
"secure-world RCE = remote key exfiltration" to "attacker must keep
running code on *this specific device* for every signature they want
to forge" — a qualitative change in the attacker cost model.

**Files touched in Stage 1.**

- `secure/src/hw/otp.rs` — add `read_device_master`, `burn_device_
  master`, `is_device_master_burned`, `ensure_device_master`.
- `secure/src/hw/secret_keys.rs` *(new)* — HKDF-SHA256 wrappers.
- `secure/src/hw/mod.rs` — register `secret_keys` module.
- `secure/src/hw/huk.rs` — swap `firmware_hash` → OTP master in
  `derive_device_key`.
- `secure/src/optiga/mod.rs` — rewrite `setup_pbs_no_handshake`,
  simplify `load_pbs`.
- `secure/src/hw/flash.rs` — delete `read_pbs` / `write_pbs` /
  `erase_pbs_page` / `PBS_PAGE_ADDR` / `PbsLoadError` / `PBS_WRAP_
  DOMAIN` / `PBS_BLOB_LEN` / `is_pbs_blank`.
- `secure/Cargo.toml` — drop `optiga-bringup-fresh`, add `otp-
  hardcoded-master-key`.
- `secure/src/measured_boot.rs` — unchanged (keeps driving OLED
  attestation + #22 manifest).

### Empirically validated: SE PIN gate survives a DHUK/BHK leak

The full threat-model claim — "a DHUK leak (or, post-Phase-2C, a BHK
leak) does not drain funds because the user PIN gate is enforced in
SE silicon, not by the encrypted channel" — is now backed by a
falsifiable hardware test rather than just a code review.

`run_admin_extract_attempt` (`secure/src/se050/mod.rs`) provisions an
isolated test sentinel on OID range `0x7B0B_xxxx` under the same
two-entry `TAG_POLICY` template the production code uses for half_E
(`apdu::build_policy`, `se050/apdu.rs:339-365`):

- user entry: `READ | WRITE | DELETE | REQUIRE_SM`
- admin entry: `DELETE | REQUIRE_SM` (no `READ` bit)

The test then opens an admin session (with the admin PIN that is, in
the threat model, recoverable from a DHUK leak), authenticates
successfully against the chip, and:

1. attempts to READ the sentinel — the chip refuses with
   `SW=0x6986` ("security status not satisfied"),
2. immediately DELETEs all three objects in the same session — the
   chip accepts, proving the refusal in step 1 was a genuine read-
   deny and not bogus authentication.

Validated 2026-05-11 on B-U585I-IOT02A board #1 (ST-LINK SN
`0029…3838`) via `make se050-admin-extract-attempt-e2e`. Semihosting
trace ends with:

```
[E2E-EXTRACT] step 4: admin-auth read REFUSED (Status(27014)) — security property holds
[E2E-EXTRACT] step 5: admin-auth delete OK (admin session was genuinely admin → step 4 refusal was a real READ deny, not bogus-auth)
[E2E-EXTRACT] PASS: admin can DELETE but NOT READ user-PIN-gated secrets
```

Operational implication of this finding: a DHUK leak (or future BHK
leak) gives the attacker the SE050 admin PIN, which lets them
**brick** a stolen wallet (delete the seed half — DoS only) but not
**extract** funds. To extract, they still need 1-in-1,000,000 luck
on the user-PIN gate before the SE auto-bricks at the 10-attempt
cap. The test is repeatable and should run in CI on any commit
touching `secure/src/se050/apdu.rs` so that an accidental
`AR_ALLOW_READ` bit added to the admin policy entry fails the build
loudly rather than silently regressing the threat model. The
OPTIGA side (`half_O` gated by `Auto(F1D0)` AuthRef, where E140/PBS
authenticates the channel but does not satisfy the read AC) is a
different mechanism with the same property and is not yet covered
by an analogous E2E.

## 3. Hallucination + verification log

The research-round prompts told the AI to cite primary sources and
say "I don't know" rather than guess. Across the 5 responses, here's
the status of every flagged citation — after a 2026-04-15 verification
round of web searches.

**Lesson learned from this verification round**: most of our initial
hallucination-flagging was wrong. We called items hallucinated because
they were future-dated relative to our own model's training cutoff;
they were actually real publications from after the cutoff. Be less
aggressive flagging things as fabricated in future rounds — verify
first, flag second.

| Claim | Source | **Verification status (2026-04-15)** | Action |
|---|---|---|---|
| `CVE-2026-4179` (Zephyr STM32 USB infinite loop) | bundle D | ✅ **REAL**. Published 2026-03-16. Zephyr advisory `GHSA-9xg7-g3q3-9prf`, CWE-835, CVSS 6.1. Affects Zephyr ≤ 4.3.0 drivers/usb/device/usb_dc_stm32.c. | Safe to cite. Note advisory is about `usb_write()` from ISR + `k_yield()`, not explicitly malicious USB host — read the GHSA before re-describing. |
| `CVE-2021-42553` (STM32Cube USB Host buffer overflow) | bundle D | ✅ **REAL**. NVD, CVSS 9.8 CRITICAL. | Safe to cite. |
| **RFC 9814** (SLH-DSA verify-after-sign inadequate) | bundle A | ✅ **REAL**. Proposed Standard, July 2025. §5 quote: *"Verifying a signature before releasing the signature value is a typical fault-attack countermeasure; however, this countermeasure is not effective for SLH-DSA."* | Safe to cite — directly supports the double-compute mandate. |
| NXP **AN12436** SCP03 default keys (ENC/MAC/DEK) | bundle B | ✅ **REAL**. Latest revision is Rev 2.4 (8 July 2024). All three hex values match byte-for-byte against earlier retrievable rev 1.6. | Safe to cite. |
| STM32U5 **errata ES0499** existence | bundle D | ✅ **REAL**, Rev 11 (December 2025) current. §2.2.15 confirmed verbatim ("OTG_FS is reset by OTGRST and DCMI_PSSIRST bits"). | Cite ES0499 safely. |
| ES0499 specific sub-section numbers (§2.26.2, §2.26.3, §2.26.4, §2.26.5) | bundle D | 🟡 **Partially verified.** USB OTG errata is indeed in ES0499; exact sub-section numbering could not be confirmed from public search snippets. May have shifted between revisions. | Download Rev 11 and pin citations to it before quoting section numbers in code. |
| **AN5342** (Flash ECC / SRAM ECC option bytes) | bundle A | ✅ **REAL**. Title: "How to use ECC management for internal memories protection on STM32 MCUs." Originally STM32H7-focused, broadened to multi-series. | Cite safely. Some STM32U5-specific ECC detail lives in RM0456 rather than AN5342; open current AN5342 to confirm U585-specific option-byte wording. |
| **RM0456** covers SAES peripheral | bundle B | ✅ **REAL**. Confirmed. | Safe to cite. Pin latest revision number when writing code against specific bit fields. |
| STM32U585 SAES bit fields (KEYSEL / KMOD positions) | bundle B | 🟡 Research author explicitly flagged as unknown; confirmation not attempted in this verification round. | Cross-check CMSIS `stm32u585xx.h` before writing SAES code. |
| **Ledger Donjon March 2025 Trezor Safe 3** glitch | bundle E | ✅ **REAL**. Blog post dated March 12, 2025 at `ledger.com/why-secure-elements-make-a-crucial-difference-to-hardware-wallet-security`. TRZ32F429 voltage-glitched, pre-shared secret extracted from flash, firmware attestation bypassed. Trezor's own confirmation at `trezor.io/vulnerability/donjon-s-trezor-safe-3-evaluation`. | Safe to cite. |
| **Trezor Safe 7** with TROPIC01 | bundle E | ✅ **REAL**. Announced October 21, 2025 (`trezor.io/trezor-safe-7`; `tropicsquare.com/news-and-events/...trezor-safe-7`). Shipping late 2025 / early 2026. Transparent secure element + EAL6+ secondary SE (dual attestation). | Safe to cite. This is the closest existing product to our PQSigner OS architecture. |
| **Trezor Safe 5** uses STM32U5 | bundle E | ✅ **REAL**. Confirmed via Trezor product page + Ledger blog. | Safe to cite. |
| Ledger Donjon 2025 statement that "no public fault injection attack on STM32U5" | bundle E | ✅ **REAL**. Exact quote in the Ledger blog post (`ledger.com/why-secure-elements-make-a-crucial-difference...` March 12, 2025). Note: **already superseded by the Simonik thesis** below. | Safe to cite, but qualify that it was true as of publication and has since been invalidated. |
| **Masaryk U Simonik thesis** 76% PIN-glitch on STM32U5A9 | bundle A / C / E | ✅ **REAL**. Bachelor's thesis by Oliver Simonik at Masaryk U on fault injection against STM32U5 (Trezor Safe 5). Referenced at `it4sec.substack.com/p/fault-injection-attack-on-the-stm32u5`. Thesis PDF on `is.muni.cz` (not directly retrieved this round — verify the URL before quoting page numbers). | Safe to cite. This is the empirical demonstration that STM32U5 is **not** glitch-immune. |
| **BlaatSchaap** STM32F103 clone research | bundle E | ✅ **REAL**. `blaatschaap.be/identifying-32f103-clones/` + multi-part Cortex-M series. Uses CPUID/ROMTABLE differences. Specific r2p1 vs r1p1 exact revision strings not confirmed this round. | Safe to cite for the approach; verify exact revision strings against primary source. |
| **TheCharlatan May 2020 ColdCard firmware-reset** | bundle E | ✅ **REAL**. `thecharlatan.ch/COLDCARD-Supply-Chain/`. | Safe to cite. |
| **Saleem Rashid 2018 Ledger Nano Snake demo** | bundle E | ✅ **REAL**. `saleemrashid.com/2018/03/20/breaking-ledger-security-model/`; Krebs on Security coverage. | Safe to cite. |
| **wallet.fail at 35C3** | bundle D | ✅ **REAL**. `media.ccc.de/v/35c3-9563-wallet_fail`. December 2018 CCC. | Safe to cite. |
| **SiliconToaster** (Ledger Donjon EMFI tool) | bundle D / E | ✅ **REAL**. `github.com/Ledger-Donjon/silicon-toaster`, LGPLv3, Hardwear.io 2020 paper (`eprint.iacr.org/2020/1115`). | Safe to cite. |
| **"Extraktor" Ledger Donjon ~$100 glitch board** | bundle D | ❌ **Cannot confirm** this specific tool name. Not found in Donjon's public repos / blog. Likely misremembering of SiliconToaster (which *is* real) or a non-public internal tool. | Do **not** cite "Extraktor" by name; say "published Ledger Donjon glitching tooling" if referring to the general capability. |
| **CanSecWest 2024 / VoidStar STM32F4 RDP bypass** | bundle D / E | ✅ **REAL**. Matthew Alt (VoidStar Security LLC), talk title "Glitching in 3D: Low-Cost EMFI Attacks." `secwest.net/presentations-2024/glitching-in-3d-low-cost-emfi-attacks`, `voidstarsec.com`. | Safe to cite. |
| "Riscure LFI on ColdCard" | bundle D / E | 🔴 **Attribution WRONG.** The ColdCard Mk2 ATECC508A single-laser-shot + Mk3 ATECC608A multi-shot attacks were done by **Ledger Donjon (Olivier Hériveaux)**, NOT Riscure. See `blog.coinkite.com/laser-fault-injection/`, SSTIC 2020/2021 papers, `ledger.com/blog/coldcard-pin-code`. | Correct attribution when citing. Research content is correct; credit is wrong. |
| **Colin O'Flynn "MIN()imum Failure" USENIX WOOT 2019** | bundle D | ✅ **REAL**. Safe to cite. |
| **Thomas Roth TrustZone-M on SAM L11 at 36C3** | bundle D | ✅ **REAL**. `media.ccc.de/v/36c3-10859-trustzone-m_eh...`. |
| **Saß et al. μ-Glitch USENIX Security 2023** | bundle A | ✅ **REAL**, 4-fault TrustZone-M bypass demonstrated. Safe to cite. |
| **Spensky et al. GlitchResistor DSN 2021** | bundle A | ✅ **REAL**. Specific "100% success at 8-cycle window" figure not reverified, but paper exists and characterises success rates in this ballpark. |
| **Genêt "Grafting Trees" TCHES 2023** | bundle A | ✅ **REAL**. Paper by Aymeric Genêt, TCHES 2023, single-fault universal-forgery via grafting subtree into SPHINCS+ hypertree. Safe to cite; this is the canonical reason verify-after-sign doesn't save SLH-DSA. |
| **Kannwischer et al. COSADE 2018** (DPA on SPHINCS-256 BLAKE) | bundle C | ✅ **REAL**. Springer LNCS 10815. ~10k traces for 32-bit chunk is consistent with paper. |
| **Saarinen "SLotH" CRYPTO 2024** + specific TVLA numbers (t=24.5 at 1k traces) | bundle C | 🟡 Saarinen's work on PQC side-channels is real. The specific SLotH paper title + exact numerical claims could not be independently confirmed in this verification round. | Verify against the actual paper before committing architectural decisions that depend on the trace-count figure. |
| **Fluhrer ePrint 2024/500** — PRF-tree 1.7× overhead, backward-compat | bundle C | ❌ **Does not exist as described** per verification agent. The claim "backward-compatible PRF-tree" is technically implausible — changing PRF tree structure changes verification output. | **Do not base architectural decisions on this citation** until verified. Treat SHAKE migration discussion as open question pending an independent reference. |
| **Belenky et al. TCHES 2023 / COSADE 2021** specific trace counts (275K / 30K) | bundle C | 🟡 Author works on side-channels; specific trace counts unverified. | Treat as indicative rather than pinpoint benchmarks. |
| **Boy et al. "SLasH-DSA 2025" Rowhammer universal forgery** | bundle A / C | 🟡 **Uncertain.** Post-May-2025 cutoff. OpenSSL SLH-DSA support shipped in OpenSSL 3.5 early 2025, so an attack paper in 2025 is plausible, but neither we nor our verification agents could confirm its existence. | Do not cite until independently found. The underlying Rowhammer-vs-PQ-signing threat class is real regardless. |
| **Fox-IT AES-256 EM attack** (5 min at 1 m) | bundle C | ✅ **REAL**. Fox-IT whitepaper by Ramsay & Van Woudenberg, 2017. Safe to cite. |
| **Kraken Security Labs Trezor glitching** ($75, 15 min) | bundle D | ✅ **REAL**. January 2020 disclosure. Safe to cite. |
| **NCC Group "CM-1-C" pattern label** | bundle A | 🟡 NCC Group's multi-part fault-injection-countermeasures series is real (`research.nccgroup.com/2021/07/08/software-based-fault-injection-countermeasures-part-2-3/`) and covers complement-storage + redundant-check patterns. The specific "CM-1-C" identifier could not be located. | Cite the NCC Group series by URL; do not cite "CM-1-C" by name. |
| **MCUboot magic constants 0x1AAA_AAAA / 0x1555_5555** | bundle A | ✅ **REAL**. Documented in MCUboot design docs; values chosen specifically for fault-injection hardening. Safe to cite. |
| **Ringzer0 PicoEMP STM32F4 RDP bypass** | bundle D | 🟡 PicoEMP (by Colin O'Flynn / NewAE) is real; STM32F4 RDP EMFI bypasses exist; specific claim of "Ringzer0 + PicoEMP + 3D printer automated scanning" could not be tied to a specific publication. | Cite PicoEMP generically; don't invent specific research attributions. |

**Bottom line**: of the 30+ technical references in the 5 research
bundles, fewer than a handful are actual hallucinations. The round
was more accurate than my initial skepticism suggested. Going
forward: verify-then-flag, not flag-then-verify.

## 4. Implementation sequencing

See todo items #18-24 for the full work list. Suggested phasing:

**Phase 0 — Device root-key architecture (todo #24)** — ~3 days
Land `hw/otp.rs` master-key API (read / burn / ensure) + `hw/secret_
keys.rs` HKDF subkeys + OPTIGA `setup_pbs_no_handshake` rewrite +
`hw/huk.rs` re-root off `firmware_hash`. Delete `PBS_PAGE_ADDR` flash-
seal infrastructure and the `optiga-bringup-fresh` Cargo feature.
Closes the production-breaking firmware-update brick (§2.6). Unblocks
#7 (HUK-SAES) and #20 (factory provisioning) downstream. Initial
testing under `otp-hardcoded-master-key`; real OTP burn proven on a
fresh OPTIGA shield before this phase is considered complete.

**Phase 1 — Stage 2 brownout foundation (todo #21)** — ~1 week
Landing BOR/IWDG/ECC/PVD/TAMP/CSS at factory defaults to secure config.
Everything that follows depends on this.

**Phase 2 — SCA mandatory-minimums (todo #18 P0 items)** — ~1 week
OptRand + double-compute + FihInt + PIN lockout fail-in. No SHAKE
migration yet; it's the architectural question for Phase 4.

**Phase 3 — USB hardening (todo #19)** — ~1 week
FI-resistant min + bounded reassembly + rate limiter + DWC2 errata
workarounds. Independent of Phases 1-2.

**Phase 4 — Architectural decision: SHAKE vs SHA2** — design work,
not code. Requires on-chain verifier assessment. Blocks the final
SLH-DSA parameter pin for production.

**Phase 5 — Production key management (todo #20)** — ~2-3 weeks
Host-side provisioning tooling, two-stage RDP flow, binding record,
anti-swap boot verification. Largest single item.

**Phase 6 — Run bundle E + apply findings (todo #22)** — TBD
Supply-chain attestation; likely augments Phase 5.

Total ≈ 6-8 weeks of focused work to reach production-ready security
posture, excluding the on-chain verifier work for a SHAKE migration.

## 5. What this doc is NOT

- Not a code specification — see the `EthereumPhone/PQ1` issue tracker
  (label `source:work-todo`) for actionable tasks, and the code itself once
  implemented.
- Not a threat model — see `docs/security/HARDENING.md` and `CLAUDE.md`
  invariants. This doc documents *mitigations* surfaced by research,
  not the overall threat taxonomy.
- Not a replacement for primary-source documentation — every register
  name / protocol detail cited here should be verified against ST
  RM0456, NXP UM11225, Infineon OPTIGA Trust M User Manual, etc.
  before code lands. The research gave us direction; the primary
  sources give us correctness.

