# Flash geometry v7 — DRAFT for adversarial review

**Status: DRAFT. Not approved, not implemented, not ratified.** Supersedes nothing
until the dual review and owner ratification that `docs/security/a-b-firmware-rollback-architecture.md`
requires, and a new specification digest replacing Draft 1.1's `abc058b1`.

Author: Claude, 2026-09-24, at the owner's direction. Layout shape "B" (symmetric —
one complete secure slot per bank) chosen over "A" (bank 1 unchanged) on 2026-09-24.

---

## 1. Why v7 exists

The owner has decided the **pixel UI ships**, replacing the 16×4 text trusted display.
Measured on this branch:

| | bytes |
|---|---:|
| ship-shaped secure image WITHOUT `ui-px` | 432,873 |
| ship-shaped secure image WITH `ui-px` | 543,893 |
| secure slot today (`SECURE_SLOT_SPAN`) | 466,944 |
| `PX_HEADROOM_MIN` | 40,960 |

`ui-px` costs **111,020 B**. No code-size lever closes the gap: an ERC-7730 native
emitter nets ~8 KB and was rejected for degrading a WYSIWYS binding; `sha2` at
`opt-level="s"` measured 4,556 B; the BIP-39 `WORDLIST` experiment saved **0** bytes.

**The 543,893 B is a LOWER BOUND and cannot currently be improved on.**
`PX_SHIP_FEATURES` excludes `mode-production` and `rdp2-self-lock`, and neither can be
compiled today (`RDP2_SELF_LOCK_REQUIRES_MODE_PRODUCTION`, and `mode-production` itself
is stopped by `FW_ROLLBACK_PRODUCTION_BLOCKED`). The measured ELF contains **zero
`first_boot` symbols** against 1,782 lines of mandatory first-boot/self-lock source.
Estimated true ship image: **~560–570 KB, unmeasurable until the rollback quarantine
closes.** Every figure below budgets 570,000 B.

## 2. Why this is urgent and irreversible

RDP-2 freezes `SECWM1`/`SECWM2`/`WRP` permanently (RM0456 §7.4.2). `SWAP_BANK` is
excepted from the freeze and an OEM2 key would permit authenticated regression — **this
project provisions no OEM2 key.** So no die that has self-locked can ever receive a
different geometry. Nothing has shipped; this is free today and impossible afterwards.

## 3. The map

8 KiB pages, 128 per bank. Bank 1 secure alias `0x0C00_0000`; bank 2 secure alias
`0x0C10_0000` (contiguous). Bank 2 NS alias `0x0810_0000`.

### Bank 1

| pages | n | owner | attr |
|---|---:|---|---|
| 0–4 | 5 | FSBL (copy 1) | SECURE |
| 5 | 1 | Manifest A | SECURE |
| 6 | 1 | Route-1 journal A | SECURE |
| 7 | 1 | Off-chain counter journal | SECURE |
| 8 | 1 | MCU PIN-attempt state | SECURE |
| 9 | 1 | Admin-wipe / duress flag | SECURE |
| 10 | 1 | Wrapped BHK | SECURE |
| 11 | 1 | First-boot provisioning journal | SECURE |
| **12–111** | **100** | **Secure slot A** | SECURE |
| 112–127 | 16 | NS slot A | NON-SECURE |

`SECWM1_PSTRT = 0x00`, `SECWM1_PEND = 0x6F` (111). One contiguous secure area ✔

### Bank 2

| pages | n | owner | attr |
|---|---:|---|---|
| 0–4 | 5 | FSBL (copy 2) | SECURE |
| 5 | 1 | Manifest B | SECURE |
| 6 | 1 | Route-1 journal B | SECURE |
| **7–106** | **100** | **Secure slot B** | SECURE |
| 107–122 | 16 | NS slot B | NON-SECURE |
| 123–127 | 5 | Reserved, erased | NON-SECURE |

`SECWM2_PSTRT = 0x00`, `SECWM2_PEND = 0x6A` (106). One contiguous secure area ✔

### Capacity

| | pages | bytes | vs need |
|---|---:|---:|---|
| secure slot (each) | 100 | **819,200** | ship ~570,000 + margin 40,960 → **208,240 B buffer** |
| NS slot (each) | 16 | **131,072** | NS image 97,808 → **33,264 B headroom** |

Bank 1 is the binding constraint: `S + N ≤ 128 − 12 = 116`. `N = 16` was chosen because
`N = 14` leaves only 16,880 B of NS headroom and `N = 12` leaves 496 B.

### Design notes

* **Pages 0–11 of bank 1 are the "never erased by an update" block**, contiguous at the
  low end: both immutable (FSBL) and per-device state. They sit as far from the NS
  boundary as the bank allows. This is tidiness, not a security property — see §6.
* **Slot A and slot B are in different banks**, so a secure-image update always erases
  the bank it is not executing from (RM0456 §7.3.1 read-while-write). Same for NS.
* **Every page has exactly one owner**, including the 5 reserved bank-2 pages. The
  registry's gap/overlap `const _: () = assert!` arms must still pass.

## 4. Protection profile

| field | value | set by | notes |
|---|---|---|---|
| `TZEN` | 1 | factory | last, after images are written (silicon-verified ordering) |
| `SECWM1_PSTRT/PEND` | `0x00` / `0x6F` | factory | |
| `SECWM2_PSTRT/PEND` | `0x00` / `0x6A` | factory | **today both predicates require SECWM2 DISABLED** — `lockdown.rs:443`, `:492` |
| `WRP1A_PSTRT/PEND` | `0x00` / `0x04` | factory | FSBL copy 1 |
| `WRP2A_PSTRT/PEND` | `0x00` / `0x04` | factory | FSBL copy 2 |
| `WRP1B`, `WRP2B` | unused | — | second range per bank held in reserve |
| `HDP1EN`/`HDP2EN` | **0 (deferred)** | — | see §6 |
| `SECBOOTADD0` | `0x0C00_0000` | factory | unchanged; FSBL stays bank 1 page 0 |
| `BOOT_LOCK` | 1 | **first field boot, not factory** | makes BOOT0 inert; setting it at the factory removes the sealed EVT's only way in |
| `SWAP_BANK` | 0, **verified** | factory | `lockdown.rs:308` currently omits OPTR bits from comparison |
| `RDP` | `0xAA` at ship → `0xCC` at first field boot | factory / device | invariant #10 |

WRP needs one range per bank for the FSBL; the second range stays free in both banks.
The five per-device pages are deliberately **not** WRP-protected — their authorised
writes must continue after RDP-2.

## 5. Cutover

* **No field migration.** Nothing has shipped. Any die already at RDP-2 without an OEM2
  key cannot take this or any other re-cut; there are none.
* **Factory genesis only.** v7 units are provisioned from erased flash.
* **Bench units** are reprovisioned (mass erase + reflash) or stay on the legacy layout
  and are marked as such. Do not build a field-migration path to preserve experimental
  units.
* **Old signed artifacts are rejected.** The manifest's geometry digest changes.
* The `#540` legacy cutover (the live code still uses the legacy layout — `fsbl/slot.rs`,
  32 KiB FSBL link, NS slots at bank-2 0–63/64–127) must land as a **separate, bisectable
  step before** this one, not folded into it.

## 6. Known costs, open questions, and things this draft does NOT settle

1. **Two NS windows.** The SAU and NS-pointer-validation model has ONE bank-2 window
   (`secure/src/sau.rs:45`, `shared/src/ns_ptr_validate.rs:155`). v7 needs two, in
   different banks. This is new attack surface in the pointer validator and is the single
   largest correctness risk in the change.
2. **Relocating the per-device pages** means fixing hard-coded page numbers:
   `secure/src/hw/flash.rs:778` (PIN), `secure/src/hw/bhk.rs:78` (BHK),
   `secure/src/first_boot/mod.rs:196` (the anti-preplant scan literally iterates
   `123..=127`), and `secure/src/flash_policy.rs:60`, whose guard is
   `page < FIRST_BOOT_JOURNAL_PAGE` — i.e. it encodes "the journal is the last page"
   inside the type that exists to make erases safe. That guard must become a real
   ownership test, not a moved constant.
3. **The secure erase path is bank-blind.** `erase_secure_page` never sets `BKER`
   (`flash.rs:1273`), and `GenericSecurePage::new` accepts any `page < 127` with no bank.
   Under v7 a bank-2 page number would silently erase the bank-1 page of that number.
   **Must be fixed before any v7 code runs.**
4. **Adjacency is not authority** — verified, not assumed. RM0456 Table 68: an NS write
   or page erase against a secure page is `WI` with the nonsecure `WRPERR` flag set and a
   FLASH illegal-access event; Table 70 rejects NS bank/mass erase against a mixture. So
   NS pages sharing bank 1 with the per-device pages grant no access to them. What DOES
   change is availability: an NS program/erase in bank 1 can stall a secure instruction
   fetch from bank 1 (§7.3.5).
5. **HDP deferred.** HDP shares `SECWM`'s start and would hide pages 0–4 after `ACCDIS`.
   Plausible for the FSBL prefix, but it denies fetch/read/write/erase until reset and is
   not needed for the capacity problem. Decide separately.
6. **The SRAM mutation closure is not solved by this.** Neither layout removes the need
   for the updater's erase/program loop and its vectors to live in SRAM during mutation
   (Draft 1.1 §738 already requires it).
7. **`make verify-linker-map` claims `.x == proto == sau.rs == Lean`.** Whether the Lean
   side encodes the geometry, and what proof work a re-cut implies, is unresolved.
8. **The true ship image cannot be measured.** Every number here budgets 570,000 B from
   an estimate. Closing the rollback quarantine enough to compile the real configuration
   should precede ratification.

---

# REVIEW OUTCOME — REJECTED 2026-09-24 (GPT-6 Astra, adversarial)

Full review: `astra-round-1.md`. Draft SHA-256 reviewed:
`736d03b65f2691c42ee0cc9b42ac7f2ddabbc2adac97c3e87c3ca2facfd098dd`.
Shape B survives; **this draft's protection settings and cutover contract do not.**
Every item below was re-verified by me against primary sources, not relayed.

## CRITICAL

**C1 — `BOOT_LOCK` must be staged at the FACTORY, not at first boot.**
Draft 1.2 stages it at the factory and permits first boot to write **only RDP**
(`fw-rollback-draft12-candidate-2026-07-21.md:167`, writer contract
`a-b-firmware-rollback-architecture.md:2259`). Burning RDP-2 first makes a later
`BOOT_LOCK` repair impossible. My rationale — "it removes the sealed EVT's way in" — was
a BENCH concern applied to a PRODUCTION contract; factory `BOOT_LOCK` does not disable
RDP-0 SWD verification, which is what invariant #10 actually needs.

**C2 — under v7, `erase_ns_page` erases the RUNNING NS slot.**
VERIFIED at `secure/src/hw/flash.rs:1134`: `let cr = PER | BKER | (page << PNB_SHIFT) | STRT;`
— `BKER` is set **unconditionally**. v7 puts NS slot A in BANK 1 (pages 112–127), so
erasing inactive A while running B would target **bank 2** pages 112–127, overlapping
running NS slot B (107–122). Catastrophic, and the exact twin of the bank-blind
`erase_secure_page` already in §6.3. The mutation API must carry bank + security +
owner, checked in both directions, before any v7 code runs.

## MAJOR

**M1 — TZEN activation DISCARDS the watermarks.** VERIFIED, RM0456 §7.5.1: "When the
TrustZone is activated (TZEN is modified from 0 to 1), the secure watermark-based user
options bytes are set to default secure state: all flash memory is secure, and no HDP
area", Table 58 (`SECWMx_PSTRT = 0`, `SECWMx_PEND = 0x7F`). So §4's "TZEN last" is
incomplete: the final watermarks must be programmed **after** TZEN activation and an
option-byte reload, not before.

**M2 — `SECBOOTADD0 = 0x0C00_0000` is the wrong FIELD value.** VERIFIED at
`shared/src/lockdown.rs:55-59`: `0x0018_0000` is the CubeProgrammer option-byte FIELD
(`addr >> 7`); `0x0C00_0000` is the address it encodes. That file documents this exact
confusion as the defect `tools/ob-configurator` carried until it was deleted (issue #37).
I walked into a trap the codebase had already written down.

**M3 — "old signed artifacts are rejected" is FALSE.** Manifest-v6's signed preimage
contains no geometry digest (`fw-manifest/src/v6.rs:423`), so changing geometry constants
does not invalidate old signatures. §5 needs an explicit new schema / signing domain, or
a signed geometry identifier the FSBL and packager both check.

**M4 — "pages 0–11 are never erased by an update" is FALSE.** Page 5 is Manifest A and
MUST be erased when slot A is updated. The updater-preserved bank-1 set is **0–4 and
6–11**. The anti-preplant scan must enumerate exactly the five mutable per-device owners
(7–11), not the whole prefix, which contains intentionally programmed manifests/journals.

**M5 — factory identity / attestation storage is unallocated.** `production-security.md:353,419`
loads a device-binding manifest from SECURE FLASH (signature alone ~7.8 KB);
`first-boot-provisioning.md:346` instead proposes OTP `176..512`, which cannot hold a
4,008-byte C10 signature. That is an unresolved allocation conflict v7 must not silently
close. The five blank first-boot pages cannot absorb a factory-written record without
changing their ownership and anti-preplant contract.

**M6 — the two-window migration is less dangerous than §6.1 said, and has more
consumers.** The existing pointer check is NOT endpoint-only: `nsc/ptr_validate.rs:88`
scans intervening 32-byte blocks and rejects a range spanning the secure hole — provided
the SAU regions are split and NOT widened across it. Missing consumers: the FSBL's own
SAU (`fsbl/src/sau.rs`, maps bank 2 only), `erase_ns_page` (C2), and every active-slot
consumer (atlas base, vectors, veneers, linker origins, measurement).

**M7 — 16 NS pages is not justified for the product's lifetime.** The atlas already
reserves `0x13000`; doubling it alone takes the NS span to ~175,632 B. Also
`PX_NS_FEATURES` omits USB and IWDG (`Makefile:2827`) and the gate measures `text+data`
rather than physical LOAD span, so the 97,808 B figure is not a shipping measurement.

## MINOR

**m1 — citation errors.** Read-while-write is **§7.3.10**, not §7.3.1. The RDP-2 option
freeze is **§7.6.2**, not §7.4.2 (§7.4.2 additionally says `SWAP_BANK` cannot change once
TZEN and `BOOT_LOCK` are set — so under the corrected profile the RDP-2 swap exception is
closed).

**m2 — §6.7 is answerable, not open.** Lean DOES model the map:
`contracts/verification/lean/SphincsCVerify/Platform/MemoryMap.lean:72` encodes one
NS-flash interval and one full-bank secure interval. Both need two-window revision.

**m3 — "WRP1B/2B held in reserve" is misleading.** Unused WRP ranges cannot be newly
configured after RDP-2. Same for HDP: `HDP=0` must be chosen deliberately before
shipment, not deferred.

**m4 — WRP needs `UNLOCK=0`**, and the 12,256 B of unused FSBL region must have defined,
verified padding identical in both copies.

## THE OPEN DECISION: the S/N split

Astra proposes **84 S / 32 NS**; my draft says 100 / 16.

| split | secure slot | buffer over ~570 KB + 40 KB | NS slot |
|---|---:|---:|---:|
| 100 / 16 (mine) | 819,200 | 208,240 | 131,072 |
| 92 / 24 | 753,664 | 142,704 | 196,608 |
| 84 / 32 (Astra) | 688,128 | 77,168 | 262,144 |

This is a genuine trade and neither number is evidenced. The owner's stated expectation
is that **hardening grows the SECURE image** (masked-sha2, FI-hardened FSBL verify, the
OPTIGA lockdown paths) while no new features are planned. Against that, 84/32 spends the
secure buffer on NS headroom nobody has asked for. 92/24 is the defensible middle.

**Do not ratify a split until both slot-linked images are measured by physical LOAD span
with the production feature set** — which currently cannot be compiled.
