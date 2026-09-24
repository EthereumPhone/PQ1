# Flash geometry v7 — DRAFT v2

**Status: DRAFT, second round. Not approved, not implemented, not ratified.**
Supersedes `geometry-v7-draft.md` (v1), which GPT-6 Astra REJECTED on 2026-09-24.
v1 and its review are retained — the corrections are the useful part of the history.

Shape "B" (symmetric, one complete secure slot per bank), chosen 2026-09-24.
Split **92 secure / 24 NS**, chosen by the owner 2026-09-24 as the middle of
100/16 (mine) and 84/32 (Astra's).

---

## 1. What changed from v1

Every v1 defect Astra found was re-verified by me against primary sources.

| v1 defect | v2 |
|---|---|
| `BOOT_LOCK` at first field boot | **at the FACTORY**, staged and verified pre-RDP-2. Draft 1.2 stages it there; first boot writes only RDP. |
| "TZEN last" | **watermarks AFTER TZEN.** RM0456 §7.5.1 + Table 58: activating TZEN resets `SECWM*` to all-secure and clears HDP. |
| `SECBOOTADD0 = 0x0C00_0000` | **field value `0x0018_0000`** (`addr >> 7`). `lockdown.rs:55` records this exact confusion as issue #37. |
| "old artifacts rejected by the geometry digest" | **no such digest exists** (`fw-manifest/src/v6.rs:423`). Needs an explicit new schema / signing domain. |
| "pages 0–11 never erased" | false — page 5 is Manifest A. Preserved set is **0–4 and 6–11**. |
| factory identity storage unallocated | **5 reserved secure pages in bank 2** (§2). |
| RWW §7.3.1, RDP-2 freeze §7.4.2 | **§7.3.10** and **§7.6.2**. |
| "Lean geometry unresolved" | it models the map — `Platform/MemoryMap.lean:72`. Needs two-window revision. |
| 100/16 split | **92/24**. |

## 2. The map

| pages | n | Bank 1 | Bank 2 | attr |
|---|---:|---|---|---|
| 0–4 | 5 | FSBL copy 1 | FSBL copy 2 | SECURE |
| 5 | 1 | Manifest A | Manifest B | SECURE |
| 6 | 1 | Route-1 journal A | Route-1 journal B | SECURE |
| 7 | 1 | Off-chain counter journal | ┐ | SECURE |
| 8 | 1 | MCU PIN-attempt state | │ | SECURE |
| 9 | 1 | Admin-wipe / duress flag | │ *(see 99–103)* | SECURE |
| 10 | 1 | Wrapped BHK | │ | SECURE |
| 11 | 1 | First-boot journal + PBS salt | ┘ | SECURE |
| **12–103** | **92** | **Secure slot A** | — | SECURE |
| **7–98** | **92** | — | **Secure slot B** | SECURE |
| 99–103 | 5 | — | **Factory binding / handoff reservation** | SECURE |
| **104–127** | **24** | **NS slot A** | **NS slot B** | NON-SECURE |

**`SECWM1_PSTRT/PEND = SECWM2_PSTRT/PEND = 0x00 / 0x67`.** Literally symmetric, which
is what §5's "selected symmetric SECWM1/2" wording asks for. One contiguous secure area
per bank (RM0456 §7.5.2). Verified: both banks cover exactly 128 pages, no gaps, no
duplicates, both secure runs contiguous.

| | each | vs need |
|---|---:|---|
| secure slot | **753,664 B** | ship ~570,000 + margin 40,960 → **142,704 B buffer** |
| NS slot | **196,608 B** | NS image 97,808 → **98,800 B headroom** |
| factory reservation | 40,960 B | capacity HELD, format not approved |

The factory reservation is space for the unresolved record described in
`production-security.md:353,419` (device-binding manifest from secure flash, ~7.8 KB of
signature alone) versus `first-boot-provisioning.md:346` (OTP `176..512`, which cannot
hold a 4,008-byte C10 signature). **Reserving capacity is not approving a format.**

## 3. Protection profile

| field | value | set by |
|---|---|---|
| `TZEN` | 1 | factory — **before** the watermarks |
| `SECWM1_PSTRT/PEND` | `0x00` / `0x67` | factory, **after TZEN + OBL** |
| `SECWM2_PSTRT/PEND` | `0x00` / `0x67` | factory, **after TZEN + OBL** |
| `WRP1A_PSTRT/PEND` | `0x00` / `0x04`, `UNLOCK=0` | factory, after FSBL contents final |
| `WRP2A_PSTRT/PEND` | `0x00` / `0x04`, `UNLOCK=0` | factory, after FSBL contents final |
| `WRP1B`, `WRP2B` | unconfigured — **and unconfigurable after RDP-2** | — |
| `HDP1EN`/`HDP2EN` | **0, chosen deliberately** — not "deferred"; HDP freezes at RDP-2 | factory |
| `SECBOOTADD0` field | **`0x0018_0000`** (= `0x0C00_0000 >> 7`) | factory |
| `BOOT_LOCK` | 1 | **factory**, verified before RDP-2 |
| `SWAP_BANK` | 0, **verified** — `lockdown.rs:308` omits OPTR today | factory |
| `RDP` | `0xAA` at ship → `0xCC` first field boot (RDP only) | factory / device |

The 12,256 B of FSBL region beyond the 28,704 B LOAD span must have defined, verified
padding, identical in both copies.

## 4. Blockers that must land before any v7 code runs

1. **`erase_ns_page` sets `BKER` unconditionally** (`flash.rs:1134`). v7 puts NS slot A
   in bank 1, so erasing inactive A while running B would erase **bank 2** pages
   104–127 — the running NS slot B. Catastrophic.
2. **`erase_secure_page` never sets `BKER`** (`flash.rs:1273`), and
   `GenericSecurePage::new` accepts any `page < 127` with no bank
   (`flash_policy.rs:60`). A bank-2 page would erase the bank-1 twin.
3. **The mutation API must carry (bank, security attribute, owner)** and be checked in
   both directions. (1) and (2) are the same defect twice.
4. **Two NS windows** in `secure/src/sau.rs`, `shared/src/ns_ptr_validate.rs`,
   `fsbl/src/sau.rs` (maps bank 2 only today), and `Platform/MemoryMap.lean:72`. Do NOT
   widen a region across the secure hole — `nsc/ptr_validate.rs:88` already scans
   intervening 32-byte blocks and rejects a spanning range if the regions are split.
5. **Per-device page numbers are hard-coded**: `flash.rs:778` (PIN), `bhk.rs:78` (BHK),
   `first_boot/mod.rs:196` (anti-preplant scan literally iterates `123..=127` — must
   become exactly the five mutable owners, pages 7–11), `flash_policy.rs:60`.
6. **`#540` legacy cutover first**, as a separate bisectable step.
7. **`OPTSTRT`/`OBL_LAUNCH` are NSCR, not SECCR** (`flash.rs:390`, RM §7.4.2) — the
   recorded defect behind #268.

## 5. OPEN QUESTION for this review round: what else can move to NS?

The atlas precedent — 75 KB of glyphs in the NS slot, pinned SHA-256, re-verified before
and after every dialog — worked. The owner asks whether more can follow.

Measured, the secure image is `.text` 459,408 + `.rodata` 70,604 + `.data` 11,300. Data
is only 13% of it, and the movable candidates are:

| candidate | bytes | what it controls |
|---|---:|---|
| `WORDLIST_FLAT` | 16,384 | the seed words and boot-fingerprint words the user READS |
| `erc7730-known-calls.bloom` | 16,384 | whether a known call can be downgraded to blind-sign |
| `WORDLIST_PREFIX5_PACKED` | 6,144 | FSBL fingerprint prefixes |
| `WORDLIST_LENS` | 2,048 | — |
| **total** | **40,960** | |

Both big items are WYSIWYS or refusal-policy inputs, so each would need the atlas's
verify-before-and-after discipline. Note that discipline FAILED OPEN in review on
2026-09-24 (`assets::atlas()` cached the verdict, not the bytes; a tampered atlas forced
the fallback path, which then rendered with the tampered glyphs) — fixed in `7e7a8900`.
Repeating the pattern twice more multiplies that surface.

**Questions for the reviewer:** is moving either defensible? Does the FSBL's use of
`WORDLIST_PREFIX5_PACKED` (it renders the boot fingerprint BEFORE any NS image is
verified) make the wordlist un-movable? Is there a THIRD approach — compressing the
wordlist in place, deriving the prefix table at runtime, or shrinking the bloom — that
gets the bytes without adding an NS-trust surface? And is 41 KB even worth it against a
142,704 B buffer?

---

# ROUND-2 REVIEW OUTCOME — REJECTED 2026-09-24

Full review: `astra-round-2.md`. v2 SHA-256 reviewed:
`668708efa6ea15e3bc9e445ddba0fcf0b732a98591937a18738c0685dbf4eb6b`.
Shape and allocation stand; the acceptance contract does not.

## The answer to §5 (what else can move to NS): essentially nothing — for a
## far better reason than §5 gave.

**The BIP-39 wordlist is a KEY-DERIVATION input, not a display asset.** VERIFIED at
`bip39/src/full.rs:301` — `Mnemonic::to_seed` Phase 1 calls `ct_load_word(self.indices[i])`
over `WORDLIST_FLAT`/`WORDLIST_LENS` to assemble the **PBKDF2 password**. An attacker who
controls those tables controls the password bytes: replace every entry with one fixed
word and length and the password becomes independent of the secret indices, so with the
empty passphrase **the derived seed becomes predictable**. That is wallet theft, not a
WYSIWYS concern. §5's framing understated it.

**The bloom filter** gates blind-sign downgrade: clearing a queried bit makes a known
tuple appear absent, both redundant queries honestly agree on the wrong answer
(`tx/erc7730.rs:232`), and the companion reaches a lower dispatch tier instead of a hard
refusal. And "pre/post hashes alone do not prove safety against change-use-restore" —
which is exactly the gap found in `assets::atlas()` and fixed in `7e7a8900`.

**Better: compact IN PLACE, no NS trust.** Pack eight letters as 5-bit symbols
(10,240 B replacing FLAT+LENS's 18,432) → **8,192 B**; derive the application's PREFIX5
from the full-word lookup → **6,144 B**; combined **14,336 B**, keeping the FSBL's own
copy separate. Any change must preserve the deliberate full-scan constant-time behaviour
(`full.rs:29`). Do NOT truncate the bloom: folding to 8 KiB gives 38.84% occupancy
against the generator's 25% cap (`dbgen/src/erc7730.rs:3292`).

**Where the bytes actually are: `.text`, 459,408 B.** Three evidenced targets —
`sha2`'s `force-soft-compact` backend (SHA-512 27,806 + SHA-256 7,202); the two UserOp
handlers duplicating envelope decode (`cmd_sign_userop::run` 14,224 + batch 18,088 =
32,312); and the pixel scene (`Anim::build` 11,734 of 36,214 UI-crate bytes).

## CRITICAL — the device cannot verify the profile it is about to freeze

`shared/src/lockdown.rs` rejects v7 as written (`:440`, `:489` demand all-secure bank 1 /
all-NS bank 2). A watermark-only repair is NOT sufficient, because the ship-state check is
independently incomplete:

* the boot-address predicate **ignores `BOOT_LOCK`** (`:75`)
* the WRP predicate accepts coverage ending at **page 3, not 4** (`:376`)
* `verify_ship_profile` receives **no WRP2 register at all** (`:428`)
* the OPTR check **ignores `SWAP_BANK`** (`:308`)

This is independent of the geometry and is the single most important unresolved item:
**nothing proves the complete intended protection profile before RDP-2 makes every
omission permanent.**

## A false claim in v2, corrected

§5 said the FSBL renders the boot fingerprint before verifying any NS image. **False.**
`fsbl/src/main.rs:189-190` runs `verify_images` for both slots first, and the comment at
:186 says the render uses "the same trusted bytes it just verified"; the render is at
:264. I wrote that from memory instead of reading the file I had already read.

## Remaining blockers (unchanged or new)

1. CRITICAL — the pre-RDP-2 acceptance contract above.
2. MAJOR — artifact incompatibility still unspecified (no geometry digest exists; pick a
   schema/domain and make legacy rejection a blocker across signer, updater and FSBL).
3. MAJOR — the production capacity gate must be restored: ratify no split before physical
   LOAD-span measurement of both slot-linked S/NS pairs with the production feature set.
4. MAJOR — the factory reservation needs an owner, format bound, authentication, pre-lock
   failure behaviour and update/wipe preservation. Capacity is not authorisation.
5. MAJOR — factory sequencing must state the DFU cutoff: `SECBOOTADD0` and `SWAP_BANK`
   BEFORE `BOOT_LOCK` (RM §7.4.2), SWD verification after. Factory `BOOT_LOCK` ends the
   sealed-EVT ROM-DFU route (`tools/flash-evt-dfu.sh` needs a separate BOOT_LOCK=0 bench
   profile).
6. Preserved-owner set must also name bank-2 `0–4, 6, 99–103`.
