# Flash geometry v7 — adversarial review engagement (2026-09-24)

**Outcome: v7 is NOT ratified.** Two drafts were written and both were rejected.
What the engagement *did* produce is six landed fixes to the **current**
geometry, every one of them a real defect today rather than a v7 precondition.
This file is the durable record of both halves: why the redesign is still open,
and what was closed on the way.

Reviewer: GPT-6 Astra (`codex exec -s read-only -m gpt-6-astra`), adversarial,
three rounds, no files modified. Raw reviews and both drafts are in the sibling
directory.

## Why this engagement happened

The owner decided to ship the pixel UI (`ui-px`) — the graphical trusted display
that replaces the text-only one. It does not fit.

| | flash |
|---|---|
| ship-shaped secure image WITH `ui-px` | 543,893 B |
| same WITHOUT `ui-px` | 432,873 B |
| secure slot A (`SECURE_SLOT_SPAN` 0x72000) | 466,944 B |

`ui-px` marginal cost **111,020 B**; headroom 34,071 B; **shortfall 76,949 B**.

Caveat that applies to every number above and in the drafts: the true shipping
image **cannot currently be compiled** (`RDP2_SELF_LOCK_REQUIRES_MODE_PRODUCTION`
and `FW_ROLLBACK_PRODUCTION_BLOCKED` both fire), so these are ship-*shaped*
estimates, not measurements of the artifact that would ship.

## Owner decisions taken during the engagement

These are settled and are inputs to any future draft, not open questions:

1. **Ship the pixel UI.** It is the shipping trusted display.
2. **All screens must be viewed before the user can sign** — the consent gate is
   scroll-to-end, reversing the pixel path's original `false`.
3. **Shape B** — secure flash in *both* banks, symmetric layout.
4. **Split 92/24** — pages per bank between the secure and non-secure slots.
5. **Do not remove the iota2 board code.**

## Provenance — the reviewed bytes are reproducible

Each draft has its review outcome appended *after* the fact, so the file on disk
is not the file that was reviewed. The reviewed prefix is exact and checkable:

| Reviewed artifact | Recover with | SHA-256 |
|---|---|---|
| draft v1 | `head -164 draft-v1.md` | `736d03b65f2691c42ee0cc9b42ac7f2ddabbc2adac97c3e87c3ca2facfd098dd` |
| draft v2 | `head -129 draft-v2.md` | `668708efa6ea15e3bc9e445ddba0fcf0b732a98591937a18738c0685dbf4eb6b` |

Both verified 2026-09-24 after the files were moved here and their internal
cross-references repointed at the new filenames. The repointed lines are inside
the appended review outcomes, i.e. past the digest boundary, so the prefixes are
byte-identical to what was reviewed.

| File | What it is |
|---|---|
| `flash-budget-research.md` | Where the bytes actually are; RM0456 Rev 7 answers to the open questions |
| `astra-round-0-capacity-options.md` | Capacity options A/B/C before any draft existed |
| `draft-v1.md` + `astra-round-1.md` | First proposal — REJECTED |
| `draft-v2.md` + `astra-round-2.md` | Second proposal — REJECTED |

## What LANDED — six commits, all defects in the geometry we ship today

The most useful output of the engagement was not the redesign. Round 1 and
round 2 found live bugs while checking whether the *current* code could support
v7, and those are fixed on `feat/pq1-board-target`:

| Commit | What |
|---|---|
| `98bbb23d` | FSBL fingerprint hold 10 s → 4 s |
| `436341d5` | `fsbl-tests/tests/paired_constants.rs` — pin the cross-world constants |
| `808c42f5` | Ship profile can verify what RDP-2 makes permanent (four gaps) |
| `03c95f03` | `erase_secure_page`: the page proof carries its bank |
| `12b99eec` | Tripwire catches a post-RDP-2 bank swap |
| `05e5534f` | `erase_ns_page`: same fix, the more dangerous half |

### The critical one: nothing verified the profile RDP-2 freezes

Round 2's CRITICAL finding was that `shared/src/lockdown.rs` could not prove the
protection profile before RDP-2 made every omission permanent. Four independent
omissions, all closed by `808c42f5` (+ `12b99eec` for the SWAP_BANK test):

| Omission | Closed by |
|---|---|
| boot-address predicate ignored `BOOT_LOCK` | `boot_lock_set()` + `ShipProfile::require_boot_lock` + `ObField::BootLock` |
| WRP accepted coverage ending at page **3**, not 4 | `wrp_covers_fsbl_bits()` + `FSBL_LAST_PAGE_{LEGACY,FROZEN}` |
| `verify_ship_profile` received **no WRP2 register at all** | `wrp2ar` parameter + `ObField::Wrp2a` + `flash::wrp2ar_raw()` (offset 0x68, RM §7.9.23) |
| OPTR check ignored `SWAP_BANK` | `OPTR_SWAP_BANK` (bit 20) + `swap_bank_clear()` + `ObField::SwapBank` |

**`require_boot_lock` is `false` in both shipped profiles, deliberately.**
BOOT_LOCK is now *representable and checkable*, not *required*, because
requiring it would end the sealed-unit ROM-DFU route (see open item 4). The
predicate exists so the decision can be made; the decision has not been made.

### The bank-blind erase pair

Round 1 found both halves and correctly rated the NS one as "as important as"
the secure one. It is worse. `erase_secure_page` without a bank erases the wrong
**inactive** page; `erase_ns_page` without a bank, under a geometry with an NS
slot in bank 1, erases the page the device is **running from** — mid-update,
with no valid fallback. Both now derive `BKER` from a bank-carrying proof
(`GenericSecurePage` / `GenericNsPage`) instead of asserting it.

Checked at the same time, **no fix made, by design**:
`write_slot_quadword_verified` dispatches on **alias**, not bank, so a bank-2
*secure* address (`0x0C10_0000`) matches neither range and returns `Err(())`. It
fails closed. Under v7 that refusal becomes wrong and the dispatch must be
extended — tracked as an open item, not a closed one.

### The paired-constants defect

Found by the **owner**, not by CI and not by a reviewer: the FSBL held the boot
fingerprint for 10 s while the secure world had shown the same eight words, from
the same digest, through the same `firmware_fingerprint_lines`, for 4 s since
2026-04-14. Two screens, one property, six seconds apart, because the constants
were set on different dates by different people with nothing tying them
together. `fsbl-tests/tests/paired_constants.rs` now fails on divergence, and
lists the pairs that deliberately differ so nobody "fixes" one into a behaviour
change.

## What is STILL OPEN

Tracked as **#752**; the factory-sequencing item is **#753**, split out because
it binds the current geometry too. v7 cannot be ratified until these are
answered. None is a coding task.

1. **Artifact incompatibility is unspecified.** No geometry digest exists. A
   schema and domain must be chosen and legacy rejection made a blocker across
   signer, updater and FSBL.
2. **The production capacity gate must be restored.** No split may be ratified
   before a physical LOAD-span measurement of *both* slot-linked S/NS pairs with
   the production feature set — which today cannot be built (see the caveat
   above). 92/24 is an allocation decision resting on ship-*shaped* numbers.
3. **The factory reservation has no owner, format bound, authentication,
   pre-lock failure behaviour or update/wipe preservation rule.** Capacity is
   not authorisation.
4. **Factory sequencing must state the DFU cutoff (#753).** `SECBOOTADD0` and
   `SWAP_BANK` before `BOOT_LOCK` (RM §7.4.2); SWD verification after. A factory
   `BOOT_LOCK` ends the sealed-EVT ROM-DFU route, so `tools/flash-evt-dfu.sh`
   needs a separate `BOOT_LOCK=0` bench profile.
5. **The preserved-owner set must also name bank-2 pages `0–4, 6, 99–103`.**
6. **The watermark half of the CRITICAL finding.** `lockdown.rs` still rejects a
   v7 layout outright (it demands all-secure bank 1 / all-NS bank 2). That is
   correct today and must change *with* v7, never before it.
7. **Consumers that assume bank == security**: the FSBL's own SAU maps only bank
   2; the atlas base, vectors, veneers, linker origins and measurement all use
   one constant rather than following the selected slot;
   `write_slot_quadword_verified` (above); and the NS-pointer window check needs
   two NS windows rather than one.

## The §5 question, answered: essentially nothing more can move to NS

v2 asked what else could be pushed into non-secure flash. The answer is almost
nothing, for a stronger reason than v2 gave.

**The BIP-39 wordlist is a key-derivation input, not a display asset.** Verified
at `bip39/src/full.rs:301` — `Mnemonic::to_seed` assembles the **PBKDF2
password** from `WORDLIST_FLAT`/`WORDLIST_LENS`. An attacker who controls those
tables controls the password bytes: replace every entry with one fixed word and
length and the password stops depending on the secret indices, so with an empty
passphrase the derived seed becomes predictable. That is wallet theft, not a
WYSIWYS concern.

**The bloom filter gates blind-sign downgrade.** Clearing a queried bit makes a
known tuple look absent; both redundant queries then honestly agree on the wrong
answer (`tx/erc7730.rs:232`) and the companion reaches a lower dispatch tier
instead of a hard refusal. Do not truncate it either — folding to 8 KiB gives
38.84% occupancy against the generator's 25% cap
(`dbgen/src/erc7730.rs:3292`).

Better, and with no NS trust: **compact in place.** Pack eight letters as 5-bit
symbols (10,240 B replacing FLAT+LENS's 18,432) → 8,192 B; derive PREFIX5 from
the full-word lookup → 6,144 B; **14,336 B combined**, FSBL copy untouched. Any
such change must preserve the deliberate full-scan constant-time behaviour at
`full.rs:29`.

Where the bytes actually are — `.text`, 459,408 B — with three evidenced
targets: `sha2`'s `force-soft-compact` backend (SHA-512 27,806 + SHA-256 7,202);
the two UserOp handlers duplicating envelope decode (`cmd_sign_userop::run`
14,224 + batch 18,088 = 32,312); and the pixel scene (`Anim::build` 11,734 of
36,214 UI-crate bytes).

## Claims I made in the drafts that were false

Recorded because the drafts are preserved verbatim and a reader will hit them.

* **v2 §5 said the FSBL renders the boot fingerprint before verifying any NS
  image.** False. `fsbl/src/main.rs:189-190` runs `verify_images` for both slots
  first; the render is at :264 and the comment at :186 says it uses "the same
  trusted bytes it just verified". I wrote it from memory instead of reading a
  file I had already read.
* **Bank swap was described as safe for a cross-bank image.** Attributes follow
  banks, but a linked image's halves move — round 2 was right.
* Several flash-saving estimates in the early rounds were wrong by an order of
  magnitude (SHA-512 estimated ~28 KB, measured 4,556 B; the wordlist estimated
  ~29 KB, measured 0 B — `compress512` actually *grows* at `opt-level="s"`).
  `flash-budget-research.md` is the measured replacement for all of them.
