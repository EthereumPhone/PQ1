# Flash-budget research — what the open questions actually resolve to
2026-09-24. Sources: RM0456 Rev 7 (on disk), the repo, and measured builds.

## The measured gap

| | flash |
|---|---|
| ship-shaped secure image WITH `ui-px` | 543,893 B |
| same WITHOUT `ui-px`                  | 432,873 B |
| secure slot A (`SECURE_SLOT_SPAN` 0x72000) | 466,944 B |

`ui-px` marginal cost **111,020 B**; headroom **34,071 B**; shortfall **76,949 B**.

## Q1 — Can the secure world use bank 2? YES, directly supported.

RM0456 **7.5.2**: "When TrustZone security is active (TZEN = 1), a part of the
flash memory can be protected against nonsecure read and write accesses. Up to
two different non-volatile secure areas can be defined by option bytes ... **one
area per bank can be selected with a page granularity**", via
`SECWMx_PSTRT`/`SECWMx_PEND`. We currently ship `SECWM2_PSTRT=0x7F
SECWM2_PEND=0x0`, which 7.5.2's Table 59 defines as "No secure area" — i.e. the
bank-2 secure area is switched OFF by choice, not absent by silicon.

Constraints that follow:
* **One CONTIGUOUS secure area per bank.** A bank-2 layout must put all secure
  pages in one run; the NS slots take the remainder.
* **Address space is contiguous across the bank boundary.** 7.3.1's organization
  table puts bank 2 immediately after bank 1; with bank 1 secure at 0x0C00_0000
  (1 MiB), bank 2's secure alias is 0x0C10_0000. A secure image *can* span banks.
* **Read-while-write is supported** (7.3.1 main features) — so an A/B update
  writing the inactive slot in the *other* bank is better off than today, not
  worse.
* **Bank swap is safe** (7.5.8): "Flash memory bank attributes follow their bank
  so there is no need to modify" `FLASH_SECWMyRx`, `FLASH_WRPxyR`,
  `FLASH_SECyBBRx`, `FLASH_PRIVyBBRx` when swapping.
* **WRP still works** (7.6.1): "Two write-protected (WRP) areas can be defined in
  **each bank**, with page granularity" — so invariant #10's FSBL write
  protection is satisfiable whichever bank the FSBL copy is in.
* **Block-based (`FLASH_SECBB2Rx`, 7.5.4)** is an alternative: "Any page can be
  programmed **on-the-fly** as secure or nonsecure". These are REGISTERS, so the
  attribution is volatile and something must re-apply it every boot (the FSBL).
  Watermark wins where both apply: "If SECyBBi bit is set or reset for a page
  already included in a secure watermark-based area, the page keeps the
  watermark-based protection security attributes." Prefer the watermark.
* Caution (7.5.2/7.5.4): "Switching a flash memory area from secure to no-secure
  does not erase its content." Any re-cut that de-secures a page must erase it
  first and flush the instruction cache.

### Does the total flash even allow it?
2 banks x 128 pages x 8 KiB = 256 pages. A re-cut needs roughly:
FSBL 5 x2 banks = 10 | manifests 2 | per-device 5 | journals 2 |
secure slots 2 x ~68 = 136 | NS slots 2 x ~22 = 44  => **199 of 256 pages**.
~57 pages (456 KB) spare. The problem is the CURRENT CUT, not the silicon.

## Q2 — Must slot A and slot B be the same size? NO, by hardware or protocol.

It is a *software convention*: one `SECURE_SLOT_SPAN` constant feeds both, via
`slot_secure_addr(slot)` (`fsbl/src/slot.rs:32`, `secure/src/hw/flash.rs:1051`).
Splitting it into A/B spans touches the geometry crate, the FSBL verify
(`fsbl/src/verify.rs:38`), the manifest, and `fw_update`. Real work, but no
silicon or protocol obstacle. This matters because a bank-1/bank-2 split makes
the two slots naturally different sizes.

## Q3 — The untraced 16,384 B blob: IDENTIFIED.

It is `WORDLIST`'s fat-pointer array. `bip39/src/wordlist.rs:9` is
`pub const WORDLIST: &[&str; 2048]`; on a 32-bit target each `&str` is
(ptr, len) = 8 B, so 2048 x 8 = **16,384 B exactly**, plus the word strings it
points at. It is present in the no-`ui-px` build too, so it predates the pixel UI.

BIP-39 in the shipped image, total:
```
16,384  WORDLIST_FLAT              constant-time 8-byte-stride table
16,384  WORDLIST (fat pointers)    the anon blob
 6,144  WORDLIST_PREFIX5_PACKED    FSBL surface, also used by the secure world
 2,048  WORDLIST_LENS
 ~2,900 bip39 code
------
~43,900 B  (+ the raw word strings WORDLIST points at, est. ~13 KB)
```
`.rodata` is 70,604 B total, so BIP-39 is the majority of it.

**`WORDLIST` looks compile-time-only at runtime.** `bip39/src/full.rs:52`
`const fn flatten_wordlist()` consumes `WORDLIST[i].as_bytes()` to BUILD
`WORDLIST_FLAT`/`WORDLIST_LENS` at compile time, and the firmware deliberately
does NOT read `WORDLIST` at runtime — `secure/src/measured_boot.rs:231` and
`secure/src/main.rs:4028` both carry comments saying the `WORDLIST[idx]` access
pattern was removed on purpose (it is index-keyed, an SCA leak; F-22, with the
`tools/sca/leakage_bip39.py` harness). It survives `--gc-sections` because it is
`pub`/`pub use`d, not because anything calls it.

=> making `WORDLIST` private / test-only, or generating the flat tables from a
build script, should drop ~16 KB of pointers plus ~13 KB of strings. It also
*removes* the leaky pattern rather than adding risk.

## Q4 — SHA-512 and the wordlist: I MEASURED both, and BOTH of my estimates were WRONG.

I first estimated ~28 KB from SHA-512 and ~29 KB from the wordlist. I built the
image three ways to check. Neither holds.

### Experiment 1 — `sha2` at `opt-level = "s"` instead of `3`
```
compress512   27,806 -> 28,070   (it GREW by 264 B)
compress256    7,202 ->  2,054   (-5,148)
whole image  543,893 -> 539,337  (-4,556 B)
```
`compress512` is not big because it is speed-unrolled; it is big because SHA-512
is 80 rounds of 64-bit operations on a 32-bit core. `opt-level` cannot fix that.
The Cargo.toml comment's justification for pinning `sha2` to 3 ("PBKDF2-HMAC-
SHA512 (BIP-39) always runs in software") is therefore buying almost nothing in
SIZE terms either way — the real saving, 5 KB, comes from SHA-256, which the
HASH peripheral already serves on pq1.
**Worth 4,556 B, not 28 KB.** Cheap and safe, but small. Unlock-time cost not
yet measured.

### Experiment 2 — make `WORDLIST` private so the linker drops it
```
whole image  543,893 -> 543,893   (NO CHANGE AT ALL; .rodata still 70,604)
```
`pub(crate)` does not help: a `const` of reference type is still materialised.
Removing the 16,384 B fat-pointer array needs the `&[&str; 2048]` const to stop
existing — i.e. generate `WORDLIST_FLAT`/`WORDLIST_LENS` from a build script over
a plain text file. That refactor's saving is **not yet measured**.

### Experiment 3 — are the word strings stored twice?
Each word appears EXACTLY ONCE in the binary, and only in the padded
`WORDLIST_FLAT` form (`b"abandon\x00ability\x00"` x1; `b"abandonability"` x0;
`zoo`, `zebra`, `youth` x1 each). rustc has already merged the `&str` literals
into the flat table. **So there is no separate ~13 KB of strings to reclaim** —
the wordlist lever is worth at most the 16,384 B pointer array, not ~29 KB.

### Corrected lever B ceiling
```
 4,556 B  measured   sha2 -> opt-level "s"
16,384 B  UNmeasured build-script refactor to kill the &[&str; 2048] const
 6,144 B  probably DON'T — WORDLIST_PREFIX5_PACKED is a deliberate
          constant-time table; deriving it at runtime risks the F-22 leak
------
~21 KB realistic ceiling, against a 76,949 B shortfall.
```
**Lever B cannot close the gap.** That is now measured, not estimated.

## Q5 — Is the NS slot really over-provisioned?

`NS_SLOT_SPAN` = 0x7A000 = 499,712 B per slot. Occupied: NS image 97,808 B +
the `ui-px` atlas window `ATLAS_SPAN` 0x13000 = 77,824 B => 175,632 B.
**~324 KB spare per NS slot**, ~65% unused.

## Bottom line for the decision

The silicon imposes NO obstacle to giving the secure world bank-2 pages: one
contiguous secure area per bank (7.5.2), contiguous secure addressing across the
bank boundary, WRP available in both banks (7.6.1), bank-swap safe (7.5.8),
read-while-write supported. Total flash is not the constraint either — a
plausible re-cut uses ~199 of 256 pages. The constraint is the CURRENT cut.

And the code diet does NOT rescue it: **measured**, lever B tops out around
21 KB (4.5 KB proven, 16 KB needing a build-script refactor) against a 76,949 B
shortfall. My earlier 25-45 KB figure was an estimate and it was wrong.

So the honest conclusion is narrower than I put it before: **lever A is not a
choice between equals, it is the only lever that closes the gap** without either
cutting the pixel UI to a third of its size (C) or giving up secure-world
rollback (D). Lever B is worth doing as a cheap adjunct, not as the answer.

## A silicon-proven trap that lever A must be validated against

2026-09-16, recorded in memory `project-fsbl-ns-read-needs-sau`: the
non-monolithic boot proof silently halted because **the FSBL configures no SAU
at all**. With `TZEN=1` and SAU disabled the whole address space defaults to
SECURE, so the FSBL's secure-state read of the bank-2 NON-secure alias
(`0x0810_0000`, watermarked NS by `SECWM2`) returned ZEROS —
`ImgNsHashed = SHA-256 of 7,488 zero bytes` — while SWD read the same address
correctly. `verify_images` failed and the FSBL parked in `loop { wfe() }`.

Bearing on lever A, both ways:
* **In its favour**: if bank-2 pages become SECURE via `SECWM2`, the FSBL reads
  them at the SECURE alias `0x0C10_0000`, which is the ordinary case it already
  does for bank 1 — so relocating the SECURE image to bank 2 does not reproduce
  this failure, and may sidestep it.
* **Against complacency**: the NS image stays NS-watermarked and the FSBL still
  has no SAU, so the underlying defect is untouched and still has to be fixed.

Either way the lesson is procedural: this exact area produced a silent,
unobservable halt once already, and it was only diagnosed by flashing a
stage-marker FSBL. **Any lever-A layout must be proven on silicon with the
stage-marker harness before it is trusted** — not reasoned about from the RM.

## A CONCRETE lever-A sketch (to react to, not a proposal to adopt)

Sized from the measured need: secure image 543,893 B -> 67 pages; round to 72
(589,824 B) for headroom. NS image 97,808 + atlas window 77,824 = 175,632 B
-> 22 pages.

```
BANK 1  (SECWM1 = pages 0..127, entirely secure — as today)
   0- 4  FSBL copy 1                     5 pages
   5- 6  Manifest A / Manifest B         2
   7- 78 SECURE SLOT A                  72 pages = 589,824 B   (need 543,893)
  79- 80 Route1 Journal A / B            2
  81-122 SPARE                          42 pages = 344 KB of growth room
 123-127 per-device (offchain, PIN,       5
         wipe-flag, BHK, first-boot)

BANK 2  (SECWM2 = pages 0..76 SECURE; 77..127 stay non-secure)
   0- 4  FSBL copy 2                     5 pages   (secure)
   5- 76 SECURE SLOT B                  72 pages   (secure)
  77- 98 NS SLOT A                      22 pages = 180,224 B   (need 175,632)
  99-120 NS SLOT B                      22 pages
 121-127 SPARE (non-secure)              7 pages
```
* Honours "one contiguous secure area per bank" (7.5.2): bank 2's secure run is
  pages 0..76, the NS remainder is 77..127.
* Slot A and slot B end up in DIFFERENT BANKS, so an A/B update always writes
  the bank it is not executing from — read-while-write (7.3.1) applies. That is
  strictly better than today, where both slots share bank 1.
* Slot A and slot B are the same size here, but they need not be (see Q2) — the
  single `SECURE_SLOT_SPAN` constant would become a per-slot span.
* Leaves 42 spare secure pages in bank 1 and 7 NS pages in bank 2.
* `SECBOOTADD0` is unaffected: the FSBL stays at bank 1 page 0.

What this costs: re-pinning the frozen geometry registry (its compile-time
gap/overlap asserts and `tests/registry.rs` re-derivation make that a mechanical
but wide change), `slot_secure_addr`/`slot_ns_addr` in BOTH the FSBL and the
secure world, the WRP/option-byte ceremony (now two banks), the SECWM2
programming step in every flash recipe, and — per the trap above — a silicon
re-proof with the stage-marker harness.

## The finding that changes the shape of the problem: the image carries TWO UI stacks

Measured from the linked image, bucketing symbols by module:

```
45,488 B   tx::display LEGACY 16x4 page painters
           (value_transfer, erc20, safe_display, eip1271, blind_sign,
            batch, typed_call, deployment, nonce_lane, value_page ...)
36,880 B   tx::display NEW *_screens.rs + px_lift + screen_kit
48,339 B   pixel engine (pqsigner-ui-px crate + secure/src/ui/px/)
--------
130,707 B  total UI
```

The device is currently paying for BOTH renderers at once. That is not an
accident and it is not permanent — mhaas's own `docs/ui/pixel-ui-port-plan.md`
step 5 ("Switch over") says:

> Text `Ui` backends become the px presenter; drop the on-device text painter.
> Keep the page painters as host-only fact producers (they are what the fact
> tests compare against).

So **~45 KB of the 76,949 B shortfall is duplication the port plan already
intends to remove** — 59% of the gap, with no geometry change and no loss of
function.

Two caveats before treating that as free:
1. The legacy GLYPH BLITTER (`ui/lcd.rs` + `FONT_FLAT_5X8`, ~480 B) must STAY —
   it is the fail-closed fallback when the NS atlas does not verify, and the
   atlas fix committed in 7e7a8900 makes that fallback load-bearing. Only the
   45 KB of PAGE PAINTERS go; the tiny blitter does not.
2. Whether the page painters are genuinely redundant on-device depends on
   whether `px_lift` LIFTS the proven pages or RE-DERIVES the content. The audit
   found it re-derives (`px_lift.rs:252`, MEDIUM, unrefuted). That cuts both
   ways: re-derivation is exactly why the page painters are droppable, and also
   exactly why two derivations could disagree. Dropping them removes the second
   derivation — which REMOVES the divergence risk rather than adding to it, at
   the cost of losing the on-device cross-check.

### Revised arithmetic
```
shortfall                                        76,949 B
- finish port step 5 (drop on-device page painters)  ~45,500   (mhaas's own plan)
- sha2 -> opt-level "s"                                4,556   (measured)
- kill the &[&str; 2048] const via build script       ~16,384   (unmeasured)
                                                   ----------
                                                    ~66,440
remaining                                           ~10,500 B
```
Close enough that lever A may not be needed at all — but every one of those
three still has to be done and measured, and the last ~10 KB is unfound.

---

# CORRECTIONS after GPT-6 Astra's review (verified by me, not relayed)

## C1. The 16,384 B blob is NOT the wordlist. I was wrong.

Astra identified `.Lanon.eeabc9bf...375` @ 0x0C071E9F as
`secure/data/erc7730-known-calls.bloom`. **Verified**: I extracted the 16,384
bytes from the ELF and hashed both.
```
blob sha256 : 9269d7224a81364644f38cad7ad0be541597f253522921557a6c96a384ee904d
file sha256 : 9269d7224a81364644f38cad7ad0be541597f253522921557a6c96a384ee904d
IDENTICAL   : True
```
My 2048 x 8 = 16,384 reasoning was a coincidence. It is an ERC-7730 known-call
Bloom filter, included at `secure/src/db_roots.rs:137`, and per Astra it stops a
hostile companion omitting known-call metadata to obtain a lower-tier /
blind-sign fallback (`tx/display/dispatch.rs:985`, with an occupancy gate at
`dbgen/src/erc7730.rs:3289`). **Credit ZERO savings, and do not shrink it
without changing refusal behaviour.** My "~16 KB wordlist refactor" line is
deleted.

## C2. I double-counted the atlas in the NS slot.

`docs/ui/pixel-ui-port-plan.md:287` reads "97,808 B non-secure (atlas 75,128 B
of ITS 77,824 B window)" — the atlas is INSIDE the 97,808, not additional. So NS
occupancy is **97,808 B of 499,712 (20%)**, ~402 KB spare per slot, not the
175,632 I wrote. The NS slot is MORE over-provisioned than I said.

## C3. SHA-512 CAN be shrunk — but not by opt-level.

`sha2 0.10.9` ships a `force-soft-compact` feature whose SHA-512 uses fixed
80-round loops with public schedule indices (no secret-dependent branches or
lookups), so it is compatible with the house constant-time rule. Astra budgets
**22-26 KB, explicitly an estimate and not a measured replacement build**. Two
cautions it raises: the feature changes software SHA-256 too, and there is a
SECOND SHA-512 consumer in bootstrap derivation (`domain/src/lib.rs:149`) that
must migrate as well or the old symbol survives. My measured 4,556 B was for the
WRONG mechanism (opt-level); this is the right one, still unmeasured.

## C4. Bank swap IS a hazard for a cross-bank image — I said it was safe.

I read 7.5.8 as "attributes follow their bank, so no hazard". Astra is right that
this is about ATTRIBUTES, not about a linked image: swapping exchanges whole bank
mappings, so the two halves of a cross-bank image move to different addresses.
Mitigation: with `TZEN=1` and `BOOT_LOCK=1`, `SWAP_BANK` cannot be modified (7.4.2),
and `BOOT_LOCK` also locks `SECBOOTADD0`. Freeze and VERIFY `SWAP_BANK=0`.

## C5. RDP-2 is not an absolute freeze.

`SWAP_BANK` is excepted from the general option-byte freeze, and provisioning an
OEM2 key permits authenticated RDP-2 regression (7.4.2, 7.6.2). Invariant #10's
"frozen forever" therefore needs BOOT_LOCK and the ABSENCE of an OEM2 key, not
just RDP-2 + WRP. The repo already knows this (`shared/src/lockdown.rs:225`).

## C6. Read-while-write constrains a cross-bank image.

Reads from the bank being programmed/erased stall. A single image spanning both
banks cannot assume its instructions, literals and interrupt handlers stay
available during either bank's erase (7.3.5, 7.3.10). Astra's preferred layout —
**one complete secure slot per bank, plus a small NS partition in each bank** —
avoids straddling the boundary altogether and is cleaner than my sketch.

## C7. Astra's capacity target

| per slot | pages | bytes |
|---|---:|---:|
| Secure | 80 | 640 KiB |
| Nonsecure | 32 | 256 KiB |

Leaves 20 pages for existing non-image roles plus 12 spare, and 111,467 B of
headroom above the measured secure image. Also flags that TODAY's driver rejects
bank-2 secure-alias writes (`secure/src/hw/flash.rs:1341`) and today's
option-byte check REQUIRES an empty bank-2 watermark
(`shared/src/lockdown.rs:479`) — both must change.

## C8. What Astra missed, and I did not

Astra's lever-B ceiling is 28-32 KB and it concludes "even deleting the entire
SHA-512 symbol and prefix table saves only 33,950 B, leaving 42,999 B short" —
so it ranks A first. But its analysis does not account for the **45,488 B of
legacy on-device page painters** that the image carries alongside the new screen
emitters, which mhaas's own port plan step 5 removes. That single item is larger
than Astra's entire lever-B budget and changes the conclusion materially.

## Corrected arithmetic

```
shortfall                                              76,949 B
- finish port step 5 (drop on-device page painters)    ~45,500   measured size, plan already intends it
- sha2 force-soft-compact (BOTH SHA-512 consumers)     ~22-26k   Astra estimate, UNMEASURED
- drop the duplicate prefix table in the secure build    6,144   Astra suggestion
- erc7730 bloom filter                                       0   NOT available (C1)
                                                     ----------
                                                      ~74-78 KB
```
That lands on the shortfall with no margin, and two of the three lines are
unmeasured. It is enough to justify DOING them and re-measuring before
committing to a geometry migration — it is NOT enough to declare the gap closed.
