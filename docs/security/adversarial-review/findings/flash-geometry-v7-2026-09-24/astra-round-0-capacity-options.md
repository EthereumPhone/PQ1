**I would choose A as the capacity fix, retain secure A/B, and apply B for additional headroom.** Hardware supports secure flash in both banks. The main difficulty is migrating the boot/update contract consistently.

I read the merged tree at `7e7a89009425a24d0449b97a5d6f88652f2ff212` and inspected the supplied ELF. No files were modified or builds run.

ST citations below refer to the supplied local [RM0456 Rev 7](/home/nicola/repos/blinky/docs/rm0456-stm32u5-series-armbased-32bit-mcus-stmicroelectronics-1.pdf), [ES0499 Rev 12](/home/nicola/repos/blinky/docs/es0499-stm32u575xx-and-stm32u585xx-device-errata-stmicroelectronics.pdf), [DS13086 Rev 10](/home/nicola/repos/blinky/docs/stm32u585ai-2.pdf), and [PM0264 Rev 8](/home/nicola/repos/blinky/docs/pm0264-stm32-cortexm33-mcus-and-mpus-programming-manual-stmicroelectronics-1.pdf).

**1a–b. Bank 2 supports a secure watermark; each bank gets one contiguous watermark range.**

RM0456 §7.5.2, pp. 309–310 explicitly says:

> “one area per bank can be selected with a page granularity.”

The surrounding text specifies `TZEN=1`, nonvolatile option-byte configuration, and `FLASH_SECWM1R1` / `FLASH_SECWM2R1`. Start/end page numbers are inclusive; start greater than end means no secure area. DS13086 §§3.4, 3.4.2 confirms two 128-page banks with 8 KiB pages for this device family; §7 identifies density code `I` as 2 MiB.

Pages outside that watermark remain nonsecure unless secured through SECBB. **An NS image need not be split:** place the secure watermark at one end and fit the NS image in the remaining contiguous range. A middle watermark leaves two NS ranges, but neither hardware nor software requires using both.

The current updater does require each image to occupy one contiguous `base + offset` range. It cannot transparently skip secure islands. See [staging.rs:35](/home/nicola/repos/pq1-uipx-merge-wt/secure/src/fw_update/staging.rs:35) and [staging.rs:74](/home/nicola/repos/pq1-uipx-merge-wt/secure/src/fw_update/staging.rs:74).

**1c. The secure aliases are contiguous, but the current allocations are not.**

For this 2 MiB part, with banks unswapped:

- Bank 1: `0x0C00_0000–0x0C0F_FFFF`.
- Bank 2: `0x0C10_0000–0x0C1F_FFFF`.

RM0456 §7.3.1, Table 52, and §7.5.8, Figure 23 footnote 1 establish the mapping. A correctly linked secure image **can span that boundary**, provided flash attribution and SAU/MPU settings permit its accesses. Secure attribution is address-dependent, not merely a consequence of executing secure code: PM0264 §2.3.4.

However, extending today’s slot linearly would encounter journals, persistent state and the bank-2 FSBL mirror. Those allocations must move, or the image format must support multiple extents. [geometry/src/lib.rs:102](/home/nicola/repos/pq1-uipx-merge-wt/geometry/src/lib.rs:102)

Execution consequences:

- **Latency:** RM0456 §7.3.3 specifies `FLASH_ACR.LATENCY` from HCLK/VCORE. I found no additional bank-boundary wait-state requirement or prohibition on sequential execution across it.
- **Read-while-write:** reads from the bank being programmed/erased stall; reads from the other bank continue. A cross-bank application cannot assume all its instructions, literals and handlers remain available during either bank’s erase. RAM-resident update machinery or carefully bounded stalls may be necessary. RM0456 §§7.3.5, 7.3.10.
- **Errata:** I found no internal-flash bank-crossing-specific erratum in supplied ES0499 Rev 12. Relevant adjacent issues are §2.2.25, stuck programming after a sequence error; §2.2.26, low-power-entry hangs involving flash prefetch on revisions X/W; and §2.2.11, cache-access corruption after Stop 2/3 on revision X. Your part number does not establish its silicon revision.

**1d. SECBB is volatile and could substitute for a watermark—but adds a boot obligation.**

RM0456 §7.5.1 calls block-based attribution volatile; §7.9.30 gives `FLASH_SECBB2Rx` reset value zero. Section 7.5.4 permits arbitrary pages to become secure dynamically. Clearing SECBB cannot override an existing secure watermark.

For this project, the **FSBL should establish and verify those attributes before accessing the added secure image through its secure alias, and before releasing any NS execution or relevant NS bus master**. Otherwise an unconfigured boot loses the intended protection. No SECBB initialization exists in the inspected FSBL/secure sources.

For permanent secure-image partitions, I prefer nonvolatile SECWM over relying on this extra per-reset operation. SECBB also does not provide HDP coverage by itself.

**1e. Invariant #10 remains achievable across banks, with conditions.**

`SECBOOTADD0` selects the initial boot address; it does not constrain the application to the same bank. Keep it pointing to the immutable FSBL. RM0456 §7.9.16.

The FSBL must authenticate **all installed secure-image bytes in both banks**, including initialized-data load images and veneers, plus the paired NS image and its atlas. A contiguous image can retain one base/length hash. A fragmented image needs an unambiguous extent mapping shared by signing, installation and verification.

Currently the FSBL verifies both S and NS hashes, but returns—and displays—the **secure hash alone**. The displayed words are not a combined S+NS digest. [verify.rs:37](/home/nicola/repos/pq1-uipx-merge-wt/fsbl/src/verify.rs:37), [main.rs:264](/home/nicola/repos/pq1-uipx-merge-wt/fsbl/src/main.rs:264)

WRP supports **two page-granular ranges per physical bank**. It can protect both FSBL copies regardless of where applications live. WRP-protecting the entire application would also prevent its updates; invariant #10 needs immutable measuring code, not immutable measured applications. RM0456 §7.6.1. The frozen contract specifically requires WRP1A/WRP2A over pages 0–4. [rollback architecture:1674](/home/nicola/repos/pq1-uipx-merge-wt/docs/security/a-b-firmware-rollback-architecture.md:1674)

HDP is a prefix of each bank’s secure watermark. Once `HDPx_ACCDIS` is set, instruction fetches, reads, writes and erases of that region are denied until reset. Do not close HDP over code the application still needs. RM0456 §7.5.3.

**RDP-2 alone does not mean “everything is frozen forever”:**

- `SWAP_BANK` is explicitly excepted from the general option-byte freeze.
- Provisioning an OEM2 key permits authenticated RDP-2 regression.

The intended guarantee therefore requires the proper `BOOT_LOCK` configuration and absence of an OEM2 regression key, alongside WRP. RM0456 §§7.4.2, 7.6.2, p. 320. The repo recognizes the OEM-key requirement. [lockdown.rs:225](/home/nicola/repos/pq1-uipx-merge-wt/shared/src/lockdown.rs:225)

**1f. Bank swap is a real hazard unless constrained.**

Swap exchanges whole bank mappings; watermark, WRP and SECBB attributes follow their **physical banks**. It does not relocate a linked application correctly or exchange arbitrary A/B slots. A cross-bank image’s halves would move to different addresses. RM0456 §7.5.8.

With `TZEN=1` and `BOOT_LOCK=1`, `SWAP_BANK` cannot be modified; `BOOT_LOCK` also locks `SECBOOTADD0`. RM0456 §7.4.2. Freeze and verify `SWAP_BANK=0`; do not use bank swapping as this updater’s activation mechanism. The existing architecture already requires that setting. [rollback architecture:1683](/home/nicola/repos/pq1-uipx-merge-wt/docs/security/a-b-firmware-rollback-architecture.md:1683)

**2. Lever B realistically offers roughly 30 KB from the identified safe changes, not 77 KB.**

**SHA-512:** the pinned `sha2 0.10.9` already supplies `force-soft-compact`. Its compact SHA-512 uses fixed 80-round loops and public schedule indices, with arithmetic/bitwise operations rather than secret-dependent branches or lookups. That source structure is compatible with the project rule; compiled constant-time behavior, stack use and unlock latency still need validation. It allocates an 80-word schedule—640 bytes before other locals. [compact implementation:13](/home/nicola/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/sha2-0.10.9/src/sha512/soft_compact.rs:13), [CLAUDE.md:230](/home/nicola/repos/pq1-uipx-merge-wt/CLAUDE.md:230)

Two implementation cautions:

- The feature changes **both SHA-512 and software SHA-256**, so its effects extend beyond unlock.
- Changing only BIP-39’s hash implementation leaves another SHA-512 consumer in bootstrap derivation. Both must migrate to eliminate the old compression symbol. [sha256.rs:3](/home/nicola/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/sha2-0.10.9/src/sha256.rs:3), [domain/src/lib.rs:149](/home/nicola/repos/pq1-uipx-merge-wt/domain/src/lib.rs:149)

I would provisionally budget **22–26 KB saved** from replacing the 27,806-byte implementation. That is an engineering estimate, **not a measured replacement build**. The current speed override is explicit. [Cargo.toml:172](/home/nicola/repos/pq1-uipx-merge-wt/Cargo.toml:172)

**Wordlists:** the full table is needed for mnemonic rendering and seed construction, but both representations need not coexist in the secure application. Implement its prefix lookup by constant-time selecting the full eight-byte word and returning the first five bytes. Keep the compact prefix table for the FSBL-only build. This saves approximately **6,144 B**, less any code delta, without constructing another RAM table. Preserve the scan barriers. [full.rs:108](/home/nicola/repos/pq1-uipx-merge-wt/bip39/src/full.rs:108), [full.rs:543](/home/nicola/repos/pq1-uipx-merge-wt/bip39/src/full.rs:543), [build.rs:114](/home/nicola/repos/pq1-uipx-merge-wt/bip39/build.rs:114)

**Anonymous blob identified:** `.Lanon.eeabc9bfd230fe3da27a16fc3b77dcd0.375`, at **`0x0C071E9F`**, is byte-for-byte identical to:

`secure/data/erc7730-known-calls.bloom`

I checked its ELF bytes against the complete 16,384-byte file; SHA-256 is `9269d7224a81364644f38cad7ad0be541597f253522921557a6c96a384ee904d`. Its source inclusion is [db_roots.rs:137](/home/nicola/repos/pq1-uipx-merge-wt/secure/src/db_roots.rs:137).

It prevents a hostile companion from omitting known-call metadata and obtaining a lower-tier/blind-sign fallback. **Credit zero easy savings here.** Removing it changes security behavior; shrinking it changes refusal rates and hits an explicit occupancy gate. [dispatch.rs:985](/home/nicola/repos/pq1-uipx-merge-wt/secure/src/tx/display/dispatch.rs:985), [dbgen/src/erc7730.rs:3289](/home/nicola/repos/pq1-uipx-merge-wt/dbgen/src/erc7730.rs:3289)

Thus **28–32 KB is a reasonable provisional B budget**. Even deleting the entire SHA-512 symbol and prefix table, with zero replacement cost, saves only **33,950 B**, leaving **42,999 B** short.

**3. Slot symmetry is a software/product constraint, not a hardware requirement.**

The current contract uses one `SECURE_SLOT_SPAN` for both slots, and v6 validates both against it. Legacy updater/FSBL code likewise shares one capacity. Unequal slots require slot-specific admission, verification, erase ranges and release-tool limits. [geometry:31](/home/nicola/repos/pq1-uipx-merge-wt/geometry/src/lib.rs:31), [v6.rs:584](/home/nicola/repos/pq1-uipx-merge-wt/fw-manifest/src/v6.rs:584), [cmd_fw_begin.rs:134](/home/nicola/repos/pq1-uipx-merge-wt/secure/src/nsc/cmd_fw_begin.rs:134)

Ordinary alternating updates remain constrained by the **smaller slot**. A permanently smaller recovery image is a different recovery architecture; the selected contract pairs both slot artifacts with the same logical source/policy identity. [rollback architecture:282](/home/nicola/repos/pq1-uipx-merge-wt/docs/security/a-b-firmware-rollback-architecture.md:282)

Even “pixel A, non-pixel B” fails today’s arithmetic:

- Pixel image: **67 pages**.
- Non-pixel image: **53 pages**.
- Available secure-image capacity: **114 pages**.
- Required: **120 pages**, six pages too many.

Also distinguish frozen geometry from running legacy code: the latter still uses **58-page S / 64-page NS** capacities. The migration is explicitly unfinished. [fw-manifest/src/lib.rs:106](/home/nicola/repos/pq1-uipx-merge-wt/fw-manifest/src/lib.rs:106), [rollback architecture:1691](/home/nicola/repos/pq1-uipx-merge-wt/docs/security/a-b-firmware-rollback-architecture.md:1691)

**4. The NS allocation is substantially oversized for the evidenced image.**

Its 61 pages arise directly from dividing the bank remainder: `(128 − 5 FSBL − 1 reserved) / 2`. It is not symmetric with the 57-page secure slot. I found no quantified future-growth requirement justifying 499,712 B. [geometry:115](/home/nicola/repos/pq1-uipx-merge-wt/geometry/src/lib.rs:115)

The recorded **97,808 B already accompanies the atlas-bearing build**. Do not add the atlas again. The linker reserves `[slot+0x1000, slot+0x14000)` and starts code afterward. [port plan:285](/home/nicola/repos/pq1-uipx-merge-wt/docs/ui/pixel-ui-port-plan.md:285), [NS linker:21](/home/nicola/repos/pq1-uipx-merge-wt/nonsecure/memory-stm32u585-px.x:21)

Twelve pages hold 97,808 B arithmetically but leave only 496 B; that is not a sensible product budget, and final sizing must use the complete load span including gaps.

**256 KiB per NS slot** is a defensible conservative allocation pending final release measurements. It returns **237,568 B per slot, 475,136 B total**, while retaining about 164 KB above the reported image.

**5. My ranking is A → B → C → D.**

For **A**, I would explore **one complete secure slot per bank**, with a small NS partition in each bank. That avoids needing a single secure image to straddle the boundary.

A concrete capacity target is:

| Allocation | Per slot |
|---|---:|
| Secure | **640 KiB / 80 pages** |
| Nonsecure | **256 KiB / 32 pages** |

Across both banks, that leaves **20 pages for existing non-image roles plus 12 additional pages**. Each secure slot has **111,467 B** above your measured image.

This requires moving persistent pages into secure prefixes and relocating one NS slot; it is a deliberate geometry redesign. Preserve both FSBL copies and all state owners. Rewire linkers, manifests, signing tools, flash-bank dispatch, SAU/NS-pointer ranges and atlas lookup together. Today’s driver rejects bank-2 secure-alias writes, and today’s option-byte check requires an empty bank-2 watermark. [flash.rs:1341](/home/nicola/repos/pq1-uipx-merge-wt/secure/src/hw/flash.rs:1341), [lockdown.rs:479](/home/nicola/repos/pq1-uipx-merge-wt/shared/src/lockdown.rs:479)

For **B**, take the compact-hash and duplicate-prefix savings after measurement; keep them as growth margin.

For **C**, reaching 34,071 B requires removing **69.3%** of the measured UI increment merely to fit. I found no demonstrated cut plan supporting that target. I would optimize identified duplication, but would not make that reduction the geometry strategy.

For **D**, I would reject removing secure A/B. It sacrifices both fallback and protection against interrupted replacement of the sole executable application. The current FSBL halts when no valid slot exists; it does not supply an independent recovery installer. [fsbl/main.rs:198](/home/nicola/repos/pq1-uipx-merge-wt/fsbl/src/main.rs:198)

**The biggest risk in A is freezing an inconsistent map into the immutable FSBL:** a missed alias, erase range or persistent-state address can brick updates or overwrite security state. Pre-production is the appropriate time to resolve that migration, but source feasibility is not silicon or shipment evidence.