**REJECT as a ratifiable specification.** The allocation fits, but v2 still leaves irreversible acceptance conditions unspecified. Its wordlist proposal also understates the consequence of tampering.

Reviewed HEAD `f1fde83a`; v2 SHA-256 `668708efa6ea15e3bc9e445ddba0fcf0b732a98591937a18738c0685dbf4eb6b`. Source, RM and ELF inspection only; no builds, hardware operations or file changes.

For **Part A**, these are specification dispositions—not claims that the implementation is fixed:

| v2 §1 item | Disposition | Evidence / remaining defect |
|---|---|---|
| Factory `BOOT_LOCK` | **PARTIALLY FIXED** | Correct lifecycle placement. Still missing explicit DFU cutoff, ordering before lock, and device-side verification discussed below. |
| Watermarks after TZEN | **FIXED** | RM0456 §7.5.1/Table 58 supports exactly this correction. The existing script already uses separate writes after reset: [flash-evt-dfu.sh:103](/home/nicola/repos/pq1-uipx-merge-wt/tools/flash-evt-dfu.sh:103). |
| `SECBOOTADD0` field | **FIXED** | `0x180000` is the CLI field; the register encodes the address. [lockdown.rs:53](/home/nicola/repos/pq1-uipx-merge-wt/shared/src/lockdown.rs:53). |
| Geometry digest | **PARTIALLY FIXED** | The false claim is withdrawn, but no replacement domain/schema is selected or made a §4 blocker. The current preimage remains geometry-free: [v6.rs:423](/home/nicola/repos/pq1-uipx-merge-wt/fw-manifest/src/v6.rs:423). |
| Preserved pages | **FIXED**, for bank 1 | `0–4,6–11` correctly excludes Manifest A. The complete updater-preserved set must additionally name bank-2 `0–4,6,99–103`. |
| Factory identity allocation | **PARTIALLY FIXED** | Capacity exists. Factory-written ownership, authentication and pre-lock acceptance remain undefined. |
| RM citations | **FIXED** | RWW §7.3.10; RDP-2 freeze §7.6.2. |
| Lean geometry | **FIXED** as diagnosis | Both NS windows **and secure footprints** require revision: [MemoryMap.lean:72](/home/nicola/repos/pq1-uipx-merge-wt/contracts/verification/lean/SphincsCVerify/Platform/MemoryMap.lean:72), `:92`. |
| 92/24 split | **PARTIALLY FIXED** | Arithmetic is sound; production capacity remains unmeasured. Increasing NS capacity does not discharge the v1 measurement objection. |

**A1 — The ordering is executable, but §3 is not yet an executable ceremony.** CubeProgrammer supports successive `-ob` transactions. Your script specifically records that secure fields are unavailable until TZEN has been applied and the chip reset. [ST CLI documentation](https://dev.st.com/stm32cube-docs/prog/2.23.0/en/docs/markup/CubeProg_Command_Lines.html#ob).

The required ordering should explicitly be:

1. Program and verify required contents through the selected factory interface.
2. Activate TZEN at RDP-0; reload and reconnect.
3. Set and read back both watermarks, HDP configuration, boot address and `SWAP_BANK=0`.
4. Finalize and verify both FSBL copies and WRP settings.
5. Set `BOOT_LOCK`; reload; verify the final profile through SWD.

An ordinary OBL does **not** erase programmed main flash. It resets execution and volatile configuration; the special TZEN-activation transition resets SECWM/HDP. Previously committed option bytes persist, subject to those transition rules. Check programming errors: RM §7.4.2 says failed option programming retains the old values.

Explicitly place `SECBOOTADD0` and `SWAP_BANK` before `BOOT_LOCK`: RM §7.4.2 prohibits changing the former with BOOT_LOCK set, and the latter with both TZEN and BOOT_LOCK set.

**A2 — Yes, factory BOOT_LOCK ends the sealed-EVT ROM-DFU route. Say so explicitly.** RM §3.3.1 forces the secure boot entry irrespective of BOOT0. Consequently:

- [flash-evt-dfu.sh:59](/home/nicola/repos/pq1-uipx-merge-wt/tools/flash-evt-dfu.sh:59) cannot enter its normal workflow on a locked board.
- Its post-write `wait_dfu` and USB readback sequence cannot follow a BOOT_LOCK-setting transaction.
- The script also contains legacy image addresses and watermark values; it is not a v7 provisioner.

This does **not** invalidate factory BOOT_LOCK: RDP-0 SWD remains the intended verification path. Retain a clearly separate BOOT_LOCK=0 bench profile, and require accessible SWD for final production verification/rework.

**A3 — No inherent blank-page conflict, but a new acceptance obligation.** “Secure” does not mean “must be blank.” The anti-preplant contract applies to the five mutable first-boot owners. Bank-2 `99–103` can be a distinct factory-written owner outside that scan.

The missing rule is:

> Blank-check exactly bank-1 `7–11`; authenticate and validate the factory record separately, before confirmation and RDP-2; preserve its pages during updates and define wipe/reprovision behavior.

The existing Phase-A path checks the five pages and OTP-master presence, then offers confirmation; it authenticates no factory record: [first_boot/mod.rs:196](/home/nicola/repos/pq1-uipx-merge-wt/secure/src/first_boot/mod.rs:196). The owner document explicitly requires receipt verification **before** burning: [first-boot-provisioning.md:346](/home/nicola/repos/pq1-uipx-merge-wt/docs/provisioning/first-boot-provisioning.md:346).

A reservation is adequate for geometry exploration. It is insufficient to authorize first-boot locking.

**A4 — Silicon does not require symmetry.** RM §7.5.2 defines independently selected per-bank intervals. The project’s [architecture:1684](/home/nicola/repos/pq1-uipx-merge-wt/docs/security/a-b-firmware-rollback-architecture.md:1684) does request selected symmetric coverage.

Under the proposed ownership, however, equality wastes **no additional page**: slot B ends at 98 and the five secure factory pages fill 99–103. Both banks therefore naturally end their secure runs at 103. Reducing the reservation could enlarge NS **B** alone; it would not enlarge the paired NS capacity constrained by bank 1.

For **Part B**, my recommendation is to retain these inputs in secure storage and first pursue representation/code-size changes.

**B1 — Moving the wordlist is technically possible, but the draft misses its most serious role.**

The premise at [v2:125](/home/nicola/repos/pq1-uipx-merge-wt/docs/security/geometry-v7-draft-v2.md:125) is false. FSBL verifies both image hashes at [main.rs:189](/home/nicola/repos/pq1-uipx-merge-wt/fsbl/src/main.rs:189), then renders at `:264`; [verify.rs:67](/home/nicola/repos/pq1-uipx-merge-wt/fsbl/src/verify.rs:67) explicitly hashes NS.

That does not make an externally supplied fingerprint vocabulary automatically trustworthy. Invariant #10 distrusts subsequent updates: a vendor-signed NS image must not redefine what the immutable FSBL’s words mean. Moving its table requires an **FSBL-pinned canonical table hash**, fixed bounds and verification before rendering. Alternatively, retain the FSBL’s existing 6,144-byte copy; moving the secure application’s copy does not require moving the FSBL copy.

More seriously, [Mnemonic::to_seed:301](/home/nicola/repos/pq1-uipx-merge-wt/bip39/src/full.rs:301) resolves all 24 words through FLAT/LENS and uses those bytes as the PBKDF2 password. Replacing every entry with one fixed word and length makes that password independent of the secret indices. With the current empty passphrase, the derived seed becomes predictable.

Therefore these tables are **key-derivation inputs**, not merely display assets. Every derivation, restore lookup and display must consume authenticated, stable bytes. Dialog-only checks are insufficient. Moving them is defensible only with a substantially stronger consumption contract; I would not choose it here.

**B2 — A tampered Bloom filter permits downgrade.** Clearing a queried bit makes a known tuple appear absent. Both redundant queries then honestly agree on the wrong result: [erc7730.rs:232](/home/nicola/repos/pq1-uipx-merge-wt/secure/src/tx/erc7730.rs:232). The companion can omit its descriptor and reach a lower dispatch tier, including blind signing, instead of hard refusal. Setting bits primarily buys denial of service. Native Safe/CoW routes already selected earlier are unaffected.

Verify-before-use closes persistent substitution **only if the authenticated bytes are the bytes queried**. Use a secure snapshot, enforced write exclusion, or an equivalent demonstrated stability property. Pre/post hashes alone do not prove safety against change-use-restore. Authentication failure must refuse, never mean “unknown call.”

**B3 — There are better secure-storage options.** Counts below are gross table savings; replacement code must be measured.

| Change | Byte cost / saving | Risk |
|---|---:|---|
| Derive application PREFIX5 from its existing full-word lookup; retain FSBL’s standalone prefix table | Save **6,144 B** in secure application | Low: preserve exact truncation/padding and existing constant-time lookup. |
| Remove LENS; count nonzero bytes across all eight padded positions | Save **2,048 B** | Low/moderate: fixed iteration count; no secret-dependent early termination. |
| Pack eight letters/padding as eight 5-bit symbols | **10,240 B**, replacing FLAT+LENS’s 18,432 B: save **8,192 B** | Moderate: fixed-width scanning remains possible; audit generated constant-time decode and lookup paths. |
| Packed words plus derived PREFIX5 | Save **14,336 B** | Best combined table candidate. Keep the FSBL-only representation separately. |
| Concatenated ASCII plus one length byte per word | **13,116 B**: save **5,316 B** | More awkward scanning. A 2-byte offset table consumes another 4,096 B. |

The actual wordlist contains **11,068 letter bytes**; approximately 13 KB includes separators. The padded representation was deliberate side-channel engineering, not accidental waste: [full.rs:29](/home/nicola/repos/pq1-uipx-merge-wt/bip39/src/full.rs:29). Any compression must preserve its full-scan behavior.

**Shrinking the Bloom is unattractive.** The actual file has 28,646/131,072 bits set for 4,615 tuples. Folding it correctly to 8 KiB produces **25,452/65,536 bits set—38.84%**, violating the generator’s 25% cap at [erc7730.rs:3292](/home/nicola/repos/pq1-uipx-merge-wt/dbgen/src/erc7730.rs:3292). Its approximate false-positive rate rises to 0.135%.

A rebuilt 14 KiB filter is estimated near 24.55% occupancy and saves only **2,048 B**. That also changes the current power-of-two indexing assumptions and requires regeneration, occupancy verification and zero-false-negative checks. Do not truncate the file.

**B4 — No: 40,960 B is not worth these added trust obligations given the claimed buffer.** It is a 28.7% increase over the 142,704-byte buffer, but relocation also consumes NS capacity, reducing the stated NS headroom from 98,800 to **57,840 B**, before added verification code. First establish the real production footprint.

**B5 — Three substantial `.text` opportunities are evidenced by this ELF.** These are measured optimization targets, **not promised net savings**:

| Opportunity | Existing `.text` footprint | Concrete approach |
|---|---:|---|
| SHA-2 compression backends | SHA-512 **27,806 B**; SHA-256 **7,202 B** | The installed `sha2 0.10.9` has **`force-soft-compact`**, a different backend from merely changing optimization level. It selects loop-based compression. |
| Single/batch UserOp handlers | `run`: **14,224 + 18,088 = 32,312 B** | Factor identical envelope decoding and common stages into non-inlined secure helpers. Matching header loads are visible at [single:279](/home/nicola/repos/pq1-uipx-merge-wt/secure/src/nsc/cmd_sign_userop.rs:279) and [batch:270](/home/nicola/repos/pq1-uipx-merge-wt/secure/src/nsc/cmd_sign_userop_batch.rs:270). Preserve each path’s independent FI and release checks. |
| Pixel scene/animation implementation | UI-crate symbols total **36,214 B**; `Anim::build` alone **11,734 B** | Factor repeated drawing sequences and simplify optional animation states in [scene.rs:885](/home/nicola/repos/pq1-uipx-merge-wt/pqsigner-ui-px/src/scene.rs:885). Keep trusted text/layout/confirmation authority secure. |

The compact SHA backend is the strongest immediate experiment. It needs timing, stack and cryptographic checks: its SHA-512 implementation explicitly allocates an 80-word schedule—**640 bytes**—at [soft_compact.rs:16](/home/nicola/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/sha2-0.10.9/src/sha512/soft_compact.rs:16). Cargo feature unification also warrants checking effects on FSBL.

I found no comparably large block that can simply execute in hostile NS while retaining its existing authority.

For **Part C**, the strongest omitted gate is the device’s final protection-profile check.

[v2 §4](/home/nicola/repos/pq1-uipx-merge-wt/docs/security/geometry-v7-draft-v2.md:81) does not require updating either lockdown predicate. Both still demand all-secure bank 1 and all-NS bank 2: [lockdown.rs:440](/home/nicola/repos/pq1-uipx-merge-wt/shared/src/lockdown.rs:440), `:489`. Unchanged, they reject v7.

A superficial watermark-only repair is dangerous:

- The boot-address predicate explicitly ignores `BOOT_LOCK`: [lockdown.rs:75](/home/nicola/repos/pq1-uipx-merge-wt/shared/src/lockdown.rs:75).
- The WRP predicate accepts coverage ending at **page 3**, not 4: `:376`.
- `verify_ship_profile` receives **no WRP2 register**: `:428`.
- Its OPTR check ignores `SWAP_BANK`: `:308`.

Current production fences and unpinned checks prevent this from being a demonstrated shipping exploit. They do **not** make v2’s implementation checklist sufficient. Require complete factory, pre-lock and every-boot checks of the appropriate final profile, with negative cases for missing page-4 protection, unprotected mirror, BOOT_LOCK clear and swapped banks.

No additional whole-page role is evidently missing. NSC veneers can remain inside their secure-slot allocation. But both slot-specific links, veneer imports, active NS/atlas bases, full LOAD-span accounting and the SRAM mutation closure must remain explicit cutover obligations. Present tooling only accepts secure slot A: [build.rs:109](/home/nicola/repos/pq1-uipx-merge-wt/secure/build.rs:109).

The supplied monolithic ELF’s physical initialized flash span is **543,904 B**. It does not establish production fit. [Makefile:2817](/home/nicola/repos/pq1-uipx-merge-wt/Makefile:2817) documents omitted production features; `:2827` omits NS USB/IWDG, and `:2856` still measures NS using `text+data`. Restore v1’s explicit prohibition on ratifying the split before production slot-linked LOAD measurements.

Ranked defects and fixes:

1. **CRITICAL — Incomplete pre-RDP-2 protection acceptance contract.** Require the complete final profile in factory verification, device pre-lock verification and phase-appropriate FSBL checks; close both-bank WRP and BOOT_LOCK omissions.
2. **MAJOR — Artifact incompatibility remains unspecified.** Select and freeze the new schema/domain or signed geometry identifier; require rejection of legacy artifacts across signer, updater and FSBL.
3. **MAJOR — Production capacity gate disappeared.** Restore mandatory physical LOAD-span measurements for both S/NS slot pairs and the completed FSBL.
4. **MAJOR — Factory reservation lacks its acceptance/lifecycle contract.** Name its owner, maximum format, authentication/binding, pre-lock failure behavior and update/wipe preservation; keep it outside the five-page blank scan.
5. **MAJOR — Factory sequencing omits the DFU cutoff.** Specify boot address/swap before BOOT_LOCK and SWD verification after it.
6. **MAJOR if §5 relocation is adopted — Wordlist threat model omits key derivation.** Authenticate stable bytes at every consumer; preferably retain and compact them in secure storage.
7. **MINOR — False FSBL verification-order claim.** Correct v2:125; image verification precedes fingerprint rendering.

**Verdict: REJECT.**

**Single most important unresolved issue: proving that the device checks the complete intended protection profile before RDP-2 makes any omission permanent.**