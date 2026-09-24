**REJECT as written.** Shape B remains viable, but this draft contains incorrect protection settings, an unsupported artifact-rejection claim, and an incomplete cutover contract.

Reviewed HEAD `f1fde83a`, draft SHA-256 `736d03b65f2691c42ee0cc9b42ac7f2ddabbc2adac97c3e87c3ca2facfd098dd`, local **RM0456 Rev 7** and **ES0499 Rev 12**. No files modified. Evidence is source/manual inspection plus an in-memory range counterexample; no hardware execution.

**1. Missing page role — FAIL for shipping completeness; PASS for preserving today’s enumerated owners.**

You have not dropped a current `Owner` variant. In particular:

- **No separate shipping boot-state page is required.** The registry comment describes the replacement design, not the legacy bench design. PENDING/CONFIRMED live in manifest QWs; the try-once token occupies TAMP `BKP8..31`, alongside BHK’s `BKP0..7`. Route-1 journals serve OTP-launch intent, **not** probation state. [Rollback architecture:317](/home/nicola/repos/pq1-uipx-merge-wt/docs/security/a-b-firmware-rollback-architecture.md:317)
- **Rollback floor:** authoritative storage remains OTP; an OTP-shadow page is neither required nor permitted to replace that authority. [Rollback architecture:3896](/home/nicola/repos/pq1-uipx-merge-wt/docs/security/a-b-firmware-rollback-architecture.md:3896)
- **Duress, BHK, provisioning journal and salt:** retained by the map.

The missing disposition is **factory identity/attestation/handoff storage**:

- The supply-chain plan explicitly loads its device-binding manifest **from secure flash**, with a signature alone around 7.8 KB. [production-security.md:353](/home/nicola/repos/pq1-uipx-merge-wt/docs/security/production-security.md:353), [419](/home/nicola/repos/pq1-uipx-merge-wt/docs/security/production-security.md:419)
- The newer handoff candidate instead proposes OTP bytes `176..512`, while leaving the mechanism undecided—including a **4,008-byte C10 signature**, which cannot fit in that 336-byte region. [first-boot-provisioning.md:346](/home/nicola/repos/pq1-uipx-merge-wt/docs/provisioning/first-boot-provisioning.md:346)
- If authenticated OTP-floor records are selected, **redundant rollback-key storage is also unresolved**. The specification explicitly forbids borrowing the BHK page. [Rollback architecture:1168](/home/nicola/repos/pq1-uipx-merge-wt/docs/security/a-b-firmware-rollback-architecture.md:1168)

These documents do not establish one settled extra-page requirement. They establish an **unresolved allocation conflict that v7 cannot silently close**. Reserve secure provisioning space, or explicitly settle storage elsewhere before ratification. The five blank first-boot pages cannot absorb a factory-written record without changing their ownership and anti-preplant contract.

**2. S/N split — FAIL as a lifetime capacity justification.**

Sixteen pages fit the supplied current measurement. That does not establish lifetime fit.

The atlas already occupies a `0x13000` reservation. Doubling that reservation alone raises the supplied image span from 97,808 to approximately **175,632 B**, before additional protocol code. Additional font tiers, scripts, and chain/token marks are credible growth sources. This is a scenario, not a forecast.

Also fix the measurement gate: `PX_NS_FEATURES` omits **USB and IWDG**, and the NS check uses `text + data`, which omits layout gaps. The cited EVT build does include USB; do not charge that existing stack twice. Measure both final slot-linked NS images by physical LOAD span. [Makefile:2827](/home/nicola/repos/pq1-uipx-merge-wt/Makefile:2827), [2856](/home/nicola/repos/pq1-uipx-merge-wt/Makefile:2856), [evt-dev-flash.sh:55](/home/nicola/repos/pq1-uipx-merge-wt/tools/evt-dev-flash.sh:55)

My provisional preference is **84 S / 32 NS**, subject to the complete secure build:

| Split | Secure capacity | Surplus after 570,000 + 40,960 B | NS capacity |
|---|---:|---:|---:|
| 100 / 16 | 819,200 | 208,240 | 131,072 |
| 92 / 24 | 753,664 | 142,704 | 196,608 |
| **84 / 32** | **688,128** | **77,168** | **262,144** |

That transfers **131,072 B per slot** from secure to NS. Twenty-four NS pages are a reasonable intermediate choice; neither number is proven sufficient by today’s evidence.

**Equal NS capacities are not a hardware requirement.** NS B may be smaller, but every release intended to alternate between A/B must fit both slot-specific builds. Otherwise an A-resident release can outgrow its next B update destination. Equality avoids that smaller-slot ceiling and simplifies release admission.

**3. Protection profile — FAIL, with several correct components.**

- **SECWM: PASS.** PSTRT/PEND are inclusive. `0/0x6F` covers pages 0–111; `0/0x6A` covers 0–106. RM §§7.5.2, 7.9.17 and 7.9.21.
- **SECBOOTADD0: FAIL as a field value.** The encoding is:
  ```
  address                  = 0x0C000000
  SECBOOTADD0 field        = address >> 7 = 0x180000
  SECBOOTADD0R address bits = register & 0xFFFFFF80
  ```
  The field occupies register bits `[31:7]`; BOOT_LOCK occupies bit 0. Preserve reserved bits. `0x0C000000` is the destination address, not the CubeProgrammer field argument. RM §7.9.16; [lockdown.rs:37](/home/nicola/repos/pq1-uipx-merge-wt/shared/src/lockdown.rs:37).
- **BOOT_LOCK at first field boot: FAIL.** Draft 1.2 explicitly stages it at the factory; first boot may write **only RDP**. V7 contradicts both that rule and `FirstBootLockWriter`’s authority. [Draft 1.2:167](/home/nicola/repos/pq1-uipx-merge-wt/docs/security/fw-rollback-draft12-candidate-2026-07-21.md:167), [writer contract:2259](/home/nicola/repos/pq1-uipx-merge-wt/docs/security/a-b-firmware-rollback-architecture.md:2259). Burning RDP2 first makes a later BOOT_LOCK repair impossible. Setting BOOT_LOCK at the factory disables alternate boot selection, including the EVT recovery route, but **does not disable RDP0 SWD verification**. Production requires accessible SWD/NRST; sealed-EVT recovery is a separate constraint. [Factory requirement F8:213](/home/nicola/repos/pq1-uipx-merge-wt/docs/provisioning/first-boot-requirements.md:213), [ST boot-selection table](https://www.st.com/resource/en/reference_manual/rm0456-stm32u5-series-armbased-32bit-mcus-stmicroelectronics.pdf).
- **HDP: PASS for invariant #10; FAIL if “deferred” means enable later on shipped units.** WRP plus locked boot selection and RDP2 provides the stated persistent immutability. HDP adds post-boot access denial, not necessary WRP coverage. But HDP’s option bytes also freeze at RDP2. Select `HDP=0` explicitly before shipment; it cannot remain a future switch for those dies. RM §§7.5.3, 7.6.2.
- **WRP 0–4: PASS.** Protecting 40,960 B while LOAD occupies 28,704 B is legal. The remaining **12,256 B** must have defined, verified padding and remain identical across both FSBL copies. Do not shrink protection to the measured four occupied pages: the specification protects the complete five-page region. Add the omitted **`UNLOCK=0`** requirement. [Rollback architecture:1674](/home/nicola/repos/pq1-uipx-merge-wt/docs/security/a-b-firmware-rollback-architecture.md:1674), RM §§7.6.1, 7.9.19.
- “WRP1B/2B held in reserve” needs qualification: unused ranges cannot be newly configured after RDP2.

**4. Ordering and bricks — FAIL: “TZEN last” is not a complete provisioning sequence.**

**Enabling TZEN resets both SECWM areas to all-secure**, with HDP disabled. Therefore final v7 watermarks must be programmed **after TZEN activation and option-byte reload**. RM §7.5.1, Table 58. Writing them before the transition does not establish the final profile.

The required ordering is:

1. Identify the die/revision; verify RDP0, OTP compatibility and OEM-key state. Establish an external factory interlock preventing normal field boot.
2. Provision and durably verify the OTP transport master **before** installing credentials derived from it. Prepare and verify SE transport state before irreversible SE policy/lifecycle closure. The exact E140/handoff ceremony remains an open owner gate.
3. Install both complete FSBL copies. Before slot genesis, initialize and validate **both Route-1 `BASE0` snapshots**.
4. For each slot: erase/verify its full capacities and manifest; install images/body; verify signatures, hashes and vector targets; program fresh install-ID/complement; then **PENDING → CONFIRMED₀ → CONFIRMED₁**, with the required independent durability checks. Both slots must finish before normal boot is released. [Factory genesis:2766](/home/nicola/repos/pq1-uipx-merge-wt/docs/security/a-b-firmware-rollback-architecture.md:2766)
5. Activate TZEN at RDP0; reload options. Then apply the final watermarks, correct boot-address field, `SWAP_BANK=0`, selected HDP configuration and full published profile. Verify the boot address **before setting BOOT_LOCK**. Apply and verify both FSBL WRP ranges, including `UNLOCK=0`, after their contents are complete.
6. Reload/read back the final profile; verify both banks, all five blank per-device pages, factory records and OTP state. Cold-boot verification must preserve RDP0. Ship with SWD/NRST accessible.
7. First field boot verifies the complete staged profile, blank pages, OTP master and required factory handoff; obtains physical confirmation; writes **only RDP=0xCC**, reloads, and verifies the locked profile.
8. Only afterward perform journaled BHK creation and credential rotation; persist the PBS salt before using it. Enter the seed wizard only after ALL_DONE.

This is the required dependency order, **not an executable production ceremony**: the physical marker codec, factory receipt, SE ordering and silicon gates remain unresolved. The current RDP routine also has the recorded wrong-control-register defect: OPTSTRT/OBL_LAUNCH belong to **NSCR**, not SECCR. [flash.rs:390](/home/nicola/repos/pq1-uipx-merge-wt/secure/src/hw/flash.rs:390), RM §7.4.2.

The irreversible failure boundaries are:

| Boundary | Failure consequence |
|---|---|
| Interrupted OTP programming | A QW may be permanently unusable; all-ones readback does not prove virginity. Main-flash erase cannot repair it. |
| SE lifecycle/credential changes in wrong order | Lost authorization or non-rotatable PBS can strand the unit. Exact recovery remains unproven. |
| RDP2 with wrong boot address, watermarks, BOOT_LOCK or WRP | Permanent bad profile or permanent loss of the trust guarantee. |
| Power loss during RDP programming | Possible torn-profile wedge/RMA. After a clean program, a cut before OBL_LAUNCH completes the lock at the next POR. |
| Lost/regenerated BHK after SE binding, lost PBS salt, or exhausted first-boot journal | Post-lock loss of credentials/RMA. |

Ordinary pre-lock image cuts require erase/restage, not necessarily scrapping the die. WRP applied too early may require destructive recovery; it is not automatically an irreversible silicon brick. See [burn-window matrix:3817](/home/nicola/repos/pq1-uipx-merge-wt/docs/security/a-b-firmware-rollback-architecture.md:3817), RM §§7.3.11–12, and ES0499 §2.2.25 for the programming-sequence/WDW trap.

**Remanence:** new erased dies avoid it. Legacy reprovisioning does not avoid it merely by changing SECWM: old bank-1 pages 123–127 become NS under v7. Erase and verify them while still secure, then declassify and flush caches. Also, mass erase leaves OTP intact; “mass erase + reflash” is insufficient to establish compatible genesis. RM §§7.5.2, 7.3.6.

**5. Two NS windows — FAIL as a complete migration specification; no demonstrated inevitable pointer leak.**

The required read predicate is **whole-range containment in one window**:

```text
checked_end = ptr.checked_add(len)
accept = in_NS_SRAM(ptr, checked_end)
      OR in_NS_A(ptr, checked_end)
      OR in_NS_B(ptr, checked_end)
```

Retain overflow/truncation/null checks and mailbox exclusion. Writes remain NS-SRAM-only.

For your map, the flash windows are:

```text
A: [0x080E0000, 0x08100000)
B: [0x081D6000, 0x081F6000)
```

Concrete counterexample to a single enclosing interval or endpoint-only membership:

```text
ptr = 0x080FFFF0
len = 0x000D6020
end = 0x081D6010
```

Both endpoints are in NS slots; the range crosses secure bank-2 pages. I evaluated this in memory: the enclosing-interval predicate accepts; whole-range-in-one-window rejects.

**The existing TT check is stronger than endpoint-only:** it scans intervening 32-byte blocks. With correctly split SAU regions, it rejects this range at `0x08100000`. [ptr_validate.rs:88](/home/nicola/repos/pq1-uipx-merge-wt/secure/src/nsc/ptr_validate.rs:88). Do not widen the SAU region across the hole to accommodate the old one-window data structure. TT does not replace independent FLASH-watermark validation, and correct SECWM still blocks NS transactions to secure pages; this counterexample alone is **not evidence of secret disclosure**.

The draft misses three concrete consumers:

- **FSBL SAU:** it independently maps only bank 2. Leaving it unchanged makes NS-A measurement use the wrong transaction attribution; the repository documents the resulting read-as-zero/hash failure. [fsbl/src/sau.rs:5](/home/nicola/repos/pq1-uipx-merge-wt/fsbl/src/sau.rs:5)
- **NS erase:** `erase_ns_page` always sets BKER. Updating inactive A while running B would erase **bank-2 pages 112–127**, including running NS-B pages 112–122. This complements—and is as important as—the secure erase bug already listed. Programming dispatch likewise equates bank with security. [flash.rs:1134](/home/nicola/repos/pq1-uipx-merge-wt/secure/src/hw/flash.rs:1134), [1341](/home/nicola/repos/pq1-uipx-merge-wt/secure/src/hw/flash.rs:1341)
- **Active-slot consumers:** atlas base, vectors, veneers, linker origins and measurement must follow the selected slot. Atlas access currently uses one constant. [assets.rs:47](/home/nicola/repos/pq1-uipx-merge-wt/secure/src/ui/px/assets.rs:47)

Represent **physical bank, page, security attribute and writer authority separately**.

**6. Low per-device block — PASS for placement; FAIL for the stated preservation rule.**

Low placement is reasonable, but **page 5 is Manifest A and must be erased when A is updated**. “Pages 0–11 are never erased by an update” is false. The updater-preserved bank-1 set is **0–4 and 6–11**. [Draft:90](/home/nicola/repos/pq1-uipx-merge-wt/docs/security/geometry-v7-draft.md:90), [updater rule:1643](/home/nicola/repos/pq1-uipx-merge-wt/docs/security/a-b-firmware-rollback-architecture.md:1643)

Neither placement wins against unchecked erase arithmetic:

- Low placement exposes page 11 to a secure-slot-start underflow.
- High placement exposes state to a slot-end overflow.
- WRP cannot protect mutable state permanently.
- Extending HDP through the low state block would also cover manifests/journals and deny their required accesses after ACCDIS.

Keep the low block, but enforce exact owner-specific erase capabilities. The anti-preplant scan must enumerate precisely the five mutable per-device owners—pages 7–11—not the whole prefix, which contains intentionally programmed manifests/journals.

**7. False assertions and citations — FAIL.**

- **“Manifest’s geometry digest changes”: false.** Manifest-v6’s signed preimage contains no geometry digest. Updating geometry constants does not invalidate old signatures. Use an explicitly new accepted schema/signing domain, or a signed geometry identifier checked by the FSBL and packager. [v6.rs:423](/home/nicola/repos/pq1-uipx-merge-wt/fw-manifest/src/v6.rs:423)
- **Tables 68/70: PASS.** They support the secure-page and mixed-bank erase denials claimed.
- **RWW citation: wrong section.** It is **§7.3.10**, not §7.3.1. Opposite-bank image mutation can use RWW; it does not cover same-bank finalization, journal operations or FSBL execution. Keep the SRAM-closure requirement.
- **RDP2 freeze citation:** the direct statement is **§7.6.2**. §7.4.2 additionally says SWAP_BANK cannot change when TZEN and BOOT_LOCK are set. Thus the general RDP2 exception does **not** leave bank swapping available under the corrected final profile.
- **Lean is not unknown:** it explicitly models one NS-flash interval and one full-bank secure interval. Its source-binding script does too. Both require two-window/alias-aware revision. [MemoryMap.lean:72](/home/nicola/repos/pq1-uipx-merge-wt/contracts/verification/lean/SphincsCVerify/Platform/MemoryMap.lean:72)

The ranked defects and fixes are:

| Rank | Severity | Defect → fix |
|---:|---|---|
| 1 | **CRITICAL** | First-boot BOOT_LOCK conflicts with RDP-only authority and risks permanent wrong boot policy → stage and verify BOOT_LOCK at factory. |
| 2 | **CRITICAL if carried into cutover** | NS erase targets running bank B during B→A update → bank/security/owner-aware mutation API, checked in both directions. |
| 3 | **MAJOR** | Claimed geometry-based signature rejection does not exist → explicit authenticated format/domain separation. |
| 4 | **MAJOR** | TZEN ordering can discard intended watermarks; boot-address field is misencoded → staged reload/readback sequence and `SECBOOTADD0=0x180000`. |
| 5 | **MAJOR** | Factory identity and optional rollback-key storage unresolved → settle allocation or reserve secure space before freezing. |
| 6 | **MAJOR** | Two-window migration omits FSBL SAU and other consumers → include all readers, writers and proof bindings. |
| 7 | **MAJOR** | Sixteen-page lifetime budget lacks evidence → measure production-paired LOAD spans and select a growth envelope. |
| 8 | **MAJOR** | “Never erase 0–11” forbids updating Manifest A → explicit preserved-owner set. |
| 9 | **MINOR** | Incorrect RM references and misleading “deferred/reserve” language → correct sections and state what RDP2 permanently freezes. |

My corrected **candidate** map keeps shape B and aligns both slot offsets:

| Pages | Bank 1 | Bank 2 |
|---|---|---|
| 0–4 | FSBL copy 1 | FSBL copy 2 |
| 5 | Manifest A | Manifest B |
| 6 | Route-1 journal A | Route-1 journal B |
| 7 | Off-chain journal | Factory binding/handoff reservation |
| 8 | PIN state | Factory binding/handoff reservation |
| 9 | Admin-wipe/duress | Secure reserved, erased |
| 10 | Wrapped BHK | Secure reserved, erased |
| 11 | First-boot journal + salt | Secure reserved, erased |
| **12–95** | **Secure A: 84 pages** | **Secure B: 84 pages** |
| **96–127** | **NS A: 32 pages** | **NS B: 32 pages** |

Both SECWM ranges become **0–95 (`PEND=0x5F`)**. The factory reservation is capacity held for the unresolved record, not approval of its format. Its final size, writer and protection policy still need selection.

**REJECT. The single most important correction is to restore factory-staged, pre-RDP2-verified BOOT_LOCK.** That removes an unnecessary irreversible field transition and restores the existing shipping contract.