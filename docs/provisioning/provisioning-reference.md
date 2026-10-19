# PQ1 Hardware Wallet — Hardened Secure-Configuration & Provisioning Reference (STM32U585 + OPTIGA Trust M V3 + NXP SE050)

> **QUARANTINE OVERRIDE (2026-07-11).** This is research input, not an
> executable ceremony. The repository's legacy factory receipt is invalid for
> STM32U585 write-once OTP QWs; all factory build/flash targets and RDP2
> authority are blocked. Hardware encoding facts below do not make the ordering
> or receipt safe. Do not run any OTP, option-byte, lifecycle, or RDP command
> from this document until a replacement ceremony is independently approved.
> In particular, the old `~18 KB` / pages-0..3 FSBL geometry, generic
> "program + lock OTP" step, and flash-as-ROM equivalence wording are
> superseded. Draft 1.1 only *proposes* pages 0..4 and a 40,960-byte hard
> ceiling; its FLASH, RAM/stack, OTP, factory, and silicon decisions remain
> open and grant no hardware authority.

> **UPDATE 2026-07-14 — selected product direction, not a ceremony.** Devices
> are intended to ship as a batch-uniform, pre-first-power-verifiable RDP-0
> artifact after factory-side SE-internal provisioning and lockdown on
> transport keysets, including S-1/S-2/S-3 metadata/object preparation,
> UserID/LUC, attestation objects, and the eventual OPTIGA lifecycle ratchets.
> The factory also burns the per-device OTP master and derives every transport
> credential from it. First field boot is limited to the MCU RDP-2 self-lock,
> BHK first-write, unsalted BHK-rooted SE050 rotation, DHUK + persisted-TRNG-
> salt OPTIGA PBS rotation, and seed wizard. The exact E140 lifecycle
> timing relative to field rotation remains OPEN and silicon-gated. This does
> **not** establish that M-1..M-7/M-9 are a safe shipped profile, authorize an
> RDP-2 self-lock, or validate the historical key-rotation order below. Exact
> option bytes, failure recovery, receipts, and irreversible operations remain
> gated by a replacement reviewed ceremony.

> **Provenance & repo notes (2026-05-29).** Output of a deep-research run against
> `docs/archive/provisioning-research-brief.md`. It is a research *synthesis*, not
> vendor-authoritative: treat specific constants (OPTIGA TLV codes, the "~600k
> monotonic-counter updates" cap, the PSA cert number) as **TO-VERIFY against the
> primary vendor doc + a sacrificial read-back**, per its own Phase 0/4 gates.
> The encodings `RDP=0xCC` and SE050 `P1=0x33` were cross-checked; using them in
> this project's ceremony is **not** currently authorized or declared safe.
>
> **Two findings reconciled against our own code/silicon — act on these:**
> 1. **S-2 trust anchor is mis-targeted and our current mitigation is a silent
>    no-op.** Our `secure/src/optiga/reset.rs` provisions a "trust anchor" at
>    `0xE0E3`, but our 2026-04-22 bench dump (memory `project_optiga_reset_oids`)
>    shows E0E3 is `e8 01 12` = `DataType 0x12` (device cert), already full — the
>    chip won't retype it. The real Protected-Update anchors are the type-0x11
>    slots (this doc: `E0E8/E0E9/E0EF`), which our code never touches. Resolution
>    + bench dump queued in `docs/production-todo.md` S-2.
> 2. **S-1 F1D0:** the legacy
>    `secure/src/optiga/apdu.rs::build_metadata_auth_ref` path writes
>    `Change=ALW`; the candidate `build_metadata_auth_ref_luc` path under
>    `optiga-lock-operational` models `Auto(F1D0)`. The irreversible lifecycle
>    ratchet and sacrificial-silicon receipt remain open, so the candidate path
>    is not production closure.

**Note on completeness:** The full per-chip configuration matrices, the
consolidated historical dependency sequence, and the residual-immutability-gap
analysis were assembled section-by-section during research and are summarized
below, followed by the per-chip misconfiguration-pitfalls lists, candidate
self-protection constraints, sources, and caveats.

---

## TL;DR
- **STM32U585:** This document records historical lockdown research, not a burn plan. The eventual ceremony must bind WRP/HDP/SECWM/BOOT_LOCK/TZEN/RDP and both-bank geometry to an approved FSBL layout and verified artifact. Draft 1.1's pages-0..4 / 40,960-byte proposal remains unapproved, and flash protection is not mask-ROM equivalence. No exact option-byte or OTP step below is executable authority.
- **OPTIGA Trust M V3 & SE050 (dual, independently hardened to the same bar):**
  factory-side work must close the S-1/S-2/S-3 metadata, trust-anchor, counter,
  policy, and unused-feature surfaces, while SE050 uses full SCP03 security
  level `P1=0x33`. The candidate factory transport credentials all derive from
  the factory-burned per-device OTP master. After first-field RDP2 self-lock,
  the implemented candidate rotates SE050 SCP03/admin to unsalted BHK-rooted
  final values and OPTIGA PBS to DHUK + persisted-page-127-TRNG-salt final
  material. Authenticated handoff, cut recovery, KVN/update shape, coordinated
  chip order, E140 timing, silicon evidence, and production approval remain
  OPEN. No exact ratchet or PUT KEY ordering in this research document is
  executable authority.
- **Future ceremony constraint, not an instruction:** any replacement must stage
  and verify reversible state first, then order one-way transitions last. Exact
  steps, receipt semantics, and authorization remain OPEN; this research does
  not define an executable RDP2 sequence.

> **Two corrections to the brief:** (1) On a *standard* OPTIGA Trust M V3, AuthRef slot **0xF1D0 ships with `Change=LcsO<operational`, `Read=ALW`, untyped** — *not* `Change=ALW`; it only becomes the typed AUTOREF secret (`Change=Conf(0xE140)&&Auto(0xF1D0)`, `Read=NEV`) in Express/MTR configs. S-1 is therefore "F1D0 left at default `Change=LcsO<op` and un-ratcheted" — at LcsO=creation a desoldered chip can still rewrite it; fix (ratchet to operational + `Change=Conf&&Auto`) is unchanged. (2) Do not infer one SKU's full `0xE0xx` inventory from the generic configuration guide. Our 2026-04-22 dump shows **0xE0E3 is already a full type-`0x12` device-certificate object**, while the type-`0x11` Protected-Update pool selected for validation is **`0xE0E8/0xE0E9/0xE0EF`**. `0xE0E0` is a device-identity certificate on production parts, not a wallet trust anchor to neutralize. S-2 is therefore "pin the exact SKU/revision inventory, close the real type-`0x11` pool, and ratchet device-cert slots without retyping them." The old public-sample helper targeting `0xE0E3` is a mis-targeted dev recovery path, not evidence of the live anchor pool.

---

## Key Findings

**1. The decisive lock set is small and each item is independently fatal if missed.** ST's SESIP/CC guidance UM3387 §3.2.3 defines the *certified* lockdown as exactly: `TZEN=1`, `SWAP_BANK=0`, `SECBOOTADD0` into the secure HDP/WRP area, `BOOT_LOCK=1`, `SECWM1` set, `HDP1EN=1` with `HDP1_PEND` covering the FSBL, `WRP1A` over the immutable area with `UNLOCK=0`, and `RDP=0xCC`. This is the most authoritative "correct config" checklist; PQ1 must replicate this exact primitive set by hand even though it does not use ST's image format. UM3387 also notes the fail behavior that doubles as a verification signal: misconfigured option bytes cause "Reset … except for the case of RDP option bytes value for which infinite loop is executed."

**2. The flash-FSBL-vs-ROM immutability gap is real and still open.** STiRoT
achieves true ROM immutability. The target PQ1 flash FSBL depends on WRP1A
(un-removable only while RDP=2 — AN5156: WRP "can be unset when RDP level ≠
2") + RDP2 + HDP1 + BOOT_LOCK. A future immutable FSBL must verify the complete
option-byte policy before handoff and halt on mismatch, but that verifier is not
implemented: the mutable secure runtime currently checks only RDP and
SECBOOTADD0, while BOOT_LOCK/HDP/WRP and the production geometry remain open.
Residual surface includes a successful FI RDP2→RDP1 downgrade (wallet.fail /
Kraken on older STM32F2/F4). U5 hardening and the no-secret-in-flash design are
useful mitigations, not evidence that this gate has closed.

**3. The SE050's published default keys are the highest-probability self-inflicted hole.** AN12436: default Platform SCP03 keys are in NXP's own tables (Table 5 for our SE050E2, Table 6 for the previous generation) and the OP-TEE source tree; "users are required to rotate/provision those keys." Un-rotated = anyone opens an authenticated channel to half_E.

**4. Object lifecycle, not encryption, is the OPTIGA control.** One-way LcsO: creation `0x01` → initialization `0x03` → operational `0x07` → termination `0x0F`; "Once LcsO is set to higher value, it is not reversible." At creation, an attacker with physical access "could change the Read access permission from NEV to ALW." Ratcheting every used object to `0x07` makes the config self-enforcing.

**5. Vendor diversity is validated by the audit literature.** Coinkite's Mk4 uses the same philosophy; when Ledger Donjon laser-fault-injected its DS28C36B "SE2," the secret held because it "requires full compromise [of] three chips." Trezor's historical no-SE stance (NDA/open-source conflict) was overtaken by Trezor itself adopting the *same* OPTIGA Trust M V3 (chosen for "no Non-Disclosure Agreements") — validating PQ1's auditable, NDA-free SE choice.

---

## Matrix 1 — STM32U585 MCU (custom FSBL root of trust, by-hand primitive lockdown)

Delivered in RDP0 with no NVM protection (UM3387 §4.1). Each row: **Setting → Hardened value → Rationale → Source → Verification before burn.**

| # | Setting | Hardened value | Rationale | Source | Verify before burn |
|---|---|---|---|---|---|
| M-1 | TZEN (FLASH_OPTR) | `TZEN=1` (0xB4) | Secure/non-secure split; FSBL, SPHINCS+ SRAM signing, SE host keys in secure world; DHUK differs Open vs closed | RM0456 §3; UM3387 §3.2.3 | Read FLASH_OPTR.TZEN=1; SAU/GTZC regions match map |
| M-2 | SECBOOTADD0 | `0x0C00_X000` inside WRP+HDP | Forces reset vector into FSBL | UM3387 §3.2.3 | Confirm address ∈ WRP1A range and HDP1 region |
| M-3 | BOOT_LOCK | `=1` | No alternate boot entry (RAM/sys bootloader) | UM3387 §3.2.3; AN5156 (UBE) | Read=1; attempt boot-source change → rejected |
| M-4 | SECWM1 | `PSTRT=0`, `PEND`=last secure page (>WRP1A_PEND) | Defines secure region enclosing FSBL+app | UM3387 §3.2.3; RM0456 §3.6 | Read FLASH_SECWM1R1 range |
| M-5 | HDP1EN/HDP1_PEND | `HDP1EN=1`; PEND covers FSBL; `<SECWM1_PEND` | Hides FSBL code+secrets after boot | RM0456 §3.6.1; UM3387; AN5156 | Read HDP1EN=1, PEND covers FSBL |
| M-6 | HDP1_ACCDIS | FSBL sets it in FLASH_SECHDPCR at boot-exit | Engages the hide for the session | UM3387 §4.2.1 | FSBL self-test reads back verification value ≠0 → halt |
| M-7 | WRP1A | Candidate FSBL pages; PEND=HDP1_PEND; **UNLOCK=0** | Intended production mechanism for write-protecting the flash FSBL with RDP2; this row does not establish current immutability | UM3387 §3.2.3; AN5156 §6 | After layout and ceremony approval, read FLASH_WRP1AR and demonstrate an FSBL-page erase is rejected on sacrificial silicon |
| M-8 | RDP | `0xCC` (Level 2) | Kills JTAG/SWD, RAM/bootloader boot, locks option bytes **EXCEPT SWAP_BANK** (DS Table 4 note 6 — see SWAP_BANK ship-blocker in `docs/archive/production-todo-retired-2026-07-19.md`), no mass-erase-open; keeps WRP un-removable | UM3387 §4.2; RM0456 §3.10; DS Table 4 | **LAST** verification; sacrificial: JTAG dead + FSBL boots |
| M-9 | OEM2 DA key (OBKeys) | Provision secret; no default; prefer no field regression | RDP2+OEM2 disables debug; default password = hole | AN6008; STM32U5 Sec Overview | DA challenge with default password → rejected |
| M-10 | OEM1KEY / RDP0 regression | Absent (no path) or PQ1-secret one-way control | RDP1→0 mass-erases; close or gate; "reset in RDP0 only" | STM32U5 Sec Overview; AN4992 | Confirm state before raising RDP |
| M-11 | BHK (candidate final SE050 SCP03/admin root) | Candidate first-field path writes the TRNG-generated BHK into TAMP backup regs after the RDP2 transition; `SAES_CR.KEYSEL=010` (BHK) / `100` (DHUK^BHK); **write-once, never SW-readable** — `TAMP_SECCFGR.BHKLOCK` makes it SAES-only until reset | Unsalted final tier-isolation input for half_E; cleared on tamper / RDP-regression; transport credentials instead derive from the factory OTP master | RM0456 §SAES; ES0499; production-security.md:479 | Verify via a SAES-CMAC(BHK) known check-value (NOT a register read-back — BHK is unreadable); confirm BHKLOCK set; separately close final-rotation state/recovery |
| M-12 | DHUK (candidate final OPTIGA-PBS root) | Constant in Open; per-die closed-state behavior requires an approved lifecycle transition. The final PBS additionally binds a non-secret TRNG salt persisted in the page-127 journal; the historical `RDP0→1` experiment is not the ceremony | Hardware-root input for the final OPTIGA PBS; factory transport PBS instead derives from the OTP master | ST Community; RM0456 §SAES; Sensitive-key-protection wiki | On an authorized sacrificial part, confirm the DHUK-wrapped value changes across the selected transition; separately close final-rotation state/recovery |
| M-13 | OTP rollback backend | **OPEN — do not program or lock** | Draft 1.1 treats OTP as a candidate WORM epoch-floor backend; codec, interruption, allocation, factory, and silicon gates are unclosed | RM0456 §OTP; Draft 1.1 OPEN-OTP-1..3 | Owner-authorized sacrificial characterization only after a separately approved plan |
| M-14 | TAMP + RNG | Internal tamper on; TRNG "config A"; tamper erases BHK | Protects the BHK-rooted final SE050 credentials; certified RNG | UM3387 §4.2.1; RM0456 §TAMP/RNG | Sacrificial tamper → BHK erase + reset; RNG health pass |
| M-15 | FI software countermeasures | Redundancy / inverse-check, timing jitter, control-flow integrity around SPHINCS+ verify + the future complete option-byte self-check | Software half of closing RDP2-downgrade residual gap; not implemented as a complete FSBL verifier | UM3387 §4.2.1 | After implementation, Rainbow single-fault simulation of verify/lock path |

**Residual-gap statement:** M-1…M-15 are a target hardening profile, not a
claim of current functional ROM-equivalence. Even after the complete profile,
build/resource gates, ceremony, and silicon receipts are demonstrated, a flash
FSBL remains distinct from true ROM because RDP2 is option-byte/state-machine
logic and is theoretically susceptible to a successful FI RDP2→RDP1
downgrade. The future FSBL self-check, U5 glitch hardening, and absence of seed
material in flash reduce that residual; none is permission to call the current
bench FSBL immutable.

---

## Matrix 2 — Infineon OPTIGA Trust M V3 (half_O; OTP-master transport PBS, candidate salted-DHUK final PBS)

Tags: RD/CHA/EXE/MUPD. Codes: `ALW=0x00`, `NEV=0xFF`, `LcsO(X)` (`E1 FC 07`="LcsO<operational"), `Conf(X)` (shielded), `Auto(X)` (auth-ref). LcsO ratchet TLV = `C0 01 07` (framed `20 03 C0 01 07`).

| # | OID | Hardened value | Rationale | Source | Verify before LcsO burn |
|---|---|---|---|---|---|
| O-1 | 0xE140 PBS | The factory transport PBS derives from the per-device OTP master. The implemented candidate final PBS derives from per-die DHUK plus a non-secret TRNG salt persisted in page 127. Exact ratchet order, handoff/recovery, and production approval remain **OPEN**; the object still requires `Read=NEV`, a reviewed `Change` policy, and an approved lifecycle ratchet | Roots shielded conn (AES-128-CCM8) protecting half_O; default PBS non-unique | SRM Shielded Conn §; Shielded-Connection-101 wiki; KBA235350 | Under the future approved protocol: verify metadata/lifecycle, unique-channel success, transport-PBS rejection after completion, and crash recovery |
| O-2 | 0xF1D0 AuthRef | Chip-unique; `Change=Conf(0xE140)&&Auto(0xF1D0)`, `Read=NEV`, AUTOREF; ratchet op | Default `Change=LcsO<op`,`Read=ALW`,untyped → creation-state rewritable (S-1) | V3 object dump; OPTIGA Config Guide | `trustm_metadata -r 0xF1D0`: `LcsO:0x07,R:NEV,C:Conf&&Auto`; unauthorized change → `0x8007` |
| O-3 | 0xE0E0/0xE0F0 | On PRODUCTION parts `0xE0E0` is a **chip-unique Infineon device cert** (`Change=NEV`, leaf key sealed at `0xE0F0 Read=NEV`) — do NOT neutralize; it's an anti-counterfeit primitive. Just don't anchor *wallet* trust on it (wrong type: device-identity 0x12, not TA) | NOT "a public sample anyone can reproduce" — that's the engineering-sample *Test* cert; our eval shield (TRUSTMV3SHIELDTOBO1) may carry the test cert | Keys&Certificates v3.10; SRM Table 68 | Confirm whether our part carries the production chip-unique cert vs the eval test cert; never anchor wallet trust on E0E0 |
| O-4 | 0xE0E1/E0E2/E0E3 device-cert surfaces | Preserve/verify `DataType=0x12`; ratchet op so `Change=LcsO<op` becomes unsatisfiable; never retype these slots as anchors | An unratcheted device-cert surface may be retyped on a variant that leaves it mutable; our observed E0E3 is already full and rejected the old sample-anchor write | Device dump; SRM Table 68; SKU/revision receipt still required | Read back type/lifecycle for each slot; post-ratchet metadata change refused |
| O-5 | 0xE0E8/E0E9/E0EF (type 0x11) | Fill-and-lock if used (PQ1 Protected-Update anchor) else ratchet op | Type-0x11 anchors authorize manifests; attacker anchor = worst case | V3 object dump; SRM | PQ1 anchor + `LcsO:0x07` or empty+ratcheted |
| O-6 | 0xF1D1–F1DB, F1E0, F1E1 | Ratchet every unused slot to op | Creation-state slots are writable footholds | V3 object dump; SRM | All unused slots `LcsO:0x07` |
| O-7 | 0xE120 counter | Init counter+threshold (8-byte ctr‖thr); link as PIN/usage limiter; ratchet op | Readable silicon leg for per-attempt charging and the directional page124→E120 boot rollback check; mandatory (S-3) | KBA235409; SRM; linux-optiga-trust-m | `trustm_monotonic_counter -r 0xE120`; sacrificial: reaches threshold→error |
| O-8 | 0xE200 AES | If used: write key, `Change=NEV`, Execute gated by `Conf(0xE140)`, ratchet op; else leave uninstantiated | Not present by default; CHA=ALW only *during* keygen, re-close after | V3 object dump; linux-optiga-trust-m note | If used: `LcsO:0x07` + shielded-gated; else absent |
| O-9 | Shielded enforcement | All half_O objects: `Read/Execute=Conf(0xE140)` (implemented 2026-10-13, #116: Read = `Auto(F1D0) AND Conf(0xE140)`, Execute = NEV on F1D1–F1D4 + duress twins) | I²C probe sees only ciphertext | SRM §Comm Protection; discussion #103 | Sacrificial: bypass shielded (`-X`) → Access Condition Not Satisfied |
| O-10 | Protected Update policy | Restrict to PQ1 anchor; manifest `Conf(secret)&&Int(anchor)` | Without locked anchor, anyone signs a manifest (S-2 core) | SRM §Protected Update; Infineon blog | Non-PQ1 manifest → rejected |
| O-11 | Security Monitor | Hardened default; do not disable | Throttles after security events (lockout silicon) | OPTIGA datasheet §Security monitor | Active; sacrificial repeated failed auth → back-off |
| O-12 | Inherit CC/PSA config | Chip-unique keys, locked secrets, shielded conn, no creation-state secrets in field | EAL6+ (high), **BSI-DSZ-CC-0961 / IFX_CCI_00000Bh** (datasheet-confirmed); **PSA Certified L3** (datasheet-confirmed). ⚠️ the cert **number/HW-ver/date** (0632793519409-10300 / V3.00.2440 / 27-07-2024) are NOT in the Infineon docs — TO-VERIFY against products.psacertified.org before citing as fact | OPTIGA datasheet v3.70 | Confirm genuine V3 (UID/cert chain); no object at LcsO=creation |

---

## Matrix 3 — NXP SE050 (half_E; OTP-master transport credentials, candidate BHK-rooted finals)

**Part: EdgeLock SE050E2, OEF ID `0xA921`, on the dev board and in production** (orderable `SE050E2HQ1/Z01Z3Z`; owner-confirmed production part 2026-10-19, #697 — the 2026-07-20 SE050C2 decision was reversed; canonical facts in `docs/secure-elements/se050-silicon-findings.md` § "Part identity") (the OM-SE050ARD-E carries SE050E; NXP docs map SE050E2 → OEF 0xA921). Implications baked into the rows below: **CC EAL6+ to OS level (yes, as NXP markets it; whether the cited certificate's TOE covers this part's JCOP release is unconfirmed, `HW-ASSUME-SE050-CERT-VERSION`), FIPS 140-2 (NO — that's SE050F only), platform SCP03 forced by default (NO — SE050E defaults `SCP_NOT_REQUIRED`; we rely on per-object `REQUIRE_SM`).** The 2026-05 working assumption ("same SE050E2/`0xA921` as the dev board") is now confirmed. The OEF is not in the GetVersion reply, so the anti-substitution check pins `AppletConfig=0x3F9F`; it runs in the stress audit only, and the boot-path assertion is still open (#61). Silicon note (EVT-3D21 6B.6, 2026-10-19): plain read-class commands were all refused, but with an SCP03 session already up, so this does not yet show what a chip does before any session. **The one variant that would move this matrix is SE050F** (would add FIPS + force SCP03); any other SE050E-class OEF only changes the expected OEF value, not the security properties. Pin the variant requirement into the hardware spec during ID so it's locked, not discovered at bring-up.

Policies = per-object `POLICY_OBJ_ALLOW_*` bitmask; rule: deny all not needed; never leave WRITE/DELETE except one admin object. SCP03 level via EXTERNAL AUTHENTICATE `P1`. HW = CC EAL6+ (to OS level); FIPS 140-2 (SL3 OS/Applet, SL4 physical) is **SE050F-only**, NOT our SE050E.

| # | Setting | Hardened value | Rationale | Source | Verify before SCP03-rotation burn |
|---|---|---|---|---|---|
| S-A | Platform SCP03 keys | Factory defaults must be replaced with OTP-master-derived transport keys. The implemented candidate rotates them to final unsalted BHK-derived keys; KVN/update shape, actor handoff, authenticate-before-rotate, ordering, cut recovery, silicon evidence, and production approval are **OPEN** | Defaults published (AN12436 Table 6 + OP-TEE source); #1 ship-blocker | AN12436; foundries.io/u-boot | Under the future approved protocol: defaults and transport keys fail after completion, final keys succeed, interrupted rotation recovers or fails closed, and receipts bind the resulting state |
| S-B | SCP03 level (P1) | **`P1=0x33`** (C-MAC+C-DEC+R-MAC+R-ENC) (S-5) | Anything less leaves bus data exposed one/both directions | GlobalPlatform SCP03 Table 7-3; AN12413 | Sniff I²C: cmd+rsp ciphertext+MAC; refuse downgrade |
| S-C | half_E object | Persistent Binary File, REQUIRE_SM, bound to the UserID AuthID (no anonymous/AuthID-0 grant). **READ + DELETE are present (SM-gated) and design-mandatory** (READ = seed reconstruction `mod.rs:2478`; DELETE = admin-wipe/S-6). **WRITE is present today but droppable** — drop it at provisioning (write-once policy; work-todo) so a PIN-session can't re-seed half_E. IMPORT_EXPORT N/A to a Binary File | Verifiable denials are IMPORT_EXPORT=False, ATTESTATION=False, no AuthID-0 grant — NOT R/D (those can never be False by design) | AN12413 Table 11, §3.7.1.1 | non-admin delete → `0x6985`; attested-read (S-G) confirms I-E/ATTESTATION=False (NOT R/D=False) |
| S-D | UserID delete policy (S-6) | Delete bound to admin SCP03 AuthID only | UserID "only be deleted and created new" → delete-recreate resets lockout | NXP Community | Non-admin delete of UserID → fail |
| S-E | UserID max_attempts (S-7) | =10; permanent fail on exhaustion; blocked-auth status maps to `PinLocked`/wipe | SE050 independently consumes every ordinary attempt, but its attempt attribute is policy-denied and is not a boot-reconciliation input; mis-mapped auth status = false success | AN12413; AN13483 | Sacrificial: exhaust → permanent lockout; verify status map and attribute-read denial |
| S-F | RESERVED_ID_FACTORY_RESET | PQ1-secret or unprovisioned; never default | `DeleteAll` only in this session; default/known = wipe+reprovision/clone path | AN12543; NXP Community | DeleteAll in default/none session → fail |
| S-G | Attestation (ECKey) | If used: `ALLOW_ATTESTATION`, **`ALLOW_SIGN=0`, `ALLOW_DECRYPT=0`**. NOT implemented in the driver today — either build it as provisioning/QA tooling or down-scope | Signed read-back proof primitive; asserts the *verifiable* denials only | AN13254 Table 1 | Attested read confirms half_E I-E/ATTESTATION=False, no AuthID-0 (lockstep with S-C — NOT R/D=False) |
| S-H | AppletConfig (variant) | **Not field-configurable** — `SetAppletFeatures` needs the NXP-owned `RESERVED_ID_FEATURE`; the feature set is fixed by the **ordered OEF variant**. This is a PROCUREMENT lever (choose variant at order time), not a provisioning step. Per invariant #5 the SE050 crypto engine is unused anyway | AppletConfig is NXP-owned | AN12436 §4.6.3, §3.2.5.4 | `GetVersion`/OEF — confirm the variant we ORDERED (anti-substitution), not "minimized" |
| S-I | Provisioning-admin object | Exactly one AuthID holds WRITE/DELETE, ceremony-only, on rotated SCP03 admin session | Concentrates all mutation rights in one auditable credential | AN12413 §3.7 | One object writable (admin AuthID); all others read/use-only |
| S-J | Persistent/lifecycle | half_E + PIN object persistent (NVM), not transient | Persistent objects survive reset, cannot be exported | AN13483; SE050 datasheet | Confirm half_E + PIN persistent |
| S-K | Inherit CC (all variants); FIPS is SE050F-only | SCP03 rotated; minimal policies; factory-reset NXP-reserved (unavailable to us) | **CC EAL6+ to OS level — all variants** ✓. ⚠️ **FIPS 140-2 SL3/SL4 is SE050F-ONLY** — an SE050E-class part is NOT FIPS (don't claim it unless we BOM SE050F). ⚠️ **"0x7FFF0207 forces SCP03" is SE050F-ONLY** — an SE050E-class part defaults `SCP_NOT_REQUIRED`; our half_E/PIN confidentiality rests on **per-object `REQUIRE_SM`** (`apdu.rs:568`), NOT forced platform SCP (decide: also `SetPlatformSCPRequest` for defense-in-depth?) | SE050 datasheet; AN12436 §2.1 | `GetVersion`/OEF assert the variant (work-todo); confirm basis = REQUIRE_SM not forced-SCP |

---

## Consolidated provisioning research sequence (not an executable ceremony)

The phase sequence below is a historical dependency hypothesis, not the
selected ceremony. It coupled deterministic DHUK/BHK helpers and SE injection
to an `RDP0→1` transition. Owner decision #36 instead targets a batch-uniform
RDP-0 transport artifact, a factory-burned OTP master and factory-side SE
preparation on credentials derived from it, and a first-field RDP-2/BHK final
SE050 rotation plus salted-DHUK OPTIGA rotation. The actor handoff,
durable public state, cut recovery, KVN/update shape, chip order, and E140
timing remain OPEN. No phase below authorizes an irreversible action or a
production credential.

**PHASE 0 — FUTURE OWNER-AUTHORIZED SACRIFICIAL VALIDATION.** No run is authorized by this document. After a replacement ceremony and exact irreversible ranges are approved, the owner may name sacrificial units and exact operations. Only that later plan may test final burns, FSBL boot/verify, PIN-attempt controls, seed reconstruction, debug closure, and object lifecycle state.

**PHASE 1 — HISTORICAL REVERSIBLE INVENTORY.** The earlier proposal listed
part identity, virgin-state checks, firmware staging, candidate option bytes,
and OEM-key preparation. Any replacement may reuse those evidence
requirements, but it must derive exact values from the approved artifact and
must not treat the legacy OTP-counter step as valid.

**PHASE 2 — SUPERSEDED LIFECYCLE HYPOTHESIS; DO NOT EXECUTE.** The earlier
proposal selected `RDP0→1` before SE work and then provisioned BHK. That order
is not the current product direction and has no burn authority. The approved
replacement must specify the first-field RDP-2/BHK transition, verification,
failure state, and recovery boundary explicitly.

**PHASE 3 — HISTORICAL DETERMINISTIC-ROOT SPIKES.** Direct DHUK-derived PBS
and BHK-derived SCP03 helpers are retained as sacrificial/bring-up evidence.
The current candidate instead uses the OTP master for factory transport,
unsalted BHK for final SE050 credentials, and DHUK + page-127 salt for the
final OPTIGA PBS. Crash-consistent handoff and production approval remain open.

**PHASE 4 — REQUIREMENTS FOR A REPLACEMENT, NOT A RUNNABLE GATE.** A future
approved plan must verify the complete MCU option-byte policy, OPTIGA metadata
and shielded-channel state, SE050 SCP03 level and object policies, final-key
rejection of defaults, dual-SE reconstruction/signing, attempt limiting, and
every cut/recovery state. It must define which failures remain reversible
before it authorizes any one-way transition.

**PHASE 5 — HISTORICAL SEQUENCE; DO NOT EXECUTE.** The dependency-ordering notes are research input only. In particular, there is no approved MCU OTP lock step, no approved WRP page range, and no approved RDP2 transition. A replacement ceremony must be generated from a reviewed artifact/layout, independently authorized, and validated on named sacrificial units before any irreversible operation.

**PHASE 6 — HISTORICAL POST-BURN CHECK; NOT EXECUTABLE.** A future approved
ceremony must define its own per-unit attestation and failure handling. This
line is neither a burn instruction nor a claim that a unit is shippable.

---

## Known Misconfiguration Pitfalls (per chip, from the audit literature → preventing setting)

**STM32U585**
- **MCU-1 RDP2→RDP1 fault-injection downgrade** (wallet.fail 35C3; Kraken Security Labs on STM32F2/F4 — "downgrading RDP2 to RDP1 can reliably be performed at boot with voltage glitching"). → Prevent: M-8 RDP2 + M-15 FI countermeasures + M-6 FSBL option-byte self-check; residual accepted because seed is split (Finding 2).
- **MCU-2 RDP not actually at Level 2 / left at Level 1** (Kraken: RDP1 allows SRAM read-out over SWD). → M-8 `RDP=0xCC`; verified last.
- **MCU-3 WRP left unlocked / FSBL rewritable** (left-open lock bit). → M-7 `WRP1A UNLOCK=0`; erase-attempt test.
- **MCU-4 Default OEM2/DA password left in place** (un-rotated default key). → M-9 provision secret OEM2; default-password challenge must fail.
- **MCU-5 BOOT_LOCK off / alternate boot entry** → M-3 `BOOT_LOCK=1`.
- **MCU-6 HDP not engaged at runtime** (HDP1_ACCDIS unset) → M-6 self-test.
- **MCU-7 Seed/keys in flash recoverable** (Kraken extracted encrypted seed from STM32 flash). → Architectural: SPHINCS+ key in TrustZone SRAM only; seed XOR-split.
- **MCU-8 SWAP_BANK cross-bank boot redirect** (historical analysis). Any approved design must protect the final frozen FSBL range in **both** physical banks, stage an identical approved FSBL in both, and mirror HDP/SECWM. Draft 1.1 currently proposes pages 0..4, but the range and ceremony remain unapproved. **SHIP-BLOCKER** — full treatment in `docs/archive/production-todo-retired-2026-07-19.md` "STM32U585 — datasheet cross-reference".

**OPTIGA Trust M V3**
- **S-1 F1D0 left un-ratcheted at `Change=LcsO<op`** — desoldered-chip attacker overwrites the AuthRef secret. → O-2 ratchet `LcsO=operational` + `Change=Conf(0xE140)&&Auto(0xF1D0)`.
- **S-2 Empty/unratcheted anchor pool or retypable certificate surface** — an attacker-controlled type-`0x11` anchor can authorize SetObjectProtected manifests. → O-3 preserves device identity, O-4 verifies and ratchets E0E1/2/3 as type-`0x12`, and O-5/O-10 close the real E0E8/E0E9/E0EF pool under the reviewed PQ1-anchor policy. The public-sample helper aimed at E0E3 is retired/mis-targeted, not the mitigation.
- **S-3 Monotonic counter not enabled in production** — no silicon usage/attempt cap. → O-7 `0xE120` linked to F1D0, ratcheted.
- **S-4 (added) Default/non-unique Platform Binding Secret left in 0xE140** — bus traffic decryptable; also any object left at LcsO=creation is rewritable by a physical attacker ("could change Read from NEV to ALW"). → O-1 unique PBS + O-6/O-12 ratchet every used/spare object to operational.
- **S-4b (added) Shielded connection not enforced on sensitive objects** — I²C probe reads plaintext. → O-9 `Read/Execute=Conf(0xE140)`.

**SE050**
- **S-5 SCP03 not at full security level** — bus data exposed. → S-B `P1=0x33`.
- **S-6 UserID admin-delete allows delete→recreate substitution** — bypasses lockout. → S-D bind delete to admin AuthID.
- **S-7 UserID max_attempts / status-code mishandling** — lockout not enforced or status misread as success. → S-E set =10; map blocked auth to `PinLocked`/wipe. Do not claim SE050 attempt-count boot readback.
- **S-8 (added) Published default Platform SCP03 keys not rotated** (AN12436; OP-TEE source) — anyone authenticates to half_E. → S-A rotate via PUT KEY.
- **S-9 (added) Over-permissive object policy / writable-deletable secrets** — half_E rewritable/exportable. → S-C/S-I deny all but one admin object.
- **S-10 (added) Factory-reset credential default/unset** — wipe+reprovision/clone path. → S-F PQ1-secret or unprovisioned.
- **S-11 (added) Unused applet features left enabled** — surface bloat. → S-H AppletConfig minimization.

---

## Recommendations

**Stage 1 — Before any silicon (now):** freeze a review/model packet containing
candidate option-byte, OID, policy, state-transition, and read-back
requirements keyed to UM3387 §3.2.3, the OPTIGA SRM, and AN12436/AN12413. Do
not encode a burn-ready script until the artifact/layout and actor/handoff
protocol are closed and independently approved.

**Stage 2 — Future sacrificial validation (Phase 0):** only after the owner
approves a replacement ceremony, names sacrificial units, and authorizes exact
irreversible operations. This research document grants none of that authority.

**Stage 3 — Production:** blocked. A reviewed replacement ceremony, factory
receipt, artifact/layout freeze, and silicon evidence must define any future
stage→verify→burn-last sequence and acceptance thresholds.

**Stage 4 — Ongoing:** Track Infineon/NXP/ST security advisories; re-run the verifier if any chip's certified config assumptions change. Subscribe to BSI/PSA maintenance updates for BSI-DSZ-CC-0961 and PSA cert 0632793519409-10300.

**Secondary — candidate constraints for a later ceremony, not current claims:**
(1) the factory must never learn final device credentials; it installs only
OTP-master-derived transport credentials. The candidate final SE050 root is
the post-lock BHK and the final OPTIGA root is DHUK plus page-127 salt, while
handoff/recovery and production approval remain OPEN; (2) any provisioning-admin
AuthID and Protected-Update anchor must stay under PQ1 custody rather than on a
partner tool; (3) self-enforcement may be claimed only after RDP2, lifecycle,
final rotation, recovery, and receipt gates all close; and (4) a future
anti-overbuild design may use per-unit HSM authorization and UID-bound
attestation, but this document selects neither protocol nor operator workflow.

---

## Sources / Citations
- **ST:** AN5156 (Introduction to STM32 microcontrollers security) — RDP/WRP/HDP/PCROP, secure-boot FSM, "WRP can be unset when RDP level ≠ 2." RM0456 (STM32U575/585 reference manual) — §3 security, §3.6 HDP, §3.10 RDP, SAES, OTP, TAMP. UM3387 (STM32U5x-WBA5x SESIP Level 3 security guidance) — §3.1 acceptance, §3.2.3 lockdown values, §4.2 RDP2/HDP/FI countermeasures. AN6008 (Debug Authentication for STM32). AN4992 (Secure Firmware Install / OEM password notes). STM32U5 Security Overview (SECOVW); STM32H5 DA training (DHUK/Open-state note); ES0499 errata (SAES KEYSEL); ST Community (BHK/RHUK/DHUK provisioning); Sensitive-key-protection wiki.
- **Infineon:** OPTIGA Trust M Solution Reference Manual (access conditions, LcsO model, Shielded Connection, Protected Update, monotonic counters); OPTIGA Trust M Datasheet v3.70 (CC EAL6+ high, **BSI-DSZ-CC-0961 / IFX_CCI_00000Bh**, PSA L3, Security Monitor); OPTIGA Trust M Configurations Guide (V1/V3/Express/MTR object defaults); Infineon V3 object dump (trust_m3_json.txt); KBA235350 (Shielded Connection), KBA235409 (Monotonic Counters); Protected Update / Metadata developer blogs; linux-optiga-trust-m tooling (LcsO one-way warning, trustm_metadata/monotonic_counter).
- **NXP:** AN12436 (SE050 configurations — default Platform SCP03 keys MUST be updated; SE050F FIPS, reserved key 0x7FFF0207). AN12413 (SE05x APDU spec — policies §3.7, SCP03, UserID). AN12543 (factory reset / RESERVED_ID_FACTORY_RESET). AN13483 (SE050E user guidelines — persistent/transient, policies). AN13254 (secure attestation — SIGN=0/DECRYPT=0). SE050 datasheet (CC EAL6+ to OS level). NXP Community (UserID delete-recreate; POLICY_OBJ_ALLOW_DELETE). GlobalPlatform SCP03 spec (P1 Table 7-3). foundries.io / u-boot (default-key rotation, BHK-derived SCP03).
- **CC / certification:** commoncriteriaportal.org & bsi.bund.de (BSI-DSZ-CC reports; OPTIGA underlying controller); products.psacertified.org (OPTIGA Trust M v3 PSA L3 cert 0632793519409-10300, HW V3.00.2440, 27/07/2024, SGS Brightsight).
- **Audits / research:** wallet.fail (35C3, media.ccc.de) — glitching to bypass IC security. Kraken Security Labs (Trezor/KeepKey RDP2→RDP1 voltage-glitch seed extraction). Ledger Donjon (secure elements vs FI; STM32U5 glitch-hardening; Mk4 DS28C36B laser FI). Coinkite Mk4 (multi-vendor three-chip seed split). Trezor Knowledge Base (no-SE rationale → adoption of OPTIGA Trust M V3 "no NDAs"). Tangem (ATECC508A LFI). Foundries.io (SE050 SCP03 in OP-TEE).

---

## Caveats
- **Two brief assumptions corrected** (top box): 0xF1D0 ships `Change=LcsO<op`/`Read=ALW`/untyped (not `Change=ALW`); and the exact E0xx inventory is SKU/revision evidence, not a generic constant. Our observed E0E3 is a full type-`0x12` device-cert object, while the candidate type-`0x11` pool is E0E8/E0E9/E0EF. The production plan must verify those facts before any ratchet.
- **Exact default OPTIGA metadata TLVs** come from Infineon's published V3 object dump + Configuration Guide, the most precise primary source short of the SRM PDF tables; cross-checked and consistent. Confirm against your specific chip with `trustm_metadata` during Phase 1.
- **CC augmentation components** (AVA_VAN.5/ALC_FLR) for BSI-DSZ-CC-0961 should be confirmed against the latest BSI maintenance report; the OPTIGA datasheet states EAL6+ (high).
- **Exact `P1` bit value `0x33`** follows the GlobalPlatform SCP03 P1 bitmap (AUTHENTICATED+C_MAC+C_DECRYPTION+R_MAC+R_ENCRYPTION); verify your middleware encodes the full level (some stacks default to C-MAC only) and that the SE050 negotiated level matches via I²C capture.
- **STM32U5 RDP2 immutability** is option-byte/state-machine enforced, not
  mask-ROM. The earlier “no public U5 FI attack” premise is obsolete: the
  Masaryk/Šimoník STM32U5 result reported a practical PIN-glitch bypass. That
  is not itself an RDP2-downgrade demonstration, but it invalidates absence-of-
  U5-FI as evidence. Keep the option-byte/FI/silicon gates open and treat the
  split-secret design as damage limitation, not proof of immutability.
- **Counter limits:** OPTIGA monotonic counters are capped at 600,000 updates each and ~2 million total updates across all objects — size the PIN/usage thresholds accordingly so the lockstep counter cannot exhaust device endurance.
- **Status-code mapping (S-E/S-7)** is the subtlest correctness risk: the MCU must never interpret an SE error code as success. Validate `AuthMethodBlocked`→`PinLocked`/wipe and the SE050 attempt-attribute `0x6986` denial against AN12413 on sacrificial units. Boot rollback reconciliation remains the separately tested directional page124/E120 check.
