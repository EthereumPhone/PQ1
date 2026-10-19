# OPTIGA Trust M bring-up — what works, what's broken

Last updated: 2026-04-16. Tracks the state of the OPTIGA Trust M V3 driver against real silicon (Infineon **OPTIGA Trust M MTR Express V3** board, on the breadboard with the **B-U585I-IOT02A**). Companion file to `project_optiga_bringup.md` in the agent memory.

---

> **Update 2026-04-30 (audit overlay).** Several "Cleanup owed" / "Still suspect"
> items from the 2026-04-16/04-20 snapshot have since landed:
>
> - **Shielded Connection in `Creation` LcsO is the correct config** (commit
>   `fa06a4f`, 2026-04-20). The old "bump LcsO to Operational" step is gone
>   from `ensure_shield`; it's now gated behind the `optiga-lock-operational`
>   Cargo feature, off by default.
> - **Hardware monotonic counter** (E120 LUC) validated on silicon
>   (commits around `987408f` / `5620b06`, 2026-04-21). The PIN attempt
>   counter participates in three-way per-attempt consumption (MCU page 124 +
>   OPTIGA E120 LUC + SE050 silicon UserID); boot reconciliation is only the
>   directional page124/E120 check and lacks a reboot-silicon receipt.
> - **Three-way per-attempt + 10-wrong wipe flow** validated (commit `7574218`
>   and follow-ups, 2026-04-23); this is not three-way boot reconciliation.
> - **DHUK-derived 64-byte PBS** (current implementation). It is stable across
>   rebuilds and has no flash-page copy. Page 126 now belongs exclusively to
>   the wrapped SE050 BHK when `bhk` is enabled.
>
> See `optiga-brick-postmortem.md` for the longer "what we changed
> structurally" story; this file is the contemporaneous status notebook.
>
> **Protected-Update correction (2026-07-14).** The April notebook's later
> claims that E0E3 held an active sample-key trust anchor and that recovery was
> validated 16/16 are superseded. The observed E0E3 is a full type-0x12 device
> certificate; the helper was a no-op and the run returned uniform status
> failures. The candidate type-0x11 pool is E0E8/E0E9/E0EF and remains OPEN.
> No instruction in the historical snapshot below authorizes a write.
>
> **Fail-closed dispatcher (2026-10-19, #991, commit `5f868288`).** The typed
> helpers' `apdu::send_command` used to send plaintext whenever the Shielded
> Connection was inactive; since `wrap_command` clears `active` on any error,
> a swallowed `Err` followed by another APDU went out unencrypted. In every
> shielded build it is now protected-only (`Err(Shield)`, nothing on the bus,
> without a session). The only plaintext APDUs left are `OpenApplication`, the
> handshake, the cfg-gated GetRandom probes, and `apdu::send_preshield` with a
> fixed allowlist — E140 PBS write, E140 metadata write, F1E1 counter read (and
> a bench-only E140 read) — which takes the protected path when a session is
> up. The read-only probe and the #116 AC probe use typed, cfg-gated plaintext
> helpers. `optiga-no-shield` (production-fenced) keeps the old two-arm body.
> After the #36 rotation, `setup_pbs_no_handshake` no longer rewrites the
> salted final PBS in plaintext after a wipe; it proves E140 by handshake.
> **Silicon: owed.** The provision / wipe / unlock / duress e2e flows have not
> been re-run under the strict dispatcher; a path that silently relied on the
> old fallback now fails with `Shield` (grep logs for
> `send_command REFUSED`).

---

## ✅ Working end-to-end

- **MCU boot + clocks + I²C1 + GTZC1_MPCBB**.
- **OPTIGA Trust M I²C bring-up**: address probe with sleep-wake retry, 50 µs guard time between register-write and register-read, soft reset (REG_SOFT_RESET 0x88 + ReSynch).
- **IFX I²C protocol layer**: FRNR/ACKNR encoding, PCTR PRESENCE_BIT layer-selector, piggybacked DL-ACKs in response data frames, CRC-16.
- **APDU layer**: OpenApplication, GetDataObject (data + metadata), SetDataObject (data + metadata + erase-and-write), GetRandom, DecryptSym (HMAC-verify), CloseApplication, **SetObjectProtected (START / CONTINUE / FINAL with CBOR-signed manifests)**.
- **Historical OID-recovery result — REFUTED:** the April run reported
  16/16 success for `optiga-reset-oids`, but the helper targeted E0E3 as a
  type-`0x11` anchor even though the observed object is a type-`0x12` device
  certificate; uniform status failures were misread as success. The feature is
  now unconditionally compile-fenced and authorizes no recovery.
- **Wallet provisioning end-to-end (bounded claim):** the six user-OID writes
  succeeded with per-write RST hard-pulses. That provisioning observation does
  not validate, depend on, or revive the retired SetObjectProtected route.
  The SE050 half also provisions through the existing `dual_se` path.

## ⚠️ Working but with workarounds in tree

- **Per-session 2-write throttle**. After 2 successful SetData-family APDUs on this specific dev chip, all subsequent data APDUs either time out (chip ACKs at DL but never sets RESP_READY in I2C_STATE) or return `Status=0xFF`. We work around it by hard-pulsing `RST` (PE0) between every pair of writes via `OptigaTrustM::hard_reset_and_reinit()`. Effective but ~150 ms wall-clock per pulse + reinit, so provisioning takes ~2 s instead of <500 ms. **Root cause unconfirmed** — best guess is the chip's Security Event Counter (`0xE0C5`) silently incrementing and crossing a threshold we haven't read yet.
- **CloseApplication never emits a data response on this chip.** ACKs at DL layer, then state stays `0x08` indefinitely. `reopen_application()` was the prior session's cycle approach; we now skip it entirely and use the RST pulse instead.
- **TZSC self-check is log-only.** The bit-position constants in `sau.rs::stm32::configure_gtzc` came from an audit commit that targeted the wrong base (`0x5003_2800` = TZIC) and a register layout that doesn't match STM32U585. Base address is now correct (`0x5003_2400`); `expect1/expect2/expect3` masks still need re-auditing against RM0456 §32.8 before the panic-on-mismatch can be reinstated.
- **Historical E0E3 sample-anchor hypothesis — refuted.** On this observed
  part E0E3 is a full type-0x12 device certificate, not a mutable type-0x11
  anchor. The retired helper did not establish a usable anchor. Production
  remains blocked on inventory and closure of E0E8/E0E9/E0EF, not on an E0E3
  overwrite ceremony.

## ❌ Still broken — needs new investigation

### 1. Shielded Connection handshake — partial progress 2026-04-20

**UPDATE 2026-04-20:** Two of the four suspects below are now resolved, and the third (SlaveHello silence) no longer reproduces on the fresh TRUSTMV3SHIELDTOBO1 with our corrected code.

Current state on the fresh chip:

| Step | Observed |
|---|---|
| MasterHello over PRL | Sent cleanly |
| SlaveHello | **38 bytes received** (not the prior `[00, 00, 00, 00]` — chip engages PRL normally now) |
| Session-key derivation | Runs locally |
| MasterFinished | Sent |
| SlaveFinished | **Chip returns a 7-byte error frame (`0a 00 02 08 40 75 d4 00`) instead of the expected ~45-byte SlaveFinished.** `shield.establish` bails with `HandshakeFailed` at the length check. |

The "SlaveHello=0000" failure on the original bench chip was likely a symptom of multiple underlying issues on that specific (recovered-via-SetObjectProtected) unit; on pristine silicon the chip does emit a proper SlaveHello.

**Resolved / false-positive:**

- ~~Chip-side PRL state requires LcsO=Operational on `0xE140`.~~ **FALSE.** The Infineon pairing example (`example_pair_host_and_optiga_using_pre_shared_secret.c:30-35`) explicitly uses `#define FINAL_LCSO_STATE (LCSO_STATE_CREATION)` during pairing, and the PRL dispatcher (`ifx_i2c_presentation_layer.c:820-829`) has no LcsO check. The SRM "Pairing Use Case Pre-conditions" (L912-913) actually requires `LcsO < operational`, not `= operational`. Our `ensure_shield` used to bump LcsO=op before `establish` — that call is now removed so PRL runs with E140 at Creation (fully reversible).
- ~~PBS cleared by RST hard-pulse.~~ **FALSE.** With the PE4 RST pulse correctly reaching the chip + fingerprint logging in `load_pbs`, we confirmed PBS matches byte-for-byte between MCU derivation and what E140 retains across resets. The earlier chip's MasterHello silence was unrelated to RST-induced PBS loss.

**Still suspect — next debug step for MasterFinished:**

- **Session-key derivation / AAD-nonce construction mismatch.** SlaveHello arrives fine (38 bytes), so MasterHello bytes are correct. Rejection of MasterFinished suggests our TLS-PRF-SHA256 output or our CCM-8 AAD/nonce layout diverges from the Infineon reference. Use LA to capture the MasterFinished payload bytes on the wire and cross-check against `ifx_i2c_presentation_layer.c::prl_derive_session_keys` + `prl_encrypt_payload`. PBS matches (confirmed via fingerprint), so the bug is in the PRF or frame-assembly code, not in the secret.
- **Security Event Counter (`0xE0C5`) above PRL threshold.** Still a possibility. Read `0xE0C5` right before `establish()` and log it. If ≥ threshold, chip refuses PRL even with valid PBS.
- **MasterHello byte format subtly off.** SlaveHello came through, so MasterHello is *mostly* right, but some field inside (ProtoVer byte, seq seeding) could still be off enough to trigger a later Finished-mismatch.

The fix that enabled this progress is in `secure/src/optiga/mod.rs::ensure_shield` — the unnecessary `ensure_pbs_lcso_operational()` call was removed (doc note preserved in that function). With that call gone, shielded messaging testing is reversible and can happen in Creation mode, exactly as Infineon's reference demonstrates.

### 2. SPHINCS+C10 sign on real silicon (BLOCKED by #1)

Untested. `nsc::cmd_sign_userop` → unlock → reconstruct entropy → derive SK → sign. Until #1 is resolved we can't reach the signing path.

### 3. Provisioning takes 2 s wall-clock

The per-write RST pulse adds ~150 ms each, ×6 OIDs, ×2 (SetData + reinit) ≈ 2 s. Acceptable for a debug binary; not for a user holding a button on first-boot. Mitigation depends on the root cause of the throttle being identified — if it's SEC counter, a metadata-only adjustment may avoid incrementing it; if it's a per-session work-buffer issue, batching multiple writes into one APDU (where the SRM allows it) reduces the count.

## 🔧 Cleanup owed before merging into main

- **`secure/src/sau.rs`** — re-audit `SECCFGR1_*_BIT` / `SECCFGR2_*_BIT` / `SECCFGR3_*_BIT` against STM32U585 RM0456 §32.8 (current values were copied from a generic STM32U5 source and don't match). Reinstate the panic-on-mismatch once the bits are right.
- **`optiga-reset-oids` feature** — retired and fail-closed. Its E0E3
  sample-key route is mis-targeted on the observed part; do not build or flash
  it. Any future Protected-Update design starts from the pinned
  E0E8/E0E9/E0EF inventory and a separately reviewed factory ceremony.
- **`hard_reset_and_reinit` calls in `store_objects`** — once the throttle root cause is fixed, remove the per-step pulses. They're a workaround, not the right design.
- **Remaining `for _ in 0..N { cortex_m::asm::nop() }` patterns** — `secure/src/tropic01_se.rs`, `secure/src/nsc/cmd_sign_userop.rs`, and `secure/src/hw/buttons.rs` still use the LTO-elidable form. Convert to `cortex_m::asm::delay(N)` to be safe.

## Hardware wiring

For anyone reproducing this on the same setup:

| Pin on OPTIGA MTR Express V3 board | Pin on B-U585I-IOT02A    | Purpose                          |
|------------------------------------|--------------------------|----------------------------------|
| `3V3`                              | `+3V3` rail              | Chip VCC                         |
| `GND`                              | `GND` rail               | Common ground                    |
| `SCL`                              | Arduino `D15` (= PB8)    | I²C1 SCL                         |
| `SDA`                              | Arduino `D14` (= PB9)    | I²C1 SDA                         |
| `CTL`                              | `+3V3` rail              | Power gate (always on)           |
| `RST`                              | Arduino `D5` (= PE0)     | Logic reset (firmware-driven)    |

Internal pull-up on the chip's RST means floating works at boot, but the firmware drives PE0 high explicitly via `optiga::reset_pin::init()` to avoid brownout-induced reset glitches. `reset_pin::hard_pulse()` toggles low for ~10 ms then returns high + 50 ms settle.
