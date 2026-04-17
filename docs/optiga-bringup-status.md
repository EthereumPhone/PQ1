# OPTIGA Trust M bring-up — what works, what's broken

Last updated: 2026-04-16. Tracks the state of the OPTIGA Trust M V3 driver against real silicon (Infineon **OPTIGA Trust M MTR Express V3** board, on the breadboard with the **B-U585I-IOT02A**). Companion file to `project_optiga_bringup.md` in the agent memory.

---

## ✅ Working end-to-end

- **MCU boot + clocks + I²C1 + GTZC1_MPCBB**.
- **OPTIGA Trust M I²C bring-up**: address probe with sleep-wake retry, 50 µs guard time between register-write and register-read, soft reset (REG_SOFT_RESET 0x88 + ReSynch).
- **IFX I²C protocol layer**: FRNR/ACKNR encoding, PCTR PRESENCE_BIT layer-selector, piggybacked DL-ACKs in response data frames, CRC-16.
- **APDU layer**: OpenApplication, GetDataObject (data + metadata), SetDataObject (data + metadata + erase-and-write), GetRandom, DecryptSym (HMAC-verify), CloseApplication, **SetObjectProtected (START / CONTINUE / FINAL with CBOR-signed manifests)**.
- **OID recovery via SetObjectProtected**: feature `optiga-reset-oids` rolls a burned `0xF1D0..0xF1DF` AUTHREF range back to a writable state, validated 16/16 OIDs OK on real silicon.
- **Wallet provisioning end-to-end**: PBS → auth_ref → entropy → master_secret → VK → bootstrap_vk → counter, all 6 user-OID writes succeed when `optiga-reset-oids` workaround (per-write RST hard-pulse) is applied. SE050 half also provisions cleanly via the existing `dual_se` path.

## ⚠️ Working but with workarounds in tree

- **Per-session 2-write throttle**. After 2 successful SetData-family APDUs on this specific dev chip, all subsequent data APDUs either time out (chip ACKs at DL but never sets RESP_READY in I2C_STATE) or return `Status=0xFF`. We work around it by hard-pulsing `RST` (PE0) between every pair of writes via `OptigaTrustM::hard_reset_and_reinit()`. Effective but ~150 ms wall-clock per pulse + reinit, so provisioning takes ~2 s instead of <500 ms. **Root cause unconfirmed** — best guess is the chip's Security Event Counter (`0xE0C5`) silently incrementing and crossing a threshold we haven't read yet.
- **CloseApplication never emits a data response on this chip.** ACKs at DL layer, then state stays `0x08` indefinitely. `reopen_application()` was the prior session's cycle approach; we now skip it entirely and use the RST pulse instead.
- **TZSC self-check is log-only.** The bit-position constants in `sau.rs::stm32::configure_gtzc` came from an audit commit that targeted the wrong base (`0x5003_2800` = TZIC) and a register layout that doesn't match STM32U585. Base address is now correct (`0x5003_2400`); `expect1/expect2/expect3` masks still need re-auditing against RM0456 §32.8 before the panic-on-mismatch can be reinstated.
- **Sample-key Trust Anchor at OID `0xE0E3`.** The TA cert that verifies our reset manifests is Infineon's `samples/integrity/sample_ec_256_priv.pem` matching cert. Anyone holding that key can `SetObjectProtected` against this chip from now until E0E3 is rewritten with a real production TA — drop `optiga-reset-oids` from default builds and plan to overwrite E0E3 (or wipe to factory metadata) before the chip ships.

## ❌ Still broken — needs new investigation

### 1. Shielded Connection handshake (BLOCKING for unlock + signing)

`OptigaTrustM::unlock` → `authenticate_and_read` → `establish` → `MasterHello` works (chip DL-ACKs the frame and emits a 4-byte response). But the response is **`SlaveHello = [00, 00, 00, 00]`** instead of the expected 38 bytes (`SCTR(1) + ProtoVer(1) + Random(32) + Seq(4)`). Without SlaveHello we can't derive session keys, so `DecryptSym`-based PIN verify never even runs.

This is the **same bug the prior session tracked** in `project_optiga_bringup.md`. Suspect list, in rough priority:

- **Chip-side PRL state requires LcsO=Operational on `0xE140`.** Currently `build_metadata_pbs_final` sets LcsO=Creation (0x01) per a comment "keep LcsO at Creation during bring-up". The Infineon reference example bumps it to Operational (0x07) before doing the handshake. Test: write a metadata-only update raising LcsO to 0x07 right after PBS provisioning, before unlock.
- **Security Event Counter (`0xE0C5`) above PRL threshold.** Read `0xE0C5` right before `establish()` and log it. If it's ≥ a small number, the chip will refuse PRL even with valid PBS. Reset it via the documented mechanism (or accept it'll decay over time on its own).
- **MasterHello byte format off-by-one.** Compare our `secure/src/optiga/shield.rs::establish()` MasterHello bytes against the reference C lib's `optiga_comms_setup_secure_session` on a logic analyser. Suspect SCTR / ProtoVer / Sequence-counter byte ordering.
- **PBS cleared by RST hard-pulse.** PBS is in NV flash and *should* survive silicon reset — but if E140's LcsO=Creation lets the chip drop the value on reset, our MCU-side cached PBS no longer matches. Test: read back E140 after a hard pulse and compare.

### 2. SLH-DSA sign on real silicon (BLOCKED by #1)

Untested. `nsc::cmd_sign_userop` → unlock → reconstruct entropy → derive SK → sign. Until #1 is resolved we can't reach the signing path.

### 3. Provisioning takes 2 s wall-clock

The per-write RST pulse adds ~150 ms each, ×6 OIDs, ×2 (SetData + reinit) ≈ 2 s. Acceptable for a debug binary; not for a user holding a button on first-boot. Mitigation depends on the root cause of the throttle being identified — if it's SEC counter, a metadata-only adjustment may avoid incrementing it; if it's a per-session work-buffer issue, batching multiple writes into one APDU (where the SRM allows it) reduces the count.

## 🔧 Cleanup owed before merging into main

- **`secure/src/sau.rs`** — re-audit `SECCFGR1_*_BIT` / `SECCFGR2_*_BIT` / `SECCFGR3_*_BIT` against STM32U585 RM0456 §32.8 (current values were copied from a generic STM32U5 source and don't match). Reinstate the panic-on-mismatch once the bits are right.
- **`optiga-reset-oids` feature** — remove from default builds before any release. The TA at E0E3 is a sample key; production must provision its own TA (or wipe E0E3) before this feature can stay enabled.
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
