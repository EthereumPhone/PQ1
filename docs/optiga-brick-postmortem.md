# OPTIGA Trust M pairing: brick post-mortem and restructure

**Audience**: engineers on the PQSigner team who need to understand (a) what bricked our TRUSTMV3SHIELDTOBO1 test chip during bring-up, (b) why the current code would brick *any* device on *any* firmware update, and (c) what we're changing structurally to make sure it never happens again.

**Last updated**: 2026-04-17.

---

## TL;DR

1. A test chip was rendered unusable for Shielded Connection (encrypted I2C) during bring-up. One OID (`0xE140`, the Platform Binding Secret) is permanently write-locked; everything else on the chip still works.
2. The code that did it isn't a bring-up-only bug. If we shipped the current driver to production, **every legitimate firmware update would brick the wallet** because the pairing secret's wrap key depends on `firmware_hash()`, which changes on every rebuild.
3. We're restructuring the OPTIGA pairing flow along the lines of Trezor's production design: derive the pairing secret deterministically from an OTP-burned device master key, drop the flash-seal entirely, decouple SE wrap keys from `firmware_hash`.
4. `firmware_hash()` itself is kept intact — the 8-BIP-39-word attestation on the OLED ("verify your device is running the source you audited") is unchanged. Only its role in SE wrap keys is removed.

If you only read one thing, read [§3 "Why the current code bricks on every update"](#3-why-the-current-code-bricks-on-every-update).

---

## 1. What actually got bricked

The chip on our bench (TRUSTMV3SHIELDTOBO1, the base V3 variant, not MTR/Express) has:

- **OID `0xE140` at LcsO=Operational with an unknown PBS.** The chip knows the 32 bytes; we don't. Change AC is `LcsO<op OR Conf(E140)` — the first clause fails because LcsO=op is hardware-forward-only, the second requires a Shielded Connection we can't establish because we don't have the PBS. So the PBS slot is write-locked forever.

That's the full extent of the damage — *one* OID, one direction:

- ✅ All APDU commands work (GetRandom, GetDataObject, SetDataObject, DecryptSym, CalcSign, HMAC, CalcHash, TLS-PRF, ECDH, …).
- ✅ All other OIDs accessible — arbitrary data slots `F1D0..F1DF`, key slots `E0F0..E0F3`, AES `E200`, session contexts `E100..E103`, certs `E0E0..E0E3`, counters `E120..E123`, lifecycle system objects.
- ✅ Security Event Counter at zero, not throttled.
- ❌ **Shielded Connection (PRL) unreachable** on this chip, because the chip's PRL state machine uses E140 as the PBS source and we can't rotate it.

For dev work without PRL (plaintext I2C between STM32 and OPTIGA on our desk), the chip is still useful. For shipping a production wallet, it is not.

---

## 2. Why we care beyond one bench chip

The bench chip got bricked during debugging, which is an acceptable cost of bring-up. The point of this doc isn't "we lost a chip." It's that **the same code path would brick customer devices on every firmware update**. We need to fix it before any silicon leaves the building.

---

## 3. Why the current code bricks on every update

Three causes. Each one alone is survivable; all three together guarantee a brick on any firmware change.

### Cause 1: LcsO=Operational is irreversible

Per OPTIGA Trust M SRM §"Life Cycle Status":

> *"Once Lcs0 is set to higher value, it is not reversible and cannot be set to lower value any more."*

Our `setup_pbs_no_handshake` writes `LcsO=0x07` (Operational) on `E140` as its final step. This is **correct** — the chip's PRL state machine refuses `MasterHello` unless `E140.LcsO >= Operational`. We have to bump it for Shielded Connection to work at all. The SRM §"Platform Binding Secret" is explicit: *"It shall be 64 bytes and LcsO set to operational."*

After the bump, `E140`'s Change AC evaluates to:
```
Change = (LcsO < Operational) OR (Conf on E140)
       =      false            OR  (needs matching PBS on both sides)
```

The first arm is permanently unsatisfiable (LcsO only moves up). The second arm needs a Shielded Connection, which needs a matching PBS. So: once LcsO is op, the only way to rewrite `E140` is if the host already knows the PBS.

### Cause 2: The PBS is non-deterministic

`setup_pbs_no_handshake` generates a fresh 32 bytes from the STM32 TRNG on every first boot:

```rust
crate::rng::fill(&mut pbs).map_err(|_| OptigaError::Transport)?;
```

Different bytes every time. The *only* copy of those bytes lives in MCU flash page 126 (once they're sealed). There's no way to regenerate them from any stable input — they're pure randomness that happens to be remembered.

### Cause 3: The flash seal depends on `firmware_hash()`

`secure/src/hw/huk.rs::derive_device_key()` mixes `firmware_hash()` — SHA-256 of the secure flash region — into the AES-256-GCM wrap key:

```rust
let mut h = Sha256::new();
h.update(b"pqsigner-device-key-v1");
h.update(&(domain_tag.len() as u32).to_le_bytes());
h.update(domain_tag);
h.update(&uid);
h.update(&fw_hash);    // ← this line
```

**Cryptographic hash: any single byte of firmware change produces a completely different digest.** So any firmware rebuild — a bug fix, a `debug-log` toggle, a comment change, anything — produces a different `fw_hash`, a different wrap key, and the previously-sealed 60 bytes on flash page 126 become undecryptable. `AuthFailed` every time.

### The combined sequence

```text
[Day 0 — first provisioning, firmware v1]
  setup_pbs_no_handshake()
    ├─ generate random PBS_v1 from TRNG
    ├─ write PBS_v1 to chip E140             (chip now has PBS_v1)
    ├─ write metadata to E140                (Change AC becomes `LcsO<op OR Conf(E140)`)
    ├─ write LcsO = Operational to E140      ★ irreversible
    └─ seal PBS_v1 to MCU flash page 126
         wrap_key = SHA256(domain || UID || fw_hash_v1)
                                       ^^^^^^^^^^^^^
                                       ties the seal to this firmware

  Shielded connection works; wallet unlocks.

[Day N — firmware v2 is shipped or flashed
          (any one-byte change in secure/src, say a bug fix)]

  load_pbs()
    ├─ reads flash page 126 — still the ciphertext from day 0
    ├─ wrap_key = SHA256(domain || UID || fw_hash_v2)
    │                                       ^^^^^^^^^^^^^
    │                                       different: NEW firmware
    ├─ AES-GCM decrypt → tag mismatch → AuthFailed
    └─ treats flash as blank; self.shield.pbs_loaded = false

  is_provisioned() returns true (chip's counter OID is populated)
    → first-boot wizard SKIPPED
    → no attempt to re-provision

  User enters PIN:
    authenticate_and_read()
      └─ ensure_shield()
           ├─ shield.active = false, shield.pbs_loaded = false
           └─ returns Err(OptigaError::Shield)

    → unlock fails.

  User tries factory-reset:
    factory_reset()
      └─ tries to write reset sentinel to counter OID
           └─ Change AC requires Conf(E140) = shielded connection = no PBS
              → Status=0xFF, refuse.

    → factory-reset fails.

  Device is inaccessible.
```

Any one of the three causes defuses the sequence:

| Cause removed | What happens on v2 update |
|---|---|
| Don't bump LcsO to op | `E140` stays at Creation, new firmware writes fresh PBS, continue. (Loses: PRL works, because PRL needs LcsO=op.) |
| PBS is deterministic | `load_pbs` doesn't exist — PBS regenerated at boot from stable input, seal irrelevant. |
| Wrap key independent of `firmware_hash` | Seal still decryptable after v2, `load_pbs` succeeds with old PBS, continue. |

We plan to remove Causes 2 and 3 (the ones that were unforced design errors). LcsO=op has to stay — it's a real requirement — but once Causes 2 and 3 are gone, the irreversibility stops being a problem.

---

## 4. The `firmware_hash()` question

Initial reaction from one of us: "can we keep `firmware_hash()` somehow, it's the attestation feature." Yes — the fix doesn't touch what `firmware_hash()` is for. It only moves it out of the place it doesn't belong.

`firmware_hash()` is doing *two* jobs today, and one of them is the wrong job for it:

| Job | Purpose | Right input | Currently |
|---|---|---|---|
| **A. Firmware attestation** | User sees 8 BIP-39 words on OLED; compares against published hash; verifies "my device is running the source I audited." | SHA-256 of secure flash region. *Must* change on every rebuild — that's the whole point. | ✅ Correct. Keep. |
| **B. SE wrap-key derivation** | Bind SE-stored secrets to this silicon. | Silicon-unique device identity. *Must* be stable across firmware versions. | ❌ Currently = `firmware_hash`. Wrong source. This is what bricks. |

The right source for Job B is an OTP-burned device master key (stable, silicon-bound, survives firmware updates). Once the OTP key is what HUK derives off, all SE wrap keys survive updates, the 8-word attestation on the OLED continues to show the firmware's fingerprint, and "is my firmware genuine?" and "what's my device identity?" are separately answerable questions.

The fear-case that motivated mixing `firmware_hash` into the wrap key was *"if an attacker replaces the firmware, the new firmware can't unwrap the SE secrets."* On inspection, that defense doesn't work:

1. A tampered firmware running on the legitimate MCU has the same OTP and UID access as legitimate firmware. It can compute any hash it wants and derive any wrap key. Binding our wrap key to our firmware_hash doesn't stop a tampered firmware from using its own firmware_hash.
2. What actually stops tampered firmware from running is **secure boot** (work-todo #13, OEMiROT signed images + hybrid ML-DSA/Ed25519 verification) and **RDP Level 2** lockdown. Those are the real defenses; the `firmware_hash`-in-HUK thing was security theatre that armed a reliability bomb.

So the plan is: keep `firmware_hash()` the function, keep the 8-word attestation, keep using `firmware_hash` as an input to the #22 attestation manifest (firmware-identity binding). Just remove it from HUK.

---

## 5. The structural fix

Five changes. Each can be landed independently; the full set removes the brick scenario entirely.

### 5.1 OTP-derived device master key (new)

`secure/src/hw/otp.rs` — read/write STM32U585 OTP block. 32 bytes of TRNG output burned once per physical MCU at factory. Immutable for the silicon's lifetime.

```rust
pub fn read_device_master() -> Result<[u8; 32], OtpError>;
pub fn burn_device_master(key: &[u8; 32]) -> Result<(), OtpError>;  // one-shot
pub fn is_device_master_burned() -> bool;
```

Makefile target `stm32-burn-device-key` runs the burn once per physical board. After that, the master key is readable by firmware but not rewriteable.

### 5.2 Deterministic key derivation layer (new, parallel to Trezor `secret_keys/`)

`secure/src/hw/secret_keys.rs`:

```rust
pub fn optiga_pairing_secret()  -> Result<[u8; 32], Error>;   // HKDF(OTP, "optiga-pbs-v1")
pub fn se050_scp03_enc_key()    -> Result<[u8; 16], Error>;   // HKDF(OTP, "se050-scp03-enc-v1")
pub fn se050_scp03_mac_key()    -> Result<[u8; 16], Error>;   // HKDF(OTP, "se050-scp03-mac-v1")
pub fn tropic01_pairing_key()   -> Result<[u8; 32], Error>;   // HKDF(OTP, "tropic01-pair-v1")
```

Every SE-bound secret derives from the OTP master via an HKDF expansion with a distinct domain label. Domain labels are versioned — if we ever need to rotate a key's derivation, we bump `-v1` → `-v2` *and accept re-pairing of that SE* (which is acceptable when we control the timing).

### 5.3 OPTIGA PBS comes from `secret_keys::optiga_pairing_secret()`

Rewrite `setup_pbs_no_handshake` in `secure/src/optiga/mod.rs`:

```rust
fn setup_pbs_no_handshake(&mut self) -> Result<(), OptigaError> {
    let pbs = hw::secret_keys::optiga_pairing_secret()
        .map_err(|_| OptigaError::Transport)?;

    unsafe {
        apdu::set_data_object(/*…*/ apdu::OID_PBS, &pbs)?;
        apdu::set_metadata(/*…*/ apdu::OID_PBS, /* full metadata */)?;

        #[cfg(feature = "optiga-lock-operational")]
        {
            // Only bump LcsO in builds that explicitly opt in AND have
            // OTP burned. Dev builds leave E140 at Creation = rewriteable.
            assert!(hw::otp::is_device_master_burned(),
                    "optiga-lock-operational requires OTP master key to be burned");
            apdu::set_metadata(/*…*/ apdu::OID_PBS, &build_metadata_lock())?;
        }
    }

    self.shield.load_pbs(&pbs);
    Ok(())
}
```

No flash seal. PBS regenerated every boot from OTP. Safe to flash any firmware revision — the PBS input doesn't change.

### 5.4 Delete flash page 126 infrastructure

`secure/src/hw/flash.rs` — remove `read_pbs` / `write_pbs` / `erase_pbs_page` / `PBS_PAGE_ADDR` / `PbsLoadError` / the AES-GCM seal/unseal path. `secure/src/optiga/mod.rs::load_pbs` becomes effectively `self.shield.load_pbs(&secret_keys::optiga_pairing_secret()?)`. Page 126 frees up for other uses.

### 5.5 Re-root `hw/huk.rs` off `firmware_hash`

```rust
pub fn derive_device_key(domain_tag: &[u8]) -> [u8; 32] {
    let uid = read_uid();
    let otp = hw::otp::read_device_master().expect("OTP master key must be burned");

    let mut h = Sha256::new();
    h.update(b"pqsigner-device-key-v1");
    h.update(&(domain_tag.len() as u32).to_le_bytes());
    h.update(domain_tag);
    h.update(&uid);
    h.update(&otp);    // ← was fw_hash; now the OTP master key
    let digest = h.finalize();
    // …
}
```

`measured_boot::firmware_hash()` is unchanged and continues to be displayed as 8 BIP-39 words at boot for user verification. It just isn't an input to SE wrap keys any more.

---

## 6. Secondary patterns picked up from Trezor

While rewriting, we're adopting a few patterns that match our threat model. Skimmed from `~/repos/trezor-firmware/core/embed/sec/optiga/` and `~/repos/trezor-firmware/core/embed/sec/secret_keys/stm32u5/`.

### 6.1 Already shared: session-cached auth state (`OID_SESSION = 0xE100`)

Trezor uses `OPTIGA_OID_SESSION_CTX` = E100 to cache Auto-Ref state after successful PIN verify. We already do the same (`apdu::OID_SESSION: u16 = 0xE100`). Not a port — just noting we're aligned.

### 6.2 Hardware monotonic counter for PIN attempts (worth porting)

Today our PIN attempt counter is a software counter at F1E1 with `Change = Conf(E140)`. Problems:

- Glitch-fragile (firmware decrement can be reverted by a voltage glitch).
- Requires shielded connection to bump, which creates a chicken-and-egg if PRL ever degrades.

Trezor uses OPTIGA's hardware monotonic counter OIDs (`E120..E123`), linked via `Auto(LUC:E120)` access conditions. The chip decrements on each gated operation; at zero the linked OID becomes inaccessible. Hardware-enforced; glitch-resistant; doesn't depend on Shielded Connection being up.

Plan:
- Swap `OID_COUNTER = 0xF1E1` → `OID_COUNTER = 0xE120`.
- Initialize threshold = `MAX_ATTEMPTS`.
- Link `OID_AUTH_REF` (F1DC)'s Change AC to `LUC(E120)`.
- Drop the firmware-side decrement-before-verify gymnastics in `authenticate_and_read` — the chip handles it.

(Already flagged in `project_optiga_bringup.md` memory as "PIN counter hardening gap surfaced by Bundle F." This is the migration.)

### 6.3 Typed metadata abstraction (cleanup)

Trezor's `optiga_metadata` struct (fields: `lcso`, `change`, `read`, `execute`, `data_type`) is cleaner than our tag-by-tag `push_ac_simple` builders. Refactor of `apdu.rs` metadata functions. No behaviour change, just more readable. Do alongside the rest of the OPTIGA rewrite.

### 6.4 Patterns we're deliberately *not* porting

For the record, so nobody asks later:

| Trezor pattern | Why we're skipping |
|---|---|
| Multi-OID PIN stretching (`OID_PIN_CMAC` E200 + `OID_PIN_HMAC` F1D8 + `OID_PIN_ECDH` E0F3) | Trezor uses this to stop offline brute-force after flash extraction. Our design never stores PIN material in MCU flash — it sits only in OPTIGA's `F1DC` with `Read=NEV`. The threat is closed at a different layer. Re-evaluate if we add flash-based PIN state later. |
| ECDSA signing-key masking with OTP-derived mask | We don't sign with OPTIGA's ECC keys; our SLH-DSA signatures are on the STM32. The pattern's worth remembering for work-todo #18 (SLH-DSA SCA/FI hardening), but not directly applicable to the OPTIGA layer. |
| `optiga_suspend` / `optiga_resume` with RTC wakeup | Battery power management. We're USB-bus-powered. Irrelevant. |
| `OID_PIN_HMAC_CTR` (E122) separate HMAC counter | Only meaningful if we port PIN stretching (§6.4 row 1). Skip together. |

---

## 7. Guard rails

New safeguards so we cannot repeat this particular mistake:

1. **`optiga-lock-operational` is a Cargo feature, not always-on.** Default dev builds don't bump LcsO. Production builds explicitly opt in once OTP is burned + PBS is deterministic.
2. **Runtime check**: `setup_pbs_no_handshake` refuses to bump LcsO if `is_device_master_burned()` returns false. Belt-and-braces: even if `optiga-lock-operational` is accidentally enabled on a board that hasn't been through factory provisioning, the bump aborts.
3. **`optiga-bringup-fresh` is removed.** It erased flash page 126 on every boot — harmless once the PBS stops coming from flash, but it's the feature that sealed our test chip's fate and there's no longer any reason for it.
4. **`optiga-no-shield` dev feature**: skip the PBS/PRL path entirely. Use when developing on a chip where PRL isn't available (our current test chip) without risk of touching E140.

---

## 8. What you'd see end-to-end after the port

On a fresh SLS32AIA shield with the rewritten code:

| Step | Observable |
|---|---|
| 1. `make stm32-burn-device-key` on a new board (one-shot factory step) | 32 TRNG bytes written to OTP; verified readback; pass/fail marker. |
| 2. `make flash-hw FEATURES=dual-se,...` with `optiga-lock-operational` | First boot: PBS derived from OTP, written to E140 at LcsO=Creation, metadata+ACs installed, LcsO bumped to Operational. Wallet provisioned. Shielded connection green. |
| 3. Any subsequent rebuild — even with wildly different features — and reflash | Boot: `firmware_hash()` changes (8-word display reflects new firmware). PBS re-derived from OTP (unchanged). `shield.establish()` succeeds with the same PBS. Wallet unlocks normally. |
| 4. Accidentally bricking becomes structurally impossible | PBS is a pure function of OTP master + HKDF label. No state to lose. |

On our current test chip with `optiga-no-shield` while we wait for fresh shields: the driver runs, all non-PRL paths exercise (provision entropy, verify PIN via HMAC, read entropy back, factory reset of F1Dx OIDs). We just don't get bus-level I²C encryption until a fresh chip lands.

---

## 9. Timeline

- **Today, step 1**: `optiga-no-shield` dev feature + `optiga-lock-operational` gate added. Current chip stays usable for dev; any future dev chip cannot be bricked by a rebuild because the LcsO bump is now opt-in.
- **This week, step 2**: `hw/otp.rs`, `hw/secret_keys.rs`, `stm32-burn-device-key` target. Independent of OPTIGA.
- **Next week, step 3**: PBS port, HUK re-rooting, flash page 126 deletion. OPTIGA rewrite proper.
- **Following week, step 4**: Hardware counter migration (6.2), metadata-struct refactor (6.3).
- **End-to-end bring-up on a fresh SLS32AIA**: PRL handshake green, PIN unlock green, factory-reset cycle green, re-flash-any-build cycle green.

---

## Appendix A: references

- OPTIGA Trust M SRM v3.70 — `~/repos/optiga-trust-m-overview/docs/OPTIGA™ Trust M Solution Reference Manual.md`
- IFX I2C Protocol v2.03 — `~/repos/optiga-trust-m-overview/docs/pdf/Infineon_I2C_Protocol_v2.03.pdf`
- Trezor reference implementation:
  - `~/repos/trezor-firmware/core/embed/sec/optiga/optiga.c`
  - `~/repos/trezor-firmware/core/embed/sec/optiga/optiga_init.c`
  - `~/repos/trezor-firmware/core/embed/sec/secret_keys/stm32u5/secret_keys.c`
- Our own prior notes: `docs/optiga-bringup-status.md`, `project_optiga_bringup.md` (memory).
- Related work-todo items: #7 HUK-SAES, #18 SLH-DSA hardening, #22 triple-UID attestation. All three touch adjacent areas; the OTP master-key infrastructure introduced here unblocks #7 and provides the device-identity primitive #22 expects.
