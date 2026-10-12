TITLE: Run the SE050 tunnel AES (SCP03 key derivation, MAC, encryption) on the SAES hardware block instead of software AES; land after the tunnel leakage measurement
LABELS: enhancement,priority:medium,surface:sca-fi,surface:secure-element,source:frontier-research-2026-10
---
## Summary

Every time the SE050 driver opens its encrypted channel (SCP03), the MCU runs software AES-128 over the long-term channel keys, with an input that comes off the I2C bus before the chip has been authenticated. By source read this happens on every boot, before the PIN prompt. That is the textbook setup for a power or electromagnetic side-channel attack on a fixed key with a varying, attacker-supplied input. The STM32U585 has a hardware AES block (SAES) which ST documents as hardened against such attacks, and the firmware already uses it for other keys. This issue asks to move the SE050 channel AES onto it. No issue tracks this: #236 only asks to measure the existing software path on silicon, and #246 only asks to confirm SAES register bit positions. The work should be designed now and landed only after the #236 measurement shows whether the software path leaks, because the benefit rests on a vendor claim that nobody here has measured.

## What the code does today

- `secure/src/se050/scp03.rs:277`: the 8-byte card challenge is copied straight out of the chip's response.
- `secure/src/se050/scp03.rs:286`: the session keys are derived from the static keys and that challenge. This runs before the card cryptogram is checked a few lines later, so the challenge is unauthenticated bus data at this point.
- `secure/src/scp03_logic.rs:390`: `kdf` is one AES-CMAC under the static key. `secure/src/scp03_logic.rs:175` and `:24`: that CMAC, and the channel's block encryption, are the software `aes` crate (`secure/Cargo.toml:67`).
- `secure/src/se050/scp03.rs:95`: with `se050-derived-scp03` the static keys are per-device keys from `hw::secret_keys`. `Makefile:2719` puts `se050-derived-scp03` in the ship feature set. Without the feature the keys are the published NXP defaults and there is nothing to extract.
- `secure/src/se050/mod.rs:244`: `init` runs the handshake. There are four more call sites in the same file (`:365`, `:447`, `:467`, `:513`) for the first-boot key rotation.
- Before the PIN: `secure/src/main.rs:3982` asks whether the wallet is provisioned, which reaches `secure/src/se050/mod.rs:1789` (`init`), and the boot PIN prompt is later at `secure/src/main.rs:4174`. I traced this one path only. I did not check whether failed handshakes are counted or rate-limited anywhere.
- `secure/src/hw/saes.rs:487`: the SAES driver hard-codes a 256-bit key size. `:448`: a software key is a 32-byte array. `:464` and `:495`: every 16-byte block resets the peripheral and reloads all key registers from CPU memory.
- `secure/src/cmac.rs:61`: `cmac_generic` already takes the block cipher as a closure. This is the seam where SAES can be substituted without touching the CMAC logic.
- The only place outside the driver that uses SAES with a firmware-loaded key is a known-answer test (`secure/src/hw/bhk.rs:397`).

## What is already tracked elsewhere

- #236 asks for on-silicon confirmation of the emulated SCP03 and OPTIGA leakage sweeps. It measures; it does not change the implementation.
- #246 asks to confirm the SAES register bit fields against the reference manual. A 128-bit key mode depends on it.
- #55 covers the SCP03 key rotation ceremony, and #202 the key hierarchy. Both touch the same keys but not where the AES runs.
- #419 covers wiping of SCP03 key state in software. #452 (closed) covered key residue in the SAES key registers.
- So this issue is only about moving the SE050 channel AES onto SAES.

## Proposed work

- [ ] Add AES-128 key size to the SAES driver, with a known-answer test on silicon. Confirm the bit field first (#246).
- [ ] Add a load-once, multi-block SAES API: load the key, run N blocks, wipe. The current per-block reload would put the static key on the internal bus once per block.
- [ ] Add the decrypt direction for AES-128 (the response path uses CBC decryption).
- [ ] Run the SCP03 key derivation, the command and response MACs and the CBC encryption over SAES through the `cmac_generic` seam. Keep the software path for QEMU and host tests.
- [ ] Switch all five handshake call sites together, including the first-boot rotation ones, so no path keeps the software AES by accident.
- [ ] Report the flash delta. The `aes` and `cmac` crates stay for other users, so this adds code.
- [ ] Update the emulated SCP03 harnesses under `tools/sca/`, which model the software AES.
- [ ] Gate landing on the #236 tunnel measurement. If the software path shows no leak at a stated sensitivity, record that and decide again.

## What it needs

Firmware only. No board change: SAES is on the chip and the ship feature set already enables it. The acceptance test needs the open bench board (debug port) and an SE050 that completes the handshake. The gating measurement (#236) needs an oscilloscope with a current shunt or a near-field probe.

## Limits

- The OPTIGA channel is not helped. Its session keys are a software HMAC-SHA-256 of the long-term pairing secret and a chip-supplied random value with no host nonce (`secure/src/optiga/shield.rs:397`), so a bus interposer can replay that value and collect traces of the same derivation. SAES does not do HMAC. That residual stays open and is not in scope here. Moving the OPTIGA AES-CCM (`secure/src/optiga/shield.rs:1047`) to SAES would protect the session keys of a replayed session, not the pairing secret.
- The benefit rests on ST's statement that SAES resists differential power analysis. That is unmeasured here.
- The static key is still produced as bytes in CPU memory by the key hierarchy and written into the key registers. A fixed-data load leak remains. Whether the SAES wrapped-key mode could avoid that was not checked against the reference manual.
- The first block of the key derivation is constant, so an attack on the software path has to go through an unknown intermediate value. It is harder than a plain first-round attack. Nobody has shown it on this device.
- Recovering the SE050 channel keys does not give the seed. It gives a view into the tunnel, so that a later tapped, legitimate unlock would reveal the SE050 half. The other half and the PIN check are separate.
- Precedent: none. Trezor runs its OPTIGA channel AES in software and does not use SAES with a firmware-loaded key (research read of a local Trezor checkout; I did not re-open it).
- The research reviewers disagreed on cost (M or L) and priority (P1 or P2). P2 and M are the final values.

## Related

#236, #246, #55, #202, #419, #452, #697 (which SE050 variant and factory keyset a unit carries).

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item SCA-02, section 4). Report priority P2 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
