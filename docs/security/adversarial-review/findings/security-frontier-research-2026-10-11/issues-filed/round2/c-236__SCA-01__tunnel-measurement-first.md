COMMENT_ON: 236
---
The 2026-10 security research (item SCA-01) argues that this measurement should come before the PRF measurement in #228, and it names the target more exactly than "the scp03 sweep". Lines are at master `c2fab970`.

**Why first**

A leak found in the signing PRF can only be documented in this hardware generation (#228 says so itself). A leak found in the tunnel crypto can be fixed in firmware, by moving the tunnel AES onto the hardware AES block. That change is proposed in {{SCA-02}}, from the same research (item SCA-02); its landing is gated on this measurement.

**What to aim at on the SE050 side**

- `secure/src/se050/scp03.rs:286`: the session keys are derived by an AES-CMAC under the static channel key over data that includes the card challenge read at `secure/src/se050/scp03.rs:277`. That challenge is unauthenticated bus data at that point, so an interposer can choose it. This is the fixed-key, varying-input computation to measure. The target is the static key, not the session keys.
- By source read this handshake runs on every boot before the PIN prompt (`secure/src/main.rs:3982` leads to `secure/src/se050/mod.rs:1789`), so traces can be collected by power-cycling. Whether failed handshakes are counted or rate-limited anywhere was not checked.
- The first CMAC block of the derivation is constant, so the attack goes through an unknown intermediate value. A simple first-round model will underperform.
- The AES is the software `aes` crate (`secure/src/scp03_logic.rs:24`). Its portable backend is bitsliced with no lookup tables (from knowledge of the crate, not checked against the lock file), so table-lookup leakage models will also underperform. A null result under those models must not be reported as clean.

**What to aim at on the OPTIGA side**

- `secure/src/optiga/shield.rs:397`: the session keys are a software HMAC-SHA-256 of the long-term pairing secret and a chip-supplied random value. That is a different leakage profile from the signer, which uses the HASH peripheral, and it is the one computation here that touches the pairing secret directly.

**Practical**

- Record which SE050 variant and which static keyset the capture unit carries (#697). The research assumed the pq1 bench board's SE050 could not complete the handshake; #697 says that mismatch was fixed by making the factory keyset selectable, so either board should work. With the published default keys there is nothing secret to recover, but the leakage test itself is the same.
- Per-call trigger wiring is needed, as for #228. The trigger module has no call sites at master.
- Report the maximum |t| against the trace count with the noise floor of the capture chain, and show first that the chain can see a known leak.

- [ ] Capture the SCP03 session-key derivation with chosen card challenges, fixed versus random.
- [ ] Capture the OPTIGA session-key derivation the same way.
- [ ] State the leakage models used and the sensitivity reached.

Needs: the open bench board or an iota2 kit with the SE050 shield, a debug port, an I2C interposer or a bench build that injects chosen challenges, and an oscilloscope with a shunt in the MCU supply (a hand modification of the bench unit) or a near-field probe.

<sub>**Provenance.** Security frontier research, 2026-10-11 (report item SCA-01, section 4). Report priority P2 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
