COMMENT_ON: 117
---
**A concrete fix for this issue, from the 2026-10-11 security frontier research (item SE-05), plus one stale detail in the body. Line numbers are at master `c2fab970`.**

**Status of the body at master.** The replay still stands. The host sends a constant hello (`secure/src/optiga/shield.rs:701`), the session keys come only from the pairing secret and the chip's random value (`secure/src/optiga/shield.rs:397`), and the host's first sequence number is the chip's value plus one (`secure/src/optiga/shield.rs:802`, `secure/src/optiga/shield.rs:915`). The host adds no fresh value of its own anywhere. One detail is stale: the body says any `seq >= dec_seq` is accepted after the handshake. Responses are now bound to an advance of 1 to 3 from the last authenticated counter (`secure/src/optiga/shield.rs:590`). That narrows mid-session tricks. It does not affect replaying a whole recorded session from its handshake.

**Why "fresh GetRandom before destructive verdicts" does not close it.** The record's authenticated header is the type, the sequence number, the version and the length (`secure/src/optiga/shield.rs:424`). It does not bind the command. A recorded GetRandom response therefore decrypts and authenticates in the replayed session, and the host has no way to tell that the bytes are old.

**Proposed mechanism: a liveness probe the host can check.** Straight after every handshake, send 32 fresh bytes through the tunnel to a command whose answer is a fixed function of those bytes, and compare the answer locally. OPTIGA `CalcHash` fits: the host computes SHA-256 of the same bytes itself. In a replayed session the recorded answer is the hash of the old challenge, so the compare fails. Forging a new answer needs the chip-to-host session key. The reviewer tried three bypasses on paper (replaying the recorded probe answer, forging one, splicing a live handshake onto recorded records) and none worked. Nothing was run.

A second reason to send the probe first: in a replayed session the host encrypts under the same key and the same nonce sequence as the recorded session. Today its first real command goes out under that reused pair. With the probe first, the only frame sent under the reused pair is random data.

- [ ] Add a `CalcHash` command to the driver. None exists: the command constants at `secure/src/optiga/apdu.rs:116` and around it have no hash command. The in-repo command reference describes it at `docs/secure-elements/OPTIGATRUSTM/commands-and-oids.md:198`. That description was not checked against the vendor manual or the part.
- [ ] Run the probe in `ensure_shield`, after `establish` succeeds (`secure/src/optiga/mod.rs:573`) and before any caller can use the session. On a mismatch, zeroize the session and leave it inactive. Guard the compare the way the sequence checks are guarded (a caller-owned receipt, checked twice), so that one skipped branch does not leave a replayed session live.
- [ ] Draw the 32 bytes from the microcontroller's own TRNG. Do not use `rng_strong`: its OPTIGA source (`secure/src/rng_strong.rs:210`) ends in `ensure_shield` (`secure/src/optiga/mod.rs:358`), so the probe would re-enter itself. The challenge only has to be unpredictable to someone replaying the bus.
- [ ] Map a probe mismatch to an inconclusive error, never to `OptigaError::Shield`. The first-boot rotation treats any failure that is not inconclusive as "not rotated yet" and falls through to rewriting the pairing secret (`secure/src/optiga/mod.rs:705`, `secure/src/optiga/mod.rs:706`). Keep "probe could not be sent" and "answer was wrong" as separate causes in the log.
- [ ] Add the probe to `contracts/verification/proverif/optiga_shield_handshake_vendor.pv`, where injective agreement is recorded as false today (`contracts/verification/proverif/optiga_shield_handshake_vendor.pv:219`), and see whether it becomes provable.
- [ ] Add host tests for the new command's framing and for the mismatch path.
- [ ] Correct `docs/security/threat-model.md:233` ("freshness nonce on each session") and `docs/security/threat-model.md:255` ("no replay window"). They are false for the OPTIGA tunnel until this lands.
- [ ] Bench test, record then replay: needs a bench unit and an active I2C interposer that can answer as the chip on I2C1. A logic analyzer only captures, so this is a hand-modified unit. The playbook row for this issue (`docs/security/adversarial-review/secure-element-adversarial-review.md:26`) already lists the replay demonstration as owed.

**What it does not do**

- It defeats replay of a recorded session. It does not stop someone who holds the pairing secret, or a live relay to the genuine chip.
- It does not close the plaintext fallback tracked in #126.
- On the unlock path, page 124 is charged before any secure-element traffic. A probe failure during an unlock therefore still costs that attempt. The gain is that it consumes no OPTIGA or SE050 attempt and can never become a wipe verdict.
- Unmeasured: whether `CalcHash` is available without an access condition on the V3 part at the shipping lifecycle state, and how long it takes. It is paid on every handshake, including each self-heal retry. A bench unit with a debug port can measure both without consuming a chip.
- In the dual-chip product the consequences of a replay are a forged E120 read that drives the tamper wipe, forged wipe acknowledgements (#123), and recorded random bytes entering the three-source draw. "Replayed unlock is a PIN bypass" applies to OPTIGA-only builds.
- No other wallet vendor was found doing this. Trezor's OPTIGA handshake has the same gap.

<sub>**Provenance.** Security frontier research, 2026-10-11 (report item SE-05, section 7). Report priority P1 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
