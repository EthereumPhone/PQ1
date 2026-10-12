COMMENT_ON: 866
---
More rows for this list, from the follow-up pass of the same research on 2026-10-12. Three groups. Lines are at master `c2fab970`.

### 1. Short stale rows

- [ ] `docs/hardware/hardware_requirements.md:106`: "Tamper mesh covering all four PCB layers". The board is six-layer (`docs/hardware/pcb/README.md:7`, "Six-layer stackup").
- [ ] `docs/hardware/hardware_requirements.md:119-122`: the consumption-mask row says "dev-board pin is PA5; pick a final pin on the custom board". The pin has been picked: on pq1 the mask is TIM3 channel 1 on PA6 (`secure/src/board/pq1.rs:319`, `secure/src/board/pq1.rs:333`), and PA6 is not connected on the board (`secure/src/board/pq1.rs:327`), so the row should also say the output drives no load.
- [ ] `docs/hardware/hardware_requirements.md:61-63`: "the two SEs share I2C1 today; evaluate moving SE050 to a second I²C peripheral". On pq1 the SE050 already has its own bus, I2C4 on PB6/PB7 (`secure/src/board/pq1.rs:156-158`).
- [ ] `docs/hardware/hardware_requirements.md:139-151` and `:245`: the VBAT supercapacitor row says "board not started". The V10 schematic already has a backup capacitor on that pin, much smaller than the one the row plans around. That one needs a measurement and an owner decision, so it has its own issue: {{H1}}.
- [ ] `CLAUDE.md:14`: "accepted ONLY against the three pinned canonical `MultiSendCallOnly` deployments". Master allowlists four (`proto/src/lib.rs:1804`, `MULTISEND_CALL_ONLY_ADDRESSES: [[u8; 20]; 4]`; Safe v1.5.0 was added by `67db8188`). `docs/companion/safe-multisig-clear-sign.md:365` has the same "three pinned" wording.
- [ ] `docs/security/red-teaming.md:757`: "shows a paymaster page (it doesn't today)". It does: a presence page is appended (`secure/src/tx/display/value_page.rs:546`, "! PAYMASTER SET"). The page shows presence only, not identity.
- [ ] `docs/security/threat-model.md:242`: lists "MPU regions enforced in both worlds" as a present control against reading secure RAM from the non-secure world. No image programs a memory protection unit: a search of `secure/src`, `nonsecure/src`, `fsbl/src`, `shared/src` and `hw/src` for the MPU registers finds nothing. {{X8a}} proposes the first such region.
- [ ] `docs/security/threat-model.md:376`: lists "post-transfer assert `DIEPTSIZ.XFRSIZ` did not exceed declared length" as an existing mitigation. A search of every Rust file in the tree for `DIEPTSIZ` and `XFRSIZ` finds nothing, the USB driver dependency has no such check, and the non-secure HID write reduces the result to `is_ok()` (`nonsecure/src/usb/hid.rs:75`).

- [ ] `fsbl/Cargo.toml:79`: "we use the SOFTWARE SHA-256 path in FSBL, not `hw-sha256`". `fsbl/Cargo.toml:16` makes `hw-sha256` the default feature. Related: the boot-time table in `docs/security/measured-boot.md:290-296` (2.930 s of work, of which 1.167 s is hashing the secure image) appears to predate that switch, since the same document dates the first hardware-SHA bootloader boot to 2026-09-28 (`docs/security/measured-boot.md:68-70`). I found no boot time recorded for the default hardware path.
- [ ] `secure/src/sign_rate.rs:36-39`: "Future hardening": a flash-persistent quota of 500 signatures per day, "Deferred because flash writes on every sign add wear". As written it reads as planned work. It would be new per-signature flash state, which `CLAUDE.md:371` rules out, and a per-day limit needs a clock the device does not have while unplugged. Reword it as declined, with those two reasons.

### 2. The consumption-mask claims (research item M15)

Additions to the two consumption-mask checkboxes above, from the same research (item M15) after a second review. Lines are at master `c2fab970`.

**The wording fix does not have to wait for a measurement.** The research first tied the rewording to the bench result. The reviewer pointed out that the code already says the effect is unmeasured (the `compile_error!` text at `secure/src/nsc/mod.rs:723`), so only the claim-shaped sentences need to change, and they can change now. Suggested neutral wording: "unvalidated noise source; efficacy pending measurement (#228, #646)". Whether the production fence at `secure/src/nsc/mod.rs:712` stays is a separate owner decision that should follow the measurement; rewording is not that decision.

**More places that describe the mask as it was, or as a working defence.** None of these is in the list above.

- [ ] `README.md:261` and `README.md:417`: "TIM2 CH1 PWM ... on PA5". True for iota2 only; pq1 runs it on TIM3_CH1 / PA6 (`secure/src/board/pq1.rs:333`).
- [ ] `CLAUDE.md:230` and `CLAUDE.md:327`: the same TIM2 / PA5 statement, in the feature list and the file map.
- [ ] `docs/security/red-teaming.md:306` (TIM2 / PA5 again) and `docs/security/red-teaming.md:308`: "masking is the only SCA mitigation today". The signer also has a per-signature shuffle (`sphincs-c10/src/hypertree.rs:214`) and fresh randomness per signature, and the mask's own effect is unmeasured.
- [ ] `docs/security/red-teaming.md:881`: the ship checklist line "active and unbiased; measurably raises CPA trace count". With no load on the pin on either board this line cannot be ticked as written. Either make it conditional on the loaded-arm measurement or reword it.
- [ ] `docs/hardware/evt-silicon-validation.md:175`: the pin row says PA5 / TIM2_CH1 and points at lines 19 and 268 of the driver file, which today are a comment about CPU cost and a register field.
- [ ] `docs/architecture/trezor-comparison.md:425`: recommends the mask "for signature operations" without the caveat that it is unloaded here.
- [ ] Code comments: `secure/src/main.rs:1411` ("TIM2 CH1 PWM on PA5"), `secure/src/hw/consumption_mask.rs:178` ("into TIM2 CCR1") and `secure/src/hw/consumption_mask.rs:185` ("the observable PA5 PWM duty").

**One more statement to make explicit.**

- [ ] `secure/src/hw/consumption_mask.rs:102`: the check that the PWM actually reaches the pad (`selftest_pin_toggles`) runs only under `debug-log`, which production forbids. A shipping image never checks it. The reviewer's recommendation is to say so in the module header ("bench-only check") and not to add a runtime check: the pin mapping is a build constant, and on pq1 the pad is not connected.

Not checked: whether other documents repeat these statements. I searched `README.md`, `CLAUDE.md`, `docs/security/red-teaming.md`, `docs/hardware/evt-silicon-validation.md`, `docs/hardware/hardware_requirements.md` and `docs/architecture/trezor-comparison.md` only.

### 3. The USB errata row (research item USB-09)

**One more row for this list, of a different kind: the control exists, but the row does not say where, and its wording is slightly stronger than the code (2026-10-11 security frontier research, item USB-09). Re-read at master `c2fab970`.**

`docs/security/threat-model.md:373` (stale FIFO data after a zero-length-packet race, ST errata sheet ES0499) lists as mitigation: "Driver enforces single-packet transfers (`DIEPTSIZ.XFRSIZ = DIEPCTL.MPSIZ`), no interleaving in ISR, flushes all FIFOs on USB reset".

The research's two review passes disagreed about this row. One searched `nonsecure/` for those register names, found nothing, and called the row a claim with no code. The other found the behaviour in the USB driver dependency. I read the dependency source to settle it:

- The driver is the `synopsys-usb-otg` crate (`nonsecure/Cargo.toml:97`), locked to 0.4.0 (`Cargo.lock:1779`). I read version 0.4.0 in the local cargo registry, not in the master tree.
- Single-packet IN transfers: in the crate's `endpoint.rs`, the IN write path returns `BufferOverflow` when the buffer is longer than the endpoint's max packet size, then programs the transfer with a packet count of 1 and a size equal to the buffer length. So a transfer is one packet, but the size written is the buffer length, not the max packet size as the row says.
- Flush on reset: in `bus.rs`, `configure_all` sets `RXFFLSH` and `TXFFLSH` with `TXFNUM: 0x10` and waits for both to clear, and `reset()` calls `configure_all` inside a critical section. The USB-reset interrupt branch flushes the receive FIFO again.
- "No interleaving in ISR": the crate wraps its register sequences in critical sections, and the NS world polls USB with no interrupt handler of its own.
- One loose end in the dependency: the endpoint-deconfigure path carries the comment `// TODO: flushing FIFO`. I did not work out whether any path on this device reaches it with stale data in the FIFO.

Suggested edit:

- [ ] Reword the row to say the mitigation is implemented by the `synopsys-usb-otg` 0.4.0 dependency, not by code in this repo, and correct `XFRSIZ = MPSIZ` to "one packet per transfer, size at most the max packet size".
- [ ] Say in the row that the dependency is exempted, not audited, in the supply-chain record (`supply-chain/config.toml:747`). The exemption and the lockfile do pin the version: by cargo-vet's rules a bump should fail `cargo vet --locked` in CI (`.github/workflows/ci.yml:146`) until someone records a new exemption or an audit. I did not run that. So the research's request for "a check that fails on an unreviewed version change" looks already met; what is missing is a note that a bump must re-check these three behaviours.
- [ ] The row's last column ("Confirm against ES0499 Rev 11") stays open. Observing the flush on a live device belongs to the USB test rig in #590.

Not checked: the ES0499 sub-section numbers, and whether the flush behaves as the source reads on silicon.

<sub>**Provenance.** Security frontier research, 2026-10-11, follow-up pass of 2026-10-12 (hardware section "Stale rows found in the requirements documents", items M15, USB-09, CS-04, X6a, X8a). Every line above was re-read at master `c2fab970`. Code and document reading only; nothing was run.</sub>
