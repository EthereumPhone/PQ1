COMMENT_ON: 546
---
**Non-normative review note: Trezor's update-control-block rules against the candidate, and one rule about frozen decoders (2026-10-11 security frontier research, item FWU-7).**

This asks for no change to the frozen draft and no code in this batch. It is input for whoever reviews the backend.

The research compared Trezor's update control block (`core/embed/sec/image/stm32/boot_ucb.c` in trezor-firmware) with the candidate design. The first proposal, to add six rows to the draft, was refuted by its own reviewer. Three things survive:

1. **A mapping to confirm.** Of the six Trezor rules, the reviewer found four already normative in Draft 1.1 (the record is bound to the artifact hashes; the bootloader re-verifies; no record field can select a destination address; "confirmed" is written by the running candidate, never by the bootloader). One does not transfer (erase the record first: Trezor copies an image, pq1 selects a slot, and the candidate's journal is program-only). One is harmful (a route-around flag byte, see point 2). I did not re-derive the section mapping. Treat it as a checklist to confirm, not as a finding.
2. **A rule worth writing into the review prompt.** A bug in a frozen decoder can only be routed around on the producer side: the updatable firmware never emits the input that triggers it. No field that the frozen bootloader honours may switch off or reinterpret one of its checks. The bootloader can only honour flags that were coded before the freeze, and any flag it does honour is a downgrade knob for hostile runtime code. The strict checks already in the pure core point the same way: `fw-manifest/src/v6.rs:562` rejects any schema other than 6, and `fw-manifest/src/v6.rs:565` and `fw-manifest/src/v6.rs:592` reject non-zero header reserved bytes and non-erased trailing bytes.
3. **Know the accepted input set before the freeze.** The bootloader links the same decoder crate the host tools use (`fsbl/src/manifest.rs:17`), so there is no second implementation to compare against. What matters is that this one decoder is fuzzed and bound-checked before it is frozen. The two harnesses under `fw-manifest/fuzz` are not run by CI (#635), and #776 records that the nightly bounded proofs did not reach this crate.

- [ ] Add points 1 and 2 to the review inputs for this batch.
- [ ] Treat #635 and #776 as prerequisites of any bootloader freeze, not only as CI hygiene.

Documentation only. No board dependency. It matters **before the first unit is locked**, because after that a decoder bug in the bootloader is permanent.

Not checked: I did not open the Trezor source, and I did not check the current state of #776.

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item FWU-7, section 9; status "redesign needed", this is the narrower surviving form). Report priority P3 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
