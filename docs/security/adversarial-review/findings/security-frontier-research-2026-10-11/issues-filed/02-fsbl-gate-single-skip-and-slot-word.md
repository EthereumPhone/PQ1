TITLE: FSBL: the signature gate admits on one skipped branch, and the boot slot is one unencoded stack word (close before the WRP + RDP-2 freeze)
LABELS: finding,ship-blocker,priority:high,surface:sca-fi,surface:lockdown,source:frontier-research-2026-10
---
## Summary

Two fault-injection weaknesses sit in the one stage that write protection plus RDP-2 make permanent (invariant 10). Once the FSBL pages are frozen, neither can ever be patched on that die.

1. **Signature admission fails open on one instruction skip.** The verify is evaluated twice inside `check_true_into_sentinel`, but the verdict is consumed by a single compare-and-branch in the caller, with *accept* as the fall-through. Nothing later re-checks it.
2. **The branch target is not bound to the verified slot.** The chosen slot is a two-variant enum held across the fingerprint window and decoded as "non-zero means slot B". One data fault or one skip boots the other slot while the panel shows the verified slot's eight words.

`fsbl/src/fi.rs:12-16` states that the bar for bypassing the gate is two coordinated faults. As built it is one.

## Evidence

Line numbers at master `0feea78a` (2026-10-11). The research ran at `c75b0d9c`, an ancestor of master; the cited files were diffed against master before filing.

**Gate (1)**

- `fsbl/src/main.rs:344-349`: `let sig_verdict = fi::check_true_into_sentinel(|| m.verify_signature(..).is_ok()); if sig_verdict != fi::OK_SENTINEL { return None; }`. The reject path is the taken branch; skipping it falls into accept.
- The research disassembled the bench ELFs and located the compare and branch at `0x0c000e54` to `0x0c000e5e` (iota2) and `0x0c000e5c` to `0x0c000e66` (pq1). I re-opened the source shape only and did not re-run the disassembly.
- No later stage re-verifies: `fsbl/src/main.rs:220-222` takes the result of `pick_slot` and `:299` branches.

https://github.com/EthereumPhone/PQ1/blob/0feea78a1b8bd5ecaa99c3346a5a69480fd13cbc/fsbl/src/main.rs#L344-L349

**Slot word (2)**

- `fsbl/src/slot.rs:9-13`: `pub enum Slot { A, B }`, a plain two-variant enum.
- `fsbl/src/main.rs:220-222`, `:299`: the slot value lives from `pick_slot` across the 4 s fingerprint hold to `branch::into_slot(slot)`.
- `fsbl/src/branch.rs:38-45`: `into_slot` loads MSP and the reset vector from `slot_secure_addr(slot)` with no re-check against what was verified or displayed.
- Disassembly sites reported by the research: `0x0c00181c`, `0x0c00192a` to `0x0c00193a`.
- `pick_slot` can also be steered to the older valid slot, because no rollback floor works today (#31).

**The stated bar**

- `fsbl/src/fi.rs:12-16`: "The overall bar for bypassing the FSBL gate stays at **2 coordinated faults**". The first of those two (a fault on the inner verify) is not needed when the attacker's manifest simply fails verification honestly.
- `fsbl/src/fi.rs:31-33`: every FSBL delay is the constant `0x42`, so the gate sits at a fixed time from reset (tracked in {{22}}).

## What an attacker needs

- For (1): attacker-chosen bytes in a slot and its manifest page (SWD at RDP-0, or a flash-write primitive after RDP-2), plus one timed skip on **every** boot.
- For (2): one fault. It is useful whenever the other slot holds a signed older image, which is the normal state after any update.

## Severity and evidence level

- (1) **High** in the instruction-skip model (cluster merger); **medium, chained** (skeptic, final value).
- (2) **Medium-high** in the model. The skeptic calls it the most reachable FSBL defect.
- Evidence: code read plus disassembly of bench ELFs by the research agents; source re-opened by the filer. The emulated fault sweep of #591 has not been run on this glue. **Silicon feasibility is unmeasured.**
- No production FSBL is buildable today. These paths are unconditional in the only FSBL code that exists, so they are what the freeze would capture.

## Fix directions

- [ ] Run the widened #591 sweep on the pq1 release FSBL ELF first, to get a failing baseline.
- [ ] Make the gate fail closed: reject as the fall-through, default to a halt stub.
- [ ] Fold per-stage verdict words (distinct constants) into the branch address through a non-cancelling accumulator, so a skipped check yields a wrong address and not a valid one.
- [ ] Carry the slot as a Hamming-distant word plus its complement, re-compare before the branch, bind the displayed fingerprint digest to it, and make `into_slot` reject anything else.
- [ ] Correct the two-fault claim in `fsbl/src/fi.rs:12-16`.
- [ ] Re-run the sweep and record the before and after counts.

## Related

#591 (FSBL fault sweep), #31 (rollback floor), #540 (geometry cutover), `tools/sca/README.md:369-394` (where the single-skip residual is described but not tracked). Literature: [Wagner et al.](https://eprint.iacr.org/2023/1572), [BSI-commissioned study](https://eprint.iacr.org/2025/2096).

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item M05, defect rows C1, C2 and E4). Source lines re-opened by the filer at master `0feea78a`; the disassembly addresses are the research agents' and were not re-derived. The full report is `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`; it was not committed when this issue was filed, so this body is written to stand alone.</sub>
