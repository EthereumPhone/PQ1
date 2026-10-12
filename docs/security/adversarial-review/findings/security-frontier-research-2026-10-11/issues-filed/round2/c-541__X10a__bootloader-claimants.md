COMMENT_ON: 541
---
**Bootloader changes that are in no reservation list yet (2026-10-11 security frontier research, item X10a).**

This gate asks for every not-yet-implemented immutable component to be represented by a documented conservative reservation. The body names the rollback family and the option-byte tripwire. The research, and the issues filed from it on 2026-10-12, add changes that would also live in the bootloader and can therefore only land before the freeze. None of them is in a reservation list, and the "Cumulative resource envelope" row in #540 is still a placeholder.

| Claimant | Where tracked | Kind | Size evidence |
|---|---|---|---|
| Fail-closed signature gate, verdict accumulator, encoded slot word | #847 | code | none |
| Random source for the fault-injection delays (a constant today) | #864 item 1 | code, clock | none |
| Blank scan of the slot tail | #864 item 2 | code, boot time | estimate only |
| Stack limit register, NMI / ECC handler | #854 | code | none |
| Wider option-byte compare (write protection in both banks, OEM locks, BOOT_LOCK, brown-out level, SRAM_RST) | #270, #848 | code | "100 to 200 B", estimate |
| Fixes that the #591 sweep of `verify_images` turns up | #591 | code | none |
| SAU map for secure flash in both banks | #752 item 7 | code | none |
| Execute protection for the bootloader (an MPU table), land or decline | #542 (comment of 2026-10-12); #54 records MPU decisions | code | none |
| Board-identity check | #487 | an interface change if done as a signed field | not a byte claim |
| Second (recovery) vendor key | #486 | an interface change: this gate's profile specifies "a real-size 32-byte vendor key" | 32 B plus one compare, estimate |
| Backlight I2C stage for pq1 | #705 | transport already linked (`fsbl/src/main.rs:84` declares the module); the commit that added it says the refusal is not armed yet, so arming it is a further claim | partly spent |

Suggested handling, from the research's independent reviewer:

- Keep the verdict where this issue puts it: the combined link in the frozen profile. A sum of per-item estimates is not a fit proof, because size deltas under link-time optimisation do not add. Any list total is report-only, as a low and a high bound.
- Give each row an authority state: approved, candidate, or needs a re-freeze. Only owner-approved rows count toward the conservative upper bound. Otherwise unadopted research items could turn this gate red. The two interface-change rows are not byte claims; under the fail-closed contract in #540 they stop the batch.
- Pin the measured span and the stack-frame total beside the list, and fail when the measurement moves without the list being updated in the same commit.
- Say where the measurement runs. `scripts/check_fsbl_geometry.py` is called only from `make fsbl` (`Makefile:2476`), which builds for the default board, the dev kit (`Makefile:43`), and no workflow runs it (#720). Either add a `BOARD=pq1` step or call the list a manual gate.

- [ ] Add the claimant list to this gate's report, or fill the envelope row in #540 with it.
- [ ] Mark each row approved, candidate or re-freeze.
- [ ] Decide the vendor-key count (#486) before this profile is frozen.

Left out on purpose: the stale 28,704 B figure (tracked in #866) and the missing CI run of the geometry gate (#720).

**This list only has value before the first unit is locked. A bootloader change that misses the frozen image cannot be retried.** Host and CI work only; no board change.

Not checked: none of the sizes is measured, and I did not link a bootloader. The per-item estimates are the research's, and it calls its own total (roughly 1.3 to 2.8 KB) unmeasured.

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item X10a, section 12). Report priority P2 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
