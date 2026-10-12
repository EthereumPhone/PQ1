COMMENT_ON: 487
---
**The trigger in this issue's title has fired: two boards are in the tree (2026-10-11 security frontier research, item FWU-3).**

This issue says to add the binding "when a second board/revision is introduced" and calls the gap harmless with a single target. Since then `BOARD=pq1` (the 48-pin production board) exists beside `BOARD=iota2` (the dev kit), and the build default is still the dev kit (`Makefile:43`).

State at master:

- Neither manifest format has a board field. The legacy signed preimage is the domain tag, the version and two hashes (`fw-manifest/src/lib.rs:204`). The candidate v6 preimage is 121 bytes with no hardware field (`fw-manifest/src/v6.rs:55`).
- `fwsign` has no notion of a board: the word does not occur under `fwsign/src`. `fsbl/build.rs` has no board-specific key handling, so both boards trust the same vendor key.
- Every bench build uses the shared development key, so a cross-board bundle is accepted today by the updater and by the bootloader. That is a bench hazard, not a shipping one: `make release` is a hard error (`Makefile:2962`).

Why it matters on this pair of boards: PA8 is the RIGHT button on the dev kit (`secure/src/board/iota2.rs:209`) and the enable for the rail that powers both secure elements on pq1 (`secure/src/board/pq1.rs:225`). By the research's reading, a vendor-signed dev-kit image on a locked pq1 leaves the secure elements unpowered, unlock fails, and because the update commands need an unlock the unit cannot be updated back. That is a brick with no secret disclosed. It needs a release-process mistake, not an attacker capability, which is why the research settled on P2 (first proposed as P0).

The mechanism is an owner decision. Four candidates:

| Mechanism | Changes the signed bytes? | Notes |
|---|---|---|
| Signed model and revision fields | Yes (121 to about 127 bytes, new digest) | Falls under the rollback-manifest rule in `CLAUDE.md`: approved specification digest, dual review, owner stage decision. An input to the candidate review (#543, #545), not an implementation request. |
| Per-board domain tag | Yes | The domain tag is part of the signed preimage (`fw-manifest/src/lib.rs:204`), and the candidate draft calls this "a new manifest schema/domain" (`docs/security/a-b-firmware-rollback-architecture.md:2436`). Same governance as the row above. |
| Per-board vendor key | No | The other half of the candidate draft's own answer for another product (a "dedicated key"). No format change. Costs a second key ceremony (#69), a per-board key-policy file and a per-board key in the bootloader build, which has no board handling today. |
| Board tag inside the secure image | No | Covered by the signed secure-image hash. It can reject only after the image is written and hashed, so it protects boot, not `FW_BEGIN`. |

Constraints whichever is chosen:

- The updater-side check has to sit inside the existing all-steps-run chain. `secure/src/fw_update/mod.rs:493` deliberately does not short-circuit, so "reject before the signature check" is not available, and the new step needs the same fault-injection sentinels as the others.
- **The bootloader-side check must exist before the first unit is locked.** After write protection plus RDP-2 it cannot be added, and a later pq1 revision would need it. Its bytes count against the bootloader budget (#541).
- An unsigned tag is not a control. It catches accidents only.

Doable now without touching any manifest:

- [ ] `fwsign sign` requires a board identity and cross-checks it against the board feature the ELF files were built with.
- [ ] The release feature set refuses to build without an explicit `BOARD`. Today `RELEASE_FEATURES` takes `$(BOARD_FEATURE)` (`Makefile:2662`), which follows the dev-kit default.
- [ ] Owner: pick the mechanism and record it with the freeze review (#226, #486).
- [ ] Update this issue's title and body: the precondition is met.

Not checked: I did not build or flash a cross-board image. The consequence chain on pq1 is the research's code reading.

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item FWU-3, section 9). Report priority P2 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
