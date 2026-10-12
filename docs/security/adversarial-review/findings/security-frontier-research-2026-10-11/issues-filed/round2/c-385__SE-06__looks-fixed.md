COMMENT_ON: 385
---
**Status check (2026-10-12): the open checkbox here looks done in the tree. Not closing; please confirm.**

The remaining item is "`OptigaError::Shield` still conflates wrong-PBS with handshake-faulted". At master `c2fab970`:

- `ensure_shield` maps a transport-class handshake failure to `OptigaError::Transport` (`secure/src/optiga/mod.rs:574`), and only other handshake failures to `Shield` (`secure/src/optiga/mod.rs:575`).
- The error type's own documentation says the split was made on 2026-07-17 (`secure/src/optiga/apdu.rs:68`), and the first-boot rotation relies on it (`secure/src/optiga/mod.rs:705`).
- `git log` attributes this to commit `8e6bcd3a` ("close the D1 residual", 2026-07-17), two days before this issue was migrated from the old to-do file.

One residual the same documentation states: `Shield` is still returned when no pairing secret is loaded and from steady-state decrypt failures, which are not probe verdicts.

Checked by reading the code and the log only. Nothing was built or run. Found while re-reading the secure-element items of the 2026-10-11 security frontier research, where two recommendations listed this issue as a prerequisite.

<sub>**Provenance.** Security frontier research, 2026-10-11 (report items SE-03 and SE-06, section 7, list this issue as related). Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
