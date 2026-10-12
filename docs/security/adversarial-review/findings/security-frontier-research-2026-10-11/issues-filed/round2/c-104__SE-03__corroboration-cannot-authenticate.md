COMMENT_ON: 104
---
**Note on the fix proposed in this issue's body, from the 2026-10-11 security frontier research (item SE-03). Line numbers are at master `c2fab970`.**

The path described here is unchanged on master: bare status accepted at `secure/src/se050/scp03.rs:615`, mapped at `secure/src/se050/apdu.rs:768` and `secure/src/se050/mod.rs:2868`, wipe at `secure/src/nsc/cmd_request_unlock.rs:163`.

Of the three corroborations the body proposes, only the page-124 floor holds against an interposer. Repeating the check after `reinit()` and a fresh session does not: SCP03 never authenticates an error status word, an interposer that stays on the bus forges the second answer too, and a genuinely locked chip gives the same transcript. The research reviewed a variant of this (confirm with an authenticated probe) and refuted it for that reason. This is reasoned from the protocol and the code. It was not run.

The surviving design, with the checkbox list, is in a comment on #853, because that issue holds the decision about which unlock arms wipe: page 124 as the only authority for the PIN-lockout wipe, a non-wiping state for a lockout reported by the SE050, and a typed "not authenticated" result for the 2-byte arm.

<sub>**Provenance.** Security frontier research, 2026-10-11 (report item SE-03, section 7). Report priority P1 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
