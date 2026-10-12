COMMENT_ON: 485
---
**Review result for this proposal, from the 2026-10-11 security frontier research (item SE-08). Line numbers are at master `c2fab970`.**

The research proposed a lifetime counter on the *read* of the two secret objects. Its review refuted that placement and confirmed the one in this issue: the counter has to sit on the guess path, which is the Execute condition of the PIN reference object. Four points for whoever picks this up.

**1. Why the read path fails (so nobody moves it there).** A wrong guess never reaches a read. The verify must succeed (`secure/src/optiga/mod.rs:2584`) before the entropy share (`secure/src/optiga/mod.rs:2619`) and the master value (`secure/src/optiga/mod.rs:2625`) are read. A counter in their Read condition would count successful unlocks only, two units per unlock, and cost an attacker nothing per wrong guess. By the research's reading of Trezor's driver, Trezor binds its total counter through Execute as well.

**2. This issue's fold target is closed.** The body says to land this "inside the #443 first-boot ceremony work". #443 is closed. The lifetime property depends on `Change = Never`, which is permanent only once the counter object is at the operational lifecycle state. So this lands with the S-3 counter profile, when that profile is frozen and exercised on a sacrificial part. It is not a standalone firmware change and it is not a reason to bring S-3 forward.

**3. What the design still has to settle.**

- [ ] The attach point inside Execute. One option is two counters in one expression on the PIN reference object (the existing attempt counter and the new lifetime one). The only counter condition the driver builds today is a single one on Execute (`secure/src/optiga/apdu.rs:1379`), and two counters in one expression are not validated on this part. The other option is a chip-side stretching key whose Execute carries the counter, which is Trezor's shape; it changes the PIN derivation and forces every bench board to be provisioned again.
- [ ] Duress parity. Under the `duress-pin` feature the duress reference object is executed on every unlock and has its own counter (`secure/src/optiga/apdu.rs:246`). Whatever is added to the real path needs a twin on the duress path, or the two become distinguishable by timing.
- [ ] The budget. The attempt counter is reset after every correct PIN (`secure/src/optiga/mod.rs:1621`), which is the gap this issue describes. The new counter is never reset, so it also counts every normal unlock and every idle re-unlock. The in-repo object table gives 600,000 as the default limit of the free counter (`docs/secure-elements/OPTIGATRUSTM/commands-and-oids.md:359`). The number is a product decision.
- [ ] What the user sees when the budget is spent (restore from the 24 words on a new unit).

**4. Silicon checks this needs, all on a sacrificial OPTIGA.** Two counters in one Execute expression are honoured; the counter object accepts `Change = Never` and it holds after the lifecycle move; the duress twin still matches in timing. A chip whose PIN reference object is already at the operational state cannot host these trials.

**Security Event Counter (the other half of the research item).** Reading it at unlock is #275 and stays advisory. The research's one addition is posted there.

<sub>**Provenance.** Security frontier research, 2026-10-11 (report item SE-08, section 7; status "redesign needed", so only the surviving form is given here). Report priority P2 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
