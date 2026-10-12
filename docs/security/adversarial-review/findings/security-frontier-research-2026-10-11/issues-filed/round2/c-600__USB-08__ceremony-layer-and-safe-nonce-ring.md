COMMENT_ON: 600
---
**Design corrections for the pure-logic core, from the 2026-10-11 security frontier research (item USB-08). Two of them contradict this issue's own text, so they are worth settling before the design document is written. Lines re-read at master `c2fab970`.**

Nothing has been built yet: there is no `docs/security/signing-ceremony-anomaly-design.md` and no ceremony module at master, and `docs/security/threat-model.md:282` still reads "NONE TODAY". The split this issue asks for (core and design document first, friction screens as a separate owner decision) is kept. The research only changes how the core should behave.

**1. Do not clear the ring on lock or idle timeout.** The body says the state is "cleared on lock/timeout/zeroize". Both lock paths can be caused by the host that this layer is meant to resist:

- The host can lock the device at will: `nonsecure/src/usb/commands.rs:287` routes the `LOCK` instruction to `nsc_api::lock()`, and the secure handler zeroizes (`secure/src/nsc/cmd_lock.rs:12`).
- The 120 s idle lock happens by itself if the host simply waits.

So a companion that sends request A, reports "failed", locks, lets the user re-enter the PIN and then sends a changed request A' would meet an empty ring. The PIN re-entry even fits the fake-error story. The ring holds only public request fields (no key, no PIN, nothing derived from either), so it can stay in secure RAM across lock and idle lock and be dropped only on reset, power loss or wipe. It is still RAM only, so the "no new flash state" rule is not touched.

**2. A per-session counter already exists, and it is the wrong one to reuse.** The triage note says "there is no per-session signing-request counter anywhere". There is one: `secure/src/sign_rate.rs:52` (`SIGNS_THIS_SESSION`). It counts signatures that were released, not prompts: it is charged inside the signer (`secure/src/crypto.rs:95`), a slot rotation charges it twice, and a declined prompt never touches it. It is also reset on every unlock and every zeroize (`secure/src/nsc/state.rs:557`, `secure/src/nsc/state.rs:388`), so it has the problem described in point 1. The signer reads it back as a fault-injection check (count must be exactly one higher), so adding a second meaning to it would break that check. The ceremony layer needs its own prompt counter, charged before the confirm dialog opens.

**3. Key the comparison on meaning, and say what "retry" means.**

- Compare on kind, chain, sender, `to`, value, token and amount, selector or calldata digest, and slot. Leave out nonce and fee fields, as this issue already says. A fingerprint over the rendered pages does not work, because the fee pages are part of what is rendered and a retry with one more wei of fee would never match.
- Do not flag "differs from the previous request" in general. Approve followed by swap, or any two unrelated transactions, would trip it and train the user to dismiss it. Restrict `MutatedRetry` to a real retry signal: same sender, chain and nonce with a different intent, or same `to` with a different amount or recipient. State in the design document that a companion using a different nonce key avoids the nonce signal.
- Decide whether batch signing, off-chain signing and forced-blind requests count as attempts. Forced blind already has its own one-attempt-per-unlock budget (#329) and should be left out.

**4. Two escalations in the research's first draft are dead ends, recorded so they are not proposed again.** "Require scroll to the end after three repeats" adds nothing: scroll-to-end is already unconditional (`secure/src/ui/px/confirm_px.rs:57`). A hold-to-sign gesture contradicts the owner's 2026-09-22 gesture decision. If the owner later wants an escalation, the one the threat-model row already names is PIN re-entry on an error budget.

**5. Testing notes.**

- The window logic needs host tests with an injected tick. The research states that the tick does not advance on the QEMU build; I did not check that.
- `e2e-test` short-circuits the confirm dialog, so an end-to-end test can show that a page was built, not that a user was held by it.
- The logic must live in a workspace crate, as this issue says. Modules under `secure/src/nsc` and `secure/src/ui` are compiled out of the host test build, so tests placed there never run.

**Limits.** This layer makes a repeat visible; it does not prevent a user from approving it. A banner that says "repeat" can reassure wrongly if the first presentation was the malicious one, so the wording must not discourage re-reading. The research found no precedent in Trezor for this (the `ContinueOnErrors` flag it first cited is used only in backup flows). The pixel-UI image is already over its flash slot, which bounds any later screen work.

**6. A nonce-keyed identity for Safe transactions (from item CS-02 of the same research).**

This issue's comparator deliberately ignores nonce and gas, so it cannot see the case the Radiant write-up describes most directly: a second, different Safe transaction for a `(safe, nonce)` pair the user has already approved. The device has everything needed to key on it, because it recomputes the Safe transaction hash itself (`secure/src/tx/eip712/safe/mod.rs:505`, `compute_safe_tx_hash`).

- [ ] Record `(safe address, safe nonce, safeTxHash)` for each Safe approval the device releases.
- [ ] Flag "different transaction, same Safe and nonce" when a later request matches on the first two fields and differs on the third.
- [ ] Do not extend this to plain UserOps keyed on `(sender, nonce)`. A same-nonce re-sign is a routine fee bump or a bundler retry, and a warning that fires on routine events trains users to ignore it. The nonce-lane trick (a second payment presented as a retry on another nonce key) already has its own page, see `secure/src/tx/display/nonce_lane.rs:1`.

**7. Three rules for a ring that survives lock (point 1).**

- [ ] Key each entry on the signing wallet's address as well, and match only within the same wallet, or clear the ring whenever the unlocked wallet changes. A ring that survives lock would otherwise carry the real wallet's history into a session opened with the duress PIN, and a "different transaction, same nonce" page there would reveal that another wallet exists. That is the same deniability class as #863.
- [ ] Record at release, after the durable tally commit (the commit is at `secure/src/nsc/cmd_sign_userop.rs:2630`), not when the request arrives. Otherwise a declined dialog poisons the ring.
- [ ] State the residual in the design document: unplugging the device clears the ring, and a malicious request that arrives first is signed with no flag. By the research's reading of the Radiant write-ups, each signer's first signature there was already the malicious one.

A further point for the later friction-page decision (which this issue keeps separate): on pq1 a Safe approval is an on-chain `approveHash` UserOp, so each "retry" already costs a separately confirmed UserOp. That limits how much the ring adds for Safe flows and should be weighed before the page is wired.

<sub>**Provenance.** Security frontier research, 2026-10-11 (report items USB-08 and CS-02, section 10). Report priority P2 is a research rating for the delta over this issue, not an owner decision; this issue's own `priority:high` label governs the core. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
