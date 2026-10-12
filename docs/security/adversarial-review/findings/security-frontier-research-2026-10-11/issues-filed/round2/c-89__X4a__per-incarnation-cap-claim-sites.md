COMMENT_ON: 89
---
**The quantification this issue's open checkbox asks for, widened from torn resets to a second device. From the 2026-10-11 security frontier research (item X4a) and its independent review. Line numbers are at master `c2fab970`. This is documentation and proof-statement work; no firmware change is proposed.**

**What the code enforces.** The slot cap is checked against tallies kept in this device's flash page 123: `aa/src/offchain_gate.rs:166`, called from `secure/src/nsc/cmd_sign_userop.rs:2089`. One code comment states the scope correctly: the tally bounds total slot-key signatures "per device incarnation" (`secure/src/hw/flash.rs:1459`). No document repeats that qualifier.

**So the bound per key is R x 65,536, not 65,536,** where R is the number of page-123 states that have ever started from zero for that key. The generic multi-target floor then falls as 96 - 2*log2(R) bits: 94 bits at R = 2. This is the same shape as the documented caveat for the bootstrap key across C chains.

**What counts towards R.** The review corrected the research's first wording here.

- A second physical unit that holds the same seed (a replacement or a clone).
- A torn page-123 compaction, which is this issue's original case.
- An erase of page 123 from outside before the device is locked (the bench `make factory-reset` target, which wipes pages 123 to 127: `Makefile:1256`).
- Not a wipe and restore on the same unit. No wipe path erases page 123: `erase_offchain_page` (`secure/src/hw/flash.rs:1578`) has two callers, the compaction (`secure/src/hw/flash.rs:1736`) and a self-heal that runs only when the page holds no live entries (`secure/src/hw/flash.rs:2023`). I also read the other erase helpers in that file: they target the firmware slots, the manifest and boot-state pages and pages 124 to 126, and none of their callers passes page 123. The page keys do not depend on the seed (`secure/src/offchain_state.rs:23`, #182), so a wallet restored on the same unit inherits its counters.

**What escapes the on-chain count.** Off-chain EIP-1271 signatures, and Type-2 signatures that were withheld or never passed validation. A UserOp whose execution reverts is counted on-chain, because the counter is bumped during validation (`contracts/smart-wallet/src/PQSmartWallet.sol:515`). The comment at `secure/src/hw/flash.rs:1453` ("or that reverted on-chain") is loose on this point.

**Nothing bounds R.** The limiter that exists is one PIN unlock and one physical confirm per signature. The documents should say that, not that R is small.

**Claim sites that say more than the code enforces**

- [ ] `contracts/verification/lean/SphincsCVerify/Crypto/Quantitative.lean:155` says the combined cap "keeps the per-key signing count `q` below `MAX_SLOT_USES`". It holds per incarnation. The theorem at `contracts/verification/lean/SphincsCVerify/Crypto/Quantitative.lean:166` takes `q ≤ MaxSlotUses` as a bare premise; qualify it the same way.
- [ ] Add a theorem that bounds the generic `(q + q²)` term at `q ≤ R · MaxSlotUses`, with R an explicit premise that nothing enforces. Do not copy the shape of the bootstrap cross-chain theorem (`contracts/verification/lean/SphincsCVerify/Crypto/Quantitative.lean:219`): it bounds only the linear term. One lemma instantiated for both C and R would be better. Re-run `verify-ledger-consistency` and `verify-proof-mutation` after the change.
- [ ] `CLAUDE.md:10` says "65,536 is a true per-key cap". Change it to per incarnation, and add the same qualifier to invariant 9.
- [ ] `docs/security/threat-model.md`: add a new row for the second-device and clone residual. Do not rewrite the row at `docs/security/threat-model.md:359`; it is about the unregistered-slot gate (annotate it separately with #180).
- [ ] `docs/companion/companion-app-integration.md:908` (recovery on a new device): add a step. Retire or wipe the old unit. After restore, call the sync command with the on-chain count for each active slot. State that the old unit's unpublished off-chain signatures and withheld UserOp signatures cannot be recovered.
- [ ] `docs/verification/fv-pilot-combined-budget-lifetime-2026-07-17.md:81` says bootstrap re-registration bounds the number of resets. #180 shows re-registration needs no Type-1 rotation, so that bound does not hold. Correct it in the same change.
- [ ] `docs/security/adversarial-review/lifecycle-persistent-state-adversarial-review.md:57` (row LC8): re-grade it as an accepted residual with the R x 65,536 figure.
- [ ] The gateway table in `CLAUDE.md` has no row for command 18 (`proto/src/lib.rs:525`).

**Not proposed here.** Letting the sync command also raise the device's UserOp-signature tally to the on-chain count. It is a wire change (the sync input is fixed at 21 bytes, `proto/src/lib.rs:1466`), it needs a second value on the confirm screen, it costs secure-slot flash, and it helps only when the companion is honest. The review split it out as a separate low-priority firmware item. No draft exists for it.

**Considered and rejected.** Forcing a Type-1 rotation after a restore. The re-derived slot key equals the key already on-chain, so the add reverts, and remove-then-add reopens #131.

**Precedent.** None in Trezor or Ledger; neither ships a few-time signer. [NIST SP 800-208](https://csrc.nist.gov/pubs/sp/800/208/final) is a loose pointer only: the research read its abstract and did not check its clauses on key cloning.

Related: #179, #180, #182, #131.

<sub>**Provenance.** Security frontier research, 2026-10-11 (report item X4a, section 12). Report priority P2 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon, and no Lean proof was built. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
