COMMENT_ON: 304
---
**The Rust verifier is the missing leg of the mutant-corpus differential, and it is the one the bootloader links (2026-10-11 security frontier research, item X9a).**

Why this has a deadline: after write protection plus RDP-2 the bootloader's signature verifier cannot be patched. It is `sphincs_c10::verify`, reached through `fw-manifest/src/lib.rs:524`, with one call site in the bootloader (`fsbl/src/main.rs:345`). This parameter set has no official known-answer tests and one active user, and the project declined a second algorithm (invariant 5). Agreement between independent implementations of the one spec is therefore the main evidence that the verifier is right, and it should be complete before the freeze.

State at master:

- The committed corpus `contracts/smart-wallet/test/c10_mutant_corpus.json` has 246 entries: 4 that must be accepted and 242 that must be rejected (I counted). It is replayed through the Yul verifier (`contracts/smart-wallet/test/SPHINCsC10AsmMutantCorpus.t.sol:58`) and through the Lean spec (`contracts/verification/lean/MutantMain.lean:126`). **No Rust file reads it.** A search for the file name finds only the Solidity test, the Lean runner and the Python generator. Nobody has run the corpus through the Rust verifier, so whether it agrees on all 246 is not known.
- Both existing legs tolerate a shrunken corpus. The Solidity test requires `entries.length >= 240`. The Lean runner fails only below 240.
- The corpus is thin exactly where the two bespoke checks are. The 242 rejects are mutations of valid signatures under one key pair: 102 byte flips, 102 bit flips, 16 tail flips, 8 zeroed regions, 8 count flips, 6 others. The research's reviewer points out that such mutants break a hash chain, so a verifier with the forced-zero check (`sphincs-c10/src/hypertree.rs:393`) or the target-sum check (`sphincs-c10/src/wots.rs:183`) deleted would still agree on all of them. I did not test that claim.
- Negatives aimed at those two checks do exist. The 12-vector KAT file carries two near-miss signatures, one per check. The Solidity KAT test loads all 12 (`contracts/smart-wallet/test/SPHINCsC10Asm.t.sol:230`) and asserts each verdict against `expectValid` (`contracts/smart-wallet/test/SPHINCsC10Asm.t.sol:244`), and the Lean vector file lists both (`contracts/verification/lean/SphincsCVerify/KatVectors.lean:59`). On the Rust side, the test that proves each near-miss is rejected by its one check alone is feature-gated (`sphincs-c10/tests/near_miss_validate.rs:11`) and runs in no CI suite (#722; the 2026-09-22 comment there records a manual green run).
- `make mutants` exists but covers two other crates by default (`Makefile:4745`).

Proposed additions to this issue:

- [ ] A default-feature test in `sphincs-c10/tests`, so the existing CI step (`.github/workflows/ci.yml:226`) runs it, that replays the committed corpus through `sphincs_c10::verify` and asserts exactly 246 entries, 4 accepted and 242 rejected, each matching `expectValid`. The same for the 12 KAT vectors.
- [ ] Tighten the two `240` thresholds to equality with the committed count.
- [ ] Enrol `near_miss_validate` per pull request (#722) and name it in the freeze checklist: near-miss vectors for both checks are rejected by the unmodified verifier.
- [ ] Run `cargo mutants` scoped to the verify path of `sphincs-c10` and to `verify_signature` in `fw-manifest`, and record any surviving mutant in the two checks. This is what shows whether the corpus is adequate.
- [ ] Record the tree hashes of `sphincs-c10` and `fw-manifest` for the bootloader build that gets frozen, next to the green run.
- [ ] Write the scope sentence down: this is a corpus-level comparison of implementations of one spec. It cannot see a flaw in the scheme or its parameters, and it does not replace the declined second algorithm.

**Host tests and CI only. It has to be green before the bootloader is frozen.**

Limits: fault-injection coverage of the same compares is a separate gap (#865, item 2). None of this exercises the hardware SHA-256 path the bootloader uses by default. The evidence for that path is the bootloader's own boot-time known-answer test (`fsbl/src/hash.rs:65`, a single block) and the hardware-SHA bootloader boot recorded in the 2026-09-28 comment on #742. I did not run any of the three legs.

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item X9a, section 12). Report priority P2 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. One correction to the report: it says the Yul side has no near-miss vectors; at master the Solidity KAT test and the Lean vector file both carry the two near-miss vectors. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
