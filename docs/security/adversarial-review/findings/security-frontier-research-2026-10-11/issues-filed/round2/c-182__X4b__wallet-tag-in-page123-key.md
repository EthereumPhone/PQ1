COMMENT_ON: 182
---
**A concrete proposal for this finding, and its link to #863, from the 2026-10-11 security frontier research (report item X4b). Line numbers are at master `c2fab970`.**

Still true at master: the page-123 key is computed from account, chain and slot only (`secure/src/offchain_state.rs:23`). The page-erase function is private (`secure/src/hw/flash.rs:1578`) and has two callers, compaction (`secure/src/hw/flash.rs:1736`) and a self-heal that refuses when live entries exist (`secure/src/hw/flash.rs:2015`, `secure/src/hw/flash.rs:2023`). No wipe path erases the page. Its doc comment mentions "a deliberate reset-to-factory flow" (`secure/src/hw/flash.rs:1573`) that does not exist.

**How far this reaches today.** On the locked ship profile a wiped device cannot be set up again (#168), and the gateway has no user wipe command, so "a different seed on the same device" happens only on bench boards, or later if recovery after a wipe is ever added. The effect is small even then: counting too much is the safe direction, and an inherited "registered" flag only yields signatures the wallet contract rejects. The reason to act is timing. The key format is free to change before launch. After launch, changing it means migrating live few-time counters.

**This is the same change as the first checkbox of #863** ("add a wallet discriminator to the page-123 key"). It should be made once, with the constraints below. The other two checkboxes of #863 (the duress wipe result and the CI build) are separate work.

- [ ] **Tag.** Derive a public wallet tag from account 0's `masterPkSeed`, which is one HMAC and one hash from the seed material and needs no key generation (`domain/src/lib.rs:598`). Do not use the CREATE2 salt: it needs the public root, which means a full key generation, and the cache of those is a 16-entry least-recently-used table (`secure/src/nsc/state.rs:332`) with no guarantee that account 0 is in it. Compute the tag once at unlock and keep it in secure state. The account index stays a separate input.
- [ ] **Switch all six call sites in one commit:** `secure/src/nsc/cmd_sign_userop.rs:2017`, `secure/src/nsc/cmd_sign_userop_batch.rs:2172`, `secure/src/nsc/cmd_sign_userop_forced.rs:1198`, `secure/src/nsc/cmd_sign_offchain.rs:263`, `secure/src/nsc/cmd_offchain_sync.rs:110`, `secure/src/nsc/cmd_offchain_status.rs:76`. Update the key-format tests (`secure/src/secure_crypto_glue_under_test/pure_tests.rs:773`).
- [ ] **Keep the distinct-slot cap global** (`secure/src/offchain_state.rs:64`). A cap per wallet would let several seeds together exceed what the page can hold and re-open the page-123 exhaustion brick. When the cap is hit, say so on the trusted display.
- [ ] **Keep page 123 on a lockout wipe and on a duress wipe**, as today. With the tag, the same seed restored on the same device finds its own counters again and a different seed sees none.
- [ ] **Write the policy down** in invariant 9 and correct the doc comment on the erase function.
- [ ] **Host test:** register a tuple under seed A, switch to seed B, assert the tuple is not registered.
- [ ] Bench boards need one page-123 erase after the change. Entries under the old key would otherwise still count toward the cap.

Later, and gated:

- [ ] **Decommission erase.** Erasing the page is a counter rollback, so it must be reachable only together with a verified wipe of both secure elements (#106, #123) and belongs with the receipt in #634. First boot requires the page to be blank (`secure/src/first_boot/mod.rs:201`), so any refurbish flow needs it anyway.

**Limits.** This does nothing when the same seed is restored on a second device, where counters start at zero (#89). Under the duress feature it removes the per-tuple leak in #863; the number of distinct slots in use is still shared between the two wallets and is a weaker sign. It adds no per-signature flash state: the record layout and the number of writes are unchanged, only the input to the 8-byte key changes. Not traced: what the unlocked state holds at each of the six call sites, so whether the tag can be computed at unlock without extra work is for the implementer to confirm. The research review of this item had one reviewer, not two. Nothing was run.

<sub>**Provenance.** Security frontier research, 2026-10-11 (report item X4b, section 12). Report priority P3 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
