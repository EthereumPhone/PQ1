TITLE: Document and test pq1 as a required owner of a k-of-n Safe on the shipped approveHash route: threat-model row, version matrix, real-Safe test
LABELS: enhancement,priority:medium,surface:clear-signing,surface:docs,surface:contracts,source:frontier-research-2026-10
---
## Summary

Every hardening item on this project protects one device. One compromised or coerced pq1 still moves everything its wallet holds. The threat model says multi-party approval is the only architectural answer to that and that pq1 does not ship it. The second half is out of date in one respect: the firmware already lets the pq1 wallet act as an owner of a Safe multisig, approving a Safe transaction with an ordinary on-chain UserOp (an ERC-4337 user operation) that the device decodes and shows. No firmware or contract change is needed. What is missing is the written statement that this is a supported custody setup, the conditions under which it actually protects anything, and a test that runs the route against real Safe bytecode. The same documents also need to say that the other route, an off-chain co-signature (an EIP-1271 contract signature), is not supported, because one doc currently endorses a blind version of it (RAW32, where the device signs a bare 32-byte hash). No issue covers the topology (searched for Safe owner, co-signer, multisig, approveHash, custody, Transaction Service).

## What the code does today

- `secure/src/nsc/cmd_sign_userop.rs:1219`: a UserOp whose inner call is `approveHash(bytes32)` is refused unless a verified Safe trailer is attached, so the device always decodes the Safe transaction behind the hash.
- `contracts/smart-wallet/src/PQSmartWallet.sol:255`: the wallet makes the call itself, so the Safe sees the wallet as `msg.sender` and no signature adapter is needed. `contracts/smart-wallet/src/PQSmartWallet.sol:246` restricts the entry to the EntryPoint.
- `secure/src/nsc/cmd_sign_userop.rs:2630`: the signature path commits the UserOp count at sign time, so the limit on unbacked off-chain signatures never applies to this route.
- `proto/src/lib.rs:1804`: the batch (multiSend) allowlist holds four MultiSendCallOnly deployments, including Safe v1.5.0. The research was written when it held three and v1.5.0 batches were refused; that changed on master.
- `secure/src/tx/eip712/safe/exec_decode.rs:7`: the second on-chain route, where the wallet is the sender of `execTransaction`, decodes from calldata that carries every field except the Safe nonce.
- `docs/companion/safe-multisig-clear-sign.md:276` says the wallet "can be a fully PQ Safe owner today". The document has no guidance on thresholds, on the second signer, or on which failures the setup covers. `docs/companion/safe-multisig-clear-sign.md:365` still says "three pinned" deployments.
- `docs/security/threat-model.md:530` and `docs/security/HARDENING.md:518` say multi-party approval is the only fix for coercion and that it is not shipped.
- `docs/security/threat-model.md:432` says the duress PIN is "Not currently implemented", while `secure/Cargo.toml:452` defines the feature (#636).
- No Foundry test runs the wallet as an owner of Safe bytecode: a search of `contracts/smart-wallet/src`, `test` and `script` for approveHash, checkNSignatures and execTransaction finds nothing.
- Off-chain route: `docs/companion/companion-safe-tx-integration.md:388` says a Safe `signMessage` flow "works as a `RAW32` off-chain sig" today. `docs/feature-roadmap-research-2026-06.md:154` says Safe needs a legacy-signature adapter and `docs/feature-roadmap-research-2026-06.md:155` and `docs/feature-roadmap-research-2026-06.md:238` call for a firmware carve-out from the off-chain gap limit. `CMD_OFFCHAIN_SYNC` (`proto/src/lib.rs:525`) already provides a confirmed reconcile, so the carve-out text is obsolete.

## What is already tracked elsewhere

- #332 covers an open review item on the `execTransaction`-sender route. That is one reason to recommend `approveHash` as the supported route.
- #381 covers whether blind RAW32 signing ships. It is the real fence against a Safe transaction hash being signed blind off-chain; a doc sentence binds only honest companions.
- #179 covers the off-chain gap limit being resettable. It should be settled before anyone designs an off-chain co-signer reconcile. No carve-out is proposed here.
- #636 covers the duress PIN not being in the ship feature set. #680 covers fuzzing of the Safe decode. #486 covers vendor-key compromise, which this topology does not address.
- So this issue is only about the topology statement, its conditions, the doc corrections and the test.

## Proposed work

- [ ] Add a "custody topology" section to `docs/companion/safe-multisig-clear-sign.md`. Recommend `approveHash` as the supported route. Describe the `execTransaction`-sender route as secondary: it shows no Safe nonce and has the open item in #332.
- [ ] State the version matrix in that section: single-call Safe transactions on Safe 1.3.0, 1.4.1 and 1.5.0 (the research found the transaction and domain type hashes identical across the three tagged sources), and batches only through the four allowlisted MultiSendCallOnly deployments. Correct "three pinned" at `docs/companion/safe-multisig-clear-sign.md:365`.
- [ ] Add a threat-model row and amend `docs/security/threat-model.md:530`, `docs/security/HARDENING.md:518` and `docs/STATUS.md`. The row must carry its conditions, or it overclaims:
  - pq1's approval is required in every quorum. If other owners can reach the threshold alone, both the post-quantum property and the on-device decoding are lost.
  - The second signer also decodes the Safe transaction. A second device that signs blind recreates the Radiant and Bybit condition.
  - The funds sit in the Safe. The wallet's own balance stays single-device.
  - `approveHash` cannot be withdrawn on-chain until that Safe nonce is consumed. A mistaken or coerced approval can only be defused by another quorum transaction that uses the nonce.
  - The device cannot see the Safe's threshold, owner set, modules or guard, and cannot tell a real Safe from a look-alike at that address. The user has to check the setup independently, and again after any owner or threshold change.
  - Not covered by two pq1 devices: a vendor firmware-key compromise, a decoder bug common to both, a companion or web UI shared by both signers. A second signer from another vendor removes those but is a classical key.
  - A 2-of-2 has no redundancy. Losing one device freezes the funds.
- [ ] While editing that table, change the duress sentence at `docs/security/threat-model.md:432` to "implemented, not in the ship feature set, see #636". Whether it ships is #636's decision and is not restated here.
- [ ] State in the same docs that the off-chain EIP-1271 Safe co-signature route is deferred. Replace the endorsement at `docs/companion/companion-safe-tx-integration.md:388` with "MUST NOT submit a Safe transaction or Safe message hash as RAW32", and name #381 as the control.
- [ ] Correct `docs/feature-roadmap-research-2026-06.md:154`, `docs/feature-roadmap-research-2026-06.md:155` and `docs/feature-roadmap-research-2026-06.md:238`: by the research's read of the tagged Safe sources, Safe 1.5.0 calls `isValidSignature(bytes32,bytes)` (magic `0x1626ba7e`) and only 1.3.0 and 1.4.1 use the legacy form (`0x20c13b0b`), for which an adapter must hash the data before forwarding; and no gap carve-out is needed.
- [ ] Add a Foundry test: a Safe with a `PQSmartWallet` owner, `approveHash` sent through the existing EntryPoint harness (`PQSmartWalletRealSig.t.sol` or `PQMultiOpBundle.t.sol`, since the wallet entry requires the EntryPoint as caller), then `execTransaction` with the pre-approved signature type, plus a negative case where the threshold is not met without the pq1 owner. Use `vm.etch` with the canonical deployed Safe runtime bytecode as fixtures. Do not add the Safe sources as a library: by the research's assessment, compiling them under this repo's compiler settings does not give the deployed bytecode, and the pinned-codehash tests are sensitive to the library set.

## What it needs

Documentation and a contract test. No firmware, no board change. A companion-side Safe Transaction Service client is a separate, larger deliverable in another repository and is not part of this issue; the research flagged a possible blocker there that it did not check (the service authenticates a proposal with an owner or delegate signature, which for a contract owner is the off-chain route).

## Limits

- Nobody ran the Foundry test. "Works against real Safe bytecode" rests on reading the firmware and the tagged Safe sources (the research read `Safe.sol` at 1.3.0, 1.4.1 and 1.5.0; this draft did not re-fetch them).
- Each approval is an on-chain UserOp: it costs gas, several seconds of signing and one use of the slot key's signature budget.
- Which Safe versions are deployed on pq1's target chains was not checked.
- The Ledger Enterprise Multisig precedent below was not re-fetched.

## Related

#332, #381, #179, #636, #680, #486, #384, #89. Public sources: [Safe signature documentation](https://docs.safe.global/advanced/smart-account-signatures), [Safe.sol v1.5.0](https://raw.githubusercontent.com/safe-global/safe-smart-account/v1.5.0/contracts/Safe.sol), [Safe.sol v1.4.1](https://raw.githubusercontent.com/safe-global/safe-smart-account/v1.4.1/contracts/Safe.sol), [Ledger Enterprise Multisig](https://www.ledger.com/blog-enterprise-multisig-new-era).

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report items X6a and X6b, section 12). Report priority P2 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
