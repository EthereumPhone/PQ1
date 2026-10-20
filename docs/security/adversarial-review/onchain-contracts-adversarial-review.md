# On-chain Solidity contracts adversarial-review playbook

**Purpose.** A reusable recipe + copy-paste **master prompt** for an adversarial code-review pass over PQSigner's on-chain Solidity — `PQSmartWallet.sol`, `PQSmartWalletFactory.sol`, `PQMultiOwnable.sol`, and `verifiers/SPHINCsC10Asm.sol`. This is a **Solidity code review distinct from the Lean `theft_free` proof**: the FV tree proves *no unauthorized fund movement given a correct signed digest*; this playbook hunts the Solidity-level failure classes that live *outside* that scope.

> **The honest headline: this surface is heavily covered.** Almost every Solidity failure class is already closed by the contract code (with a file:line), the Lean tree (`theft_free` + `Wallet/*.lean`), the codehash-freeze / bytecode-repro tests, or the Kontrol/Halmos symbolic proofs. So this playbook's job is **mostly to state what is already covered and cross-link it** — and to keep a bright light on the *three* items covered by **neither** forge nor FV.

**How this differs from the FV playbook + the bench red-team.** The [FV adversarial-review playbook](../../verification/fv-adversarial-review-playbook.md) attacks the *Lean proofs* for vacuity (is `theft_free` hollow?). **This playbook attacks the Solidity as code** — reentrancy, storage collision, dispatch confusion, upgrade paths — the EVM-level behaviors a Lean state-transition model doesn't drive concretely. The C10 verifier *math* is out of scope (that is the A3.1 bytecode bridge, FV surface #2). Cross-link the Lean/forge/Kontrol/Halmos gates; do not re-derive them.

> **Honesty note.** Every row's `Status` tags its existing coverage (`theft_free` / Lean / `codehash-freeze` / `forge` / `Kontrol` / `Halmos` / **NONE**). Only the **NONE** rows are live review targets. SOL6 (cross-slot `removeOwnerAtIndex`) is a genuine un-reviewed item promoted to a GitHub issue on `EthereumPhone/PQ1` (likely by-design — confirm in the threat model); SOL2 (EVM reentrancy) is mitigated-but-untested; SOL8 is an operational (not in-contract) assumption.
>
> **UPDATE 2026-10-20 (Trail of Bits audit freeze).** SOL6 and SOL9 are closed: `removeOwnerAtIndex` was deleted and the owner set is append-only (rows below). SOL8's deployment topology changed: the freeze set has new addresses, is not deployed yet, and the deploy scripts now refuse to broadcast unless the predicted factory and proxy init-code hash equal the firmware constants (`script/ProductionDeploy.sol`), with CI checking the same binding (`DeployedBytecodeReproCheck`, deploy profile). New surface to review: the legacy `isValidSignature(bytes,bytes)` entry and the token receiver hooks.

---

## Part A — The Solidity failure catalog (SOL1–SOL8)

| # | Failure mode | What it looks like | Status / existing coverage | Live target? |
|---|---|---|---|---|
| SOL1 | **"Validated X, executed Y" swap** | the executed call differs from the signed one | **DEFENDED.** `sphincsDigest` (`PQSmartWallet.sol:374-391`) folds `sha256(callData)`, `sha256(paymasterAndData)`, all gas fields, `entryPoint`, and `block.chainid` into the signed digest — target/value/data can't be substituted post-validation. Covered: `theft_free`, forge | ❌ closed |
| SOL2 | **EVM-level reentrancy of `execute*WithOffchainCount`** | a malicious `target` re-enters to mint value / replay a credit | **MITIGATED, UNTESTED.** EP-gate is the primary mitigation: every mutating entry point is `msg.sender == _entryPoint`-gated (`PQSmartWallet.sol:246,:271,:351,:360,:213`), so a malicious target cannot re-enter the wallet directly; the only channel is a nested `EntryPoint.handleOps`, which needs fresh valid sigs (v0.6 consumes the nonce at validation) — making the CEI note below a second line, not the first. CEI-clean: `_consumeValidatedCredit` (one-shot, EIP-1153 transient) runs *before* the external call (`:247`); `offchainSigCount` already advanced + monotonic; `receive()` state-free. The stated residual (re-entry consumes a co-bundled op's credit → sibling reverts) is **unreachable in v0.6** per the EP-gate. **But FV models the credit as one-shot at the state-transition level only — no concrete EVM reentrancy harness exists** | ⚠ **NONE (mitigated, no concrete test)** |
| SOL3 | **ERC-7201 storage collision** | the namespaced storage aliases ERC-1967 or itself | **DEFENDED.** Slot `keccak256(keccak256(ns)-1)&~0xff` (`PQMultiOwnable.sol:60-63`); mappings, no packed sub-word aliasing. Covered: `StorageSlotParity.t.sol:46/76`, Lean `StorageLayout.lean:79-97` | ❌ closed |
| SOL4 | **Cap off-by-one / bypass** | the monotonic cap is bypassable or miscounts | **DEFENDED at the function level; see SOL9 for the composed bypass.** `>=` pre-bump (validation) vs `>` post-bump (execution) — both correct, sum can't exceed cap (`PQSmartWallet.sol:453/479`, `PQMultiOwnable.sol:228/231`); bump only after C10 verify. No `reset*`/`increaseMax*`/`rotateMasterKeys` anywhere — but that is a *function-level* claim: the remove+re-add composition in SOL9 is a semantic reset with no such function. Covered: Lean `MultiOwnable.lean`, forge cap-exhaust + `PQBootstrapCapEvasion.t.sol`, Kontrol, Halmos | ❌ closed (function-level; composed case = SOL9) |
| SOL5 | **Type1/Type2 dispatch confusion** | a slot key calls `addOwnerBytes`, or a bootstrap key executes / signs off-chain | **DEFENDED.** Role-split on `ownerIndex` (`:449-482`): Type1 (0) may only `addOwnerBytes`, Type2 (≥1) only execute/remove (`_isSlotAllowedSelector:544`); bootstrap forbidden off-chain (`:630`); H-2 self-call block (`:248,:282`). Covered: forge `test_slotCannotCallAddOwner`/`test_bootstrapCannotCallExecute`, Lean | ❌ closed |
| SOL6 | **Cross-slot `removeOwnerAtIndex` not bound to the signing slot** | a slot key at index *i* removes an unrelated slot *j* | **✅ CLOSED 2026-10-20 by deleting `removeOwnerAtIndex` (#213, audit freeze).** No key can remove an owner; a slot-signed op carrying the old selector `0x89625b57` fails validation and dispatches nothing (`test_removedRemoveOwnerSelectorFailsValidation`, Halmos `check_removed_selector_does_not_dispatch` + `check_validate_rejects_removed_selector`, Kontrol `prove_removed_selector_does_not_dispatch`). Residual: no on-chain revocation (`contracts/smart-wallet/AUDIT_REVIEW_GOALS.md` §4). Historical text follows. **◑ DOCUMENTED + PINNED 2026-07-02 (availability, by-design; tighten-decision open).** Now covered by `test_sol6_crossSlotRemoveIsAcceptedByDesign` + a `threat-model.md` §8 design note.**Was:** UN-REVIEWED. The H-3 parity check (calldata first-arg == signed `ownerIndex`) is **deliberately skipped for the remove selector** (`:469-474`), so any slot key ≥1 can `removeOwnerAtIndex(j, owner_j)` for any *j*≥1 (`ownerAtIndex(j)` is a public getter). Impact: intra-wallet **availability**, not theft; bootstrap (0) is unremovable + can re-add. **`theft_free` silent** (no funds move); Lean covers index-0 only; no forge/Kontrol/Halmos test exercises cross-slot *authorization*. The code comment suggests it is intended — **confirm the threat model accepts "any slot can prune any slot"** | ✅ **CLOSED 2026-10-20 — function deleted** (was: ⚠ **NONE — promoted to an `EthereumPhone/PQ1` issue**) |
| SOL7 | **Proxy / ERC-1967 upgrade path** | an upgrade selector or delegatecall lets the impl be swapped | **DEFENDED.** No `delegatecall` in `execute*` (grep empty), no UUPS selector, nothing writes the ERC-1967 impl slot. Covered: Lean `UpgradeSafety.upgrade_path_unreachable:121`, forge `invariant_impl_slot_unchanged:190`. **One-line confirm worth keeping**: the proxy IS Solady's ERC-1967 (`LibClone`), so the guarantee rests on the impl exposing no upgrade selector | ❌ closed (confirm no impl upgrade selector) |
| SOL8 | **CREATE2 salt / cross-chain topology** | the same-address-every-chain property breaks, or a squat pre-empts a victim | **DEFENDED (with an operational caveat).** `_salt = sha256(masterPkSeed‖masterPkRoot)` (`Factory.sol:145`, fixed-width packed → no concat-collision); squat defense = bootstrap-key C10 sig over `addSlot0Digest` bound to `chainId` (`:104-112,142`); atomic init. Covered: forge squat/chain tests, Halmos `prove_createAccount_iff`, Kontrol, Lean `Factory.lean`. **Operational caveat (not in-contract)**: address determinism silently depends on identical factory+impl addresses cross-chain — asserted for Base by `DeployedBytecodeReproCheck.t.sol`, not enforceable in-contract | ⚠ operational assumption (not a code bug) |
| SOL9 | **Per-key few-time budget reset via remove + re-add** | `removeOwnerAtIndex(i, k)` then `addOwnerBytes(k)` reinstalls the same key at a fresh index with zeroed counters — a semantic cap reset with no `reset*` function | **✅ CLOSED 2026-10-20 (#131, audit freeze).** Removal is deleted, so the owner set is append-only and `_addOwnerAtIndex` refuses any key ever installed (`AlreadyOwner`): a key keeps one index and one set of counters for the wallet's life. Covered by Lean `reachable_key_installed_at_most_once` / `reachable_addOwner_refuses_installed_key` (assembled over `Reachable`, so the composition is covered), forge `test_installedKeyCanNeverBeInstalledAgain`, and the stateful `invariant_owner_set_append_only` with a re-install handler (0 accepted). Historical text follows. **CANDIDATE (2026-07-17 sweep, pre-adjudication; MEDIUM, source-verified).** `_removeOwnerAtIndex` deletes only `isOwner`/`ownerAtIndex` (`PQMultiOwnable.sol:192-193` — counters at the old index untouched, no tombstone); `_addOwner` installs at a fresh `nextOwnerIndex` (`:175-181`) whose `slotUses`/`offchainSigCount` are zero. The sequence is fully authorized (cross-slot remove works at cap per SOL6; bootstrap re-add is the documented recovery flow), repeatable up to the bootstrap cap. Invariant #7 ("caps monotonic, **unresettable**") is false at the *key* level — per-*index* counters are unresettable, per-*key* budgets are not — and the on-chain cap is the documented backstop for a rolled-back local counter (F3 page-123 residual). The Lean `no_reset_path` proof is per-method and structurally cannot see the composition (class vi: helper proved, composition unproven); `S-CAP-RESET` cites it as the no-reset evidence. Fixes (all alter codehash-frozen contracts → deliberate re-freeze): key counters by `keccak256(owner)`; or a removal-surviving `lifetimeUses[keccak(owner)]`; or permanent tombstone on ever-seen bytes (kills the re-add recovery — arguably correct few-time hygiene) | Forge PoC sketched: storage-poke `slotUses[1]=65536`, cross-slot remove, bootstrap re-add, assert fresh budget + a new `executeWithOffchainCount` validates | ✅ **CLOSED 2026-10-20 — removal deleted; key installed at most once** (was: ⚠ **NONE (no forge/FV coverage of the composition)**) |

**Read this catalog as the answer to "is there un-reviewed Solidity that could move funds or brick the wallet?"** The theft classes (SOL1/SOL4/SOL5/SOL7/SOL8) are closed by code + FV + tests. The genuinely un-reviewed residuals are **three, none of them fund-theft**: SOL2 (EVM reentrancy — mitigated by CEI + one-shot transient credit, but no concrete harness), SOL6 (cross-slot remove — availability, likely by-design), and SOL8's cross-chain deployment-topology assumption (operational, not in-contract). Everything else is affirmatively closed with a cited gate.

---

## Part B — The existing defenses (Layer 1)

1. **Forge suites** (`contracts/smart-wallet/test/`): `PQSmartWallet.t.sol` (functional + audit regressions H-1/2/3, L-1/2), `PQBootstrapCapEvasion.t.sol`, `PQMultiOpBundle.t.sol` (cross-index credit theft), `PQSmartWalletInvariants.t.sol` (stateful invariants), `StorageSlotParity.t.sol`, `PQSmartWalletRealSig.t.sol` (real C10 vectors).
2. **Codehash / bytecode gates**: `PinnedCodehashes.t.sol` + `DeployedBytecodeReproCheck.t.sol` (byte-for-byte repro of deployed Base bytecode) + `PinnedBytecodeImmutableLemma.t.sol` + `LeanSelectorParity.t.sol` + `SPHINCsC10AsmMutantCorpus.t.sol`.
3. **Lean `theft_free` + `Wallet/*.lean`**: `ValidateUserOp`, `Execute`, `CreditLedger`, `MultiOwnable`, `Factory`, `IsValidSignature`, `StorageLayout`, `UpgradeSafety`, `OffchainBinding`, `TxFlow`, `Invariants`. The A3.1 bridge (`Bridge/`) models the Yul verifier control-flow (explicitly *not* gas/revert-data/ABI-decoding).
4. **Kontrol / Halmos symbolic**: pointwise equivalence of `validateUserOp`/`execute*`/`addOwner`/`removeOwner`/`createAccount`/`isValidSignature` vs the Lean models + non-bypass/entrypoint-gating/credit-one-shot.
5. **The un-covered gaps** (the payload): SOL2 (no concrete reentrancy harness), SOL6 (no cross-slot authorization test), SOL8 (the deployment-topology assumption asserted only for Base).

---

## Part C — THE MASTER PROMPT

```
ROLE: You are an adversarial Solidity reviewer of PQSigner_OS's on-chain contracts. Your job
is to find a Solidity-level failure (reentrancy, storage collision, dispatch confusion, upgrade
path, authorization gap) that the Lean theft_free proof and the codehash-freeze tests do NOT
cover — NOT to re-verify the C10 math (that is the A3.1 bridge, out of scope). Default to "this
is un-reviewed until I confirm a forge/Lean/Kontrol/Halmos/codehash gate covers it." The value
here is the NONE rows: EVM reentrancy (mitigated, untested), cross-slot removeOwnerAtIndex, and
the cross-chain deployment-topology assumption.

TARGET (read first, in this order):
  - docs/security/adversarial-review/onchain-contracts-adversarial-review.md §A — SOL1–SOL8
    (with the existing-coverage tag per row).
  - contracts/smart-wallet/src/{PQSmartWallet,PQMultiOwnable,PQSmartWalletFactory}.sol.
  - contracts/smart-wallet/test/ — confirm which class each test actually covers.
  - contracts/verification/lean/SphincsCVerify/Wallet/*.lean — what theft_free/Lean covers.
SCOPE THIS RUN: {{e.g. "EVM reentrancy of execute*WithOffchainCount (SOL2)" | "cross-slot
  removeOwnerAtIndex authorization (SOL6)" | "the full role-split dispatch" | "verify every
  SOL row's cited gate actually covers what it claims"}}.

ATTACK PROTOCOL — walk EVERY SOL1–SOL8 mode; for each, either produce a PoC OR cite the exact
gate that closes it (and CONFIRM the gate covers the claim — a forge test named for X that
doesn't assert X is a hollow gate, report it):
  SOL1 validated-X-executed-Y · SOL2 EVM reentrancy · SOL3 ERC-7201 collision · SOL4 cap
  off-by-one · SOL5 Type1/Type2 dispatch · SOL6 cross-slot remove · SOL7 proxy/upgrade ·
  SOL8 CREATE2 salt / cross-chain topology.

For each candidate finding you MUST produce a FALSIFIABLE PoC, one of:
  - a forge reentrancy harness where a malicious target re-enters execute* and gains value or
    replays a credit (SOL2);
  - a signed op where slot i removes slot j with no i–j binding (SOL6) + a threat-model quote
    showing it's unexpected;
  - a storage-slot computation that aliases (SOL3) or an upgrade selector that swaps the impl (SOL7);
  - a gate whose name claims coverage its body doesn't provide (a hollow test).
  No PoC ⇒ list under "suspicions, unverified".

RULES:
  - Verify against the CURRENT tree; the C10 verifier math is OUT of scope (A3.1 bridge).
  - Distinguish theft (funds move) from availability (a slot pruned) from operational (a
    deployment assumption) — SOL6/SOL8 are not theft; label severity accordingly.
  - For each candidate: SOL-mode, file:line, PoC, provisional severity, stable
    candidate ID, and proposed fix (flag if it
    would change a codehash-frozen contract — that breaks the pin and needs a re-freeze).
    Do not assign a finding disposition.

OUTPUT — return an external candidate packet to the coordinator. Do not modify
the repository, write a canonical findings report, or update catalogue/status
fields. Include every candidate and the honest residual. The coordinator freezes
the raw packet and gives the complete union to the exact Partner-A/Partner-B
pair; only their symmetric cross-adjudication may assign dispositions. An
authorized maintainer records the adjudicated result afterward.

FILING — the coordinator files every kept adversarial-review candidate as a
GitHub issue on EthereumPhone/PQ1 (labels `finding`, `priority:*`, `surface:*`;
`ship-blocker` when the candidate gates production). The issue is the
actionable record; any report under findings/ remains the frozen evidence.
Phase-D merge-review outcomes are never filed as issues. Do not file issues
yourself unless the coordinator's brief says so.

MANDATORY HONEST RESIDUAL (the run is INVALID without it):
  1. "What I tried to break and COULDN'T" — per class, with the covering gate.
  2. "What I did NOT look at" — classes not walked, gates not confirmed to cover their claim.
  3. "PROVENANCE — did this pass RUN forge / kontrol / halmos, or read source + Lean only?"
  Never imply "the rest is fine."
```

**Running it as a swarm.** Use ≥3 independent discovery reviewers per scope
across two model backends. Quorum only corroborates/prioritizes discovery; it
does not set a disposition, and sub-quorum variants remain in the packet. Give
every candidate and origin variant to the exact Partner-A/Partner-B pair in
[`../../planning-and-review-workflow.md`](../../planning-and-review-workflow.md);
only their symmetric cross-adjudication may disposition it, with disagreement
preserved. A productive split: one reviewer writes the SOL2 reentrancy harness,
one attacks SOL6 authorization, and one audits whether each cited gate actually
covers its claim.

---

## Part D — Cadence + honest boundary

- **Per-PR touching a contract:** `forge test` + the codehash-freeze tests (a source change that alters bytecode must re-freeze the pin deliberately) + a scoped Part-C pass. Re-run Kontrol/Halmos if a proven function changed.
- **Per-milestone:** a fresh Part-C pass focused on the NONE items (SOL2, SOL6, SOL8-operational, SOL9); land the SOL2 reentrancy harness + a SOL6 authorization test + the SOL9 remove/re-add forge PoC to shrink the un-covered set.
- **The one-line gut check:** *for each Solidity failure class, is there a gate that turns red if it regresses — and does that gate actually assert the property, not just its name?* SOL2/SOL6 currently have no such gate.

**The boundary, stated on purpose.** This playbook can tell you that every fund-theft Solidity class is closed by a cited gate, and it names the three residuals covered by neither forge nor FV (SOL2/SOL6/SOL8). It **cannot** tell you the EVM reentrancy is truly safe without a concrete harness (SOL2), that the cross-slot remove is acceptable without a threat-model decision (SOL6), or that the cross-chain factory+impl addresses match in a future deployment (SOL8 — that is a deployment process, asserted only for Base). Those are the harness's, the threat-model owner's, and the deploy process's job.
