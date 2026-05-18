# AUDIT_2026-05-18 — Cross-Check Report

**Date:** 2026-05-18
**Reviewer:** independent cross-check on top of the colleague's fix
commit `aa537ad`.
**Purpose:** verify each High finding's fix matches the audit's recommended
remediation AND that the existing regression tests reproduce the original
attacker probes faithfully.

---

## Method

For each High finding:
1. Open the audit doc's "What's wrong" section and copy the attacker
   reproduction probe.
2. Open the fix source and compare against the audit's "Suggested fix"
   section.
3. Open the regression test that landed alongside the fix; verify it
   exercises the same attacker probe.
4. Add a sibling-angle test if the existing suite leaves an obvious gap.

`forge test` itself was not run by this cross-check (foundry not in the
sandbox's PATH; pipe-installer for `foundryup` is blocked by the
auto-mode classifier). User must run `make -C contracts/smart-wallet`
or `forge test` to confirm green build. The cross-check below is a
code-review pass; the test bodies are mechanically inspected against
the audit doc.

---

## H-1 — Factory traps `msg.value` on already-deployed wallets

### Audit's attacker probe (AUDIT §H-1 lines 96-110)
- Deploy via `createAccount(... no value ...)`.
- Call `createAccount{value: 1 ether}(... same params ...)` — expects
  the second call to early-return and strand the ETH on the factory.

### Fix in `PQSmartWalletFactory.sol:85-102`
```solidity
bytes32 salt = _salt(masterPkSeed, masterPkRoot);
(bool alreadyDeployed, address deployed) =
    LibClone.createDeterministicERC1967(msg.value, implementation, salt);
account = PQSmartWallet(payable(deployed));
if (alreadyDeployed) {
    return account;   // Solady already forwarded msg.value
}
// ... squat defence ...
```

**Matches audit's suggested fix verbatim.** Solady's
`createDeterministicERC1967` Yul: when the proxy is already deployed,
it calls `call(gas(), instance, value, ...)` so the ETH is forwarded
to the existing wallet rather than stranded.

### Regression tests
- `test_audit_h1_factoryForwardsValueWhenAlreadyDeployed` (line 952) —
  literal audit probe. Asserts `address(w).balance == 1 ether` and
  `factory.balance == 0` after two deploys, second with msg.value.
- `test_audit_h1_factoryAlreadyDeployedSkipsSigCheck` (line 969) —
  confirms the audit's corner case: with the squat-check now AFTER
  the create call, an `alreadyDeployed == true` path must succeed
  even when the verifier is flipped to reject (`c10.setValid(false)`).
  Otherwise the second deploy would block legitimate top-ups.

**Verdict: covered.** Both audit-recommended tests are present.

---

## H-2 — Slot keys can self-call to register new owners

### Audit's attacker probe (AUDIT §H-2 lines 200-230)
- Slot-1 holder signs a UserOp whose calldata is
  `executeWithOffchainCount(1, 0, address(thisWallet), 0, addOwnerBytesCall)`.
- Expected pre-fix: `validateUserOp` accepts (sig OK, selector slot-
  allowed), execute self-calls `addOwnerBytes` with
  `msg.sender == address(this)` → NotFromSelf passes → new owner
  installed at index 2.

### Fix in `PQSmartWallet.sol:215-266`
```solidity
function executeWithOffchainCount(...) {
    if (msg.sender != address(_entryPoint)) revert NotFromEntryPoint();
    _consumeValidatedOwnerIndex(ownerIndex);  // H-3
    if (target == address(this)) revert SelfCallForbidden();  // H-2
    ...
}
function executeBatchWithOffchainCount(...) {
    ...
    for (uint256 i; i < n; ++i) {
        if (targets[i] == address(this)) revert SelfCallForbidden();
        ...
    }
}
```

**Matches audit's "Option A" (recommended).** New `error
SelfCallForbidden()` declared at line 111. Both execute paths
check; batch checks per-iteration so a self-target in any array
position reverts (not only position 0).

### Regression tests
- `test_audit_h2_executeWithOffchainCount_rejectsSelfTarget` (line
  990) — literal audit probe. Validates the slot-1 wrapper first (sig
  passes by design; the role-split moves to execute time), then
  asserts execute reverts `SelfCallForbidden` and `nextOwnerIndex()`
  is unchanged.
- `test_audit_h2_executeBatch_rejectsSelfTargetAnywhereInArray` (line
  1020) — sibling angle: self-target embedded in the MIDDLE of a
  3-element batch (`tos[1] = address(w)`), confirms the per-iteration
  check fires before any of the surrounding calls execute. Worth
  having: a naive fix that only checked the first or last element
  would pass the simpler test but fail this one.

**Sibling indirect-callback angle considered:** an attacker could try
`target = helperContract` where `helperContract.callbackIntoWallet()`
re-enters `wallet.addOwnerBytes`. This is blocked one layer up:
`addOwnerBytes` requires `msg.sender == address(this)`, but the inner
call from `helperContract` has `msg.sender == helperContract`. No new
test needed — this is the existing `addOwnerBytes` NotFromSelf guard,
which is independent of H-2.

**Verdict: covered.**

---

## H-3 — Cross-slot `offchainSigCount` poisoning via mismatched ownerIndex

### Audit's attacker probe (AUDIT §H-3 lines 348-376)
- Slot-1 holder signs a UserOp:
  - wrapper `ownerIndex = 1` (sig verifies against slot-1 pubkey)
  - calldata `executeWithOffchainCount(99, 65000, ...)`
- Expected pre-fix: validate accepts (sig OK against slot 1, bumps
  `slotUses[1]`); execute reads its OWN calldata `ownerIndex = 99`
  and writes `offchainSigCount[99] = 65000`. Slot 99 is dead-on-arrival
  when later registered, OR slot 1 grief'd slot 2's budget at cost
  1 attacker-sig.

### Fix in `PQSmartWallet.sol:268-284, 445-449`
```solidity
// In `_validateSignature` after sig verify + counter bump:
assembly ("memory-safe") {
    tstore(_TS_VALIDATED_OWNER_INDEX_PLUS_ONE, add(ownerIndex, 1))
}

// In `_consumeValidatedOwnerIndex` (called at top of execute fns):
uint256 expectedPlusOne;
assembly ("memory-safe") {
    expectedPlusOne := tload(_TS_VALIDATED_OWNER_INDEX_PLUS_ONE)
    tstore(_TS_VALIDATED_OWNER_INDEX_PLUS_ONE, 0)  // one-shot consume
}
if (expectedPlusOne == 0 || expectedPlusOne - 1 != ownerIndex) {
    revert OwnerIndexMismatch();
}
```

**Matches audit's suggested fix verbatim.** EIP-1153 transient
storage (`tstore`/`tload` on Solidity 0.8.24+; wallet is on 0.8.28).
`+1 / -1` shift so `0` reliably means "unset" (no preceding
validate). The `tstore(0)` happens BEFORE the comparison so the
token is consumed even on a mismatch — prevents a follow-up call
from re-using it.

### Regression tests
- `test_audit_h3_rejectsMismatchedOwnerIndex` (line 1058) — literal
  audit probe (wrapper=1, calldata=99).
- `test_audit_h3_acceptsMatchingOwnerIndex` (line 1085) — regression
  check that the parity gate doesn't block the legitimate
  wrapper=calldata case.
- `test_audit_h3_executeBatch_rejectsMismatchedOwnerIndex` (line
  1095) — same on the batch variant.
- `test_audit_h3_executeFailsIfCalledOutsideValidatedFlow` (line
  1120) — direct execute call with no preceding validate. The token
  is `0`, so the `expectedPlusOne == 0` guard fires.
- **NEW** `test_audit_h3_validateConsumedByPriorExecute` (sibling-
  angle test added by this cross-check, line 1131) — validate
  followed by TWO execute calls with identical parameters. The
  first execute succeeds; the second must revert because the
  transient token was consumed by the first execute's
  `_consumeValidatedOwnerIndex` (one-shot semantics). Confirms a
  replay attack across one validated bundle is blocked.

**Verdict: covered + one additional sibling angle.**

---

## Summary

| Finding | Fix in source | Audit-recommended fix? | Regression tests | New cross-check test |
|---|---|---|---|---|
| H-1 | `PQSmartWalletFactory.sol:85-102` | ✅ verbatim | 2 (forward-value + skip-sigcheck) | — |
| H-2 | `PQSmartWallet.sol:111, 224, 258` | ✅ Option A verbatim | 2 (single + batch-middle) | — |
| H-3 | `PQSmartWallet.sol:119, 268-284, 445-449` | ✅ verbatim (transient storage) | 4 (mismatch + match + batch + no-validate) | 1 (replay/one-shot consumption) |

All three High findings are correctly fixed with regression tests that
reproduce the original attacker probes. One additional sibling-angle
test added for H-3 (validate-consumed-by-prior-execute) to nail down
the one-shot transient semantics. Tests not run in this cross-check —
user should confirm with `forge test --match-test test_audit_` or
`make` from the repo root.

Out of scope (deliberately not cross-checked): M-1, M-2, L-1, L-2,
L-3, I-1, I-2, I-3. Their fixes are visible in the same commit and
appear to match the audit recommendations on a quick read, but the
user explicitly asked about the three High findings.
