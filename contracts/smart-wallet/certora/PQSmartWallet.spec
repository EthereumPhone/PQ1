/*
 * PQSmartWallet Certora spec — discharges the cross-method
 * surface of `solidityWallet_compiles_correctly` (A3.2) for Claims
 * 1, 2, and 3 universally-quantified-over-methods properties.
 *
 * Run via:
 *   certoraRun certora/confs/PQSmartWallet.conf
 */

use builtin rule sanity;

methods {
    function entryPoint() external returns (address) envfree;
    function c10Verifier() external returns (address) envfree;
    function nextOwnerIndex() external returns (uint256) envfree;
    function ownerAtIndex(uint256) external returns (bytes) envfree;
    function bootstrapUses() external returns (uint256) envfree;
    function slotUses(uint256) external returns (uint256) envfree;
    function offchainSigCount(uint256) external returns (uint256) envfree;
    function MAX_BOOTSTRAP_USES() external returns (uint256) envfree;
    function MAX_SLOT_USES() external returns (uint256) envfree;
}

/* ── Claim 1: validateUserOp only callable by EntryPoint ─────────── */

rule validateUserOp_only_entrypoint(env e, calldataarg args) {
    bool senderIsEntryPoint = e.msg.sender == entryPoint();
    validateUserOp@withrevert(e, args);
    bool reverted = lastReverted;
    assert !reverted => senderIsEntryPoint,
        "Claim 1 violation: validateUserOp accepted non-EntryPoint caller";
}

/* ── Claim 2: addOwnerBytes / removeOwnerAtIndex only via self-call */

rule addOwnerBytes_only_self(env e, bytes newOwner) {
    addOwnerBytes@withrevert(e, newOwner);
    bool reverted = lastReverted;
    assert !reverted => e.msg.sender == currentContract,
        "Claim 2 violation: addOwnerBytes accepted non-self caller";
}

rule removeOwnerAtIndex_only_self(env e, uint256 i, bytes owner) {
    removeOwnerAtIndex@withrevert(e, i, owner);
    bool reverted = lastReverted;
    assert !reverted => e.msg.sender == currentContract,
        "Claim 2 violation: removeOwnerAtIndex accepted non-self caller";
}

/* ── Claim 3: execute*WithOffchainCount only callable by EntryPoint */

rule execute_only_entrypoint(env e, calldataarg args) {
    executeWithOffchainCount@withrevert(e, args);
    bool reverted = lastReverted;
    assert !reverted => e.msg.sender == entryPoint(),
        "Claim 3 violation: executeWithOffchainCount accepted non-EntryPoint caller";
}

rule executeBatch_only_entrypoint(env e, calldataarg args) {
    executeBatchWithOffchainCount@withrevert(e, args);
    bool reverted = lastReverted;
    assert !reverted => e.msg.sender == entryPoint(),
        "Claim 3 violation: executeBatchWithOffchainCount accepted non-EntryPoint caller";
}

/* ── Claim 3 (E-2): self-target refused ──────────────────────────── */

rule execute_rejects_self_target(env e, uint256 ownerIndex, uint256 newCount, uint256 value, bytes data) {
    executeWithOffchainCount@withrevert(e, ownerIndex, newCount, currentContract, value, data);
    bool reverted = lastReverted;
    assert reverted,
        "Claim 3 (E-2) violation: self-target accepted in executeWithOffchainCount";
}

/* ── Immutability: entryPoint and c10Verifier are immutable ──────── */

rule entryPoint_immutable(env e, method f) {
    address before = entryPoint();
    calldataarg args;
    f(e, args);
    address after = entryPoint();
    assert before == after, "Claim 2 violation: entryPoint changed (proxy storage)";
}

rule c10Verifier_immutable(env e, method f) {
    address before = c10Verifier();
    calldataarg args;
    f(e, args);
    address after = c10Verifier();
    assert before == after, "Claim 2 violation: c10Verifier changed";
}
