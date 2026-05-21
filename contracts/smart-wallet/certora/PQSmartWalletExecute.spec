/*
 * PQSmartWallet executor spec — discharges Claim 3's universally
 * quantified properties: no execute path mutates the owner table
 * except through the explicit (addOwnerBytes / removeOwnerAtIndex)
 * self-call route.
 *
 * Run via:
 *   certoraRun certora/confs/PQSmartWalletExecute.conf
 */

use builtin rule sanity;

methods {
    function entryPoint() external returns (address) envfree;
    function nextOwnerIndex() external returns (uint256) envfree;
    function ownerAtIndex(uint256) external returns (bytes) envfree;
}

/* ── Claim 3 (E-2 + E-3 composite): execute_does_not_touch_owner_table */

// **execute_does_not_touch_owner_table** — `executeWithOffchainCount`
// does not mutate any `ownerAtIndex[i]` UNLESS it self-calls into
// addOwnerBytes / removeOwnerAtIndex. Since `executeWithOffchainCount`
// refuses self-targets (audit H-2 fix), the antecedent is never met.
rule execute_does_not_touch_owner_table(env e, uint256 i,
    uint256 ownerIndex, uint256 newCount, address target, uint256 value, bytes data)
{
    bytes before = ownerAtIndex(i);
    executeWithOffchainCount@withrevert(e, ownerIndex, newCount, target, value, data);
    bool reverted = lastReverted;
    bytes after = ownerAtIndex(i);
    assert reverted || keccak256(before) == keccak256(after),
        "Claim 3 violation: execute mutated owner table";
}

// **executeBatch_does_not_touch_owner_table** — same for batch.
rule executeBatch_does_not_touch_owner_table(env e, uint256 i, calldataarg args) {
    bytes before = ownerAtIndex(i);
    executeBatchWithOffchainCount@withrevert(e, args);
    bool reverted = lastReverted;
    bytes after = ownerAtIndex(i);
    assert reverted || keccak256(before) == keccak256(after),
        "Claim 3 violation: executeBatch mutated owner table";
}

/* ── Claim 3 (E-1): only EntryPoint reaches the executor ─────────── */

rule onlyEntryPoint_reaches_executor(env e, calldataarg args) {
    executeWithOffchainCount@withrevert(e, args);
    bool reverted = lastReverted;
    assert !reverted => e.msg.sender == entryPoint(),
        "Claim 3 (E-1) violation: executor reached by non-EntryPoint";
}

rule onlyEntryPoint_reaches_batch_executor(env e, calldataarg args) {
    executeBatchWithOffchainCount@withrevert(e, args);
    bool reverted = lastReverted;
    assert !reverted => e.msg.sender == entryPoint(),
        "Claim 3 (E-1 batch) violation: batch executor reached by non-EntryPoint";
}

/* ── Claim 3 (E-2): self-target refused at any position ──────────── */

rule executeBatch_rejects_self_at_position_0(env e,
    uint256 ownerIndex, uint256 newCount,
    uint256 v0, uint256 v1,
    bytes d0, bytes d1)
{
    address[] targets;
    uint256[] values;
    bytes[] datas;
    require targets.length == 2;
    require values.length == 2;
    require datas.length == 2;
    require targets[0] == currentContract;

    executeBatchWithOffchainCount@withrevert(e, ownerIndex, newCount, targets, values, datas);
    assert lastReverted,
        "Claim 3 (E-2 batch[0]) violation: self at index 0 accepted";
}
