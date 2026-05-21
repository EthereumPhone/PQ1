/*
 * PQMultiOwnable Certora spec — discharges
 * `solidityMultiOwnable_compiles_correctly` (A3.4) and
 * Claim 2 (owner-set integrity & init atomicity) at the bytecode level.
 *
 * Run via:
 *   certoraRun certora/confs/PQMultiOwnable.conf
 *
 * Adapted from contracts/smart-wallet/reference/certora/specs/ERC4337Account.spec
 * (Coinbase Smart Wallet upstream), pruned to remove EOA / WebAuthn paths
 * that PQSmartWallet does not support.
 */

use builtin rule sanity;

methods {
    function nextOwnerIndex() external returns (uint256) envfree;
    function ownerAtIndex(uint256) external returns (bytes) envfree;
    function isOwnerBytes(bytes) external returns (bool) envfree;
    function bootstrapUses() external returns (uint256) envfree;
    function slotUses(uint256) external returns (uint256) envfree;
    function offchainSigCount(uint256) external returns (uint256) envfree;
    function ownerCount() external returns (uint256) envfree;
    function removedOwnersCount() external returns (uint256) envfree;
}

definition initialized() returns bool = nextOwnerIndex() > 0;

definition MAX_BOOTSTRAP_USES() returns uint256 = 65536;
definition MAX_SLOT_USES() returns uint256 = 65536;

/* ── Claim 2: Owner-set integrity ─────────────────────────────────── */

// **bootstrap_unremovable** — `removeOwnerAtIndex(0, _)` always reverts.
// Direct port of Lean theorem `cannot_remove_bootstrap` (I-4).
rule bootstrap_unremovable(env e, bytes ownerBytes) {
    removeOwnerAtIndex@withrevert(e, 0, ownerBytes);
    assert lastReverted, "Claim 2 violation: bootstrap (index 0) was removed";
}

// **cantInitTwice** — `initialize` cannot be called twice.
// Direct port of Lean `initialize_called_exactly_once`.
rule cantInitTwice(env e1, env e2, env e3, method f) filtered {
    f -> f.selector != sig:initialize(bytes, bytes).selector
} {
    bytes b1; bytes s01;
    bytes b2; bytes s02;
    initialize(e1, b1, s01);
    calldataarg args;
    f(e3, args);
    initialize@withrevert(e2, b2, s02);
    assert lastReverted, "Claim 2 violation: initialize accepted second call";
}

// **onlySelfCanChangeOwnerAtIndex** — for any non-view, non-initialize
// function, if `ownerAtIndex[i]` changes, msg.sender must be `currentContract`.
rule onlySelfCanChangeOwnerAtIndex(env e, method f) filtered {
    f -> !f.isView
        && f.selector != sig:initialize(bytes, bytes).selector
} {
    uint256 i;
    bytes before = ownerAtIndex(i);
    bool senderIsSelf = e.msg.sender == currentContract;

    require initialized();
    calldataarg args;
    f(e, args);

    bytes after = ownerAtIndex(i);
    assert keccak256(before) != keccak256(after) => senderIsSelf,
        "Claim 2 violation: owner mutated by non-self caller";
}

// **onlySelfCanChangeIsOwnerBytes** — dual of above for the isOwner map.
rule onlySelfCanChangeIsOwnerBytes(env e, method f) filtered {
    f -> !f.isView
        && f.selector != sig:initialize(bytes, bytes).selector
} {
    bytes account;
    bool before = isOwnerBytes(account);
    bool senderIsSelf = e.msg.sender == currentContract;

    require initialized();
    calldataarg args;
    f(e, args);

    bool after = isOwnerBytes(account);
    assert before != after => senderIsSelf,
        "Claim 2 violation: isOwnerBytes mutated by non-self caller";
}

/* ── Claim 2/3: Counter monotonicity ──────────────────────────────── */

// **bootstrapUses_only_increases** — across ALL methods, the counter
// never decreases.
rule bootstrapUses_only_increases(env e, method f) {
    uint256 before = bootstrapUses();
    calldataarg args;
    f(e, args);
    uint256 after = bootstrapUses();
    assert after >= before, "Claim 2 violation: bootstrapUses decreased";
}

// **slotUses_only_increases** — per-slot monotonic.
rule slotUses_only_increases(env e, method f, uint256 i) {
    uint256 before = slotUses(i);
    calldataarg args;
    f(e, args);
    uint256 after = slotUses(i);
    assert after >= before, "Claim 2 violation: slotUses[i] decreased";
}

// **offchainSigCount_only_increases** — per-slot monotonic.
rule offchainSigCount_only_increases(env e, method f, uint256 i) {
    uint256 before = offchainSigCount(i);
    calldataarg args;
    f(e, args);
    uint256 after = offchainSigCount(i);
    assert after >= before, "Claim 2 violation: offchainSigCount[i] decreased";
}

// **combined_cap_invariant** — `slotUses + offchainSigCount <= MAX_SLOT_USES`.
// Inductive invariant per slot.
invariant combined_cap_invariant(uint256 i)
    slotUses(i) + offchainSigCount(i) <= MAX_SLOT_USES();

// **bootstrapUses_capped** — bootstrap cap is never exceeded.
invariant bootstrapUses_capped()
    bootstrapUses() <= MAX_BOOTSTRAP_USES();

// **nextOwnerIndex_monotonic_growth** — owner-index counter only grows.
rule nextOwnerIndex_monotonic_growth(env e, method f) {
    uint256 before = nextOwnerIndex();
    calldataarg args;
    f(e, args);
    uint256 after = nextOwnerIndex();
    assert after >= before, "Claim 2 violation: nextOwnerIndex decreased";
}

// **no_owner_above_nextOwnerIndex** — ownerAtIndex[i] is empty for i >= nextOwnerIndex.
invariant no_owner_above_nextOwnerIndex(uint256 i)
    i >= nextOwnerIndex() && nextOwnerIndex() < max_uint256
      => ownerAtIndex(i).length == 0;
