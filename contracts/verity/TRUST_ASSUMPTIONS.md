# TRUST_ASSUMPTIONS.md

What the Verity port of the PQSigner smart-wallet contracts **does and
does not** verify. Matches Verity's own convention
([`lfglabs-dev/verity/TRUST_ASSUMPTIONS.md`](https://github.com/lfglabs-dev/verity/blob/main/TRUST_ASSUMPTIONS.md)).

A `lake build` success means **the theorems in `Theorems.lean` hold
under the assumptions enumerated below**. None of those assumptions
are checked by Lean; each is an axiom or an external dependency.

## What IS verified

| Theorem | Statement | Implies CLAUDE.md invariant |
|---------|-----------|------------------------------|
| #1, #2, #3 | All three counter writers are monotonic and bounded by their caps. | #7 (per-chain caps monotonic) |
| #4 | `_removeOwnerAtIndex(0, _)` always reverts. | #6 (bootstrap immutable) — part 1 |
| #5 | No reachable trace overwrites `ownerAtIndex[0]` after construction. | #6 (bootstrap immutable) — part 2 |
| #6 | N-mask layout is enforced for every owner add. | (no CLAUDE.md mapping; defence-in-depth) |
| #7 | Factory salt has zero data dependence on `chainId`. | #6 (same address every chain) |
| #8 | `createAccount` is idempotent given identical args. | (no CLAUDE.md mapping; safety) |
| #9 | Distinct `chainId` ⇒ distinct squat-defence digest. | Squat-defence cross-chain |
| #10 | `ownerIndex == 0` dispatch only bumps `bootstrapUses`, only allows `addOwnerBytes`. | Dispatch correctness |
| #11 | `ownerIndex ≥ 1` dispatch never bumps `bootstrapUses`. | Dispatch correctness |
| #12 | EIP-1271 rejects `ownerIndex == 0`. | Bootstrap key never EIP-1271-signs |
| #13 | Global combined-cap invariant. | #7 (combined invariant) |

## What is NOT verified (trusted axioms)

1. **`SPHINCsC10Asm.sol` correctness.** Modelled as opaque oracle
   `c10Verify : ByteVec → ByteVec → ByteVec → ByteVec → Bool`. We
   assume:
   - Deterministic in its inputs.
   - May revert (caller wraps in `try/catch`).
   - No observable side effect on our ERC-7201 namespace.

   The verifier itself implements FIPS 205-aligned SPHINCS+C10 in
   hand-tuned Yul. Lifting this to a Lean theorem is the subject of
   `docs/handoff-verity-c10-verifier.md`.

2. **SHA-256 / Keccak-256 precompile correctness.** Both are
   axiomatised as the spec hash functions. Theorem #9
   (`addSlot0Digest_binds_chain_id`) relies on SHA-256
   collision-resistance — that is an assumption on the function, not
   a Lean-provable fact.

3. **`solc 0.8.33` Yul → EVM bytecode correctness.** Verity's
   in-Lean compilation proof terminates at Yul; the Yul → bytecode
   lowering is `solc`. Pinning the version (matching Verity's own
   pin) is our only mitigation. Verity itself acknowledges this in
   its TRUST_ASSUMPTIONS.md.

4. **Solady `LibClone` (`createDeterministicERC1967`,
   `predictDeterministicAddressERC1967`).** Axiomatised by:

   ```lean
   axiom predict_matches_create :
     ∀ impl salt factory value,
       (createDeterministicERC1967 value impl salt factory).fst =
         predictDeterministicAddressERC1967 impl salt factory
   ```

   The deeper claim — that the resulting address equals
   `CREATE2(factory, salt, ERC1967_INIT_CODE_HASH(impl))` — is a
   property of Solady's lib + the EVM CREATE2 opcode + `keccak256`.
   Out of scope.

5. **EIP-1967 proxy `delegatecall` semantics.** All wallets are
   ~55-byte proxies that `DELEGATECALL` to the impl. We reason about
   the impl directly; the proxy is opaque and assumed semantics-
   preserving (this is a property of `DELEGATECALL` + EIP-1967, not
   our code).

6. **EntryPoint v0.6 invariants.** The caller of `validateUserOp` is
   the EntryPoint singleton. We axiomatise that it follows ERC-4337
   v0.6 — specifically that it never calls `validateUserOp` with
   stale `missingAccountFunds` or skips the post-call settlement.
   Out of scope; trusted per the ERC-4337 spec.

7. **Firmware-side wire format from CLAUDE.md §"Unified sign
   input".** The SHA-256 preimage that the firmware signs is *input*
   to our spec (via the opaque `sphincsDigest` function), not
   verified by it. If the firmware's `cmd_sign_userop.rs` builds the
   wrong preimage, the sigs it produces will be rejected on-chain —
   fail-safe, but the bug is not caught here.

8. **`block.chainid` truthfulness.** The "same 24 words → same
   address on every chain" claim holds within a single canonical
   history per chain. An L2 reorg that retroactively reassigns its
   chain ID is out of scope (and would be a far larger problem than
   our wallet).

9. **Gas griefing / OOG.** Verity does not reason about gas. The C10
   verify burns 1.7–4M gas; an attacker who supplies a malformed
   UserOp that triggers an OOG before the counter bump could leave
   storage in a stuck-pending state. Mitigation lives at the
   EntryPoint level (bundler gas estimation) and at the firmware
   level (slot-cache invalidation on OOG), not in this Lean proof.

10. **`bumpBootstrapUses` is never called outside `validateUserOp`.**
    The chain of custody from "external entry point" to "counter
    bump" is part of theorem #10. If a future PR exposes
    `_bumpBootstrapUses` as a public function (or adds a new public
    entry point that calls it), theorem #10's premise no longer
    holds — but Lean would not catch it, because the new entry point
    is a new theorem obligation. **Code review remains responsible
    for noticing new public writers.**

## Recovering trust when an axiom fails

Each axiom corresponds to a specific failure mode:

| Axiom failure | What breaks | Mitigation |
|---------------|-------------|------------|
| C10 verifier accepts a forged sig | Funds drainable from any slot | Part B handoff (Verity port of `SPHINCsC10Asm.sol`) |
| `keccak256` collision found | EIP-712 / CREATE2 collisions across the ecosystem | Industry-wide problem; out of scope |
| `sha256` collision found | Squat-defence digest reuse across chains | Industry-wide; out of scope. The combined-cap invariant still holds. |
| `solc 0.8.33` codegen bug | Verified Yul → buggy EVM bytecode | Differential test against the existing Solidity build catches behavioural divergence on test vectors |
| Solady `LibClone` deploys at wrong address | CREATE2 prediction differs from actual deploy | Solady is audited; if their pin moves, re-validate |
| EntryPoint v0.6 violates ERC-4337 | UserOp settlement breaks | Industry-wide; out of scope |
| Firmware builds wrong `sphincsDigest` preimage | Sigs rejected on-chain (fail-safe) | Firmware-side test in `secure/src/nsc/cmd_sign_userop.rs` |

## Diff against `lfglabs-dev/verity/TRUST_ASSUMPTIONS.md`

Verity's own list:
- Lean kernel correctness (trusted)
- `solc` Yul-to-bytecode correctness (trusted)
- `lake` build reproducibility (trusted)

Our additions:
- C10 verifier (opaque oracle — the big one)
- Solady `LibClone` (axiomatised)
- EntryPoint v0.6 (axiomatised)
- Firmware-side wire format (input to spec)

Our list inherits Verity's; the union is what reviewers should look
at before declaring a deployment "verified".
