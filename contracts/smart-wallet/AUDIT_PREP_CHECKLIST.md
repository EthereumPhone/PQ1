# PQSmartWallet — Audit Prep Checklist (2026-05-22)

Status against Trail of Bits' audit-prep checklist. Generated during
the `/audit-prep-assistant` pass on 2026-05-22.

## Documents produced this pass

- `AUDIT_REVIEW_GOALS.md` — scope, security objectives, areas of
  concern, worst-case scenarios, specific questions for auditors.
- `AUDIT_STATIC_ANALYSIS.md` — coverage, contract sizes, dead-code,
  Halmos/Certora status, tool-gap notes.
- `AUDIT_SCOPE.md` — file list, dependency pins, build instructions,
  frozen rev pointer, reading order, outdated docs to ignore.
- `AUDIT_DIAGRAMS.md` — sequence + state-machine diagrams, actor /
  privilege map, system invariants (S/T/V/A), glossary.

## Pre-existing audit artefacts

- `AUDIT_2026-05-18.md` — prior audit, 11 findings (3H/2M/3L/3I), all
  fixed in `aa537ad9`.
- `AUDIT_2026-05-18_CROSS_CHECK.md` — independent fix verification.
- `halmos.toml` + `test/halmos/Halmos*.t.sol` — symbolic-execution
  discharges for validate + execute paths.
- `certora/*.spec` (4 files) — formal-verification rules.
- `test/PinnedCodehashes.t.sol`, `test/StorageSlotParity.t.sol`,
  `test/LeanSelectorParity.t.sol` — defense-in-depth pinning.
- `test/PQSmartWalletInvariants.t.sol` — 7 stateful invariants @ 256 ×
  128k calls.
- `test/PQSmartWalletRealSig.t.sol` — real-firmware-signature
  integration tests.

## Step-by-step status

### Step 1: Review goals
- [x] Security objectives documented
- [x] Areas of concern listed
- [x] Worst-case scenarios listed
- [x] Specific questions for auditors written

### Step 2: Easy issues / clean baseline
- [x] Forge tests pass (92/92 prod profile)
- [x] Stateful invariants pass (7/7)
- [x] Coverage measured (75-90% in-scope; verifier Yul not
  line-measurable but exercised by vectors + real-sig tests)
- [x] Dead code scan (none found)
- [ ] **Slither not installed.** Auditor to run, or add to CI before
  handoff.
- [ ] **4naly3er not run.**
- [ ] **Mythril not run.**
- [ ] **Halmos** configured but not re-run this pass; status pending.
- [ ] **Certora** specs present but runs gated on API key.

### Step 3: Code accessibility
- [x] File scope documented (`AUDIT_SCOPE.md` §2)
- [x] Out-of-scope explicit (`AUDIT_SCOPE.md` §3)
- [x] Dependency pins (`AUDIT_SCOPE.md` §4)
- [x] Build instructions verified on this workstation
  (`AUDIT_SCOPE.md` §5)
- [x] Reading order for reviewer
- [x] Outdated docs flagged (`README.md`, `PQ_README.md`)
- [ ] **Frozen branch / tag.** HEAD `9a589ace` identified;
  tag-and-push pending — user action.
- [ ] **Stale READMEs.** `README.md` is upstream Coinbase boilerplate;
  `PQ_README.md` describes pre-C10 SLH-DSA-SHA2-128f design. Both
  flagged but **not rewritten** this pass — see follow-up below.

### Step 4: Documentation
- [x] Sequence diagram (deploy → sign → execute)
- [x] State-machine diagrams (validateUserOp, execute, factory,
  EIP-1271/6492)
- [x] Actor / privilege map
- [x] System + function invariants enumerated (S-1..11, T-1..3,
  V-1..8, A-1..4)
- [x] Glossary (~35 terms)
- [x] NatSpec on public functions — already present in source
- [x] User stories — covered by the sequence diagram + role notes

## Follow-ups before audit hand-off

Ordered by priority:

1. **Tag the freeze commit.**
   `git tag audit-2026-05-22-handoff 9a589ace8438cd1cd8ccf6843cf3d5afa1f2288c && git push --tags`
   (or whichever name the audit firm asks for).
2. **Rewrite or delete the stale READMEs.** `README.md` is the
   upstream Coinbase Smart Wallet boilerplate (with
   `executeWithoutChainIdValidation`, P-256 owners, EOA owners — all
   of which we deleted). `PQ_README.md` describes a pre-C10
   SLH-DSA-SHA2-128f design with a different wire format and
   single-owner model. Both are actively misleading to a reviewer.
   Either delete and link to `AUDIT_REVIEW_GOALS.md`, or rewrite
   against the current design.
3. **Run slither and add to CI.**
   `pip install slither-analyzer && slither . --filter-paths "lib/|reference/|test/|script/" --exclude-dependencies`.
4. **Re-run Halmos against the freeze commit.** Confirm
   `VERIFIED` for both `HalmosValidateUserOp` and `HalmosExecute`.
   Update `halmos.toml` pinned codehashes if the freeze produces
   different bytecode than the current pins.
5. **Run Certora.** All 4 spec files; document rule statuses.
6. **Reconcile EIP-7702 warning in `README.md`** (currently inherited
   from upstream; the PQ build's stance on 7702 is undocumented).
7. **Resolve the working-tree drift:** the new
   `script/DeployImplAndFactoryEthMainnet.s.sol` and its
   `broadcast/` artefact are uncommitted. Either commit (and confirm
   they're out-of-scope) or stash before the freeze tag.
8. **CI gates that should land pre-handoff:** slither clean, coverage
   floor on in-scope contracts, Halmos VERIFIED, codehash pins fresh.

## Items the prior audit settled (do not re-derive)

From `AUDIT_2026-05-18.md` §"Items explicitly checked and Pass":

- Yul verifier byte parity vs Rust `sphincs-c10/` (ADRS, force-zero,
  hash inputs, N-mask, htIdx, branchless swap, WOTS+C digits).
- ERC-7201 slot derivation `0x470749ee…d000`; no Coinbase-upstream
  collision.
- `_removeOwnerAtIndex` blocks `index == 0`.
- `_entryPoint`, `c10Verifier`, `implementation` immutable; no UUPS
  upgrade path.
- Impl `initialize` is locked out by constructor-seeded zero owner.
- Cross-chain / cross-wallet replay protection (chainId +
  verifyingContract / entryPoint in both `sphincsDigest` and the
  EIP-712 domain).
- Real-sig `validateUserOp` gas: 229,830 (verifier alone 180,306).
- Bytecode-freeze defense-in-depth via codehash pinning.
- Bootstrap forbidden from EIP-1271.
- Factory squat-defence working under `factorySig` checks.
- `executeWithOffchainCount` self-call rejection (H-2 fix).
- Cross-slot `offchainSigCount` poisoning closed via transient-storage
  ownerIndex token (H-3 fix).
- Bootstrap-budget bump deferred to `addOwnerBytes` (M-1 fix).
- Factory `msg.value` no longer stranded (H-1 fix).
- Wrapper tail-pad enforced (L-1 fix).
- `_erc1271Signer()` reverts as tripwire (L-2 fix).
- Batch length-mismatch custom error (L-3 fix).
