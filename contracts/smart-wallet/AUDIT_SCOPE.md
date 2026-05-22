# PQSmartWallet — Audit Scope, Build, Frozen Rev

**Companion to** `AUDIT_REVIEW_GOALS.md`. This document is the
"point your IDE here" landing doc for the reviewer.

---

## 1. Frozen rev for audit

| Item | Value |
|---|---|
| Repo | `sphincs_rust` (PQSigner OS monorepo) |
| Branch at prep time | `master` |
| HEAD commit | `9a589ace8438cd1cd8ccf6843cf3d5afa1f2288c` |
| HEAD message | `docs(claude): note Safe-tx local decode and zk-attested CoW Swap clear-sign` |
| Audit-relevant last fix | `aa537ad9 smart-wallet: address all findings from AUDIT_2026-05-18` |

**Action before handoff:** tag the freeze commit, e.g.
`git tag audit-2026-05-22-handoff <SHA>` and push. Lock the branch in
the reviewer's contract or auto-create a `release/audit-2026-05` branch.

The working tree at prep time has the following uncommitted items —
none belong to the audit-scope source tree:

```
?? AUDIT_REVIEW_GOALS.md          (this prep pass)
?? AUDIT_STATIC_ANALYSIS.md       (this prep pass)
?? AUDIT_SCOPE.md                 (this file)
?? broadcast/DeployImplAndFactoryEthMainnet.s.sol/   (deploy artifact)
?? script/DeployImplAndFactoryEthMainnet.s.sol       (deploy script — out of audit scope)
```

---

## 2. In-scope source

```
contracts/smart-wallet/src/
├── PQSmartWallet.sol                  (569 LoC) — ERC-4337 v0.6 account
├── PQMultiOwnable.sol                 (267 LoC) — ERC-7201 storage + counters
├── PQSmartWalletFactory.sol           (148 LoC) — CREATE2 ERC-1967 proxy factory
├── verifiers/
│   ├── ISPHINCSVerifier.sol           ( 20 LoC) — verifier interface
│   └── SPHINCsC10Asm.sol              (228 LoC) — Yul SPHINCS+C10 verifier
└── generated/
    └── PqsignerProto.sol              ( 48 LoC) — auto-generated from Rust IDL
```

Total: **1,280 LoC Solidity + Yul.**

`generated/PqsignerProto.sol` is regenerated from
`proto/src/lib.rs` (Rust) via
`cargo run -p pqsigner-xtask -- gen-solidity-constants`. CI diffs the
checked-in file against the fresh generation to catch drift. The
auditor should treat the checked-in file as the source of truth for
this audit but flag any constants that look surprising.

---

## 3. Out-of-scope (but relevant to reproduce)

```
contracts/smart-wallet/
├── lib/                  — pinned dependencies (Solady, OpenZeppelin, account-abstraction, forge-std)
├── reference/            — upstream Coinbase Smart Wallet fork-base, kept for diff
├── test/                 — Foundry + Halmos test suites
├── certora/              — formal-verification specs
├── script/               — deploy scripts (NOT in audit scope; review separately)
├── broadcast/            — deploy artefacts (NOT in scope)
├── stubs/halmos-cheatcodes/   — symbolic-execution stubs
├── deployments/          — deployment addresses
├── out/, cache/, target/, .gas-snapshot   — build artefacts
└── foundry.toml, halmos.toml, remappings.txt   — config
```

---

## 4. Pinned dependencies

| Dep | Submodule | Commit |
|---|---|---|
| Solady | `lib/solady` | `90db92ce1738` |
| OpenZeppelin Contracts | `lib/openzeppelin-contracts` | `9cfdccd35350` |
| `account-abstraction` (eth-infinitism) | `lib/account-abstraction` | `7af70c8993a6` (tag `v0.7.0` repo but we use the `legacy/v06/` subtree only) |
| `forge-std` | `lib/forge-std` | `f494b0c2c045` |

Note: the wallet imports **EntryPoint v0.6** types from
`account-abstraction/legacy/v06/`. The submodule's HEAD happens to be
the v0.7.0 tag of the upstream repo, but only the `legacy/v06/`
subtree is consumed. This is intentional — see CLAUDE.md "No
EntryPoint v0.7 / v0.8 migration."

Also pinned but not direct deps of in-scope source:
- `lib/p256-verifier`, `lib/webauthn-sol` — unused in PQ build but
  retained for `reference/` diff convenience.
- `lib/safe-singleton-deployer-sol` — used by deploy scripts only.

---

## 5. Build & test

Verified on Linux 6.17 / bash. Single fresh-clone walkthrough:

```bash
# 1. Clone with submodules.
git clone --recursive <repo-url> sphincs_rust
cd sphincs_rust/contracts/smart-wallet

# 2. Install Foundry (>=1.2.3-stable).
curl -L https://foundry.paradigm.xyz | bash
foundryup --version stable

# 3. Build.
forge build               # production profile (via_ir, optimizer=200)

# 4. Unit + invariant tests.
forge test                # 92 tests, expects all green

# 5. Coverage (optional).
forge coverage --ir-minimum --no-match-path 'test/halmos/*' \
                --no-match-test 'codehash|Bytecode'
# (see AUDIT_STATIC_ANALYSIS.md §3 for why codehash tests fail under
#  coverage mode — production build still pins correctly.)

# 6. Halmos symbolic (optional; ~30 min/contract).
pipx install halmos       # halmos >= 0.2.0
halmos --contract HalmosValidateUserOp
halmos --contract HalmosExecute

# 7. Contract sizes.
forge build --sizes
```

Expected `forge test` result (production profile, today):
- 92 tests, 92 pass, 0 fail, 0 skip.

If the codehash-pinning tests fail with "drift", DO NOT silently update
the pin — investigate. The pins exist because Halmos discharges
specifications against the pinned bytecode, so a drift means Halmos
verification is stale.

---

## 6. Reading order for the reviewer

1. `AUDIT_REVIEW_GOALS.md` — what we're worried about.
2. `AUDIT_2026-05-18.md` — last audit's findings; section "Items
   explicitly checked and Pass" is what NOT to re-derive.
3. `AUDIT_2026-05-18_CROSS_CHECK.md` — fix verification.
4. `CLAUDE.md` (repo root, "Non-Negotiable Invariants" + "What NOT to
   do") — the contract is one half of a tightly coupled
   firmware-contract design; the firmware references are pointers, not
   black-box trust.
5. Source files, in this order:
   - `src/generated/PqsignerProto.sol` (constants the rest of the code
     uses)
   - `src/PQMultiOwnable.sol` (storage + counter primitives)
   - `src/PQSmartWallet.sol` (the meat: validateUserOp, execute,
     EIP-1271)
   - `src/PQSmartWalletFactory.sol` (CREATE2 + squat defence)
   - `src/verifiers/SPHINCsC10Asm.sol` (Yul verifier; pair with the
     Rust reference at `sphincs-c10/`)
6. Tests in `test/` — particularly `PQSmartWalletInvariants.t.sol` and
   `test/halmos/` for the formal-ish specs.
7. `certora/*.spec` — formal rules.

---

## 7. Outdated docs the reviewer should ignore

These pre-date the post-2025 cutover and describe an older
construction. The auditor should **NOT** treat them as ground truth:

- `README.md` — the upstream Coinbase Smart Wallet README (with
  `executeWithoutChainIdValidation`, P-256 owners, EOA owners).
  Retained for the upstream-fork diff. The current PQ build has
  **deleted** that surface; see `PQ_README.md` and CLAUDE.md.
- `PQ_README.md` — describes an earlier PQ design that used
  **SLH-DSA-SHA2-128f** with a 17,088-byte signature and a
  `sha256(slh-dsa pk)` single-owner model. The current build uses
  **SPHINCS+C10** (4,008-byte sig, 64-byte `pkSeed || pkRoot` owners,
  multi-owner via ownerIndex). Treat as stale.

The authoritative description of the current wire format and design
is `AUDIT_REVIEW_GOALS.md` (this prep pass) + CLAUDE.md.

---

## 8. CI / signal-of-life

`.github/workflows/` contains:
- `test.yml` — runs `forge test` on PR.

Items that should also gate CI before audit handoff but currently
don't:
- Slither / 4naly3er clean run.
- `forge coverage` floor (e.g. 80% lines on in-scope contracts).
- Halmos `VERIFIED` rules from `halmos.toml`.
- Certora rule status.

Not blocking the audit (these are belt-and-braces), but raise the
priority post-audit.
