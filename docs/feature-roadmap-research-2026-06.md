<!-- Generated 2026-06-30 by a 15-agent research workflow (10 web-search finders across privacy/paymasters/AA-modules/DeFi/security/interop/PQ-positioning/competitor-gap/recovery/payments -> consolidation+feasibility -> 3-lens panel -> synthesis). 46 candidates surfaced, 27 deliberately ruled out. Invariant-aware: every item filtered against C10-only, v0.6-frozen, ~1s-sign latency, stateless-slot. -->

# PQ1 Feature & Appeal Research (2026-06)

## TL;DR — the strategic call

**PQ1 is not a daily-driver. It is the deliberate, high-assurance, post-quantum signer you bolt onto money that should move slowly.** The ~1 s / 4008-byte SPHINCS+C10 signature is a tax on a hot wallet and a *feature* on a multisig or a cold vault, where every signature is supposed to be a considered act. Stop trying to out-MetaMask MetaMask; that lane is structurally closed (a C10 "session key" is still a 1 s C10 sign — zero latency win). Lead the product, the marketing, and the next quarter of engineering with the two postures where the shipped code already *is* the product:

1. **PQ1 as a post-quantum EIP-1271 co-signer/owner inside a Safe multisig.** Drop one provably hash-based, blind-sign-proof owner into an otherwise-classical treasury Safe. Even if every ECDSA owner key is quantum-forged, the Safe still cannot move without the C10 owner. This independently surfaced as the #1 candidate in all three lenses and reuses 100% of the shipped SafeTx EIP-712 + multiSend + Safe-mgmt + Safe-wrapped-CoW clear-signing. **It is not free** — three load-bearing adaptations below.
2. **Long-term PQ cold-storage vault** (counterfactual ERC-6492 + deterministic CREATE2). The literal answer to harvest-now-decrypt-later, with *zero* new device or contract work — every primitive (`GET_WALLET_ADDRESS` / `GET_INIT_CODE` / `SIGN_USEROP` / ERC-6492 deploy-then-spend) already ships.

**The five highest-leverage moves, in order:**

1. **WalletConnect v2 (Reown WalletKit) in the companion** — the master unblock. Until this exists PQ1 is a Send/Receive curiosity; after it, the whole dapp ecosystem reaches the device through the shipped `CMD_SIGN_*` paths with **no device change and no ECDSA anywhere**. L effort, zero dependencies. Gates ~10 downstream features.
2. **Stand up the Safe co-signer posture** — Safe Transaction Service client + a thin legacy-`isValidSignature` adapter contract + the gap-cap firmware fix. This is the flagship; it is mostly companion + one small external contract.
3. **Ship the cold-vault posture as a companion "Vault" mode** — near-zero engineering, pure repositioning of shipped counterfactual machinery. The cleanest PQ story you have.
4. **ERC-7730 descriptor pack** — the cheapest scaling lever in the whole set. Turns "write + audit a Rust decoder per protocol" into "add a signed JSON descriptor," reusing the shipped renderer + Merkle-root verify. This is how DeFi/RWA coverage scales after WalletConnect lands.
5. **Gas abstraction on v0.6 (ERC-7677 sponsored first-deploy)** — solves the PQ-specific cold-start: a zero-ETH user literally cannot afford their own `INCLUDE_INIT_CODE + REGISTER_SLOT` deploy. Must target Pimlico's **v0.6** path; Circle Paymaster is v0.7/v0.8-only and ruled out.

The one recurring firmware constraint that shapes the whole roadmap: **`MAX_OFFCHAIN_GAP = 100`** (proto/src/lib.rs:954, enforced at cmd_sign_offchain.rs:317). A wallet that only ever signs off-chain EIP-1271 never advances `last_userop_count` and **bricks at 100 sigs**. This pushes the flagship Safe co-signer, intent swaps, and standing orders all toward *on-chain* authorization, and it is the flagship's single concrete firmware follow-up.

---

## The constraint lens (why generic wallet advice doesn't apply)

Four hard invariants bound the entire design space. Every recommendation is filtered through them.

| Constraint | What it is | Rules **out** | Rules **in** / reframes |
|---|---|---|---|
| **C10-only signer** (invariant #5) | Single `c10Verifier`; no secp256k1/P-256/Ed25519/lattice anywhere in firmware or contract | Passkey/P-256 owners, EIP-7702 (ECDSA auth tuple), EIP-2612/Permit2-ECDSA/EIP-3009 permits, perps agent keys, any classical fallback, stealth-address *spending* | EIP-1271/ERC-6492 contract sigs, C10 guardians, Permit2-via-ERC-1271 (once deployed), direct `approve`/`setAuthorization` |
| **EntryPoint v0.6 frozen forever** (invariant #6) | Address + ABI baked into the CREATE2 init-code hash; bumping breaks same-seed→same-address | ERC-7579 modules, v0.7 packed-UserOp paymaster fields, Circle Paymaster, native ERC-7932/8141 migration | Pimlico ERC20PaymasterV06, ERC-7677 (returns v0.6 `paymasterAndData`), every v0.6 bundler (still served in 2026) |
| **~1 s / 4008-byte sign** (latency reality) | First-sign ≤3 s incl. keygen; cached Type-2 ~1.1 s; sigs are huge | Session keys for speed, tight-RFQ quote-chasing, retail tap-to-pay, x402 micropayments, HFT/perps, encrypted-mempool ordering | Multisig co-signing, cold vault, set-and-forget DeFi, batched revokes, batch UserOps (EIP-5792) — *deliberate by nature* |
| **Stateless slot selection + no new per-sig flash** (invariants #7, #8) | Companion supplies `(chain_id, slot_index, flags)`; only the page-123 off-chain counter persists | On-device address book / blocklist / approval DB; per-signature flash state | S-world **config** state (policy guard — precedent: page-123 counter); advisory companion-supplied markers |

Two more filters that do most of the discriminating work in practice:

- **The ECDSA-onboarding test.** Many privacy/identity schemes derive a spending/viewing key from an ECDSA *signature* over a fixed message — PQ1 cannot produce one. The discriminating question per protocol is **"does a non-ECDSA key path exist?"** Seed-derived schemes pass (Railgun's Baby-Jubjub-from-BIP-39, Privacy Pools' own phrase, XMTP/SIWE via EIP-1271); ECDSA-signature-derived schemes fail unless a key-import path exists.
- **Device vs companion.** The STM32U585 cannot run a forked EVM, fetch chain state, or do route/proof/price compute. Everything heavy lives in `pq1-companion`; the device only ever clear-signs a decoded artifact and confirms.

---

## Recommended roadmap (tiered)

### Tier 0 — table stakes / unblock everything

| Feature | What | Place | Effort | Impact | Gates |
|---|---|---|---|---|---|
| **WalletConnect v2 (Reown WalletKit)** | Pair from `wc:`/QR, advertise the CREATE2 address across CAIP-25 namespaces, route `eth_sendTransaction`→UserOp→`CMD_SIGN_USEROP` and `personal_sign`/`eth_signTypedData_v4`→`CMD_SIGN_OFFCHAIN` | Companion | L | High | SIWE login, EIP-5792 batch, intent/RFQ swaps, cross-chain bridging, dapp-driven DeFi clear-signing, multichain sessions, XMTP |

*Integration sketch:* companion is the relay; device sees only an already-decoded artifact via shipped `CMD_SIGN_*`. Dapps consume the C10 sig via ERC-1271/6492 — no ECDSA. EIP-1193 + EIP-6963 injected-provider bridge (Tier 2) is the alternative gate for in-browser injected-only dapps.

### Tier 1 — high-impact, good fit, do next

| Feature | What (one line) | Place | Effort | Impact | Dep | Integration sketch |
|---|---|---|---|---|---|---|
| **Safe PQ co-signer** ⭐ | Register PQ1 as a Safe owner; clear-sign the EIP-712 `SafeTx`, return a C10 EIP-1271 sig the Safe checks via `checkNSignatures` | Companion + contract | M | High | Safe Tx Service client; adapter contract; gap-cap fix | Device clear-signs the shipped SafeTx (incl. multiSend / Safe-mgmt / Safe-wrapped-CoW); companion proposes/fetches/confirms the SafeTx |
| **Long-term PQ cold vault** ⭐ | "Park funds at the undeployed counterfactual address for a decade; deploy-then-spend at first withdrawal" | Companion | S | High | none | Companion "Vault" mode watches balances + assembles the first-spend deploy+UserOp; device path is 100% shipped (slot_index 0) |
| **ERC-7730 DeFi/RWA descriptor pack** | Ship signed ERC-7730 JSON descriptors into the firmware-pinned Merkle bundle; render via the shipped renderer | Both | S | High | none | Companion fetches from EF/Ledger registry; device renders via existing `erc7730` path + `db_roots` Merkle verify. **Highest-leverage scaling lever.** |
| **SIWE / dapp-login (EIP-4361)** | Answer login challenges with one deliberate EIP-1271 sign; ERC-6492 lets a counterfactual wallet log in pre-deploy | Companion | S | High | WC2 | Reuses `CMD_SIGN_OFFCHAIN` with firmware-side `replaySafeHash` nesting; the honest survivor of "session keys" — a non-spending grant |
| **Gas: ERC-7677 sponsored first-deploy** | Companion runs the 7677 stub→final handshake against a v0.6 verifying paymaster; sponsors the costly first deploy | Both | M | High | ERC-7677 client | One new device "Gas: sponsored by `<sponsor>`" page fed by a companion sponsor-name field; v0.6 folds `keccak256(paymasterAndData)` into `userOpHash` so the displayed sponsor is what the C10 sig authorizes |
| **Token-approval / allowance manager** | revoke.cash-style dashboard → bundle `approve(spender,0)` calls into ONE atomic-batch/multiSend the device clear-signs per-record | Both | S | High | none | Reuses shipped ≤6-record per-record ERC-20 decode; batching is the *right* UX (N separate 1 s signs would be wrong); no new flash state |
| **Deliberate DeFi: staking (Lido/RocketPool/Kiln)** | Clear-sign `Lido.submit` / wstETH wrap / `RocketDepositPool.deposit` as "Stake 2.0 ETH with Lido → stETH" | Both | S | High | ERC-7730 pack (optional) | Direct-call UserOp (gap-free); cheapest clear-sign to add (small selector table). Use plain `approve`, **never** stETH EIP-2612 permit (ECDSA) |
| **Portfolio / multichain / NFT / history dashboard** | Build the bare Dashboard into a real portfolio + local encrypted address book | Companion | M | Med | none | Read-only indexer/price work; device untouched. Closes the widest "feels like a real wallet" gap vs Ledger Live/Trezor Suite/Rabby |
| **Fiat on/off-ramp (MoonPay/Transak/Coinbase Onramp)** | Hosted KYC widget delivering USDC/ETH to the CREATE2 address | Companion | M | High | none | Deterministic same-address-everywhere = KYC/whitelist ONE address across all chains; off-ramp send is a normal ERC-20 transfer the device already clear-signs |

⭐ = strategic-fork flagship.

### Tier 2 — strong differentiators / medium effort

*Safety / defense-in-depth*

| Feature | What | Place | Effort | Impact | Dep | Note |
|---|---|---|---|---|---|---|
| **On-device clear-sign policy guard** | S-world spend-limit/allowlist/selector gate refuses out-of-policy ops *before* the confirm screen | Device | M | High | none | Module-grade limits with no on-chain module on the frozen wallet. Adds S-world **config** flash (not per-sig); gate edits behind a confirm + optionally the bootstrap key |
| **On-device Permit2 / EIP-712 approval-intent rendering** | Decode Permit2 `PermitSingle/Batch/PermitTransferFrom`: spender/token/amount (LOUD on unlimited)/expiry | Device | M | High | none | Kills the dominant 2025 drainer vector. ERC-2612 token-permit is ecrecover-only (out); Permit2 has no ERC-6492 unwrap → undeployed PQ1 can *render* but only a *deployed* one can sign |
| **Paymaster-aware clear-signing** | Widen the sign-input parser for paymaster addr + mode + sponsor name; render a Gas Abstraction page; warn on post-op token-pull | Device | M | High | none | Parse-side only — no new wire format, no new flash. Makes the device the source of truth on *who pays* |
| **Local pre-sign simulation (revm/anvil fork)** | Dry-run the inner call against the user's own RPC in the Tauri Rust backend; show balance/approval deltas | Companion | L | High | none | Sovereign defense-in-depth — no payload leak to a third-party shadow fork. Simulation is *advisory*; the device's own calldata decode stays authoritative |
| **Cloud pre-sign sim + scam scan (Tenderly/Blockaid)** | Net asset deltas + risk score; device independently decodes the same calldata | Companion | M | High | WC2 (dapp flows) | Table-stakes vs Rabby/Safe. Leaks the payload to a third party → keep optional; a companion "sim digest" shown on-device would be theatre |

*Gas / payments*

| Feature | What | Place | Effort | Impact | Dep | Note |
|---|---|---|---|---|---|---|
| **Pay gas in USDC (Pimlico ERC20PaymasterV06)** | Stablecoin-only holders transact; first leg is `approve(paymaster, cap)` the shipped decoder renders | Both | M | High | ERC-7677 client | MUST use Pimlico's **v0.6** `0x6666…c68b`. LOUD-flag unlimited/oversized approvals (malicious-paymaster drain) |
| **Stablecoin payments UX (PYUSD/USDC/USDT/USDe)** | Add the stablecoin set to the known-token Merkle DB; companion adds ENS-pay, request links/QR, CCTP | Both | S | High | none | Mostly companion UX over shipped ERC-20 clear-signing; `db_roots` Merkle update is the only device touch. B2B/invoice fit; retail tap-to-pay out |

*DeFi*

| Feature | What | Place | Effort | Impact | Dep | Note |
|---|---|---|---|---|---|---|
| **Intent/RFQ swap via CoW `setPreSignature`** | Path-A: UserOp→`GPv2Settlement.setPreSignature` (on-chain, gap-free, **already proven on-device**) | Both | M | High | WC2 | The standout swap path. Avoid off-chain Path-B at volume (gap-cap). Tight-RFQ quote-chasing ruled out (1 s staleness) |
| **Cross-chain bridging via ERC-7683 (Across)** | Clear-sign `depositV3(...)` and assert `recipient == this wallet's CREATE2 addr on destChainId` | Both | M | High | WC2 + cross-chain addr check | Same-address-on-every-chain turns "bridge to myself" into an on-device-verifiable guarantee — a *strength*. Prefer `OnchainCrossChainOrder`/`depositV3` (gap-free) over the Permit2 gasless variant |
| **DeFi lending (Aave v3 / Spark / Morpho Blue)** | Expand native ERC-7730 coverage only where every signed operand is rendered; assert `onBehalfOf==this` | Both | M | High | ERC-7730 pack | The current strict Aave v3 catalogue accepts plain `withdraw`/`repay` and refuses formats such as `supply`/`borrow` whose descriptors hide `referralCode`. Fix those descriptors before claiming coverage. Use Morpho's **direct** `setAuthorization`, never `setAuthorizationWithSig` (ECDSA). |
| **DeFi restaking (EigenLayer/Symbiotic/Karak)** | Clear-sign `depositIntoStrategy`/`delegateTo`/`queueWithdrawals` with operator labelling | Both | M | Med | ERC-7730 pack | `delegateTo` passes an empty approver sig under open delegation (no user ECDSA). Long-horizon lock-and-delegate is the PQ1 sweet spot |
| **EIP-5792 `wallet_sendCalls` (atomic batch)** | Advertise `atomicBatch` via `wallet_getCapabilities`; fold a dapp's approve+swap into one multiSend | Both | M | Med | WC2 | The rare connectivity feature where latency is an *advantage* — high cost-per-sign pushes toward batching, which 5792 standardizes. Maps onto shipped batch/multiSend |
| **Standing/conditional orders (CoW ComposableCoW)** | One on-chain authorization lets a solver fill TWAP/DCA/limit repeatedly | Both | L | Med | WC2 | Viable ONLY as a single on-chain conditional order. A 100-leg off-chain DCA exhausts the gap cap and bricks |
| **Pre-signed scheduled UserOp sequence (DCA surrogate)** | Device clear-signs K future UserOps (incrementing nonces); companion submits on schedule | Both | M | Med | none | Only recurring-automation form compatible with a deliberate signer. Honest limit: `sphincsDigest` does **not** cover `validUntil/validAfter`, so a relayer can submit the whole schedule early (cannot reorder/forge legs) |
| **Multichain / L2 v0.6 sessions** | Present the same address across all v0.6 chains a dapp requests | Companion | M | High | WC2 | Companion MUST track per-chain monotonic caps (approach 65,536, no reset) + warn, and MUST NOT migrate any chain to v0.7 |

*Recovery / inheritance*

| Feature | What | Place | Effort | Impact | Dep | Note |
|---|---|---|---|---|---|---|
| **On-device "Check backup"** | Re-enter seed, recompute `masterPkSeed/masterPkRoot` in S-world, confirm it matches the active-slot fingerprint | Device | S | Med | none | Read-only, no exposure, no new flash. Unverified backup is the #1 silent loss cause. Pairs with Shamir |
| **Shamir / SLIP-39 backup (k≥2)** | k-of-n threshold split generated + re-entered entirely in S-world | Device | L | High | Check backup (pairing) | **Disclose the fork:** custom GF(256) of the exact BIP-39 entropy *preserves* the address (recommended); standard SLIP-39 is cross-vendor but yields a *different* address (new-wallet choice). Never ship 1-of-1 |
| **BIP-39 passphrase / hidden wallets** | S-world-typed passphrase extends the PBKDF2 salt → a separate deterministic wallet set | Device | S | Med | none | Nearly free (derivation already runs PBKDF2-HMAC-SHA512); never crosses to NS; base address unaffected. Ship with the backlogged duress-PIN decoy, not standalone |
| **PQ1 as guardian for someone else's hot account** | PQ1 as the break-glass Safe guardian that clear-signs the owner-swap SafeTx if a hot key is lost | Both | S | Med | Safe Tx Service client | Reuses shipped Safe owner-mgmt rendering; acts via EIP-1271, hosts no module |
| **Native social recovery via C10 slot-owner rotation** | A pre-designated C10 guardian co-authorizes a UserOp adding the new device's slot pubkey | Both | M | Med | none | Guardians MUST be C10 (no arbitrary EOA). Touches slot owners only, never master/salt → address stable |
| **Safe + Zodiac Delay Modifier inheritance** | Heir (plain EOA) can rotate the Safe owner set after a long timelock; live PQ1 owner holds cancel/veto | Companion + contract | M | Med | Safe co-signer | No new PQ1 contract — Zodiac is battle-tested; heir sits on the Safe (not bound by invariant #5). Clean dead-man-switch with veto |

*Interop*

| Feature | What | Place | Effort | Impact | Dep | Note |
|---|---|---|---|---|---|---|
| **EIP-1193 + EIP-6963 injected-provider bridge** | Inject `window.ethereum`, announce via 6963, tunnel RPC to the device-routing layer | Companion | L | Med | none | Covers injected-only dapps; alternative gate to WC2 for in-browser dapps |
| **ENS resolution / reverse / primary-name** | Forward/reverse ENSIP-19 labels; optionally clear-sign `setNameForAddr` | Both | S | Med | none | Resolution is read-only/advisory — OLED keeps the authoritative raw 20-byte address. Setting a name is just another clear-signed UserOp |
| **RWA / treasury clear-signing (Ondo/BUIDL/Superstate)** | ERC-7730 descriptors for subscribe/redeem/transfer → "Subscribe 50,000 USDC → OUSG" | Both | M | Med | ERC-7730 pack | RWA tokens are allowlist-gated ERC-20s; one-deterministic-address *helps* allowlisting. Pure ERC-7730 reuse |

### Tier 3 — moonshots / forward-looking PQ bets

| Feature | What | Place | Effort | Impact | Dep | Note |
|---|---|---|---|---|---|---|
| **Reference open-source on-chain C10/SLH-DSA verifier + vectors** | Publish `SPHINCsC10Asm.sol` + test vectors + param spec as the reference hash-based verifier for ERC-7932/EIP-8141 | Contract | M | Med | none | Claims the standard slot without migrating off v0.6. Honest: ~200k+ gas vs ~3k ECDSA, 7-17 KB sigs — value is conformance + L2/off-chain, **not** cheap L1 verify |
| **PQ device-identity attestation (C10 certificate)** | Device C10-signs a verifier nonce + key fingerprint → "verified post-quantum device" badge | Both | M | Med | none | Just another C10 sign. MUST use a dedicated attestation domain tag disjoint from any Type-1/2 `sphincsDigest` (RAW32 oracle hazard) |
| **Quantum-exposure scanner + "sweep to PQ1"** | Flag the user's quantum-exposed addresses (revealed ECDSA pubkeys); guided sweep into the PQ1 vault | Companion | M | Med | none | The reason-to-exist funnel. Honest surface: only *revealed* pubkeys are exposed; don't oversell the Q-Day canary |
| **PQ encrypted backup / inheritance (ML-KEM-1024)** | Extend the backlogged SE-wrap to a quantum-safe sealed backup of recovery material | Both | L | High | ML-KEM-1024 SE-wrap (**descoped 2026-07-07** — owner accepted the bus residual, work-todo #9; the `pqsigner-pq-seal` prototype this would build on stays in-tree feature-gated) | Makes the *whole* lifecycle PQ. Encapsulation in S-world; must preserve invariant #1 (never reassemble both XOR halves outside the secure world) |
| **Privacy Pools (0xbow) deposit/withdraw clear-signing** | Clear-sign the two public boundary UserOps; in-pool secret is 0xbow's own phrase | Both | M | High | none | **No ECDSA-onboarding blocker** — nullifier derived from 0xbow's phrase, not a wallet sig. PQ1 secures only the public boundary (proof gen needs the spend key off-device). ASP-compliant, Vitalik-endorsed |
| **Railgun shield/unshield boundary clear-signing** | Clear-sign the public shield/unshield UserOp; 0zk wallet from an independent BIP-39 seed | Both | M | Med | none | ECDSA gotcha **resolved**: Railgun spend/view keys derive from BIP-39 via BIP-32 (Baby-Jubjub/Ed25519) — the message-signing onboarding is a convention, a seed can be imported. Spend key lives hot in companion |
| **Kohaku-stack (EF privacy SDK) PQ signer integration** | Make the companion a Kohaku-compatible signer surface for the EF's 4337 privacy relay | Companion | M | Med | Kohaku v0.6 targeting (verify) + Railgun/PP renderers | "The PQ signer for the EF privacy stack" > any single integration. MUST confirm Kohaku targets v0.6 or is version-agnostic |
| **Confidential ERC-20 (ERC-7984 / Zama FHEVM)** | Clear-sign `confidentialTransfer(to, encAmount, inputProof)` | Both | L | Med | Zama gateway EIP-1271 acceptance (verify) | **Weakest fit.** Unverified whether Zama's gateway accepts a smart-account EIP-1271 user-decryption auth (vs ecrecover-EOA); device can't verify ciphertext==amount. Verify the gateway first |
| **XMTP messaging onboarding (EIP-1271 inbox)** | PQ1 owns an XMTP inbox for tamper alerts / tx-request inbox / co-signer coordination | Companion | M | Low | WC2 (optional) | No ECDSA blocker (SCW path is EIP-1271; installation keys client-generated). Credibility proof-point, not a flagship |
| **Stealth-address RECEIVING-only (ERC-5564/6538)** | Companion-managed receive + sweep with a non-PQ1 throwaway key | Companion | M | Low | none | Receive only; spending is ruled out (needs secp256k1 + mints a new address per pay). Low-impact at most |
| **Treasury audit-trail / signed attestation export** | Companion compiles a statement; device optionally C10-signs over its own per-slot counters | Companion | M | Low | none | MUST use a dedicated attestation domain tag disjoint from any `sphincsDigest` preimage (RAW32 oracle) |

---

## Deep dives on the highest-leverage themes

### 1. WalletConnect + PQ1 acting as a *wallet*, not a *signer device*

**What.** Embed Reown WalletKit (WalletConnect v2) in the companion: pair from a `wc:` URI/QR, advertise the CREATE2 address across CAIP-25 namespaces, and route dapp RPC to the shipped `CMD_SIGN_*` handlers — `eth_sendTransaction`→UserOp→`CMD_SIGN_USEROP`, `personal_sign`/`eth_signTypedData_v4`→`CMD_SIGN_OFFCHAIN` (ERC-1271/6492 wrapper).

**Why it fits PQ1 specifically.** PQ1 is a 4008-byte smart-account signer; it *cannot* plug into MetaMask/Rabby/Frame as a classic BIP-32 secp256k1 HID device (they expect EOA sigs). It must connect *as a wallet*. WalletConnect is the one integration that is purely additive companion network work — the device path is already built, dapps consume the C10 sig through ERC-1271/6492, and nothing classical is required. It is also the binary gate: without it, adoption is capped at Send/Receive.

**The one gotcha.** A naive WC2 integration that forwards a dapp's `permit`/`eth_signTypedData` request straight through will **silently fail** on every EIP-2612/Permit2-ECDSA/EIP-3009 permit — those verify via `ecrecover`, which a contract account cannot satisfy. The companion must *translate*: direct `approve` / Permit2-via-ERC-1271 (and Permit2 only once the account is deployed — no ERC-6492 unwrap).

### 2. The Safe-multisig / cold-funds positioning (the real wedge)

**What.** Two reinforcing postures, both repositionings of shipped code: (a) register PQ1 as one owner of an existing classical treasury Safe so the vault survives total ECDSA collapse; (b) package the counterfactual ERC-6492 address as a decade-long quantum-safe cold vault.

**Why it fits PQ1 specifically.** Multisig and cold-storage signing are *inherently deliberate and low-frequency* — the exact grain where a 1 s, clearly-displayed, blind-sign-proof signature is an asset, not a tax. The competitive gap is real and verifiable: every cold/multisig incumbent (Keystone 3 Pro, GridPlus Lattice1, Ledger Enterprise/Multisig, Coldcard, Safe itself) is classical-signature, and even Trezor Safe 7's "quantum-ready" is boot/firmware/device-cert only — **none sign post-quantum on-chain**. "Add one provably PQ owner to the Safe you already run" is additive (no wallet switch, no migration) and is the only posture all three lenses converged on.

**The three load-bearing gotchas (do not let marketing call this "free"):**
1. **Selector mismatch.** Safe calls the *legacy* `isValidSignature(bytes,bytes)→0x20c13b0b`; PQSmartWallet (Solady) only exposes the *modern* `isValidSignature(bytes32,bytes)→0x1626ba7e` (PQSmartWallet.sol:555). Bridge with a **thin external adapter contract** registered as the Safe owner — editing PQSmartWallet would shift the CREATE2 init-code hash and break invariant #6. **UPDATE 2026-10-20: resolved in the wallet.** The address change was accepted once, before launch, for the Trail of Bits audit freeze, and the frozen `PQSmartWallet` implements the legacy entry itself (#995): it returns `0x20c13b0b` exactly when the bytes32 entry accepts `keccak256(data)`. No adapter is needed; Safe v1.3.0 / v1.4.1 accept the wallet as a contract owner directly.
2. **The gap-cap brick.** A wallet used *purely* as an EIP-1271 co-signer never advances `last_userop_count`, so `gap = local_offchain − last_userop` climbs to `MAX_OFFCHAIN_GAP = 100` (cmd_sign_offchain.rs:317) and the device **refuses to co-sign** with no on-chain reconcile. Needs a firmware special-case (a deployed EIP-1271-only signer carve-out) or a companion-triggered reconcile UserOp.
3. **Must be deployed.** Safe calls `isValidSignature` on-chain — ERC-6492's deploy-then-verify does not help. The PQ1 used as a Safe owner has to be deployed first.

### 3. Privacy via Railgun / Privacy Pools — and the ECDSA-onboarding gotcha

**What.** Companion runs the protocol SDK (deposit/shield, ASP-membership or BN254 proof, relay); device clear-signs only the **public boundary** UserOps (deposit pool/asset/amount; shield/unshield token+amount+commitment) via a new typed-call renderer.

**Why it fits PQ1 specifically.** Both survive the ECDSA-onboarding test, which is the sharpest filter in the whole set. Privacy Pools' in-pool spend authority comes from 0xbow's *own* BIP-39-style phrase (nullifier derived from it, not from a wallet signature). Railgun's spend/view keys derive from an *independent* BIP-39 seed via BIP-32 over Baby-Jubjub/Ed25519 — the message-signing onboarding is a *convention*, not mandatory, so a seed can be imported independently. Both ride the EF Kohaku 4337-relay wave (Railgun live May 2026).

**The one gotcha.** Be honest about the security boundary: the in-pool/in-shield spend key is **non-C10 and must live hot in the companion** for zk-proof generation — it cannot sit in the SE. **PQ1 secures the public deposit/withdraw boundary, not in-pool custody.** Selling it as "PQ custody of your private funds" misrepresents the model. (Confidential ERC-20 / Zama is the *weakest* member of this cluster — keep it in Tier 3 until you confirm Zama's gateway accepts a smart-account EIP-1271 decryption authorization; if it's ecrecover-EOA-only, a PQ1 user cannot even view their own balance.)

### 4. Gas abstraction on a frozen v0.6 wallet

**What.** Companion runs the ERC-7677 stub→final handshake against a **v0.6-supporting** paymaster, assembles `paymasterAndData`; the device renders one Gas Abstraction page (sponsor name, or "gas paid in N USDC"). Sponsoring the costly first `INCLUDE_INIT_CODE + REGISTER_SLOT` deploy solves the PQ cold-start.

**Why it fits PQ1 specifically.** v0.6's EntryPoint folds `keccak256(paymasterAndData)` into the `userOpHash`, so the displayed sponsor/token is *exactly* what the C10 sig authorizes — the device becomes the source of truth on who pays, a differentiator no hot wallet matches. ERC-7677 explicitly returns v0.6 `paymasterAndData`. This is also the only thing that lets a zero-ETH user start at all.

**The one gotcha.** Provider churn is real: **Circle Paymaster is v0.7/v0.8-only and ruled out**, Alchemy plans a 2026 v0.6 sunset, Biconomy routes new chains to v0.7+. Target Pimlico's `ERC20PaymasterV06` (`0x6666…c68b`) and ship **multi-provider fallback** — never wire to a v0.7-only service. And LOUD-flag any unlimited/oversized `approve(paymaster, …)`: a malicious paymaster route is a classic drain vector dressed as "just gas."

### 5. Security as the load-bearing differentiator

**What.** Three device-boundary defenses that attack the actual 2024-25 drainer playbook: the **on-device policy guard** (refuse out-of-policy ops before confirm), **Permit2 approval-intent rendering** (LOUD on unlimited), and the **batch-revoke allowance manager** — backed by **local revm/anvil simulation** in the Tauri backend.

**Why it fits PQ1 specifically.** PQ1 already has the secure-world renderer competitors lack; these extend it. The policy guard is the only way to get module-grade spend limits on a wallet where no on-chain module can ever be installed (it adds S-world *config* state — precedent: the page-123 counter — not per-signature state, so invariant #8 is untouched). Local simulation matches PQ1's sovereign self-custody identity: Blockaid phones the raw payload home; a local revm fork doesn't.

**The one gotcha.** Resist "simulation as a device feature." A companion-supplied "simulation digest" confirmed on the OLED is **theatre** — the STM32U585 cannot re-run a fork, so a digest it can't reproduce proves nothing. Keep simulation strictly advisory and companion-side; the device's own independent calldata decode stays authoritative and survives a compromised companion (the Bybit lesson). Same discipline for *any* device-signed attestation: it must use a dedicated domain tag disjoint from every Type-1/2 `sphincsDigest` preimage, or the "PQ badge" becomes a UserOp-forgery oracle (the RAW32 hazard).

---

## Considered but ruled out / needs reshaping

| Idea | Why ruled out / reshaped | Survivor |
|---|---|---|
| **Session keys for speed** (gaming/trading/social/HFT) | A PQ1 session key is itself C10 → 1 s sign, 4008-byte sig → **zero latency win** (invariant #5). Structurally dead | One-time off-chain SIWE/auth *grant* |
| **EIP-7702 flows** (self-upgrade, sponsored EOA, EOA batching) | 7702 authorization is an ECDSA tuple signed by an EOA secp256k1 key (a/c); module ecosystem assumes v0.7/v0.8 (b); PQ1 has no EOA key and is already a full smart account | — |
| **Stealth-address spending** (ERC-5564/6538) | Needs a fresh secp256k1 key per receipt (a) + mints a new address, fighting the one-deterministic-address model (d) | Receiving-only + companion sweep (Tier 3, low) |
| **Circle Paymaster** (USDC gas) | v0.7/v0.8-only — cannot serve frozen v0.6 (b) | Pimlico `ERC20PaymasterV06` (v0.6) |
| **EntryPoint v0.7/v0.8 migration + ERC-7579 modules** | Bumping the EntryPoint changes the CREATE2 init-code hash → breaks same-seed→same-address (invariant #6) | Stay v0.6 (bundlers still serve it 2026) |
| **Coinbase Spend Permissions / ERC-7715/7710 delegation on PQ1's own wallet** | `SpendPermissionManager` is added as an *address* owner and calls `execute` directly; PQMultiOwnable accepts only 64-byte C10 owners and every `execute*` reverts unless `msg.sender==EntryPoint` | Safe-hosted spend modules + off-chain SIWE auth |
| **On-chain spend-limit / social-guardian MODULE on PQ1** | No module-install path on the frozen wallet; owners are same-seed C10 (no external EOA guardians) | S-world policy guard + C10-rotation / Safe-guardian recovery |
| **EIP-2612 / Permit2-ECDSA / EIP-3009 / Morpho `setAuthorizationWithSig`** | All verify via `ecrecover` over an ECDSA (v,r,s) a contract account cannot produce (c) | Direct `approve` / direct `setAuthorization` / Permit2-via-ERC-1271 once deployed |
| **Perps / orderbook (Hyperliquid, dYdX v4, GMX)** | Latency-hostile + onboarding derives an ECDSA agent/API key (c + frequency) | — |
| **Tight-RFQ / Dutch-auction quote-chasing on-device** | Quotes expire in seconds; 1 s sign + human confirm makes them stale | Single on-chain conditional/limit order |
| **Bulk per-order off-chain ERC-1271 DCA (100+)** | Each order bumps `local_offchain` with no backing UserOp → bricks at `MAX_OFFCHAIN_GAP=100` (cmd_sign_offchain.rs:317) | Single on-chain ComposableCoW / `setPreSignature` |
| **Passkey / secp256r1 (P-256) owner** | Needs a P-256 verifier on-device + in-contract; invariant #5 fixes a single c10Verifier | — |
| **Falcon / ML-DSA hybrid or any classical fallback** | Invariant #5 explicitly forbids a "just-in-case" signer | — |
| **x402 micropayments / retail tap-to-pay** | Rides EIP-3009/Permit2 ECDSA (c) + sub-second cadence | B2B/invoice stablecoin settlement |
| **On-device live EVM/fork simulation + "sim digest" on-device** | STM32U585 can't run a fork or fetch state (e); a non-reproducible digest is theatre | Companion sim (advisory) + device calldata decode (authoritative) |
| **On-device address book / blocklist / approval DB in flash** | Clashes with stateless-slot design (f) | Companion state + advisory markers |
| **Custodial seed-fragment backup / pre-signed drain-to-heir dead-man-switch** | Custodial fragments violate invariant #1; a pre-signed drain is a standing theft primitive, fragile vs nonce/cap drift | Safe + Zodiac Delay Modifier |
| **Single-share SLIP-39 (1-of-1)** | Same entropy as a BIP-39 seed, no security gain | Genuine k-of-n, k≥2 |
| **Plug PQ1 into MetaMask/Rabby/Frame as an HID hardware wallet** | They expect BIP-32 secp256k1 EOA sigs (a) | Connect *as a wallet* over WalletConnect/EIP-6963 |
| **Aztec / Tornado Cash classic / unvetted mixers** | Non-C10 L2 with no C10 verifier / sanctions+compliance risk | Privacy Pools (ASP model) |
| **Custodying any shielded-pool spend key in the SE** | Non-C10 + must be off-device for proof gen | PQ1 secures the public boundary only |
| **Master-key-rotating recovery (Ledger Recover, Safe social recovery *of* PQ1)** | Any master rotation changes the CREATE2 address (invariant #6) | Seed-only restore + duress decoy + C10 slot-owner rotation |
| **Auto-approve / allowance-based silent signing of small txns** | Defeats the deliberate, per-tx-confirm, high-assurance posture that is PQ1's entire value prop. A conscious *posture* rejection, not a capability gap | Every sign stays an explicit confirm |
| **Encrypted-mempool / front-running-protection signing** | High-frequency, latency-sensitive ordering (Shutter et al.); a 1 s deliberate signer adds nothing and the value lives at the bundler/builder layer (e) | — |
| **Native solo staking (32-ETH deposit + BLS withdrawal credentials / EIP-7002)** | The validator signing key is a separate BLS key, not a wallet-signing feature | Pooled staking (Lido/Rocket Pool/Kiln) |
| **Native ERC-7932 / EIP-8141 PQ-EOA migration** | These target PQ EOAs / native-AA and would require migrating off EntryPoint v0.6 → breaks invariant #6. Ride the standard by *publishing the reference verifier*, not migrating | Reference C10 verifier (Tier 3) |

---

## Where the lenses agree vs diverge

**Unanimous consensus (all three lenses rank it top-tier):**
- **Safe PQ co-signer** — #1 in security-first *and* PQ-narrative-first; the strategic wedge in mass-adoption too. The single most-converged candidate in the entire research set.
- **WalletConnect v2** — the explicit #1 in mass-adoption and the silent prerequisite under the dapp-driven half of the other two.
- **Long-term PQ cold vault** — top-4 in security and PQ-narrative; the "embrace the latency" posture both lenses lean on.
- **ERC-7730 descriptor pack** and **batch-revoke allowance manager** appear across all three as cheap, invariant-clean, high-leverage wins.

**The genuine strategic tension** is *only* about sequencing and emphasis, not feasibility:
- **Security-first** demotes connectivity entirely — it ranks the policy guard, Permit2 rendering, and recovery robustness above WalletConnect, because under a pure loss-minimization lens connectivity isn't a safety property.
- **Mass-adoption-first** inverts that — WalletConnect, gas sponsorship, portfolio, and fiat on-ramp are the funnel; the Safe co-signer is the *strategic wedge* but the everyday work is connectivity + table stakes.
- **PQ-narrative-first** pulls toward the moonshots that build mindshare — the reference verifier, attestation, the exposure-scanner funnel, ML-KEM backup — which the other two lenses park in Tier 3.

**Resolution.** They do not actually conflict. WalletConnect (Tier 0) is a no-regrets prerequisite under every lens. The two strategic flagships (Safe co-signer, cold vault) reuse shipped code and are top-ranked everywhere. Then the lenses differ only on *which Tier 1/2 cluster to fund first* — and the honest answer is to lead positioning + the next two flagship-enabling investments (Safe Tx Service client + adapter + gap-cap fix; companion Vault mode) with the **PQ-narrative + security** framing, while shipping the **mass-adoption** table stakes (portfolio, on-ramp, sponsored deploy) in parallel because they are independent and cheap.

---

## Open questions / things to verify before committing

These are the per-protocol / per-provider facts that should be confirmed from primary sources before the corresponding feature is funded:

1. **Gap-cap firmware fix (flagship-blocking).** Decide and implement the reconcile path for a deployed EIP-1271-only Safe co-signer: a firmware carve-out (don't count toward `MAX_OFFCHAIN_GAP` when `last_userop` can never advance) vs a companion-triggered no-op reconcile UserOp. **This is the one concrete firmware change the flagship requires** (cmd_sign_offchain.rs:317).
2. **Safe legacy-`isValidSignature` adapter.** Confirm the exact adapter shape (legacy `bytes,bytes → 0x20c13b0b` wrapping the modern `bytes32,bytes → 0x1626ba7e`) and that registering an adapter contract as a Safe owner passes `checkNSignatures` cleanly. PQSmartWallet itself must not be edited (init-code hash / invariant #6). **UPDATE 2026-10-20: superseded.** The legacy entry is now in `PQSmartWallet` (#995, audit freeze); `contracts/smart-wallet/test/LegacyERC1271.t.sol` runs it through a mock of Safe v1.4.1's `checkNSignatures` contract-signature branch. Live Safe confirmation waits for the freeze set to be deployed.
3. **v0.6 paymaster reality.** Verify Pimlico `ERC20PaymasterV06` (`0x6666…c68b`) is still live on each target chain in 2026 and confirm Alchemy's v0.6 sunset timeline; build multi-provider fallback accordingly. Confirm Circle Paymaster is still v0.7/v0.8-only.
4. **Zama FHEVM gateway (Confidential ERC-20).** Confirm whether Zama's gateway/KMS accepts a **smart-account EIP-1271** user-decryption authorization vs `ecrecover`-against-EOA. If EOA-only, a PQ1 user cannot view their own confidential balance → keep ERC-7984 out of the roadmap.
5. **Railgun key-import path.** Confirm from Railgun docs/SDK that the 0zk wallet can be derived from an **independently imported BIP-39 seed** (not only via a wallet-signature onboarding) — the research says yes (BIP-32 over Baby-Jubjub/Ed25519); verify the SDK actually exposes the import.
6. **CoW / 1inch Fusion contract-wallet acceptance.** "Supports ERC-1271" ≠ "solver backend accepts contract-wallet orders." CoW engineered this; 1inch Fusion / Dutch-RFQ acceptance is *inferred*, not verified. Confirm before promising off-chain Path-B intent swaps.
7. **Kohaku EntryPoint targeting.** Confirm the EF Kohaku 4337 relay targets EntryPoint **v0.6** (or is UserOp-version-agnostic) — PQ1 cannot migrate to v0.7/v0.8 (invariant #6).
8. **ERC-7683 / Across `depositV3` destination semantics.** Confirm the cross-chain order's `recipient` field is the value PQ1 should assert against its own `CMD_GET_WALLET_ADDRESS(destChainId)`, and that the gap-free `OnchainCrossChainOrder` path (not the Permit2 gasless variant) is the one to render.
9. **SLIP-39 vs custom GF(256) decision.** Decide the default before shipping Shamir: address-preserving custom GF(256) (recommended) vs cross-vendor standard SLIP-39 (different address). Marketing must never say "same seed, same address" for standard SLIP-39.
