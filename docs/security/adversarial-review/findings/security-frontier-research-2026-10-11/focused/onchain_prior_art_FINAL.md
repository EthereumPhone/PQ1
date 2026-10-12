# Prior art for an on-chain policy layer in a no-upgrade, single-signer 4337 wallet

Sources accessed 2026-10-12; no repository file was modified. Line numbers come from grep on downloaded source. "(doc)" marks prose read through a summarising fetch: sourced, but wording may be paraphrased. UNCONFIRMED means no primary source was found. The limitation column says whether a control binds the owner key.

Three findings cut across the topics:
- Almost every shipped cap binds a delegate and leaves the owner key free.
- On 1 June 2026 the Zodiac Delay and Roles modules were exploited through their own ERC-1271 check: the policy layer was the hole.
- I found no shipped design that delays or caps the owner's own EIP-1271 signatures.

## 1. Delayed execution with a cancel window

| Design | Shipped by / date | Mechanism | Limitation or incident | URL |
|---|---|---|---|---|
| Zodiac Delay Modifier | Gnosis Guild; Delay.sol changed 2026-06-05 | Modules enqueue a hash and timestamp. Anyone runs `executeNextTx` after `txCooldown` and before `txExpiration`. Strict FIFO. Cancel is `setTxNonce`, `onlyOwner` (L114) | Binds module callers only. The same owner sets the cooldown with no floor (L93) and enables modules, so there is no cancel-only role. A stuck head blocks the queue | https://github.com/gnosisguild/zodiac-modifier-delay/blob/main/contracts/Delay.sol |
| Gnosis Pay | Gnosis; docs read 2026-10-12 | Safe + Delay + Roles; the user's EOA acts through the Delay. Docs now give delay 25 h and expiry 31 h; earlier docs said 3 minutes (search summary) | 1 Jun 2026: the modules' ERC-1271 check ignored whether the call succeeded, which "let the attacker(s) queue withdrawals from accounts they did not own". About $1.5M taken; about $1.8M affected across 5,281 wallets (doc; byline 2026-07-03, page metadata 2026-10-06). Which delay was live that day is not stated | https://www.gnosis.io/blog/post-mortem-gnosis-pay-vulnerability-exploit and https://docs.gnosispay.com/concepts/safe/overview.md |
| Safe{RecoveryHub} | Safe; live by Dec 2023 | The recoverer is a Delay module. Default 28 days. Signers at threshold cancel | "there is no form of notification sent" (doc) | https://help.safe.global/en/articles/110656-account-recovery-with-safe-recoveryhub |
| Argent L1 | Argent; spec 2021-08-11 | Guardian and trusted-contact changes wait 36 h, confirmed before 48 h. Recovery finalises after 48 h. Before v2.5, over-limit transfers were pending 24 h | The owner-binding spend delay was removed in 2.5.0 (topic 2) | https://github.com/argentlabs/argent-contracts/blob/develop/specifications/specifications.tex |
| Argent X (Starknet) | Argent; repo pushed 2025-11-07 | Owner and guardian co-sign. Either alone may `trigger_escape_*`; default 7 days. An unused escape expires after a second period | A leaked key can burn fees with escape calls. Limited to one per 12 h plus a per-transaction fee cap | https://github.com/argentlabs/argent-contracts-starknet/blob/main/docs/argent_account_escape.md |
| Rhinestone ColdStorageHook | Rhinestone (ERC-7579); 2025-04-17 | The hook reverts direct execution on a sub-account. Only a transfer to one fixed `owner` address, or `setWaitPeriod`, can be requested, and it runs after `waitPeriod`. Module changes are timelocked too (`requestTimelockedModuleConfig`) | Owner-bound, by fixing the destination. No cancel function. No ERC-1271 handling | https://github.com/rhinestonewtf/core-modules/blob/main/src/ColdStorageHook/ColdStorageHook.sol |
| Revault | spec 2022-05-19 | A pre-signed Cancel "pays back to a deposit output". "watchtowers (or anyone else)" may fee-bump it | Needs live watchtowers | https://github.com/revault/practical-revault/blob/master/transactions.md |
| OP_VAULT (BIP-345) | 2023; status Closed, never activated | Recovery sweeps to a prespecified path until the withdrawal confirms. It is triggered by anyone who knows the path, or by a separate recovery-authorization key | Unauthorized recovery is replayable ("recover all such vaults at once"). A stolen authorization key "may grief", which is "not catastrophic"; lost with the trigger key, "likely coin loss" | https://github.com/bitcoin/bips/blob/master/bip-0345.mediawiki |

Implications:
- If a cancel can only return funds to a destination fixed in advance, the cancel right can be handed out cheaply: a thief of it can only grief. ColdStorageHook is the EVM form of that Bitcoin result.
- A cancel right held by the spending key is worthless here, and Zodiac's owner role is too strong to give a guardian. The wallet needs a narrow canceller role, and every parameter setter needs the spend delay.
- Apart from Gnosis Pay's former 3 minutes, shipped windows run from 24 h to 28 days. Prefer hash-keyed queue entries with expiry to a FIFO.

## 2. Spend limits

| Design | Shipped by / date | Mechanism | Limitation or incident | URL |
|---|---|---|---|---|
| Safe AllowanceModule | Safe; file 2026-02-19 | The Safe calls `setAllowance(delegate, token, amount, resetTimeMin)`. The module makes the transfer for the delegate | Owner-bound: no; owners use `execTransaction`. Per-token, no pricing | https://github.com/safe-global/safe-modules/blob/main/modules/allowances/contracts/AllowanceModule.sol |
| Zodiac Roles allowances | Gnosis Guild | Per-function scoping. `WithinAllowance` on one calldata uint, `EtherWithinAllowance` on value, `CallWithinAllowance` on call count (doc) | Owner-bound: no. Each call shape is scoped by hand. Hit by the June 2026 bug | https://docs.roles.gnosisguild.org/general/allowances |
| Gnosis Pay | Gnosis | Roles allowance for the card issuer, with a "hardcoded on-chain limit of $20K per token" | The cap binds the issuer's delegate. The owner is bound by the Delay only | https://docs.gnosispay.com/concepts/safe/overview.md |
| Argent daily limit | Argent; removed in 2.5.0, 2021-04-23 | Rolling 24 h, default 1 ETH, "cross-token (ETH + ERC20)" through an on-chain price oracle. Approvals counted. "Swapping tokens is not constrained by the daily limit" | Owner-bound: yes. Removed for gas cost: "pushing the daily limit to 0 which enables us to remove all the logic associated to it". Replaced by whitelists, dapp filters and guardian approval | https://github.com/argentlabs/argent-contracts/releases/tag/2.5.0 |
| Coinbase SpendPermissionManager | Coinbase; file 2025-04-08 | A singleton added as a wallet owner. A spender pulls up to an allowance per period of one token, native or ERC-20 | Owner-bound: no. A permission can be created from an off-chain signature (`approveWithSignature`, L293-305) | https://github.com/coinbase/spend-permissions/blob/main/src/SpendPermissionManager.sol |
| ERC-7715 via MetaMask enforcers | MetaMask; repo pushed 2026-10-06 | `ERC20TransferAmountEnforcer` requires calldata length 68 and the `transfer` selector (L87-97). Native variants cap `value`. `ERC20BalanceChangeEnforcer` compares balances before and after | Owner-bound: no. The balance-delta enforcer cannot see approvals and warns "use this enforcer at your own risk" | https://github.com/MetaMask/delegation-framework/tree/main/src/enforcers |

Implications:
- Nobody bounds ERC-20 value under arbitrary calls. Shipped designs let the policy contract make the transfer, pin the call to exactly `transfer(address,uint256)`, or allowlist targets and scope each function.
- The one owner-binding cross-token cap that shipped (Argent) needed a price oracle, a permanent dependency in a no-upgrade wallet, and was deleted for gas cost.
- A native-ETH-only cap exists as a building block. I found no wallet relying on it alone (UNCONFIRMED absence).
- An ETH cap on `execute` does not see fees. In v0.6 the wallet prefunds `requiredGas * mUserOp.maxFeePerGas` (EntryPoint.sol L325-332), and the gas cost at the op's own price goes to the `beneficiary` named by whoever calls `handleOps` (L47-49, L600-608). A thief can drain ETH that way unless `validateUserOp` bounds the fee fields.

## 3. The off-chain-signature bypass

| Design | Shipped by / date | Mechanism | Limitation or incident | URL |
|---|---|---|---|---|
| Safe fallback handler | Safe; tag v1.4.1 | `isValidSignature`: an empty signature requires `signedMessages[hash] != 0`, set on-chain through `execTransaction`; a non-empty one goes straight to `checkSignatures` (L28-39) | Guards and modules see only the on-chain path | https://github.com/safe-global/safe-smart-account/blob/v1.4.1/contracts/handler/CompatibilityFallbackHandler.sol |
| Coinbase Smart Wallet | Coinbase; file 2024-04-22 | `isValidSignature` checks an owner signature over `replaySafeHash(hash)` (L69-71). No hook, no caller argument | Nothing delays or limits it | https://github.com/coinbase/smart-wallet/blob/main/src/ERC1271.sol |
| Smart Sessions (ERC-7579) | Rhinestone, Biconomy; repo pushed 2025-10-15 | `isValidSignatureWithSender(sender, hash, sig)`. The EIP-712 content type must be allowlisted (`allowedERC7739Content`) and pass `I1271Policy.check1271SignedAction` | Session keys only. The root validator stays unrestricted | https://github.com/erc7579/smartsessions/blob/main/contracts/interfaces/IPolicy.sol |
| Verifiers accepting ERC-1271 | Permit2; USDC | Permit2 calls `isValidSignature` when `claimedSigner.code.length != 0` (L26-44). USDC `EIP2612.sol` uses a `SignatureChecker` with an ERC-1271 branch | USDC is exposed to permit by signature alone. CoW and Seaport not re-read here | https://github.com/Uniswap/permit2/blob/main/src/libraries/SignatureVerification.sol and https://github.com/circlefin/stablecoin-evm/blob/master/contracts/v2/EIP2612.sol |
| A cap or delay bypassed through a wallet's own 1271 | none found | | UNCONFIRMED after two extended searches. Nearest is Gnosis Pay, where 1271 inside the policy module was the flaw | |

Implications:
- The only shipped way to put 1271 under a delay is Safe's on-chain path, where a transaction registers the hash. Making that the only path is my inference, not a shipped default, and it would end gasless sign-in and ERC-6492 signatures.
- `isValidSignature(hash, sig)` sees only a hash. Classifying the content requires the typed-data preimage inside the signature blob, as ERC-7739 does.
- After one (usually unlimited) `approve` to Permit2, Seaport or CoW's relayer, every later drain needs only a signature. An execute-path policy sees that approve once and must treat it as an unlimited spend then.

## 4. ERC-4337 validation constraints (v0.6.0, released 2023-04-24)

| Item | Source | Text or behaviour | Consequence | URL |
|---|---|---|---|---|
| Packing | Helpers.sol L23-31 | `aggregator = address(uint160(vd))`; `validUntil = uint48(vd >> 160)`, and zero becomes `type(uint48).max`; `validAfter = uint48(vd >> (48 + 160))` | Bits 0-159 authorizer (0 valid, 1 signature failed), 160-207 validUntil, 208-255 validAfter | https://github.com/eth-infinitism/account-abstraction/blob/v0.6.0/contracts/core/Helpers.sol |
| Enforcement | EntryPoint.sol L466-473, L486-494 | `outOfTimeRange = block.timestamp > data.validUntil \|\| block.timestamp < data.validAfter`, then `revert FailedOp(opIndex, "AA22 expired or not due")` | Both bounds inclusive. `handleOps` reverts and the bundler bears it | https://github.com/eth-infinitism/account-abstraction/blob/v0.6.0/contracts/core/EntryPoint.sol |
| Account interface | IAccount.sol L30 | "Note that the validation code cannot use block.timestamp (or block.number) directly." | Time returns through validationData | https://github.com/eth-infinitism/account-abstraction/blob/v0.6.0/contracts/interfaces/IAccount.sol |
| ERC-4337 text of 2023-06-23 | eip-4337.md L365, L293 | Forbidden: "`GASPRICE`, `GASLIMIT`, `DIFFICULTY`, `TIMESTAMP`, `BASEFEE`, `BLOCKHASH`, `NUMBER`, `SELFBALANCE`, `BALANCE`, `ORIGIN`, `GAS`, `CREATE`, `COINBASE`, `SELFDESTRUCT`. They should only be forbidden during verification, not execution." Also: "A node MAY drop a UserOperation if it expires too soon" | Execution-phase code may read the clock | https://github.com/ethereum/EIPs/blob/9653a7e81c/EIPS/eip-4337.md |
| ERC-7562 | OP-011, STO-010 | Blocked list includes `TIMESTAMP (0x42)` and `NUMBER (0x43)`. "Access to the 'account' storage is always allowed." | A freeze flag or queue timestamp in the wallet's own storage is readable in validation | https://github.com/ethereum/ERCs/blob/master/ERCS/erc-7562.md |
| Bundler thresholds | reference bundler L52, L424-433; rundler; alto | Reference: `VALID_UNTIL_FUTURE_SECONDS = 30`, errors 'expires too soon' and 'time-range in the future' at submission. Rundler: 20 s buffer, checked when building a bundle. Alto: 5 s, only when `expirationCheck` is on | A not-yet-valid op is refused by the reference bundler | https://github.com/eth-infinitism/bundler/blob/master/packages/validation-manager/src/ValidationManager.ts and https://github.com/alchemyplatform/rundler/blob/main/crates/builder/src/bundle_proposer.rs |

Implications:
- The working pattern is shipped: store a timestamp when queuing, then return `validAfter = stored + delay`. Rhinestone's DeadmanSwitch does this (https://github.com/rhinestonewtf/core-modules/blob/main/src/DeadmanSwitch/DeadmanSwitch.sol).
- A short `validUntil` costs something only below about 30 s. The clockless device cannot check it, so the host picks it.
- An op queued for later cannot be parked with the reference bundler; someone must submit it after the delay.

## 5. Who gets to cancel or freeze

| Design | Shipped by / date | Mechanism | Limitation or incident | URL |
|---|---|---|---|---|
| Zodiac Delay owner | Gnosis Guild | One `onlyOwner` role cancels, sets the cooldown and enables modules (Modifier.sol L136-151) | No veto-only role exists. If the owner is the Safe and the user reaches it only through the Delay, a cancel queues behind the attacker's transaction (my inference) | https://github.com/gnosisguild/zodiac-core/blob/master/contracts/core/Modifier.sol |
| Argent L1 lock | Argent; develop branch | Any one guardian calls `lock()` (L194). The lock expires after 5 days. Any guardian unlocks. The owner may revoke a guardian while locked, after 36 h | I found no cooldown against re-locking | https://github.com/argentlabs/argent-contracts/blob/develop/contracts/modules/SecurityManager.sol |
| Argent X | Argent; 2025 | The guardian co-signs, so it vetoes by silence. The owner alone removes it after 7 days: "asymmetric in favor of the owners" | A guardian outage means a 7-day wait | https://github.com/argentlabs/argent-contracts-starknet/blob/main/docs/argent_account_escape.md |
| BIP-345 recovery authorization | 2023 | The key that triggers recovery is separate from the key controlling the destination | Stolen: grief only. Lost: no recovery | https://github.com/bitcoin/bips/blob/master/bip-0345.mediawiki |
| ERC-8238 draft | cmayorga; 2026-04; unshipped | Any one guardian pauses for at most 24 h. Early unpause needs the guardian multisig (doc) | The thread never mentions EIP-1271 | https://ethereum-magicians.org/t/erc-coercion-resistant-vault-spending-limits-timelock-multisig-against-5-wrench-attacks/28130 |

Implications:
- Shipped bounds on a veto-only guardian: automatic expiry (5 days; 24 h in the draft), an owner-only removal path with its own delay (36 h; 7 days), and a cancel that can only return funds to the owner.
- Named failure modes: griefing with a stolen guardian key, loss of the guardian key, fee burning.
- The owner key must not remove the guardian instantly, or the attacker does that first. Argent's 36 h is the precedent. `msg.sender == guardian` suffices for all of these.

## 6. Monitoring

| Service | Status / date | Mechanism | Limitation | URL |
|---|---|---|---|---|
| OpenZeppelin Defender, then Monitor | Announced 2025-06-30: "July 1, 2026: The Defender platform will officially retire" (doc). Actual shutdown not confirmed. `openzeppelin-monitor` is AGPL-3.0, pushed 2026-10-12 | Hosted service replaced by a self-hosted watcher | You run it | https://www.openzeppelin.com/news/doubling-down-on-open-source-and-phasing-out-defender and https://github.com/OpenZeppelin/openzeppelin-monitor |
| Tenderly Alerts | current | Triggers on event, function call, transaction result, balance or state change; delivers to email, Slack, webhook, Web3 Actions (doc) | Hosted. Automatic on-chain response not confirmed | https://docs.tenderly.co/alerts/intro-to-alerts |
| Forta | 2026 blog index centres on Forta Firewall | Detection bots; transaction screening | Per-address alert status UNCONFIRMED | https://www.forta.org/blog |
| Safe{Wallet}: Blockaid, Tenderly, Hypernative Guardian | Sept 2024; Nov 2025 | Scanning and simulation before signing. Guardian installs a Transaction Guard (search summary) | Pre-signature, or vendor-decided. Covers `execTransaction` only | https://help.safe.global/en/articles/470314-understanding-safe-shield-guardian-by-hypernative |
| Candide recovery alerts | current | Email and SMS when a recovery request appears, during its grace period (search summary) | Recovery only | https://docs.candide.dev/wallet/plugins/recovery-alerts-guide/ |

Implications:
- The closest shipped "alert tied to a cancel window" is Candide's, for recovery. I found none for spends (UNCONFIRMED absence).
- Safe ships a 28-day recovery window with no alert. A window needs a default alert path.
- Emit one indexed event per queued action and per registered signature hash, so any watcher works without a vendor. Hosted monitors disappear.

## 7. Hardware wallets that enforce policy

| Product | Date | Policy and where enforced | Limitation | URL |
|---|---|---|---|---|
| Coldcard SSSP | Firmware Mk4 5.4.4, Q 1.3.4Q | On-device: maximum per transaction, minimum blocks between spends read from PSBT `nLockTime`, whitelist, web 2FA (doc) | "The only way to disable SSSP without the Policy Unlock PIN is to destroy the seed and recover from a backup or seed words". A seed holder is unbound | https://coldcard.com/docs/sssp/ |
| Coldcard CCC | 2025; version UNCONFIRMED | On-chain 2-of-3. The device holds two keys; the policy key signs only if the rules pass (doc) | Policy logic is on-device and both keys sit in it. Whether the policy seed is displayed: UNCONFIRMED | https://coldcard.com/ccc-feature |
| Coldcard HSM mode | page updated 2026-10-01 | On-device rules with a velocity period; "There is no absolute concept of time on the Coldcard" (doc) | As SSSP | https://coldcard.com/docs/hsm/rules/ |
| GridPlus Lattice1 | Permissions announced 2020 | On-device auto-sign limits | UNCONFIRMED. `addPermissionV0` is absent from the current SDK | https://github.com/GridPlus/gridplus-sdk |
| Ledger Multisig | 2025-10-23 | Safe-based, for "teams, DAOs, and foundations". The announcement names no limit or delay (doc) | Not a consumer single-signer product | https://www.ledger.com/blog-ledger-multisig-secure-on-chain-governance |
| Ledger Enterprise | current | Amount ranges, whitelists, approval steps, enforced by Ledger's HSM (search summary) | Vendor infrastructure, off-chain | https://help.enterprise.ledger.com/helpcenter2/governance-rules-and-whitelists |
| Bitkey | Block | 2-of-3. The server co-signs up to a daily limit; hardware is needed above it (search summary; fetch blocked) | Vendor server | https://support.bitkey.world/hc/en-us/articles/18800126247060 |
| Liana with hardware signers | README 2026-01-28 | On-chain relative timelock on the recovery path only | The primary key is unrestricted | https://github.com/wizardsardine/liana |
| Trezor, Keystone, BitBox02, Passport | | No spending-policy feature found | UNCONFIRMED absence; vendor documentation not read | |

Implications:
- I found no shipped consumer product pairing a hardware signer with an on-chain delay and cap that bind that signer. It would be a first in that narrow form only; absence is not proven.
- Nearest neighbours: Gnosis Pay (consumer, on-chain delay, any EOA signer), a self-assembled Safe plus Zodiac Delay with a hardware owner, Coldcard CCC (on-chain multisig, on-device policy), Liana (recovery timelock).
- SSSP and HSM policies do not bind someone who holds the seed. CCC is stronger because the chain requires two keys.

## Five facts to re-verify yourself

1. v0.6 packing and the inclusive time check: Helpers.sol L23-31, EntryPoint.sol L486-494. https://github.com/eth-infinitism/account-abstraction/blob/v0.6.0/contracts/core/Helpers.sol
2. The June 2026 exploit was an ERC-1271 flaw inside the Delay and Roles modules. The fixed line is `return success && bytes4(returnData) == EIP1271_MAGIC_VALUE;` (zodiac-core SignatureChecker.sol L99). https://www.gnosis.io/blog/post-mortem-gnosis-pay-vulnerability-exploit
3. Safe's two 1271 paths, and that Permit2 and USDC accept contract signatures. https://github.com/safe-global/safe-smart-account/blob/v1.4.1/contracts/handler/CompatibilityFallbackHandler.sol
4. Fees are an uncapped outflow in v0.6 (EntryPoint.sol L47-49, L325-332, L600-608), and the reference bundler refuses ops that are not yet valid or expire within 30 s (ValidationManager.ts L424-433). https://github.com/eth-infinitism/account-abstraction/blob/v0.6.0/contracts/core/EntryPoint.sol
5. Argent removed its owner-binding daily limit for gas cost, in its own words. https://github.com/argentlabs/argent-contracts/releases/tag/2.5.0

Gap: Gnosis Guild's own disclosure of the June bug was not found. The same report is saved at /tmp/claude-1000/-home-nicola-repos-PQSigner-OS/7844318a-f4f1-49a2-b794-31ae48f548cc/scratchpad/log/report_final.txt, and the source log with every URL and line at /tmp/claude-1000/-home-nicola-repos-PQSigner-OS/7844318a-f4f1-49a2-b794-31ae48f548cc/scratchpad/log/sources.txt. Both are in the session scratchpad, which is not durable across a reboot.