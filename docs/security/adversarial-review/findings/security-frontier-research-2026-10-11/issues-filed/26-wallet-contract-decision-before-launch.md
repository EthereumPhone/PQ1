TITLE: Owner decision before the first user wallet: take #131 (per-key budget reset) and an optional guard hook in PQSmartWallet as one contract decision; a separate vault contract is the candidate for protecting savings
LABELS: question,priority:high,surface:contracts,surface:onchain,source:frontier-research-2026-10
---
## Why this is an issue and not only a document

`docs/security/vendor-signing-key-compromise.md:136-139` carries an unchecked box, "On-chain policy decision taken before wallet launch", with no issue behind it. `PQSmartWallet` has no upgrade path, so anything meant to live inside it must be in before the first user wallet. A focused research pass on 2026-10-12 looked at that decision. Its result is a narrower and more concrete question than the checkbox, and it needs an owner.

## What the pass found

1. **Savings can be protected without changing the wallet.** A separate vault contract controlled by the wallet address can hold them, delay every withdrawal, and offer one instant action that can only send the funds to a safe address fixed at creation. It can be deployed at any time, including after launch. So the checkbox's "now or never" is too strong for this part.
2. **Changing the wallet is not free today.** The implementation, factory and verifier are deployed on Base mainnet, audited, and bound to the formal proofs by code hash (`contracts/verification/docs/PINNED_CODEHASHES.md`); the factory address is compiled into the firmware. A change means a redeploy, a firmware constant change, a new audit and a proof re-run.
3. **What is still launch-bound:** protection of funds, approvals, off-chain signatures and fee payments at the wallet's **own** address. A vault cannot cover those. The only small way to keep that door open is an optional guard hook in the wallet (one address that is asked before each call and before each off-chain signature is accepted, and can only refuse; changes to it are delayed).
4. **#131 is launch-bound for a separate reason and changes the cost.** Removing a slot key and registering it again installs it at a new index with fresh counters (`contracts/smart-wallet/src/PQMultiOwnable.sol:175-193`, `:242-258`), which resets the per-key signature budget that invariant 7 is meant to protect. Every fix recorded for it (SOL9 in `docs/security/adversarial-review/onchain-contracts-adversarial-review.md:25`) changes the frozen contract. If #131 leads to a redeploy, the audit and proof cost is being paid anyway and the guard hook adds little. If #131 is accepted as a residual, the hook has to justify the whole cost alone.

## The decision

- [ ] #131: fix before launch (redeploy), or accept as a recorded residual.
- [ ] Guard hook in the wallet: add in the same redeploy, or decline and record that funds at the wallet's own address are unprotected against a leaked seed by design.
- [ ] Built-in vault mode in the wallet: the research recommends declining it in either case (largest change, largest new attack surface).
- [ ] Vault contract as a product feature: yes or no. If yes, write its specification before any code.
- [ ] Record the outcome at `docs/security/vendor-signing-key-compromise.md:136-139` and tick the box.

## If the vault is pursued: acceptance criteria from an independent review

The first draft of the design was attacked by an independent model before this issue was written. Its verdict was "revise before adopting". These are its points, which I checked against the source:

- **Deposit check on the device.** A hostile companion can present a vault whose safe address is the attacker's. Before any deposit the device must verify a pinned vault factory and code identity, the exact creation parameters, the chain, the controlling wallet, a non-zero delay, and that the safe address is not the wallet, the vault or zero. The user must still check the safe address against an independent source.
- **Recovery is a constant-cost state change with no external calls**, followed by separate permissionless sweeps per asset. Otherwise one reverting or blocklisting token blocks recovery.
- **Announcements are bounded:** fixed asset, recipient and amount; reserved against the balance present when made; with an expiry. Outflows are plain transfers only.
- **Recovery does not depend on the wallet.** One mis-signed operation can exhaust a slot key's budget (`PQMultiOwnable.sol:220-240`), so the recovery-code path must work with no call from the wallet and with gas paid from elsewhere.
- **One independent recovery code per vault per chain.** It is a bearer secret once revealed. It is a hash preimage, not a signature, so invariant 5 is untouched.
- **An independent watcher and a margin before the delay ends.** Owner and thief hold the same key, so the owner has to act early.
- **No signature checks, price oracle, setters or upgrade path in the vault.** On 1 June 2026 Gnosis Pay lost about 1.5 million dollars through the signature check of the Zodiac Delay and Roles modules ([post-mortem](https://www.gnosis.io/blog/post-mortem-gnosis-pay-vulnerability-exploit)). For the same reason the research recommends against using Safe plus Zodiac Delay as the vault.

## What this is worth

A plain account, which is what Ledger and Trezor keys control, can do none of this. The prior-art survey found no consumer product that pairs a hardware signer with an on-chain delay that binds that signer (an absence after search, not a proof). Against a leaked seed, which is what a display-bus implant yields, an on-chain delay with a safe-address escape is the only control found that still works.

## Evidence level

Contract source read; prior-art survey with primary sources; one independent model review (a second reviewer was unavailable). No vault code exists and nothing was tested. The research is section 13 of `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, which was not committed when this issue was filed.

## Related

#131, #381 (RAW32 off-chain signing decision). Report items CS-03 (on-device spending guard) and CS-06 (on-chain intent commitment, rejected).
