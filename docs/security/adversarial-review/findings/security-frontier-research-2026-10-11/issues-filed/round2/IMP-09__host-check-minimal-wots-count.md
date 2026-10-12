TITLE: Host-side check that each WOTS+C count in a device signature is the smallest valid one (closes the smaller of two firmware covert channels; R stays open)
LABELS: enhancement,priority:medium,surface:companion,surface:docs,source:frontier-research-2026-10
---
## Summary

A malicious or modified secure image could, in principle, leak key material inside signatures that verify correctly (reasoned from how the scheme works; no proof of concept exists). Signatures go on-chain, so no radio would be needed. A SPHINCS+C10 signature has two fields the signer is free to choose and no verifier constrains: the 16-byte randomizer `R`, and one 4-byte grinding counter (`count`) per hypertree layer, in the one-time-signature part called WOTS+C. The honest signer always emits the first counter that works, and that counter is computed from public inputs only, so anyone holding the signature can recompute it and compare. This issue asks for that comparison in a host library and in the companion guidance. It is cheap and needs no firmware or wire change. It does not close the main channel: `R` is derived with the secret seed, so nobody outside the device can check it, and it carries far more bits. The research first proposed fixing `R` with a host-committed random input and found that proposal does not work (see Limits), so that original is not what is asked here. #238 tracks the documentation of this channel and nothing else does.

## What the code does today

Lines at master `c2fab970`.

- `sphincs-c10/src/wots.rs:73` to `sphincs-c10/src/wots.rs:82`: the signer tries `count = 0, 1, 2, ...` and returns the first value whose digit sum equals the target.
- `sphincs-c10/src/hash.rs:352`: the digest being ground takes a seed, an address, the message hash and the counter. The signing call passes the public seed in that position (`sphincs-c10/src/hypertree.rs:310` passes `&seed`, the padded public seed, and `sk_seed` as separate arguments), so every input is public or recomputable from the signature.
- `sphincs-c10/src/hypertree.rs:324`: the counter is written into the signature, once per layer.
- `sphincs-c10/src/wots.rs:183`: verification only checks that the digit sum matches. Any counter that works is accepted, not only the first. The on-chain verifier reads the counter from the signature the same way (`contracts/smart-wallet/src/verifiers/SPHINCsC10Asm.sol:156`) and does not check that it is the first.
- `sphincs-c10/src/fors.rs:117`: `R` is a hash over the secret seed, a label, the optional random input, the message and a nonce. `sphincs-c10/src/hypertree.rs:393`: the only thing a verifier checks about `R` is that the last index of the few-time-signature part (FORS) comes out zero.
- `secure/src/crypto.rs:237`: the optional random input is drawn inside the device with no host contribution.
- `sphincs-c10/src/lib.rs:320`: the crate's public `verify` function. A stricter host-only variant would sit next to it.

## What is already tracked elsewhere

- #238 asks to reword the documents that say this channel does not exist, and to add a threat-model row. It is documentation only and calls a protocol fix "an open research direction".
- #371 is about host-supplied entropy at seed creation. Different surface.

So this issue is only the host-side counter check, plus recording the decision that a real fix for `R` would need.

## Proposed work

- [ ] Add a host-only function next to `verify` (not used by firmware, not used on-chain) that re-grinds each layer's counter from zero and returns whether the counter in the signature is the first hit. Give it test vectors: an honest signature passes, and a signature re-signed with the second valid counter still verifies but fails this check.
- [ ] Describe the check in `docs/companion/companion-app-integration.md`: run it on every signature the device returns, before broadcasting, and treat a failure as "this device is not running reference firmware".
- [ ] State the cost: the honest grind is tens of thousands of hashes per layer on average (the comment at `sphincs-c10/src/wots.rs:60`), which is trivial on a host.
- [ ] Fold the result into the threat-model row #238 asks for, so the row says which channel is checked and which is not.
- [ ] Owner decision, unticked, no work until taken: whether to make `R` checkable by the host. The only design the research found that works makes `R` a public function of a device nonce committed in advance, a host value and the message, with the smallest valid grind nonce, over a two-round exchange. The price is stated under Limits.

## What it needs

Host library and companion documentation only. No firmware change, no wire-format change, no contract change.

## Limits

- **`R` remains.** A malicious image can put about 117 chosen bits into `R` per signature (16 bytes minus the 11-bit constraint) and nobody can tell. The counter check removes a second, smaller channel and leaves this one. On its own it does not stop a determined malicious image from leaking a seed.
- **Why the obvious fix does not work.** Committing the host to the random input, as Jade and BitBox02 do for ECDSA, fails here: `R` is hashed with the secret seed, no verifier re-derives it, so a malicious image can return an honest-looking transcript and still set `R` freely. This was the research's original proposal and its own review refuted it.
- **What a real fix costs.** A public `R` removes the secret-keyed protection the scheme relies on if the device's random source fails: with a predictable device nonce, a hostile companion could predict FORS indices. The two properties cannot both be had without a zero-knowledge proof. It would also change a signing primitive that has formal proof work attached. That is why it is an owner decision and not a task.
- A companion check only binds honest companions. A device that refuses to sign for some messages, or varies its signing time, still has a slow channel.
- The existing defence against malicious firmware is unchanged: the boot fingerprint, reproducible builds and the signed update path.
- The counter check was reasoned from the code. It has not been implemented or run.

## Related

#238, #371. Public precedent for host-checked signing randomness, for ECDSA only: [Blockstream Jade anti-exfil](https://blog.blockstream.com/blockstream-jade-tech-overview-part-1/), [BitBox02 changelog, v9.4.0 and v9.5.0](https://raw.githubusercontent.com/BitBoxSwiss/bitbox02-firmware/master/CHANGELOG.md). The research found no hash-based signer that has one.

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item IMP-09, section 1; status "redesign needed", only the narrower form is filed). Report priority P2 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
