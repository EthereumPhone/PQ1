TITLE: fwsign: compute each vendor-key signature twice in separate processes and compare, keep a fail-closed signature ledger, and split digest / sign / assemble
LABELS: enhancement,priority:medium,surface:release,surface:fw-update,surface:sca-fi,source:frontier-research-2026-10
---
## Summary

`fwsign`, the host tool that signs firmware with the vendor key, computes the signature once and then verifies it. For this hash-based signature family, verifying after signing does not catch the fault that matters. A memory error while a subtree is being built can give a signature that still verifies, but in which a one-time key of the top tree has signed a wrong subtree root. A later honest signature that lands on the same one-time key then puts two different messages under one one-time key, which is the starting point of the published "grafting" forgery. The device already defends its own signing against this by signing twice and comparing bytes (`crypto::c10_sign_verified*`). The host signer holds the one key that can never be rotated once the bootloader is frozen (#486), and has no such defence. No issue tracks it: #592, #368 and #296 are about on-device paths, #225 is a signature count cap, #69 is key establishment.

The same change is the natural place to split the tool so that the step holding the key sees only a 32-byte digest. That split is also what any custody option other than "a laptop" needs (#69).

## What the code does today

- `fwsign/src/subcommands/sign.rs:262`: `let sig = key.sign(&digest);`. One pass.
- `fwsign/src/subcommands/sign.rs:271`: the only check is a self-verify of that one signature.
- `fwsign/src/keystore.rs:131`: the key signs with `sk.sign(msg_hash, None)`. `sphincs-c10/src/fors.rs:91` documents the `None` path as deterministic. Two honest passes over the same digest are therefore byte-identical, so a byte comparison is possible here with no change to the signature scheme.
- `sphincs-c10/src/params.rs:25` and `sphincs-c10/src/params.rs:31`: the hypertree has 2 layers of 512 leaves each. There is one top tree, so every signature uses one of 512 top one-time keys to sign a bottom-tree root.
- `fwsign/src/subcommands/sign.rs:355` (`record_signing`): the ledger line holds a timestamp, the version, the bundle path and the key fingerprint. It holds no digest and no signature, and nothing reads the ledger back. `fwsign/src/subcommands/sign.rs:359` skips the ledger with a warning when no data directory is found, and `fwsign/src/subcommands/sign.rs:363` ignores a failed directory creation. The comment at `fwsign/src/subcommands/sign.rs:174` says "the ledger is convenience, not" security.
- `fwsign/src/subcommands/sign.rs:210`: the key file is decrypted into the memory of the same process that parses the ELF files and packs the bundle.
- `fwsign/src/main.rs:284`: an `extract-sig` subcommand exists. There is no subcommand that inserts an externally produced signature, and none that prints only the digest.
- `docs/security/threat-model.md:211` and `docs/security/threat-model.md:317` describe the double-compute defence for Type 1 / Type 2 signatures. Neither says the host signer is outside it.

`fwsign/` is byte-identical between the research commit and master (no commits in between).

## What is already tracked elsewhere

- #69 covers establishing the key and its custody. A comment posted there the same day lists the custody decision inputs. This issue is only about what the tool does.
- #225 covers a per-key signature cap. A cap does not help here: the exposure is per fault, not per count.
- #592, #368 and #296 cover the same fault class on the device, not on the host.
- #486 and #266 cover the missing rotation path. They are the reason hygiene here is cheap relative to the loss.
- #742 covers a bootloader receipt in the release flow. Separate.

## Proposed work

- [ ] Split the signing step into `fwsign digest` (no key: builds the manifest, prints the preimage and digest), `fwsign sign-digest` (key: digest in, signature out) and `fwsign assemble` (no key: inserts the signature, verifies it, packs). Keep `fwsign sign` as a wrapper for bench use. No bundle or manifest format change.
- [ ] In `sign-digest`, compute the signature twice. Run the second pass in a fresh process that re-reads and re-decrypts the key file. Refuse to output unless the two 4,008-byte signatures are byte-equal and verify. (Two passes in one process share the decrypted key copy; a fresh process removes that shared state.)
- [ ] Ledger: key each entry on (vendor key fingerprint, digest). Store the signature and the top-tree leaf index it used. Fail closed when the ledger cannot be written, and when a digest that was signed before now gives different bytes. For any key other than the in-tree development key the ledger is mandatory.
- [ ] Archive sweep (a `fwsign` subcommand or a script): over all published signatures under one vendor key, any two that use the same top-tree leaf must carry identical top-layer one-time-signature bytes. This uses public data only, and it catches the cross-release case that the same-digest check misses.
- [ ] Tests under `fwsign/tests` that CI runs: equal passes accepted; one flipped byte in either pass refused; ledger divergence refused; missing ledger directory refused for a non-development key. Check the executed test count, because signing is slow in the debug profile.
- [ ] Docs: say in `docs/security/threat-model.md` that the double-compute claim covers on-device signing, and name what covers the host signer. This is independent of the rest and can land first.
- [ ] Record the items above as acceptance criteria for whichever production signer is eventually approved, so that they survive a rewrite of this bench tool.
- [ ] Owner decision, not part of this issue: whether the second pass may run on a second machine. That copies the only non-rotatable key to another host (#69, #266). A second pass after a cold reboot of the same offline machine is the lower-risk variant.

## What it needs

Host tool and CI only. No board, no firmware change. **It has to be in place before the production vendor key signs its first image.** The public half of that key is baked into the bootloader, and the bootloader cannot be replaced after the first unit is locked.

## Limits

- The research's independent reviewer rates this as cheap hygiene on an unrecoverable key, not as a live exposure. No production key exists (#69) and `make release` is a hard error today.
- An attacker-induced fault (Rowhammer class) needs attacker code on the signing host, where stealing the key is more direct. The realistic case is an uncorrected memory error on a machine without ECC memory.
- Only a fraction of faulted signatures still verify, and a forgery also needs a second signature on the same one of 512 top leaves. The cost of forging from two signatures under one one-time key of this target-sum variant is unmeasured; the reviewer's rough figure was explicitly unverified. There is no proof of concept.
- Two passes do not catch a fault that hits both passes the same way (the correlated case that #592 models for the device), and they do not catch a wrong but self-consistent key file.
- The archive sweep sees only signatures that were published.
- Sequencing: the 2026-09-28 comment on #742 mentions uncommitted `fwsign/` work in a local working tree. If any of it is still unlanded, do the subcommand split after it lands. The code statements above are about master only.
- The statement that verify-after-sign is insufficient for this fault class is the project's own position for on-device signing (`CLAUDE.md`, code conventions) and comes from the sources below. I did not reproduce a faulted signature.

## Related

#69, #225, #266, #486, #592, #368, #296, #742.

Sources as cited by the research (not re-fetched by me): [RFC 9814](https://www.rfc-editor.org/rfc/rfc9814.html), [Genêt, TCHES 2023](https://eprint.iacr.org/2023/042), [SLasH-DSA](https://arxiv.org/abs/2509.13048).

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item X2a, section 12; the digest / assemble split is from item X2b). Report priority P2 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
