COMMENT_ON: 69
---
**Custody of the vendor key: what a decision record has to state before the production key exists (2026-10-11 security frontier research, item X2b).**

State at master: the key is a passphrase-encrypted file, decrypted in the memory of a general-purpose PC for every signature (`fwsign/src/subcommands/sign.rs:210`, `fwsign/src/keystore.rs:130`). The only custody guidance is "an **offline** / air-gapped laptop" (`docs/firmware/how_to_make_update.md:26`). The first decision box in the note under #486 asks for a documented ceremony with "HSM" in the list (`docs/security/vendor-signing-key-compromise.md:92`), but this signature scheme is a bespoke parameter set and, by the research's reading, no hardware security module implements it. The key cannot be rotated once the bootloader is frozen (#486).

The research proposed a dedicated pq1 unit as the signing appliance. Its independent reviewer did not refute the idea, but found that three of its claims fail against the code, so it should not be costed as first written:

1. **The on-device signer is not deterministic.** `c10_sign_verified` always draws fresh randomness (`secure/src/crypto.rs:237`). "The appliance signs through the hardened signer" and "two appliances produce byte-identical signatures" cannot both hold. Byte equality across two signers needs either a new variant without that randomness, which removes a defence the code documents, or one unit exporting its random value to the other.
2. **Two appliances holding the same key are a consistency check, not dual control.** The bootloader accepts one signature (`fsbl/src/main.rs:345`), so either custodian can sign alone, and two units double the places the key can be extracted from. Real dual control needs two baked keys with both required. That is a freeze decision (#266, #486), and a second signature does not fit the manifest page.
3. **A counter on the appliance is per unit, not per key.** It cannot serve as the per-key signature cap of #225.

What the record has to state for every option, appliance or not:

- **The at-rest trade.** Today: a memory-hard key derivation over a passphrase of any strength. Appliance: a short numeric PIN whose strength is the secure elements' attempt counters, on chips whose lifecycle lockdown is still open (S-1, S-2, S-3). An appliance is better against remote malware on the signing host and worse against physical theft.
- **Key format and import.** The signer's key is a raw seed from the operating system's random source (`fwsign/src/keystore.rs:105`), not a wallet derivation. An appliance needs its own generate, back-up and import design.
- **Bootstrap.** The appliance's own bootloader bakes a vendor key and locks itself. Is the appliance signed by a throwaway key, never updated, or signed by the key it holds?
- **What a display would prove.** Showing a 32-byte digest is blind signing. The appliance would have to receive the preimage, hash it itself and show image hashes that an operator can compare with two independent reproducible builds.
- **Feasibility today.** A production-mode image with both secure elements cannot be built (`secure/src/nsc/mod.rs:316`), so no appliance can hold a production key before S-2 closes.

What can be done now, whatever is decided:

- [ ] Write the custody decision record (here or in the note under #486) with the options corrected as above. The appliance firmware itself is a later, owner-gated item; the research rates it P3 and large.
- [ ] Split `fwsign` so that the step holding the key sees only a digest. That is part of {{X2a}}, which carries the digest / sign / assemble split. The split keeps every custody option open, including a signer that is not a PC.

A reminder already made in the 2026-07-31 comment on #486: the HSM key of #67 is the factory-manifest key, a different key from this one.

No board dependency. **The record has to exist before the production key is generated**, because its public half goes into the bootloader, which cannot be changed after the first unit is locked.

Not checked: I did not survey HSM products; "no HSM implements it" is the research's statement.

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item X2b, section 12). Report priority P2 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
