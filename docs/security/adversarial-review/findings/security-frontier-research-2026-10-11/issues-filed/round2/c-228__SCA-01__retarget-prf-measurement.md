COMMENT_ON: 228
---
The 2026-10 security research re-read the code of the signing pseudo-random function (PRF) against this issue's plan (its items SCA-01 and M15). The measurement is still the right next step. Four things about how it is aimed should change before bench time is spent. Lines are at master `c2fab970`.

**1. The "sk_seed-absorption window" is the wrong window for a correlation attack**

- `sphincs-c10/src/hash.rs:378`: `wots_secret` hashes `sk_seed`, the label, the layer, then a 32-byte tree field. `sphincs-c10/src/hash.rs:180` shows that field is zero in its first 24 bytes. So the first SHA-256 block is exactly `sk_seed`, "wots", the layer and 24 zero bytes: a constant per key and layer, with no varying known input. A fixed-versus-random test can still see it; a correlation attack has nothing to correlate against. The varying known words (tree, key pair, chain index) are all in the second block, which runs on a secret chaining value.
- `sphincs-c10/src/hash.rs:410`: `fors_secret` is one single block that mixes `sk_seed` with three varying known words (position, tree index, leaf index). That is the block where secret and known data meet in one compression.
- `sphincs-c10/src/fors.rs:148`: FORS leaves are walked in natural order. The per-signature shuffle reorders the trees (`sphincs-c10/src/hypertree.rs:214`), not the leaves inside a tree.

So the targets should be `fors_secret` first and the second block of `wots_secret` second. The varying words are small (the leaf index is 11 bits, the tree index is below 13), so this is not a textbook case either; that affects a later key-recovery attempt, not the leakage test.

**2. One secret-absorbing call is missing from the census**

- `sphincs-c10/src/fors.rs:117`: `grind_r` hashes `sk_seed` on every iteration of its search loop. It has no counter bump.
- `sphincs-c10/src/hash.rs:63`: the "secret-touching" total is `wots_secret + fors_secret` only, so the 70,754 figure this issue quotes excludes the grind.
- `tools/sca/README.md:620` still says of `grind_r` that it "NEVER reads `sk_seed`". That was true of an earlier, public-input version.
- [ ] Add a `grind_r` bucket to the hash counters, and correct the README paragraph.
- [ ] Split the census into "absorbs raw `sk_seed`" and "compresses on a secret chaining value" (see the comment on #229).

**3. A whole-signature trigger cannot isolate these calls**

- `secure/src/hw/sca_trigger.rs:26` documents a trigger around the whole hardened sign. No call site exists at master, so nothing fires today. Even when wired, one sign is seconds long and is run twice; one `fors_secret` compression is microseconds on the HASH peripheral.
- [ ] Build a bench harness image that calls `fors_secret` and `wots_secret` directly with chosen `sk_seed` and inputs, raises the trigger per call, and uses the `hw-sha256` path so that it measures the production primitive.
- [ ] Capture with the shuffle off first, to see the underlying leak, then with it on. Use 10,000 traces or more per set; 1,000 is too few to quantify what the shuffle buys.
- [ ] Report the maximum |t| against the number of traces, with the noise floor of the capture chain. Before the campaign, show the chain can detect a known leak (for example software AES on the same board). Two documents disagree on the capture chain: `docs/security/red-teaming.md:103` assigns power analysis to the oscilloscope with a shunt or current probe, and `docs/hardware/evt-silicon-validation.md:920` says it needs a ChipWhisperer that is not on the bench (the contradiction itself is listed in #866). A clean result at an unknown noise floor proves nothing.

**4. Add the consumption-mask arms to the same capture session (research item M15)**

The mask is production-mandatory and drives no load on either board (`secure/src/board/pq1.rs:327`: the pq1 pin is not connected). Whether it changes anything has never been measured, and #646 asks for trace evidence before any efficacy claim. One capture session can settle it:

- [ ] Three arms on an iota2 kit: mask off, mask on with the pin unloaded (as shipped), mask on with a resistor from the mask pin to ground, sized inside the pin's current limit.
- [ ] Report the maximum |t| and traces-to-detect per arm, raw and after a high-pass filter above 100 kHz. The filtered number is the one that counts: the duty changes once per millisecond against a 100 microsecond period, so an attacker can filter or subtract it.
- [ ] Keep everything else constant across the arms. The mask-off arm needs a non-shipping build, which also changes confirm and timing behaviour.
- The result feeds an owner decision: keep the mask as a production requirement, or demote it to an unvalidated noise source. A positive result on iota2 does not by itself justify changing the pq1 board, because the two parts have different packages and supply networks. Loading the pin on pq1 needs a new board and is not proposed here.

**Order across the bench issues**

The tunnel-crypto measurement in #236 should come first. It is the only half where a finding can be fixed in this hardware generation (by moving the tunnel AES onto the hardware AES block). A PRF leak found here can only be documented, as this issue's own disposition says.

Needs: the open bench board or an iota2 kit, a debug port, the trigger pin, an oscilloscope with a shunt or current probe in the MCU supply (a hand modification of a bench unit) or a near-field probe with amplifier. The harness image and the census change are firmware only.

Nothing here reopens masked SHA-2, SHAKE, or the PRF layout.

<sub>**Provenance.** Security frontier research, 2026-10-11 (report items SCA-01 and M15, section 4). Report priorities P2 and P3 are research ratings, not owner decisions. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
