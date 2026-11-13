# C10 autoresearch — round 4: what has not been tried

Advisor: Fable 5.2, 2026-11-12. Read-only, at head `d66b03a85`, including the ledger's "Round 4 (in progress)" notes. I built and ran nothing. Product-path findings are read from source; hash-path gains are estimates until the kit measures them.

## Summary

1. **Under `ui-px`, the time from confirm to the companion holding the signature does not depend on hash speed at all.** The signing film has a scripted minimum length, and the sign handler blocks on it before returning. From `pqsigner-ui-px/src/loading.rs` and `film_resolve`: any sign that finishes within 4.8 s of the film's start returns **8.65 s** after that start. Master's 3.4 s sign and today's 0.99 s sign both return at 8.65 s. Of that, the last 2.45 s is a hold on the result frame.
2. **That applies to the `ui-px` pilot only,** which CLAUDE.md keeps out of `make release`. On the legacy LCD path the equivalent is a 3,000,000-iteration `nop` loop after "Signed": my estimate is 0.1–0.2 s.
3. **USB adds host round trips on top of the ~70 ms you measured.** The device pages the result in ~250-byte `GET_RESPONSE` chunks: 17 host turnarounds for a normal sign.
4. **On the hash path I have one cheap untried item:** digest read-out through the `HASH_HRA` alias, 1–2%. Your round-4 probes have already settled DMA and software SHA; I agree with both verdicts and add the reasons they could not have worked.
5. **The one remaining large hash lever breaks the frozen format:** a one-block tweakable hash. By arithmetic on your floors it would roughly halve a pass. It is possible only before launch.

## Ranking: cheapest × biggest first

| # | Hypothesis | Gain | Confidence | Kit? | Cost |
|---|---|---|---|---|---|
| A | `ui-px`: return the signature before the result hold | −2.45 s to the companion per sign | High (constants in source) | No | Small; UI timing only |
| B | `ui-px`: decouple the film's minimum length from delivery | up to −5 s more on a 1 s sign | High on the number | No | Animation continues after return; owner and designer decision |
| C | Legacy LCD: drop the post-sign `nop` spin | −0.1 to −0.2 s per sign | Medium | No | Trivial |
| D | One framed HID response instead of `GET_RESPONSE` paging | −0.05 to −0.2 s per sign | Medium | No (needs NS + host) | Companion protocol change |
| E | Digest read-out through HRA0–3 with one load-multiple | −1 to −2% of a pass | Medium | Yes | Tiny; documented alias |
| F | Fewer film frames while hash-bound | −7 to −12% of hash wall time under `ui-px` | Medium | No | Owner UX decision; moot until A and B |
| G | Drop the DCIS clear and its entry check | −2% of a pass | High on the number | Yes | Removes an FI tripwire; I would not |
| H | Template loads through the C-bus alias | 0 to −2% | Low | Yes | Possible stale reads through the ICACHE |
| I | One-block tweakable hash ("C10 v2") | −45 to −50% of a pass | Medium | Yes, as a prototype | Breaks frozen formats and wallet addresses; pre-launch only |
| J | Same firmware on a 250 MHz part | −36% | Low-medium | No | Board respin; new silicon validation |
| — | GPDMA feed; software SHA in idle windows | none; ≤ 2.5% | Measured by you | Done | Dead |

---

## Product path (your items 5 and 6)

### A, B. The signing film sets the latency, not the signer

What the code does:
- `secure/src/nsc/cmd_sign_userop.rs` starts the film before the slot keygen and, after the signature is in the output buffer, calls `film_resolve(Ending::Signed)`. Only then does the gateway return. The off-chain and batch handlers make the same call at their success exits.
- `film_resolve` (`secure/src/ui/px/lcd.rs`) loops on `build_and_present` until `anim.film_done(t)`. Its doc says it "returns when the result has held `RESULT_HOLD_MS`".
- `film_done` is `film_t(now) >= T7 + RESULT_HOLD_MS` (`pqsigner-ui-px/src/loading.rs`).
- The timeline constants: `T_ORBIT` = 2,250 ms, then `REVS` = 3 turns of `TURN_MS` = 850 ms ("the film's MINIMUM length"), giving `T5` = 4,800; spiral to `T6` = 5,800; flash to `T7` = 6,200; hold `RESULT_HOLD_MS` = 2,450.
- `film_time` is the identity up to `T5`. If the answer arrives after `T5`, whole 850 ms turns are added until it does.

Consequences:
- An answer at or before 4.8 s: the handler returns at 6,200 + 2,450 = **8,650 ms after the film started.**
- An answer later than 4.8 s: 8,650 ms plus the lateness rounded up to a whole turn.
- So for the `ui-px` build, cutting the sign from 3.41 s to 0.99 s moves nothing the user or the companion can observe. The non-secure USB loop cannot send until the gateway returns.

I have not run this on a panel; it is a reading of the constants and the loop.

**A. Return before the hold.** The last 2,450 ms shows the result. Return once the result frame is painted, record a "do not overdraw before" time, and make the next secure draw wait out the remainder.
- Gain: 2.45 s to the companion on every `ui-px` sign. The glass shows the same thing.
- One caveat I did not resolve: the film-less resolve fades the check mark and caption in over about 0.35–0.5 s after the flash. If the film does the same, the truly static part of the hold is about 2.0 s, and the return point should be after the fade.
- Cost: a timestamp, a wait in the next draw path, and a check that lock and idle-wipe during the hold still leave the glass in the right state.

**B. Decouple the minimum length from delivery.** The scripted 6.2 s before the hold is a design decision about how signing should look. Delivery does not have to wait for it. Two ways:
- Return as soon as the signature is released and let the film finish from a secure timer interrupt, or from a small secure "film tick" call that the non-secure loop makes between HID reports. The next gateway call that draws must wait for, or cut, the running film.
- Or shorten the script when the work is fast: fewer minimum turns, or start the spiral when progress crosses a threshold.
- Gain on a 1 s sign: the companion gets the signature about 1 s after confirm instead of 8.65 s. On top of A that is up to ~5 s.
- Cost: the first form puts rendering in an interrupt or behind a non-secure-driven pump, which is new for the trusted display and needs its own review. The second changes the designer's timeline. Both are for the owner.
- Refusals are unaffected: there is nothing to deliver.

### C. Legacy LCD path

After a successful sign without `ui-px`, the handler shows "Signed" and runs `for _ in 0..3_000_000 { cortex_m::asm::nop() }`. Without cortex-m's `inline-asm` that `nop` is an out-of-line call (the driver's own comment says so for `dsb`), so each iteration is nearer ten cycles than three: about 30 M cycles, **0.1–0.2 s**. It holds the gateway the same way. A timestamped hold, as in A, removes it. This is the build shape that ships today.

### D. USB result transfer

Your round-4 note has the wire floor: 59 payload bytes per millisecond, ~70 ms for a 4.15 KB result. What it does not include:
- The transport's TX buffer is 256 bytes (`nonsecure/src/usb/transport.rs`), so the result is paged. The device answers `0x61xx` and the host must send a `GET_RESPONSE` for each ~250-byte page. A comment in `commands.rs` counts 17 pages for the 4,280-byte initCode.
- Each page is one host OUT report and five device IN reports, so the device-side floor is about 6 ms per page: ~100 ms for 17 pages, not 70.
- Each page also waits for the host to notice the previous one and send the next request. Through WebHID that is several milliseconds each. I would expect 0.15–0.3 s for a normal sign; I have no measurement.

Options:
- Let one framed response carry the whole result. The HID framing already has a 16-bit length; streaming from `SIG_BUF` avoids a larger TX buffer. This reaches your 70 ms floor with no host turnarounds.
- Bulk or WebUSB, as you note, for under 10 ms.
- Experiment: timestamps in the companion around the first `0x61` and the last page. No firmware change is needed to size this.

### F. Film cost while hashing

From `lcd.rs`: a CPU-bound frame starts every second panel refresh (`FILM_CPU_PERIOD_MS` = 28); a band render is budgeted at `BAND_RENDER_CYC` = 240,000 cycles for a 48 × 142 band, about 35 cycles per pixel; the strip stream already has a GPDMA path (`ui-px-dma`) and deferred bands. So DMA for the SPI stream exists; what remains is rasterisation.
- Halving the frame rate while hash-bound would take the film's share from 14% (your notes) or 25% (8 ms per 32 ms in the source) to half that.
- Drawing the orbit from pre-rasterised sprites would cut the per-pixel cost several times; that is work in `pqsigner-ui-px` and an atlas rebuild.
- **Neither matters while A and B stand.** With an 8.65 s floor, a film that slows a 1 s sign to 1.3 s is invisible.

### Other things I checked

- **Non-secure ↔ secure handoff:** one gateway call, a few KB copied each way. Negligible.
- **Interrupt load during a sign:** `consumption_mask::randomize()` runs from SysTick at 1 kHz, about ten cycles; with TE edges and the timeout tick it is well under 1%.
- **PendSV idle re-unlock:** not on the sign path.
- **USB during the secure call:** the endpoint NAKs for the whole call. With `ui-px` that is 8.65 s today. I did not check whether any host stack or the companion treats that as a stall.

---

## Hash path

### E. HR read-out through the alias

- The RM (§51.6.4, p. 2030) documents `HASH_HRA0`–`HRA4` at offsets `0x0C`–`0x1C`, identical to `HASH_HR0`–`HR4` at `0x310`, directly after CR, DIN and STR.
- Mechanism: four digest words in one load-multiple from `base + 0x0C` (about 5 cycles) instead of four 32-bit-encoded loads at `+0x30C…` (~2.6 each by your figure). If the loads stay separate, the small offsets at least allow 16-bit encodings.
- Gain: 3–5 cycles on every truncating digest, about 1.0–1.7 M cycles per pass, **1–2%**. Your profiler shows the read-out among the remaining non-engine costs.
- Output-identical; documented. A load-multiple restarted by an interrupt re-reads the same registers, which is harmless. The compiler will not merge volatile reads, so it needs a small `asm!` block for the read-out alone. Your full asm chain step lost to the compiler; this is four instructions inside its loop. `search128` reads HR3–7, and HR5–7 have no alias, so it gains less.
- Experiment: `chain_steps` only, one kit run.

### G. Dropping the DCIS clear

- INIT clears DCIS (RM p. 2033). The no-BUSY-wait variant in the tree still reads SR once per digest for the stale-DCIS check and still clears DCIS after read-out. Removing the clear makes that check meaningless, so both go: two accesses, ~5 cycles, **about 2% of a pass**.
- FI cost: a skipped INIT would leave DCIS set, the next poll would pass at once, and the read-out would return the previous digest. A silently stale digest is what the H-1 comments in the driver exist to prevent. The pass compare still refuses it. I would not take this.

### H. Template loads over the C-bus alias

- I expect little. The core issues one data access at a time, and with the ICACHE hitting, fetch is not competing for either bus.
- Hazard: reads in the code region pass through the ICACHE block, and RM Table 85 lists SRAM as "not recommended" for caching. If data reads through `0x0E00_xxxx` are cached, a template word rewritten through `0x3000_xxxx` (the chain index, once per chain) could read back stale. The byte gate would show it.
- Experiment: one pointer offset in `wots_chains16`. Wrong bytes means stale reads; right bytes and under 1% means drop it.

### Your DMA and software-SHA probes

Both verdicts stand, and neither could have come out differently:
- **DMA:** your 2.3 cycles per word is what a load-multiple and four stores already do, and the CPU has nothing to do with the time it gets back. A linked list could alternate control writes and data, but nothing in GPDMA can hold the next message's INIT until DCIS; pacing it from a timer would turn any jitter into a wrong digest. I did not read the whole trigger table, only searched it for HASH.
- **Software SHA:** at 5.3 k cycles per block, and with slices that must end before the engine does (every cycle the CPU is late costs the engine a cycle), your +2.5% is the ceiling. It would also have to stay on public data: SLotH's side-channel result is against CPU hashing of secret-dependent values.

### On the 17% headroom in your floor arithmetic

Your split is 72 M engine, 22 M un-overlappable block-1 feed, and ~20 M of BUSY wait, polling, read-out and control. E and G are both inside that last 20 M. Beyond #1151 and E, I do not see how to reach the rest: the poll and the two control writes per digest are what is left, and each is one bus access.

---

## Radical ideas, with their costs

### I. A one-block tweakable hash

The engine cost is per block, a context restore costs as much as a block, and every 96-byte preimage is two blocks. A preimage of at most 55 bytes is one.
- Shape: `seed(16) ‖ compact address ‖ value(16)` for chains and leaves; `seed(16) ‖ compact address(≤ 7) ‖ left(16) ‖ right(16)` for nodes; `seed(16) ‖ compact address ‖ node(16) ‖ count(4)` for the count grind. C10's address fields fit: tree index 9 bits, key pair 9, chain 6, position 3, FORS index 11, height 4.
- Block counts: chain step 2 → 1; node 3 → 1; count-grind try 3 → 1; WOTS PRF 2 → 1; `th_multi` 23 → 12.
- Effect, by arithmetic on your unit costs (a one-block digest at ~125 cycles: 14 words, one block, read-out): chains −31 M per pass, grind −11 M, FORS −7 M, PRFs −4 M, `th_multi` −1 M. **About −48% of a pass; a warm sign near 0.5 s with the cache.**
- The signature layout and size do not change. Every hash preimage does.
- Cost:
  - the on-chain verifier changes, so its codehash pins, the initCode hash and every wallet address change. Invariant 6 forbids that after launch;
  - every test vector, the Lean extraction and the EasyCrypt line citations for the hash layer are redone;
  - the security argument needs a pass. A pk-seed-prefixed single-block tweakable hash is the "simple" construction, but the compact address must keep every domain distinct;
  - it diverges from upstream SPHINCS-.
- CLAUDE.md says parameters are still renamable before launch. This is the only idea I have that moves the hash work by tens of percent, and it has a deadline.
- A kit prototype of the one-block chain step would test the 125-cycle figure without touching anything frozen.
- The standard SLH-DSA layout (seed padded to its own block) would not help on this peripheral. It depends on a cheap midstate, and you measured the restore at 108 cycles.

### J. A faster part

Cortex-M33 parts with a HASH peripheral exist at 250 MHz. If the peripheral is the same, cycle counts carry over and wall time scales by about 0.64. Cost: a board respin, a different lifecycle and debug-protection scheme on which invariant 10 would have to be re-derived, and every silicon receipt again. I have not checked pin, peripheral or lifecycle compatibility. A direction, not a finding.

### Not proposed

- Overclocking beyond 160 MHz: outside the datasheet, and it narrows glitch margins.
- Driving the chain from the DCIS interrupt so the film gets the idle time: interrupt entry and exit cost 30–40 cycles per digest, which slows hashing by 12–15%.
- Weakening parameters, the secure elements' SHA-256 over I2C, or anything touching the double compute or the reuse already rejected.

---

## Not checked

- No build or measurement. The 8.65 s figure is from constants and control flow, not from a panel.
- Whether the film's result fades in during the first part of the hold, which sets the earliest clean return point for A.
- The code around the `film_resolve` calls in the off-chain and batch handlers.
- Host-side HID turnaround per page; the 0.15–0.3 s is an estimate.
- The cycle cost of the legacy `nop` loop; 0.1–0.2 s assumes an out-of-line `nop`.
- Whether data reads through the C-bus alias are cached by the ICACHE.
- The GPDMA trigger table in full.
- Pin, lifecycle and peripheral compatibility of any 250 MHz part.
- The working tree also holds changes that are not mine: a modified `probe_pbkdf2/src/lib.rs` and new probe files.
