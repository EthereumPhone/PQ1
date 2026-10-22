# VULN — `CMD_GET_INIT_CODE` is an uncapped, unconfirmed bootstrap few-time-signature oracle

**Severity: LOW** (downgraded from HIGH on 2026-07-24 — see
[`UPDATE 2026-07-24 (b)`](#update-2026-07-24-b--severity-downgraded-to-low-firmware-cap-intentionally-absent)).
**This is not a path to steal funds.** No attacker in any reachable position can turn it into a
signature forgery, a key extraction, or a transaction the user did not confirm; every actor who can
reach the oracle already holds a faster, more direct route to the funds (see §2 of
`UPDATE 2026-07-10`). What remains is a **security-margin bookkeeping defect**: the firmware
produces bootstrap signatures on paths no counter observes, so the 65,536 figure the design's
security rationale rests on is not enforced anywhere. The absence of that enforcement is
[**deliberate**](#update-2026-07-24-b--severity-downgraded-to-low-firmware-cap-intentionally-absent)
— a hard firmware cap would risk a device that refuses to sign.
Historical note: the *original* HIGH rating (2026-06-30) was assigned on the theft-takeover
scenario in *Exploit chain* below, which the two quantification passes since have shown is not
reachable. Read that section as the mechanism, not as the risk.

> **STATUS: ACCEPTED / KNOWN TRADEOFF (per user/owner decision, 2026-06-30). WON'T-FIX — do not
> re-raise.** The owner accepts this as a deliberate tradeoff: `GET_INIT_CODE` stays silent (no
> `confirm()`) so the companion's `eth_estimateUserOperationGas` flow works without a button press,
> and the per-call OptRand randomization stays (SCA / Genêt TCHES-2023 defense), accepting the
> theoretical few-time erosion because the practical forgery threshold (~2^28–2^32 distinct
> bootstrap sigs vs a keygen-bound ~80 sigs/unlock-window) is orders of magnitude beyond reach.
> The fixes below are recorded for completeness only; they are NOT scheduled. Documented so future
> vuln sweeps skip it (same disposition class as the paymaster-unshown WON'T-FIX).

> **UPDATE 2026-10-22 — the silent window grows by 20 s per unlock.** `GET_INIT_CODE` now moves
> the idle deadline +20 s, once per unlock (owner decision; `timeout::grant_init_code_grace`,
> CLAUDE.md "NS does not control the inactivity timer"). It is still unconfirmed. Effect on this
> finding: per unlock, the host gains at most 20 s of extra unlocked time in which it can call
> `GET_INIT_CODE` silently — about one more bootstrap signature per unlock at the measured 13.6 s
> per call on pq1. The disposition above is unchanged (LOW, accepted); the per-unlock count it
> relies on rises by about one. A button-press consent on this command was considered the same
> day and not taken.

**Status:** ACCEPTED KNOWN TRADEOFF (found 2026-06-30; owner-classified WON'T-FIX same day;
severity corrected HIGH → **LOW** and the uncapped design confirmed **intentional** 2026-07-24).
Novel — not in the prior finding ledger.

> ⚠️ **READ [`UPDATE 2026-07-24`](#update-2026-07-24--the-threshold-in-the-2026-07-10-quantification-is-wrong-by-2700x-in-q-100-bits-of-margin) BEFORE ACTING ON ANYTHING ABOVE.** The
> "~2^28–2^32 signatures" threshold quoted in the STATUS block and in `UPDATE 2026-07-10` is
> **wrong** — it is the FORS *saturation* point, not the point where forgery work drops below the
> claimed 128-bit level. The real crossover is **99,375 signatures (1.52× the cap)**; at 2^28 the
> forgery costs 2^27. The won't-fix on *practical theft* still holds; its stated reasoning does not.
> A second path (the per-chain cap on a chain-independent key) was not considered by either pass.
>
> ⚠️ **AND THEN READ [`UPDATE 2026-07-24 (b)`](#update-2026-07-24-b--severity-downgraded-to-low-firmware-cap-intentionally-absent).**
> That update's "severity HIGH is unchanged" line is **superseded**: severity is **LOW**, this is
> **not a theft path**, and the missing firmware cap is a **deliberate availability choice**, not an
> oversight. Fix (B) (a hard firmware bootstrap cap) is **rejected** — do not implement it.

**Component:** `secure/src/nsc/cmd_get_init_code.rs` (CMD 15) + `secure/src/nsc/factory_calldata.rs`
+ `secure/src/crypto.rs` (`c10_sign_verified_with_progress`).

---

## Invariant violated

> **Scoping note added 2026-07-24 (b):** invariant #7 names the *on-chain* counters, and that is how
> it is now read. The bootstrap key's few-time budget is deliberately bounded by physical unlock
> cadence rather than a firmware counter — see
> [`UPDATE 2026-07-24 (b)` §2](#2-the-bootstrap-key-is-uncapped-on-purpose--do-not-add-a-firmware-cap).
> The gap described below is real as a description of the mechanism; it is not an action item.

CLAUDE.md **Non-Negotiable Invariant #7**: *"Per-chain caps monotonic, unresettable.
`bootstrapUses < 65,536` … No `reset*` or `increaseMax*` path. Exhausted chains stay frozen."*

The bootstrap (master, `ownerIndex == 0`) SPHINCS+C10 key is a **few-time** key. The cap
`MAX_BOOTSTRAP_USES = 65,536` exists precisely to bound how many signatures it ever produces,
so its FORS few-time security holds. `CMD_GET_INIT_CODE` lets a malicious companion drive the
bootstrap key to produce an **unbounded** number of distinct signatures, **off the books** —
no counter, no cap, no user confirmation.

## The defect

`cmd_get_init_code::run` (CMD 15, dispatched unconditionally at `nsc/mod.rs:1230`, present in
every production build) does, on **every** call, after only a `pin_verified` check and with
**no `confirm()` / OLED gate** (`cmd_get_init_code.rs:30-35`, "No OLED confirmation"):

1. Re-derives the **bootstrap** C10 secret key (`cmd_get_init_code.rs:231`).
2. Calls `factory_calldata::build` → `crypto::c10_sign_verified_with_progress(&c10_sk, &factory_digest)`
   (`factory_calldata.rs:77`), producing a **bootstrap signature** over
   `factory_digest = sha256("pqwallet-factory-add-slot" ‖ chain_id ‖ slot0PkSeed ‖ slot0PkRoot)`.
3. Returns the signature to the non-secure world inside the 4280-byte initCode.

There is **no firmware-side bootstrap-use counter** anywhere (grep: the only `reset_bootstrap_uses`
hits are *test assertions that such a function must not exist*; the lone real constant is the
on-chain `MAX_BOOTSTRAP_USES`). The on-chain `bootstrapUses` cap (`PQMultiOwnable.sol`) is bumped
**only** by Type-1 UserOps in `validateUserOp`; these factory-authorisation signatures are never
submitted as Type-1 UserOps, so the on-chain cap **never observes them**. `CMD_GET_INIT_CODE`
also does **not** call `timeout::reset_activity()`, and bumps no page-123 counter.

## Root cause — a randomization regression + a stale "safely reusable" comment

The handler's own doc comment (`cmd_get_init_code.rs:23-28`) asserts the factory signature is
*"identical byte-for-byte to what the eventual real sign will emit"* and *"safely reusable."*
That **was** true when C10 signing was deterministic. It is **no longer true**:
`crypto.rs:101-135` (work-todo #18 / Trezor parity) now draws a **fresh 16-byte OptRand per
signing call** (`rng_strong::fill`, 3-source TRNG XOR) and mixes it into the R-grind, so

> *"re-drawing per sign … would produce divergent sigs"* — `crypto.rs:123-125`.

The randomiser is drawn **once per call** only so the within-call double-compute FI gate
(`sig_a == sig_b`) passes; **across calls it differs**, so every `CMD_GET_INIT_CODE` invocation
yields a **distinct** signature over the **same** `factory_digest`, landing at a fresh,
pseudo-random hypertree leaf (`ht_idx`) and consuming **fresh FORS few-time positions** of the
bootstrap key. The SCA/Genêt randomization (good in itself) silently invalidated the
"deterministic, reusable, one-position" assumption that made an uncapped, unconfirmed
`GET_INIT_CODE` safe — and no counter/cap was added to compensate. The stale doc comment is the
fingerprint of the oversight.

## Exploit chain (theft, if the few-time threshold is reached)

1. Attacker = malicious companion app / compromised USB host. User has unlocked (PIN entered).
2. Companion loops `CMD_GET_INIT_CODE(account_index, chain_id)`. Each call returns a fresh,
   distinct bootstrap signature over `factory_digest`. No confirm, no cap, no counter.
3. After collecting enough distinct signatures to erode the bootstrap key's FORS few-time
   security, perform a SPHINCS+ few-time forgery: produce a bootstrap signature over a **new**
   message — a Type-1 `userOpHash`/`sphincsDigest` whose `callData` is
   `addOwnerBytes(attacker_slot_pubkey)`.
4. Submit that forged Type-1 UserOp. `PQSmartWallet._validateSignature` (ownerIndex 0) accepts
   the forged bootstrap signature → installs the attacker's slot key as a new owner.
5. Attacker signs Type-2 UserOps with the attacker-controlled slot → **drains the wallet**.

The on-chain `bootstrapUses` cap does not help: step 4 is the *first* on-chain bootstrap use; the
thousands–millions of oracle signatures in step 2 never touched the chain.

## Exploitation & honest caveat (why the severity needs a crypto number)

- **Rate limit.** Each call re-derives the bootstrap SK (~1 s) + a double-compute sign (~0.5 s) ⇒
  ~1.5 s/call. `GET_INIT_CODE` does **not** extend the 120 s idle window
  (`timeout.rs:17`, `TIMEOUT_TICKS = 120000`), so a companion gets ~80 signatures per
  *user-initiated* unlock. Reaching the cap (2^16) takes ~800 unlocks; reaching a larger
  few-time-break threshold scales linearly.
- **Few-time margin.** CLAUDE.md says the 2^16 cap is *"well inside the C10 birthday margin."*
  The *actual* forgery threshold is therefore meaningfully above 2^16; if it is ~2^32 the attack
  is centuries-long, if it is closer to ~2^20 it is plausible over a device's multi-year life
  against a persistent companion. **The crypto team should quantify the C10 (k=13, a=11, w=8)
  FORS+C few-time forgery threshold to fix the severity exactly.**
- **What is unambiguous regardless of the number:** a non-negotiable invariant (#7) is violated
  for the *most powerful* key in the system, via a path with **no counter, no cap, and no user
  confirmation**, and the safety assumption it relied on (deterministic, reusable factory sig)
  is provably false in the current code.

## Fix (any one closes it; do (A) regardless)

> **Dispositions as of 2026-07-24:** (A) is the only one still on the table (optional, pre-launch,
> availability-neutral). **(B) is REJECTED** — a hard firmware cap is the one change that can make
> the device stop signing; see
> [`UPDATE 2026-07-24 (b)`](#update-2026-07-24-b--severity-downgraded-to-low-firmware-cap-intentionally-absent).
> (C) was declined by the original owner decision (silent `GET_INIT_CODE` is required for the
> companion's gas-estimation flow).

- **(A) Deterministic factory signature.** Sign `factory_digest` with `opt_rand = None`
  (the R-grind already derives R deterministically from `sk_seed ‖ message ‖ nonce` when
  OptRand is absent — `crypto.rs:118`). Then repeated `GET_INIT_CODE` / counterfactual /
  INCLUDE_INIT_CODE calls return the **identical** signature, consuming exactly **one** few-time
  position — restoring the doc comment's "safely reusable" property and closing the oracle. The
  factory message is a fixed *public* authorisation, so dropping per-call OptRand here costs no
  meaningful SCA protection. **Also fixes the now-false doc comment** and the gas-estimation
  initCode-vs-real-sign divergence.
- **(B) Firmware bootstrap-use counter.** Mirror the per-slot `userop_sigs` page-123 tally with a
  durable per-`(account,chain)` *bootstrap* tally, bumped by **every** bootstrap-signing path
  (`GET_INIT_CODE`, `INCLUDE_INIT_CODE` in `cmd_sign_userop`, the ERC-6492 counterfactual in
  `cmd_sign_offchain`), and refuse past `MAX_BOOTSTRAP_USES`. This is the true firmware analogue
  of the per-slot cap that already backstops the slot keys.
- **(C)** At minimum, gate `GET_INIT_CODE` behind a `confirm()` (it produces master-key
  signatures) — though (A) is strictly better since it removes the few-time consumption entirely.

## Related

- Sibling (MEDIUM, firmware-backstopped): on-chain per-`ownerIndex` cap is resettable via
  `removeOwnerAtIndex` → `addOwnerBytes` re-add of the same slot pubkey at a fresh index
  (`PQMultiOwnable.sol:184/242`). Backstopped by the per-`slot_index` page-123 counter; see the
  memory note. Same class of bug: **on-chain caps key by storage index, not by key identity.**
  **UPDATE 2026-10-20: the sibling is fixed** (#131, Trail of Bits audit freeze).
  `removeOwnerAtIndex` was deleted; the owner set is append-only and `AlreadyOwner` refuses any
  key ever installed, so a key keeps one index and one set of counters for the wallet's life.
  This VULN (the GET_INIT_CODE bootstrap oracle) is unaffected by that fix.
- The per-*slot* keys are NOT affected by the GET_INIT_CODE oracle (it only signs with the
  bootstrap key). The slot keys are firmware-capped per `(account,chain,slot_index)`.

---

## UPDATE 2026-07-10 — practical-risk quantification (answers the "quantify the threshold" ask in *Exploitation & honest caveat*)

A follow-up USB-HID attack-surface sweep (5-agent adversarial audit + manual review) re-confirmed
this is the **only** USB-reachable, scriptable weakness on the whole surface — framing/reassembly,
command router, NS→S boundary + PIN gating, off-chain parsers, FW-update chunk staging, and the
USB-HID stack itself all came back clean. It also pins the crypto/rate numbers the caveat section
above left open. **Net conclusion: it is practically impossible to steal funds via this path; the
ACCEPTED / WON'T-FIX disposition stands.**

### 1. It is practically infeasible — the harvest is the wall, and it's measured in centuries

Two costs gate a forgery: harvesting the signatures, then the offline grind. The **harvest
dominates** and is throttled by the victim's own PIN cadence:

- **Forgery target:** ~2^28–2^29 distinct bootstrap signatures (FORS saturation for C10 `k=13,
  a=11` ⇒ ~2^18 hypertree instances × ~2^11 leaves ≈ 2^29 for straightforward forgery; somewhat
  fewer if trading signatures for offline hash-grinding). NB this yields **universal forgery**
  (assemble a signature on a chosen message) — **not** extraction of `sk_seed`, which stays behind
  a one-way PRF.
- **Harvest rate:** ~1.5 s/call, inside a **120 s idle window that `GET_INIT_CODE` does not
  reset** (S-only timer; USB/NS traffic cannot extend it) ⇒ **~60–80 signatures per
  *user-initiated* unlock**, then auto-lock. Keys are per-device, so **no cross-device
  parallelism** (forging device A needs device A's signatures).
- **⇒ Wall-clock to reach ~2^28 (~4 million unlock sessions):**
  | Victim behaviour | Time to harvest enough to forge |
  |---|---|
  | Realistic (~5 unlocks/day) | **~2,500 years** |
  | Heavy user (~50 unlocks/day) | **~250 years** |
  | Physically-absurd upper bound (victim unlocks 24/7, nonstop, does nothing else) | **~18 years** |
- The offline grind, once harvested, is comparatively trivial (days–weeks) and **cannot shortcut
  the harvest** (fewer signatures ⇒ grind cost blows back up toward full 2^128 security).

### 2. The unlock precondition makes it moot — anyone who can reach it already has a faster path to the funds

The oracle only fires on an **unlocked** device (correct PIN entered). There are exactly two ways a
device gets unlocked, and in **both** the attacker already holds a faster, more direct route to the
funds than a multi-century signature harvest:

- **Attacker has the PIN + the physical device.** They just unlock and confirm a send-all
  transaction on the trusted display — **instant, total drain**. The oracle grants them nothing
  they don't already have. (I.e. *with the right PIN you can already steal all the funds directly*;
  the oracle is a strictly worse, centuries-long detour to the same outcome.)
- **A compromised host piggybacks on the legitimate user's unlock** (this doc's canonical model).
  The host is capped at ~80 sigs per user unlock, and its *fastest* route to the funds isn't this
  oracle at all — it's social-engineering the user into confirming a malicious transaction on the
  trusted display, an unrelated attack that harvests nothing.

In every position from which the oracle is reachable, the actor already possesses a faster, more
direct path to the funds. **The oracle strictly dominates nothing**, and the harvest wall-clock
means there is **no realistic scenario in which it is exploitable to steal funds.**

### 3. Disposition unchanged; fix (A) remains the clean pre-launch closure

The quantification **supports** the original owner call — recorded here only to close the open
"quantify the C10 few-time threshold" question. The invariant-#7 violation is still real and worth
tidying **before mainnet value is on-chain**, and fix **(A) deterministic factory signature**
(`opt_rand = None`) remains the low-cost closure: it removes the cryptographic target entirely
(every harvested signature collapses to the single one already published on-chain at deploy), so
the safety margin no longer rests **solely** on the idle-lock throttle. Not scheduled; not a
blocker.

---

## UPDATE 2026-07-24 — the threshold in the 2026-07-10 quantification is wrong by ~2700x in q (~100 bits of margin)

**What changes:** the *practical-theft* conclusion of §2/§3 above **stands** — this is still not a
realistic route to stealing funds, for the reasons given there. What does not stand is the number
underneath it, and a second exposure path that no prior pass examined. Net effect: the wallet does
**not** meet its claimed NIST Cat-1 (128-bit) level in ordinary multi-chain use, with no attacker
involved at all.

### The methodological error

§1 estimated the forgery target as *"~2^18 hypertree instances x ~2^11 leaves ~= 2^29"*. That is the
**FORS saturation** point — where essentially every leaf of every tree has been revealed and forgery
becomes a certainty. It is not the point at which forgery becomes *cheaper than the claimed security
level*, which is what a Cat-1 claim requires and which arrives far earlier. Forgery work is

```
Work = 2^143 / E[gamma^12],    gamma ~ Poisson(q / 2^18)
```

(2^-11 for the FORS+C forced-zero R-grind x 2^-132 for the 12 binding FORS trees; the 13th tree is
forced to index 0, so its revealed secret is a per-position constant and contributes nothing.)

| q (sigs under ONE keypair) | forgery work |
|---|---|
| 65,536 = `MAX_BOOTSTRAP_USES`, one chain | 2^130.6 |
| **99,375 -- 128-bit crossover (1.52x the cap)** | **2^128** |
| 262,144 (4 chains at cap) | 2^121 |
| 1,048,576 (16 chains at cap) | 2^108 |
| 2^24 | 2^70 |
| 2^28 -- *the figure §1 assumed was the target* | **2^27.1** |

At the assumed-safe 2^28 the forgery is a laptop-seconds computation, not a wall. The margin at the
nominal cap is **2.6 bits**, and it decays as the *12th power* of q -- so q is the entire ballgame.

**Confidence.** Derived three independent ways that agree to the decimal: closed-form Poisson,
Monte-Carlo over sampled position multiplicities, and an independent transliteration of *both*
verifiers (Rust + the Yul `SPHINCsC10Asm`). The same model reproduces the official SPHINCS+-128s
(2^134) and -128f (2^131) parameter sets at their stated q_max = 2^64, i.e. it agrees with the
published sets that they meet 128-bit. It also agrees with this repo's own
`sphincs-c10/tests/fors_forgery_resistance.rs`, which asserts >= 2^128 **at exactly the cap** and
prints ~2^131 -- the test is correct; what is missing is anything that holds q at the cap.

Structural facts verified empirically (host-side, repo unmodified):
- At a repeated hypertree position the whole **1672-byte hypertree section is byte-identical**
  across signatures, so a forger reuses bytes 2336..4008 verbatim and needs only FORS leaves.
- `fors_secret(sk_seed, ht_idx, tree_idx, leaf_idx)` is position-bound, so per-position leaf sets
  are exactly what the model assumes.

### The path nobody analysed: the cap is per-chain, the key is not

Prior passes treated cmd 15 as the only way past `MAX_BOOTSTRAP_USES`. It is not the only one, and
the other needs no attacker:

`master = HMAC-SHA512("sphincs-c6-v1", bip39_seed)` carries **no `chain_id`** (slot keys do:
`slot_entropy = sha256(slot_master || "slot_entropy" || chain_id_be8 || slot_index_be4)`), while
`bootstrapUses` is per-proxy-per-chain storage in `PQMultiOwnable`. So the ceiling is
`N_chains x 65,536` on a **single** keypair. Four chains at cap = 2^121, below the claimed 128.
Cross-chain address identity (invariant #6, "same 24 words -> same address on every chain") is the
product's flagship feature, so this is the *intended* usage pattern eroding the *stated* security
level.

Second, the enforcement asymmetry is now explicit: `secure/src/offchain_state.rs` durably tallies
**slot** keys (`offchain_count` / `last_userop_count` / `userop_sigs`, checked *before* signing),
and there is **no bootstrap counterpart anywhere in the firmware**. On-chain `bootstrapUses` counts
only *submitted* Type-1 UserOps and structurally cannot see cmd-15 or ERC-6492 factory signatures.

### Exposure, stated honestly

- Harvest rate via cmd 15 is ~110 sigs per 120 s unlock window. The idle timer is **not** remotely
  resettable: the only `timeout::reset_activity()` reachable without a physical button press is in
  `cmd_fw_begin.rs:224`, which sits behind **two** trusted-display confirms. So §1's throttle
  argument holds.
- Reaching the 2^128 crossover: ~900 unlocks. Reaching a practical (<= 2^80) break: q ~ 2^23,
  ~76,000 unlocks -- out of reach. **Theft via this oracle remains impractical.**
- But the Cat-1 *claim* is breached at 4 chains with zero attacker effort, and §"Exploitation &
  honest caveat" above set its own bar at *"if it is closer to ~2^20 it is plausible over a
  device's multi-year life"* -- q = 2^20 gives 2^108.

### Disposition ~~(superseded by `UPDATE 2026-07-24 (b)` below)~~

> ⚠️ **SUPERSEDED same day.** The severity call and the fix-(B) recommendation in this paragraph
> were revised hours later; the *arithmetic* above stands unchanged. Kept verbatim for the honest
> history. Read the next section for the live disposition.

~~Severity **HIGH** is unchanged and correctly assigned.~~ The won't-fix on *theft risk* survives; the
**rationale must not** -- any future sweep that re-derives "~2^28 is safe" will reach the wrong
conclusion, since 2^28 is 2^27 work. Fix **(A)** (`opt_rand = None` on this path only) still closes
the oracle cheaply. ~~Fix **(B)** (a durable *global* bootstrap tally) is what invariant #7 actually
requires, and is now the load-bearing one, because (B) -- not (A) -- is what bounds the multi-chain
path.~~ Pre-launch, both are still free.

---

## UPDATE 2026-07-24 (b) — severity downgraded to LOW; firmware cap intentionally absent

Owner decision, same day, after walking the quantification above end-to-end. Two changes: the
severity was wrong, and the missing counter is a **design choice**, not a defect to be fixed.

### 1. This is not a path to steal funds — severity **HIGH → LOW**

Stated plainly, so no future sweep re-escalates it:

- **No theft.** There is no reachable sequence of commands by which an attacker obtains a signature
  over a message the user did not confirm, extracts `sk_seed` (it stays behind a one-way PRF), or
  moves funds. The forgery in *Exploit chain* is a real cryptographic mechanism at a signature
  count nobody reaches: ~8.8M signatures for a 2^80 forgery, ~24M for 2^64 — at ~110 sigs per
  user-initiated unlock that is **~80,000 and ~220,000 unlock sessions** respectively, i.e. decades
  of continuous compromised-host operation on one specific device. The signatures are also
  device-bound, so no cross-device parallelism.
- **No new capability.** Both positions from which the oracle is reachable (attacker holds PIN +
  device; malicious host piggybacking a legitimate unlock) already carry a faster, more direct
  route to the funds — see §2 of `UPDATE 2026-07-10`. The oracle strictly dominates nothing.
- **What is left** is a *bookkeeping* gap: the 65,536 figure that the C10 security rationale in
  `sphincs-c10/src/params.rs` and the `forgery_work_at_onchain_cap_exceeds_128_bits` test both
  assume is not enforced by any firmware counter, and the on-chain counter it *is* enforced by is
  per-chain while the master key is chain-independent. That is worth documenting accurately — the
  margin at the nominal cap is 2.6 bits and decays as the 12th power of q — but it is a
  margin/claim-hygiene issue, **not an exploitable weakness**. LOW.

### 2. The bootstrap key is uncapped **on purpose** — do not add a firmware cap

Fix (B) (a durable global bootstrap tally that *refuses* past a threshold) is **rejected**, and the
reason is availability, which outranks the theoretical margin here:

> A cap that the firmware enforces is a cap that can **fire on a legitimate user**. If some owner
> genuinely drives the bootstrap key past X signatures — many chains, an unusually chatty companion
> doing per-transaction gas estimation, years of counterfactual `GET_INIT_CODE` calls, a
> re-provisioning loop, a bug in a third-party companion — a hard cap means the device **stops
> signing and never signs again**. The bootstrap key cannot be rotated (invariant #6: the CREATE2
> salt is derived from it, so rotating changes the wallet address on every chain), so there is no
> recovery: the wallet is bricked for slot registration, on every chain, permanently.

Weigh that against what the cap would buy: protection against a forgery that needs ~10M signatures
and tens of thousands of unlock sessions. **A device that refuses to sign is a certain loss of
access; the forgery is not a realistic loss of funds.** The trade is not close. The same reasoning
applies to any softer variant that can still refuse (per-chain firmware cap, cap-with-override,
lockout-on-threshold) — the failure mode is the same brick.

Consequences that bind future work:

- **Do not implement fix (B) or any bootstrap-signing refusal path.** A future sweep that reads
  invariant #7 literally will want to; this section is the standing answer.
- **Non-refusing observability is acceptable** if anyone wants it: a durable *count* with no
  enforcement, or a display/companion-visible tally, is fine — it must never gate a signature.
- **Fix (A) remains the only mitigation on the table** (`opt_rand = None` on the factory-signature
  path only): it makes repeated `GET_INIT_CODE` / counterfactual calls return the *identical*
  signature, so they consume exactly one few-time position instead of a fresh one. It shrinks q at
  the source and **cannot ever refuse to sign**, which is precisely why it survives this decision
  while (B) does not. Optional, pre-launch, cheap; not a blocker.
- **Invariant #7 should be read as scoped to the on-chain counters it names.** The bootstrap key's
  few-time budget is deliberately bounded by the physical unlock cadence and the 120 s idle timer,
  not by a firmware counter. If CLAUDE.md's invariant #7 wording is ever tightened, it must not be
  tightened into requiring a bootstrap refusal path.

### 3. What stays true from the earlier passes

The arithmetic in `UPDATE 2026-07-24` is unaffected and remains the reference: forgery work is
`2^143 / E[gamma^12]`, the 128-bit crossover is 99,375 signatures, and **2^28 signatures is 2^27
work, not a wall**. Anyone re-deriving the risk must start from those numbers, then apply the
disposition here — not from the retracted "~2^28-2^32 is safe" figure in the STATUS block.
