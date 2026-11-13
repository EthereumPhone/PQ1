# C10 v2: one-block tweakable hash (DRAFT 0.3, for review)

Status: research draft for #1155. Nothing has landed. 0.2 on 2026-11-12, 0.3 on 2026-11-13.

**History.**

- **0.1:** first draft.
- **0.2:** folds in two independent adversarial reviews, GPT-6 Astra and Fable 5.2, both "adopt with changes, no blocking concern". Changes from 0.1:
  - the A7 bit layout (chain position byte-aligned);
  - WOTS_DIGEST field order;
  - a dedicated tweak for the last FORS root;
  - T_k tweak-first;
  - the H_MSG field order;
  - WOTS digits taken from the top of the digest (reverted in 0.3);
  - §3 rewritten, because 0.1 overclaimed;
  - stronger §7 gates;
  - v1 accounting fixes.
- **0.3:** WOTS digits go back to v1's position, the low 129 bits of the digest.
  - On the kit, top-bit digits bought nothing measurable: mean single-pass sign 78.55 M (top) against 79.35 M (low), over the same 16 messages, inside grind noise.
  - With v1's position, v2 runs v1's `wots::extract_digits` and `wots::digit_sum` unchanged, so the formally verified extraction code is not touched.
  - Nothing else changes. Keys (`pk_root`) are identical to 0.2; signatures and KATs differ.
  - **Nobody has reviewed 0.2's changes yet.** A review of 0.3 covers both.

## What changes and what does not

C10 v1 already has `N = 16` and masks `pk_seed` to 16 bytes. Its preimages are
long only because every field is laid out as a 32-byte EVM word: the seed and
every 16-byte value are zero-padded to 32 bytes, and the address (ADRS) is 32
bytes.

v2:

- drops the zero padding;
- replaces the 32-byte ADRS with a 7-byte compact address, A7.

Every chain step, tree node, FORS leaf, PRF call and grind try is then **one**
SHA-256 block (≤ 55 bytes).

**Unchanged:**

- the parameters: h=18, d=2, a=11, k=13, w=8, l=43, target_sum=205;
- the signature layout and length (4,008 B), and the key shapes (`pk_seed16`, `pk_root16`, `sk_seed32`);
- the FORS+C rule (the last FORS index must be 0) and the WOTS+C rule (the digit sum must be 205);
- FORS index and `ht_idx` extraction from H_MSG;
- WOTS digit extraction from WOTS_DIGEST (0.3: v1's low 129 bits);
- the R derivation, which is signer-only (§6).

**Changed:**

- every hash preimage (§2);
- so every `pk_root`, wallet address, signature byte and KAT;
- and the on-chain verifier.

## 1. Compact address `A7`

A7 is a 56-bit unsigned integer, serialized big-endian as 7 bytes. Every field
has a fixed position whatever the type, and unused fields are zero.
Constructors reject any field value that does not fit its width.

| bits | field | width | range used by C10 |
|---|---|---|---|
| 55..52 | `type` | 4 | 0..9 (table below) |
| 51 | `layer` | 1 | 0..1 |
| 50..33 | `tree` | 18 | hypertree `idx_tree` < 2^9; FORS `ht_idx` < 2^18 |
| 32..24 | `kp` | 9 | WOTS key pair (leaf) < 2^9; FORS tree index < 13 |
| 23..18 | `ci` | 6 | WOTS chain index < 43 |
| 17..16 | zero | 2 | |
| 15..12 | `cp` | 4 | WOTS chain position < 7; tree height 1..11 |
| 11..1 | `ha` | 11 | node / leaf index < 2^11 |
| 0 | zero | 1 | |

**Byte layout.**

- Bytes 0..3 are `type | layer | tree | kp`, constant for a whole key pair.
- Byte 4 is `ci << 2`.
- Bytes 5..6 are `cp << 12 | ha << 1`.

So `cp` is the top nibble of byte 5, and a chain step adds a constant to one
DIN word. Both reviewers checked every width against the code, including
hostile signatures: the verifier derives every field from masked digest bits or
bounded loops. The WOTS `count` is a separate `uint32` and never enters A7.

| type | name | used by | fields set |
|---|---|---|---|
| 0 | WOTS_HASH | chain step F | layer, tree, kp, ci, cp |
| 1 | WOTS_PK | T_43 | layer, tree, kp |
| 2 | TREE | hypertree node H | layer, tree, cp = height 1..9, ha = index |
| 3 | FORS_TREE | FORS leaf F (cp=0, ha=leaf) and node H (cp=height 1..11, ha=index) | tree = ht_idx, kp = FORS tree |
| 4 | FORS_ROOTS | T_13 | tree = ht_idx |
| 5 | WOTS_PRF | WOTS secret PRF | layer, tree, kp, ci |
| 6 | FORS_PRF | FORS secret PRF | tree = ht_idx, kp = FORS tree, ha = leaf |
| 7 | WOTS_DIGEST | WOTS+C count grind | layer, tree, kp |
| 8 | H_MSG | message digest | (none) |
| 9 | FORS_LAST | F over the last FORS slot | tree = ht_idx |

**Type 9 fixes a v1 defect.** v1 hashes the last FORS slot under
`(FORS_TREE, ht_idx, kp=12, cp=0, ha=0)` (`hypertree.rs:255`,
`SPHINCsC10Asm.sol:127`). That is the tweak of leaf 0 of FORS tree 12
(`fors.rs:156`), and both calls run in every sign. The two inputs differ unless
the slot equals that leaf's secret, but one tweak serves two roles, which the
tweakable-hash argument excludes. Not a demonstrated forgery.

## 2. Hash functions (`S` = `pk_seed`, 16 bytes; `||` = concatenation)

| function | preimage | bytes | v2 blocks (v1) | output |
|---|---|---:|---:|---|
| F (chain step, FORS leaf, FORS_LAST) | `S \|\| v16 \|\| A7` | 39 | 1 (2) | first 16 B |
| H (tree node) | `S \|\| L16 \|\| R16 \|\| A7` | 55 | 1 (3) | first 16 B |
| WOTS_PRF, FORS_PRF | `sk_seed32 \|\| A7` | 39 | 1 (2 and 1) | first 16 B |
| WOTS_DIGEST | `S \|\| m16 \|\| be32(count) \|\| A7` | 43 | 1 (3) | all 32 B |
| T_43 (WOTS pk) | `S \|\| A7 \|\| 0x00 \|\| v_0 .. v_42` | 712 | 12 (23) | first 16 B |
| T_13 (FORS roots) | `S \|\| A7 \|\| 0x00 \|\| r_0 .. r_12` | 232 | 4 (8) | first 16 B |
| H_MSG | `S \|\| root16 \|\| M32 \|\| R16 \|\| A7(type 8)` | 87 | 2 (3) | all 32 B |

Notes:

- **One-block functions put A7 last.** For one compression the order is
  immaterial; A7 last keeps the 16-byte values word-aligned for the HASH
  peripheral. Their lengths are all ≡ 3 (mod 4), so their last DIN word holds
  three bytes (NBLW = 24).
- **The multi-block T_k put A7 first**, after S and padded with one zero byte.
  The values stay aligned, and no tweak-free prefix can be shared across
  targets. With A7 last, an internal-state collision of the prefix would carry
  across every address. That is not a break below the security level, and
  tweak-first is free.
- **WOTS digits** are v1's: `digit_i = (D >> 3i) & 7` for i = 0..42, with D
  the WOTS_DIGEST output as a 256-bit big-endian integer, i.e. its low 129
  bits (bytes 15..31). The digit sum must equal 205. Draft 0.2 took the top 129
  bits instead; 0.3 reverts that (see History).
- **`m16`** in WOTS_DIGEST is the 16-byte node being signed. That is the FORS
  pk at layer 0 and the layer-0 root at layer 1; v1 zero-pads the same 16 bytes.
- **H_MSG** puts R last so that its first 64 bytes are constant across the R
  grind. That gains nothing on the U585, which has no usable midstate, but
  halves a host signer's grind. FORS indices and `ht_idx` are extracted as in v1.
- **The last FORS slot:** `roots[12] = F(S, A7(FORS_LAST, tree=ht_idx), slot)`.
- **Unchanged from v1:** chain positions, `count` placement in the signature,
  auth-path order and the left/right rule (`idx & 1`).

## 3. Domain separation (corrected)

**Claim:** for one key pair, the map from a *logical input* to the SHA-256 input
is injective. A logical input is (function role, address tuple, message
fields), and roles are as in §2.

Two cases are not collisions:

- **Re-evaluation of the same logical input** (sign and verify computing the same
  node) is the same input by design.
- **Grind tries** share one address and differ in `count` (WOTS) or `R` (H_MSG).

**Lengths:**

- The 39-byte inputs are F and the two PRFs. All carry A7 at bytes 32..39, with
  `type` at a fixed bit position, and their type sets are disjoint: F uses
  {0, 3, 9}, the PRFs {5, 6}.
- Every other length belongs to one role: 55 (H), 43 (WOTS_DIGEST), 712 (T_43),
  232 (T_13) and 87 (H_MSG).

**Within a role**, A7 is unique per logical call: the field tuple is unique, as
with v1's ADRS, minus v1's FORS_LAST reuse, now fixed by type 9.

**Across key pairs:** `S` or `sk_seed` usually differ. Distinct key pairs *may*
share `pk_seed`; the argument then rests on `sk_seed`, as in v1.

**Across versions:**

- v1 input lengths: 48, 80, 96, 103, 119, 128, 160, 480 and 1440.
- v2 input lengths: 39, 43, 55, 87, 103, 119, 232 and 712.

The shared lengths, 103 and 119, are the R-grind PRF (`fors.rs::grind_r`),
the same function in both versions. Every changed primitive therefore has
inputs disjoint from every v1 primitive. That matters because the KDF tags are
not changing (§5).

**What this argument is not:**

- It is an injectivity statement plus the ROM/QROM treatment of the simple
  tweakable hash (Hülsing–Kudinov, ePrint 2022/346).
- It is not a proof that SHA-256 behaves as independent random functions on
  unequal lengths.
- C10 has no parameter-specific reduction in either version.

## 4. Cost

On the U585 HASH a one-block digest costs about 19 + 66 + 2.6 × (DIN words)
cycles, from the 52-byte probe in the ledger. The 39-byte and 43-byte cases at
NBLW = 24 still need a kit measurement.

Fable's per-pass estimate from the ledger's unit counts is about −40% (range
−36% to −44%). Cached sign would go from 233 M to about 135–145 M cycles, with
no top cache. This is arithmetic, not a measurement.

**Measured at 0.3 (2026-11-13, kit, fused v2 entries, luck-averaged over 16
messages; ledger round 5):** mean single-pass sign 79.35 M against 110.10 M for
the v1 fused head (−27.9%); keygen 25.0 M against 36.8 M (−32%); verify about
106 k against 183 k (−42%). Estimated cached sign (2 passes + verify): 0.99 s
against 1.38 s. Forge verify gas: 163,186 against 180,812 (−9.7%).

**Measured earlier (2026-11-12):** on the generic oneshot path, about 250 cycles
of per-call overhead swamp the block saving. That is −5.7% on keygen, so the
gain exists only on the fused driver entries.

On-chain, the SHA-256 precompile costs 60 + 12 per 32-byte word. So:

| call | v1 gas | v2 gas |
|---|---:|---:|
| F | 96 | 84 |
| H | 108 | 84 |
| T_43 | 600 | 336 |
| T_13 | 240 | 156 |

The rest of the verifier's cost (calldata, mstore packing, loops) needs forge.

## 5. Scope

- **Wallet keys (bootstrap + slot) and the on-chain verifier: v2.** With them the
  codehash pins, the initCode hash and every CREATE2 address change. Invariant 6
  allows that pre-launch only.
- **Firmware signing stays v1 (default assumption).** The FSBL, fwsign and
  fw-manifest verify C10 v1, and flashed FSBLs are the trust root.
  `sphincs-c10` carries both versions.
- **KDF tags unchanged.** §3 shows the inputs are disjoint across versions.

## 6. Signer-only freedom (not part of the verifier contract)

**R.** R is checked only through H_MSG. v1's R-grind PRF is kept. A cheaper
derivation is a separate signer-only change: for example `K = PRF(sk, rand, M)`
once, then `R_i = SHA256(K ‖ be32(i))[..16]`.

**The last FORS slot.** Its value is opaque to the verifier, which only computes
`F(slot)`, and the same at every signature for one `ht_idx`. A signer may emit a
PRF value there instead of building FORS tree 12. That saves 6,142 digests per
pass. It is a track-C candidate, valid under both v1 and v2. It needs its own
review against the FORS+C argument and is not adopted here.

## 7. Gates (replace `golden.bin` identity, which is void for v2)

1. **Python reference** (`c10v2_ref.py`, from this spec): keygen, sign, verify
   and KATs. The verify checks both +C rules.
2. **Rust v2:** byte-identical to the Python KATs (pk_root and signature) over
   several keys and messages.
3. **+C-only near-misses.** Signatures that rebuild the *correct* root and break
   exactly one rule:
   - the WOTS digit sum at layer 0;
   - the WOTS digit sum at layer 1;
   - the FORS last index ≠ 0.

   Every verifier (Python, Rust, Solidity) must reject them. The existing v1
   clean-room Python verifier does not check the digit sum. Astra ran it on the
   frozen baseline, and it accepted `near-miss-WOTS-digit-sum`.
4. **Solidity v2:**
   - accepts every KAT;
   - rejects ordinary near-misses (a flipped bit in each region) and the +C-only set;
   - per-primitive preimage checks against Python, covering both left/right
     parities and nonzero counts. Packed 16-byte stores overlap, so they must
     run in ascending address order, with A7 stored last.
5. **Driver:** every fused v2 entry (39, 43 and 55 bytes at NBLW = 24) matches
   software SHA-256, including interleaving with v1 or FSBL digests that need
   NBLW = 0.
6. **Regression:** v1 golden, the v1 KATs and FSBL image identity are unchanged.
7. **Measurement:** kit v2 cached sign on the fused entries against the v1
   fused head; forge gas for v1 against v2.

**Gate status at 0.3 (2026-11-13).**

- **Met:** 1 (Python self-test); 2 (6 KATs, Rust = Python byte for byte); 3 in
  Python, Rust and Solidity, each near-miss mutation-controlled (deleting the
  WOTS sum check accepts exactly the two WOTS near-misses, deleting the FORS+C
  check accepts exactly the FORS one); 4 partly (KATs, bit flips, +C set,
  cross-version); 6 for v1 golden and KATs (suite 82/0, kit v1 golden);
  7 (figures in §4).
- **Kit golden for v2:** `golden-v2.bin` (0.3) equals Python, `host_v2` and
  `host_v2f`, and the kit's fused v2 build reproduces it byte for byte.
- **Not met:** the per-primitive preimage checks in gate 4; gate 5 as stated
  (per-entry differential and the NBLW interleaving test; the kit golden
  exercises the entries only end to end); FSBL image identity in gate 6.
