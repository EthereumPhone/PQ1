# SPHINCS+C10 ↔ FIPS 205 (SLH-DSA) delta-audit

**Status:** reference / audit ledger. First written 2026-06-12.
**Scope:** the production C10 signer (`sphincs-c10/`, Rust) and the production
on-chain verifier (`contracts/smart-wallet/src/verifiers/SPHINCsC10Asm.sol`,
Yul). Does **not** cover the Lean spec layer (`contracts/verification/lean/`),
which is audited separately — see [§9](#9-relationship-to-the-lean-spec-and-a31).

---

## 0. What this document is, and is not

This is a **one-time, line-grounded map** of every algorithm in NIST
FIPS 205 (SLH-DSA, Aug 2024) to its C10 counterpart, classifying each as one
of:

- **SAME** — structurally identical to the FIPS 205 algorithm (modulo the
  parameter set and the hash instantiation, which are tracked separately).
- **DEVIATES (SPHINCS+C)** — an intentional structural compression from the
  *SPHINCS+C* proposal: Hülsing et al., "SPHINCS+C: Compressing SPHINCS+
  With (Almost) No Cost" (NIST PQC 2022 workshop; IACR ePrint 2022/778).
  The in-repo citation lives in the Lean spec layer,
  `contracts/verification/lean/SphincsCVerify/Spec/Params.lean:13-17`; the
  crate itself uses the construction names (`W+C_F+C`, `lib.rs:3`) and
  credits its reference implementation, the Python signer at
  `github.com/nconsigny/SPHINCS-` (`lib.rs:13-15`). The two techniques —
  grind a `count` to fix the WOTS digit sum and drop the checksum chains
  (WOTS+C), and grind `R` to force the last FORS index to zero and drop one
  auth path (FORS+C) — are **not** part of FIPS 205 (verified by full-text
  scan — see [§3.2](#32-wots--wotsc-alg-58) / [§3.5](#35-fors--forsc-alg-1417)).
  Related later NIST-track work on the same size-reduction ideas: Fluhrer &
  Dang, "Smaller Sphincs+" (ePrint 2024/018) and the SP 800-230 draft track —
  i.e., grinding-style parameter compression is an active standardization
  direction, just not in FIPS 205 today.
- **DEVIATES (C10 design)** — an intentional deviation specific to *this*
  wallet's parameter choice or instantiation, with no external standard to
  cite; the citation is the frozen production artifact itself.

It exists for two reasons:

1. **Reviewer onramp.** A cryptographer who knows FIPS 205 can read this and
   know exactly where C10 stands relative to the standard, without
   reverse-engineering 233 lines of Yul.
2. **Accidental-deviation catch.** The class of bug that A3.1 was — a layout
   that silently diverged from intent — is caught by forcing every line of
   the two production artifacts to be classified against an external
   reference. This audit found **no new unintended divergence**: the Rust
   signer and the Yul verifier agree byte-for-byte on every offset, ADRS
   field, preimage, and bit-extraction examined below
   ([§8](#8-cross-artifact-consistency-the-core-finding)).

**C10 is not SLH-DSA and does not claim to be.** It shares the hash-based
hypertree *skeleton* with FIPS 205 but uses a different parameter set, a
different hash instantiation, a different ADRS encoding, a different message
randomizer, and two structural compressions (WOTS+C, FORS+C) that FIPS 205
does not contain. Its lineage is the round-3 SPHINCS+ submission
(`sphincs.org`) plus SPHINCS+C (ePrint 2022/778), adapted into a
wallet-specific, hardware-sized instance (the C10 tuple is deliberately not
one of the paper's table sets — `Spec/Params.lean:19-22`). Any public
statement must say "SPHINCS+C variant, parameter set C10" and never
"FIPS 205" / "SLH-DSA" / "NIST-standardized".

---

## 1. Verdict (TL;DR)

| Axis | Relationship to FIPS 205 |
|------|--------------------------|
| **Hypertree skeleton** (FORS → d-layer XMSS/WOTS Merkle walk → root compare) | SAME shape |
| **Parameter set** | DEVIATES (C10 design) — custom shallow `h=18,d=2,w=8`; not a FIPS set |
| **WOTS chaining + recovery** | SAME (WOTS+ chain direction) |
| **WOTS checksum** | DEVIATES (SPHINCS+C) — *no checksum*; count-grinding to a fixed digit-sum |
| **FORS structure** | SAME shape (k trees, height a, treehash) |
| **FORS last tree** | DEVIATES (SPHINCS+C) — *FORS+C* forced-zero index drops one auth path |
| **Hash instantiation** (`H_msg, PRF, F, H, T_l`) | DEVIATES (C10 design) — different preimages, no MGF1, no 64-byte seed block, uncompressed ADRS, ASCII-tagged PRF |
| **ADRS encoding** | DEVIATES (C10 design) — 32-byte uncompressed, field widths differ |
| **Message digest split / index extraction** | DEVIATES (C10 design) — LSB-first bit windows, different field offsets |
| **API boundary** (context string, prehash) | DEVIATES (C10 design) — none; bare 32-byte message hash |
| **Rust signer ↔ Yul verifier agreement** | **CONSISTENT** — no unintended divergence found |

---

## 2. Parameter-set delta

FIPS 205 §11 Table 2 defines six standard sets. The two SHA-2 category-1
sets, beside C10:

| Param | SLH-DSA-SHA2-128s | SLH-DSA-SHA2-128f | **C10** | `params.rs` |
|-------|------|------|------|------|
| `n` (security bytes) | 16 | 16 | **16** | :19 |
| `h` (total HT height) | 63 | 66 | **18** | :22 |
| `d` (HT layers) | 7 | 22 | **2** | :25 |
| `h'` (subtree height) | 9 | 3 | **9** | :28 |
| `a` (FORS tree height) | 12 | 6 | **11** | :37 |
| `k` (FORS trees) | 14 | 33 | **13** | :34 |
| `lg_w` | 4 (`w=16`) | 4 (`w=16`) | **3 (`w=8`)** | :43-46 |
| `m` (msg digest bytes) | 30 | 34 | **≈21** (161 bits used) | derived |
| signature bytes | 7856 | 17088 | **4008** | :79 |
| public-key bytes | 32 | 32 | **32** | :85 |

**Classification: DEVIATES (C10 design).** C10's hypertree is deliberately
shallow — `h=18` gives only `2^18 = 262,144` signing positions vs the standard
`2^63`/`2^66`. This is sound *only* because the wallet caps on-chain use at
`MAX_BOOTSTRAP_USES = MAX_SLOT_USES = 65,536` per chain (well inside the
`2^18` position space and the C10 birthday margin; see
`SPHINCsC10Asm.sol:6-10` and the non-negotiable invariant #7 in `CLAUDE.md`).
`w=8` (not 16) trades a longer signature for fewer hash chains. **No FIPS 205
parameter set is used or claimed.**

> Derived check (signature size): `R(16) + FORS(k·n + (k−1)·a·n) +
> d·(l·n + 4 + h'·n)` = `16 + (208 + 2112) + 2·(688 + 4 + 144)` = `2336 +
> 1672` = **4008** ✓ (`params.rs:62-79`, asserted at compile time `:89-91`).

---

## 3. Algorithm-by-algorithm map

FIPS 205 numbering follows the **final standard** (Aug 2024), Algorithms
1–25. (The initial public draft numbered these one lower; the final inserted
`gen_len2`=Alg 1 and `toInt`=Alg 2.) For each: the C10 counterpart, its
location, and the classification.

### 3.1 Low-level conversions (Alg. 2–4)

| FIPS 205 | C10 counterpart | Where | Class |
|----------|-----------------|-------|-------|
| **Alg. 2 `toInt`** | big-endian `u32/u64::from_be_bytes` in ADRS unpack | `address.rs` | SAME |
| **Alg. 3 `toByte`** | `to_be_bytes`, `u64_to_b32` | `hash.rs:178-191` | SAME |
| **Alg. 4 `base_2b`** | `extract_digits` (WOTS), `read_bits_le` (FORS/HT) | `wots.rs:16-47`, `fors.rs:19-34` | **DEVIATES (C10 design)** |

**`base_2b` deviation.** FIPS 205 `base_2b` (Alg. 4) consumes the message
digest **MSB-first** (big-endian bit order — confirmed: the pseudocode is
`total ← (total ≪ 8) + X[in]` then `(total ≫ bits) mod 2^b`). C10 reads
**LSB-first 3-bit windows**:
`digit[i] = (digestWord >> (i·3)) & 7`, scanning up from the least-significant
bit of `digest[31]` (`wots.rs:27-46`; mirrored in Yul
`SPHINCsC10Asm.sol:175` `and(shr(mul(i,3),d),0x7)`). The FORS/HT extractor
`read_bits_le` uses the same LSB-first convention (`fors.rs:19-34`). This is a
self-consistent custom bit order, not the FIPS one.

### 3.2 WOTS+ / WOTS+C (Alg. 5–8)

| FIPS 205 | C10 counterpart | Where | Class |
|----------|-----------------|-------|-------|
| **Alg. 5 `chain`** | `chain_hash` (+ `chain_buf`/`chain_value`) | `hash.rs:324-341`, `425-438` | SAME (direction) |
| **Alg. 6 `wots_pkGen`** | `wots::keygen_pk` | `wots.rs:101-117` | DEVIATES (SPHINCS+C) |
| **Alg. 7 `wots_sign`** | `wots::sign_with_shuffle` + `find_count` | `wots.rs:63-156` | DEVIATES (SPHINCS+C) |
| **Alg. 8 `wots_pkFromSig`** | `wots::pk_from_sig` | `wots.rs:162-196` | DEVIATES (SPHINCS+C) |

**The WOTS+C deviation (the headline one).** FIPS 205 WOTS+ signs `len =
len_1 + len_2` chains, where `len_2` chains carry a **checksum** of the message
digits (the `csum` computation in `wots_sign`, Alg. 7). For C10's `w=8, n=16`,
`len_1 = ⌈8n/lg_w⌉ = ⌈128/3⌉ = 43` and FIPS would add `len_2 = 3` checksum
chains → 46 chains.

C10 has **no checksum chains** (`l = 43`, all message digits). Instead it
**grinds a 32-bit `count`** until the base-8 digit sum of a count-tweaked
digest equals exactly `TARGET_SUM = 205` (`find_count`, `wots.rs:63-94`;
`params.rs:52`). The constant-sum constraint is what a checksum would
otherwise enforce (it pins the total digit weight so an attacker can't freely
lower digits to forge). This is the "WOTS+C" construction; the `count` is
carried in the signature (4 bytes/layer) and re-hashed at verify time
(`wots_digest`, see [§5](#5-hash-instantiation-delta)). FIPS 205 contains no
such construction — a full-text scan of the standard finds zero occurrences of
"grind", "WOTS+C", "digit sum", or "target_sum"; FIPS WOTS+ always computes and
signs the full `len_2`-digit checksum.

- **Chain direction is SAME as WOTS+.** Sign advances each chain from
  position `0` for `digit[i]` steps (`wots.rs:153`); verify advances from
  `digit[i]` for `w−1−digit[i] = 7−digit[i]` steps (`wots.rs:191-192`; Yul
  `SPHINCsC10Asm.sol:176` `steps := sub(7,digit)`). Both reach chain end 7.
- **Digit-sum gate is enforced on the verify side too** — `pk_from_sig`
  returns the all-zero pubkey if `Σ digit ≠ 205` (`wots.rs:179-185`), and the
  Yul reverts (`SPHINCsC10Asm.sol:170`). A signature with a non-conforming
  count cannot validate.
- **Bound check:** `l·(w−1) = 43·7 = 301 ≥ 205` ✓, so a conforming count
  exists for essentially every message (grinding bound `10^7`,
  `wots.rs:62`). (For reference, FIPS WOTS+ at this `w=8, n=16` would use
  `len_1 = ⌈128/3⌉ = 43` message chains **plus** `len_2 = ⌊log₂(301)/3⌋+1 = 3`
  checksum chains = 46; C10's count-grind drops those 3.)
- C10 also Fisher-Yates **shuffles** chain processing order during signing as
  an SCA defence (`wots.rs:124`). This is a side-channel hardening of the
  *computation order* only; the emitted signature is at natural index order
  and is byte-identical to an unshuffled signer. Not a FIPS concept; does not
  affect the verifier.

### 3.3 XMSS (Alg. 9–11)

| FIPS 205 | C10 counterpart | Where | Class |
|----------|-----------------|-------|-------|
| **Alg. 9 `xmss_node`** | `merkle` treehash (`compute_pk_root`, subtree build) | `merkle.rs:30-120`, `hypertree.rs:27-31` | SAME |
| **Alg. 10 `xmss_sign`** | per-layer WOTS sign + auth-path emit | `hypertree.rs:291-316` | SAME (shape) |
| **Alg. 11 `xmss_pkFromSig`** | `merkle::verify_auth_path` after `pk_from_sig` | `merkle.rs` `verify_auth_path`, `hypertree.rs:419-470` | SAME |

XMSS leaves are WOTS+C public keys (so they inherit the WOTS+C deviation),
but the Merkle auth-path walk itself is the standard XMSS construction:
`th_pair` of `(left, right)` with `ADRS_TREE` type, height tweak `h+1`, parent
index `idx>>1`, left/right ordered by `idx & 1`. The Rust
(`merkle.rs:verify_auth_path`) and Yul (`SPHINCsC10Asm.sol:204-222`, branchless
swap) match exactly. `h' = 9` levels per layer.

### 3.4 Hypertree (Alg. 12–13)

| FIPS 205 | C10 counterpart | Where | Class |
|----------|-----------------|-------|-------|
| **Alg. 12 `ht_sign`** | `hypertree::sign_inner` layer loop | `hypertree.rs:265-336` | SAME (shape) |
| **Alg. 13 `ht_verify`** | `verify` layer loop + final root compare | `hypertree.rs:419-475`, `SPHINCsC10Asm.sol:149-228` | SAME (shape) |

`d = 2` layer walk: bottom 9 bits of `idx_tree` select the leaf in this
layer's subtree, `idx_tree >>= 9` advances to the next layer
(`hypertree.rs:270-271`; Yul `SPHINCsC10Asm.sol:150-151`). Final
reconstructed root is compared to `pk_root` (`hypertree.rs:475`; Yul
`:228` `eq(currentNode, root)`). Identical structure to FIPS `ht_verify`,
specialized to two layers.

### 3.5 FORS / FORS+C (Alg. 14–17)

| FIPS 205 | C10 counterpart | Where | Class |
|----------|-----------------|-------|-------|
| **Alg. 14 `fors_skGen`** | `fors_secret` PRF | `hash.rs:408-417` (impl), `fors.rs` callers | DEVIATES (C10 design — PRF) |
| **Alg. 15 `fors_node`** | `compute_fors_root` treehash | `fors.rs:113-159` | SAME |
| **Alg. 16 `fors_sign`** | `sign_fors_tree` + R-grinding | `fors.rs:68-237` | DEVIATES (SPHINCS+C — FORS+C) |
| **Alg. 17 `fors_pkFromSig`** | `reconstruct_fors_root` + `compute_fors_pk` | `hypertree.rs:479-511`, `fors.rs:242-245` | DEVIATES (SPHINCS+C — FORS+C) |

**The FORS+C deviation.** FIPS 205 FORS signs all `k` trees and emits `k`
auth paths. C10 implements *FORS+C*: it **grinds the message randomizer `R`**
until the last (`k−1 = 12`th) FORS index is forced to zero
(`grind_r`, `fors.rs:68-108`, check `read_bits_le(digest,(K−1)·A,A)==0` at
`:103`). The last tree then contributes **only its root** (placed in the
secret slot) with **no auth path** — saving `a·n = 11·16 = 176` bytes. The
verifier enforces the forced-zero index (Yul `SPHINCsC10Asm.sol:86`
`if and(shr(132,dVal),0x7FF) { revert }`; `132 = (k−1)·a`) and reconstructs
the 13th root by a single `th` of its secret (`:124-132`,
`hypertree.rs:413-415`).

**FORS secret is `ht_idx`-bound (security-critical, SAME *intent* as FIPS but
a custom PRF preimage).** `fors_secret = SHA-256(sk_seed ‖ "fors" ‖ ht_idx ‖
tree_idx ‖ leaf_idx)[0..16]` (`hash.rs:408-417`). Folding `ht_idx` makes every
one of the `2^18` hypertree positions an *independent* FORS forest — without
it, a passive observer collecting signatures could reassemble a shared forest
and forge (CWE-347 / few-time-key reuse). FIPS 205 achieves the same
independence through the ADRS tree-address fed to its `PRF`; C10 achieves it
by binding `ht_idx` into the PRF preimage *and* into the FORS-tree ADRS
(`tree` field = `ht_idx`, see [§6](#6-adrs-delta)). The Yul verifier carries
`ht_idx` in all four FORS ADRS words (`SPHINCsC10Asm.sol:97,103,127,137`).
This binding is the `fcee705a` position-binding fix; the verifier codehash was
re-pinned for it (`SPHINCsC10Asm.t.sol` codehash
`0xf1ef4ccee22e6b39446723232fe39761f089c7195941b2c12576956b38fcfef5`).

> **No grinding on the FORS *tree* side** — only the single `R`-grind loop.
> Each tree signature is deterministic once `R` is fixed (`fors.rs`).

### 3.6 Top-level (Alg. 18–25)

| FIPS 205 | C10 counterpart | Where | Class |
|----------|-----------------|-------|-------|
| **Alg. 18 `slh_keygen_internal`** | `SigningKey::keygen` → `compute_pk_root` | `lib.rs:111-118`, `hypertree.rs:27-31` | SAME (shape) |
| **Alg. 19 `slh_sign_internal`** | `hypertree::sign_inner` | `hypertree.rs:148-348` | DEVIATES (R-grind, below) |
| **Alg. 20 `slh_verify_internal`** | `verify` | `hypertree.rs:351-476` + Yul | SAME (shape) |
| **Alg. 21-22 `slh_keygen`/`slh_sign`** | (no ctx wrapper) | — | **DEVIATES (C10 design)** |
| **Alg. 23/25 prehash `HashSLH-DSA`** | (none) | — | **DEVIATES (C10 design)** |

**Message randomizer `R` — DEVIATES (SPHINCS+C + C10).** FIPS 205 derives
`R = PRF_msg(SK.prf, opt_rand, M) = Trunc_n(HMAC-SHA-256(SK.prf, opt_rand ‖
M))` — a single keyed PRF. C10 derives `R` by the FORS+C **grind loop**:
`R = SHA-256(SK.seed ‖ "R_grind" ‖ [opt_rand] ‖ M ‖ nonce_be32)[0..16]`, iterated
until the forced-zero FORS index holds (`fors.rs:109-124`) — **secret-keyed
(`SK.seed`) AND message-bound (`M`)** since the 2026-06-13 hardening
(`b12d4969`; corrected here 2026-07-02 — this line previously recorded the
pre-hardening `SHA-256("R_grind" ‖ [opt_rand] ‖ nonce)` preimage). With
`opt_rand = None` the path is deterministic (preserves byte-stable KAT vectors); with
`opt_rand = Some` per-call randomness enters, closing the msg-dependent
iteration-count leak (`fors.rs:84-87`). Different mechanism, different
preimage from FIPS `PRF_msg`.

**No context string, no prehash — DEVIATES (C10 design).** FIPS 205
`slh_sign` (Alg. 22) prepends a domain block `toByte(0,1) ‖ toByte(|ctx|,1) ‖
ctx` to the message, and `HashSLH-DSA` (`hash_slh_sign`, Alg. 23) defines a prehash variant
with an OID-tagged digest. C10 takes a **bare 32-byte message hash** with no
ctx and no prehash framing (`lib.rs:253` `verify`; `hypertree.rs:368` feeds
`message` straight into `H_msg`). So even at the API boundary a C10 signature
is **not** a FIPS 205 "pure" or "prehash" SLH-DSA signature. The 32-byte input
is whatever upstream produced it (in the wallet, a `sphincsDigest` /
firmware-update preimage); domain separation is the caller's responsibility.

---

## 4. Public key & keygen

`VerifyingKey = pk_seed(16) ‖ pk_root(16) = 32 bytes` (`lib.rs:217-244`),
**SAME** as FIPS 205's `PK = (PK.seed, PK.root)`. `keygen` builds the top
(`layer=1, tree=0`) subtree's `2^9` WOTS+C leaves and Merkle-roots them
(`hypertree.rs:27-31`); structurally `slh_keygen_internal` with the C10
parameter set and WOTS+C leaves. `sk_seed(32) ‖ pk_seed(16)` are inputs to the
crate (generated upstream from the dual-chip XOR entropy split, per
`CLAUDE.md`); the crate does not contain `slh_keygen`'s own RNG draw.

---

## 5. Hash-instantiation delta

This is the largest and most numerous deviation. FIPS 205 §11.2.1 defines the
SHA-2 / category-1 hash family with a **compressed 22-byte ADRSᶜ**, a
**64-byte seed block** (`PK.seed ‖ toByte(0, 64−n)`), an **MGF1**-based
`H_msg`, and an **HMAC**-based `PRF_msg`. C10 uses none of these. Side by side
(C10 from `hash.rs`, cross-checked against Yul; FIPS from §11.2.1):

| Function | FIPS 205 (SHA-2, cat 1) | **C10** | C10 ref |
|----------|-------------------------|---------|---------|
| `H_msg` | `MGF1-SHA256(R ‖ PK.seed ‖ SHA256(R ‖ PK.seed ‖ PK.root ‖ M), m)` | `SHA256(pkSeed₃₂ ‖ pkRoot₃₂ ‖ R₃₂ ‖ msg₃₂ ‖ 0xFF×32)` → **full 32 B** | `hash.rs:291-305` |
| `PRF` (sk derivation) | `Trunc₁₆(SHA256(PK.seed ‖ toByte(0,48) ‖ ADRSᶜ ‖ SK.seed))` | WOTS: `Trunc₁₆(SHA256(skSeed₃₂ ‖ "wots" ‖ layer₄ ‖ tree₃₂ ‖ kp₄ ‖ chain₄))`; FORS: `Trunc₁₆(SHA256(skSeed₃₂ ‖ "fors" ‖ htIdx₄ ‖ treeIdx₄ ‖ leaf₄))` | `hash.rs:376-417` |
| `PRF_msg` | `Trunc₁₆(HMAC-SHA256(SK.prf, opt_rand ‖ M))` | `Trunc₁₆(SHA256(skSeed₃₂ ‖ "R_grind" ‖ [opt_rand] ‖ msg₃₂ ‖ nonce₃₂))` in a grind loop | `fors.rs:109-124` |
| `F` (1-input tweak) | `Trunc₁₆(SHA256(PK.seed ‖ toByte(0,48) ‖ ADRSᶜ ‖ M₁))` | `th = Trunc₁₆(SHA256(pkSeed₃₂ ‖ adrs₃₂ ‖ val₃₂))` | `hash.rs:216-223` |
| `H` (2-input tweak) | `Trunc₁₆(SHA256(PK.seed ‖ toByte(0,48) ‖ ADRSᶜ ‖ M₂))` | `th_pair = Trunc₁₆(SHA256(pkSeed₃₂ ‖ adrs₃₂ ‖ left₃₂ ‖ right₃₂))` | `hash.rs:230-243` |
| `T_l` (l-input tweak) | `Trunc₁₆(SHA256(PK.seed ‖ toByte(0,48) ‖ ADRSᶜ ‖ M))` | `th_multi = Trunc₁₆(SHA256(pkSeed₃₂ ‖ adrs₃₂ ‖ pad16(v₀) ‖ …))` | `hash.rs:260-273` |
| (count tweak, C10-only) | — | `wots_digest = SHA256(pkSeed₃₂ ‖ wotsAdrs₃₂ ‖ msg₃₂ ‖ count_u256)` → **full 32 B** | `hash.rs:350-365` |

**Classification: DEVIATES (C10 design)**, in every row. The structural
differences:

1. **No MGF1.** C10's `H_msg` is a single SHA-256 with a trailing `0xFF×32`
   domain block, not the FIPS mask-generation expansion. (`m`-byte output is
   replaced by C10 taking the full 32-byte digest and slicing 161 bits.)
2. **No 64-byte seed block.** FIPS pads `PK.seed` to a full 64-byte SHA-256
   block with `toByte(0, 48)`. C10 pads `pk_seed` to **32 bytes**
   (`pad16`: 16 value + 16 zero) and concatenates the **uncompressed 32-byte
   ADRS** — a 96-byte (`F`), 128-byte (`H`) or `64 + 32k`-byte (`T_l`)
   preimage with no block alignment.
3. **Uncompressed ADRS.** FIPS feeds the 22-byte `ADRSᶜ`. C10 feeds the full
   32-byte ADRS ([§6](#6-adrs-delta)).
4. **ASCII-tagged, `pk_seed`-free PRF.** C10's secret-key PRFs key on
   `sk_seed` and use ASCII domain tags `"wots"` / `"fors"` plus mixed-width
   fields; they do **not** include `pk_seed`. FIPS `PRF` keys on `PK.seed`
   and includes `SK.seed` as the message tail. Different inputs entirely.
5. **`H_msg` and `wots_digest` return the full 32-byte digest** (not
   truncated to 16) because the caller extracts index/digit bits from it;
   every other primitive truncates to `n = 16` (`hash.rs:169-173`).
6. **Input ordering differs** even where the ingredients overlap: C10 `H_msg`
   is `seed ‖ root ‖ R ‖ msg`, FIPS inner hash is `R ‖ seed ‖ root ‖ msg`.

> One-shot boundary: every C10 primitive assembles its full preimage in a
> stack buffer and makes a single `sha256_bytes` call (`hash.rs:200-204`).
> This is the boundary the §33 Lean verification collapses onto one
> FIPS-180-4-transcribed, CAVP-pinned `sha256` (see
> `contracts/verification/extracted/Extracted/HashPure.lean`). **SHA-256
> itself is FIPS 180-4 conformant** (229/229 NIST CAVP vectors,
> `make verify-cavp`); it is the *instantiation around* SHA-256 that deviates
> from FIPS 205.

---

## 6. ADRS delta

FIPS 205 §4.2 defines a 32-byte address that, for SHA-2, is **compressed to
22 bytes** (`ADRSᶜ`: 1-byte layer ‖ 8-byte tree ‖ 1-byte type ‖ 12-byte
type-specific) before hashing. C10 uses a **32-byte uncompressed** address
fed directly into every hash, with this fixed layout (big-endian):

| Bytes | Field | Width | C10 ref | Yul shift |
|-------|-------|-------|---------|-----------|
| `[0..4)` | layer | u32 | `address.rs:32` | `shl(224,·)` |
| `[4..12)` | tree | **u64** | `:34` | `shl(160,·)` |
| `[12..16)` | type | u32 | `:35` | `shl(128,·)` |
| `[16..20)` | keypair | u32 | `:36` | `shl(96,·)` |
| `[20..24)` | chain_index | u32 | `:37` | `shl(64,·)` |
| `[24..28)` | chain_pos / height | u32 | `:38` | `shl(32,·)` |
| `[28..32)` | hash_address | u32 | `:39` | low bits |

**Classification: DEVIATES (C10 design).** Differences from FIPS 205's
address: (a) no compression — C10 hashes all 32 bytes; (b) the `tree` field is
**8 bytes** (u64) in C10 vs FIPS's 12-byte tree address; (c) the
type-specific sub-layout (keypair/chain/hash) uses four u32 words, a C10
convention. **The Rust ADRS layout and the Yul bit-packing match exactly** —
verified field-by-field ([§8](#8-cross-artifact-consistency-the-core-finding)).

Address-type constants (`address.rs:97-101`): `WOTS=0, WOTS_PK=1, TREE=2,
FORS_TREE=3, FORS_ROOTS=4`. FIPS 205 uses `WOTS_HASH=0, WOTS_PK=1, TREE=2,
FORS_TREE=3, FORS_ROOTS=4` — **same numbering** (one of the few encoding
details that coincides).

---

## 7. Message-digest split / index extraction

The 32-byte `H_msg` digest is consumed as `161` bits:

| Field | C10 bits | Width | C10 ref | Yul |
|-------|----------|-------|---------|-----|
| FORS index `t` (`t∈0..13`) | `[t·11 .. (t+1)·11)` | 11 | `fors.rs:42-48` | `:90-91` `shr(i·11,d)&0x7FF` |
| FORS forced-zero (`t=12`) | `[132..143)` must be 0 | 11 | `fors.rs:103` | `:86` `shr(132,d)&0x7FF` |
| hypertree index `ht_idx` | `[143..161)` | 18 | `fors.rs:58-60` | `:81` `shr(143,d)&0x3FFFF` |

**Classification: DEVIATES (C10 design).** FIPS 205 `slh_verify_internal`
(Alg. 20, line 9; same split in `slh_sign_internal` Alg. 19) splits the digest as the first `⌈k·a/8⌉` bytes (`md`, big-endian)
for FORS, then byte-aligned `idx_tree` / `idx_leaf` fields. C10 uses
**LSB-first contiguous bit windows** (`read_bits_le`) with `k·a = 143` bits of
FORS index immediately followed by `h = 18` bits of `ht_idx` — a different
bit order *and* a different field packing. Within the hypertree walk, the
bottom 9 bits of `ht_idx` are the layer-0 leaf, the next 9 the layer-1 leaf
(`hypertree.rs:270-271`; Yul `:150-151`). Rust and Yul agree on every shift
and mask.

---

## 8. Cross-artifact consistency (the core finding)

The two **production** artifacts are the Rust signer and the Yul verifier (the
Lean spec is a third, separately-audited artifact — [§9](#9-relationship-to-the-lean-spec-and-a31)).
This audit cross-checked every scheme-level quantity between them. **They
agree on all of it:**

- **ADRS field offsets** — Rust byte ranges `[0..4)…[28..32)`
  (`address.rs:32-39`) ↔ Yul shifts `shl(224)…low` (`SPHINCsC10Asm.sol`):
  exact, field by field.
- **`H_msg` preimage** — `seed‖root‖R‖msg‖0xFF×32`, 160 bytes
  (`hash.rs:291-305` ↔ `:71-77`): exact.
- **`wots_digest`** — `seed‖adrs‖msg‖count`, count in bytes `[124..128)`
  (`hash.rs:350-365` ↔ `:156-162`, `shr(224,·)` then `mstore(0x60,·)`): exact.
- **FORS forced-zero gate** at digest bits `[132..143)`
  (`fors.rs:103` ↔ `:86`): exact.
- **WOTS+C digit-sum gate `= 205`** (`wots.rs:156-162` ↔ `:166-170`): exact.
- **Chain advance** `start=digit, steps=7−digit` (`wots.rs:168-169` ↔
  `:176`): exact.
- **`th_multi` widths** — FORS roots compress over 13 (`fors.rs:242-245` ↔
  `:134-142`, `0x1E0=480=32+32+13·32`); WOTS PK over 43
  (`wots.rs:97` ↔ `:192-200`, `0x5A0=1440=32+32+43·32`): exact.
- **4008-byte wire layout** — `R(16) | FORS-secrets(208) |
  FORS-auth(2112) | layer0(836) | layer1(836)`, with each layer
  `WOTS(688) | count(4) | auth(144)` (`params.rs:62-79`,
  `hypertree.rs:236-336` ↔ `SPHINCsC10Asm.sol:88-226`): exact.

**Finding: no unintended divergence between the signer and the verifier.**
This is the result the §33 differential KAT testing (`c10_test_vectors.json`,
10 vectors that sign in Rust and verify on-chain) exercises dynamically; this
audit confirms it statically, line by line. The accidental-deviation bug class
(A3.1) is **not present** in the Rust↔Yul pair.

---

## 9. Relationship to the Lean spec and A3.1

The one *known* C10 fidelity defect lives in neither production artifact. It
is in the **Lean reconstruction-layer ADRS** of the separate verification
spec (`contracts/verification/lean/SphincsCVerify/Spec/`), where
`Spec.Signature.verify` returns `false` on valid KAT vectors — the spec's
WOTS+C / hypertree reconstruction ADRS diverges from the deployed Yul. That is
tracked as **A3.1** (`contracts/verification/docs/A3_1_VERIFIER_GAP.md`,
`AXIOM_STATUS.json` `discharged-bytecode-partial`) and in `docs/work-todo.md`
§18b ④. This delta-audit does **not** resolve A3.1; it scopes it precisely:

- The **digest + `ht_idx` sub-layers** of the Lean spec are byte-exact vs
  FIPS/bytecode (10/10 KAT, `lake exe verify-test-vectors`).
- The **functional reconstruction layer** is the diverging part, and it is the
  prerequisite for extending the spec-vs-implementation differential
  ([§10](#10-recommended-follow-ups)).
- The **§33 Aeneas-extracted** Lean (`contracts/verification/extracted/`) is a
  *different* and faithful artifact: it is extracted directly from this Rust
  and proves the WOTS+C/FORS/merkle pure logic with the hash boundary pinned
  to FIPS-180-4 SHA-256. It does not have the A3.1 gap.

---

## 10. Recommended follow-ups

1. **A3.1 fix** (already queued, §18b ④): make the Lean `Spec` reconstruction
   ADRS byte-faithful to the Yul so `verify-test-vectors` is green on all
   layers — the prerequisite for the full-verify differential.
2. **Bulk random differential** (queued, §33 P4): extend the Rust↔Lean (and
   Rust↔Yul) conformance from 10 KATs to hundreds of
   `gen_test_vectors.rs`-generated vectors. This audit shows the *structure*
   matches; the differential proves it stays matched under fuzzing.
3. **Keep this ledger current.** If any C10 parameter, ADRS field, preimage,
   or bit-extraction changes, re-run the two extraction agents and update §§2-8
   — a drift here is exactly the A3.1 class.
4. **External KAT provenance & per-primitive component KATs** (new 2026-07-06,
   from the ETHFALCON-port assessment). Because C10 shares *only* raw SHA-256
   with any standard (§5/§6), no official SPHINCS+/SLH-DSA KAT can anchor it and
   the sole external cross-check is our own independent re-implementation. The
   assessment recommends adding per-tweakable-hash intermediate-value KATs
   (localize an A3.1-class divergence to the exact primitive) + a portable
   `.rsp`-style artifact. See
   [`external-kat-provenance-and-ethfalcon-port-2026-07.md`](./external-kat-provenance-and-ethfalcon-port-2026-07.md).

---

## Appendix: citation index

- **FIPS 205** — NIST FIPS 205, *Stateless Hash-Based Digital Signature
  Standard* (SLH-DSA), August 2024. Algorithm numbering and §11.2.1 SHA-2
  instantiation as cited inline.
- **SPHINCS+C** — Hülsing et al., "SPHINCS+C: Compressing SPHINCS+ With
  (Almost) No Cost", NIST PQC 2022 workshop / IACR ePrint 2022/778. Lineage
  of WOTS+C (no checksum, count-grind to fixed digit sum) and FORS+C
  (forced-zero last index). In-repo citation:
  `contracts/verification/lean/SphincsCVerify/Spec/Params.lean:13-22` (which
  also records that the C10 tuple is deliberately NOT one of the paper's
  table sets). Related later work: Fluhrer & Dang, "Smaller Sphincs+"
  (ePrint 2024/018) and the NIST SP 800-230 reduced-use parameter-set track.
- **SPHINCS+ v3** — round-3 submission, `sphincs.org/data`. Base parameter
  naming and ADRS-type numbering.
- **Reference signer** — Python adaptation noted at `sphincs-c10/src/lib.rs:14`
  (`github.com/nconsigny/SPHINCs-`).
- **Production artifacts** — `sphincs-c10/src/` (signer),
  `contracts/smart-wallet/src/verifiers/SPHINCsC10Asm.sol` (verifier, pinned
  codehash `0xf1ef4cce…fcfef5`).
- **SHA-256 conformance** — FIPS 180-4; 229/229 NIST CAVP vectors via
  `make verify-cavp` (`contracts/verification/cavp/`).

---

## Addendum (2026-06-12, same day): upstream provenance deep-dive

A full examination of the reference repo `github.com/nconsigny/SPHINCS-`
(clone reviewed at 324 commits, latest 2026-06-12) sharpens the lineage:

- **C10's parameter set originated there** — commit `0516a11` (2026-04-09)
  introduced c10 with the security curve **sec_14=128, sec_16=128,
  sec_18=118.3, sec_20=104.5 bits** from its Fluhrer-Dang sweep
  (`legacy/script/sweep_d2_fluhrer_dang.py`). That table directly validates
  PQSigner's 65,536 (2^16) per-chain cap as sitting at the 128-bit boundary.
- **Upstream has retired C10** (superseded by C13); PQSigner is the parameter
  set's only active user. The C10 ancestor artifacts live in its `legacy/`
  tree (`legacy/script/signer.py`, `legacy/src/SPHINCs-C10Asm.sol` —
  keccak-based; PQSigner swapped to SHA-256).
- **Citation corpus** (upstream `sphincs_parameters_paper_corpus.md`): the
  WOTS+C/FORS+C family origin is IACR ePrint **2025/2203**; the few-time
  security formula is Fluhrer & Dang ePrint **2024/018**; background
  Kölbl-Philipoom ePrint 2022/1725. These join the SPHINCS+C PQC-2022
  citation already in `Spec/Params.lean`.
- **Convergent bug discovery:** upstream independently found and fixed the
  same shared-FORS-forest forgery class (their "Finding C", commit `237ab69`,
  2026-06-03) that PQSigner fixed as the CWE-347 ht_idx binding — but with a
  **different binding encoding** (FIPS-style field split vs PQSigner's full
  `ht_idx` in the 8-byte ADRS tree field). The two implementations are NOT
  byte-compatible on the bound FORS path; PQSigner's encoding is pinned by
  its frozen verifier.
- **Known divergence with a hardening implication:** upstream's current R
  derivation is `H(sk_seed ‖ "R_grind" ‖ message ‖ nonce)` — secret-keyed and
  message-bound — adopted to close a chosen-message FORS-saturation analysis
  (their `docs/SECURITY-ANALYSIS.md` §2 "Avenue B"). **PQSigner ADOPTED that form
  2026-06-13 (`b12d4969`; corrected here 2026-07-02 — this addendum previously
  recorded the pre-hardening `H("R_grind" ‖ opt_rand ‖ nonce)`):** R is
  `Trunc₁₆(SHA256(SK.seed ‖ "R_grind" ‖ [opt_rand] ‖ M ‖ nonce))` (`fors.rs:109-124`),
  i.e. **secret-keyed (`SK.seed`) and message-bound (`M`)**. So Avenue-B safety
  no longer rests on `opt_rand` freshness — the `sk_seed + message` binding holds
  even on the deterministic `opt_rand = None` path (production still supplies fresh
  TRNG `opt_rand`, `secure/src/crypto.rs:118-123`, as belt-and-braces). The Lean
  model `Spec/Signer.lean:104-109` matches this current preimage.
