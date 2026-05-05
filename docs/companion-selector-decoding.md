# Companion-app guide — function-selector → typed-args decoding

What the companion has to do so that, when the user signs an unrecognised
contract call, the device shows

```
! BLIND SIGN
transfer(uint256)

arg 0 uint256:
1000

To: <contract>
…
```

instead of a hex word-dump.

This document is companion-side only. The firmware logic is already in
tree (`secure/src/selectors/`, `secure/src/tx/typed_call/`,
`secure/src/tx/display/typed_call/`); the dispatcher already prefers the
typed render over the blind-sign fallback when it has a verified bundle.

---

## 1. The deal

The wallet supports **two parallel paths** for surfacing a function name
+ typed args on the trusted UI. Both are verified in firmware; both go
through the same per-arg renderer; they differ only in *who attests the
text-signature* (and consequently the banner the device shows).

### 1a. Curated path (Phase 2)

The wallet ships with a 32-byte Merkle root (`SELECTOR_DB_ROOT`) baked
into the secure firmware image. The companion holds the full
selectors-DB blob (`selectors_db.bin`, ~775 KB) on disk. Per call:

1. Read the 4-byte selector from `calldata[0..4]`.
2. Look it up in the local `selectors_db.bin`.
3. If found: build a `(selector, text_sig, leaf_index, proof)` bundle
   and attach it to the sign payload as the **curated selector
   trailer** (slot 4 of the trailer chain).

The firmware Merkle-verifies the bundle against `SELECTOR_DB_ROOT`,
cross-checks `bundle.selector == calldata[0..4]`, parses the `text_sig`,
ABI-walks the calldata, and renders one trusted-UI page per decoded
argument under a `! BLIND SIGN` banner.

Trust property: the companion is treated as relay. It cannot forge a
bundle (proof fails), cannot graft one selector's text onto a different
calldata (cross-check fails), cannot inject non-printable bytes
(`SELECTOR_TEXT_SIG_MAX_LEN = 63`, ASCII gate). One canonical text-sig
per selector is enforced at curation time, so adversarial 4byte
collisions can't be substituted.

### 1b. Self-attest path (Phase 2b)

For selectors *not* in the curated DB, the companion can supply a
`(selector, text_sig)` pair directly — no Merkle proof, no curated DB
involvement. Per call:

1. Read the 4-byte selector from `calldata[0..4]`.
2. The companion knows (or guesses, e.g. via 4byte.directory) a
   `text_sig`.
3. Build a self-attest bundle and attach it to the sign payload as the
   **self-attest trailer** (slot 5).

The firmware verifies internal consistency only:

- `keccak256(text_sig)[..4] == bundle.selector` — defeats the trivial
  case where a malicious companion picks a name unrelated to the
  calldata.
- `bundle.selector == calldata[..4]` — same cross-check as the curated
  path.
- The existing strict ABI walker rejects shape mismatches (top-zero
  pads, residual bytes, etc.).

Then renders the typed-args flow under a louder `! UNVERIFIED` banner.

Trust property: the keccak check defeats the easy attack ("evil
companion picks an unrelated benign-looking name"). It does *not*
defeat crafted hash collisions — a patient attacker can brute-force
~2³² keccak ops to find a same-shape colliding `text_sig` for any
target selector. So the displayed function NAME is companion-controlled
in this path; the user must verify it against the dapp. The displayed
ARGUMENTS, however, are extracted from the calldata's actual bytes and
are not lie-able regardless of the path.

### 1c. Mutual exclusion

The two paths are **mutually exclusive per call**. The firmware refuses
any payload that carries both a non-empty curated trailer AND a
non-empty self-attest trailer (`InvalidPointer`). The companion picks
exactly one path:

- **Curated DB hit** → curated trailer.
- **Curated DB miss + companion has a `text_sig`** → self-attest trailer.
- **Neither** → no selector trailer. Device falls back to the existing
  blind-sign flow (no FUNCTION/GUESS page).

In all three cases, the ARGS still get rendered (or not) by the same
strict ABI walker — the difference is just which banner / label the
device shows.

---

## 2. Where the blob comes from

Single source of truth is `secure/data/selectors.json` — the curated
JSON that `dbgen` consumes. `tools/build_selectors_json.py` produces
this file from `~/Documents/4bytes-db` (a checked-out clone of
[ethereum-lists/4bytes](https://github.com/ethereum-lists/4bytes)).

`cargo run -p dbgen` then writes:

```
tools/companion-stub/selectors_db.bin     # production blob (companion ships this)
tools/companion-stub/selectors_db_e2e.bin # tiny fixture for QEMU e2e tests
secure/src/db_roots.rs                    # SELECTOR_DB_ROOT (production + e2e)
```

The companion-app build pipeline must:

1. Pull the matching `selectors_db.bin` for the firmware version it
   speaks to (the blob and the firmware's root must agree).
2. Either bundle the blob as a static asset or download it on first
   run and pin its SHA-256 against a value baked into the companion.
3. On startup, hash the loaded blob and compare to the version pin.
   If it doesn't match: the companion has a stale blob, refuse to
   build bundles and fall back to blind-sign — never just send a
   bundle from the wrong root, the firmware will silently drop it.

Root rotation: every firmware release that touches `selectors.json`
rotates `SELECTOR_DB_ROOT`. The companion must ship a new blob in
lockstep. The firmware does not yet expose a "what root are you using"
gateway command — for now, the companion is expected to know which root
goes with which firmware version (the firmware version is the
8-BIP-39-words measured-boot fingerprint shown on the OLED on every
boot, and the release tag in the GitHub release the companion was built
against).

---

## 3. Selectors DB binary format

Single source of truth: `shared/src/db_format.rs:275-358`. Reproduced
here for self-containment.

### Magic / header (32 bytes, little-endian throughout)

| Offset | Size | Field          | Notes                                |
|-------:|-----:|----------------|--------------------------------------|
|      0 |    4 | `magic`        | `b"SEL4"`                            |
|      4 |    4 | `version`      | `1`                                  |
|      8 |    4 | `flags`        | `0` reserved                         |
|     12 |    4 | `entry_cnt`    | number of entries                    |
|     16 |    4 | `pool_off`     | byte offset of string pool           |
|     20 |    4 | `pool_size`    | bytes                                |
|     24 |    4 | `proof_depth`  | sibling hashes per proof             |
|     28 |    4 | `proofs_off`   | byte offset of per-entry proofs      |

### Entries (`entry_cnt × 8 bytes`, sorted ascending by selector)

| Offset | Size | Field      | Notes                              |
|-------:|-----:|------------|------------------------------------|
|      0 |    4 | `selector` | first 4 bytes of `keccak256(text)` |
|      4 |    4 | `text_off` | offset into string pool            |

### String pool

Length-prefixed UTF-8 (printable ASCII, in fact): `[len: u8][bytes:
len]`. Strings are interned at build time, so identical text-sigs are
stored once. `len` is in `1..=63`; `bytes` are all in `0x20..=0x7e`.

### Proofs

`entry_cnt × proof_depth × 32 bytes`. Proof[i] is the list of sibling
hashes from leaf `i` up to the root, ordered leaf-up. The direction at
each level is implicit from the bits of `i` (bit 0 = leaf-level
direction; `0` means our leaf is the left child).

### Padding

The leaf set is padded to the next power of two by duplicating the
last real leaf hash. This is invisible to lookups (the duplicates
share the original's selector, so binary search never lands there
unless the selector is genuinely the largest one — and even then, both
copies map to the same proof).

### Merkle hashing

```
leaf_hash(canonical) = SHA-256(0x00 || canonical_bytes)
node_hash(L, R)      = SHA-256(0x01 || L || R)
```

The `0x00`/`0x01` domain separation is load-bearing — without it, an
attacker who controls the entry encoding could craft canonical bytes
that look like a node concatenation.

### Canonical leaf encoding (selectors)

```
selector       (4)
text_sig_len   (1)
text_sig       (text_sig_len)
```

This is the byte-string the companion hashes to compare against the
pre-computed leaf in the tree, and the byte-string the firmware
re-derives from the bundle to feed `verify_proof`.

---

## 4. Lookup procedure

Reference implementation: `nonsecure/src/selectors_db.rs:52-83`
(Rust, no_std, used by the QEMU e2e harness as a dev-only companion
stub).

```python
def find_index(blob: bytes, selector: bytes) -> Optional[int]:
    """Binary search the sorted entry array for `selector` (4 bytes)."""
    assert len(selector) == 4
    entry_cnt = u32_le(blob, 12)
    lo, hi = 0, entry_cnt
    HEADER_LEN = 32
    ENTRY_LEN = 8
    while lo < hi:
        mid = (lo + hi) // 2
        off = HEADER_LEN + mid * ENTRY_LEN
        mid_sel = blob[off : off + 4]
        if mid_sel < selector:
            lo = mid + 1
        elif mid_sel > selector:
            hi = mid
        else:
            return mid
    return None

def lookup(blob: bytes, selector: bytes) -> Optional[Tuple[bytes, int, int, bytes]]:
    """Returns (text_sig, leaf_index, proof_depth, proof) or None."""
    idx = find_index(blob, selector)
    if idx is None:
        return None
    HEADER_LEN, ENTRY_LEN = 32, 8
    pool_off    = u32_le(blob, 16)
    proof_depth = u32_le(blob, 24)
    proofs_off  = u32_le(blob, 28)

    entry_off = HEADER_LEN + idx * ENTRY_LEN
    text_off  = u32_le(blob, entry_off + 4)
    pool_at   = pool_off + text_off
    text_len  = blob[pool_at]
    text_sig  = blob[pool_at + 1 : pool_at + 1 + text_len]

    proof_size = proof_depth * 32
    proof_base = proofs_off + idx * proof_size
    proof      = blob[proof_base : proof_base + proof_size]

    return text_sig, idx, proof_depth, proof
```

Selectors are compared lexicographically as raw bytes (not
endian-converted). The on-disk array is sorted by `bytes(selector)` —
the same comparison `find_index` performs.

Strict-but-cheap self-checks the companion should run:

- `magic == b"SEL4"`, `version == 1`. Refuse to use a blob that
  doesn't match.
- `entry_cnt > 0`.
- `proof_depth <= 32` (the firmware-side cap).
- All entry `text_off` values are within `pool_off..pool_off + pool_size`.
- Every pool string's bytes are in `0x20..=0x7e` and `1..=63` chars long.
- The blob's SHA-256 matches the pin baked into the companion build.

A blob that fails any of these is corrupt or version-mismatched —
fall back to "no bundle" for every call.

### Optional: independently verify before sending

The companion can also re-run the Merkle proof locally before sending
(belt-and-braces against a corrupt blob you somehow shipped):

```python
def verify_locally(canonical, leaf_index, proof_depth, proof, root):
    h = sha256(b"\x00" + canonical)
    idx = leaf_index
    for level in range(proof_depth):
        sib = proof[level * 32 : (level + 1) * 32]
        if idx & 1 == 0:
            h = sha256(b"\x01" + h + sib)
        else:
            h = sha256(b"\x01" + sib + h)
        idx >>= 1
    return h == root
```

The companion doesn't need to ship the firmware's `SELECTOR_DB_ROOT`
to do this — it can re-derive the root from its own blob at startup
and check its hash-pin against that. The firmware doesn't care; this
is purely a local sanity gate.

---

## 5. Bundle wire formats

### 5a. Curated bundle

Single source of truth: `tx/src/selectors/bundle.rs::verify_selector_bundle`.

```
offset  size                field
─────────────────────────────────────────────
   0     4                  selector
   4     1                  text_sig_len   (1..=63)
   5     text_sig_len       text_sig       (printable ASCII)
   …     4 LE               leaf_index
   …     4 LE               proof_depth    (0..=32)
   …     proof_depth × 32   proof bytes
```

Total length: `13 + text_sig_len + 32*proof_depth`. Upper bound
`MAX_SELECTOR_BUNDLE_LEN = 4 + 1 + 63 + 4 + 4 + 32*32 = 1100 bytes`.

Critical: the firmware refuses any **trailing bytes** after the
declared proof. Don't append padding. The framing layer's `len` field
is what carries the size to the secure side; the bundle itself must be
exactly `13 + text_sig_len + 32*proof_depth` bytes.

Endianness — `selector` is raw bytes, `leaf_index` and `proof_depth`
are little-endian u32, the proof is a contiguous `proof_depth × 32`
blob. (The little-endian for indices/depths is a quirk of the on-disk
DB format being LE everywhere; the wire framing inherited it.)

### 5b. Self-attest bundle

Single source of truth: `tx/src/selectors/bundle.rs::parse_self_attest_bundle`.

```
offset  size                field
─────────────────────────────────────────────
   0     4                  selector
   4     1                  text_sig_len   (1..=63)
   5     text_sig_len       text_sig       (printable ASCII)
```

Total length: `5 + text_sig_len`. Upper bound
`MAX_SELF_ATTEST_BUNDLE_LEN = 4 + 1 + 63 = 68 bytes`. No proof, no leaf
index. The firmware also refuses trailing bytes here — exact length
discipline.

The selector bytes in the bundle MUST equal `keccak256(text_sig)[..4]`;
the firmware re-runs the keccak and rejects on mismatch. The companion
should run the same check locally to surface typos as a JS error
rather than a silent on-device fall-back.

---

## 6. Where to attach the trailers in SIGN_USEROP

`CMD_SIGN_USEROP` payload layout (cumulative offsets after the 330-byte
fixed header + variable `data_len` calldata). All length prefixes are
**big-endian u16**. Source: `secure/src/nsc/cmd_sign_userop.rs:244-420`.

```
[fixed 330B header][data_len][data]
[erc20_bundle_len    ][erc20_bundle    ]   ← slot 0
[zk_v1_len           ][zk_v1_bundle    ]   ← slot 1
[zk_v3_len           ][zk_v3_bundle    ]   ← slot 2
[safe_v1_len         ][safe_v1_payload ]   ← slot 3
[curated_selector_len][curated_bundle  ]   ← slot 4 (Phase 2)
[self_attest_len     ][self_attest     ]   ← slot 5 (Phase 2b)
[names_count: u8     ][name_bundle_0 …  name_bundle_{count-1}]
```

Rules:

- Slots are **positional**. To say "no erc20 bundle, no zk, no safe, no
  curated selector, but yes self-attest", write `0x0000` for the first
  five lengths, then `[self_attest_len][self_attest_bundle]`.
- Any `*_len = 0` means "this trailer absent". The firmware skips it
  cleanly.
- Slots ≥ 4 are mutually exclusive with each other in one specific way:
  if **both** curated_selector_len > 0 AND self_attest_len > 0, the
  firmware returns `InvalidPointer`. Pick exactly one path per call.
- The names section is the only one with a count byte instead of a
  length byte; both selector slots go BEFORE names so the names
  framing stays the very last thing in the payload.
- Slots after the highest-numbered non-empty one can be omitted —
  reaching `cursor == total_len` is treated by the firmware's
  read-optional-u16 helper as "all remaining trailers absent". This
  keeps the wire bit-identical to the pre-Phase-2b shape when no
  selector trailer is needed.
- Total payload length must be exactly `cursor` after the last
  name-bundle. The firmware's final-length check refuses any trailing
  bytes — same rule as inside the bundle itself.

### Worked layout — curated-only trailer

```
header(330) || data_len(2) || data(N)
|| 00 00     (erc20_len            = 0)
|| 00 00     (zk_v1_len            = 0)
|| 00 00     (zk_v3_len            = 0)
|| 00 00     (safe_v1_len          = 0)
|| LL LL     (curated_selector_len = curated bundle byte length)
|| <curated_bundle>
```

`nonsecure/src/e2e_test.rs:267-284` shows the byte-level builder.

### Worked layout — self-attest-only trailer

```
header(330) || data_len(2) || data(N)
|| 00 00     (erc20_len            = 0)
|| 00 00     (zk_v1_len            = 0)
|| 00 00     (zk_v3_len            = 0)
|| 00 00     (safe_v1_len          = 0)
|| 00 00     (curated_selector_len = 0)
|| MM MM     (self_attest_len      = self-attest bundle byte length)
|| <self_attest_bundle>
```

`nonsecure/src/e2e_test.rs:286-315` shows the byte-level builder
(`build_self_attest_bundle` + `append_self_attest_only_trailers`).

---

## 7. Cross-checks the firmware enforces

Predictable failure modes — most silently fall back to the blind-sign
render path (the signed transaction is unchanged; the user just sees
the un-decoded view). The one HARD-FAIL case is "both selector
trailers present" → `InvalidPointer`.

### Curated path (slot 4)

| Check                                                  | Where               |
|--------------------------------------------------------|---------------------|
| `bundle.len() < 13` or `> 1100`                        | `verify_selector_bundle` (size gate) |
| `text_sig_len == 0` or `> 63`                          | `bundle.rs::verify_selector_bundle` |
| Any byte in `text_sig` not in `0x20..=0x7e`            | ASCII gate          |
| `proof_depth > 32`                                     | size gate           |
| `bundle.len() != 13 + text_sig_len + 32*proof_depth`   | no-trailing-bytes   |
| Merkle proof doesn't terminate at `SELECTOR_DB_ROOT`   | `verify_proof`      |
| `bundle.selector != calldata[0..4]`                    | `cmd_sign_userop.rs` cross-check |

### Self-attest path (slot 5)

| Check                                                  | Where               |
|--------------------------------------------------------|---------------------|
| `bundle.len() < 5` or `> 68`                           | size gate           |
| `text_sig_len == 0` or `> 63`                          | `parse_self_attest_bundle` |
| Any byte in `text_sig` not in `0x20..=0x7e`            | ASCII gate          |
| `bundle.len() != 5 + text_sig_len`                     | no-trailing-bytes   |
| `keccak256(text_sig)[..4] != bundle.selector`          | keccak verification |
| `bundle.selector != calldata[0..4]`                    | `cmd_sign_userop.rs` cross-check |

### Mutual exclusion (HARD FAIL)

| Check                                                  | Action              |
|--------------------------------------------------------|---------------------|
| Both `curated_selector_len > 0` AND `self_attest_len > 0` | `InvalidPointer` returned to companion; OLED shows `both selector trailers` |

### Common (both paths, after verification)

| Check                                                  | Where               |
|--------------------------------------------------------|---------------------|
| Calldata starts with one of `transfer / transferFrom / approve` selectors | `pick_sign_pages` prefers `render_erc20_*` first; selector bundle is ignored |
| `text_sig` contains an out-of-whitelist type           | `parser::parse_text_sig` declines |
| Calldata body shape doesn't match the type list        | `abi::walk` declines |
| Type list contains a tuple or a nested array           | `abi::classify` declines |
| Static array `T[N]` has `N == 0` or `N > 256`          | `abi::classify` declines |
| More than 6 top-level args                             | `MAX_TYPED_ARGS_RENDERED` declines |

For everything except the hard-fail case, the companion has no way to
distinguish these failure modes from the device side without reading
the OLED. Treat them as "best-effort hint"; the wallet will sign either
way.

---

## 8. What types decode today

Single source of truth: `secure/src/tx/typed_call/parser.rs:260-282`
(parser whitelist) and `secure/src/tx/typed_call/abi.rs:196-225`
(walker classifier).

| Type                                  | Renders | Notes |
|---------------------------------------|---------|-------|
| `uintN` (8..=256, multiples of 8)     | yes     | decimal across up to 2 rows; bare `uint` = `uint256` |
| `intN` (8..=256)                      | yes     | two's-complement → signed decimal; bare `int` = `int256` |
| `address`                             | yes     | hex; replaced with name if the names-DB resolver hits |
| `bool`                                | yes     | literal `true` / `false` |
| `bytes1` … `bytes32`                  | yes     | hex, head/tail eliding when too wide |
| `bytes` (dynamic)                     | yes     | `len: N`, `(binary)`/preview, SHA-256 fingerprint head/tail |
| `string` (dynamic)                    | yes     | `len: N`, ASCII preview, SHA-256 fingerprint |
| `T[N]`, `T[]` where `T` is primitive  | yes     | `[N items]` + first-element preview |
| `(T0, T1, ...)` tuple                 | declines (Phase 2 first cut) |
| `T[][]` nested arrays                 | declines |
| `T[N][M]` nested fixed                | declines |
| Arrays whose element is dynamic       | declines |
| 7+ top-level args                     | declines |

A decline returns `None` from `try_render_typed_call`, so the user
sees the BLIND SIGN flow with the `FUNCTION:` page intact (i.e. the
function name still shows; the args don't).

The companion has no need to predict any of this client-side beyond
respecting the curation invariants in §10. The 4bytes-db curator
already drops anything outside the whitelist (the Python validator in
`tools/build_selectors_json.py` mirrors the firmware-side parser
exactly), so any text_sig the companion finds in `selectors_db.bin`
parses on-device by construction.

---

## 9. Static-shape mismatch

ABI-encoded calldata for `text_sig = "transfer(uint256)"` is exactly
`4 + 32 = 36` bytes. The walker rejects `36 ± k` — including
attacker-mutated calldata that adds trailing junk after a valid
encoding. Concretely the walker enforces:

- `body.len() % 32 == 0` where `body = calldata[4..]`
- Static-head + every dynamic-tail-section sum to exactly `body.len()`
- Dynamic-section offsets appear in arg order, with no gaps, each
  padded to a 32-byte boundary
- Address words have 12 zero bytes of left-padding
- `bool` words are exactly `0x00…00` or `0x00…01`
- `uint`/`int` length words have their top 28 bytes zero (cap at u32
  for offsets and lengths)

A real Solidity ABI encoder produces the canonical shape. If the
companion is constructing calldata with a non-canonical encoder
(stray leading zeros in length words, gaps between tails, …), the
typed render will decline → blind-sign fallback. There's no recovery
at the trusted-UI layer; either generate canonical calldata or skip
the bundle for that call.

---

## 10. Curation invariants (companion-side validator)

If the companion ever generates its own blob (e.g. a registry of
custom dapps the user has added), the curator must enforce the
same gates the canonical curator does. Otherwise the blob's root won't
match and the firmware will reject every bundle.

Reference: `tools/build_selectors_json.py:90-260`.

1. **One canonical `text_sig` per selector.** Adversarial collisions
   exist (every 4-byte selector has roughly 1-in-2³² namespace
   pressure on top of an unbounded function-name space; ENS-squatting
   on `transfer(addr,uint256)` is real). When two text_sigs share a
   selector, drop both — never pick "the one that came first". The
   curator must also drop any text_sig that:
   - doesn't ASCII-match `^[A-Za-z_][A-Za-z0-9_]*\(` for the function
     name,
   - contains any character outside `0x20..=0x7e`,
   - has `len(text_sig) > 63`,
   - parses to anything outside the type whitelist (§8),
   - exceeds 16 top-level args, 32 arena entries, 8 levels of
     nesting, or 8 fields per tuple.

2. **Sort entries by selector, ascending.** Lexicographic over the
   raw 4 bytes. Binary search depends on this.

3. **Intern the string pool.** Identical text-sigs must share a
   `text_off`. The leaf hashes are independent of pool layout, but
   keeping the pool deduplicated keeps blob size linear in distinct
   text-sigs rather than in entries.

4. **Pad leaves to power-of-two by duplicating the last leaf hash.**
   `dbgen::merkle::MerkleTree::build` does this for you; if you
   re-implement, mirror that exactly. The proof-depth field in the
   header is `log2(padded leaf count)`.

5. **Validate via round-trip.** After writing the blob, walk every
   entry, build its bundle, and run `verify_selector_bundle` against
   the freshly-derived root. Refuse to ship if any entry fails.
   `dbgen::selectors::round_trip_check` is the reference.

The Python curator already does all of this; if you stay on the
canonical pipeline (`secure/data/selectors.json` → `dbgen` →
`selectors_db.bin`), you don't have to re-derive any of it. If you
fork the curator, this list is what you have to preserve.

---

## 11. End-to-end example: `transfer(uint256)`

Hypothetical custom token contract whose `transfer` takes only a
uint256 (the recipient is implicit, e.g. derived from `msg.sender`
or pre-bound at construction). Selector
`keccak256("transfer(uint256)")[0..4] = 0x12514bba`.

### Companion side

1. Build the inner calldata:

   ```
   selector = 12 51 4b ba            # 4 bytes
   amount   = 00…00 00 00 03 e8      # 32 bytes, big-endian u256 = 1000
   data     = selector || amount      # 36 bytes
   ```

2. Look up `0x12514bba` in `selectors_db.bin` (binary search).
   Suppose it's at index 1234 with `proof_depth = 18` (so the curated
   set has 2^17 < entries ≤ 2^18 leaves).

3. Build the bundle:

   ```
   selector       = 12 51 4b ba                         (4 bytes)
   text_sig_len   = 17                                  (1 byte)
   text_sig       = "transfer(uint256)"                 (17 bytes ASCII)
   leaf_index     = D2 04 00 00                          (4 bytes LE = 1234)
   proof_depth    = 12 00 00 00                          (4 bytes LE = 18)
   proof          = <18 × 32 = 576 bytes>
   ────────────────────────────────────────────────────────────
   total          = 4 + 1 + 17 + 4 + 4 + 576 = 606 bytes
   ```

4. Pack the SIGN_USEROP payload:

   ```
   [330B header][2 = data_len = 36][36B inner_data]
   [00 00]                                  ← erc20_len   = 0
   [00 00]                                  ← zk_v1_len   = 0
   [00 00]                                  ← zk_v3_len   = 0
   [00 00]                                  ← safe_v1_len = 0
   [02 5E]                                  ← selector_len = 606 (0x025e)
   [<606-byte selector_bundle>]
   ```

5. Send via `CMD_SIGN_USEROP` (cmd 7). No `names_count` byte; the
   firmware infers count = 0 from `cursor == total_len`.

### Device side (what the user sees)

#### Curated path

Page 0:

```
! BLIND SIGN
transfer(uint256)
> next
```

#### Self-attest path

Same calldata, same args, but the companion shipped a self-attest
trailer (e.g. because `0x12514bba` isn't in `selectors_db.bin`):

```
! UNVERIFIED
transfer(uint256)
> next
```

The trusted-UI tail (To, Value, Chain, fees, nonce) is byte-identical
to the curated render. Only the page-0 banner copy and the
fallback-page label change (`FUNCTION:` → `GUESS:` when the typed
walker declines and the device falls through to blind-sign).

Page 1:

```
arg 0 uint256:
1000

> next
```

Page 2:

```
To:
0x… (or `dapp.eth` if
the names DB has it)
> next
```

Then the standard tail pages: chain, max-fee, worst-case, nonce.
`R=Confirm` to sign, `L=Cancel` to abort.

The "BLIND SIGN" banner stays on page 0 by design — Phase 2 attests
the *type list* came from the vendor-curated DB; it does not attest
the *contract semantics* (the contract called `transfer` could
arbitrarily redefine what 1000 means). Dropping the banner entirely
is Phase 3 (per-`(chain_id, contract, selector)` ERC-7730
attestation), not yet built.

---

## 12. Source-file index

| Path                                                | Role                                          |
|-----------------------------------------------------|-----------------------------------------------|
| `shared/src/db_format.rs:275-358`                   | Selectors DB on-disk binary format constants  |
| `secure/data/selectors.json`                        | Curated `(selector, text_sig)` source         |
| `tools/build_selectors_json.py`                     | 4byte-db → `selectors.json` curator + validator |
| `dbgen/src/selectors.rs`                            | `selectors.json` → `selectors_db.bin` writer + round-trip |
| `dbgen/src/merkle.rs`                               | SHA-256 Merkle tree builder (leaf/node hashing) |
| `tools/companion-stub/selectors_db.bin`             | Canonical production blob the companion ships |
| `tx/src/selectors/bundle.rs`                        | Curated wire format + `verify_selector_bundle`; self-attest wire format + `parse_self_attest_bundle`; `SelectorProvenance::{Curated,SelfAttest}` |
| `secure/src/db_roots.rs`                            | `SELECTOR_DB_ROOT` (production + e2e variants) |
| `secure/src/nsc/cmd_sign_userop.rs`                 | Trailer parsing + cross-check + mutual-exclusion guard for both paths |
| `secure/src/tx/typed_call/parser.rs`                | Text-sig tokenizer (whitelist mirrored in py validator) |
| `secure/src/tx/typed_call/abi.rs`                   | Strict ABI walker                             |
| `secure/src/tx/display/typed_call/mod.rs`           | Per-arg page renderer; banner switches on `provenance` |
| `secure/src/tx/display/blind_sign.rs`               | Fallback render; `FUNCTION:` / `GUESS:` label switches on `provenance` |
| `secure/src/tx/display/mod.rs`                      | Dispatcher: typed_call beats blind-sign       |
| `nonsecure/src/selectors_db.rs`                     | Reference Rust blob-lookup + curated bundle-builder |
| `nonsecure/src/e2e_test.rs:267-373`                 | Trailer builders (`append_selector_only_trailers`, `build_self_attest_bundle`, `append_self_attest_only_trailers`, `append_both_selector_trailers`) |
| `nonsecure/src/e2e_test.rs` Scenarios 5b/5c/5d      | Curated path: typed render / cross-check / walker-decline |
| `nonsecure/src/e2e_test.rs` Scenarios 5j/5k/5l      | Self-attest: typed render / keccak-mismatch silent drop / both-trailers refused |
| `tools/webhid_test.html`                            | Browser companion: inline keccak256 + `selectorsDb` module + `buildSelfAttestBundle` + 4byte hint |

---

## 13. What's NOT in this doc

- **4byte.directory as a trust anchor.** The 4byte directory has no
  Merkle root the firmware can verify against, so its results cannot
  drive the curated path. The companion CAN use 4byte as a
  *suggestion source* for the self-attest path: query the API, get
  one or more `text_sig` candidates, run `keccak256(candidate)[..4]`
  locally to confirm the prefix matches the calldata's selector,
  then ship the survivor as a self-attest bundle. Multiple matches
  per selector are common (real adversarial collisions exist) — the
  companion should display all candidates and let the user pick, or
  refuse to pick blindly. `tools/webhid_test.html` shows both
  patterns.
- **Phase 3 per-contract attestation** — the eventual fourth Merkle
  DB keyed on `(chain_id, contract, selector)` carrying ERC-7730-style
  display rules (which arg is "amount" with N decimals, which is
  "recipient", a contract-level display name, …). Sketched in
  `docs/calldata-decoding-handoff.md § Migration to ERC-7730`.
  When that lands, the `BLIND SIGN` / `UNVERIFIED` banners both get
  replaced by `VERIFIED CONTRACT — <display_name>` for covered
  surfaces.
- **EIP-1271 off-chain sigs** — `CMD_SIGN_OFFCHAIN` and the
  PersonalSign mode have their own display path; neither selector
  trailer is consulted there. (PersonalSign messages aren't
  ABI-encoded calldata; they're free-form bytes the dapp wraps in
  EIP-712.)
- **Batch sign** — `CMD_SIGN_USEROP_BATCH` (cmd 30) carries one
  selector trailer per inner UserOp. Same wire format per-tx; the
  outer batch framing is documented in
  `docs/companion-batch-sign-integration.md`.
