# M4 handoff — CowSwap EIP-712 order clear-signing

> **Purpose of this document**: M4 was deferred during the M0–M5 execution
> round that shipped the in-tree Circom toolchain (`circuits/`), the
> `aave_v3_pool` baseline, and the CowSwap `setPreSignature` on-chain
> circuit. This file captures everything learned during that round so
> that a future session can resume M4 without re-discovering the same
> gotchas. It is meant to be read top-to-bottom once before touching any
> code.
>
> Scope: this is a **technical design note**, not a plan. The actual
> implementation plan for M4 should be written separately with current
> repo state as its input.

## TL;DR

1. **The CowSwap display today is essentially static** — `"Pre-sign
   CowSwap order"`, 22 characters, identical for every order. See
   §"What M3 actually achieved" for why.
2. **M4's goal is a display that actually shows what the user is
   trading** — sellToken / buyToken / amounts / validTo / kind.
3. **The big insight** (not in the original plan): you probably do
   **not** need keccak-in-circom. Use Poseidon inside the circuit as
   usual, and compute the EIP-712 keccak digest **natively in the
   secure world** before signing. The firmware feeds the same
   `canonical_order_bytes` into both the ZK verifier (bound via
   Poseidon) and the native EIP-712 digest computation (for the
   actual signature). This sidesteps the ~150k-constraint keccak
   circuit entirely. See §"Key design insight".
4. **M4 is still three distinct pieces of work** that each deserve
   their own PR: (a) the new `cowswap_eip712_order` circuit, (b) a
   firmware code path for EIP-712 message signing (new secure-world
   command or a polymorphic `CMD_CLEAR_SIGN` payload), and (c) the
   associated test vector + e2e wiring mirroring what M3 already
   does.
5. **Do NOT bump `VK_DB_VERSION`** unless you genuinely need the
   `domain` per-entry byte. With the key insight above you probably
   don't — every VK in the DB stays Poseidon-binding, and the
   difference between "calldata" and "EIP-712 order" is a firmware
   dispatch decision on the NS → S payload shape, not a DB-entry
   property.

## 1. What's already shipped (state at the end of M0-M3 + M5)

Reading this section first saves you from fighting assumptions that
no longer match the tree.

### 1.1 The `circuits/` tree is real

Sources, toolchain, build driver, and reproducibility pins all live
under `circuits/`. Layout:

```
circuits/
├── .gitignore                  # node_modules/
├── .tool-versions              # nodejs 22.17.0, circom 2.1.9 (but we
│                               #  actually run 2.2.3 — see below)
├── package.json                # snarkjs 0.7.4, circomlib 2.0.5,
│                               #  circomlibjs 0.1.7, poseidon-bls12381 1.0.2,
│                               #  poseidon-bls12381-circom 1.0.0
├── package-lock.json           # committed
├── ptau.lock                   # SHA-pinned pot14_bls12_381_final.ptau
├── circuits.json               # manifest — one row per circuit
├── README.md                   # authoring workflow + trust note
├── UPSTREAM.md                 # provenance for ZKNoxHQ/ZKlarity imports
├── aave_v3/
│   ├── *.circom                # 6 files, byte-identical copies of
│   │                           #  ZKNoxHQ/ZKlarity@5e8b3f9 with attribution
│   │                           #  headers. NO LICENSE in upstream — treat
│   │                           #  as provisional.
│   └── circuit_final.zkey      # 3.8 MB — committed reproducibility pin
├── cowswap/
│   └── set_pre_signature/
│       ├── circuit.circom      # M3 — written in-tree, NOT from upstream
│       ├── contribution.seed   # 32 bytes, audit record only (see §3.4)
│       └── circuit_final.zkey  # 1.6 MB — committed reproducibility pin
└── scripts/
    ├── vk_json_to_bin.js       # snarkjs vk.json → 960-byte .vk.bin
    ├── vk_bin_to_rust.js       # .vk.bin → secure/src/zk/vk_data.rs
    └── gen_cowswap_e2e_vector.js  # M3 e2e test vector generator
                                #  — REUSE this pattern for M4
```

`tools/build_vks.sh` is the single driver. It has three modes:

1. `--from-zkey <id>=<path>` — explicit external zkey override
2. Auto-detect committed `circuit_final.zkey` next to the circuit
   source (the normal reproducibility path — what both current
   circuits use)
3. Fall-through to full `circom + snarkjs setup + contribute` (used
   when AUTHORING a new circuit for the first time; commit the
   resulting zkey afterward)

Do **not** rewrite this script from scratch. Extending it for M4
should be a single function addition at most.

### 1.2 The VK DB contains two protocols today

```
aave-v3-pool-v1              5 deployments (Aave V3 Pool on 5 chains)
cowswap-set-pre-signature-v1 4 deployments (GPv2Settlement on 4 chains)
```

DB binary format: `shared/src/db_format.rs:142-155`. Magic `b"VKDB"`,
version 1. Entry layout:

```
chain_id    u64 LE   (8)
contract    [u8; 20] (20)
vk_id       u8       (1)
vk_sha_pfx  [u8; 3]  (3)
total                (32 bytes per entry)
```

`VK_DB_VERSION = 1` still. The canonical leaf hash is
`sha256(0x00 || chain_id || contract || vk_bytes)` — no `domain`
byte, no `selector` byte, no protocol-specific metadata. Keep it
that way unless M4 forces a change.

### 1.3 The CMD_CLEAR_SIGN payload is fixed at 612 bytes header + tx + bundle

`shared/src/lib.rs:22-56`:

```
[0..384)         Groth16 proof        (π.A 96 + π.B 192 + π.C 96)
[384..548)       calldata             (164 bytes, zero-padded)
[548..612)       readable string      (64 bytes, null-padded)
[612..616)       tx_len               (u32 LE)
[616..616+tx_len)  EIP-1559 envelope  (strict parser)
[616+tx_len..)   [bundle_len u32 LE][VK bundle]
```

Constants: `ZK_MAX_CALLDATA=164`, `ZK_STRING_LEN=64`, `ZK_PROOF_LEN=384`,
`ZK_HEADER_LEN=612`.

Secure-world handler: `secure/src/nsc.rs::cmd_clear_sign` (line 573
onward, as of M5). This function:

1. Copies the full payload into a secure-stack TOCTOU-safe buffer
2. Parses the fixed header (proof, calldata, readable, tx_len)
3. Parses the EIP-1559 envelope via `eip1559::parse`
4. Cross-checks parsed tx against the calldata field
5. Verifies the VK bundle's Merkle proof against `VK_DB_ROOT`
6. Cross-checks the bundle's `(chain_id, contract)` against the
   parsed tx's `to`
7. Runs Groth16 via `verify_clear_signing_proof(calldata, readable,
   proof, vk)` which internally computes
   `h_tx = Poseidon(calldata, 164)` and
   `h_str = Poseidon(readable, 64)`
8. Renders the `readable` string on the trusted UI across three
   pages + confirm prompt
9. Derives the signing key from the encrypted entropy blob + master
   secret and signs `keccak256(unsigned_envelope)` with SLH-DSA

**This entire path assumes an EIP-1559 tx envelope.** M4 needs a
second path that takes an EIP-712 typed-data payload instead. How
that path integrates is the main firmware design decision — see §4.

### 1.4 `cargo run -p zk-test` passes; `make e2e` has 5 scenarios

- `zk-test` is a host-CPU mirror of the Aave V3 supply Groth16 verify.
  It was pre-broken on master before M0 (`vk_data.rs` had been
  deleted in commit `55b1359`); M2a fixed it by adding
  `circuits/scripts/vk_bin_to_rust.js` which regenerates `vk_data.rs`
  from the committed `.vk.bin`. Re-run
  `node circuits/scripts/vk_bin_to_rust.js --in
  secure/data/vks/aave_v3_pool.vk.bin --out secure/src/zk/vk_data.rs`
  after any VK change.
- `make e2e` drives the full QEMU stack through 5 scenarios. The 5th
  (`cowswap_pre_sign`) is what M3 added. The test vector is
  auto-generated by `circuits/scripts/gen_cowswap_e2e_vector.js` and
  its output is pasted statically into `nonsecure/src/e2e_test.rs`
  between `// ── AUTO-GENERATED BEGIN` and `// ── AUTO-GENERATED END`
  markers. Groth16 prove is randomised, so successive regenerations
  produce different proof bytes — that's expected.

### 1.5 Supporting docs already updated

- `docs/architecture.md` — §"Building the ERC20 + VK databases" now
  describes the `circuits/` pipeline. §"Release-review workflow" was
  rewritten to remove every reference to on-chain
  `clearSigningVKHash`. That language should **never** come back.
- `README.md` — "Adding a ZK clear-signing protocol" section was
  rewritten to walk through `circuits/` + `tools/build_vks.sh` +
  `dbgen`.
- `circuits/README.md` — authoring workflow + reproducibility model.
- `circuits/UPSTREAM.md` — the "why is there a 3.8 MB .zkey file
  checked in" story.

### 1.6 Trust model (hardware-only, no on-chain anchoring)

This was tightened during M2a:

```
firmware-signing key
      ↓  signs
firmware release (containing VK_DB_ROOT in secure flash)
      ↓  anchors
VK_DB_ROOT                          [32 bytes in secure/src/db_roots.rs]
      ↓  Merkle-proves
(chain_id, contract, vk_bytes)      [NS-supplied bundle at sign time]
      ↓  Groth16-verifies
proof π binds calldata → readable   [displayed on trusted UI]
```

There is **no** `clearSigningVKHash` comparison anywhere in the
project. Not automated, not manual. The release reviewer just diffs
`secure/data/vks.review.txt` against the previous release as a
build-traceability check. M4 must not reintroduce any on-chain
governance lookup.

## 2. What M3 actually achieved (and its limitations)

M3 shipped `circuits/cowswap/set_pre_signature/circuit.circom`, a
216-line Circom file covering
`GPv2Settlement.setPreSignature(bytes orderUid, bool signed)`. It
verifies (see the circuit source for details):

1. selector == `0xec6cb13f`
2. ABI bytes offset == `0x40`
3. bool signed == `1`
4. ABI bytes length == `56`
5. The 8-byte tail padding after the orderUid is zero
6. The readable string is exactly `"Pre-sign CowSwap order"`
   (22 ASCII bytes + 42 zero bytes)
7. Poseidon255 bindings: `Poseidon(calldata, 164) == H_tx` and
   `Poseidon(readable, 64) == H_str`

Constraint count: **2426** (compile output in the M3 session; well
under the 16384 pot14 budget).

### 2.1 What the user sees today

Three pages on the trusted UI (verified end-to-end via `make e2e`):

```
Page 1/3:                    Page 2/3:                    Page 3/3:
+----------------+           +----------------+           +----------------+
|ZK Clear Sign   |           |Pre-sign CowSwap|           |                |
|Proof verified! |           | order          |           |  Long-press:   |
|                |           |                |           |  L=Cancel      |
|  [scroll ->]   |           |                |           |  R=Confirm     |
+----------------+           +----------------+           +----------------+
```

22 characters of **static text**, identical for every order. The
user learns that this is "some CowSwap setPreSignature call with
signed=1" — nothing about which order, which tokens, which amounts,
which owner, or which expiry.

### 2.2 What's inherently visible vs opaque in setPreSignature calldata

The 56-byte orderUid decomposes as:

| Offset | Field | Wallet can decode? | Useful to display? |
|---|---|---|---|
| `[0..32)` | `orderDigest` = `keccak256(GPv2Order struct)` | No — opaque hash | No, but worth showing ~8 bytes hex as a discriminator |
| `[32..52)` | `owner` (20-byte address) | Yes — raw bytes | Yes — should cross-check against wallet's own address |
| `[52..56)` | `validTo` (uint32 BE Unix) | Yes — raw bytes | Yes — expiry timestamp |

The meaningful semantic fields (`sellToken`, `buyToken`, `sellAmount`,
`buyAmount`, `appData`, `feeAmount`, `kind`, ...) live **only in the
off-chain struct** that the orderDigest commits to. The wallet never
sees them through `setPreSignature` alone. This is the fundamental
reason M3's display is weak: the data simply isn't in the calldata.

### 2.3 Three tiers of incremental improvement WITHOUT M4

For context — these are cheaper alternatives M4 should be compared
against:

**Tier 0 (firmware-only, ~20 LOC):**
Extract `calldata[132..152]` (the `owner` slice of the orderUid)
and cross-check against the wallet's own signing address
post-Groth16. Reject if different. Doesn't change the display but
removes the main attack (a dApp tricking the user into pre-signing
a third party's order). **Strongly recommended to ship this
regardless of whether M4 lands.** Owner derivation already exists
in `secure/src/crypto/derive_signing_key_from_entropy` — you just
need to compute the address from the SLH-DSA public key.

Note: SLH-DSA → Ethereum address mapping is not standard. The
wallet's "own address" is whatever it chose to derive. If this
project uses a specific derivation, reference it here. If not, this
check only makes sense once an address convention is fixed.

**Tier 1 (circuit extension, ~1000 extra constraints):**
Extend `circuits/cowswap/set_pre_signature/circuit.circom` to
format part of the orderUid as ASCII hex into the readable string.
Something like:

```
+----------------+
|CowSwap order   |
|0xaabbccddeeff..|   ← first 8 bytes of orderDigest
|own 0x742d..f44e|   ← truncated owner
|exp 0x68000000  |   ← validTo as 8 hex chars
+----------------+
```

Still 64 ASCII bytes across 4 lines of 16. The circuit decodes
bytes → nibbles (4 constraints per byte for the `value == hi*16 + lo`
check) → ASCII (`nibble + 48` or `nibble + 87`). ~50 constraints
per hex digit. Comfortably fits pot14.

**Tier 2 (circuit extension, moderate):**
Decode `validTo` as a date. Division by 86400, leap year logic.
Fiddly in circom, doable, not small. Skip unless Tier 1 is shipped
and users ask for it.

**Tier 3 = M4 (full order preview):**
See §3 onward.

## 3. M4 proper — full EIP-712 GPv2Order clear-signing

### 3.1 The fundamental distinction from setPreSignature

Two different user flows involve CowSwap:

| Flow | What's signed | Current wallet support |
|---|---|---|
| `setPreSignature` on-chain call | EIP-1559 tx wrapping `setPreSignature(orderUid, true)` — the tx hash goes to the chain; the `owner` field in the orderUid is what the settler compares signatures against | **M3 — weak display** |
| Direct EIP-712 order signing | A 65-byte ECDSA signature over `keccak256("\x1901" || domainSeparator || structHash)` — the signature goes to the solver/settler off-chain; no on-chain tx | **M4 — not started** |

In the EIP-712 flow, the wallet is not producing an Ethereum
transaction at all. It's producing a **message signature** over a
typed-data digest. The secure world's current sign path is
hard-coded around EIP-1559 envelopes (`secure/src/tx/eip1559.rs`,
`secure/src/nsc.rs::cmd_clear_sign`, the constant `ZK_HEADER_LEN`
assumes a `tx_len u32` field, etc.). M4 needs either a second
command or a polymorphic version of the existing one.

### 3.2 What an EIP-712 GPv2Order actually looks like

```solidity
// From cowprotocol/contracts:
struct Data {
    IERC20  sellToken;              // 20-byte address
    IERC20  buyToken;                // 20-byte address
    address receiver;                // 20-byte address
    uint256 sellAmount;              // 32 bytes
    uint256 buyAmount;               // 32 bytes
    uint32  validTo;                 // 4 bytes
    bytes32 appData;                 // 32 bytes (hash of arbitrary metadata)
    uint256 feeAmount;               // 32 bytes
    bytes32 kind;                    // 32 bytes ("sell" or "buy" as keccak hash)
    bool    partiallyFillable;       // 1 byte
    bytes32 sellTokenBalance;        // 32 bytes ("erc20" | "external" | "internal")
    bytes32 buyTokenBalance;         // 32 bytes ("erc20" | "internal")
}
// Total ABI-encoded: 12 fields × 32 bytes (addresses are left-padded to 32) = 384 bytes.
```

`structHash = keccak256(abi.encode(ORDER_TYPEHASH, <all 12 fields>))`
where `ORDER_TYPEHASH` is a compile-time constant
(`keccak256("Order(address sellToken,address buyToken,...)")`).

`domainSeparator = keccak256(abi.encode(EIP712_DOMAIN_TYPEHASH,
keccak256("Gnosis Protocol"), keccak256("v2"), chainId,
verifyingContract))`. This is **chain-dependent and contract-dependent**
but otherwise constant per deployment.

`digest = keccak256("\x19\x01" || domainSeparator || structHash)`.

The user's ECDSA signature is over `digest`, not over the struct
directly. The settler recovers the signer from `digest`, not from
the struct bytes. So the **authoritative binding** is to `digest`,
not to any other hash.

### 3.3 Key design insight — keccak stays OUT of the circuit

**This is the most important thing to understand about M4.** The
original plan assumed the Groth16 circuit would recompute the
EIP-712 digest (including a keccak-in-circom of the struct). That
path needs ~150k+ constraints and a `pot18` (~600 MB) or larger
ptau file, plus bit-level keccak plumbing that is genuinely
expert-level Circom work.

**You don't need any of that.** Here's why.

The wallet needs to do exactly two things:

1. Produce a signature that settles the order: the signature is
   over `keccak256("\x1901" || domainSeparator || structHash)`.
2. Convince the user, on the trusted display, that the bytes being
   signed correspond to a specific human-readable string (sell X,
   buy Y, expiry Z, ...).

The Groth16 proof's job is **only** to back claim 2. It does not
need to compute or expose the EIP-712 digest. It just needs to
bind the readable string to the same `order_canonical_bytes` that
the secure world is about to sign.

So:

- **In the circuit**: use Poseidon — exactly like Aave and CowSwap
  on-chain do today. Two public signals: `H_order = Poseidon(order_canonical_bytes)`
  and `H_str = Poseidon(readable)`. Private witness is the struct
  fields.
- **In the secure world**: take the same `order_canonical_bytes`
  from the NS → S payload, compute Poseidon (matches `H_order` →
  feeds the Groth16 verifier), AND natively compute the EIP-712
  keccak digest (this is the thing actually signed with the SLH-DSA
  signing key). The binding between "what the user saw" and "what
  got signed" is that the firmware computed both from the same
  in-memory buffer in the same function call.

The canonical encoding is a design choice. Simplest: use the ABI
encoding of the struct (384 bytes), which matches what
`keccak256(abi.encode(...))` would hash anyway. Then:

```rust
// In the secure world, roughly:
fn cmd_clear_sign_eip712(payload: &[u8]) -> NscStatus {
    // 1. Copy to secure stack, parse header
    // 2. Run VK bundle Merkle check against VK_DB_ROOT
    // 3. Compute h_order = poseidon_bytes(order_canonical, 384)
    //    Compute h_str   = poseidon_bytes(readable, 64)
    //    Run groth16_verify(proof, vk, h_order, h_str)
    // 4. NOW compute the real EIP-712 digest natively:
    //    struct_hash  = keccak256(ORDER_TYPEHASH || order_canonical)
    //    domain_sep   = lookup or recompute per chain_id + contract
    //    digest       = keccak256("\x1901" || domain_sep || struct_hash)
    // 5. Display readable, confirm, then sign digest with SLH-DSA
}
```

This turns M4 from "write a keccak circuit" into "add a keccak
crate to the secure world" — 100× less work.

The `sha3` crate's `Keccak256` type is no_std-compatible and adds
~5 KB of code. It's already in common use in embedded Ethereum
wallets.

### 3.4 What this means for the VK DB format

With the insight above, the VK DB format does **not** need a
`domain` byte. Every VK in the DB is Poseidon-binding; the
firmware decides at dispatch time whether to wrap the witness in
an EIP-1559 parse (existing) or an EIP-712 canonical parse (new),
based on the incoming command.

**Keep `VK_DB_VERSION = 1`.** No binary format changes. No
parser changes. No `shared/src/db_format.rs` changes. No
`nonsecure/src/vk_db.rs` changes. No `secure/src/zk/vk_bundle.rs`
changes. No `dbgen/src/vks.rs` changes to the on-disk layout.

The only dbgen-visible change M4 might need is letting `vks.json`
carry an optional `"domain"` or `"flow"` field *for the human
reviewer*, without writing it into the binary. Even that is optional.

### 3.5 Recommended command strategy

Option A — second command (cleaner):
```
CMD_NONE              = 0
CMD_GET_REMAINING     = 1
CMD_REQUEST_UNLOCK    = 2
CMD_GET_PUBKEY        = 3
CMD_SIGN              = 4
CMD_CLEAR_SIGN        = 5  (existing, EIP-1559 wrapped)
CMD_CLEAR_SIGN_MSG    = 6  (new — EIP-712 typed-data)
```

Dispatcher: `secure/src/nsc.rs::dispatch` at line 156. Add one arm.

Option B — polymorphic CMD_CLEAR_SIGN with a leading discriminator
byte. Slightly less code in `nsc.rs` but breaks the "one command,
one job" invariant and forces the NS-side payload builder to branch
inside a single command id.

**Recommendation: Option A.** It's a 1-line dispatch arm and a
parallel 100-line handler that shares helpers (Merkle verify,
Poseidon, Groth16, confirm, sign) with the existing handler.

### 3.6 NS → S payload layout for CMD_CLEAR_SIGN_MSG

Strawman:

```
[0..384)         Groth16 proof         (π.A 96 + π.B 192 + π.C 96)
[384..384+CAN)   order_canonical       (384 bytes, ABI-encoded struct)
[384+CAN..+64)   readable string       (64 bytes, null-padded)
[...]            [bundle_len u32 LE][VK bundle]
```

Where `CAN = 384`. No tx envelope (there's no tx). No calldata
(the witness is the canonical struct). Total fixed header:
`384 + 384 + 64 = 832` bytes, plus the bundle.

Unlike `CMD_CLEAR_SIGN`, there is no EIP-1559 parse step. The
secure world instead uses the bundle's `(chain_id, contract)` to
look up the correct `domainSeparator` (either recomputed on the
fly, or pulled from a hard-coded table of CowSwap deployments
keyed on `chain_id`, which is simpler and more gas-efficient — the
domain separator is fixed per contract deployment and there are
only ~5 CowSwap chains).

Add constants to `shared/src/lib.rs`:

```rust
pub const EIP712_CANONICAL_LEN: usize = 384;
pub const EIP712_STRING_LEN: usize = 64;
pub const EIP712_PROOF_LEN: usize = 384;
pub const EIP712_HEADER_LEN: usize =
    EIP712_PROOF_LEN + EIP712_CANONICAL_LEN + EIP712_STRING_LEN;  // 832
```

### 3.7 File-by-file change list (M4 bill of materials)

**New files:**

- `circuits/cowswap/eip712_order/circuit.circom` — new circuit.
  Binds `order_canonical` (384 bytes) and `readable` (64 bytes)
  with Poseidon. Decodes the struct fields internally and
  constrains the readable against them. Reuses
  `circuits/aave_v3/abi_primitives.circom` (SlotSelector,
  ExtractAddress, ExtractUint256, etc.) and the `PackBytes31` /
  `PoseidonBytes` templates. See §5 for the Poseidon budget.
- `circuits/cowswap/eip712_order/contribution.seed` — 32 bytes,
  audit record.
- `circuits/cowswap/eip712_order/circuit_final.zkey` — produced
  once, committed as the reproducibility pin (see §3.10).
- `circuits/scripts/gen_cowswap_eip712_e2e_vector.js` — mirror of
  the M3 generator for the on-chain path. Takes an order struct,
  produces witness, runs `snarkjs groth16 prove`, emits Rust
  snippet for pasting into `e2e_test.rs`.
- `secure/src/tx/eip712.rs` — new module. Computes the EIP-712
  digest natively: `keccak256("\x1901" || domain_sep ||
  struct_hash)`. Carries a small table of
  `(chain_id, verifying_contract) → domain_separator` for the
  supported CowSwap deployments.

**Modified files:**

- `shared/src/lib.rs` — add `CMD_CLEAR_SIGN_MSG = 6`, add
  `EIP712_*` constants.
- `shared/Cargo.toml` — possibly nothing; the `sha3` dep lives on
  the secure crate only.
- `secure/Cargo.toml` — add `sha3 = { version = "0.10",
  default-features = false }` for keccak256. no_std compatible.
- `secure/src/nsc.rs` — new `cmd_clear_sign_msg` handler parallel
  to `cmd_clear_sign`. Add a dispatch arm in `dispatch` at line
  156. Emit a new `[S][e2e] cmd_clear_sign_msg dispatch = ZkClearSignMsg`
  log for the e2e harness to assert on.
- `secure/src/zk/groth16.rs` — optional: a second entry point
  `verify_clear_signing_proof_bytes(canonical: &[u8;
  EIP712_CANONICAL_LEN], readable: &[u8; 64], proof, vk)` that
  takes a 384-byte canonical buffer instead of 164-byte calldata.
  Or make `verify_clear_signing_proof` generic over the length of
  its first argument. The current signature is hard-coded to
  `[u8; MAX_CALLDATA]` where `MAX_CALLDATA = 164`.
- `secure/src/zk/poseidon.rs` — check whether we already support
  `poseidon_bytes` for N = 384. Currently it handles 164 (→
  `poseidon6`, 6 blocks) and 64 (→ `poseidon3`, 3 blocks). For
  384 bytes we need ceil(384/31) = 13 blocks → `poseidon13`
  (t=14). That's a **new Poseidon instance** with new round
  constants and a new MDS matrix. Adding it means:
    - Extracting `poseidon13` params from the
      `poseidon-bls12381` npm package
    - Regenerating `secure/src/zk/poseidon_constants.rs` via a
      retargeted `tools/export_zk_constants.js`
    - Exposing a new `poseidon13` branch in `poseidon_bytes()`
  This is not trivial but it's mechanical. **Unless you can get
  the canonical encoding down to ≤ 310 bytes (10 blocks,
  `poseidon10`), in which case pick whichever existing instance
  the upstream package ships.** Actually the upstream ships
  `poseidon2..poseidon16`, so `poseidon13` is almost certainly
  available out of the box.
- `secure/src/zk/mod.rs` — re-exports for new constants.
- `nonsecure/src/nsc_api.rs` — add `clear_sign_msg()` forwarder
  (mirror of `clear_sign()` at `nsc_api.rs:107`).
- `nonsecure/src/e2e_test.rs` — scenario 6 `cowswap_eip712_order`
  mirroring scenario 5 but exercising the new command + new
  payload shape + the new test vector.
- `Makefile` — add `"\\[S\\]\\[e2e\\] cmd_clear_sign_msg dispatch =
  ZkClearSignMsg"` and `"\\[E2E\\] cowswap_eip712_order = PASS"`
  to the assertion list in the `e2e` target.
- `secure/data/vks.json` — new protocol row
  `cowswap-eip712-order-v1` with the chains where CowSwap is
  deployed (same CREATE2 address across all EVM chains). `dbgen`
  will pick it up automatically once `vk_file` points to a
  committed `.vk.bin`.
- `circuits/circuits.json` — new row for `cowswap_eip712_order`.
- `docs/architecture.md` — ZK clear-signing section gets a second
  payload shape diagram. The "canonical leaf encoding" section
  stays the same.
- `docs/m4-cowswap-eip712.md` (this file) — delete or mark as
  "historical" once M4 is done.

**NOT modified (explicitly):**

- `shared/src/db_format.rs` — VK DB format stays at v1
- `dbgen/src/vks.rs` — the builder doesn't care about command type
- `nonsecure/src/vk_db.rs` — the lookup API is already
  `(chain_id, contract) → bundle`
- `secure/src/zk/vk_bundle.rs` — the bundle wire format is
  unchanged; we're just adding a different header shape above it

### 3.8 The circuit — what it actually does

Goal: decode a 384-byte ABI-encoded GPv2Order struct into a
readable string like:

```
Sell 100.00 USDC
for buy 0.05 WETH
exp 0x68abcdef
partial=0
```

Or, broken across four 16-char lines of the confirm page. The
exact format is a UX decision.

Constraints the circuit must enforce:

1. The 384-byte canonical encoding contains exactly the 12 fields
   at the expected offsets (address slots zero-padded to 32B,
   bool at byte 31 of its slot, etc.)
2. `sellToken` address resolves through a `TokenRegistry` (reuse
   Aave's or extend it — see `circuits/aave_v3/token_registry.circom`)
3. `buyToken` similarly
4. `sellAmount` formatted with `sellToken`'s decimals
5. `buyAmount` formatted with `buyToken`'s decimals
6. `validTo` as hex or timestamp
7. The readable string is a byte-for-byte match of the formatted
   result
8. `Poseidon(canonical, 384) == H_order`
9. `Poseidon(readable, 64) == H_str`

Constraint budget estimate:
- ABI walker: ~200 constraints (12 fields × ~15 constraints each)
- Two token registry lookups: 2 × ~200 = ~400 constraints
- Two amount formatters: 2 × ~600 = ~1200 constraints (same as
  Aave's single formatter)
- String assembly: ~500 constraints (more complex than Aave
  because 5-part output)
- PoseidonBytes(384) ≈ 13 blocks × ~500 constraints = ~6500
  constraints (vs ~3000 for Aave's PoseidonBytes(164))
- PoseidonBytes(64) ≈ ~1500 constraints (same as Aave)
- Total: roughly **~10,000-12,000 constraints**

Still comfortably under `pot14 = 16384`. No ptau upgrade needed.

### 3.9 Token registry expansion

Aave's registry (`circuits/aave_v3/token_registry.circom`) has 8
tokens. CowSwap users trade many more pairs. Options:

- **Option 1**: ship M4 with Aave's 8 tokens only. Any order
  involving an unknown token fails the circuit. Coverage is
  narrow (USDC/USDT/DAI/WETH/WBTC/wstETH/LINK/AAVE only), but
  shipping is quick.
- **Option 2**: expand the registry to ~30 common tokens across
  the major chains. Each added token is ~30 constraints
  (IsZero on address comparison + mux for symbol/decimals). 30
  tokens ≈ 900 extra constraints. Still within budget. This is
  probably the right move for M4 since the entire value of M4
  is better UX, and a registry of 8 tokens limits that.
- **Option 3**: a Merkle-verified token registry where the full
  list lives in NS rodata (analogous to the VK DB model itself).
  Circuit only verifies a single Merkle inclusion per token,
  which is size-constant. This is the future-proof answer but
  it's its own design problem (how does the circuit receive the
  Merkle proof as a witness? what's the root? does it match the
  erc20_db root?). **Defer to a follow-up.**

The existing `secure/data/erc20.json` already has the metadata
for ~218 tokens across 8 chains. In principle the circuit could
share the exact same dataset via Option 3. That's the elegant
long-term answer but it's beyond M4's core scope. Mention it in
the M4 plan as a follow-up.

### 3.10 Reproducibility of the M4 circuit

**snarkjs 0.7.4's `zkey contribute` is not deterministic** even
with `-e=<hex>` pinned entropy. This was verified empirically
during M3 (three runs with identical inputs produced three
different zkeys; see the test near the end of M3 execution).

**The workaround: commit `circuit_final.zkey` in-tree next to the
circuit source.** `tools/build_vks.sh` auto-detects this file and
extracts the VK from it via `snarkjs zkey export verificationkey`,
skipping the non-deterministic setup pipeline entirely.
Subsequent runs produce byte-identical `.vk.bin`.

When you author the M4 circuit:

1. Write `circuits/cowswap/eip712_order/circuit.circom`
2. Write `circuits/cowswap/eip712_order/contribution.seed` (audit
   record only)
3. Add the row to `circuits/circuits.json`
4. `tools/build_vks.sh cowswap_eip712_order` — runs the full
   pipeline ONCE, producing `build/circuits/cowswap_eip712_order/circuit_final.zkey`
5. Review the `.vk.bin` (byte layout, sha256)
6. Copy the `.zkey`:
   ```sh
   cp build/circuits/cowswap_eip712_order/circuit_final.zkey \
      circuits/cowswap/eip712_order/circuit_final.zkey
   git add circuits/cowswap/eip712_order/circuit_final.zkey
   ```
7. From here on `tools/build_vks.sh cowswap_eip712_order` uses
   the committed zkey and is byte-stable.

Expected zkey size: ~8-12 MB (scaled from the 1.6 MB cowswap
on-chain zkey by the ~5× constraint-count factor). That's a
meaningful repo bloat. Budget discussion: the existing repo
committed `circuits/aave_v3/circuit_final.zkey` (3.8 MB) and
`circuits/cowswap/set_pre_signature/circuit_final.zkey` (1.6 MB)
for a total of 5.4 MB. Adding ~10 MB more pushes that to ~15 MB.
Still acceptable for a firmware project but worth calling out.

### 3.11 Test vector generation — reuse the M3 pattern

Study `circuits/scripts/gen_cowswap_e2e_vector.js` before writing
the M4 equivalent. Key structural points to copy:

1. **Poseidon hash computation** uses the `poseidon-bls12381` JS
   package (`poseidon6`, `poseidon3`, etc.). For
   `PoseidonBytes(384)` you need `poseidon13` — verify it's in the
   JS package (it should be).
2. **Witness generation** uses the circom-compiled
   `build/circuits/<id>/circuit_js/generate_witness.js` +
   `circuit.wasm`. This means the M4 circuit must be **compiled
   at least once** before test vector generation — the committed
   zkey alone is not enough for witness generation; you also
   need the wasm. Handle this by checking for the wasm path in
   the generator script and emitting a helpful error if
   missing, identical to how M3's script does it.
3. **`snarkjs groth16 prove` is randomised**, so the proof bytes
   change every regeneration. Commit the bytes statically in
   `nonsecure/src/e2e_test.rs` between `AUTO-GENERATED BEGIN/END`
   markers.
4. **RLP encoding** is not needed for the EIP-712 flow (there's
   no tx envelope). Drop the ethers dependency from the M4
   generator; only the EIP-712 canonical bytes are needed.
5. **Sanity-verify the proof locally** before emitting the
   snippet:
   ```js
   execSync(`"${SNARKJS}" groth16 verify "${vkJsonPath}"
               "${publicPath}" "${proofPath}"`);
   ```
   The M3 generator does this and it catches 90% of integration
   bugs.

### 3.12 `make e2e` integration

The M3 scenario pattern is:

- Static byte arrays in `nonsecure/src/e2e_test.rs` between the
  `AUTO-GENERATED` markers
- A `{}` block in `fn main()` that looks up the VK from `vk_db`,
  builds the clear-sign payload, calls `nsc_api::clear_sign`
  (or `clear_sign_msg` for M4), reports pass/fail
- A `grep` assertion in the `Makefile` `e2e` target's `for line
  in` list

Follow this pattern exactly for the M4 scenario. Name the
scenario `cowswap_eip712_order`. Expect to assert on both:

```
"\\[S\\]\\[e2e\\] cmd_clear_sign_msg dispatch = ZkClearSignMsg"
"\\[E2E\\] cowswap_eip712_order = PASS"
```

The `cmd_clear_sign_msg` dispatch log line should be added to
the new handler in `secure/src/nsc.rs`, mirroring the existing
`cmd_clear_sign dispatch = ZkClearSign` log at line 735.

## 4. Gotchas (things I learned the hard way in M0–M5)

Read this section before touching the code. Each item cost me
actual debugging time.

### 4.1 snarkjs 0.7.4 `zkey contribute` is non-deterministic

Verified empirically. Three runs with the EXACT same inputs
(same r1cs, same ptau, same `-e=<hex>` entropy) produced three
different zkeys. The `contribution.seed` files you see in the
repo are audit records only — they do **not** guarantee byte
stability. **Reproducibility is via the committed
`circuit_final.zkey`, nothing else.** Do not waste time trying
to make `zkey contribute` reproducible.

### 4.2 circom version mismatch is fine (2.1.9 pinned, 2.2.3 used)

`circuits/.tool-versions` pins `circom 2.1.9`, but the
`circom 2.2.3` binary I installed at `~/.local/bin/circom`
worked correctly for both circuits. circom 2.x is pragma-level
stable across the 2.1.x – 2.2.x line. Don't flip out if the
version doesn't exactly match. Do update `.tool-versions` when
you verify a newer version works.

### 4.3 The ZKlarity upstream directory is at
`/home/markus/Documents/zk_clear_signing/`, **not** `ZKlarity/`

The upstream repo is named `ZKNoxHQ/ZKlarity` but the local
clone on this machine is called `zk_clear_signing`. Scripts
that look for `../../ZKlarity` will not find it.
`tools/export_zk_constants.js` has a stale default path to
`../../ZKlarity` from the original import — pass the path
explicitly or update the default.

Relevant paths on this developer machine:

```
/home/markus/Documents/zk_clear_signing/
├── circuits/              # 6 .circom files (Aave V3 clear-signing)
├── keys/
│   ├── circuit_final.zkey # 3.8 MB — source of aave_v3 zkey pin
│   └── verification_key.json
├── pot/
│   └── pot_final.ptau     # 28 MB, sha256 10733b838b5f85c4...
├── proof_{supply,borrow,repay,withdraw}.json
├── public_{supply,borrow,repay,withdraw}.json
└── witness_{supply,borrow,repay,withdraw}.wtns
```

Upstream commit the files were imported from:
`ZKNoxHQ/ZKlarity @ 5e8b3f9`.

### 4.4 Upstream has no `LICENSE` file

The .circom files under `circuits/aave_v3/` are copied from an
upstream with no `LICENSE`. The user elected to copy with
attribution headers (see `circuits/UPSTREAM.md`). Any new
circuit you write that reuses Aave's primitives inherits the
same provisional-license status. Flag this prominently if M4
ever gets prepared for open-source release.

### 4.5 circom `include "../../node_modules/..."` is relative to the .circom file

Our layout `circuits/<proto>/<action>/circuit.circom` means the
include path is `../../node_modules/...` (two levels up to
`circuits/`, then into `node_modules/`). Upstream's flat layout
uses `../node_modules/...`. If you copy files from upstream,
you do NOT need to rewrite include paths as long as you
preserve the directory depth — see the M0 analysis where this
turned out to work unmodified because our `circuits/aave_v3/`
mirrors upstream's `circuits/` depth.

### 4.6 The circom `-l` flag adds a library search path

Used by `tools/build_vks.sh` as `-l $NODE_MODULES` where
`$NODE_MODULES = circuits/node_modules`. This means `include
"circomlib/..."` works in addition to the explicit relative
path. Don't delete `-l` from build_vks.sh without understanding
what breaks.

### 4.7 BLS12-381 G2 uses `c1-first` byte order for uncompressed

The `bls12_381` Rust crate's `G2Affine::from_uncompressed`
expects `x.c1 || x.c0 || y.c1 || y.c0`, each as 48-byte
big-endian. **NOT** `c0`-first. This is different from some
Ledger C implementations which use `c0`-first.

The canonical source of this convention in the repo is
`tools/export_zk_constants.js::g2Bytes`. The copy at
`circuits/scripts/vk_json_to_bin.js::g2Bytes` is a duplicated
helper (with a TODO comment noting the duplication). Both
files agree on the same order. Don't flip them.

### 4.8 `component main` in included files breaks the include chain

`circuits/aave_v3/clear_signing_proof.circom` has a
`component main {public [H_tx, H_str]} = ClearSigningProof();`
at the bottom. That means you can't `include` this file from
another .circom file — circom will reject a file that has two
`component main`s.

Consequence: if M4 wants to reuse the `PoseidonBytes` and
`PackBytes31` templates that currently live inside
`clear_signing_proof.circom`, you must **copy** them rather
than include them. The M3 circuit does exactly this
(`circuits/cowswap/set_pre_signature/circuit.circom` has
`CsPackBytes31` and `CsPoseidonBytes` as local copies with
`Cs`-prefixed names to avoid collision).

The cleanest long-term fix is to lift `PoseidonBytes` and
`PackBytes31` into a shared `circuits/lib/poseidon_bytes.circom`
file that both Aave and CowSwap circuits include. M3 deferred
this refactor with a TODO comment. **M4 is a good time to do
the refactor.**

### 4.9 `cargo run -p zk-test` was pre-broken on master

At the start of M0, `cargo run -p zk-test` failed to compile
because `secure/src/zk/vk_data.rs` had been deleted in commit
`55b1359` (the commit that moved VK storage to NS rodata), but
`zk-test/src/main.rs:25` still had `mod vk_data;`. M2a fixed it
by regenerating `vk_data.rs` from the committed `.vk.bin` via
the new `circuits/scripts/vk_bin_to_rust.js` script.

**If you wipe `secure/src/zk/vk_data.rs` again (e.g., during
development), regenerate it** with:

```sh
node circuits/scripts/vk_bin_to_rust.js \
  --in  secure/data/vks/aave_v3_pool.vk.bin \
  --out secure/src/zk/vk_data.rs
```

### 4.10 `nonsecure/src/vk_db.bin`, `secure/src/db_roots.rs`, `secure/data/vks.review.txt` are generated

`cargo run -p dbgen` produces all three from `secure/data/vks.json`
+ `secure/data/vks/*.vk.bin`. Do not edit them by hand. The
`nonsecure/build.rs` has a magic-bytes validator that fails the
build if `vk_db.bin` doesn't start with `b"VKDB"`, which
catches most out-of-band edits.

The Merkle root changes every time the VK set changes. After
M4 adds `cowswap_eip712_order`, the root will bump again — this
is expected and cascades to `secure/src/db_roots.rs`.

### 4.11 SLH-DSA signatures are 17,088 bytes

This matters for the payload sizes in `e2e_test.rs`. The
`SIG_BUF: [u8; SIGNATURE_LEN]` static needs that much SRAM
regardless of what kind of clear-sign is happening. If M4 adds
a new scenario, it reuses the same `SIG_BUF` — no change.

### 4.12 The secure world buffer sizes in `e2e_test.rs`

```rust
const CLEAR_SIGN_BUF_LEN: usize = ZK_HEADER_LEN + 4096 + 4 + 2048;
static mut CLEAR_SIGN_BUF: [u8; CLEAR_SIGN_BUF_LEN] = [0u8; CLEAR_SIGN_BUF_LEN];
```

This assumes `ZK_HEADER_LEN = 612`. For the M4 payload (header
= 832), you'll either need a second buffer with
`EIP712_HEADER_LEN + bundle_len + slop` or widen this one to
take the max of both. Probably cleaner to add
`CLEAR_SIGN_MSG_BUF` as a second static.

`VK_BUNDLE_BUF` stays 2048 bytes — the bundle wire format is
unchanged by M4.

### 4.13 Keccak256 crate options for no_std secure world

Good choices:

- `sha3 = { version = "0.10", default-features = false }` —
  the standard one. ~5 KB code size. Well-audited.
- `tiny-keccak = { version = "2", default-features = false }` —
  smaller but less ergonomic API.
- Hand-rolled Keccak-f[1600] — unnecessary; the sha3 crate is
  fine.

The secure crate already pulls in `sha2` for PBKDF2 etc.
Adding `sha3` alongside is uncontroversial.

### 4.14 Don't regenerate `poseidon_constants.rs` unless you need to

`secure/src/zk/poseidon_constants.rs` is a generated file
containing ~2000 lines of Poseidon round constants extracted
from the `poseidon-bls12381` npm package by
`tools/export_zk_constants.js`. It currently contains
`poseidon3` and `poseidon6` params (for `PoseidonBytes(64)` and
`PoseidonBytes(164)`).

If M4's `PoseidonBytes(384)` needs `poseidon13`, you must:

1. Verify `poseidon-bls12381` actually exports `poseidon13`
   (looking at upstream's package: it ships poseidon2..
   poseidon16, so yes)
2. Extend `tools/export_zk_constants.js` to also extract
   poseidon13 params from
   `node_modules/poseidon-bls12381/src/instances/poseidon13.ts`
3. Regenerate `poseidon_constants.rs`
4. Add the corresponding case to
   `secure/src/zk/poseidon.rs::poseidon_bytes` for `n = 384`

This is mechanical but touches code that's been stable for
months. Do not conflate this change with other M4 work — land
it as its own commit with its own review.

### 4.15 EIP-712 `domainSeparator` caching is a simple optimization

For CowSwap there's ~5 chains × 1 contract = ~5 domain
separators, each 32 bytes. Hardcode them as a static table in
`secure/src/tx/eip712.rs`:

```rust
pub struct DomainEntry {
    chain_id: u64,
    verifying_contract: [u8; 20],
    domain_separator: [u8; 32],
}

pub static COWSWAP_DOMAINS: &[DomainEntry] = &[
    DomainEntry { chain_id: 1, ..., domain_separator: hex!("...") },
    DomainEntry { chain_id: 100, ..., domain_separator: hex!("...") },
    // ...
];
```

Compute each domain separator once off-chain with a throwaway
script, copy the hex into the static table. Recomputing on
every sign call (3 keccak invocations × a 416-byte hash) is
about 0.1 ms so honestly caching is optional — but the static
table also serves as documentation of "these are the deployments
the wallet knows about".

### 4.16 The Keccak chain_id check is NOT redundant with the bundle's chain_id

The VK bundle carries a `chain_id` field that the secure world
cross-checks against the parsed tx (in the current
`cmd_clear_sign` flow). For M4, there is no parsed tx, so the
cross-check becomes: `bundle.chain_id` must match the `chain_id`
embedded in the `domainSeparator` lookup. Make this explicit —
a bundle for CowSwap Mainnet must not be confusable with a
bundle for CowSwap Gnosis.

### 4.17 Secure-world stack is not infinite

`secure/src/main.rs` sets the secure stack to the first 128 KB
of SSRAM-1. The M4 payload adds ~220 bytes of secure-stack use
(the 384-byte canonical copy). Should be fine but worth
measuring. Don't add new large static buffers without checking
the linker map.

## 5. Open questions to resolve before starting M4

Roughly in priority order:

1. **Token registry strategy** (§3.9). Pick one. Default: Option 2
   — expand the in-circuit registry to ~30 tokens.
2. **Canonical encoding**: 384-byte ABI-style encoding vs a
   custom packed encoding. Default: ABI-style, because it's
   what `keccak256(abi.encode(...))` wants anyway. Trade-off:
   slightly more circuit constraints due to the 12-byte
   zero-pads on addresses, but far less cognitive overhead.
3. **`domainSeparator` lookup**: hardcoded static table
   (§4.15) vs on-the-fly recomputation. Default: static table
   for documentation value.
4. **Readable string format**: multi-line layout for the 4×16
   trusted UI grid. Draft and dry-run the rendering before
   writing the circuit — it constrains what you need to format.
   Suggested:
   ```
   Line 1: "CowSwap SELL OP"     ← or "BUY" depending on kind
   Line 2: "100.00 USDC"         ← sell amount + sell symbol
   Line 3: "for >= 0.05 WETH"    ← buy amount + buy symbol
   Line 4: "exp 0x68abcdef"      ← validTo
   ```
   Total 64 chars, fits STRING_LEN=64.
5. **How does the NS side get the canonical order bytes?**
   Some dApp sends the structured order to the wallet; the NS
   world serializes it via `abi.encode` equivalent. Do we trust
   NS to serialize correctly? Yes — if NS lies, the Groth16
   proof won't verify, because the proof is computed against
   the CORRECT serialization. No extra defense needed.
6. **SLH-DSA vs ECDSA**: CowSwap on-chain verifies ECDSA
   signatures recovered from the digest. This wallet only has
   SLH-DSA. That means any "signature" this wallet produces
   for an EIP-712 order is a 17 KB SPHINCS+ blob, NOT an
   ECDSA signature that CowSwap can actually verify on-chain.
   **This is a fundamental product question that M4 does not
   answer.** The wallet either needs to:
   - (a) Run an ECDSA signer alongside the SLH-DSA one (defeats
     the PQ goal)
   - (b) Produce a SPHINCS+ signature and defer the ECDSA
     production to a companion app (breaks the "hardware
     wallet signs the real thing" property)
   - (c) Wait for PQ-friendly settlement (e.g., a CowSwap
     variant that accepts SLH-DSA or STARK-verifier signatures)
   This question blocks M4 from being a PRODUCT feature, not
   just a TECHNICAL feature. Resolve it before investing
   circuit-authoring time. If the answer is "M4 is for
   learning and testing, not production", say so in the
   commit message.
7. **Should the e2e test verify the displayed string
   character-by-character?** Currently `make e2e` just asserts
   `PASS` lines and the dispatch log. For M4 it would be
   valuable to also grep for an expected rendered line like
   `|CowSwap SELL 100|` in the QEMU output, so regressions in
   the circuit's formatter get caught. The existing
   `ui-semihosting` feature already dumps the UI pages to
   stdout, so this is just a new grep line in the Makefile.

## 6. Quick-start checklist for M4 (when you actually start)

Do these in order. Each step has its own small verification.

- [ ] Read this document top-to-bottom
- [ ] Read `circuits/cowswap/set_pre_signature/circuit.circom`
      (the M3 circuit) — this is the model
- [ ] Read `circuits/scripts/gen_cowswap_e2e_vector.js` — this
      is the test vector pattern
- [ ] Read `secure/src/nsc.rs::cmd_clear_sign` — this is the
      firmware handler to fork
- [ ] Run `make e2e` on current master — confirm all 5
      scenarios pass
- [ ] Resolve §5 question 6 (SLH-DSA vs ECDSA) before writing
      any circuit code. This is the go/no-go gate
- [ ] Decide token registry strategy (§5 question 1)
- [ ] Lift `PoseidonBytes` / `PackBytes31` into
      `circuits/lib/poseidon_bytes.circom` (§4.8 refactor).
      Update both `circuits/aave_v3/clear_signing_proof.circom`
      and `circuits/cowswap/set_pre_signature/circuit.circom` to
      include from the lib. Confirm both VKs still rebuild
      byte-identical via the committed zkeys. This is a
      risk-free prep commit
- [ ] Add `poseidon13` to `secure/src/zk/poseidon_constants.rs`
      and `poseidon.rs::poseidon_bytes` via an extended
      `tools/export_zk_constants.js` — separate commit
- [ ] Add `CMD_CLEAR_SIGN_MSG` constant to `shared/src/lib.rs`
      + `EIP712_*` constants
- [ ] Add `sha3` to `secure/Cargo.toml`
- [ ] Write `secure/src/tx/eip712.rs` — just the digest
      computation, no handler wiring yet. Unit test it in
      `zk-test` against known vectors (there are published
      CowSwap EIP-712 test vectors in the cowprotocol repo)
- [ ] Author `circuits/cowswap/eip712_order/circuit.circom`
      with Aave-style amount formatting + expanded token
      registry
- [ ] Compile, check constraint count, iterate on UX string
      format until it fits 64 bytes
- [ ] `tools/build_vks.sh cowswap_eip712_order` — first full
      pipeline run
- [ ] Copy the resulting zkey into the circuit dir and commit
- [ ] Add protocol row to `secure/data/vks.json`, run dbgen,
      verify round-trip
- [ ] Extend `nsc.rs` with `cmd_clear_sign_msg` handler
- [ ] Extend `nsc_api.rs` with `clear_sign_msg` forwarder
- [ ] Write `circuits/scripts/gen_cowswap_eip712_e2e_vector.js`
      based on the M3 generator
- [ ] Add scenario 6 to `nonsecure/src/e2e_test.rs`
- [ ] Add assertions to the `Makefile` `e2e` target
- [ ] `make e2e` — confirm all 6 scenarios pass
- [ ] Update `docs/architecture.md` with the second payload
      shape (and delete this handoff file, or mark it
      historical)

## 7. Non-goals for M4

Things that might look like they belong in M4 but don't:

- **Extending Aave V3 from 4 → 13 actions.** That's M2b, a
  separate deferred milestone. It affects
  `circuits/aave_v3/clear_signing_proof.circom`, which is
  independent of anything M4 touches.
- **Adding an on-chain `clearSigningVKHash` check.** Explicitly
  out of scope. The trust model is offline-only.
- **STARK verifier migration.** M4 stays on Groth16 BLS12-381.
- **Extending the ERC20 DB format.** Unrelated.
- **Adding protocols other than CowSwap.** One protocol at a
  time.
- **Making snarkjs deterministic.** Upstream problem; we work
  around it with committed zkeys.

---

**End of handoff. If you read this far, you know everything M0-M5
left on the table for M4 except the SLH-DSA-vs-ECDSA product
question, which you need to resolve with the user before writing
any code.**
