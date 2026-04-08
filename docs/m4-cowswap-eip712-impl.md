# M4 implementation notes — CowSwap EIP-712 GPv2Order clear-signing

> Companion to [`docs/m4-cowswap-eip712.md`](./m4-cowswap-eip712.md), the
> original design handoff. This file describes the **as-built** M4 path
> and the things the design sketch turned out to be wrong about.

## TL;DR — what shipped

- New gateway command `CMD_CLEAR_SIGN_MSG = 6` whose payload is a
  single 612-byte fixed header `(proof || canonical || readable)` plus
  a trailing VK bundle. **No EIP-1559 envelope.** The signed bytes are
  an EIP-712 typed-data digest the firmware computes natively.
- A new in-tree Circom circuit
  `circuits/cowswap/eip712_order/circuit.circom` (~2.4k R1CS
  constraints, well under `pot14 = 16384`).
- A new firmware module `secure/src/tx/eip712.rs` that turns the
  164-byte canonical buffer into the EIP-712 keccak digest the SLH-DSA
  signer consumes.
- A new VK DB protocol `cowswap-eip712-order-v1` keyed on a sentinel
  address (`...ab42`, distinct from the real GPv2Settlement `...ab41`)
  so the existing `(chain_id, contract)` lookup key stays unique
  without bumping `VK_DB_VERSION`.
- An e2e scenario (`cowswap_eip712_order`) wired into `make e2e`. The
  trusted UI now prints "CowSwap SELL" + "exp 0xXXXXXXXX" pages
  attested by the proof.

`make e2e` runs **6 / 6** scenarios green on first run after wiring.

## How the as-built differs from the original handoff

The handoff in `m4-cowswap-eip712.md` was deliberately conservative
about scope and recommended several things that turned out to be
unnecessary or counterproductive once we actually started writing
code. The diffs are:

### 1. Canonical encoding is 164 bytes, not 384

The handoff (§3.6) recommends a 384-byte ABI-encoded canonical buffer,
because that "matches what `keccak256(abi.encode(...))` would hash
anyway". That choice forces the firmware to grow Poseidon support from
the existing `poseidon6` (6 blocks × 31 = 186 bytes) up to `poseidon13`
(13 blocks), which means:

- extending `tools/export_zk_constants.js` to extract `poseidon13.ts`
  from the npm package
- regenerating `secure/src/zk/poseidon_constants.rs` (the file already
  has ~840 lines for `poseidon3` + `poseidon6` alone)
- adding a `poseidon13` arm to `secure/src/zk/poseidon.rs::poseidon_bytes`
- bumping the `MAX_T` constant from 8 to 14 across the Poseidon
  permutation, which touches stable, security-sensitive crypto

What we did instead: **define a custom 164-byte packed encoding** sized
to fit the exact same Poseidon slot as the existing M3
`cowswap_set_pre_signature` circuit. This reuses `poseidon_bytes(_,
164)` (which the firmware already has) and the existing
`verify_clear_signing_proof` shape (length-fixed `[u8; MAX_CALLDATA]`
input), zero firmware crypto changes. The trade-off is that the
canonical buffer isn't `abi.encode(...)`, so the secure world must
re-expand it into the 416-byte ABI struct before keccak'ing — but
that's ~30 lines of straight-line memcpy in `eip712.rs::struct_hash`.

The 164 bytes are spent as:

```
[  0..  20)  sellToken          (20 B address)
[ 20..  40)  buyToken           (20 B address)
[ 40..  60)  receiver           (20 B address)
[ 60..  92)  sellAmount         (uint256 BE)
[ 92.. 124)  buyAmount          (uint256 BE)
[124.. 156)  feeAmount          (uint256 BE)
[156.. 160)  validTo            (uint32 BE)
[160]        kind               (0 = sell, 1 = buy)
[161]        partiallyFillable  (0 / 1)
[162]        sellTokenBalance   (0 = erc20, 1 = external, 2 = internal)
[163]        buyTokenBalance    (0 = erc20, 1 = internal)
```

`appData` is the only GPv2Order field that does NOT fit. v1 forces
`appData = bytes32(0)` (the default empty-metadata hash that most
CowSwap orders use anyway). v2 can either grow the canonical buffer
to 217 B + add `poseidon7` to the firmware Poseidon footprint, or
shuttle `appData` over a separate non-Poseidon-bound channel and
cross-check it on the trusted UI.

### 2. Sentinel address instead of a `domain` byte in the DB format

The handoff (§3.4) goes through the question of whether the VK DB
format needs a `domain` (or `flow`, or `protocol_id`) byte to
distinguish "calldata-bound" entries from "EIP-712-bound" entries —
because the `setPreSignature` and EIP-712 protocols both target the
**same** GPv2Settlement contract on the **same** chains, so the
existing `(chain_id, contract)` primary key collides:

```
chain_id=1, contract=0x9008...ab41  →  setPreSignature VK   (M3)
chain_id=1, contract=0x9008...ab41  →  EIP-712 GPv2Order VK (M4)  ← collision
```

`dbgen` rejects duplicate `(chain_id, contract)` keys explicitly. The
handoff concludes that bumping `VK_DB_VERSION` isn't needed if the
firmware can just dispatch on the incoming command, but doesn't
actually solve the lookup-key collision.

What we did: **define a sentinel verifying contract** for the M4
entries that differs from the real one in exactly the last byte:

```rust
// secure/src/tx/eip712.rs
pub const GPV2_SETTLEMENT_ADDRESS: [u8; 20] = [
    0x90, 0x08, 0xd1, 0x9f, 0x58, 0xaa, 0xbd, 0x9e, 0xd0, 0xd6,
    0x09, 0x71, 0x56, 0x5a, 0xa8, 0x51, 0x05, 0x60, 0xab, 0x41,  // real
];
pub const COWSWAP_EIP712_SENTINEL: [u8; 20] = [
    0x90, 0x08, 0xd1, 0x9f, 0x58, 0xaa, 0xbd, 0x9e, 0xd0, 0xd6,
    0x09, 0x71, 0x56, 0x5a, 0xa8, 0x51, 0x05, 0x60, 0xab, 0x42,  // sentinel
];
```

The sentinel never makes it onto Ethereum: it is a pure DB lookup
key. The secure handler:

1. Looks up the VK by `(chain_id, sentinel)` like any other entry.
2. Cross-checks `verified.contract == COWSWAP_EIP712_SENTINEL`
   (rejecting any in-DB VK whose contract bytes happen to match the
   sentinel only by accident — there are none today, but the check
   keeps the invariant explicit).
3. Hardcodes the **real** `GPV2_SETTLEMENT_ADDRESS` as the
   `verifyingContract` field of the EIP-712 domain separator.

This keeps `VK_DB_VERSION = 1`, leaves `shared/src/db_format.rs`
untouched, and means the on-disk binary layout is bit-identical to
M3. `secure/data/vks.json` documents the sentinel via an
`_address_note` field that `serde` silently ignores at load time.

### 3. Readable format is the minimum viable, not Aave-style

The handoff (§3.8) sketches an Aave-style format with token registry
lookups and decimal amount formatting:

```
Sell 100.00 USDC
for buy 0.05 WETH
exp 0x68abcdef
partial=0
```

That requires reusing Aave's `TokenRegistry`, `FormatSupplyString`,
`SlotToField`, and the `int_digits` / `frac_digits` divmod plumbing,
plus extending the registry from 8 to ~30 tokens.

What we did: **shipped the smallest readable that still beats M3's
22-byte static string** — two lines × 16 chars:

```
"CowSwap SELL    "
"exp 0x68000000  "
```

The kind word (`SELL` / `BUY `) is muxed inside the circuit from the
canonical's kind byte; the 8 hex chars are the in-circuit ASCII
upper-hex of the 4 `validTo` bytes via a `ByteToHexAscii` template
that splits each byte into two `Num2Bits(4)`-checked nibbles and runs
a `LessThan(4)(nibble, 10)` mux to pick the `'0'..'9'` vs `'A'..'F'`
ASCII offset.

This proved enough to demonstrate the entire EIP-712 dispatch path
end-to-end without writing a token registry. v2 can either layer the
Aave-style amount/symbol formatting on top (the byte slots are
already in canonical) or use a Merkle-verified token registry that
shares state with `erc20_db` (mentioned as "Option 3" in §3.9 of the
handoff).

### 4. Did NOT lift `PoseidonBytes` into a shared lib

The handoff (§4.8) recommends a refactor commit that lifts
`PoseidonBytes` and `PackBytes31` from
`circuits/aave_v3/clear_signing_proof.circom` into a shared
`circuits/lib/poseidon_bytes.circom`. The reason that file can't be
included directly is its trailing `component main =
ClearSigningProof();`, which makes it un-includeable.

What we did: **followed the M3 pattern of duplicating the templates
with a unique name prefix** (`EipPackBytes31`, `EipPoseidonBytes`).
That added ~30 lines to the new circuit, vs. a multi-file refactor
that would also have rebuilt and re-pinned the existing Aave +
setPreSignature `circuit_final.zkey` files. Risk-free vs. "needs to
revalidate three byte-stable artifacts".

The shared-lib refactor is still a good idea for any future M5 / M6
circuit and is now blocked only on someone caring about the duplication.

### 5. Did NOT add a separate `poseidon13` regeneration step

Direct consequence of (1): we never touched
`tools/export_zk_constants.js`, `secure/src/zk/poseidon.rs`, or
`secure/src/zk/poseidon_constants.rs`.

## What we re-confirmed from the handoff

Several "gotchas" from §4 of the original doc held up exactly as
written and saved real time:

- **§4.1 — `snarkjs zkey contribute` is non-deterministic.** Confirmed
  by inspection of the build pipeline. We skipped trying to make it
  reproducible and committed `circuit_final.zkey` straight into
  `circuits/cowswap/eip712_order/`.
- **§4.5 — circom include paths are relative to the source file.**
  `include "../../node_modules/..."` worked unmodified at the
  `circuits/cowswap/eip712_order/` depth.
- **§4.8 — `component main` blocks include chains.** Lived with it via
  the `Eip*` prefix duplication trick.
- **§4.13 — `sha3` is the right keccak crate.** `sha3 = { version =
  "0.10", default-features = false }` was already in
  `secure/Cargo.toml` for other reasons; no new dependency.
- **§4.15 — domain separator hardcoded vs. computed.** We compute it
  on the fly (5 keccaks per request); the upfront table from §4.15 is
  a future micro-optimization that nobody will need.
- **§3.3 — keccak stays OUT of the circuit.** This was the single most
  important call in the entire handoff and it held. M4 ships without
  any keccak template inside Circom, and the firmware just wraps the
  same canonical bytes the proof bound.

## What we hit that the handoff didn't predict

### Circom 2.x: signal declarations cannot live inside `for` scopes

Trying to declare a per-iteration `signal expected;` inside a `for`
loop fails with `error[T2011]: Signal, bus or component declaration
inside While scope`. The fix is to declare an `signal expected[N]`
array before the loop and assign by index. The handoff should have
mentioned this — it cost ~one debug cycle on the first compile.

### `<--` vs `<==` distinction in mux templates

`<--` is the "non-constraining" assignment (the prover sets the
value, the circuit doesn't enforce a relation). For mux templates
like `kind_expected[i] <== SELL[i] + kind * (BUY[i] - SELL[i])` we
used `<==` (full constraint) so the prover cannot choose a different
expected character.

### `dbgen` silently ignores unknown JSON fields

`VkProtocol` does not set `#[serde(deny_unknown_fields)]`, so the
`_address_note` and `_comment` keys we use for human reviewers are
silently dropped at load time. That's the behavior we wanted, but it
also means typos in real fields go unnoticed. Worth keeping in mind
when adding fields in the future.

### Phase-2 `prepare phase2` on BLS12-381 pot14 takes ~25 minutes

A fresh `pot14_bls12_381_final.ptau` could not be downloaded because
the project's pinned hash refers to a private upstream artifact. We
re-generated one with `snarkjs powersoftau new bls12-381 14 ... &&
contribute && prepare phase2`. The first two steps each took ~30
seconds, but `prepare phase2` ran for ~25 minutes at 290% CPU and
~190 MB RSS before producing the 28 MB output. The output is
write-once and is now cached at `build/ptau/pot14_bls12_381_final.ptau`
(sha256 `b1d5cf5e97e5a3d00d9b2d7118a4f3033d7075bd9053182d21cfc546dd64620b`,
plus the SHA pin in `circuits/ptau.lock` should be updated to match if
anyone needs to re-author another circuit). Existing circuits with
committed `circuit_final.zkey` files don't need the ptau at all
because `tools/build_vks.sh` skips the full pipeline for them.

## File-by-file change list (as built)

**New files:**

- `circuits/cowswap/eip712_order/circuit.circom` — the Circom source
  (~250 lines, 692 nonlinear + 1757 linear constraints).
- `circuits/cowswap/eip712_order/circuit_final.zkey` — committed
  reproducibility pin (~1.6 MB).
- `circuits/cowswap/eip712_order/contribution.seed` — 32-byte audit
  record (the entropy is `m4-cowswap-eip712-order-fixed-entropy`
  truncated to 32 bytes).
- `circuits/scripts/gen_cowswap_eip712_e2e_vector.js` — test-vector
  generator (mirrors the M3 generator pattern).
- `secure/data/vks/cowswap_eip712_order.vk.bin` — 960-byte VK blob
  emitted by `vk_json_to_bin.js`.
- `secure/src/tx/eip712.rs` — native EIP-712 digest computation
  (typehash constants, domain separator, struct hash, decode of the
  164-byte canonical, final `0x1901 ‖ ds ‖ sh` digest).
- `docs/m4-cowswap-eip712-impl.md` — this file.

**Modified files:**

- `shared/src/lib.rs` — added `CMD_CLEAR_SIGN_MSG = 6` and the
  `EIP712_*` constants.
- `secure/src/tx/mod.rs` — `pub mod eip712;`.
- `secure/src/nsc.rs` — added `cmd_clear_sign_msg` handler (~250
  lines, parallel to `cmd_clear_sign`) plus the dispatch arm.
- `secure/src/zk/groth16.rs` — added `verify_with_public_signals`
  helper that takes precomputed `Scalar` public signals (so the M4
  handler can pass `poseidon_bytes(canonical, 164)` and
  `poseidon_bytes(readable, 64)` directly, without going through the
  fixed-size `[u8; MAX_CALLDATA]` shape of the existing
  `verify_clear_signing_proof`).
- `nonsecure/src/nsc_api.rs` — added `clear_sign_msg` forwarder.
- `nonsecure/src/e2e_test.rs` — scenario 6 (`cowswap_eip712_order`)
  with auto-generated proof / canonical / readable / sentinel
  byte arrays between `AUTO-GENERATED EIP712 BEGIN/END` markers.
- `nonsecure/src/vk_db.bin` — regenerated by `dbgen` (now contains
  the M4 protocol).
- `secure/data/vks.json` — added the `cowswap-eip712-order-v1`
  protocol row with sentinel deployments and an `_address_note`.
- `secure/data/vks.review.txt` — regenerated.
- `secure/src/db_roots.rs` — `VK_DB_ROOT` bumped (expected; cascades
  every time the VK set changes).
- `circuits/circuits.json` — added the `cowswap_eip712_order` row.
- `Makefile` — added grep assertions for `cmd_clear_sign_msg dispatch
  = ZkClearSignMsg` and `[E2E] cowswap_eip712_order = PASS`.
- `docs/architecture.md` — updated the ZK Clear Signing intro to
  mention EIP-712, added a payload-shape table, extended the e2e
  scenarios table.
- `docs/m4-cowswap-eip712.md` — marked as historical with a pointer
  to this file at the top.

**Explicitly NOT touched:**

- `shared/src/db_format.rs` — VK DB format stays at v1.
- `dbgen/src/vks.rs` — the builder doesn't care about command type.
- `nonsecure/src/vk_db.rs` — the lookup API is already
  `(chain_id, contract) → bundle`.
- `secure/src/zk/vk_bundle.rs` — bundle wire format unchanged.
- `secure/src/zk/poseidon.rs` / `poseidon_constants.rs` — no new
  Poseidon instance needed.
- `tools/export_zk_constants.js` — same.
- `circuits/aave_v3/*.circom` and
  `circuits/cowswap/set_pre_signature/circuit.circom` — untouched, so
  their committed `circuit_final.zkey` files remain reproducibility
  pins for the existing protocols.

## Trust model (M4 specific)

The same firmware-signing-key → VK_DB_ROOT → Merkle → Groth16 chain
applies, with one extra link: the **EIP-712 digest is recomputed
natively from the same canonical bytes the proof bound**, so the
binding between "what the user saw on the OLED" and "what got signed
with SLH-DSA" is local to a single function call in
`cmd_clear_sign_msg`. The proof attests `Poseidon(canonical) ↔
Poseidon(readable)`; the firmware separately runs
`keccak256(eip712(canonical))` over the **same in-memory buffer** as
the input to `Poseidon`. There is no path where the proof
can be valid for one set of bytes and the signed digest for another,
because there is only one `canonical` array on the secure stack.

The M4 path does not introduce any new on-chain governance lookup,
on-chain VK hash comparison, or external trust anchor. The release
review still happens by diffing `secure/data/vks.review.txt` against
the previous release before signing the firmware image.

## Caveats and known limitations

1. **`appData` is forced to `bytes32(0)`.** Orders that use a
   non-default `appData` hash (e.g. orders that pin a specific
   "appCode" string) cannot be signed by M4 today. The proof will
   verify, the digest will compute, but the digest will not match
   what a CowSwap solver would expect for the user's actual order.
   Fix is "v2 of the canonical buffer" (see §1 above).
2. **Receiver, feeAmount, and the balance enums are bound but not
   displayed.** They are part of the keccak struct hash via the
   canonical buffer, so substituting them would break the proof,
   but the trusted UI does not surface them. A user reading the
   OLED only sees `kind` and `validTo`. Future readable formats can
   decode more.
3. **SLH-DSA signatures, not ECDSA.** The wallet still produces a
   17 KB SPHINCS+ signature over the EIP-712 digest, NOT an ECDSA
   signature CowSwap solvers can verify on-chain today. This is a
   product question (handoff §5 q.6) that M4 does not answer; M4 is
   for technical and integration validation, not for production
   CowSwap settlement. The path to product use is either (a) a
   CowSwap variant that accepts SLH-DSA / STARK-verifier signatures,
   or (b) a companion that re-signs the same digest with an ECDSA
   key after the user confirms on-device.
4. **Token registry / amount formatting deferred.** Today the user
   sees `kind` and `validTo` only. The next obvious win is to layer
   the Aave-style ERC20 amount formatter on top of the existing
   canonical layout — the bytes are all in there.
5. **Proof generation requires a working snarkjs / circom toolchain
   off-device.** No change from M3, but worth noting that the M4
   test-vector generator depends on the committed `circuit_final.zkey`
   plus a one-time `circom` invocation to produce the `.wasm`
   witness generator.

## Quick command reference (for future maintenance)

Re-build the M4 VK from source (requires `circom` + `snarkjs` + a
matching pot14 BLS12-381 ptau):

```sh
# 1. Compile the circuit (once per circuit-source change)
circom circuits/cowswap/eip712_order/circuit.circom \
    --r1cs --wasm --sym --prime bls12381 \
    --output build/circuits/cowswap_eip712_order/ \
    -l circuits/node_modules

# 2. Run the trusted-setup pipeline (only when there's no committed zkey;
#    otherwise tools/build_vks.sh extracts the VK from the committed file)
SNARKJS=circuits/node_modules/.bin/snarkjs
node "$SNARKJS" groth16 setup \
    build/circuits/cowswap_eip712_order/circuit.r1cs \
    build/ptau/pot14_bls12_381_final.ptau \
    build/circuits/cowswap_eip712_order/circuit_0000.zkey
node "$SNARKJS" zkey contribute \
    build/circuits/cowswap_eip712_order/circuit_0000.zkey \
    build/circuits/cowswap_eip712_order/circuit_final.zkey \
    --name="m4-eip712-order" -e="<32 bytes of entropy>"

# 3. Export the VK as a 960-byte binary blob and fold it into the DB
node "$SNARKJS" zkey export verificationkey \
    build/circuits/cowswap_eip712_order/circuit_final.zkey \
    build/circuits/cowswap_eip712_order/verification_key.json
node circuits/scripts/vk_json_to_bin.js \
    --in  build/circuits/cowswap_eip712_order/verification_key.json \
    --out secure/data/vks/cowswap_eip712_order.vk.bin \
    --n-public 2
cargo run -p dbgen
```

Re-generate the e2e test vector (random Groth16 prove → new proof
bytes pasted into `nonsecure/src/e2e_test.rs`):

```sh
node circuits/scripts/gen_cowswap_eip712_e2e_vector.js
# then manually paste the AUTO-GENERATED EIP712 block into
# nonsecure/src/e2e_test.rs between the BEGIN/END markers
```

Run the full e2e suite:

```sh
make e2e
```
