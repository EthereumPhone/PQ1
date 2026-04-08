pragma circom 2.0.0;

//
// ─────────────────────────────────────────────────────────────────────
// circuits/lib/erc20_registry.circom — shared ERC20 token registry
// ─────────────────────────────────────────────────────────────────────
//
// Generic in-circuit ERC20 token registry indexed by `token_idx`. The
// caller provides an address and a witness index; the registry checks
// that the address matches the table entry at `token_idx`, and exports
// the matching `symbol[SYMBOL_LEN]`, `decimals`, and `scale_factor`.
//
// `scale_factor = 10^(MAX_DECIMALS - decimals)` is what `FormatAmount`
// multiplies the raw uint256 amount by, so the formatter can keep
// MAX_DECIMALS as a compile-time constant across every token in the
// table (a token with fewer on-chain decimals than MAX_DECIMALS just
// gets pre-scaled).
//
// The registry is intentionally **fixed at compile time**: every
// circuit using `Erc20Registry` will have the same table baked in. To
// add a new token to clear-signing, edit this file and re-build every
// circuit that includes it. The companion firmware does NOT need to
// know the table — the proof's binding to (sellToken, buyToken) plus
// the canonical's address bytes is sufficient on its own.
//
// Why a hard-coded list of 8: a Merkle-verified ERC20 lookup (the way
// firmware does it for `cmd_sign`) would require Poseidon
// hash-in-circuit, which would explode the constraint count. The
// fixed table is small enough to be muxed cheaply (~80 constraints
// per registry) and big enough to cover the dominant CowSwap pairs.
// Tokens NOT in the registry can still be signed via `cmd_sign` (the
// blind/known/unknown ERC20 paths), they just don't get the
// EIP-712 clear-signing UX.
//
// Symbol layout: SYMBOL_LEN = 4 ASCII chars, right-padded with 0x20
// (space). 4 chars covers every dominant ERC20 ticker on every chain
// the wallet currently supports (USDC, USDT, WETH, WBTC, DAI, LINK,
// AAVE, UNI, COMP, ...). Longer-symbol tokens like wstETH are
// out-of-scope for v1; either truncate, or pull them in once the
// readable layout supports a wider line.
//
// MAX_DECIMALS = 18 (every supported token's `decimals()` field is
// in [6, 18]) — keeps `scale_factor` as a small power of ten for
// every entry.

include "../node_modules/circomlib/circuits/comparators.circom";

// AddressEq — equality check between two field-element-encoded
// 20-byte addresses.
template AddressEq() {
    signal input  a;
    signal input  b;
    signal output ok;

    component isz = IsZero();
    isz.in <== a - b;
    ok <== isz.out;
}

// Erc20Registry — fixed-table token lookup. Inputs:
//
//   addr_input : the 20-byte address as a single field element
//                (caller is responsible for the BE byte → field
//                conversion; see `BytesToAddressField` below)
//   token_idx  : the prover-supplied index into the table; the
//                circuit constrains addr_input == ADDRS[token_idx]
//
// Outputs:
//
//   symbol[4]    : ASCII symbol bytes, right-padded with 0x20
//   decimals     : 6 / 8 / 18 depending on the token
//   scale_factor : 10^(18 - decimals) — for use with FormatAmount
//   ok           : 1 iff `addr_input` matches the registry entry at
//                  `token_idx` AND `token_idx` is in range
//
// The caller should constrain `ok === 1` to fail the proof if any
// of those checks fail.
template Erc20Registry() {
    var N_TOKENS   = 8;
    var SYMBOL_LEN = 4;

    signal input  addr_input;
    signal input  token_idx;

    signal output symbol[SYMBOL_LEN];
    signal output decimals;
    signal output scale_factor;
    signal output ok;

    // ── Address table (Ethereum mainnet checksums; lowercase OK) ─────
    //
    //  0  USDC  0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48   6 dec
    //  1  USDT  0xdAC17F958D2ee523a2206206994597C13D831ec7   6 dec
    //  2  DAI   0x6B175474E89094C44Da98b954EedeAC495271d0F  18 dec
    //  3  WETH  0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2  18 dec
    //  4  WBTC  0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599   8 dec
    //  5  LINK  0x514910771AF9Ca656af840dff83E8264EcF986CA  18 dec
    //  6  AAVE  0x7Fc66500c84A76Ad7e9c93437bFc5Ac33E2DDaE9  18 dec
    //  7  UNI   0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984  18 dec
    var ADDRS[N_TOKENS] = [
        0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48, // USDC
        0xdAC17F958D2ee523a2206206994597C13D831ec7, // USDT
        0x6B175474E89094C44Da98b954EedeAC495271d0F, // DAI
        0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2, // WETH
        0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599, // WBTC
        0x514910771AF9Ca656af840dff83E8264EcF986CA, // LINK
        0x7Fc66500c84A76Ad7e9c93437bFc5Ac33E2DDaE9, // AAVE
        0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984  // UNI
    ];
    var DECS[N_TOKENS] = [6, 6, 18, 18, 8, 18, 18, 18];
    // scale_factor = 10^(18 - decimals)
    var SCALES[N_TOKENS] = [
        1000000000000,  // USDC  6 dec → 10^12
        1000000000000,  // USDT  6 dec → 10^12
        1,              // DAI  18 dec
        1,              // WETH 18 dec
        10000000000,    // WBTC  8 dec → 10^10
        1,              // LINK 18 dec
        1,              // AAVE 18 dec
        1               // UNI  18 dec
    ];
    // Symbol bytes, right-padded with 0x20 (space) to SYMBOL_LEN.
    // ASCII: 'U'=85 'S'=83 'D'=68 'C'=67 'T'=84 'A'=65 'I'=73
    //        'W'=87 'E'=69 'H'=72 'B'=66 'L'=76 'N'=78 'K'=75
    //        'V'=86 ' '=32
    var SYMS[N_TOKENS][SYMBOL_LEN] = [
        [85, 83, 68, 67],  // "USDC"
        [85, 83, 68, 84],  // "USDT"
        [68, 65, 73, 32],  // "DAI "
        [87, 69, 84, 72],  // "WETH"
        [87, 66, 84, 67],  // "WBTC"
        [76, 73, 78, 75],  // "LINK"
        [65, 65, 86, 69],  // "AAVE"
        [85, 78, 73, 32]   // "UNI "
    ];

    // ── Range check ─────────────────────────────────────────────────
    component range = LessThan(4);   // N_TOKENS = 8 < 2^4
    range.in[0] <== token_idx;
    range.in[1] <== N_TOKENS;
    signal in_range;
    in_range <== range.out;

    // ── One-hot selector on token_idx ───────────────────────────────
    component eqs[N_TOKENS];
    signal sel[N_TOKENS];
    for (var i = 0; i < N_TOKENS; i++) {
        eqs[i] = IsZero();
        eqs[i].in <== token_idx - i;
        sel[i] <== eqs[i].out;
    }

    // ── Mux: expected address ───────────────────────────────────────
    signal addr_acc[N_TOKENS+1];
    addr_acc[0] <== 0;
    for (var i = 0; i < N_TOKENS; i++) {
        addr_acc[i+1] <== addr_acc[i] + sel[i] * ADDRS[i];
    }
    component addr_eq = AddressEq();
    addr_eq.a <== addr_input;
    addr_eq.b <== addr_acc[N_TOKENS];

    // ── Mux: decimals ───────────────────────────────────────────────
    signal dec_acc[N_TOKENS+1];
    dec_acc[0] <== 0;
    for (var i = 0; i < N_TOKENS; i++) {
        dec_acc[i+1] <== dec_acc[i] + sel[i] * DECS[i];
    }
    decimals <== dec_acc[N_TOKENS];

    // ── Mux: scale_factor ───────────────────────────────────────────
    signal scale_acc[N_TOKENS+1];
    scale_acc[0] <== 0;
    for (var i = 0; i < N_TOKENS; i++) {
        scale_acc[i+1] <== scale_acc[i] + sel[i] * SCALES[i];
    }
    scale_factor <== scale_acc[N_TOKENS];

    // ── Mux: symbol ─────────────────────────────────────────────────
    signal sym_acc[SYMBOL_LEN][N_TOKENS+1];
    for (var b = 0; b < SYMBOL_LEN; b++) {
        sym_acc[b][0] <== 0;
        for (var i = 0; i < N_TOKENS; i++) {
            sym_acc[b][i+1] <== sym_acc[b][i] + sel[i] * SYMS[i][b];
        }
        symbol[b] <== sym_acc[b][N_TOKENS];
    }

    ok <== addr_eq.ok * in_range;
}

// BytesToAddressField(20) — pack a 20-byte big-endian address into a
// single field element. Used to feed a calldata-style address slice
// into `Erc20Registry`.
template BytesToAddressField() {
    signal input  bytes[20];
    signal output addr;

    signal acc[21];
    acc[0] <== 0;
    for (var i = 0; i < 20; i++) {
        acc[i+1] <== acc[i] * 256 + bytes[i];
    }
    addr <== acc[20];
}
