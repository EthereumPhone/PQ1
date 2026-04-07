//
// ─────────────────────────────────────────────────────────────────────
// Imported from: github.com/ZKNoxHQ/ZKlarity at commit 5e8b3f9
// Original path: circuits/token_registry.circom
// Imported on:   2026-04-07
// License:       UNRESOLVED — see circuits/UPSTREAM.md
// Local edits:   none — sources below are byte-identical to upstream.
// ─────────────────────────────────────────────────────────────────────
//
pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/comparators.circom";

/*
 * TOKEN_REGISTRY.circom
 *
 * Un "registre" de tokens connus codé en dur dans le circuit.
 * Associe une adresse à :
 *   - son symbole (string ASCII, longueur fixe padded)
 *   - ses decimals
 *
 * Le circuit vérifie que l'adresse fournie correspond bien
 * à l'un des tokens connus, et sort son symbole + decimals.
 *
 * DESIGN :
 *   On a N_TOKENS tokens. Le prover fournit un index token_idx.
 *   Le circuit vérifie addr == ADDR[token_idx] et sort SYMBOL[token_idx].
 *
 * Tokens Aave v3 Ethereum mainnet (pool = 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2) :
 *   0  USDC  0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48  6
 *   1  USDT  0xdAC17F958D2ee523a2206206994597C13D831ec7  6
 *   2  DAI   0x6B175474E89094C44Da98b954EedeAC495271d0F  18
 *   3  WETH  0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2  18
 *   4  WBTC  0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599  8
 *   5  wstETH 0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0 18
 *   6  LINK  0x514910771AF9Ca656af840dff83E8264EcF986CA  18
 *   7  AAVE  0x7Fc66500c84A76Ad7e9c93437bFc5Ac33E2DDaE9  18
 *
 * SYMBOL_LEN = 6 (longueur max d'un symbole, padded avec 0x00)
 */

// ─── Constantes (adresses comme field elements 160-bit) ─────────────────────
//
// Les adresses sont des entiers sur 20 bytes.
// Ici on les écrit en décimal pour Circom (qui n'accepte pas 0x... natif
// dans les expressions de template, mais les field elements le sont).
// → On utilisera une syntaxe d'initialisation par bytes dans le main circuit.
//
// Pour l'instant on définit les constantes symboliquement.

/*
 * APPROCHE CHOISIE : Mux sur l'index token
 *
 * Le prover fournit `token_idx` ∈ [0, N_TOKENS-1].
 * Le circuit vérifie que ADDR[token_idx] == addr_input.
 * Il sort SYMBOL[token_idx] et DECIMALS[token_idx].
 *
 * Implémentation : tableau de comparateurs en parallèle + mux.
 */

/* ─────────────────────────────────────────────────────────────────────
 * AddressEq : compare deux adresses (field elements)
 * ───────────────────────────────────────────────────────────────────── */
template AddressEq() {
    signal input  a;
    signal input  b;
    signal output ok;

    component isz = IsZero();
    isz.in <== a - b;
    ok <== isz.out;
}

/* ─────────────────────────────────────────────────────────────────────
 * TokenRegistry(N_TOKENS, SYMBOL_LEN)
 *
 * Registre de tokens hard-codé.
 *
 * Entrées :
 *   addr_input   : adresse du token dans le calldata
 *   token_idx    : index dans la table (fourni par le prover, privé)
 *
 * Sorties :
 *   symbol[SYMBOL_LEN] : bytes ASCII du symbole (padded 0x00)
 *   decimals           : nb de décimales
 *   ok                 : 1 si addr_input correspond au token_idx
 *
 * NOTE : SYMBOL_LEN = 6 (max symbole : "wstETH")
 * ───────────────────────────────────────────────────────────────────── */
template TokenRegistry() {
    var N_TOKENS   = 8;
    var SYMBOL_LEN = 6;

    signal input  addr_input;          // adresse extraite du calldata
    signal input  token_idx;           // index fourni par le prover

    signal output symbol[SYMBOL_LEN];  // ASCII du symbole
    signal output decimals;            // nb de décimales
    signal output scale_factor;        // 10^(18 - decimals) : normalise raw_amount à 18 décimales
    signal output ok;                  // addr_input est bien le token token_idx

    // ── Table des adresses (field elements, 160 bits) ──────────────────
    // Adresses converties en décimal big-endian 20 bytes
    var ADDRS[N_TOKENS] = [
        0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48, // USDC
        0xdAC17F958D2ee523a2206206994597C13D831ec7, // USDT
        0x6B175474E89094C44Da98b954EedeAC495271d0F, // DAI
        0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2, // WETH
        0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599, // WBTC
        0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0, // wstETH
        0x514910771AF9Ca656af840dff83E8264EcF986CA, // LINK
        0x7Fc66500c84A76Ad7e9c93437bFc5Ac33E2DDaE9  // AAVE
    ];

    // ── Table des decimals ─────────────────────────────────────────────
    var DECS[N_TOKENS] = [6, 6, 18, 18, 8, 18, 18, 18];

    // ── Table des scale factors : 10^(18-dec) ─────────────────────────
    // USDC/USDT: 10^12, WBTC: 10^10, autres: 1
    var SCALES[N_TOKENS] = [
        1000000000000,  // USDC  6  dec
        1000000000000,  // USDT  6  dec
        1,              // DAI  18  dec
        1,              // WETH 18  dec
        10000000000,    // WBTC  8  dec
        1,              // wstETH 18 dec
        1,              // LINK 18  dec
        1               // AAVE 18  dec
    ];

    // ── Table des symboles (ASCII, SYMBOL_LEN bytes, padded 0x00) ────
    // 'U'=85 'S'=83 'D'=68 'C'=67 'T'=84 'E'=69 'H'=72 'W'=87
    // 'A'=65 'I'=73 'D'=68 'L'=76 'N'=78 'K'=75 'B'=66
    // 0x00 = padding
    var SYMS[N_TOKENS][SYMBOL_LEN] = [
        [85, 83, 68, 67,  0,  0],  // "USDC\0\0"
        [85, 83, 68, 84,  0,  0],  // "USDT\0\0"
        [68, 65, 73,  0,  0,  0],  // "DAI\0\0\0"
        [87, 69, 84, 72,  0,  0],  // "WETH\0\0"
        [87, 66, 84, 67,  0,  0],  // "WBTC\0\0"
        [119,115,116,69,84,72],    // "wstETH"
        [76, 73, 78, 75,  0,  0],  // "LINK\0\0"
        [65, 65, 86, 69,  0,  0]   // "AAVE\0\0"
    ];

    // ── Vérification que token_idx est dans [0, N_TOKENS-1] ───────────
    component range = LessThan(4);  // N_TOKENS = 8 < 2^4
    range.in[0] <== token_idx;
    range.in[1] <== N_TOKENS;
    signal in_range;
    in_range <== range.out;

    // ── Mux : sélectionne addr/symbol/dec via token_idx ───────────────
    // Approche : one-hot encoding de token_idx
    // sel[i] = 1 si token_idx == i, 0 sinon

    component eqs[N_TOKENS];
    signal sel[N_TOKENS];

    for (var i = 0; i < N_TOKENS; i++) {
        eqs[i] = IsZero();
        eqs[i].in <== token_idx - i;
        sel[i] <== eqs[i].out;
    }

    // ── Vérification adresse ───────────────────────────────────────────
    // addr_expected = sum_i( sel[i] * ADDRS[i] )
    signal addr_acc[N_TOKENS+1];
    addr_acc[0] <== 0;
    for (var i = 0; i < N_TOKENS; i++) {
        addr_acc[i+1] <== addr_acc[i] + sel[i] * ADDRS[i];
    }
    signal addr_expected;
    addr_expected <== addr_acc[N_TOKENS];

    component addr_eq = AddressEq();
    addr_eq.a <== addr_input;
    addr_eq.b <== addr_expected;

    // ── Sortie decimals ────────────────────────────────────────────────
    signal dec_acc[N_TOKENS+1];
    dec_acc[0] <== 0;
    for (var i = 0; i < N_TOKENS; i++) {
        dec_acc[i+1] <== dec_acc[i] + sel[i] * DECS[i];
    }
    decimals <== dec_acc[N_TOKENS];

    // ── Sortie scale_factor ────────────────────────────────────────────
    signal scale_acc[N_TOKENS+1];
    scale_acc[0] <== 0;
    for (var i = 0; i < N_TOKENS; i++) {
        scale_acc[i+1] <== scale_acc[i] + sel[i] * SCALES[i];
    }
    scale_factor <== scale_acc[N_TOKENS];

    // ── Sortie symbol ──────────────────────────────────────────────────
    signal sym_acc[SYMBOL_LEN][N_TOKENS+1];
    for (var b = 0; b < SYMBOL_LEN; b++) {
        sym_acc[b][0] <== 0;
        for (var i = 0; i < N_TOKENS; i++) {
            sym_acc[b][i+1] <== sym_acc[b][i] + sel[i] * SYMS[i][b];
        }
        symbol[b] <== sym_acc[b][N_TOKENS];
    }

    // ok = addr_match AND in_range
    ok <== addr_eq.ok * in_range;
}
