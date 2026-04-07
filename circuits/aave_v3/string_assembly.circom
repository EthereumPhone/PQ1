//
// ─────────────────────────────────────────────────────────────────────
// Imported from: github.com/ZKNoxHQ/ZKlarity at commit 5e8b3f9
// Original path: circuits/string_assembly.circom
// Imported on:   2026-04-07
// License:       UNRESOLVED — see circuits/UPSTREAM.md
// Local edits:   none — sources below are byte-identical to upstream.
// ─────────────────────────────────────────────────────────────────────
//
pragma circom 2.0.0;

include "./formatting.circom";
include "./token_registry.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

/*
 * STRING_ASSEMBLY.circom
 *
 * Assemble la chaîne humainement lisible complète affichée sur le Nano.
 *
 * Format visé :
 *   Supply   → "Supply 1000.50 USDC"
 *   Borrow   → "Borrow 0.5 WETH (variable)"
 *   Repay    → "Repay 500.00 USDT (stable)"
 *   Withdraw → "Withdraw 100.0 DAI"
 *
 * STRING_LEN fixe = 64 bytes (padded 0x00), suffisant pour le Nano.
 * Le Nano s'arrête au premier 0x00 pour l'affichage.
 *
 * ARCHITECTURE :
 *   1. FormatAmount  → digits ASCII du montant avec point décimal
 *   2. TokenRegistry → symbole ASCII du token
 *   3. Concat        → assemblage de la chaîne complète
 *   4. Poseidon      → hash de la chaîne (dans le circuit parent)
 */

// Constantes ASCII utiles
// 'S'=83 'u'=117 'p'=112 'l'=108 'y'=121 ' '=32
// 'B'=66 'o'=111 'r'=114 'w'=119
// 'R'=82 'e'=101 'p'=112 'a'=97 'y'=121
// 'W'=87 'i'=105 't'=116 'h'=104 'd'=100 'r'=114 'a'=97 'w'=119

/* ─────────────────────────────────────────────────────────────────────
 * ConcatFixed(A, B) : concatène deux tableaux de longueurs fixes
 * ───────────────────────────────────────────────────────────────────── */
template ConcatFixed(A, B) {
    signal input  a[A];
    signal input  b[B];
    signal output out[A+B];

    for (var i = 0; i < A; i++)    out[i]   <== a[i];
    for (var i = 0; i < B; i++)    out[A+i] <== b[i];
}

/* ─────────────────────────────────────────────────────────────────────
 * RateModeString : produit " (variable)" ou " (stable)"
 *   mode == 2 → variable (11 chars : " (variable)")
 *   mode == 1 → stable   (9 chars  : " (stable)")
 *
 * Sortie : 11 bytes fixes (padded 0x00 si stable)
 *
 *   " (variable)" = [32,40,118,97,114,105,97,98,108,101,41]
 *   " (stable)\0\0" = [32,40,115,116,97,98,108,101,41, 0, 0]
 * ───────────────────────────────────────────────────────────────────── */
template RateModeString() {
    signal input  rate_mode;       // 1 = stable, 2 = variable
    signal output ascii[11];
    signal output ok;              // 1 si rate_mode ∈ {1, 2}

    // sel_var = 1 si rate_mode == 2
    component is2 = IsZero();
    is2.in <== rate_mode - 2;
    signal sel_var;
    sel_var <== is2.out;

    // sel_sta = 1 si rate_mode == 1
    component is1 = IsZero();
    is1.in <== rate_mode - 1;
    signal sel_sta;
    sel_sta <== is1.out;

    ok <== sel_var + sel_sta;  // ok si l'un des deux

    // " (variable)" bytes
    var VAR[11] = [32, 40, 118, 97, 114, 105, 97,  98, 108, 101, 41];
    // " (stable)\0\0" bytes
    var STA[11] = [32, 40, 115, 116, 97,  98,  108, 101,  41,   0,  0];

    for (var i = 0; i < 11; i++) {
        ascii[i] <== sel_var * VAR[i] + sel_sta * STA[i];
    }
}

/* ─────────────────────────────────────────────────────────────────────
 * FormatSupplyString(MAX_INT_DIGITS)
 *
 * Produit : "Supply <amount> <SYMBOL>"
 *
 * Layout (STRING_LEN = 64) :
 *   "Supply "  : 7 bytes
 *   amount     : MAX_INT_DIGITS + 1 + DECIMALS bytes (avec point)
 *   " "        : 1 byte
 *   symbol     : SYMBOL_LEN bytes (6)
 *   padding    : 0x00 jusqu'à 64
 *
 * MAX_INT_DIGITS : max digits partie entière. 12 couvre 999999.xxxxxx
 *                 pour USDC/USDT. Pour WETH, les amounts < 1000 ETH
 *                 en pratique, donc 4-5 digits entiers suffisent.
 *                 On prend MAX_INT_DIGITS = 10 par sécurité.
 * ───────────────────────────────────────────────────────────────────── */
template FormatSupplyString(MAX_INT_DIGITS, MAX_DECIMALS) {
    // Longueur ASCII du montant : MAX_INT_DIGITS + 1(point) + MAX_DECIMALS
    var AMOUNT_ASCII = MAX_INT_DIGITS + 1 + MAX_DECIMALS;
    var SYMBOL_LEN   = 6;
    var STRING_LEN   = 64;
    // "Supply " = 7 bytes
    var PREFIX_LEN   = 7;
    // " " = 1 byte entre amount et symbol
    var TOTAL_USED   = PREFIX_LEN + AMOUNT_ASCII + 1 + SYMBOL_LEN;

    signal input  raw_amount;
    signal input  int_digits[MAX_INT_DIGITS];
    signal input  frac_digits[MAX_DECIMALS];
    signal input  n_leading_zeros;
    signal input  addr_input;
    signal input  token_idx;

    signal output str[STRING_LEN];   // la chaîne finale padded
    signal output ok;

    // ── Préfixe "Supply " ─────────────────────────────────────────────
    var PREFIX[7] = [83, 117, 112, 112, 108, 121, 32];
    // S=83 u=117 p=112 p=112 l=108 y=121 SPACE=32

    // ── TokenRegistry ─────────────────────────────────────────────────
    component reg = TokenRegistry();
    reg.addr_input <== addr_input;
    reg.token_idx  <== token_idx;

    // ── FormatAmount ──────────────────────────────────────────────────
    component fmt = FormatAmount(MAX_INT_DIGITS, MAX_DECIMALS);
    fmt.raw_amount      <== raw_amount;
    for (var i = 0; i < MAX_INT_DIGITS; i++) fmt.int_digits[i]  <== int_digits[i];
    for (var i = 0; i < MAX_DECIMALS; i++)   fmt.frac_digits[i] <== frac_digits[i];
    fmt.n_leading_zeros <== n_leading_zeros;
    fmt.scale_factor    <== reg.scale_factor;

    // ── Assemblage dans str[] ──────────────────────────────────────────
    // Préfixe
    for (var i = 0; i < PREFIX_LEN; i++) {
        str[i] <== PREFIX[i];
    }

    // Amount ASCII
    for (var i = 0; i < AMOUNT_ASCII; i++) {
        str[PREFIX_LEN + i] <== fmt.ascii[i];
    }

    // Espace
    str[PREFIX_LEN + AMOUNT_ASCII] <== 32;

    // Symbole
    for (var i = 0; i < SYMBOL_LEN; i++) {
        str[PREFIX_LEN + AMOUNT_ASCII + 1 + i] <== reg.symbol[i];
    }

    // Padding 0x00
    for (var i = TOTAL_USED; i < STRING_LEN; i++) {
        str[i] <== 0;
    }

    ok <== fmt.ok * reg.ok;
}

/* ─────────────────────────────────────────────────────────────────────
 * FormatBorrowString(MAX_INT_DIGITS, MAX_DECIMALS)
 *
 * Produit : "Borrow <amount> <SYMBOL> (variable|stable)"
 * ───────────────────────────────────────────────────────────────────── */
template FormatBorrowString(MAX_INT_DIGITS, MAX_DECIMALS) {
    var AMOUNT_ASCII = MAX_INT_DIGITS + 1 + MAX_DECIMALS;
    var SYMBOL_LEN   = 6;
    var STRING_LEN   = 64;
    var PREFIX_LEN   = 7;   // "Borrow "
    var MODE_LEN     = 11;  // " (variable)" ou " (stable)\0\0"

    signal input  raw_amount;
    signal input  int_digits[MAX_INT_DIGITS];
    signal input  frac_digits[MAX_DECIMALS];
    signal input  n_leading_zeros;
    signal input  addr_input;
    signal input  token_idx;
    signal input  rate_mode;   // 1 ou 2

    signal output str[STRING_LEN];
    signal output ok;

    // "Borrow "
    var PREFIX[7] = [66, 111, 114, 114, 111, 119, 32];
    // B=66 o=111 r=114 r=114 o=111 w=119 SPACE=32

    component reg = TokenRegistry();
    reg.addr_input <== addr_input;
    reg.token_idx  <== token_idx;

    component fmt = FormatAmount(MAX_INT_DIGITS, MAX_DECIMALS);
    fmt.raw_amount <== raw_amount;
    for (var i = 0; i < MAX_INT_DIGITS; i++) fmt.int_digits[i]  <== int_digits[i];
    for (var i = 0; i < MAX_DECIMALS; i++)   fmt.frac_digits[i] <== frac_digits[i];
    fmt.n_leading_zeros <== n_leading_zeros;
    fmt.scale_factor    <== reg.scale_factor;


    component rms = RateModeString();
    rms.rate_mode <== rate_mode;

    // Assemblage
    for (var i = 0; i < PREFIX_LEN; i++)      str[i] <== PREFIX[i];
    for (var i = 0; i < AMOUNT_ASCII; i++)    str[PREFIX_LEN + i] <== fmt.ascii[i];
    str[PREFIX_LEN + AMOUNT_ASCII] <== 32;
    for (var i = 0; i < SYMBOL_LEN; i++)      str[PREFIX_LEN + AMOUNT_ASCII + 1 + i] <== reg.symbol[i];
    for (var i = 0; i < MODE_LEN; i++)        str[PREFIX_LEN + AMOUNT_ASCII + 1 + SYMBOL_LEN + i] <== rms.ascii[i];

    var TOTAL_USED = PREFIX_LEN + AMOUNT_ASCII + 1 + SYMBOL_LEN + MODE_LEN;
    for (var i = TOTAL_USED; i < STRING_LEN; i++) str[i] <== 0;

    signal t0; t0 <== fmt.ok * reg.ok;
    ok <== t0 * rms.ok;
}


/* ─────────────────────────────────────────────────────────────────────
 * FormatRepayString(MAX_INT_DIGITS, MAX_DECIMALS)
 *
 * Produit : "Repay <amount> <SYMBOL> (variable|stable)"
 * ───────────────────────────────────────────────────────────────────── */
template FormatRepayString(MAX_INT_DIGITS, MAX_DECIMALS) {
    var AMOUNT_ASCII = MAX_INT_DIGITS + 1 + MAX_DECIMALS;
    var SYMBOL_LEN   = 6;
    var STRING_LEN   = 64;
    var PREFIX_LEN   = 6;   // "Repay "
    var MODE_LEN     = 11;  // " (variable)" ou " (stable)\0\0"

    signal input  raw_amount;
    signal input  int_digits[MAX_INT_DIGITS];
    signal input  frac_digits[MAX_DECIMALS];
    signal input  n_leading_zeros;
    signal input  addr_input;
    signal input  token_idx;
    signal input  rate_mode;   // 1 ou 2

    signal output str[STRING_LEN];
    signal output ok;

    // "Repay "
    var PREFIX[6] = [82, 101, 112, 97, 121, 32];
    // R=82 e=101 p=112 a=97 y=121 SPACE=32

    component reg = TokenRegistry();
    reg.addr_input <== addr_input;
    reg.token_idx  <== token_idx;

    component fmt = FormatAmount(MAX_INT_DIGITS, MAX_DECIMALS);
    fmt.raw_amount      <== raw_amount;
    for (var i = 0; i < MAX_INT_DIGITS; i++) fmt.int_digits[i]  <== int_digits[i];
    for (var i = 0; i < MAX_DECIMALS; i++)   fmt.frac_digits[i] <== frac_digits[i];
    fmt.n_leading_zeros <== n_leading_zeros;
    fmt.scale_factor    <== reg.scale_factor;

    component rms = RateModeString();
    rms.rate_mode <== rate_mode;

    // Assemblage
    for (var i = 0; i < PREFIX_LEN; i++)      str[i] <== PREFIX[i];
    for (var i = 0; i < AMOUNT_ASCII; i++)    str[PREFIX_LEN + i] <== fmt.ascii[i];
    str[PREFIX_LEN + AMOUNT_ASCII] <== 32;
    for (var i = 0; i < SYMBOL_LEN; i++)      str[PREFIX_LEN + AMOUNT_ASCII + 1 + i] <== reg.symbol[i];
    for (var i = 0; i < MODE_LEN; i++)        str[PREFIX_LEN + AMOUNT_ASCII + 1 + SYMBOL_LEN + i] <== rms.ascii[i];

    var TOTAL_USED = PREFIX_LEN + AMOUNT_ASCII + 1 + SYMBOL_LEN + MODE_LEN;
    for (var i = TOTAL_USED; i < STRING_LEN; i++) str[i] <== 0;

    signal t0; t0 <== fmt.ok * reg.ok;
    ok <== t0 * rms.ok;
}
/* ─────────────────────────────────────────────────────────────────────
 * FormatWithdrawString(MAX_INT_DIGITS, MAX_DECIMALS)
 *
 * Produit : "Withdraw <amount> <SYMBOL>"
 * ───────────────────────────────────────────────────────────────────── */
template FormatWithdrawString(MAX_INT_DIGITS, MAX_DECIMALS) {
    var AMOUNT_ASCII = MAX_INT_DIGITS + 1 + MAX_DECIMALS;
    var SYMBOL_LEN   = 6;
    var STRING_LEN   = 64;
    var PREFIX_LEN   = 9;   // "Withdraw "

    signal input  raw_amount;
    signal input  int_digits[MAX_INT_DIGITS];
    signal input  frac_digits[MAX_DECIMALS];
    signal input  n_leading_zeros;
    signal input  addr_input;
    signal input  token_idx;

    signal output str[STRING_LEN];
    signal output ok;

    // "Withdraw "
    var PREFIX[9] = [87, 105, 116, 104, 100, 114, 97, 119, 32];
    // W=87 i=105 t=116 h=104 d=100 r=114 a=97 w=119 SPACE=32

    component reg = TokenRegistry();
    reg.addr_input <== addr_input;
    reg.token_idx  <== token_idx;

    component fmt = FormatAmount(MAX_INT_DIGITS, MAX_DECIMALS);
    fmt.raw_amount <== raw_amount;
    for (var i = 0; i < MAX_INT_DIGITS; i++) fmt.int_digits[i]  <== int_digits[i];
    for (var i = 0; i < MAX_DECIMALS; i++)   fmt.frac_digits[i] <== frac_digits[i];
    fmt.n_leading_zeros <== n_leading_zeros;
    fmt.scale_factor    <== reg.scale_factor;


    for (var i = 0; i < PREFIX_LEN; i++)     str[i] <== PREFIX[i];
    for (var i = 0; i < AMOUNT_ASCII; i++)   str[PREFIX_LEN + i] <== fmt.ascii[i];
    str[PREFIX_LEN + AMOUNT_ASCII] <== 32;
    for (var i = 0; i < SYMBOL_LEN; i++)     str[PREFIX_LEN + AMOUNT_ASCII + 1 + i] <== reg.symbol[i];

    var TOTAL_USED = PREFIX_LEN + AMOUNT_ASCII + 1 + SYMBOL_LEN;
    for (var i = TOTAL_USED; i < STRING_LEN; i++) str[i] <== 0;

    ok <== fmt.ok * reg.ok;
}
