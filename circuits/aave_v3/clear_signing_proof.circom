//
// ─────────────────────────────────────────────────────────────────────
// Imported from: github.com/ZKNoxHQ/ZKlarity at commit 5e8b3f9
// Original path: circuits/clear_signing_proof.circom
// Imported on:   2026-04-07
// License:       UNRESOLVED — see circuits/UPSTREAM.md
// Local edits:   none — sources below are byte-identical to upstream.
// ─────────────────────────────────────────────────────────────────────
//
pragma circom 2.0.0;

include "./abi_primitives.circom";
include "./aave_abi_parsers.circom";
include "./string_assembly.circom";
include "../node_modules/poseidon-bls12381-circom/circuits/poseidon255.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

/*
 * CLEAR_SIGNING_PROOF.circom
 *
 * Circuit racine. Prouve que :
 *
 *   (1) BINDING TX     : Poseidon255(calldata_bytes) == H_tx
 *   (2) PARSING ABI    : calldata est un appel Aave valide → params
 *   (3) FORMATTING     : format(params) == human_string
 *   (4) BINDING STRING : Poseidon255(human_string) == H_str
 *
 * Signaux PUBLICS (vérifiés par le Nano) :
 *   H_tx  : hash de la tx que l'utilisateur va signer
 *   H_str : hash de la string affichée sur l'écran
 *
 * Signaux PRIVÉS (le witness, calculé off-chain) :
 *   calldata_bytes[]  : bytes bruts du calldata
 *   action_type       : 0=supply 1=borrow 2=repay 3=withdraw 4=collateral 5=emode
 *   token_idx         : index dans le registre de tokens
 *   int_digits[]      : chiffres partie entière du montant
 *   frac_digits[]     : chiffres partie fractionnaire
 *   rate_mode         : 1=stable 2=variable (borrow/repay)
 *   human_string[]    : la chaîne ASCII affichée (64 bytes)
 *
 * Paramètres de compilation :
 *   MAX_CALLDATA  : taille max du calldata (164 bytes = borrow, le plus long)
 *   MAX_INT_DIGITS: 10
 *   MAX_DECIMALS  : 18
 *   STRING_LEN    : 64
 *
 * ──────────────────────────────────────────────────────────────────────
 * NOTE SUR POSEIDON :
 *   Poseidon est défini sur BN254 (même courbe que notre Nano).
 *   circomlib fournit Poseidon255(N) qui prend N field elements.
 *   On groupe les bytes par blocs de 31 (< p) pour hacher le calldata.
 *   31 bytes × 8 = 248 bits < 254 bits (BN254 prime) → pas de débordement.
 * ──────────────────────────────────────────────────────────────────────
 */

/* ─────────────────────────────────────────────────────────────────────
 * PackBytes31(N_BLOCKS) : regroupe N_BLOCKS × 31 bytes en N_BLOCKS fields
 *
 * Utilisé pour préparer l'entrée de Poseidon depuis un tableau de bytes.
 * ───────────────────────────────────────────────────────────────────── */
template PackBytes31(N_BLOCKS) {
    var TOTAL_BYTES = N_BLOCKS * 31;

    signal input  bytes[TOTAL_BYTES];
    signal output fields[N_BLOCKS];

    signal acc[N_BLOCKS][32];
    for (var b = 0; b < N_BLOCKS; b++) {
        acc[b][0] <== 0;
        for (var i = 0; i < 31; i++) {
            acc[b][i+1] <== acc[b][i] * 256 + bytes[b * 31 + i];
        }
        fields[b] <== acc[b][31];
    }
}

/* ─────────────────────────────────────────────────────────────────────
 * PoseidonBytes(N_BYTES) : hash Poseidon d'un tableau de bytes
 *
 * On pad à N_BLOCKS * 31 bytes, on pack, on applique Poseidon.
 * N_BLOCKS = ceil(N_BYTES / 31)
 * ───────────────────────────────────────────────────────────────────── */
template PoseidonBytes(N_BYTES) {
    var N_BLOCKS = (N_BYTES + 30) \ 31;   // ceil division
    var PADDED   = N_BLOCKS * 31;

    signal input  bytes[N_BYTES];
    signal output hash;

    // Pad avec 0
    signal padded[PADDED];
    for (var i = 0; i < N_BYTES; i++)  padded[i] <== bytes[i];
    for (var i = N_BYTES; i < PADDED; i++) padded[i] <== 0;

    component pack = PackBytes31(N_BLOCKS);
    for (var i = 0; i < PADDED; i++) pack.bytes[i] <== padded[i];

    component h = Poseidon255(N_BLOCKS);
    for (var i = 0; i < N_BLOCKS; i++) h.in[i] <== pack.fields[i];

    hash <== h.out;
}

/* ─────────────────────────────────────────────────────────────────────
 * ActionMux : sélectionne le bon parser selon action_type
 *
 * On instancie TOUS les parsers en parallèle (taille fixe du circuit),
 * puis on mux les sorties selon action_type.
 *
 * action_type :
 *   0 = supply    (132 bytes)
 *   1 = borrow    (164 bytes)
 *   2 = repay     (132 bytes)
 *   3 = withdraw  (100 bytes)
 *
 * MAX_CALLDATA = 164 bytes (borrow, le plus long)
 * Les parsers plus courts lisent les premiers N bytes.
 * ───────────────────────────────────────────────────────────────────── */
template ActionMux() {
    var MAX_CALLDATA = 164;
    var N_ACTIONS    = 4;

    signal input  calldata[MAX_CALLDATA];
    signal input  action_type;           // 0..3

    // Sorties unifiées
    signal output asset;
    signal output amount;
    signal output rate_mode;
    signal output abi_ok;

    // ── One-hot sur action_type ────────────────────────────────────────
    component eqs[N_ACTIONS];
    signal sel[N_ACTIONS];
    for (var i = 0; i < N_ACTIONS; i++) {
        eqs[i] = IsZero();
        eqs[i].in <== action_type - i;
        sel[i] <== eqs[i].out;
    }

    // ── Parsers (instanciés tous en parallèle) ─────────────────────────

    // Supply (132 bytes)
    component p_supply = ParseSupply();
    for (var i = 0; i < 132; i++) p_supply.calldata[i] <== calldata[i];

    // Borrow (164 bytes)
    component p_borrow = ParseBorrow();
    for (var i = 0; i < 164; i++) p_borrow.calldata[i] <== calldata[i];

    // Repay (132 bytes)
    component p_repay = ParseRepay();
    for (var i = 0; i < 132; i++) p_repay.calldata[i] <== calldata[i];

    // Withdraw (100 bytes)
    component p_withdraw = ParseWithdraw();
    for (var i = 0; i < 100; i++) p_withdraw.calldata[i] <== calldata[i];

    // ── Mux : asset ────────────────────────────────────────────────────
    signal asset_acc[N_ACTIONS+1];
    asset_acc[0] <== 0;
    asset_acc[1] <== asset_acc[0] + sel[0] * p_supply.asset;
    asset_acc[2] <== asset_acc[1] + sel[1] * p_borrow.asset;
    asset_acc[3] <== asset_acc[2] + sel[2] * p_repay.asset;
    asset_acc[4] <== asset_acc[3] + sel[3] * p_withdraw.asset;
    asset <== asset_acc[N_ACTIONS];

    // ── Mux : amount ───────────────────────────────────────────────────
    signal amount_acc[N_ACTIONS+1];
    amount_acc[0] <== 0;
    amount_acc[1] <== amount_acc[0] + sel[0] * p_supply.amount;
    amount_acc[2] <== amount_acc[1] + sel[1] * p_borrow.amount;
    amount_acc[3] <== amount_acc[2] + sel[2] * p_repay.amount;
    amount_acc[4] <== amount_acc[3] + sel[3] * p_withdraw.amount;
    amount <== amount_acc[N_ACTIONS];

    // ── Mux : rate_mode (0 pour supply/withdraw) ───────────────────────
    signal rm_acc[N_ACTIONS+1];
    rm_acc[0] <== 0;
    rm_acc[1] <== rm_acc[0] + sel[0] * 0;
    rm_acc[2] <== rm_acc[1] + sel[1] * p_borrow.interest_rate_mode;
    rm_acc[3] <== rm_acc[2] + sel[2] * p_repay.interest_rate_mode;
    rm_acc[4] <== rm_acc[3] + sel[3] * 0;
    rate_mode <== rm_acc[N_ACTIONS];

    // ── Mux : abi_ok ───────────────────────────────────────────────────
    signal ok_acc[N_ACTIONS+1];
    ok_acc[0] <== 0;
    ok_acc[1] <== ok_acc[0] + sel[0] * p_supply.abi_ok;
    ok_acc[2] <== ok_acc[1] + sel[1] * p_borrow.abi_ok;
    ok_acc[3] <== ok_acc[2] + sel[2] * p_repay.abi_ok;
    ok_acc[4] <== ok_acc[3] + sel[3] * p_withdraw.abi_ok;
    abi_ok <== ok_acc[N_ACTIONS];
}

/* ─────────────────────────────────────────────────────────────────────
 * StringMux : sélectionne le bon formateur selon action_type
 * ───────────────────────────────────────────────────────────────────── */
template StringMux(MAX_INT_DIGITS, MAX_DECIMALS) {
    var STRING_LEN = 64;
    var N_ACTIONS  = 4;

    signal input  action_type;
    signal input  raw_amount;
    signal input  int_digits[MAX_INT_DIGITS];
    signal input  frac_digits[MAX_DECIMALS];
    signal input  n_leading_zeros;
    signal input  addr_input;
    signal input  token_idx;
    signal input  rate_mode;

    signal output str[STRING_LEN];
    signal output ok;

    // One-hot
    component eqs[N_ACTIONS];
    signal sel[N_ACTIONS];
    for (var i = 0; i < N_ACTIONS; i++) {
        eqs[i] = IsZero();
        eqs[i].in <== action_type - i;
        sel[i] <== eqs[i].out;
    }

    // Formatters
    component f_supply = FormatSupplyString(MAX_INT_DIGITS, MAX_DECIMALS);
    f_supply.raw_amount <== raw_amount;
    for (var i = 0; i < MAX_INT_DIGITS; i++) f_supply.int_digits[i]  <== int_digits[i];
    for (var i = 0; i < MAX_DECIMALS; i++)   f_supply.frac_digits[i] <== frac_digits[i];
    f_supply.n_leading_zeros <== n_leading_zeros;
    f_supply.addr_input <== addr_input;
    f_supply.token_idx  <== token_idx;

    component f_borrow = FormatBorrowString(MAX_INT_DIGITS, MAX_DECIMALS);
    f_borrow.raw_amount <== raw_amount;
    for (var i = 0; i < MAX_INT_DIGITS; i++) f_borrow.int_digits[i]  <== int_digits[i];
    for (var i = 0; i < MAX_DECIMALS; i++)   f_borrow.frac_digits[i] <== frac_digits[i];
    f_borrow.n_leading_zeros <== n_leading_zeros;
    f_borrow.addr_input <== addr_input;
    f_borrow.token_idx  <== token_idx;
    f_borrow.rate_mode  <== rate_mode;

    component f_repay = FormatRepayString(MAX_INT_DIGITS, MAX_DECIMALS);
    f_repay.raw_amount <== raw_amount;
    for (var i = 0; i < MAX_INT_DIGITS; i++) f_repay.int_digits[i]  <== int_digits[i];
    for (var i = 0; i < MAX_DECIMALS; i++)   f_repay.frac_digits[i] <== frac_digits[i];
    f_repay.n_leading_zeros <== n_leading_zeros;
    f_repay.addr_input <== addr_input;
    f_repay.token_idx  <== token_idx;
    f_repay.rate_mode  <== rate_mode;

    component f_withdraw = FormatWithdrawString(MAX_INT_DIGITS, MAX_DECIMALS);
    f_withdraw.raw_amount <== raw_amount;
    for (var i = 0; i < MAX_INT_DIGITS; i++) f_withdraw.int_digits[i]  <== int_digits[i];
    for (var i = 0; i < MAX_DECIMALS; i++)   f_withdraw.frac_digits[i] <== frac_digits[i];
    f_withdraw.n_leading_zeros <== n_leading_zeros;
    f_withdraw.addr_input <== addr_input;
    f_withdraw.token_idx  <== token_idx;

    // Mux string byte par byte
    signal s_acc[STRING_LEN][N_ACTIONS+1];
    for (var b = 0; b < STRING_LEN; b++) {
        s_acc[b][0] <== 0;
        s_acc[b][1] <== s_acc[b][0] + sel[0] * f_supply.str[b];
        s_acc[b][2] <== s_acc[b][1] + sel[1] * f_borrow.str[b];
        s_acc[b][3] <== s_acc[b][2] + sel[2] * f_repay.str[b];
        s_acc[b][4] <== s_acc[b][3] + sel[3] * f_withdraw.str[b];
        str[b]      <== s_acc[b][N_ACTIONS];
    }

    // ok
    signal ok_acc[N_ACTIONS+1];
    ok_acc[0] <== 0;
    ok_acc[1] <== ok_acc[0] + sel[0] * f_supply.ok;
    ok_acc[2] <== ok_acc[1] + sel[1] * f_borrow.ok;
    ok_acc[3] <== ok_acc[2] + sel[2] * f_repay.ok;
    ok_acc[4] <== ok_acc[3] + sel[3] * f_withdraw.ok;
    ok <== ok_acc[N_ACTIONS];
}

/* ─────────────────────────────────────────────────────────────────────
 * ClearSigningProof : circuit racine
 *
 * Le Nano reçoit (H_tx, H_str, π) et vérifie π.
 * Il sait que la string affichée hash à H_str.
 * Il fait signer H_tx à l'utilisateur.
 * ───────────────────────────────────────────────────────────────────── */
template ClearSigningProof() {
    var MAX_CALLDATA  = 164;
    var MAX_INT_DIGITS = 10;
    var MAX_DECIMALS   = 18;
    var STRING_LEN     = 64;

    // ══ SIGNAUX PUBLICS ══════════════════════════════════════════════════
    signal input  H_tx;    // Poseidon255(calldata)   — ce que le Nano vérifie
    signal input  H_str;   // Poseidon255(string)     — hash de ce qui est affiché

    // ══ SIGNAUX PRIVÉS (witness) ═════════════════════════════════════════
    signal input  calldata[MAX_CALLDATA];   // bytes bruts, padded 0x00
    signal input  calldata_len;             // longueur réelle (100/132/164)

    signal input  action_type;              // 0=supply 1=borrow 2=repay 3=withdraw
    signal input  token_idx;               // index dans le registre
    signal input  int_digits[MAX_INT_DIGITS];
    signal input  frac_digits[MAX_DECIMALS];
    signal input  n_leading_zeros;          // nb de zéros de tête dans int_digits
    signal input  rate_mode;               // 1 ou 2 (ignoré pour supply/withdraw)

    signal input  human_string[STRING_LEN]; // la string ASCII affichée

    // ══ CONTRAINTE 1 : BINDING CALLDATA ══════════════════════════════════
    // Poseidon255(calldata) == H_tx
    component h_tx = PoseidonBytes(MAX_CALLDATA);
    for (var i = 0; i < MAX_CALLDATA; i++) h_tx.bytes[i] <== calldata[i];

    h_tx.hash === H_tx;

    // ══ CONTRAINTE 2 : PARSING ABI ═══════════════════════════════════════
    component mux = ActionMux();
    for (var i = 0; i < MAX_CALLDATA; i++) mux.calldata[i] <== calldata[i];
    mux.action_type <== action_type;

    // ABI valide
    mux.abi_ok === 1;

    // ══ CONTRAINTE 3 : FORMATTING ════════════════════════════════════════
    component fmt = StringMux(MAX_INT_DIGITS, MAX_DECIMALS);
    fmt.action_type    <== action_type;
    fmt.raw_amount     <== mux.amount;
    fmt.n_leading_zeros <== n_leading_zeros;
    for (var i = 0; i < MAX_INT_DIGITS; i++) fmt.int_digits[i]  <== int_digits[i];
    for (var i = 0; i < MAX_DECIMALS; i++)   fmt.frac_digits[i] <== frac_digits[i];
    fmt.addr_input  <== mux.asset;
    fmt.token_idx   <== token_idx;
    fmt.rate_mode   <== mux.rate_mode;

    // Format valide (recomposition OK, token connu, digits corrects)
    fmt.ok === 1;

    // La string calculée par le circuit == la string fournie par le prover
    for (var i = 0; i < STRING_LEN; i++) {
        fmt.str[i] === human_string[i];
    }

    // ══ CONTRAINTE 4 : BINDING STRING ════════════════════════════════════
    // Poseidon255(human_string) == H_str
    component h_str = PoseidonBytes(STRING_LEN);
    for (var i = 0; i < STRING_LEN; i++) h_str.bytes[i] <== human_string[i];

    h_str.hash === H_str;
}

// ── Point d'entrée ────────────────────────────────────────────────────
component main {public [H_tx, H_str]} = ClearSigningProof();
