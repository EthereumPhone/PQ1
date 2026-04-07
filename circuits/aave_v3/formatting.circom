//
// ─────────────────────────────────────────────────────────────────────
// Imported from: github.com/ZKNoxHQ/ZKlarity at commit 5e8b3f9
// Original path: circuits/formatting.circom
// Imported on:   2026-04-07
// License:       UNRESOLVED — see circuits/UPSTREAM.md
// Local edits:   none — sources below are byte-identical to upstream.
// ─────────────────────────────────────────────────────────────────────
//
pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/comparators.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

/*
 * FORMATTING.circom
 *
 * Conversion uint256 → string décimale ASCII en circuit ZK.
 *
 * PRINCIPE FONDAMENTAL :
 *   La division n'existe pas nativement en R1CS.
 *   → Le prover calcule les chiffres off-chain.
 *   → Le circuit vérifie que la recomposition est correcte.
 *
 *   Si digits = [d0, d1, ..., d_{N-1}], le circuit vérifie :
 *     d0 * 10^(N-1) + d1 * 10^(N-2) + ... + d_{N-1} == value
 *   ET chaque di ∈ [0, 9]
 *   ET pas de zéro non significatif (d0 != 0, sauf si N == 1)
 */

/* ─────────────────────────────────────────────────────────────────────
 * IsDigit : contraint x ∈ {0, 1, ..., 9}
 *
 * Méthode : LessThan(4) car 9 < 2^4 = 16.
 * 2 contraintes : x < 10 et x >= 0 (garanti si x est field positif
 * et < 10, mais on doit aussi exclure x > p-10 qui serait < 10 mod p).
 * → On ajoute Num2Bits(4) pour forcer x ∈ [0,15] puis LessThan.
 * ───────────────────────────────────────────────────────────────────── */
template IsDigit() {
    signal input  x;
    signal output ok;

    // Force x dans [0, 15] via décomposition 4 bits
    component bits = Num2Bits(4);
    bits.in <== x;

    // Vérifie x < 10
    component lt = LessThan(4);
    lt.in[0] <== x;
    lt.in[1] <== 10;
    ok <== lt.out;
}

/* ─────────────────────────────────────────────────────────────────────
 * AllDigits(N) : vérifie que N valeurs sont toutes des chiffres [0-9]
 * ───────────────────────────────────────────────────────────────────── */
template AllDigits(N) {
    signal input  digits[N];
    signal output ok;

    component checks[N];
    signal acc[N+1];
    acc[0] <== 1;
    for (var i = 0; i < N; i++) {
        checks[i] = IsDigit();
        checks[i].x <== digits[i];
        acc[i+1] <== acc[i] * checks[i].ok;
    }
    ok <== acc[N];
}

/* ─────────────────────────────────────────────────────────────────────
 * RecomposeDecimal(N) : vérifie que digits[] encode bien value
 *
 * Calcule : sum = d[0]*10^(N-1) + d[1]*10^(N-2) + ... + d[N-1]
 * Contraint : sum == value
 *
 * C'est le cœur de la vérification de formatting.
 * ───────────────────────────────────────────────────────────────────── */
template RecomposeDecimal(N) {
    signal input  digits[N];   // chiffres du plus significatif au moins significatif
    signal input  value;       // valeur attendue (field element)
    signal output ok;          // 1 si la recomposition est correcte

    signal acc[N+1];
    acc[0] <== 0;
    for (var i = 0; i < N; i++) {
        acc[i+1] <== acc[i] * 10 + digits[i];
    }

    component isz = IsZero();
    isz.in <== acc[N] - value;
    ok <== isz.out;
}

/* ─────────────────────────────────────────────────────────────────────
 * CountLeadingZeros(N) : compte les zéros de tête dans digits[]
 *
 * Le prover fournit n_lz (le nombre de zéros de tête).
 * Le circuit vérifie :
 *   - digits[0..n_lz-1] sont tous nuls
 *   - digits[n_lz] != 0  (sauf si n_lz == N-1, i.e. valeur = 0)
 *
 * n_lz est un signal privé fourni par le prover.
 * ───────────────────────────────────────────────────────────────────── */
template CountLeadingZeros(N) {
    signal input  digits[N];
    signal input  n_lz;        // nb de zéros de tête (witness)
    signal output ok;

    // 1. Vérifie que digits[0..n_lz-1] sont nuls
    //    Approche : one-hot sur n_lz, puis vérification cumulée
    //    Pour N <= 10, on peut vérifier avec un mux simple.

    // sel[i] = 1 si i < n_lz (on doit avoir digits[i] == 0)
    // Trick : pour chaque i, contraint digits[i] * (1 - IsGte(i, n_lz)) == 0
    // Plus simple : somme des digits[i]^2 pour i < n_lz == 0
    // Mais on n'a pas d'opérateur < sur les signaux sans contraintes supplémentaires.
    //
    // Solution compacte : le prover fournit un selector one-hot is_lz[i]
    // is_lz[i] = 1 si i < n_lz → vérifié par RecomposeDecimal + count
    //
    // Pour rester simple : on vérifie directement via des IsZero conditionnels
    // en utilisant le fait que n_lz <= N-1.

    // Recompose n_lz en one-hot (sel[i] = 1 si i == n_lz)
    component eqs[N];
    signal sel[N];
    for (var i = 0; i < N; i++) {
        eqs[i] = IsZero();
        eqs[i].in <== n_lz - i;
        sel[i] <== eqs[i].out;
    }

    // cum[i] = 1 si i >= n_lz (les digits à partir de n_lz ne sont pas forcément nuls)
    // cum[i] = 0 si i < n_lz (ces digits DOIVENT être nuls)
    // cum[i] = sum_{j=0}^{i} sel[j]
    signal cum[N+1];
    cum[0] <== 0;
    for (var i = 0; i < N; i++) {
        cum[i+1] <== cum[i] + sel[i];
    }

    // Contrainte : (1 - cum[i+1]) * digits[i] == 0
    // Si i < n_lz → cum[i+1] < 1 → 1-cum[i+1] > 0 → digits[i] doit être 0
    // Si i >= n_lz → cum[i+1] == 1 → contrainte triviale
    signal must_be_zero[N];
    component isz[N];
    signal ok_acc[N+1];
    ok_acc[0] <== 1;
    for (var i = 0; i < N; i++) {
        isz[i] = IsZero();
        must_be_zero[i] <== (1 - cum[i+1]) * digits[i];
        isz[i].in <== must_be_zero[i];
        ok_acc[i+1] <== ok_acc[i] * isz[i].out;
    }

    // 2. Vérifie que n_lz est dans [0, N-1]
    component range = LessThan(4);
    range.in[0] <== n_lz;
    range.in[1] <== N;

    ok <== ok_acc[N] * range.out;
}

/* ─────────────────────────────────────────────────────────────────────
 * Uint256ToDecimalDigits(MAX_DIGITS)
 *
 * Template principal : prend un uint256 et des digits en entrée (witness),
 * vérifie que les digits représentent correctement la valeur.
 *
 * MAX_DIGITS : longueur fixe du tableau de digits (avec zéros à gauche
 *              jusqu'au chiffre significatif).
 *
 * Paramètre N_DIGITS (signal) : nombre de chiffres significatifs
 *   Le prover fournit les digits avec zéros de remplissage à gauche.
 *   Ex: value=1234, MAX_DIGITS=8 → digits=[0,0,0,0,1,2,3,4]
 *
 * IMPORTANT : on travaille avec MAX_DIGITS fixe pour que le circuit
 * ait un nombre fixe de contraintes. Le padding de zéros à gauche est
 * vérifié par RecomposeDecimal (les zéros n'affectent pas la somme).
 * ───────────────────────────────────────────────────────────────────── */
template Uint256ToDecimalDigits(MAX_DIGITS) {
    signal input  value;                // uint256 à encoder
    signal input  digits[MAX_DIGITS];   // digits fournis par le prover (witness privé)

    signal output ok;                   // 1 si encoding correct

    // 1. Tous les digits sont dans [0,9]
    component digit_check = AllDigits(MAX_DIGITS);
    for (var i = 0; i < MAX_DIGITS; i++) {
        digit_check.digits[i] <== digits[i];
    }

    // 2. La recomposition donne bien value
    component recompose = RecomposeDecimal(MAX_DIGITS);
    for (var i = 0; i < MAX_DIGITS; i++) {
        recompose.digits[i] <== digits[i];
    }
    recompose.value <== value;

    // ok = digit_check.ok AND recompose.ok
    ok <== digit_check.ok * recompose.ok;
}

/* ─────────────────────────────────────────────────────────────────────
 * InsertDecimalPoint(MAX_DIGITS, DECIMALS)
 *
 * Transforme un tableau de chiffres entiers en tableau ASCII avec
 * point décimal inséré à la bonne position.
 *
 * Ex : USDC a 6 decimals
 *   digits = [0,0,0,1,0,0,0,0,0,0,0,0]  (12 digits, value = 1_000000)
 *   DECIMALS = 6
 *   → ascii = "1.000000" = [49, 46, 48, 48, 48, 48, 48, 48]
 *
 * La partie entière = digits[0..MAX_DIGITS-DECIMALS-1]
 * La partie décimale = digits[MAX_DIGITS-DECIMALS..MAX_DIGITS-1]
 *
 * OUT_LEN = MAX_DIGITS + 1  (+ le point)
 *   sauf si DECIMALS == 0 → OUT_LEN = MAX_DIGITS (pas de point)
 *
 * NOTE : on émet tous les bytes ASCII y compris les zéros de tête.
 * Le circuit parent devra gérer le "trim" des zéros non significatifs
 * via le signal n_significant (nombre de digits significatifs).
 * ───────────────────────────────────────────────────────────────────── */
template DigitsToAsciiWithDecimalPoint(INT_DIGITS, FRAC_DIGITS) {
    // INT_DIGITS  : nb de chiffres partie entière (fournis sans zéros de tête)
    // FRAC_DIGITS : nb de chiffres partie fractionnaire (précision du token)
    var TOTAL_DIGITS = INT_DIGITS + FRAC_DIGITS;
    var ASCII_LEN    = (FRAC_DIGITS > 0) ? TOTAL_DIGITS + 1 : TOTAL_DIGITS;
    // +1 pour le point décimal si FRAC_DIGITS > 0

    signal input  int_digits[INT_DIGITS];    // chiffres partie entière
    signal input  frac_digits[FRAC_DIGITS];  // chiffres partie fractionnaire
    signal output ascii[ASCII_LEN];          // codes ASCII

    // Partie entière → ASCII
    for (var i = 0; i < INT_DIGITS; i++) {
        // digit + 48 = code ASCII ('0' = 48, '9' = 57)
        ascii[i] <== int_digits[i] + 48;
    }

    if (FRAC_DIGITS > 0) {
        // Point décimal : ASCII 46 = '.'
        ascii[INT_DIGITS] <== 46;

        // Partie fractionnaire → ASCII
        for (var i = 0; i < FRAC_DIGITS; i++) {
            ascii[INT_DIGITS + 1 + i] <== frac_digits[i] + 48;
        }
    }
}

/* ─────────────────────────────────────────────────────────────────────
 * FormatAmount(MAX_INT_DIGITS, DECIMALS)
 *
 * Template de haut niveau : prend un amount brut (ex: 1000_000000 pour
 * 1000 USDC) et produit la représentation ASCII complète.
 *
 * Paramètres :
 *   MAX_INT_DIGITS : nombre max de chiffres pour la partie entière
 *   DECIMALS       : décimales du token (6 pour USDC, 18 pour WETH...)
 *
 * Entrées (signaux) :
 *   raw_amount   : le montant brut (field element)
 *   int_digits[] : chiffres de la partie entière (witness)
 *   frac_digits[]: chiffres de la partie fractionnaire (witness)
 *
 * Sortie :
 *   ascii[]      : représentation ASCII (avec point décimal)
 *   ok           : 1 si tout est cohérent
 *
 * VÉRIFICATION :
 *   raw_amount == int_value * 10^DECIMALS + frac_value
 *   où int_value = recompose(int_digits)
 *       frac_value = recompose(frac_digits)
 * ───────────────────────────────────────────────────────────────────── */
template FormatAmount(MAX_INT_DIGITS, DECIMALS) {
    var ASCII_LEN = (DECIMALS > 0) ? MAX_INT_DIGITS + 1 + DECIMALS : MAX_INT_DIGITS;

    signal input  raw_amount;                   // montant brut
    signal input  int_digits[MAX_INT_DIGITS];   // witness : partie entière
    signal input  frac_digits[DECIMALS];        // witness : partie fractionnaire
    signal input  n_leading_zeros;              // witness : nb de zéros de tête dans int_digits
    signal input  scale_factor;                  // 10^(18-decimals) du token

    signal output ascii[ASCII_LEN];             // string ASCII (MAX_INT_DIGITS - n_lz + 1 + DECIMALS bytes)
    signal output ok;

    // 1+2. Recomposition manuelle int et frac (pas de composant intermédiaire)
    // Calcul de 10^DECIMALS (constante de compilation)
    var pow10 = 1;
    for (var i = 0; i < DECIMALS; i++) {
        pow10 = pow10 * 10;
    }

    // 3. Contrainte principale :
    //    raw_amount == int_value * 10^DECIMALS + frac_value
    //    ⟺  acc_int * pow10 + acc_frac == raw_amount
    signal reconstructed;

    signal int_acc[MAX_INT_DIGITS+1];
    int_acc[0] <== 0;
    for (var i = 0; i < MAX_INT_DIGITS; i++) {
        int_acc[i+1] <== int_acc[i] * 10 + int_digits[i];
    }

    signal frac_acc[DECIMALS+1];
    frac_acc[0] <== 0;
    for (var i = 0; i < DECIMALS; i++) {
        frac_acc[i+1] <== frac_acc[i] * 10 + frac_digits[i];
    }

    // Contrainte centrale : raw_amount * scale_factor == int_acc * 10^18 + frac_acc
    // raw_amount * scale_factor = une contrainte quadratique (signal * signal)
    reconstructed <== raw_amount * scale_factor;
    component isz = IsZero();
    isz.in <== reconstructed - (int_acc[MAX_INT_DIGITS] * pow10 + frac_acc[DECIMALS]);
    signal recompose_ok;
    recompose_ok <== isz.out;

    // 4. Tous les chiffres sont dans [0,9]
    component int_digit_check = AllDigits(MAX_INT_DIGITS);
    for (var i = 0; i < MAX_INT_DIGITS; i++) {
        int_digit_check.digits[i] <== int_digits[i];
    }

    component frac_digit_check = AllDigits(DECIMALS);
    for (var i = 0; i < DECIMALS; i++) {
        frac_digit_check.digits[i] <== frac_digits[i];
    }

    // 5. Compte et vérifie les zéros de tête
    component count_lz = CountLeadingZeros(MAX_INT_DIGITS);
    for (var i = 0; i < MAX_INT_DIGITS; i++) {
        count_lz.digits[i] <== int_digits[i];
    }
    count_lz.n_lz <== n_leading_zeros;

    // 6. Assemblage ASCII
    component to_ascii = DigitsToAsciiWithDecimalPoint(MAX_INT_DIGITS, DECIMALS);
    for (var i = 0; i < MAX_INT_DIGITS; i++) {
        to_ascii.int_digits[i] <== int_digits[i];
    }
    for (var i = 0; i < DECIMALS; i++) {
        to_ascii.frac_digits[i] <== frac_digits[i];
    }
    for (var i = 0; i < ASCII_LEN; i++) {
        ascii[i] <== to_ascii.ascii[i];
    }

    // ok global
    signal t0; t0 <== recompose_ok * int_digit_check.ok;
    signal t1; t1 <== t0 * frac_digit_check.ok;
    ok <== t1 * count_lz.ok;
}
