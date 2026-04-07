//
// ─────────────────────────────────────────────────────────────────────
// Imported from: github.com/ZKNoxHQ/ZKlarity at commit 5e8b3f9
// Original path: circuits/abi_primitives.circom
// Imported on:   2026-04-07
// License:       UNRESOLVED — upstream has no LICENSE file at import
//                time. See circuits/UPSTREAM.md for the full provenance
//                story and license caveats. This copy may need to be
//                removed or relicensed if upstream publishes an
//                incompatible license.
// Local edits:   none — sources below are byte-identical to upstream.
//                Include resolution still works because our layout
//                (circuits/aave_v3/*.circom → circuits/node_modules/)
//                preserves the same one-up relative path as upstream.
// ─────────────────────────────────────────────────────────────────────
//
pragma circom 2.0.0;

include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

/*
 * ABI_PRIMITIVES.circom
 *
 * Briques de base pour le parsing ABI d'un calldata Ethereum.
 * On travaille sur un tableau de bytes (field elements in [0,255]).
 *
 * Convention : calldata[0..3]   = selector (4 bytes)
 *              calldata[4..N-1] = slots ABI (multiples de 32 bytes)
 *
 * BN254 field prime ≈ 2^254, donc un slot de 32 bytes rentre
 * dans un seul field element (uint256 ≤ 2^256 - attention au MSB,
 * mais en pratique les amounts Aave sont << p).
 * Pour une rigueur maximale on travaille byte à byte.
 */

/* ─────────────────────────────────────────────────────────────────────
 * IsZero254 : vérifie qu'un tableau de N bytes vaut 0x00...0x00
 * Utilisé pour vérifier le padding des slots address / uint16.
 * ───────────────────────────────────────────────────────────────────── */
template AllZeroBytes(N) {
    signal input  bytes[N];
    signal output ok;          // 1 si tous nuls, 0 sinon

    signal acc[N+1];
    acc[0] <== 0;
    for (var i = 0; i < N; i++) {
        // bytes[i] == 0  ⟺  bytes[i] * (1 - IsZero(bytes[i])) == 0
        // Plus simple : on accumule bytes[i]^2, si tout est 0 la somme est 0
        acc[i+1] <== acc[i] + bytes[i] * bytes[i];
    }
    // acc[N] == 0 ⟺ tous les bytes sont nuls
    component isz = IsZero();
    isz.in <== acc[N];
    ok <== isz.out;
}

/* ─────────────────────────────────────────────────────────────────────
 * BytesEqual(N) : vérifie que deux tableaux de N bytes sont identiques
 * ───────────────────────────────────────────────────────────────────── */
template BytesEqual(N) {
    signal input  a[N];
    signal input  b[N];
    signal output ok;   // 1 si a == b

    signal diffs[N];
    signal acc[N+1];
    acc[0] <== 0;
    for (var i = 0; i < N; i++) {
        diffs[i] <== a[i] - b[i];
        acc[i+1] <== acc[i] + diffs[i] * diffs[i];
    }
    component isz = IsZero();
    isz.in <== acc[N];
    ok <== isz.out;
}

/* ─────────────────────────────────────────────────────────────────────
 * SelectorCheck(expected) : vérifie calldata[0..3] == expected[0..3]
 *
 * Le selector est passé comme constante dans le circuit (hard-coded
 * par action). Pas de signal public pour le selector → le circuit
 * est spécialisé par fonction Aave.
 * ───────────────────────────────────────────────────────────────────── */
template SelectorCheck(s0, s1, s2, s3) {
    signal input calldata_bytes[4];
    signal output ok;

    // Contraintes directes : chaque byte doit valoir la constante
    signal d0; d0 <== calldata_bytes[0] - s0;
    signal d1; d1 <== calldata_bytes[1] - s1;
    signal d2; d2 <== calldata_bytes[2] - s2;
    signal d3; d3 <== calldata_bytes[3] - s3;

    // ok = (d0 == 0) AND (d1 == 0) AND (d2 == 0) AND (d3 == 0)
    // Chaque produit dans sa propre contrainte (R1CS : un seul produit par contrainte)
    signal sq0; sq0 <== d0 * d0;
    signal sq1; sq1 <== d1 * d1;
    signal sq2; sq2 <== d2 * d2;
    signal sq3; sq3 <== d3 * d3;
    signal c01; c01 <== sq0 + sq1;
    signal c23; c23 <== sq2 + sq3;
    signal acc; acc <== c01 + c23;

    component isz = IsZero();
    isz.in <== acc;
    ok <== isz.out;
}

/* ─────────────────────────────────────────────────────────────────────
 * SlotToField(NBYTES) : pack N bytes big-endian en un field element
 *
 * out = bytes[0] * 256^(N-1) + bytes[1] * 256^(N-2) + ... + bytes[N-1]
 *
 * NBYTES ≤ 31 pour rester sous p de BN254 sans ambiguité.
 * Pour uint256 complet (32 bytes), utiliser avec précaution
 * (valable si la valeur < p ≈ 2^254, ce qui est le cas des amounts).
 * ───────────────────────────────────────────────────────────────────── */
template SlotToField(NBYTES) {
    signal input  bytes[NBYTES];
    signal output out;

    signal acc[NBYTES + 1];
    acc[0] <== 0;
    for (var i = 0; i < NBYTES; i++) {
        acc[i+1] <== acc[i] * 256 + bytes[i];
    }
    out <== acc[NBYTES];
}

/* ─────────────────────────────────────────────────────────────────────
 * ExtractAddress : extrait une adresse ETH depuis un slot ABI de 32 bytes
 *
 * ABI address encoding : [12 bytes 0x00 padding][20 bytes address]
 *
 * Sorties :
 *   addr_field = adresse encodée en field element (160 bits)
 *   ok         = 1 si le padding est bien nul (intégrité ABI)
 * ───────────────────────────────────────────────────────────────────── */
template ExtractAddress() {
    signal input  slot[32];   // 32 bytes du slot ABI
    signal output addr_field; // 20 bytes → field element
    signal output ok;         // padding ok

    // Vérifie que les 12 premiers bytes sont 0
    component pad_check = AllZeroBytes(12);
    for (var i = 0; i < 12; i++) {
        pad_check.bytes[i] <== slot[i];
    }
    ok <== pad_check.ok;

    // Pack les 20 bytes d'adresse
    component pack = SlotToField(20);
    for (var i = 0; i < 20; i++) {
        pack.bytes[i] <== slot[12 + i];
    }
    addr_field <== pack.out;
}

/* ─────────────────────────────────────────────────────────────────────
 * ExtractUint256 : extrait un uint256 depuis un slot ABI de 32 bytes
 *
 * Pas de padding à vérifier. Pack direct 32 bytes.
 * ATTENTION : valide uniquement si valeur < BN254 prime.
 * Pour les montants DeFi c'est toujours le cas en pratique.
 * ───────────────────────────────────────────────────────────────────── */
template ExtractUint256() {
    signal input  slot[32];
    signal output value;

    component pack = SlotToField(32);
    for (var i = 0; i < 32; i++) {
        pack.bytes[i] <== slot[i];
    }
    value <== pack.out;
}

/* ─────────────────────────────────────────────────────────────────────
 * ExtractUint16 : extrait un uint16 depuis un slot ABI de 32 bytes
 *
 * ABI uint16 encoding : [30 bytes 0x00 padding][2 bytes value]
 * ───────────────────────────────────────────────────────────────────── */
template ExtractUint16() {
    signal input  slot[32];
    signal output value;
    signal output ok;   // padding nul

    component pad_check = AllZeroBytes(30);
    for (var i = 0; i < 30; i++) {
        pad_check.bytes[i] <== slot[i];
    }
    ok <== pad_check.ok;

    value <== slot[30] * 256 + slot[31];
}

/* ─────────────────────────────────────────────────────────────────────
 * ExtractUint8 : extrait un uint8 (ex: rateMode) depuis un slot ABI
 *
 * ABI uint8 encoding : [31 bytes 0x00 padding][1 byte value]
 * ───────────────────────────────────────────────────────────────────── */
template ExtractUint8() {
    signal input  slot[32];
    signal output value;
    signal output ok;

    component pad_check = AllZeroBytes(31);
    for (var i = 0; i < 31; i++) {
        pad_check.bytes[i] <== slot[i];
    }
    ok <== pad_check.ok;

    value <== slot[31];
}

/* ─────────────────────────────────────────────────────────────────────
 * SlotSelector(NSLOTS) : découpe calldata en selector + slots de 32 bytes
 *
 * calldata_len = 4 + NSLOTS * 32
 * ───────────────────────────────────────────────────────────────────── */
template SlotSelector(NSLOTS) {
    var CALLDATA_LEN = 4 + NSLOTS * 32;
    signal input  calldata[CALLDATA_LEN];

    signal output selector[4];
    signal output slots[NSLOTS][32];

    // Selector
    for (var i = 0; i < 4; i++) {
        selector[i] <== calldata[i];
    }

    // Slots
    for (var s = 0; s < NSLOTS; s++) {
        for (var b = 0; b < 32; b++) {
            slots[s][b] <== calldata[4 + s * 32 + b];
        }
    }
}
