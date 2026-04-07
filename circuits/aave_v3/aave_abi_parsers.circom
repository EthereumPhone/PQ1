//
// ─────────────────────────────────────────────────────────────────────
// Imported from: github.com/ZKNoxHQ/ZKlarity at commit 5e8b3f9
// Original path: circuits/aave_abi_parsers.circom
// Imported on:   2026-04-07
// License:       UNRESOLVED — see circuits/UPSTREAM.md
// Local edits:   none — sources below are byte-identical to upstream.
// ─────────────────────────────────────────────────────────────────────
//
pragma circom 2.0.0;

include "./abi_primitives.circom";

/*
 * AAVE_ABI_PARSERS.circom
 *
 * Un template par fonction Aave.
 * Chaque template :
 *   - vérifie le selector (hard-coded)
 *   - vérifie l'intégrité ABI (padding)
 *   - extrait les paramètres comme field elements
 *
 * Selectors keccak256 (4 bytes) :
 *   supply(address,uint256,address,uint16)      → 0x617ba037
 *   borrow(address,uint256,uint256,uint16,address) → 0xa415bcad
 *   repay(address,uint256,uint256,address)       → 0x573ade81
 *   withdraw(address,uint256,address)            → 0x69328dec
 *   setUserUseReserveAsCollateral(address,bool)  → 0x5a3b74b9
 *   setUserEMode(uint8)                          → 0x28530a47
 *   liquidationCall(address,address,address,uint256,bool) → 0x00a718a9
 */

/* ─────────────────────────────────────────────────────────────────────
 * ParseSupply
 *
 * supply(address asset, uint256 amount, address onBehalfOf, uint16 referralCode)
 * calldata = 4 + 4*32 = 132 bytes
 *
 * Slots :
 *   [0] asset        → address
 *   [1] amount       → uint256
 *   [2] onBehalfOf   → address
 *   [3] referralCode → uint16
 * ───────────────────────────────────────────────────────────────────── */
template ParseSupply() {
    signal input  calldata[132];

    // Paramètres extraits (sorties publiques du sous-circuit)
    signal output asset;          // field element : adresse 20 bytes
    signal output amount;         // field element : uint256
    signal output on_behalf_of;   // field element : adresse 20 bytes
    signal output referral_code;  // field element : uint16

    signal output abi_ok;         // 1 si selector + padding corrects

    // Découpe selector + 4 slots
    component slicer = SlotSelector(4);
    for (var i = 0; i < 132; i++) {
        slicer.calldata[i] <== calldata[i];
    }

    // Vérif selector 0x617ba037
    component sel = SelectorCheck(0x61, 0x7b, 0xa0, 0x37);
    for (var i = 0; i < 4; i++) {
        sel.calldata_bytes[i] <== slicer.selector[i];
    }

    // Slot 0 → asset (address)
    component ext_asset = ExtractAddress();
    for (var i = 0; i < 32; i++) ext_asset.slot[i] <== slicer.slots[0][i];
    asset <== ext_asset.addr_field;

    // Slot 1 → amount (uint256)
    component ext_amount = ExtractUint256();
    for (var i = 0; i < 32; i++) ext_amount.slot[i] <== slicer.slots[1][i];
    amount <== ext_amount.value;

    // Slot 2 → onBehalfOf (address)
    component ext_obo = ExtractAddress();
    for (var i = 0; i < 32; i++) ext_obo.slot[i] <== slicer.slots[2][i];
    on_behalf_of <== ext_obo.addr_field;

    // Slot 3 → referralCode (uint16)
    component ext_ref = ExtractUint16();
    for (var i = 0; i < 32; i++) ext_ref.slot[i] <== slicer.slots[3][i];
    referral_code <== ext_ref.value;

    // abi_ok = AND de tous les checks
    // (sel.ok AND asset.ok AND obo.ok AND ref.ok)
    signal t0; t0 <== sel.ok * ext_asset.ok;
    signal t1; t1 <== t0 * ext_obo.ok;
    abi_ok <== t1 * ext_ref.ok;
}

/* ─────────────────────────────────────────────────────────────────────
 * ParseBorrow
 *
 * borrow(address asset, uint256 amount, uint256 interestRateMode,
 *        uint16 referralCode, address onBehalfOf)
 * calldata = 4 + 5*32 = 164 bytes
 *
 * Slots :
 *   [0] asset            → address
 *   [1] amount           → uint256
 *   [2] interestRateMode → uint256 (valeur 1 ou 2)
 *   [3] referralCode     → uint16
 *   [4] onBehalfOf       → address
 * ───────────────────────────────────────────────────────────────────── */
template ParseBorrow() {
    signal input  calldata[164];

    signal output asset;
    signal output amount;
    signal output interest_rate_mode;  // 1 = stable, 2 = variable
    signal output referral_code;
    signal output on_behalf_of;

    signal output abi_ok;

    component slicer = SlotSelector(5);
    for (var i = 0; i < 164; i++) slicer.calldata[i] <== calldata[i];

    // Selector 0xa415bcad
    component sel = SelectorCheck(0xa4, 0x15, 0xbc, 0xad);
    for (var i = 0; i < 4; i++) sel.calldata_bytes[i] <== slicer.selector[i];

    component ext_asset = ExtractAddress();
    for (var i = 0; i < 32; i++) ext_asset.slot[i] <== slicer.slots[0][i];
    asset <== ext_asset.addr_field;

    component ext_amount = ExtractUint256();
    for (var i = 0; i < 32; i++) ext_amount.slot[i] <== slicer.slots[1][i];
    amount <== ext_amount.value;

    // interestRateMode est un uint256 mais vaut 1 ou 2
    // On l'extrait comme uint256, la contrainte valeur sera dans le circuit parent
    component ext_irm = ExtractUint256();
    for (var i = 0; i < 32; i++) ext_irm.slot[i] <== slicer.slots[2][i];
    interest_rate_mode <== ext_irm.value;

    component ext_ref = ExtractUint16();
    for (var i = 0; i < 32; i++) ext_ref.slot[i] <== slicer.slots[3][i];
    referral_code <== ext_ref.value;

    component ext_obo = ExtractAddress();
    for (var i = 0; i < 32; i++) ext_obo.slot[i] <== slicer.slots[4][i];
    on_behalf_of <== ext_obo.addr_field;

    signal t0; t0 <== sel.ok * ext_asset.ok;
    signal t1; t1 <== t0 * ext_obo.ok;
    signal t2; t2 <== t1 * ext_ref.ok;
    abi_ok <== t2;
}

/* ─────────────────────────────────────────────────────────────────────
 * ParseRepay
 *
 * repay(address asset, uint256 amount, uint256 interestRateMode, address onBehalfOf)
 * calldata = 4 + 4*32 = 132 bytes
 *
 * Slots :
 *   [0] asset            → address
 *   [1] amount           → uint256 (uint256.max = repay all)
 *   [2] interestRateMode → uint256 (1 ou 2)
 *   [3] onBehalfOf       → address
 * ───────────────────────────────────────────────────────────────────── */
template ParseRepay() {
    signal input  calldata[132];

    signal output asset;
    signal output amount;
    signal output interest_rate_mode;
    signal output on_behalf_of;

    signal output abi_ok;

    component slicer = SlotSelector(4);
    for (var i = 0; i < 132; i++) slicer.calldata[i] <== calldata[i];

    // Selector 0x573ade81
    component sel = SelectorCheck(0x57, 0x3a, 0xde, 0x81);
    for (var i = 0; i < 4; i++) sel.calldata_bytes[i] <== slicer.selector[i];

    component ext_asset = ExtractAddress();
    for (var i = 0; i < 32; i++) ext_asset.slot[i] <== slicer.slots[0][i];
    asset <== ext_asset.addr_field;

    component ext_amount = ExtractUint256();
    for (var i = 0; i < 32; i++) ext_amount.slot[i] <== slicer.slots[1][i];
    amount <== ext_amount.value;

    component ext_irm = ExtractUint256();
    for (var i = 0; i < 32; i++) ext_irm.slot[i] <== slicer.slots[2][i];
    interest_rate_mode <== ext_irm.value;

    component ext_obo = ExtractAddress();
    for (var i = 0; i < 32; i++) ext_obo.slot[i] <== slicer.slots[3][i];
    on_behalf_of <== ext_obo.addr_field;

    signal t0; t0 <== sel.ok * ext_asset.ok;
    abi_ok <== t0 * ext_obo.ok;
}

/* ─────────────────────────────────────────────────────────────────────
 * ParseWithdraw
 *
 * withdraw(address asset, uint256 amount, address to)
 * calldata = 4 + 3*32 = 100 bytes
 * ───────────────────────────────────────────────────────────────────── */
template ParseWithdraw() {
    signal input  calldata[100];

    signal output asset;
    signal output amount;
    signal output to;

    signal output abi_ok;

    component slicer = SlotSelector(3);
    for (var i = 0; i < 100; i++) slicer.calldata[i] <== calldata[i];

    // Selector 0x69328dec
    component sel = SelectorCheck(0x69, 0x32, 0x8d, 0xec);
    for (var i = 0; i < 4; i++) sel.calldata_bytes[i] <== slicer.selector[i];

    component ext_asset = ExtractAddress();
    for (var i = 0; i < 32; i++) ext_asset.slot[i] <== slicer.slots[0][i];
    asset <== ext_asset.addr_field;

    component ext_amount = ExtractUint256();
    for (var i = 0; i < 32; i++) ext_amount.slot[i] <== slicer.slots[1][i];
    amount <== ext_amount.value;

    component ext_to = ExtractAddress();
    for (var i = 0; i < 32; i++) ext_to.slot[i] <== slicer.slots[2][i];
    to <== ext_to.addr_field;

    signal t0; t0 <== sel.ok * ext_asset.ok;
    abi_ok <== t0 * ext_to.ok;
}

/* ─────────────────────────────────────────────────────────────────────
 * ParseSetCollateral
 *
 * setUserUseReserveAsCollateral(address asset, bool useAsCollateral)
 * calldata = 4 + 2*32 = 68 bytes
 *
 * bool en ABI = uint256 valant 0 ou 1
 * ───────────────────────────────────────────────────────────────────── */
template ParseSetCollateral() {
    signal input  calldata[68];

    signal output asset;
    signal output use_as_collateral;   // 0 ou 1

    signal output abi_ok;

    component slicer = SlotSelector(2);
    for (var i = 0; i < 68; i++) slicer.calldata[i] <== calldata[i];

    // Selector 0x5a3b74b9
    component sel = SelectorCheck(0x5a, 0x3b, 0x74, 0xb9);
    for (var i = 0; i < 4; i++) sel.calldata_bytes[i] <== slicer.selector[i];

    component ext_asset = ExtractAddress();
    for (var i = 0; i < 32; i++) ext_asset.slot[i] <== slicer.slots[0][i];
    asset <== ext_asset.addr_field;

    // bool = uint256 : on extrait et on vérifiera que val ∈ {0,1} côté circuit parent
    component ext_bool = ExtractUint256();
    for (var i = 0; i < 32; i++) ext_bool.slot[i] <== slicer.slots[1][i];
    use_as_collateral <== ext_bool.value;

    abi_ok <== sel.ok * ext_asset.ok;
}

/* ─────────────────────────────────────────────────────────────────────
 * ParseSetEMode
 *
 * setUserEMode(uint8 categoryId)
 * calldata = 4 + 1*32 = 36 bytes
 * ───────────────────────────────────────────────────────────────────── */
template ParseSetEMode() {
    signal input  calldata[36];

    signal output category_id;   // uint8
    signal output abi_ok;

    component slicer = SlotSelector(1);
    for (var i = 0; i < 36; i++) slicer.calldata[i] <== calldata[i];

    // Selector 0x28530a47
    component sel = SelectorCheck(0x28, 0x53, 0x0a, 0x47);
    for (var i = 0; i < 4; i++) sel.calldata_bytes[i] <== slicer.selector[i];

    component ext_cat = ExtractUint8();
    for (var i = 0; i < 32; i++) ext_cat.slot[i] <== slicer.slots[0][i];
    category_id <== ext_cat.value;

    abi_ok <== sel.ok * ext_cat.ok;
}
