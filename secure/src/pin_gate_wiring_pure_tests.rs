//! Wiring pins for the die-bound PIN credential path (issue #855).
//!
//! The derivation and the salt lifecycle are executed by host tests in
//! `pin_credential` and `pin_salt`. What those tests cannot reach is the
//! firmware around them: `pin_gate`, `hw::secret_keys`, `hw::flash` and `nsc`
//! are `#[cfg(not(test))]`, so nothing on the host runs the code that picks
//! the PRF key, chooses the salt policy, or decides when the attempt counter
//! is reset. A host test that injects its own PRF proves nothing about which
//! PRF the device uses.
//!
//! These tests read that source text and pin the specific wiring facts the
//! security argument rests on. They are deliberately strict (whole function
//! bodies, exact call shapes): a change to any of them should be a decision,
//! made with this file open, not a side effect.
//!
//! What a source-text pin can and cannot show: it shows the reviewed text is
//! still the text. It does not show the text is correct, and it does not
//! replace running the path on silicon.

const PIN_GATE_SRC: &str = include_str!("pin_gate.rs");
const SECRET_KEYS_SRC: &str = include_str!("hw/secret_keys.rs");
const FLASH_SRC: &str = include_str!("hw/flash.rs");
const NSC_MOD_SRC: &str = include_str!("nsc/mod.rs");
const REQUEST_UNLOCK_SRC: &str = include_str!("nsc/cmd_request_unlock.rs");
const MAIN_SRC: &str = include_str!("main.rs");
const DUAL_SE_SRC: &str = include_str!("dual_se.rs");
const OPTIGA_SRC: &str = include_str!("optiga/mod.rs");
const SE050_SRC: &str = include_str!("se050/mod.rs");

/// The text of `fn <name>` from its signature line to the closing brace at
/// the function's own indentation.
fn function_text<'a>(src: &'a str, signature_start: &str) -> &'a str {
    // Leading spaces in the argument are ignored: the indentation is read
    // from the source line itself, so the closing brace that is searched
    // for is always the function's own.
    let signature_start = signature_start.trim_start();
    assert_eq!(
        src.matches(signature_start).count(),
        1,
        "`{signature_start}` must occur exactly once"
    );
    let start = src
        .find(signature_start)
        .unwrap_or_else(|| panic!("`{signature_start}` not found"));
    let line_start = src[..start].rfind('\n').map_or(0, |i| i + 1);
    let indent = &src[line_start..start];
    assert!(
        indent.chars().all(|c| c == ' '),
        "`{signature_start}` is not at the start of a line"
    );
    let closer = std::format!("\n{indent}}}\n");
    let end = src[start..]
        .find(&closer)
        .unwrap_or_else(|| panic!("end of `{signature_start}` not found"));
    &src[start..start + end + closer.len()]
}

/// Source text with comments and all whitespace removed, so a pin is about
/// the code and survives re-wrapping.
fn code_only(src: &str) -> std::string::String {
    let mut out = std::string::String::new();
    for line in src.lines() {
        let code = match line.find("//") {
            Some(i) => &line[..i],
            None => line,
        };
        out.extend(code.chars().filter(|c| !c.is_whitespace()));
    }
    out
}

// ─────────────────────────────────────────────────────────────────────
// The PRF the device actually uses
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_production_prf_is_exactly_the_device_key_kdf() {
    // ASSUMPTION ATTACKED: someone edits the wrapper so that it still calls
    // the device-key KDF but then replaces, mixes or truncates the output
    // with something unkeyed. Every host test would stay green, because the
    // host tests pass their own PRF. So the wrapper's whole body is pinned:
    // it is one call and nothing else.
    let body = code_only(function_text(
        SECRET_KEYS_SRC,
        "pub fn pin_credential_prf(info: &[u8], out: &mut [u8]) -> Result<(), OtpError> {",
    ));
    assert_eq!(
        body,
        "pubfnpin_credential_prf(info:&[u8],out:&mut[u8])->Result<(),OtpError>{derive_into(info,out)}",
        "pin_credential_prf must be exactly `derive_into(info, out)`"
    );
}

#[test]
fn negative_device_key_kdf_selects_its_root_exactly_as_reviewed() {
    // ASSUMPTION ATTACKED (review): the wrapper is untouched, but the root
    // it reaches is changed underneath it — the cfg arms of `derive_into`
    // reordered, or the SAES key selector swapped for a software key. The
    // whole of `derive_into` is therefore pinned too. It is shared with the
    // OPTIGA pairing secret, so a change here is already a re-pairing event;
    // this makes it a visible one for the PIN credentials as well.
    let body = code_only(function_text(
        SECRET_KEYS_SRC,
        "fn derive_into(label: &[u8], output: &mut [u8]) -> Result<(), OtpError> {",
    ));
    assert_eq!(
        body,
        concat!(
            "fnderive_into(label:&[u8],output:&mut[u8])->Result<(),OtpError>{",
            "#[cfg(feature=\"otp-hardcoded-master-key\")]",
            "{letmutmaster=unsafe{otp::ensure_device_master()?};hkdf_expand(&master,label,output);master.zeroize();Ok(())}",
            "#[cfg(all(not(feature=\"otp-hardcoded-master-key\"),feature=\"saes-dhuk\"))]",
            "{derive_into_saes_kdf(label,output)}",
            "#[cfg(all(not(feature=\"otp-hardcoded-master-key\"),not(feature=\"saes-dhuk\")))]",
            "{letmutmaster=unsafe{otp::ensure_device_master()?};hkdf_expand(&master,label,output);master.zeroize();Ok(())}",
            "}",
        ),
        "derive_into's root selection changed: re-review what keys the PIN credentials"
    );
}

#[test]
fn negative_production_prf_is_on_the_dhuk_axis() {
    // `derive_into` is the DHUK axis. The BHK axis (`derive_into_bhk`) has
    // open lifecycle defects (#707, #712) and the transport axis is public
    // by design; neither may key the PIN credentials.
    let body = function_text(
        SECRET_KEYS_SRC,
        "pub fn pin_credential_prf(info: &[u8], out: &mut [u8]) -> Result<(), OtpError> {",
    );
    assert!(!body.contains("derive_into_bhk"));
    assert!(!body.contains("transport_derive_into"));

    // And under `saes-dhuk` that axis is the SAES peripheral keyed by the
    // DHUK, not a key held in CPU-visible memory.
    let saes = function_text(
        SECRET_KEYS_SRC,
        "fn derive_into_saes_kdf(label: &[u8], output: &mut [u8]) -> Result<(), OtpError> {",
    );
    assert!(saes.contains("|block| saes::encrypt_ecb_block(KeySel::Dhuk, None, block),"));
    // The scratch copy of `label || salt || PIN` is wiped before return.
    assert!(saes.contains("info.zeroize();"));
}

#[test]
fn negative_pin_gate_derives_only_through_the_production_prf() {
    let raw = function_text(PIN_GATE_SRC, "pub fn credentials(");
    // Every shippable build takes the device-key PRF; the bench PRF is
    // selected only by the two bench features. Nothing else is ever bound.
    assert!(
        raw.contains(
            "    #[cfg(not(any(feature = \"e2e-test\", feature = \"otp-hardcoded-master-key\")))]\n    let prf = crate::hw::secret_keys::pin_credential_prf;\n"
        ),
        "a shippable build must bind the device-key PRF"
    );
    assert!(raw.contains(
        "    #[cfg(any(feature = \"e2e-test\", feature = \"otp-hardcoded-master-key\"))]\n    let prf = crate::hw::secret_keys::pin_credential_bench_prf;\n"
    ));
    assert_eq!(raw.matches("let prf = ").count(), 2);
    let body = code_only(raw);
    assert!(
        body.contains("pin_credential::derive_set(role,salt,pin,prf).map_err(|_|PinGateError::Derive)"),
        "pin_gate::credentials must hand derive_set the PRF bound above"
    );
    // The bench PRF exists only under the bench features.
    assert!(SECRET_KEYS_SRC.contains(
        "#[cfg(any(feature = \"e2e-test\", feature = \"otp-hardcoded-master-key\"))]\npub fn pin_credential_bench_prf(info: &[u8], out: &mut [u8]) -> Result<(), OtpError> {"
    ));
    assert!(SECRET_KEYS_SRC.contains(
        "#[cfg(any(feature = \"e2e-test\", feature = \"otp-hardcoded-master-key\"))]\nconst BENCH_PIN_PRF_KEY: [u8; 32]"
    ));
    // One derivation site, one PRF, in the whole firmware.
    for (name, src) in [
        ("pin_gate.rs", PIN_GATE_SRC),
        ("dual_se.rs", DUAL_SE_SRC),
        ("optiga/mod.rs", OPTIGA_SRC),
        ("se050/mod.rs", SE050_SRC),
        ("main.rs", MAIN_SRC),
    ] {
        let want = usize::from(name == "pin_gate.rs");
        assert_eq!(
            src.matches("derive_set(").count(),
            want,
            "{name}: derive_set may be called only from pin_gate::credentials"
        );
    }
    assert_eq!(
        SECRET_KEYS_SRC.matches("pub fn pin_credential_prf").count(),
        1
    );
}

// ─────────────────────────────────────────────────────────────────────
// Mint policy and salt policy
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_production_refuses_to_derive_below_rdp2() {
    let policy = code_only(function_text(PIN_GATE_SRC, "const fn mint_policy() -> MintPolicy {"));
    assert!(
        policy.contains(
            "ifcfg!(any(feature=\"mode-production\",feature=\"rdp2-self-lock\")){MintPolicy::RequireRdp2}else{MintPolicy::AnyLevel}"
        ),
        "a production build must select MintPolicy::RequireRdp2"
    );
    // The check runs before the derivation, on the live RDP level.
    let creds = code_only(function_text(PIN_GATE_SRC, "pub fn credentials("));
    let gate = creds
        .find("if!pin_credential::mint_allowed(mint_policy(),rdp_is_level2){returnErr(PinGateError::DeviceKeyNotFinal);}")
        .expect("credentials() must refuse when minting is not allowed");
    let derive = creds.find("pin_credential::derive_set(").expect("derive present");
    assert!(gate < derive, "the mint check must come before the derivation");
    assert!(creds.contains("crate::hw::flash::rdp_level()"));
    assert!(creds.contains("crate::hw::flash::RdpLevel::L2"));
}

#[test]
fn negative_bench_salt_is_fenced_out_of_production() {
    // The fixed public salt exists only under the two bench features ...
    let cfg = "#[cfg(any(feature = \"e2e-test\", feature = \"otp-hardcoded-master-key\"))]\nstatic BENCH_FIXED_SALT:";
    assert!(
        PIN_GATE_SRC.contains(cfg),
        "BENCH_FIXED_SALT must be compiled only under e2e-test / otp-hardcoded-master-key"
    );
    assert_eq!(PIN_GATE_SRC.matches("static BENCH_FIXED_SALT").count(), 1);
    // ... a production build with either feature does not compile ...
    assert!(PIN_GATE_SRC.contains(
        "#[cfg(all(\n    feature = \"mode-production\",\n    any(feature = \"e2e-test\", feature = \"otp-hardcoded-master-key\")\n))]\ncompile_error!("
    ));
    // ... and every other build gets the per-provisioning policy.
    let policy = function_text(PIN_GATE_SRC, "const fn salt_policy() -> SaltPolicy {");
    assert!(policy.contains(
        "#[cfg(not(any(feature = \"e2e-test\", feature = \"otp-hardcoded-master-key\")))]\n    {\n        SaltPolicy::PerProvisioning\n    }"
    ));
    assert_eq!(policy.matches("SaltPolicy::FixedBench").count(), 1);
    // The bench constant is used nowhere but through that policy.
    assert_eq!(
        PIN_GATE_SRC.matches("BENCH_FIXED_SALT").count(),
        3,
        "BENCH_FIXED_SALT: its definition, the compile_error tag, and one use in salt_policy"
    );
}

#[test]
fn negative_provisioning_retires_an_existing_salt_without_erasing() {
    let body = code_only(function_text(PIN_GATE_SRC, "pub unsafe fn load_or_create_salt<R>("));
    let retire = body
        .find("ifmatches!(decision,ProvisionSalt::ReplaceRandom){")
        .expect("load_or_create_salt must handle ReplaceRandom");
    let in_place = body
        .find("pin_salt::destroy_in_place(&mutregion).map_err(|_|PinGateError::SaltStore)?;")
        .expect("a salt already on flash must be retired in place");
    let create = body.find("pin_salt::create(&mutregion,&salt)").expect("create present");
    assert!(retire < in_place && in_place < create);
    // Provisioning must never take the erase path: that would clear the
    // duress-mode flag and arm the wipe flag behind the wizard's back.
    assert!(!body.contains("pin_salt::destroy(&"));
    assert!(!body.contains("erase_admin_page"));
}

// ─────────────────────────────────────────────────────────────────────
// Wipe and the attempt counter
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_post_wipe_counter_reset_is_gated_on_the_salt() {
    // The gate itself: salt verified absent, through the FI sentinel, before
    // the reset.
    let gate = code_only(function_text(
        FLASH_SRC,
        "pub unsafe fn pin_attempts_reset_after_wipe() -> Result<(), ()> {",
    ));
    assert!(gate.contains(
        "letsalt_gone=crate::fi::check_true_into_sentinel(pin_salt_is_absent);ifsalt_gone!=crate::fi::OK_SENTINEL{returnErr(());}"
    ));
    assert!(gate.ends_with("unsafe{pin_attempts_erase()}}"));

    // The three product wipe paths use the gated reset ...
    let lockout = function_text(REQUEST_UNLOCK_SRC, "unsafe fn trigger_lockout_wipe() -> u32 {");
    assert!(lockout.contains("crate::hw::flash::pin_attempts_reset_after_wipe()"));
    assert_eq!(lockout.matches("pin_attempts_").count(), 1);

    let reconcile = function_text(NSC_MOD_SRC, "pub unsafe fn reconcile_pin_attempts<S>(se: &mut S)");
    assert!(reconcile.contains("crate::hw::flash::pin_attempts_reset_after_wipe()"));
    assert_eq!(code_only(reconcile).matches("pin_attempts_reset").count(), 1);

    let boot = MAIN_SRC
        .find("ui::show_status(\"WIPING\", \"resuming from interrupt\");")
        .expect("boot wipe-resume block present");
    let boot_block = &MAIN_SRC[boot..boot + 1400];
    assert!(boot_block.contains("hw::flash::pin_attempts_reset_after_wipe()"));
    assert_eq!(code_only(boot_block).matches("pin_attempts_reset").count(), 1);

    // ... the correct-PIN reset is used exactly once, in gated_unlock ...
    let unlock = function_text(NSC_MOD_SRC, "pub unsafe fn gated_unlock(");
    assert_eq!(
        code_only(unlock).matches("pin_attempts_reset_after_correct_pin()").count(),
        1
    );
    for (name, src) in [
        ("nsc/mod.rs", NSC_MOD_SRC),
        ("nsc/cmd_request_unlock.rs", REQUEST_UNLOCK_SRC),
        ("dual_se.rs", DUAL_SE_SRC),
        ("optiga/mod.rs", OPTIGA_SRC),
        ("se050/mod.rs", SE050_SRC),
        ("main.rs", MAIN_SRC),
    ] {
        let want = usize::from(name == "nsc/mod.rs");
        assert_eq!(
            code_only(src).matches("pin_attempts_reset_after_correct_pin()").count(),
            want,
            "{name}: the correct-PIN reset belongs to gated_unlock alone"
        );
        // ... and nothing names a bare reset any more: the function is gone.
        assert_eq!(
            code_only(src).matches("pin_attempts_reset()").count(),
            0,
            "{name}: a bare pin_attempts_reset() call is back"
        );
    }
    // The bench variant is not reachable from the gateway's product files.
    assert_eq!(code_only(NSC_MOD_SRC).matches("pin_attempts_reset_bench").count(), 0);
    assert_eq!(code_only(REQUEST_UNLOCK_SRC).matches("pin_attempts_reset_bench").count(), 0);

    // The dual-SE layer never resets the counter on a product path: its wipe
    // leaves that to the three callers above. (The semgrep rule
    // `post-wipe-counter-reset-is-gated` cannot be pointed at this file or at
    // main.rs, because bench code in both calls the bench reset; this pin is
    // their cover. Review 2026-10-13.) The one reset in dual_se.rs is the
    // bench one, inside the multi-unlock e2e cascade.
    let dual_wipe = function_text(
        DUAL_SE_SRC,
        "    fn factory_reset_admin(&mut self) -> Result<(), SeError> {",
    );
    assert_eq!(code_only(dual_wipe).matches("pin_attempts_").count(), 0);
    assert_eq!(code_only(DUAL_SE_SRC).matches("pin_attempts_reset").count(), 1);
    let bench_at = DUAL_SE_SRC
        .find("crate::hw::flash::pin_attempts_reset_bench()")
        .expect("the bench reset in the multi-unlock e2e cascade");
    let e2e_at = DUAL_SE_SRC
        .find("#[cfg(feature = \"dual-se-multi-unlock-e2e\")]")
        .expect("the multi-unlock e2e cascade");
    assert!(e2e_at < bench_at, "the bench reset moved out of the e2e-only cascade");

    // The helper the gate trusts really reads the salt log. (Second review
    // wave: with its body replaced by `true` every assertion above still
    // held, because only the CALL was pinned. These wrappers are not compiled
    // on the host, so their whole bodies are pinned.)
    assert_eq!(
        code_only(function_text(FLASH_SRC, "pub fn pin_salt_is_absent() -> bool {")),
        "pubfnpin_salt_is_absent()->bool{crate::pin_salt::is_absent(&unsafe{PinSaltRegion::new()})}"
    );
    assert_eq!(
        code_only(function_text(
            FLASH_SRC,
            "pub fn pin_salt_load() -> crate::pin_salt::SaltState {"
        )),
        "pubfnpin_salt_load()->crate::pin_salt::SaltState{crate::pin_salt::load(&unsafe{PinSaltRegion::new()})}"
    );

    // main.rs: the whole boot wipe region, from the first trigger to the
    // "WALLET WIPED" status, holds exactly one reset, the gated one ...
    let region_start = MAIN_SRC
        .find("let wipe_armed = hw::flash::is_wipe_armed();")
        .expect("boot wipe block present");
    let region_len = MAIN_SRC[region_start..]
        .find("ui::show_status(\"WALLET WIPED\", \"restore from seed\");")
        .expect("end of the boot wipe block");
    let region = code_only(&MAIN_SRC[region_start..region_start + region_len]);
    assert_eq!(region.matches("pin_attempts_reset").count(), 1);
    assert_eq!(region.matches("hw::flash::pin_attempts_reset_after_wipe()").count(), 1);
    // ... and the bench reset, which compiles into every image that is not
    // `mode-production`, has a counted set of call sites in this file (the
    // e2e and reset-tool flows). A new one, for instance in front of the boot
    // wipe block, has to be added here on purpose. (Second review wave.)
    assert_eq!(code_only(MAIN_SRC).matches("pin_attempts_reset_bench()").count(), 9);
    assert_eq!(code_only(MAIN_SRC).matches("pin_attempts_reset_after_wipe()").count(), 1);
}

#[test]
fn negative_a_wallet_that_cannot_be_opened_is_wiped_at_boot() {
    // Review: with the up-front refusal in gated_unlock, a provisioned
    // wallet with no salt would otherwise sit there for ever — refused,
    // never charged, never wiped. The boot wipe block has a third trigger.
    let boot = MAIN_SRC
        .find("let wipe_armed = hw::flash::is_wipe_armed();")
        .expect("boot wipe block present");
    let block = &MAIN_SRC[boot..boot + 2600];
    assert!(block.contains(
        "let unrecomputable = crate::fi::check_true_into_sentinel(|| {\n                !se.pin_credentials_recomputable()\n            }) == crate::fi::OK_SENTINEL;"
    ), "the trigger must be affirmed twice through the FI sentinel");
    assert!(block.contains("unrecomputable && se.is_provisioned()"));
    assert!(block.contains("if wipe_armed || attempts_exhausted || dead_wallet {"));

    // Which builds have this block at all. It is compiled for SE050 and
    // dual-SE hardware (the product is dual-SE) and NOT for an OPTIGA-only
    // bench build, which therefore has no boot recovery: there a wallet with
    // no salt is refused, uncharged, until a reset tool removes it. (Second
    // review wave: the pin above checked the text and not the configuration
    // around it.) This pins the condition so that narrowing it is a decision.
    let main_code = code_only(MAIN_SRC);
    let cfg = "#[cfg(all(feature=\"stm32u585\",any(feature=\"se050\",feature=\"dual-se\"),\
not(feature=\"se050-crash-safety-e2e\"),not(test),))]unsafe{usesecure_element::WalletStore;";
    assert_eq!(main_code.matches(cfg).count(), 1, "the boot wipe block's build condition changed");
    let cfg_at = main_code.find(cfg).expect("checked above");
    let trigger_at = main_code
        .find("letwipe_armed=hw::flash::is_wipe_armed();")
        .expect("boot wipe block present");
    assert!(cfg_at < trigger_at);
    assert!(
        !main_code[cfg_at + cfg.len()..trigger_at].contains("#[cfg("),
        "another condition now sits between the block's cfg and its triggers"
    );

    // And a wipe that failed on one chip stays resumable: the dual-SE layer
    // puts the flag back if any leg, or the salt destroy, failed.
    let wipe = code_only(function_text(
        DUAL_SE_SRC,
        "fn factory_reset_admin(&mut self) -> Result<(), SeError> {",
    ));
    assert!(wipe.contains(
        "ifsalt_gone.is_err()||optiga_result.is_err()||se050_result.is_err(){unsafe{if!crate::hw::flash::is_wipe_armed(){let_=crate::hw::flash::arm_wipe_flag();}}}"
    ));
}

#[test]
fn negative_decoy_is_provisioned_only_under_a_salt_minted_this_boot() {
    // Review (the class behind the HIGH finding): a derivation under the
    // salt on flash, for a PIN the caller chose, with no attempt charged,
    // is one free guess against a credential read out earlier. The decoy
    // entry point refuses unless a salt was minted in this boot.
    let body = code_only(function_text(PIN_GATE_SRC, "pub fn decoy_provisioning_credentials("));
    let check = body
        .find("if!pin_salt::decoy_provisioning_allowed(salt_policy(),minted){returnErr(PinGateError::NoSalt);}")
        .expect("the decoy entry point must check the minted-this-boot flag");
    let derive = body.find("credentials(WalletRole::Duress,&salt,duress_pin)").expect("derive");
    assert!(check < derive);
    // Set only where a record is actually created; cleared on destroy.
    assert_eq!(PIN_GATE_SRC.matches("SALT_MINTED_THIS_BOOT.store(true,").count(), 1);
    let create = code_only(function_text(PIN_GATE_SRC, "pub unsafe fn load_or_create_salt<R>("));
    assert!(create.contains(
        "pin_salt::create(&mutregion,&salt).map_err(|_|PinGateError::SaltStore)?;SALT_MINTED_THIS_BOOT.store(true,"
    ));
    let destroy = code_only(function_text(PIN_GATE_SRC, "pub unsafe fn destroy_salt() -> Result<(), ()> {"));
    assert!(destroy.starts_with(
        "pubunsafefndestroy_salt()->Result<(),()>{SALT_MINTED_THIS_BOOT.store(false,"
    ));
    // The three decoy provisioning sites use it, and nothing else derives
    // the duress role for provisioning.
    for (name, src) in [("dual_se.rs", DUAL_SE_SRC), ("optiga/mod.rs", OPTIGA_SRC), ("se050/mod.rs", SE050_SRC)] {
        assert_eq!(
            src.matches("crate::pin_gate::decoy_provisioning_credentials(duress_pin)").count(),
            1,
            "{name}"
        );
    }
}

#[test]
fn negative_salt_bytes_come_from_the_reviewed_generators_only() {
    // The salt reaches a KDF, so where its bytes come from is policed by
    // `scripts/rng_consumer_audit.py` as well. This pins the same facts next
    // to the rest of the wiring.
    //
    // Product store: the strict three-source generator, nothing else.
    let draw = code_only(function_text(DUAL_SE_SRC, "    fn draw_pin_salt("));
    assert!(
        draw.ends_with("{crate::rng_strong::fill_with_store(&mutout[..],self)}"),
        "the dual-SE salt must be a three-source draw, got: {draw}"
    );
    assert_eq!(
        DUAL_SE_SRC.matches("crate::pin_gate::load_or_create_salt(|bytes| self.draw_pin_salt(bytes))").count(),
        1
    );
    assert_eq!(DUAL_SE_SRC.matches("load_or_create_salt(").count(), 1);

    // Single-chip store (bench-only): the platform TRNG, and a shipping
    // build refuses before reaching it. "Shipping" is `mint_policy()`, the
    // predicate `negative_production_refuses_to_derive_below_rdp2` pins, so
    // this refusal and the RDP-2 mint rule cannot drift apart.
    let single = code_only(function_text(PIN_GATE_SRC, "fn single_chip_salt_draw("));
    assert!(
        single.ends_with(
            "->Result<(),()>{ifmatches!(mint_policy(),MintPolicy::RequireRdp2){returnErr(());}crate::rng::fill(out)}"
        ),
        "the single-chip salt source changed: {single}"
    );
    // That is the only platform-RNG call in the gate, and the only user of
    // the helper is the single-chip provisioning entry point.
    assert_eq!(code_only(PIN_GATE_SRC).matches("rng::").count(), 1);
    assert_eq!(code_only(PIN_GATE_SRC).matches("single_chip_salt_draw").count(), 2);
    let entry = code_only(function_text(PIN_GATE_SRC, "pub unsafe fn provisioning_credentials("));
    assert!(entry.contains("letsalt=unsafe{load_or_create_salt(single_chip_salt_draw)}?;"));
    // No backend passes its own generator in.
    for (name, src) in [("optiga/mod.rs", OPTIGA_SRC), ("se050/mod.rs", SE050_SRC)] {
        assert!(!src.contains("load_or_create_salt("), "{name}");
        assert!(!code_only(src).contains("|b|crate::rng::fill(b)"), "{name}");
    }
}

#[test]
fn negative_every_wipe_opens_by_destroying_the_salt() {
    // Each of the three backends destroys the salt before its first chip
    // step. (The pure lifecycle is tested in `pin_salt`; this pins the call.)
    for (name, src, sig, salt_step, chip_steps) in [
        (
            "dual_se",
            DUAL_SE_SRC,
            "    fn factory_reset_admin(&mut self) -> Result<(), SeError> {",
            "crate::pin_gate::begin_wipe()",
            &["self.reset_optiga_for_admin()", "self.se050.factory_reset_admin()"][..],
        ),
        (
            "se050",
            SE050_SRC,
            "    fn factory_reset_admin(&mut self) -> Result<(), SeError> {",
            "crate::pin_gate::begin_wipe()",
            &[
                "crate::hw::secret_keys::se050_admin_pin()",
                "self.iterative_wipe(",
                "self.admin_factory_reset(",
            ][..],
        ),
        (
            "optiga",
            OPTIGA_SRC,
            "    fn factory_reset_admin(&mut self) -> Result<(), SeError> {",
            "crate::pin_gate::destroy_salt()",
            &["self.factory_reset()"][..],
        ),
    ] {
        let body = function_text(src, sig);
        let salt_at = body
            .find(salt_step)
            .unwrap_or_else(|| panic!("{name}: factory_reset_admin must call {salt_step}"));
        for step in chip_steps {
            let at = body
                .find(step)
                .unwrap_or_else(|| panic!("{name}: `{step}` not found"));
            assert!(salt_at < at, "{name}: `{step}` runs before the salt is destroyed");
        }
        // A surviving salt makes the wipe report failure.
        assert!(
            body.contains("salt_gone.map_err("),
            "{name}: a surviving salt must be reported"
        );
    }

    // `begin_wipe` arms the flag first, then destroys.
    let begin = code_only(function_text(PIN_GATE_SRC, "pub unsafe fn begin_wipe() -> Result<(), ()> {"));
    let arm = begin.find("crate::hw::flash::arm_wipe_flag()").expect("arms the flag");
    let destroy = begin.find("unsafe{destroy_salt()}").expect("destroys the salt");
    assert!(arm < destroy);
}

#[test]
fn negative_gated_unlock_refuses_an_unrecomputable_wallet_before_charging() {
    let body = function_text(NSC_MOD_SRC, "pub unsafe fn gated_unlock(");
    let refuse = body
        .find("if !se.pin_credentials_recomputable() {\n        return Err(UnlockError::InternalError);\n    }")
        .expect("gated_unlock must refuse when credentials cannot be recomputed");
    let charge = body
        .find("crate::hw::flash::pin_attempts_bump()")
        .expect("the pre-commit bump is present");
    let duress = body.find("se.unlock_duress(pin)").expect("duress dispatch present");
    let unlock = body.find("se.unlock(pin)").expect("unlock call present");
    assert!(refuse < charge, "the refusal must come before the attempt is charged");
    assert!(refuse < duress && refuse < unlock, "and before anything reaches a chip");
}

// ─────────────────────────────────────────────────────────────────────
// Flash layout
// ─────────────────────────────────────────────────────────────────────

#[test]
fn negative_salt_log_sits_after_the_flag_quadwords_and_only_zeros_are_overwritten() {
    assert!(FLASH_SRC.contains("const WIPE_FLAG_OFFSET: u32 = 16;"));
    assert!(FLASH_SRC.contains("const DURESS_WIPE_MODE_OFFSET: u32 = 32;"));
    assert!(FLASH_SRC.contains("const PIN_SALT_FIRST_QW: u32 = 16;"));
    assert!(FLASH_SRC.contains(
        "const _: () = assert!(DURESS_WIPE_MODE_OFFSET + 16 <= PIN_SALT_FIRST_QW * 16);"
    ));

    // The one deliberate program over a non-erased quad-word writes zeros
    // and nothing else (RM0456 Rev 7 section 7.3.7).
    let zero = code_only(function_text(
        FLASH_SRC,
        "    fn zero_qw(&mut self, index: usize) -> Result<(), ()> {",
    ));
    assert!(zero.ends_with("unsafe{write_quadword_verified(Self::addr(index),&[0u8;16])}}"));

    // The erase fallback puts the wipe flag straight back.
    let erase = code_only(function_text(
        FLASH_SRC,
        "    fn erase_region(&mut self) -> Result<(), ()> {",
    ));
    assert!(erase.ends_with("unsafe{erase_admin_page()?;arm_wipe_flag()}}"));
}
