RE-CHECK OF DEFECT CLAIMS at c75b0d9c (feat/pq1-board-target). Read and grep only; nothing built, flashed, run, modified, filed or committed. A copy of this report is at /tmp/claude-1000/-home-nicola-repos-PQSigner-OS/7844318a-f4f1-49a2-b794-31ae48f548cc/scratchpad/recheck-report.md.

Ground facts used throughout
- Ship set (Makefile:2662 RELEASE_FEATURES, :2718 PROD_SHIP_FEATURES, identical): stm32u585, se050, optiga-trust-m, dual-se, ui-lcd, usb, iwdg, saes-dhuk, se050-derived-scp03, mode-production, optiga-lock-operational, optiga-hw-counter, consumption-mask, tamp, tamp-wipe, tzic-wipe, bhk, rdp2-self-lock, board. Not in it: duress-pin, ui-px, debug-log, e2e-test, e2e-skip-admin-wipe.
- Every code and doc file cited below is unmodified in the working tree, so working-tree lines equal c75b0d9c. The one exception is secure/src/secure_element.rs (modified); it matters only for D9 and was read with `git show c75b0d9c:`.
- Verdict rule applied uniformly: only an error in mechanism or impact downgrades a verdict. Line drift and wrong cites go in the "imprecise" bullet.

ROW A4: PARTLY  (a = PARTLY, b = CONFIRMED, c = CONFIRMED)

A4(a): PARTLY
- Corrected citations: secure/src/optiga/mod.rs:2795-2801 (E120 reset compiled out under optiga-lock-operational), :1668 (the reset function itself is compiled out), :1429-1435 (re-provisioning skips E120 when its metadata is already correct), :3243-3274; secure/src/dual_se.rs:113-136; secure/src/nsc/mod.rs:1661-1716 (comparison at :1692); call site secure/src/main.rs:1801.
- Decisive code:
  `#[cfg(all(feature = "optiga-hw-counter", not(feature = "optiga-lock-operational")))]` (optiga/mod.rs:2801)
  `let mcu_vs_se = se_count > mcu;` (nsc/mod.rs:1692)
- Wrong or imprecise: the literal statement holds as built (E120 keeps its count, page 124 is reset to 0, so each boot shows "TAMPER DETECT" and wipes). But (a) is not an independent recovery blocker. The reconcile runs before the wizard (main.rs:1801 vs the wizard at ~4000), re-wipes an already blank device, and then falls through to the wizard. E120 is reset by any successful F1D0 authentication (optiga/mod.rs:2650), including the wizard's auto-unlock (main.rs:4108). That reset is unreachable today only because (c) kills the wizard first. So (a) is a consequence of (c), and would heal on the first good unlock if (c) were fixed.
- Strongest doubt: it needs the OPTIGA shield up at reconcile and a readable E120; neither was observed, and no part has been run in the locked profile.

A4(b): CONFIRMED
- Corrected citations: secure/src/se050/mod.rs:2286-2288 (USERID_OBJ is best-effort only), :1993-2001 (guard), :2023-2025 (UserID written with no admin entry); secure/src/se050/apdu.rs:498-522 (policy builder); secure/src/crypto.rs:471-496 (rollback and panic).
- Decisive code:
  `if userid_exists && admin_pin.is_some() {` (se050/mod.rs:1993)
  `return Err(Se050Error::Status(0x6986));` (se050/mod.rs:2000)
  `panic!("provisioning failed — rolled back for wizard restart");` (crypto.rs:496)
- Wrong or imprecise: (1) it is not specific to the locked profile. The guard is on every stm32u585 build without e2e-skip-admin-wipe (se050/mod.rs:2906), bench builds included. (2) On the ship profile it is never reached: OPTIGA provisions first (dual_se.rs:201-202, then :209-210) and fails on (c). (3) The 0x6986 is synthesised by firmware, not returned by the chip. (4) It is a recorded, deliberate S-6 trade-off: docs/security/threat-model.md:146-148 says the chip is "single-use" after lockout and needs an OID range bump. That remedy does not exist per device: USERID_OBJ is a `pub const` (se050/mod.rs:53), so a bump is a firmware change for every unit (my reasoning, not something the docs state). Meanwhile the wipe screen says "restore from seed" (cmd_request_unlock.rs:209).
- Strongest doubt: survival of a locked USERID_OBJ against the unauthenticated sweep rests on SE05x policy semantics as coded, not on a post-S-6 silicon run.

A4(c): CONFIRMED
- Corrected citations: secure/src/optiga/apdu.rs:1373-1374 (Change = Auto(F1D0)); secure/src/optiga/mod.rs:1040-1043 (LcsO lock under optiga-lock-operational), :1123-1131 (first write in provision_auth_ref), :2839-2840 (wipe leaves F1D0 untouched), :2162-2165 (call site).
- Decisive code:
  `if change_is_auto {` / `push_ac_auto(&mut inner, &mut c, META_CHANGE, OID_AUTH_REF);` (apdu.rs:1373-1374)
  `apdu::OID_AUTH_REF, pin_secret,` (mod.rs:1127)
- Wrong or imprecise: "fails at its first APDU" is wrong about position. The failing write is the first APDU of step 2 (provision_auth_ref). Before it come the E140 PBS write and metadata (mod.rs:2111), a chip reset, the shield handshake (:2132) and the E120 metadata read (:2143-2146). Also: OID_AUTH_REF is a `pub const` (apdu.rs:198), so the comment at mod.rs:2797-2800 ("re-provisioning bumps to a fresh range") describes a mechanism that does not exist. The block applies even when the user still knows the PIN (forced wipe), because provisioning never authenticates first.
- Strongest doubt: no part has been taken to LcsO=Operational with Auto(F1D0), so the chip's refusal is inferred from the metadata, not observed; S-1 is an open ship blocker.

ROW A5: CONFIRMED  (all six sub-claims CONFIRMED)
- Corrected citations: secure/src/nsc/cmd_request_unlock.rs:196, :204, :209; secure/src/main.rs:1946-1952; secure/src/nsc/mod.rs:1713-1715; secure/src/crypto.rs:495; secure/src/se050/mod.rs:3192-3205, :2293-2295, :2398, :2416, :2434, :2444, :678-686, :3222-3224, :2328-2379; secure/src/se050/apdu.rs:474, :477; secure/src/dual_se.rs:631-640.
- Decisive code:
  `let _ = se.factory_reset_admin();` (cmd_request_unlock.rs:196)
  `if apdu::check_exists(&mut self.t1, &mut self.scp03, *obj_id).unwrap_or(false) {` (se050/mod.rs:2416)
  `if !self.admin_exists() {` / `let _ = crate::hw::flash::erase_admin_page();` (se050/mod.rs:3222-3223)
- Sub-verdicts:
  1. Discarded verdict at call sites: CONFIRMED for every ship-reachable site (cmd_request_unlock.rs:196, main.rs:1946, nsc/mod.rs:1713, crypto.rs:495). The intrusion wipe (hw/tzic.rs:246) only arms the flag and reuses main.rs:1946. Sites that do consume the result are all outside the ship set: factory_provisioning.rs:440, main.rs:3008/3565/3706, dual_se.rs:756/857 (e2e and factory features in PROD_FORBIDDEN).
  2. Ok(()) on admin-PIN derivation failure: CONFIRMED, se050/mod.rs:3192-3204 (`self.zeroize_caches(); return Ok(());` after an unauthenticated sweep).
  3. Existence checks coerce a transport error to "gone": CONFIRMED and worse than stated. `Se050::init()` returns Ok from cache when the session is already up (se050/mod.rs:225-229). If the bus dies after that, :2293-2295 reads "no admin", the unauthenticated sweep and `reinit()` results are discarded (:2398), every post-check reads "gone", and `admin_factory_reset` returns Ok(()) having deleted nothing. Consuming the result at the call sites would therefore not fix A5 alone.
  4. admin_exists() clears the page-125 resume flag: CONFIRMED (se050/mod.rs:678-686, :3222-3224). The erase runs before the `wipe_result` error check at :3226, and in dual-SE it also discards the flag the OPTIGA leg armed, whatever the OPTIGA result (dual_se.rs:632-638).
  5. Admin object self-delete when data deletes failed: CONFIRMED (se050/mod.rs:2328-2343 only logs delete errors; :2368-2379 self-deletes unconditionally). In ship builds the logging compiles out.
  6. Unconditional page-124 reset: CONFIRMED at three sites (cmd_request_unlock.rs:204, main.rs:1951, nsc/mod.rs:1714).
- Wrong or imprecise: claim cites :2443 (actual :2444) and :3193 (actual :3192); "every call site" should read "every ship-reachable call site".
- Strongest doubt: on the ship profile a lost resume flag after a real 10-wrong lockout is partly covered by the next-boot E120 > page-124 reconcile, so practical exposure is narrower than the code defects suggest.

ROW A10: CONFIRMED
- Corrected citations: secure/src/optiga/mod.rs:70, :916-918 (derivation), ship call sites :2144, :2164, :2502, :2561; domain/src/lib.rs:97-103; secure/src/se050/mod.rs:2023-2025 (UserID written with the raw PIN), :2776-2777 (verify with the raw PIN), :2938-2943; secure/src/se050/apdu.rs:794-816; secure/src/dual_se.rs:370, :455.
- Decisive code:
  `crate::crypto::kdf(PIN_AUTH_DOMAIN, pin, 0)` (optiga/mod.rs:917; kdf is one SHA-256 over domain, input, index)
  `USERID_OBJ, pin, max_attempts, None,` (se050/mod.rs:2024)
  `let mut full_entropy = xor_32(&half_o, &half_e);` (dual_se.rs:455)
- Wrong or imprecise: the cite optiga/mod.rs:1939-1943 is inside `probe_hmac_auth_luc_at`, which is gated to duress-probe-e2e and not in the ship set; the ship sites are listed above. No PIN-labelled derivation exists in secure/src/hw/secret_keys.rs, and saes-dhuk/bhk do not touch the PIN path.
- Strongest doubt: "storage extraction yields the PIN" assumes the SE050 applet stores the UserID value in a recoverable form; that is not knowable from this repo.

ROW A14: CONFIRMED (by source read only)
- Corrected citations: secure/src/nsc/cmd_request_unlock.rs:35; secure/src/hw/iwdg.rs:126, :137, :276-286, :287-303, :305-322; secure/src/main.rs:4309-4315, :4490-4628, :4257; secure/src/ui/pin_entry.rs:102-103; guard sites secure/src/ui/confirm.rs:194, secure/src/ui/px/lcd.rs:750, secure/src/ui/px/confirm_px.rs:153.
- Decisive code:
  `} else if handler_busy {` ... `if b < MAX_BUSY_TICKS {` (iwdg.rs:287, :296)
  `if s < NS_STALL_LIMIT_TICKS {` (iwdg.rs:310)
  `let event = match input().wait_button(&mut idle) {` (pin_entry.rs:103, no guard)
- Wrong or imprecise: there is a third guard site, px/confirm_px.rs:153 (ui-px, not ship). Both budgets omit the 1 to 3 s hardware timeout that follows (about 32 s and about 6 s in total). "A reset during entry consumes no attempt" is true for entry but not if the reset lands during the SE verify, after the page-124 pre-commit (nsc/mod.rs:1473). The boot-arm prompt is not affected: iwdg::init() is at main.rs:4257, after the boot unlock loop, and the FSBL has no IWDG code.
- Strongest doubt: never built or run with iwdg on; shared/src/lockdown.rs does not pin the IWDG_SW option bit, so hardware-watchdog behaviour at boot is unchecked.

ROW A15: CONFIRMED
- Corrected citations: secure/src/main.rs:4198-4207 (boot arm), :4208-4211 ("Wrong PIN" / "try again"), :4587-4598 (PendSV arm), :1934-1952 (next-boot wipe when page 124 is at MAX); secure/src/nsc/cmd_request_unlock.rs:146-151, :159-164, :190-211.
- Decisive code:
  `ui::show_status("PIN locked", "power cycle");` (main.rs:4204, :4595)
  `secure_log!("[S] PIN locked out (no wipe performed on this path)");` (main.rs:4205)
  `break;`
- Wrong or imprecise: the difference is deliberate and commented (#715). For the ten-wrong case page 124 at MAX is itself the durable trigger: the next boot wipes (main.rs:1935-1946), so no page-125 flag is needed there. The USB arm also wipes on the tenth wrong PIN through `remaining_after == 0` (:146-151), not only on PinLocked.
- Strongest doubt: for an SE-originated lockout with page 124 below 10 there is no boot-time trigger at all, but OPTIGA errors take precedence (dual_se.rs:384-391), so that state needs OPTIGA to accept while SE050 is blocked.

ROW A30: CONFIRMED
- Corrected citations: nonsecure/src/usb/commands.rs:286-287, :497-507; shared/src/apdu_framing.rs:108-116 (routing checks CLA only); secure/src/nsc/cmd_request_unlock.rs:29-31, :51-52, :54-66.
- Decisive code:
  `INS_V2_UNLOCK => return self.cmd_unlock(),` (commands.rs:286)
  `if state::peek_state(|s| s.pin_verified.is_true_fi()) {` (cmd_request_unlock.rs:29)
  `let mut pin = match enter_pin() {` (cmd_request_unlock.rs:54)
- Wrong or imprecise: nothing found. The sign-rate limiter (nsc/state.rs:384, :532) covers signing only. Context: the device already paints the PIN prompt by itself at every boot and after every idle lock, so the added exposure is small. With iwdg in the ship set an ignored prompt ends in a watchdog reset at about 32 s (A14).
- Strongest doubt: not traced whether other commands can raise a prompt while locked.

ROW A31: CONFIRMED
- Corrected citations: secure/src/ui/pin_entry.rs:73-88 (discard at :83); secure/src/rng_strong.rs:206-213 and its Err arms (buffer zeroised before returning Err).
- Decisive code:
  `let _ = crate::rng_strong::fill(&mut rand_bytes);` (pin_entry.rs:83)
  `pin[i] = rand_bytes[i] % 10;` (pin_entry.rs:85)
- Wrong or imprecise: it is a documented, deliberate fallback (comment at :73-78), not an oversight. In dual-SE both SE contributions are mandatory, so failing either I2C bus is enough to force it.
- Strongest doubt: none on the code; the exploit still needs a press-counting observer.

ROW A33: CONFIRMED
- Corrected citations: secure/src/nsc/mod.rs:1429-1437; secure/src/nsc/cmd_request_unlock.rs:118-124, :159-164; secure/src/hw/flash.rs:824-833; secure/src/main.rs:1935-1951.
- Decisive code:
  `if pre_count_a != pre_count_b {` ... `return Err(UnlockError::PinLocked);` (nsc/mod.rs:1432, :1437)
  `return PIN_ATTEMPTS_CAPACITY as u8;` (flash.rs:831)
- Wrong or imprecise: understated. `pin_attempts_read` already returns 32 when its own forward and reverse scans disagree, so one faulted scan reaches PinLocked without a disagreeing pair. There is a second direct path (cmd_request_unlock.rs:122-124). And it is not only the USB arm: the boot check `pin_attempts_read() >= MAX_ATTEMPTS` (main.rs:1935-1936) is a single call that also wipes on one faulted read.
- Strongest doubt: whether a transient read fault on internal flash is realistic outside deliberate fault injection.

ROW B3: PARTLY  (1 = CONFIRMED, 2 = CONFIRMED, 3 = PARTLY)
- Gating feature: `duress-pin` (secure/Cargo.toml:425, = ["dual-se", "optiga-hw-counter"]). Not in the ship set. Not in PROD_FORBIDDEN either. The only make target that enables it is duress-provision-e2e, which is forbidden. The page-123 code itself is not gated; the leak only exists once duress-pin adds a second wallet.
- Corrected citations: secure/src/offchain_state.rs:23-33; secure/src/nsc/cmd_offchain_status.rs:36, :75-79; secure/src/se050/mod.rs:2266-2276, :2286-2288, :2118-2150, :2162-2167; secure/src/nsc/mod.rs:1513-1548 (swallow at :1546); secure/src/nsc/cmd_request_unlock.rs:196, :204.
- Decisive code:
  `h.update([account_index]);` / `h.update(chain_id.to_be_bytes());` / `h.update(slot_index.to_be_bytes());` (offchain_state.rs:26-28)
  `let _ = se.factory_reset_admin();` (nsc/mod.rs:1546)
- Sub-verdicts:
  1. Page-123 counters have no wallet discriminator: CONFIRMED. No "duress" or "decoy" token appears in offchain_state.rs, cmd_offchain_status.rs or nsc/state.rs.
  2. SE050 duress objects absent from the wipe lists: CONFIRMED. The four DURESS_* IDs appear only in provisioning and unlock code, never in a delete list or post-check. Three comments claim the opposite (se050/mod.rs:68-70, :2099-2101; optiga/mod.rs:2850-2851). Impact is limited because a decoy is always provisioned, so the objects' presence does not show that duress was configured.
  3. Wipe-on-duress swallows the error and does not reset page 124: PARTLY. The swallow is real. But on the USB arm the returned PinLocked runs `trigger_lockout_wipe`, which wipes again and does reset page 124 (cmd_request_unlock.rs:196, :204). Only the boot and PendSV arms leave it charged, and the comment at nsc/mod.rs:1521-1522 says that is intended.
- Strongest doubt: whether decoy signing also writes the real wallet's counters was not traced (same key, so likely).

ROW D9: PARTLY
- Corrected citations: Makefile:3401-3411 (text :3402-3407, features :3411); secure/src/main.rs:3421-3429, :3481, :3597-3599; secure/src/se050/mod.rs:1993-2000; secure/src/main.rs:412-422; commits 0969901c (2026-04-22), 3fe56460 (2026-05-28); docs/security/threat-model.md:571.
- Decisive code:
  `--features pin-gate-wipe-e2e,stm32u585,ui-lcd,debug-log,e2e-test,otp-hardcoded-master-key,$(BOARD_FEATURE)` (Makefile:3411)
  `// in the tree. \`mod secure_lockout_wipe_fi_pure_tests;\` was removed in e537e7cf` (main.rs:414)
- Wrong or imprecise:
  First half is worse than claimed. The feature set is as stated (non-locked, otp-hardcoded-master-key), and the Makefile text does disclose "Does NOT bump any OID to LcsO=Operational". But by source the test cannot pass its recovery step on any current build: its post-wipe `se.provision` (main.rs:3597) hits the USERID guard, which is active on exactly this feature set. Its only recorded pass is the 2026-04-22 commit, and the "Passing" row in threat-model.md:571 is dated 2026-05-12; both predate the 2026-05-28 S-6 change that made USERID_OBJ undeletable by admin. The test's own comments (main.rs:3421, :3427) still describe the pre-S-6 behaviour. I found no later receipt. This also resolves the "unreconciled" note in row A4: that test resets E120 and has F1D0 Change=ALW because it is a non-locked build, and its recovery receipt predates (b).
  Second half has the right outcome and the wrong reason. `WipeFault` has 0 hits in secure_element.rs at c75b0d9c and 6 in the uncommitted working tree; the test file is untracked. The suite does not run because its `mod` line was removed in e537e7cf, which main.rs:412-422 already states in the tree. It was a crate-root `#[cfg(test)]` module, not code inside `cfg(not(test))` modules; if wired it would exercise a mock-based model plus source-text pins, never the production wipe code.
- Strongest doubt: I did not run the e2e, so "cannot pass" is a source-read inference.

ROW E1: CONFIRMED
- Corrected citations: docs/security/threat-model.md:115-116 (Claim 1), :131-132, :224-225 (single-chip rows), :226 (quoted sentence), :252, :600.
- Decisive text:
  "So even decapping both chips, the attacker still needs to *use* the chip with its silicon-enforced PIN gate." (:226)
  "Offline brute force against persisted PIN material is structurally impossible because the PIN never leaves SE silicon." (:131-132)
- Wrong or imprecise: the single-chip rows are :224-225, not :222-223. The claim's :121 is inside Claim 2 (DHUK/BHK leak), not Claim 1. Lines :131-132 and :252 are the statements A10 contradicts most directly and are missing from the claim. No "dictionary", "unsalted" or "#124" wording exists anywhere in the file, so the residual is not scoped there.
- Strongest doubt: inherits A10's assumption about SE050 internal storage.

ROW E6: PARTLY
- Corrected citations: docs/security/HARDENING.md:1-5 (title and purpose), :32, :176, :178-187; CLAUDE.md:48 ("SE attest"); docs/security/threat-model.md:505-506.
- Decisive text:
  "# Hardware Wallet Hardening Requirements" (HARDENING.md:1)
  "3. Verify the signature chains to NXP's root certificate, hardcoded in the Secure image." (HARDENING.md:184)
  "### 9.4 Boot-time SE attestation is not yet landed" (threat-model.md:505)
- Wrong or imprecise: the code absence is right. A case-insensitive search for "attest" across secure/src/{se050,optiga,first_boot,hw}, dual_se.rs and main.rs finds only two comments (factory_provisioning.rs:304, main.rs:1598); searches for certificate, UID and ECDSA equivalents find nothing either. But HARDENING.md is a requirements document written in the imperative, so "present tense" overstates it as a status claim. The parts that do read as fact are the residency table row at :32 and CLAUDE.md:48.
- Strongest doubt: none on the code; the disagreement is about how to read a requirements document.

ROW E7: CONFIRMED
- Corrected citations: docs/security/HARDENING.md:30-31, :158-163, :258-270; code: secure/src/se050/apdu.rs:551-577 (UserID object), secure/src/se050/mod.rs:2023-2025, secure/src/nsc/cmd_request_unlock.rs:1-3, :54.
- Decisive text:
  "- Type: **AESKey** (not UserID — UserID is plaintext on the I²C bus)." (:160)
  "1. NS UI collects PIN digits, passes a byte buffer into a Secure NSC entry point." (:262)
- Wrong or imprecise: nothing substantive. The only PBKDF2 in secure/, domain/ and shared/ is the BIP-39 seed derivation (domain/src/lib.rs:310); there is no AESKey object, no PIN stretching and no device salt. Rows :30-31 of the residency table repeat the same non-existent design and are not cited. Same framing caveat as E6: the document is titled as requirements.
- Strongest doubt: none.

ROW E10: PARTLY
- Corrected citations: CLAUDE.md:23 (invariant #2); secure/src/nsc/mod.rs:1361-1363, :1646-1647; secure/src/se050/mod.rs:2857-2862; secure/src/nsc/cmd_request_unlock.rs:180; violating callers secure/src/main.rs:4198-4207, :4587-4598.
- Decisive code:
  `/// max-10 lockout, and maps \`AuthMethodBlocked\` to the wipe path. Making its` (nsc/mod.rs:1647)
  `///      \`PinLocked\`. Caller is responsible for running` / `///      \`trigger_lockout_wipe\` on that signal.` (nsc/mod.rs:1362-1363)
- Wrong or imprecise: of the two cited comments, se050/mod.rs:2860 scopes itself to the gateway ("gateway fires trigger_lockout_wipe") and is accurate as written; only its cross-reference "cmd_request_unlock.rs:117-122" is stale (the arm is at :159-164). nsc/mod.rs:1362 does not mention AuthMethodBlocked; it states a caller contract that two of three callers do not follow, which is drift of a different kind. The comment that matches the claim's wording is nsc/mod.rs:1646-1647. Neither CLAUDE.md nor the comments say "unconditionally".
- Strongest doubt: none on the code.

SUMMARY
Fully confirmed: 9 rows (A5, A10, A14, A15, A30, A31, A33, E1, E7). A5 counts as confirmed because all six sub-claims hold.
Partly: 5 rows (A4 because of (a); B3 because of sub-claim 3; D9; E6; E10). Refuted: 0.
Trust least: A4. Its three mechanisms are all source inferences about a locked OPTIGA/SE050 state that no bench part has been put in, and the only silicon test that speaks to recovery predates the change that causes (b).