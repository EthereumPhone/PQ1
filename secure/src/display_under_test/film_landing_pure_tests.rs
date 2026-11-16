//! #773 — every sign route that STARTS the loading film must also guarantee
//! it LANDS.
//!
//! `lcd::film_tick` is the signer's `fn(u8)` progress hook, so the film only
//! advances while the signing chain calls it. An error return between
//! `film_start()` and `film_resolve(Signed)` therefore stopped calling it and
//! left the last painted orbit frame on the glass forever — a signing
//! FAILURE, the one event the user most needs to see, rendered identically to
//! "still working".
//!
//! The fix is `lcd::FilmLanding`, a `Drop` guard: armed next to
//! `film_start()`, disarmed at the success landing, and on every other exit
//! from the scope it lands the film on `Ending::Failed`. That is structural
//! rather than per-site precisely because there were 25 error returns across
//! the three windows and a future `return` would silently undo an enumerated
//! fix.
//!
//! WHY THIS TEST IS A SOURCE SCAN. The guard lives in `ui/px/lcd.rs`, which
//! is `#[cfg(feature = "ui-lcd")]` — it compiles only in a hardware build, so
//! no host test can execute its `Drop`. What a host test CAN do is hold the
//! pairing: a route that starts a film and never arms the guard is the defect
//! coming back, and that is visible in the source. Same pattern as the
//! `meta.chain_id == chain_id` binding in `safe_display_render_pure_tests`.

const HANDLERS: [(&str, &str); 3] = [
    ("cmd_sign_userop.rs", include_str!("../nsc/cmd_sign_userop.rs")),
    ("cmd_sign_offchain.rs", include_str!("../nsc/cmd_sign_offchain.rs")),
    ("cmd_sign_userop_batch.rs", include_str!("../nsc/cmd_sign_userop_batch.rs")),
];

const LCD: &str = include_str!("../ui/px/lcd.rs");

/// Every `film_start()` is paired with an armed guard, and every success
/// landing disarms it first.
#[test]
fn every_film_start_arms_a_landing_guard() {
    for (name, src) in HANDLERS {
        let starts = src.matches("lcd::film_start()").count();
        assert!(starts > 0, "{name}: expected at least one film_start()");

        let armed = src.matches("FilmLanding::armed()").count();
        assert_eq!(
            armed, starts,
            "{name}: {starts} film_start() call(s) but {armed} FilmLanding::armed() — a route \
             that starts the film without arming the guard freezes on a signing failure (#773)"
        );

        let landings = src.matches("film_resolve(pqsigner_ui_px::scene::Ending::Signed)").count();
        let disarms = src.matches("g.disarm()").count();
        assert_eq!(
            disarms, landings,
            "{name}: {landings} success landing(s) but {disarms} disarm(s) — the guard would \
             land a SECOND ending on top of the signed one"
        );
    }
}

/// The guard must be declared before the `film_start()` it protects, or the
/// early returns between them are still unguarded.
#[test]
fn the_guard_is_declared_before_the_film_starts() {
    for (name, src) in HANDLERS {
        let decl = src
            .find("let mut film_landing: Option<crate::ui::px::lcd::FilmLanding> = None;")
            .unwrap_or_else(|| panic!("{name}: no film_landing declaration"));
        let start = src.find("lcd::film_start()").unwrap();
        assert!(
            decl < start,
            "{name}: the landing guard is declared AFTER film_start(), so the returns between \
             them are unguarded"
        );
    }
}

/// ANTI-VACUITY. The scan above passes trivially if the strings it looks for
/// are not the ones that carry the behaviour, so pin the guard itself: it
/// must land on `Failed` from `Drop`, and `disarm` must actually clear the
/// flag. A guard whose `Drop` did nothing would satisfy every count above.
#[test]
fn the_guard_lands_on_failed_from_drop() {
    let drop_impl = LCD
        .find("impl Drop for FilmLanding")
        .expect("FilmLanding has no Drop impl — the guard cannot fire on an early return");
    let body = &LCD[drop_impl..drop_impl + 400];
    assert!(
        body.contains("film_resolve(Ending::Failed)"),
        "FilmLanding::drop must land the film on Ending::Failed, not abort or no-op:\n{body}"
    );
    assert!(
        body.contains("if self.armed"),
        "FilmLanding::drop must respect disarm(), or the success path lands twice"
    );
    assert!(
        LCD.contains("pub fn disarm(&mut self) {\n        self.armed = false;\n    }"),
        "disarm() must clear the flag"
    );
}

/// The failure ending needs a caption of its own on every family, or the
/// screen says nothing about what happened. `Family::failed` is the field
/// that carries it; every construction site must set it, and it must differ
/// from the decline (a failure is not a refusal by the user).
#[test]
fn every_family_carries_a_distinct_failed_caption() {
    const FAMILIES: [(&str, &str); 9] = [
        ("userop_screens.rs", include_str!("../tx/display/userop_screens.rs")),
        ("erc20_screens.rs", include_str!("../tx/display/erc20_screens.rs")),
        ("cowswap_screens.rs", include_str!("../tx/display/cowswap_screens.rs")),
        ("slot_rotation_screens.rs", include_str!("../tx/display/slot_rotation_screens.rs")),
        ("value_transfer_screens.rs", include_str!("../tx/display/value_transfer_screens.rs")),
        ("blind_sign_screens.rs", include_str!("../tx/display/blind_sign_screens.rs")),
        ("erc7730_screens.rs", include_str!("../tx/display/erc7730_screens.rs")),
        ("offchain_screens.rs", include_str!("../tx/display/offchain_screens.rs")),
        ("batch_screens.rs", include_str!("../tx/display/batch_screens.rs")),
    ];
    for (name, src) in FAMILIES {
        let declined = src.matches("declined:").count();
        let failed = src.matches("failed:").count();
        assert_eq!(
            declined, failed,
            "{name}: {declined} declined caption(s) but {failed} failed caption(s) — a family \
             without one falls back to the generic SAFE TX FAILED on every route"
        );
    }
}

// ---- #1154: a Signed film lands after its sign returned ---------------------
//
// The three release sites still call `film_resolve(Signed)` (pinned above),
// but the film's landing frames are drawn from PendSV once the handler has
// returned the released signature. These scans hold the properties that make
// that sound; each was a design decision, and each has a quiet way to break.

const MAIN: &str = include_str!("../main.rs");
const UI_MOD: &str = include_str!("../ui/mod.rs");

/// The body of the first `fn` whose signature starts with `sig`, up to its
/// closing brace at column 0.
fn body<'a>(src: &'a str, sig: &str) -> &'a str {
    let rest = src.split(sig).nth(1).unwrap_or_else(|| panic!("missing `{sig}`"));
    &rest[..rest.find("\n}\n").unwrap_or(rest.len())]
}

fn at(hay: &str, needle: &str) -> usize {
    hay.find(needle).unwrap_or_else(|| panic!("missing `{needle}`"))
}

/// A Signed resolve returns before the scripted landing, after handing the
/// film to the background; every other ending still lands in place.
#[test]
fn signed_resolve_returns_before_the_landing_loop() {
    let fr = body(LCD, "pub fn film_resolve(e: Ending) {");
    // The one-shot hold is consumed first, so an early return (bad atlas)
    // cannot leave it armed for the next sign's resolve.
    assert!(at(fr, "let hold = LANDING_HOLD.swap(false, Ordering::Relaxed);") < at(fr, "assets::atlas_verified()"));
    let branch = at(fr, "if matches!(e, Ending::Signed) && !hold {");
    let write = at(fr, "(*core::ptr::addr_of_mut!(FILM)).write((anim, now));");
    let set = at(fr, "LANDING_SET.store(true, Ordering::Release);");
    let ret = branch + fr[branch..].find("        return;\n").expect("the Signed branch returns");
    let lp = at(fr, "    loop {\n");
    // The slot is written before the flag publishes it, and the branch
    // returns before the blocking loop that every other ending runs.
    assert!(branch < write && write < set && set < ret && ret < lp);
}

/// `show_ending` (the batch's between-member interstitial, followed at once
/// by the next dialog) lands in place: in the background it would be cut
/// after one frame.
#[test]
fn show_ending_lands_before_returning() {
    let se = body(LCD, "pub fn show_ending(e: Ending) {");
    assert!(at(se, "LANDING_HOLD.store(true, Ordering::Relaxed);") < at(se, "film_resolve(e);"));
}

/// One owner for the glass: every other way onto the panel first lands a
/// live landing (`landing_yield`) before it draws. A frame that had to land
/// it repaints in full, since the glass no longer holds what its damage was
/// computed against.
#[test]
fn every_other_draw_lands_the_landing_first() {
    let pfc = body(LCD, "fn present_frame_cols(");
    let y = at(pfc, "let (cols, bg) = if !IN_LANDING_STEP.load(Ordering::Relaxed) && landing_yield() { (None, false) } else { (cols, bg) };");
    assert!(y < at(pfc, "film_reap(true);") && y < at(pfc, "FRAME_IN_FLIGHT.swap(true") && y < at(pfc, "let (xa, xend) = match cols {"));
    let clear = body(LCD, "pub fn clear() {");
    assert!(at(clear, "landing_yield();") < at(clear, "lcd::fill_screen(0);"));
    let start = body(LCD, "pub fn film_start_with(s: &Screen) {");
    assert!(at(start, "landing_yield();") < at(start, "(*core::ptr::addr_of_mut!(FILM)).write((anim, now));"));
    // Only a lock (`landing_yield`, `landing_gateway_tick`) and a refused
    // atlas view (`landing_step`) cut a landing; no draw does any more
    // (review M1).
    assert_eq!(LCD.matches("landing_cut();").count(), 3);
    assert!(body(LCD, "pub fn landing_yield() -> bool {").contains("landing_cut();"));
    assert!(body(LCD, "pub fn landing_step() {").contains("landing_cut();"));
    assert!(body(LCD, "pub fn landing_gateway_tick() {").contains("if crate::nsc::is_definitely_locked() {\n        landing_cut();"));
    // ANTI-VACUITY: the cut must clear the flag, not just reap.
    let lc = body(LCD, "pub fn landing_cut() {");
    assert!(lc.contains("if LANDING_SET.swap(false, Ordering::AcqRel) {"));
}

/// Review M1: the non-secure world gets the signature at once, but it cannot
/// put the next dialog over SIGNED. Every input dialog plays the live
/// landing out (through the check and its result hold, input-dead) BEFORE
/// it samples a single edge; only a lock cuts it.
#[test]
fn a_dialog_cannot_start_before_the_live_landing_has_shown_the_check() {
    // The three input dialogs: the yield precedes sampling and the FSM's
    // level seed, so presses made while SIGNED played never reach them.
    let rf = body(LCD, "pub fn run_flow(");
    assert!(at(rf, "landing_yield();") < at(rf, "sampling_enable();") && at(rf, "landing_yield();") < at(rf, "InputFsm::resumed("));
    let rp = body(LCD, "pub fn run_pager(");
    assert!(at(rp, "landing_yield();") < at(rp, "carry_take()") && at(rp, "landing_yield();") < at(rp, "sampling_enable();"));
    let sy = body(LCD, "    fn sync(&mut self) {");
    assert!(at(sy, "landing_yield();") < at(sy, "sampling_enable();"));
    // ...and they are the only samplers: a new one would need its own yield.
    assert_eq!(LCD.matches("sampling_enable();").count(), 3);
    // An earlier landing lands before a resolve reuses `FILM`.
    let fr = body(LCD, "pub fn film_resolve(e: Ending) {");
    assert!(at(fr, "landing_yield();") < at(fr, "let hold = LANDING_HOLD.swap(false, Ordering::Relaxed);"));

    // The yield lands unless the device is locked, and never consults the
    // landing-frame flag (review L4: a stuck flag must not skip it).
    let y = body(LCD, "pub fn landing_yield() -> bool {");
    let locked = at(y, "if crate::nsc::is_definitely_locked() {\n        landing_cut();\n        return false;\n    }");
    assert!(at(y, "if !landing_live() {") < locked && locked < at(y, "landing_finish();"));
    assert!(!y.contains("IN_LANDING_STEP"));

    // The finish plays to the end of the script: the blocking loop, left
    // only through `film_done`, busy for the watchdog, on the film view.
    let f = body(LCD, "fn landing_finish() {");
    let lp = at(f, "        loop {\n");
    let done = at(f, "            if anim.film_done(t) && landing_held(t) {\n                break;\n            }");
    assert!(lp < done);
    let looped = &f[lp..done];
    assert!(looped.contains("let _ = build_and_present(anim, &marks, &font, None, None, None);"));
    for exit in ["return", "break", "is_idle", "ring_has_edges", "drain(", "sampling_enable"] {
        assert!(!looped.contains(exit), "nothing may leave or read input inside the finish loop: `{exit}`");
    }
    assert!(at(f, "if !LANDING_SET.swap(false, Ordering::AcqRel) {") < lp);
    assert!(at(f, "let _busy = crate::nsc::HandlerGuard::enter();") < lp);
    assert!(f.contains("assets::atlas_film_frame()") && !f.contains("atlas_verified"));

    // The hold is a VISIBLE hold: the film clock is wall-clock, so the loop
    // also waits until the check has been ON THE GLASS for RESULT_HOLD_MS,
    // measured from the first frame that showed it (noted after each frame).
    assert!(at(looped, "let _ = build_and_present(") < at(looped, "landing_note_check(anim, t);"));
    let held = body(LCD, "fn landing_held(now: u32) -> bool {");
    assert!(held.contains("LANDING_CHECK_SHOWN.load(Ordering::Relaxed)\n        && now.wrapping_sub(LANDING_CHECK_AT.load(Ordering::Relaxed)) >= pqsigner_ui_px::loading::RESULT_HOLD_MS"));
    let note = body(LCD, "fn landing_note_check(anim: &Anim, t: u32) {");
    assert!(note.contains("if !LANDING_CHECK_SHOWN.load(Ordering::Relaxed) && anim.film_done(t.wrapping_add(pqsigner_ui_px::loading::RESULT_HOLD_MS)) {"));
    assert!(at(note, "LANDING_CHECK_AT.store(t, Ordering::Relaxed);") < at(note, "LANDING_CHECK_SHOWN.store(true, Ordering::Relaxed);"));
    // Each landing starts unshown; the background step needs the visible
    // hold too before it ends the landing.
    let fr2 = body(LCD, "pub fn film_resolve(e: Ending) {");
    assert!(at(fr2, "LANDING_CHECK_SHOWN.store(false, Ordering::Relaxed);") < at(fr2, "LANDING_SET.store(true, Ordering::Release);"));
    let ls = body(LCD, "pub fn landing_step() {");
    assert!(ls.contains("let done = anim.film_done(now) && landing_held(now);"));
    assert!(at(ls, "film_reap(true);") < at(ls, "landing_note_check(anim, now);"));
    // ANTI-VACUITY: `film_done` really waits for the check (T7) and its hold.
    const LOADING: &str = include_str!("../../../pqsigner-ui-px/src/loading.rs");
    assert!(LOADING.contains("self.ready.is_some() && self.film_t(now) >= T7 + RESULT_HOLD_MS"));
    assert!(LOADING.contains("pub const RESULT_HOLD_MS: u32 = 2450;"));
    // ...and `HandlerGuard` really is the busy count the watchdog reads.
    const NSC: &str = include_str!("../nsc/mod.rs");
    assert!(NSC.contains("HANDLER_DEPTH.fetch_add(1, core::sync::atomic::Ordering::SeqCst);"));
}

/// Landing frames read the film view, as the blocking landing's frames did:
/// `film_resolve` verified the secure SRAM3 copy, and only the secure world
/// writes it (#1133), so the non-secure world running between frames cannot
/// change what they read. A per-frame `atlas_verified` would copy and hash
/// 75 KB at PendSV priority on every frame (review L1), and `load_copy`
/// would rewrite the copy under any view a preempted context still holds
/// (L2). The landing is cut, not drawn, once any verify has failed. And no
/// landing frame is left streaming (or its band buffers unwiped) when
/// PendSV returns.
#[test]
fn landing_frames_use_the_film_view_and_finish_before_returning() {
    let ls = body(LCD, "pub fn landing_step() {");
    assert!(ls.contains("let Some(atlas) = assets::atlas_film_frame() else {\n        landing_cut();\n        return;\n    };"));
    for per_frame in ["atlas_verified", "verify_atlas", "load_copy"] {
        assert!(!ls.contains(per_frame), "a landing frame must not re-copy or re-hash the atlas (`{per_frame}`)");
    }
    // ANTI-VACUITY: the view refuses once a verify failed, and the bracket
    // opens with a real verify in `film_resolve`.
    const ASSETS: &str = include_str!("../ui/px/assets.rs");
    let ff = body(ASSETS, "pub fn atlas_film_frame() -> Option<AtlasRef> {");
    assert!(ff.contains("BOOT_OK => Atlas::parse(window()).map(|atlas| AtlasRef { atlas }),\n        _ => None,"));
    let fr = body(LCD, "pub fn film_resolve(e: Ending) {");
    assert!(fr.contains("let Some(atlas) = assets::atlas_verified() else {"));
    assert!(ls.contains("film_reap(true);"));
    let bg = body(LCD, "fn film_bg_allowed() -> bool {");
    assert!(
        bg.trim_start().contains("if IN_LANDING_STEP.load(Ordering::Relaxed) {\n        return false;\n    }"),
        "a landing frame must never stream in the background"
    );
    assert!(at(bg, "return false;") < at(bg, "#[cfg(feature = \"ui-px-film-bench\")]"));
}

/// The deferred "Ready" is drawn only after the landing flag is cleared;
/// the other order would defer it again, for ever.
#[test]
fn ready_is_drawn_after_the_landing_ends() {
    let ls = body(LCD, "pub fn landing_step() {");
    assert!(at(ls, "LANDING_SET.store(false, Ordering::Release);") < at(ls, "ready_at_rest(&atlas);"));
    // ...and never over a locked device (review L5), through the
    // fail-closed predicate, not `!is_definitely_locked()`.
    assert!(ls.contains("if LANDING_THEN_READY.swap(false, Ordering::Relaxed) && crate::nsc::is_unlocked() {\n            ready_at_rest(&atlas);"));
    let ss = body(UI_MOD, "pub fn show_status(title: &str, sub: &str) {");
    assert!(ss.contains("if title == \"PQSigner OS\" && sub == \"Ready\" && px::lcd::landing_defer_ready() {\n        return;\n    }"));
}

/// The deferred Ready runs inside a landing step (PendSV, above every
/// non-secure exception). It paints ONE resting frame from the landing's
/// film view (review L6): `show_status` would play the idle entrance for up
/// to `PLAY_CAP_MS` there, a continuous non-secure blackout of up to 3 s
/// against the watchdog's 4 s budget, and re-verify the atlas.
#[test]
fn the_deferred_ready_is_one_resting_frame() {
    let ls = body(LCD, "pub fn landing_step() {");
    assert!(!ls.contains("show_status("), "the landing step must not run a status screen's entrance");
    let rr = body(LCD, "fn ready_at_rest(atlas: &assets::AtlasRef) {");
    assert!(rr.contains("paint_rest(&s, atlas);"));
    for long in ["play_screen", "show_status", "show_with", "verify_atlas", "atlas_verified"] {
        assert!(!rr.contains(long), "the deferred Ready must not call `{long}`");
    }
    assert!(rr.contains("classify(\"PQSigner OS\", \"Ready\")"));
    // ANTI-VACUITY: `paint_rest` settles on synthetic time and draws once.
    let pr = body(LCD, "pub fn paint_rest(s: &Screen, atlas: &assets::AtlasRef) {");
    assert!(pr.contains("while anim.step(t) && t < PLAY_CAP_MS {\n        t += 16;\n    }"));
    assert_eq!(pr.matches("build_and_present(").count(), 1);
    assert!(!pr.contains("wfi"));
}

/// PendSV draws a landing frame only with the gateway gate taken by itself
/// (no gateway call preempted) and no handler busy; a lock by the idle wipe
/// ends the landing and runs the re-unlock instead. SysTick never pends it
/// while a handler is busy.
#[test]
fn pendsv_draws_a_landing_frame_only_between_gateway_calls() {
    let pendsv = &MAIN[at(MAIN, "fn PendSV() {")..];
    let gate = at(pendsv, "let _gateway_token = nsc::GATEWAY_GATE.try_enter();");
    let live = at(pendsv, "if crate::ui::px::lcd::landing_live() {");
    let locked = at(pendsv, "if nsc::is_definitely_locked() {\n            crate::ui::px::lcd::landing_cut();\n            if !timeout::is_idle() {");
    let step = at(pendsv, "if gate_free && !nsc::handler_is_busy() {\n                crate::ui::px::lcd::landing_step();");
    let reunlock = at(pendsv, "enter_pin()");
    assert!(gate < live && live < locked && locked < step && step < reunlock);
    assert!(pendsv[gate..step].contains("let gate_free = _gateway_token.is_some();"));
    let systick = body(MAIN, "fn SysTick() {");
    assert!(systick.contains("if crate::ui::px::lcd::landing_due(timeout::now()) && !nsc::handler_is_busy() {"));
}

/// SysTick re-pends PendSV while a landing frame draws (it is not over yet,
/// so it still reads as due), and that PendSV tail-chains in before the
/// non-secure world runs. Without a due check at the top of the step it
/// draws the next frame back to back and the non-secure world gets no CPU
/// until the film is done — the signature would still reach the companion
/// at the end of the film. The gap is measured from where a frame ENDS.
#[test]
fn landing_frames_leave_the_non_secure_world_a_gap() {
    let ls = body(LCD, "pub fn landing_step() {");
    let due = at(ls, "if !landing_due(timeout::now()) {\n        return;\n    }");
    assert!(due < at(ls, "assets::atlas_film_frame()") && due < at(ls, "anim.step(now);"));
    // The gap starts after the frame (and its reap), not before it.
    assert!(at(ls, "film_reap(true);") < at(ls, "LANDING_LAST_MS.store(timeout::now(), Ordering::Relaxed);"));
    let ld = body(LCD, "pub fn landing_due(now: u32) -> bool {");
    assert!(ld.contains("now.wrapping_sub(LANDING_LAST_MS.load(Ordering::Relaxed)) >= LANDING_GAP_MS"));
}

/// The legacy glyph blitter (`flush` when the pixel engine declines, and the
/// secret-row path always) writes the panel without `present_frame_cols`.
#[test]
fn the_glyph_blitter_ends_the_landing_too() {
    const DISPLAY: &str = include_str!("../ui/lcd.rs");
    let fl = body(DISPLAY, "    pub fn flush(&mut self) {");
    assert!(at(fl, "crate::ui::px::lcd::landing_yield();") < at(fl, "self.blit_glyph(c, r, &cols);"));
    let fs = body(DISPLAY, "    pub fn flush_with_secret_rows(&mut self, secret_rows: &[(usize, &[u8])]) {");
    assert!(at(fs, "crate::ui::px::lcd::landing_yield();") < at(fs, "self.blit_glyph("));
}

/// A lock during a landing that is NOT the idle wipe (CMD_LOCK zeroizes, then
/// draws; a SysTick between pends PendSV for the landing) ends the landing and
/// returns: only the idle wipe may run the PIN re-unlock. Without this the
/// landing's own PendSV opened an unrequested PIN dialog.
#[test]
fn a_non_idle_lock_during_a_landing_opens_no_pin_dialog() {
    let pendsv = &MAIN[at(MAIN, "fn PendSV() {")..];
    let live = at(pendsv, "if crate::ui::px::lcd::landing_live() {");
    let branch = &pendsv[live..at(pendsv, "// Only run if we're actually locked (avoids spurious re-entry)")];
    let not_idle = at(branch, "if !timeout::is_idle() {");
    let ret = not_idle + branch[not_idle..].find("return;").expect("the non-idle lock returns");
    let cut = at(branch, "crate::ui::px::lcd::landing_cut();");
    assert!(cut < not_idle && not_idle < ret, "cut, then return unless the idle wipe locked it");
    // ANTI-VACUITY: cmd_lock really zeroizes before it draws (the window this closes).
    const LOCK: &str = include_str!("../nsc/cmd_lock.rs");
    assert!(at(LOCK, "super::zeroize_sensitive_state();") < at(LOCK, "crate::ui::show_status(\"Locked\", \"\");"));
}

/// `IN_LANDING_STEP` turns off every other draw's cut, so it is set and
/// cleared only by the `LandingFrame` guard (review L4): a positional
/// `store(false)` after a frame was one early return away from a stuck flag,
/// and a stuck flag let a landing outlive a later dialog and paint its stale
/// SIGNED over that dialog's own ending.
#[test]
fn the_landing_frame_flag_is_scoped() {
    assert_eq!(LCD.matches("IN_LANDING_STEP.store(true, Ordering::Relaxed);").count(), 1);
    assert_eq!(LCD.matches("IN_LANDING_STEP.store(false, Ordering::Relaxed);").count(), 1);
    let enter = body(LCD, "    fn enter() -> Self {\n        IN_LANDING_STEP.store(true, Ordering::Relaxed);");
    assert!(enter.contains("LandingFrame"));
    let drop = at(LCD, "impl Drop for LandingFrame {\n    fn drop(&mut self) {\n        IN_LANDING_STEP.store(false, Ordering::Relaxed);\n    }\n}");
    assert!(drop > 0);
    // Both frame sites take the guard around their draw.
    let fr = body(LCD, "pub fn film_resolve(e: Ending) {");
    assert!(at(fr, "let _frame = LandingFrame::enter();") < at(fr, "let _ = present_film(&anim, &marks, &font, true);"));
    let ls = body(LCD, "pub fn landing_step() {");
    let g = at(ls, "let _frame = LandingFrame::enter();");
    assert!(g < at(ls, "anim.step(now);") && at(ls, "film_reap(true);") < at(ls, "LANDING_LAST_MS.store("));
}

/// Review M1, second half: PendSV draws only while no gateway call is in
/// progress, and the non-secure world decides that. Back-to-back short calls
/// that keep the gate held would freeze the landing mid-orbit (it looks like
/// signing in progress while the companion already has the signature). So
/// every veneer, through `fi_boundary`, first draws a due landing frame in
/// thread mode under its own gate, before its command runs and before its
/// FI-delay accounting starts; the step's own gap check keeps that to one
/// frame per gap.
#[test]
fn back_to_back_gateway_calls_cannot_freeze_the_landing() {
    const NSC: &str = include_str!("../nsc/mod.rs");
    let fb = body(NSC, "fn fi_boundary(run: impl FnOnce() -> u32) -> u32 {");
    let tick = at(fb, "crate::ui::px::lcd::landing_gateway_tick();");
    assert!(tick < at(fb, "crate::fi::clear_delay_poison();") && tick < at(fb, "let status = run();"));
    assert!(fb.contains("#[cfg(all(feature = \"ui-px\", feature = \"ui-lcd\", not(feature = \"ui-px-landing-blocking\")))]\n    crate::ui::px::lcd::landing_gateway_tick();"));
    let gt = body(LCD, "pub fn landing_gateway_tick() {");
    let due = at(gt, "if !landing_due(timeout::now()) {\n        return;\n    }");
    let locked = at(gt, "if crate::nsc::is_definitely_locked() {\n        landing_cut();\n        return;\n    }");
    assert!(due < locked && locked < at(gt, "landing_step();"));
    // Not inlined into all the veneers it is called from.
    assert!(LCD.contains("#[inline(never)]\npub fn landing_gateway_tick() {"));
    // ANTI-VACUITY: the step it calls keeps its own gap check first.
    let ls = body(LCD, "pub fn landing_step() {");
    assert!(at(ls, "if !landing_due(timeout::now()) {\n        return;\n    }") < at(ls, "anim.step(now);"));
}

/// Review L3: PendSV now also runs for landing frames, so it must not infer
/// "the idle wipe asked for a re-unlock" from "the device is locked". The
/// idle wipe records the request right before it pends PendSV, and PendSV
/// runs the PIN re-unlock only after swap-clearing it, so a stray pend on a
/// locked device returns instead of opening an unsolicited PIN prompt.
#[test]
fn the_pin_reunlock_runs_only_when_the_idle_wipe_asked() {
    let systick = body(MAIN, "fn SysTick() {");
    let idle = at(systick, "if timeout::is_idle() && !nsc::handler_is_busy() && !nsc::is_definitely_locked() {");
    let arm = &systick[idle..];
    let req = at(arm, "REUNLOCK_REQUESTED.store(true, core::sync::atomic::Ordering::Release);");
    let pend = at(arm, "ARCH.icsr.write(1 << 28); // PENDSVSET");
    assert!(at(arm, "nsc::zeroize_sensitive_state();") < req && req < pend);
    // The landing pend (later in SysTick) does not set it.
    assert_eq!(MAIN.matches("REUNLOCK_REQUESTED.store(true").count(), 1);
    let pendsv = &MAIN[at(MAIN, "fn PendSV() {")..];
    let landing = at(pendsv, "if crate::ui::px::lcd::landing_live() {");
    let swap = at(pendsv, "if !REUNLOCK_REQUESTED.swap(false, core::sync::atomic::Ordering::AcqRel) {");
    let reunlock = at(pendsv, "enter_pin()");
    assert!(landing < swap && swap < at(pendsv, "if nsc::is_unlocked() {") && swap < reunlock);
    // The refused branch clears the re-entry flag and returns.
    let refused = &pendsv[swap..at(pendsv, "if nsc::is_unlocked() {")];
    assert!(refused.contains("core::ptr::write_volatile(core::ptr::addr_of_mut!(PENDSV_IN_FLIGHT), 0);") && refused.contains("return;"));
}

/// Review L7: `ui-px-landing-blocking` is a dev/bench A/B switch. It is
/// fenced out of production in both places the other dev features are (the
/// `mode-production` compile fence and the Makefile `PROD_FORBIDDEN` ship
/// gate), it is compiled by the ui-px config matrix on both boards, and the
/// cfgs that hand a landing off and pace it agree on `stm32u585`.
#[test]
fn the_landing_blocking_switch_is_fenced_built_and_the_cfgs_agree() {
    const NSC: &str = include_str!("../nsc/mod.rs");
    let end = at(NSC, "\"PRODUCTION_DESTRUCTIVE_HARNESS_FORBIDDEN: mode-production");
    let start = NSC[..end].rfind("#[cfg(all(\n    feature = \"mode-production\",\n    any(\n").expect("fence opener");
    assert!(NSC[start..end].contains("        feature = \"ui-px-landing-blocking\",\n"));
    const MAKEFILE: &str = include_str!("../../../Makefile");
    let pf = at(MAKEFILE, "override PROD_FORBIDDEN :=");
    let pf_end = pf + MAKEFILE[pf..].find("\n\n").expect("PROD_FORBIDDEN ends");
    assert!(MAKEFILE[pf..pf_end].split_whitespace().any(|w| w == "ui-px-landing-blocking"));
    let sx = at(MAKEFILE, "UI_PX_SUFFIXES := \\\n");
    let sx_end = sx + MAKEFILE[sx..].find("\nUI_PX_CONFIGS").expect("matrix ends");
    assert!(MAKEFILE[sx..sx_end].contains("\tdebug-log,ui-px,ui-px-landing-blocking \\\n"));
    // The hand-off and the pacing agree on `stm32u585`, and `ui-lcd` (which
    // `px::lcd` needs) implies it.
    let systick = body(MAIN, "fn SysTick() {");
    assert!(systick.contains("#[cfg(all(feature = \"ui-px\", feature = \"ui-lcd\", feature = \"stm32u585\", not(feature = \"ui-px-landing-blocking\")))]\n    if crate::ui::px::lcd::landing_due("));
    let pendsv = &MAIN[at(MAIN, "fn PendSV() {")..];
    assert!(pendsv.contains("#[cfg(all(feature = \"ui-px\", feature = \"ui-lcd\", feature = \"stm32u585\", not(feature = \"ui-px-landing-blocking\")))]\n    if crate::ui::px::lcd::landing_live() {"));
    let fr = body(LCD, "pub fn film_resolve(e: Ending) {");
    assert!(fr.contains("#[cfg(all(feature = \"stm32u585\", not(feature = \"ui-px-landing-blocking\")))]\n    if matches!(e, Ending::Signed) && !hold {"));
    assert!(LCD.contains("#[cfg(not(feature = \"stm32u585\"))]\ncompile_error!("));
    const CARGO: &str = include_str!("../../Cargo.toml");
    assert!(CARGO.contains("gpio-buttons = [\"stm32u585\"]") && CARGO.contains("ui-lcd = [\"spi1-arduino\", \"gpio-buttons\""));
}

/// Re-review N1: every dialog verifies the atlas before it draws, and a
/// failed verify latches `BOOT_BAD`, which refuses the landing's film view.
/// So `verify_atlas` plays a live landing out first, on the copy
/// `film_resolve` verified, before it re-copies and re-hashes: a non-secure
/// atlas swap after the sign can refuse the next dialog, but only after
/// SIGNED and its check have been shown.
#[test]
fn an_atlas_reverify_plays_the_landing_out_first() {
    const ASSETS: &str = include_str!("../ui/px/assets.rs");
    let va = body(ASSETS, "pub fn verify_atlas() -> Result<AtlasRef, ()> {");
    let y = at(va, "super::lcd::landing_yield();");
    assert!(y < at(va, "match verify_atlas_inner() {"));
    assert!(va.contains("#[cfg(not(feature = \"ui-px-landing-blocking\"))]\n    super::lcd::landing_yield();"));
    // The copy is rewritten in exactly one place, reached only through
    // `verify_atlas`, so nothing re-copies before the yield.
    assert_eq!(ASSETS.matches("load_copy();").count(), 1);
    assert!(body(ASSETS, "fn verify_atlas_inner() -> Result<AtlasRef, ()> {").contains("load_copy();"));
    assert_eq!(ASSETS.matches("verify_atlas_inner()").count(), 2, "one definition, one call (in verify_atlas)");
    // ANTI-VACUITY: the finish draws from the film view, which a failed
    // verify would refuse; that is why the order matters.
    let f = body(LCD, "fn landing_finish() {");
    assert!(f.contains("let Some(atlas) = assets::atlas_film_frame() else {"));
}
