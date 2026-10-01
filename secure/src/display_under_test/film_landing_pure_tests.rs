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
