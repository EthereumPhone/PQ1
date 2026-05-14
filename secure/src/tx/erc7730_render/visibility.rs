//! ERC-7730 §"Conditional Visibility" — render-time evaluator.
//!
//! Per the Phase 4 plan (`~/.claude/plans/fully-implement-phase-4-
//! nested-puppy.md` §"Visibility semantics"), the five `Visibility`
//! variants collapse as follows:
//!
//! | Variant    | Phase 4 behaviour                                    |
//! |------------|------------------------------------------------------|
//! | Always     | Render unconditionally.                              |
//! | Never      | Skip; walker NOT invoked.                            |
//! | Optional   | Render (Phase 5 compact-mode toggle differentiates). |
//! | IfNotIn    | Render. Value list not yet wire-encoded by `dbgen`.  |
//! | MustMatch  | Reject. Value list not yet wire-encoded by `dbgen`.  |
//!
//! The current `dbgen::erc7730::compile_params` writes only a 1-byte
//! VISIBILITY TLV payload; sub-TLV for value lists is a Phase 5 wire
//! extension. Until that lands, `MustMatch` carries the descriptor's
//! *intent* without the mechanism to enforce it. Rather than silently
//! pretend a rule is satisfied, we reject — the priority-ladder caller
//! falls through to blind-sign and surfaces a status banner.
//!
//! Once the value-list extension ships, `IfNotIn` / `MustMatch` will
//! consult `params.visibility_values` (a `[u8 count][u8 elem_len][bytes
//! ; count * elem_len]` sub-TLV) and compare against the resolved
//! [`crate::tx::erc7730::AbiValue`] via byte-wise canonical encoding.

use crate::tx::erc7730::{AbiValue, Visibility};

use super::params::ParamSet;

/// What the visibility evaluator tells the formatter dispatcher.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// Walk the path, format the value, append the page.
    Render,
    /// Skip this field — don't walk, don't format.
    Skip,
    /// Descriptor disagrees with the inbound tx — the caller surfaces
    /// `RenderErr::Reject(reason)` and falls through to blind-sign.
    Reject(&'static str),
}

/// Decide whether to render the field, given its parameter set and the
/// (optional) already-walked value. `resolved` is `None` for `Always`
/// / `Never` (cheap pre-walk decision) and `Some(value)` for the
/// IfNotIn / MustMatch branches that depend on the resolved value.
///
/// The caller is responsible for invoking the walker only when the
/// decision actually needs the value (the API encodes that by accepting
/// `Option<AbiValue>` rather than forcing the caller to walk first).
pub fn should_render(
    params: &ParamSet<'_>,
    resolved: Option<&AbiValue<'_>>,
) -> Action {
    match params.visibility {
        Visibility::Always => Action::Render,
        Visibility::Never => Action::Skip,
        // Phase 4 collapses Optional → Always. Phase 5 may distinguish
        // it for a compact-display mode that the user can toggle in
        // settings; the wire bit is preserved so a future firmware can
        // read it without a descriptor reflash.
        Visibility::Optional => Action::Render,
        Visibility::IfNotIn => {
            // Without a value list (Phase 5+) there is nothing to filter
            // against. Render — matches the seed-corpus's pragmatic
            // behaviour of treating "IfNotIn no list" as "always show".
            // The `_ = resolved` placeholder reminds Step 3 (and Phase
            // 5) not to drop the parameter from the call site when the
            // sub-TLV lands.
            let _ = (params.visibility_values, resolved);
            Action::Render
        }
        Visibility::MustMatch => {
            // Conservative choice — see the module comment.
            //
            // Once Phase 5 lands the value-list sub-TLV, swap the
            // unconditional reject for: walk `resolved`, scan
            // `params.visibility_values` for an equal canonical
            // encoding, render on match, reject on mismatch.
            let _ = (params.visibility_values, resolved);
            Action::Reject("7730 must-match unsupported")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params_with(v: Visibility) -> ParamSet<'static> {
        let mut p = ParamSet::default();
        p.visibility = v;
        p
    }

    #[test]
    fn always_renders_without_value() {
        let p = params_with(Visibility::Always);
        assert_eq!(should_render(&p, None), Action::Render);
    }

    #[test]
    fn never_skips() {
        let p = params_with(Visibility::Never);
        assert_eq!(should_render(&p, None), Action::Skip);
    }

    #[test]
    fn optional_renders_in_phase_4() {
        let p = params_with(Visibility::Optional);
        assert_eq!(should_render(&p, None), Action::Render);
    }

    #[test]
    fn if_not_in_renders_when_no_value_list() {
        let p = params_with(Visibility::IfNotIn);
        assert_eq!(should_render(&p, None), Action::Render);
    }

    #[test]
    fn must_match_rejects_in_phase_4() {
        let p = params_with(Visibility::MustMatch);
        match should_render(&p, None) {
            Action::Reject(_) => (),
            other => panic!("expected Reject, got {:?}", other),
        }
    }
}
