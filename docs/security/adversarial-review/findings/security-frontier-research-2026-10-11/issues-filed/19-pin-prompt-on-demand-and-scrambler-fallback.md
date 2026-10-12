TITLE: A locked device paints the trusted PIN dialog on every host unlock request with no rate bound, and the PIN start-digit scrambler falls back to all zeros when the RNG fails
LABELS: finding,priority:low,surface:usb,surface:trusted-ui,source:frontier-research-2026-10
---
## Summary

Two small PIN-dialog items.

1. **Prompt on demand.** Any USB host can raise the trusted PIN dialog on a locked device, as often as it likes. No attempt is consumed and nothing is unlocked without a physical PIN, but the dialog that users are trained to trust appears at the host's command.
2. **Scrambler fallback.** The PIN dialog starts each position at a random digit so that press counts do not reveal the PIN. If the random draw fails, the result is discarded and every position starts at 0.

## Evidence

Line numbers at master `0feea78a` (2026-10-11). The research ran at `c75b0d9c`, an ancestor of master; the cited files were diffed against master before filing.

**Prompt on demand**

- `nonsecure/src/usb/commands.rs:286-287`: `INS_V2_UNLOCK => return self.cmd_unlock()`; `:497-507`. Routing checks the class byte only (`shared/src/apdu_framing.rs:108-116`).
- `secure/src/nsc/cmd_request_unlock.rs:29-31`, `:51-52`, `:54`: if not already unlocked, `enter_pin()`.
- The sign-rate limiter in `secure/src/nsc/state.rs` covers signing only. #148 fixed the unlocked case only.
- With `iwdg` in the ship set, an ignored prompt ends in a watchdog reset after about 32 s (see {{10}}).

**Scrambler fallback**

- `secure/src/ui/pin_entry.rs:83`: `let _ = crate::rng_strong::fill(&mut rand_bytes);` then `:85` `pin[i] = rand_bytes[i] % 10;`.
- `secure/src/rng_strong.rs:206-213`: the buffer is zeroised before `Err` is returned.
- The comment at `secure/src/ui/pin_entry.rs:73-78` records this as a deliberate choice: "We do NOT refuse PIN entry — bricking the wallet on transient RNG flake would be worse". In a dual-SE build both secure-element contributions are mandatory, so making either I2C bus fail is enough to force the fallback.

## Severity and evidence level

- Both **low**. The first is nuisance and habituation. The second gives the press-count channel back to an attacker who can also force an RNG failure.
- Evidence: code read; re-checked independently (both confirmed). The device already shows the PIN prompt by itself at every boot and after every idle lock, so the added exposure of the first item is small.

## Fix directions

- [ ] Bound host-raised prompts (for example one per physical button press, or a minimum interval).
- [ ] Scrambler: one bounded retry, then refuse with a status. This reverses the recorded rationale, so it needs an owner decision.

## Related

#148, #637.

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item M12 / M04, defect row A30 and A31). Re-checked before filing by an independent read at `c75b0d9c` (both confirmed). The full report is `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`; it was not committed when this issue was filed, so this body is written to stand alone.</sub>
