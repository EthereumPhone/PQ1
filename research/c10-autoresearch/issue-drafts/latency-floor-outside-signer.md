**Owner decision needed. Nothing has landed.** Found during the 2026-11-12 signing-speed loop (Fable 5.2 round 4; verified in source). With the hash work now ~1.0–1.5 s, these decide when the companion actually gets a signature.

## 1. `ui-px`: the gateway returns ≥ 8.65 s after the film starts, whatever the hash speed

- `cmd_sign_userop.rs` starts the film before the slot keygen (`film_start`, ~line 2358).
- After the signature is in the output buffer, it calls `film_resolve(Ending::Signed)` (~line 3056).
- `film_resolve` (`ui/px/lcd.rs`) loops until `anim.film_done(t)`, which is `QubitFilm::done`: `film_t(now) >= T7 + RESULT_HOLD_MS` (`pqsigner-ui-px/src/loading.rs`).
- With `T7 = 6200` and `RESULT_HOLD_MS = 2450`, that is 8,650 ms of film time.
- `film_time` is the identity up to `T5 = 4800`. An answer later than that adds whole 850 ms turns.

So a sign that finishes within 4.8 s of the film's start returns to the non-secure world at **8.65 s**. Master's 3.4 s sign and the research head's ~1.0–1.5 s sign both return at 8.65 s. The USB loop cannot send until then. This is a reading of the constants and the control flow, not a panel measurement.

Options:

- **(a) Return before the hold.** Return once the result frame is on the glass, and have the next secure draw wait out the rest of the 2.45 s.
  - The glass shows the same thing, and the companion gets the result 2.45 s sooner.
  - Check whether the check mark fades in during the hold; if it does, return after the fade.
- **(b) Decouple the film's minimum length from delivery.**
  - Either return when the signature is released and let the film finish from a secure timer or a non-secure-pumped tick, or shorten the script when the work is fast.
  - On a 1 s sign this saves up to ~5 s more.
  - It is a design/UX decision, and it needs a trusted-display review.
- **Fewer film frames while hash-bound.** The film draws for ~8 ms of every 32 ms. This only matters once (a) or (b) is in place.

## 2. Legacy LCD route: a fixed spin after "Signed"

Without `ui-px`, the handler shows "Signed" and then runs `for _ in 0..3_000_000 { cortex_m::asm::nop() }` before returning. Without cortex-m's `inline-asm`, the `nop` is an out-of-line call, so this costs roughly 0.1–0.2 s on every sign (not measured). A timestamped hold, as in 1(a), would take it off the gateway path.

## 3. USB result paging

- The non-secure transport's TX buffer is 256 bytes (`nonsecure/src/usb/transport.rs`). Results are therefore paged with `0x61xx` + `GET_RESPONSE`.
- A ~4.15 KB Type-2 result is ~17 host round trips.
- Each page is 1 OUT report and ~5 IN reports at 1 ms, so the device-side floor is ~100 ms. Host turnaround per page comes on top, an estimated 0.15–0.3 s via WebHID (not measured).

Options:

- One framed response streamed from the result buffer: a ~70 ms floor with no host turnarounds.
- Bulk or WebUSB: under 10 ms.

Companion timestamps around the first `0x61` and the last page would size this with no firmware change.

Related: #1153 (RNG, prewarm, speculative signing) and #1149 (film tick cost).
