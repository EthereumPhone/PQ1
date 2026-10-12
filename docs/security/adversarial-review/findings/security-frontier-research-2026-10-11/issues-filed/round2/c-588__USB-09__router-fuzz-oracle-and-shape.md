COMMENT_ON: 588
---
**Scope note for the `apdu_router_state_machine` target, from the 2026-10-11 security frontier research (item USB-09). Lines re-read at master `c2fab970`.**

The target as specified here feeds HID reports through `process_frame`, `parse_apdu_header`, `route_v2` and `ChainState::step`. All four live in the `shared` crate. That is worth having, but it stops before the code that is the largest host-reachable parser on the device: the non-secure (NS) command router. The router never runs on a host today, so no fuzz target, Kani harness or unit test reaches it.

**What the code does today**

- `nonsecure/src/usb/commands.rs` is 1274 lines. The `nonsecure` crate has no `[lib]` target and no `tests` directory, so nothing in it compiles for the host.
- Router state is module-level `static mut` plus a raw cursor: `nonsecure/src/usb/commands.rs:122` (`CHAIN_BUF`), `nonsecure/src/usb/commands.rs:125` (`PENDING_PTR`), `nonsecure/src/usb/commands.rs:136` (`ROUTER_OWNER`), and two function-local statics at `nonsecure/src/usb/commands.rs:863` and `nonsecure/src/usb/commands.rs:1196`. The cursor is dereferenced at `nonsecure/src/usb/commands.rs:864`.
- The handlers call the secure gateway directly (30 `nsc_api::` call sites in that file).
- The parts no harness reaches: `dispatch` and its session lease (`nonsecure/src/usb/commands.rs:226`), the trailer padding written into the chain buffer (`nonsecure/src/usb/commands.rs:780`), the status-word mapping and the `GET_RESPONSE` drain.

**Suggested additions (they depend on #313 item (a), the host-compile path)**

- [ ] Shape of the refactor: move the `static mut` and raw-pointer state into one owned struct and put the gateway behind a trait, so a mock gateway can return arbitrary statuses and lengths. This is a real refactor, not a re-export shim.
- [ ] Use an oracle stronger than "no panic". After any sequence of frames: (1) the router still answers a fresh `GET_VERSION`, which catches a stuck session lease; (2) `ensure_trailer_skeleton` never returns a length above `per_cmd_chain_bound(ins)` (`nonsecure/src/usb/commands.rs:99`).
- [ ] The refactor changes the NS image layout. Re-run the gateway address check (`tools/check-gateway-abi.sh`) and re-measure the NS slot afterwards, because the first-stage bootloader measures that slot.
- [ ] #313 says the file is 1111 lines; it is 1274 now.

**Limits**

- By design the NS world holds no secret, and the secure world copies and re-parses everything it is given. A fuzz of the router with a mock gateway can find panics, lease wedges and out-of-bounds writes inside NS. It cannot find a signing or disclosure bug.
- Router state is RAM only, so a wedge found this way does not survive a power cycle. The research dropped its first claim that it could.
- The research rated this P3 (its two review lenses said P2 and P3). This issue's own `priority:high` label covers the three targets it already lists.

<sub>**Provenance.** Security frontier research, 2026-10-11 (report item USB-09, section 10). Report priority P3 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading; nothing was run on silicon and no fuzz target was built. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
