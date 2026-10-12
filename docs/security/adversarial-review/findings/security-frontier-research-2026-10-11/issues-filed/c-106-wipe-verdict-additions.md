COMMENT_ON: 106
---
**Additions from the 2026-10-11 security frontier research (defect row A5), after an independent re-check at `c75b0d9c`. Line numbers below are at master `0feea78a`.**

Everything in this issue's body still holds; the lines have moved. Three points are not in the body:

1. **Consuming the result at the call sites would not be enough.** `Se050::init()` returns `Ok` from cache when the session is already up (`secure/src/se050/mod.rs:225-229`). If the bus dies after that, the admin check at `:2293-2295` reads "no admin", the unauthenticated sweep and the `reinit()` result are discarded (`:2398`), every post-check reads "gone" (`:2416`, `:2434`, `:2444`), and `admin_factory_reset` returns `Ok(())` having deleted nothing. The probes themselves must become tri-state (present / absent / unknown), with unknown meaning "not wiped".
2. **The admin object deletes itself even when data deletes failed.** `secure/src/se050/mod.rs:2328-2343` only logs delete errors (and the logging compiles out in ship builds); `:2368-2379` self-deletes unconditionally. After that, nothing can authenticate a retry.
3. **Page 124 is reset unconditionally at three sites**, not one: `secure/src/nsc/cmd_request_unlock.rs:204`, `secure/src/main.rs:1962`, `secure/src/nsc/mod.rs:1735`.

Current lines for the items already in the body: discarded verdict at `cmd_request_unlock.rs:196`, `main.rs:1957`, `nsc/mod.rs:1734`, `crypto.rs:495`; `Ok(())` on admin-PIN derivation failure at `se050/mod.rs:3192-3204`; `admin_exists()` clearing the page-125 flag at `se050/mod.rs:678-686` and `:3222-3224`, which runs before the `wipe_result` check at `:3226` and in dual-SE also discards the flag the OPTIGA leg armed (`dual_se.rs:631-640`).

One mitigating fact: on the ship profile a lost resume flag after a real ten-wrong-PIN lockout is partly covered by the next-boot counter reconcile, so practical exposure is narrower than the code defects suggest.

Evidence: code read only; nothing run on silicon.
