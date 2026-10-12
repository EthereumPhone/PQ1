COMMENT_ON: 418
---
**Status check (2026-10-12): this looks fixed in the tree. Not closing; please confirm.**

At master `0feea78a` both veneers take the guard before touching `FW_UPDATE`:

- `secure/src/nsc/cmd_fw_status.rs:28`: `let _busy = super::HandlerGuard::enter();`
- `secure/src/nsc/cmd_fw_abort.rs:33`: `let _busy = super::HandlerGuard::enter();`

and `secure/src/nsc_fw_update_pure_tests.rs:1674-1730` pins both ("LCR-F2: ABORT now holds `HandlerGuard::enter()` ...", "STATUS must call `HandlerGuard::enter()` before reading `FW_UPDATE`").

One caveat that keeps this from being a clean close: `HandlerGuard::enter()` only increments a depth counter. It excludes the SysTick idle cleanup, which is what this issue is about, but it does not refuse a nested veneer call. That separate defect is filed as its own issue ({{01}}).
