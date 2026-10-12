TITLE: NSC gateway is re-entrant: a nested veneer call can replace the signed calldata after the confirm screen in the single-sign handler (SIGN_SNAP_BUF is re-read post-confirm)
LABELS: bug,finding,priority:critical,surface:trustzone,surface:clear-signing,source:frontier-research-2026-10
---
## Summary

The secure gateway does not refuse a second entry while a handler is already running. `HandlerGuard::enter()` only increments a depth counter. The single-sign handler keeps its request in a shared `static mut` buffer and reads the calldata out of it again **after** the user has confirmed, with no check that it is still what was displayed. A second gateway call made while the first is parked in the confirm dialog can refill that buffer, and the outer handler then signs bytes the user never saw.

This is the only finding of the research that breaks "what you see is what you sign". The displayed `to` and `value` stay honest; the `data` is what changes. Example of what that allows: the screen shows an ERC-20 `transfer` of 1 token to Alice, and the signature covers a `transfer` of the whole balance to another address on the same token contract, with the same calldata length.

**The batch handler is not affected, and it already contains the fix.** It commits to each member's `(to, value, calldata digest)` before the member's confirm, and after the final confirm it re-derives that commitment from the bytes it is about to sign and refuses on a mismatch. The single-sign handler computes the same digest before confirm but only displays it.

## Evidence

Line numbers at master `0feea78a` (2026-10-11). The research ran at `c75b0d9c`, an ancestor of master; I re-read every line below at master before filing.

- `secure/src/nsc/mod.rs:1298-1301`: `HandlerGuard::enter()` is an unconditional `fetch_add`. Nothing returns "busy". The only reader of the depth counter is the SysTick idle-wipe guard (`secure/src/main.rs:4413`).
- `secure/src/nsc/mod.rs:1042`: `SIGN_SNAP_BUF` is one shared `static mut`, used by `cmd_sign_userop`, `cmd_sign_userop_batch` and `cmd_sign_offchain`.
- `secure/src/nsc/cmd_sign_userop.rs:173-189`: on entry the handler zeroes the whole shared buffer and copies the non-secure payload into it. A nested call does the same to the outer call's snapshot.
- `secure/src/nsc/cmd_sign_userop.rs:280-299`: the header fields (sender, nonce, the five gas fields, the paymaster hash, `to`, `value`) are copied to locals before confirm. They are not swappable.
- `secure/src/nsc/cmd_sign_userop.rs:388`: `inner_data` is a slice **into the shared buffer**, not a copy. It is the only thing read from the shared buffer after confirm.
- `secure/src/nsc/cmd_sign_userop.rs:1716`: `calldata_fingerprint = calldata_digest(inner_data)` is computed before confirm and used only to draw the fingerprint page (`:1718`). It is never compared with anything afterwards.
- `secure/src/nsc/cmd_sign_userop.rs:1933`: `confirm_checked(...)` blocks for the user (up to the 120 s idle limit).
- `secure/src/nsc/cmd_sign_userop.rs:2133-2137`: after confirm, `reconstruct_execute_calldata(.., &tx_for_display, inner_data)` builds the signed calldata from that slice.
- No gateway handler masks interrupts. A grep of `secure/src` for `BASEPRI`, `PRIMASK`, `ITNS` and `interrupt::free` finds only flash, OTP, IWDG and logging critical sections.

https://github.com/EthereumPhone/PQ1/blob/0feea78a1b8bd5ecaa99c3346a5a69480fd13cbc/secure/src/nsc/mod.rs#L1298-L1301

https://github.com/EthereumPhone/PQ1/blob/0feea78a1b8bd5ecaa99c3346a5a69480fd13cbc/secure/src/nsc/cmd_sign_userop.rs#L2133-L2137

### What the batch handler does (the pattern to copy)

- `secure/src/nsc/cmd_sign_userop_batch.rs:1485`, `:1718`: each member's calldata digest is taken before that member's confirm and folded into a commitment after it.
- `:1776-1811`: the commitments are recomputed from the live buffer and compared (`batch_tuple_matches`).
- `:2263`, `:2276-2281`: after the final confirm, `batch_call_digest::checked_digest(.., &batch_final, ..)` re-parses the encoded calldata and requires it to match the confirmed commitment before any signature.

The report this issue comes from said the batch handler had "the same pattern". That was wrong, and I am correcting it here. A nested call during a batch would make the batch refuse, which is a denial of service and not a wrong signature.

### Comments that assert the opposite (they are wrong)

- `secure/src/nsc/mod.rs:1017-1019` and `:1040`: "the dispatcher is single-threaded and non-reentrant".
- `secure/src/nsc/mod.rs:1936`: "single-threaded non-reentrant dispatcher invariant (no two veneers in flight at once)".
- `secure/src/sau.rs:716`: "PRIS=0 → an NS IRQ can preempt a secure veneer mid-handler", which implies PRIS=1 prevents it. It does not. `AIRCR.PRIS` only lowers non-secure exception priorities relative to secure **exceptions**. A veneer called from non-secure thread mode runs in secure thread mode, and any exception can preempt thread mode.
- About 40 `SAFETY` comments in `secure/src/nsc/` lean on the same guarantee.
- `docs/security/threat-model.md` has no row for nested gateway entry.

## What an attacker needs

1. Code execution in the non-secure image. That image is FSBL-measured and vendor-signed, so this means a malicious or compromised signed non-secure build, or a memory-safety bug in the non-secure USB router.
2. A banked non-secure system exception (SysTick_NS or PendSV_NS). These are controlled by the non-secure world and are not routed through `NVIC_ITNS`.
3. A user who confirms a single (non-batch) transaction. The nested call must leave bytes of the same `data_len` at the same offset.

#835 (H5) already records, independently, that a compromised non-secure image can preempt a secure thread call and invoke another veneer "with no re-entry rejection".

## Severity and evidence level

- Severity: **high to critical** within the threat model (one review lens), **high** (the other). Both lenses note the precondition is a compromised non-secure image.
- Evidence: **code read only**. **No proof of concept exists.** The swap has not been reproduced on silicon or in emulation, and the nested stack depth is unmeasured.
- Scope: real CMSE veneers on STM32U585 only. The QEMU mailbox runs each call to completion, so no QEMU test can show this.
- Off-chain signing (`cmd_sign_offchain`) shares the buffer but was traced by the research as not swap-vulnerable. I did not re-trace that handler.
- What the user would see is not established. Under `ui-lcd` the pages are a stack value, so the dialog should keep showing the original transaction, but a nested call that fails loudly paints a status line over it. Under `ui-px` the nested zeroing wipes the pixel transcript that overlays the buffer tail, which is likely to break or refuse the dialog. Neither was run.

## Fix directions

- [ ] **Bind the signed bytes to the confirmed bytes in `cmd_sign_userop`**, the way the batch handler does: keep the pre-confirm `calldata_fingerprint`, recompute it from the encoded calldata after confirm, and refuse on a mismatch through the sentinel idiom. This closes the wrong-signature outcome even if a guard is skipped by a fault.
- [ ] Refuse nested entry: an atomic `compare_exchange(0, 1)` at the top of **every** `cmse-nonsecure-entry` veneer, before any argument is read. Return a new `NscStatus::Busy` with a USB status-word mapping.
- [ ] Keep the per-handler `enter()` for the idle-wipe depth semantics, and define how the PendSV idle re-unlock takes the same token.
- [ ] Scrub `SIGN_SNAP_BUF` on every early return.
- [ ] Decide whether veneers also raise `BASEPRI_S` to 0x80 for their critical sections.
- [ ] Guard the veneers that have no guard at all (`cmd_pin_attempt_log`, `nsc_register_heartbeat`). The pointer check in the first is {{18}}.
- [ ] Correct the comments listed above and add a threat-model row for nested entry.
- [ ] Evidence: a source-invariant test over all veneers (the existing source-pin tests assert the literal `fetch_add` and must be rewritten), a host model of the guard in a workspace crate so the test actually runs, and one silicon test.

## Related

#152 (veneers without `HandlerGuard`, idle-wipe preemption), #418, #140, #835 (H5), #600. Precedent: Ledger rejected interleaved commands centrally after [LSB-023](https://donjon.ledger.com/lsb/023/).

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item USB-01, defect rows A1 and E5). Every cited line was re-read by the filer at master `0feea78a` before filing; the batch-handler statement in the report was found wrong during that re-read and is corrected above. The full report is `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`; it was not committed when this issue was filed, so this body is written to stand alone.</sub>
