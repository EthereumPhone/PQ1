COMMENT_ON: 168
---
**The concrete mechanisms behind this issue, from the 2026-10-11 security frontier research (defect row A4), after an independent re-check at `c75b0d9c`. Line numbers are at master `0feea78a` (the cited files are unchanged).**

This is a recovery defect in the locked ship profile. It does not argue for doing the OPTIGA lifecycle work now; it describes what the post-wipe rule has to solve when that work is done.

1. **OPTIGA: the PIN reference object cannot be rewritten after a wipe (untracked until now).** `secure/src/optiga/apdu.rs:1373-1374` gives F1D0 the access condition `Change = Auto(F1D0)`: changing it requires authenticating with its current value. The wipe leaves F1D0 untouched (`secure/src/optiga/mod.rs:2839-2840`). Re-provisioning writes it without authenticating first (`:1123-1131`, called from `:2162-2165`), so on a part taken to the operational lifecycle state (`:1040-1043`) the write is refused and provisioning fails at that step. This holds even when the user still knows the PIN. The comment at `:2797-2800` says "re-provisioning bumps to a fresh range", but the object id is a `pub const` (`secure/src/optiga/apdu.rs:198`), so that mechanism does not exist.
2. **SE050: the locked UserID object survives the wipe.** `secure/src/se050/mod.rs:2286-2288` deletes it best-effort only, and since the S-6 change admin cannot delete it. Re-provisioning then refuses with a firmware-synthesised `0x6986` (`:1993-2000`) and the caller panics (`secure/src/crypto.rs:496`). `docs/security/threat-model.md:146-148` records this as deliberate ("data destroyed, UserID orphaned") with an object-range bump as the remedy; the id is a `pub const` (`se050/mod.rs:53`), so that remedy is a firmware change for every unit, not a per-device action. This one is not specific to the locked profile.
3. **The repeated "tamper" wipe on every boot is a consequence, not a third cause.** The OPTIGA counter E120 is not reset under the locked profile (`secure/src/optiga/mod.rs:2795-2801`), so each boot sees it ahead of page 124 and wipes again (`secure/src/nsc/mod.rs:1713`), then falls through to the wizard. A successful F1D0 authentication resets E120 (`optiga/mod.rs:2650`), so this would heal on the first good unlock if (1) were fixed.

Meanwhile the wipe screen tells the user to "restore from seed" (`secure/src/nsc/cmd_request_unlock.rs:209`).

The one test that speaks to recovery does not cover this: `make pin-gate-wipe-e2e` builds a non-locked image, and its last recorded pass (2026-04-22) predates the S-6 change of 2026-05-28. Details in {{23}}.

Evidence: code read only. No part has been taken to the operational lifecycle state with this access condition, so the chip's refusal in (1) is inferred from the metadata, not observed.
