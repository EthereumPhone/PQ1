COMMENT_ON: 70
---
**Status check (2026-10-12): this looks resolved, and it still carries `ship-blocker` + `priority:critical`. Not closing; please confirm.**

The body says `secure/src/sau.rs` clears `GTZC1_TZSC_SECCFGR{1,2,3}` to 0. At master `0feea78a` it does not:

- `secure/src/sau.rs:257-283` sets the SECCFGR1 bits for IWDG, I2C1, I2C2 and (pq1) I2C4, and the SECCFGR3 block keeps AES / HASH / RNG / PKA / SAES secure with USB OTG FS non-secure, under exact-equality `const assert!` arms.
- `docs/security/red-teaming.md:508-509` records the silicon receipt: "Silicon-validated 2026-05-20 (`make gtzc-enforcement-hw` PASSED 7/7; USB still enumerates as `1209:7051`)".

Both checkboxes in this issue appear satisfied by that. The remaining TrustZone attribution gaps are different registers and are tracked elsewhere: TAMP (#81) and RCC / PWR / SYSCFG (#80).

I mention it because an open `ship-blocker` that is already fixed makes the ship-blocker list harder to trust. The same receipt appears to satisfy #239.
