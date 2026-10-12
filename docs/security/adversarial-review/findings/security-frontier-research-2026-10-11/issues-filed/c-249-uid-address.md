COMMENT_ON: 249
---
**Correction to the UID address in this issue's body (from the 2026-10-11 security frontier research, defect E16).**

The body gives the device UID at `0x0BFA_0590`. That is the STM32L5 location. On the STM32U5 the unique device ID is at **`0x0BFA_0700`** (RM0456 Rev 7, section 76.1, "Base address: 0x0BFA 0700").

The code already uses the right address (`secure/src/nsc/prodtest.rs:46-47`, `proto/src/lib.rs:647` and `:902` at master `0feea78a`), and a silicon receipt exists for it. `docs/security/production-security.md` repeats the wrong value at `:370`, `:395` and `:424` and contradicts itself at `:140`.

Nothing is broken today. The risk is that new tooling written from this issue or from that document reads the wrong address. I re-checked the reference manual text myself before posting.
