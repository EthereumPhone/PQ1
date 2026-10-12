COMMENT_ON: 80
---
**Two notes from the 2026-10-11 security frontier research (defects D12 and A13). The first is a trap for whoever implements this issue.**

**1. The address in this issue's body is not `RCC_SECCFGR`.** The body says to write the mask "via the SECURE alias `0x5602_0C10`". With the secure RCC base at `0x5602_0C00`, offset `0x010` is `RCC_ICSCR3`, the HSI16 trim register. `RCC_SECCFGR` is at offset **`0x110`** (RM0456 Rev 7, section 11.8.51), so the secure alias is `0x5602_0D10`. Implementing the body as written would write the mask into the oscillator calibration. I checked both offsets in the reference manual text myself.

**2. Securing RCC does not close the whole timing lever: `FLASH_ACR` stays writable from the non-secure world.** RM0456 Rev 7, section 7.9.1: "This register is nonsecure. It can be read and written by both secure and nonsecure access. This register can be protected against unprivileged access when NSPRIV = 1 in FLASH_PRIVCFGR register." `NSPRIV` only stops unprivileged non-secure code. The only `FLASH_ACR` write in the firmware is `secure/src/hw/rcc.rs:180-183`, once at boot, never re-read, and nothing writes `FLASH_PRIVCFGR`. The same register also holds the bank power-down requests, and `FLASH_PDKEYxR` is non-secure too.

What this means: after this issue lands, non-secure code can still lower the flash wait states under a running secure world. Nobody has shown that this yields a usable fault in secure code (the secure HardFault handler zeroizes and resets, so it may be a denial of service only). Severity as rated by the research: medium, by manual reading, not demonstrated.

Suggested checklist additions:

- [ ] Use offset `0x110` for `RCC_SECCFGR`.
- [ ] Have the secure world re-assert and read back `FLASH_ACR.LATENCY` before fault-sensitive sections (signing, unlock), since it cannot be locked.
- [ ] Record the `FLASH_ACR` residual in the threat model.
