# USB attack surface audit and hardening for PQSigner OS on STM32U585

**The single most dangerous threat to PQSigner's USB stack is not a software CVE but electromagnetic fault injection (EMFI) targeting branch instructions in the USB control transfer path** — demonstrated by Colin O'Flynn on the Trezor One (STM32F205) and Solo Key FIDO2 token, recovering private keys via a single glitched `MIN()` check. This attack applies to any USB stack, including Rust-based ones, because `core::cmp::min()` compiles to the same conditional branch. The custom synopsys-usb-otg + usb-device stack avoids every known STM32Cube CVE (all are host-side or HAL-middleware-specific), but inherits three DWC2 hardware errata in ES0499 — two of which carry data-leakage risk. No CVEs exist against either Rust crate in the RustSec database. The architecture of USB in the non-secure TrustZone world on OTG_FS (which has no DMA engine) is fundamentally sound: the CPU mediates every byte between FIFO and SRAM, so no peripheral-initiated bus master transaction can bypass TrustZone memory protections.

---

## 1. CVE catalogue with applicability analysis

The table below catalogues every relevant vulnerability discovered, tagged by applicability layer. The "Custom Stack" column indicates whether the issue affects PQSigner's synopsys-usb-otg + usb-device configuration running on the STM32U585 DWC2 OTG_FS peripheral.

| ID / Reference | Description | Layer | Custom Stack? | Severity |
|---|---|---|---|---|
| **O'Flynn EMFI (WOOT '19)** | EMFI glitch skips `MIN(wLength, desc_len)` branch → memory readout up to 64 KB including keys | Generic + Physical | **YES** — Rust `min()` compiles to identical branch | **CRITICAL** |
| **ES0499 §2.26.3** | ZLP race: unexpected data packet sent instead of zero-length packet under specific SNAK/CNAK/token timing | DWC2 hardware | **YES** — all stacks | **HIGH** (data leak) |
| **ES0499 §2.26.2** | CSR access interleaved with TxFIFO push corrupts transfer size → wrong packet on bus | DWC2 hardware | **YES** — all stacks | **MEDIUM** (corruption) |
| **synopsys-usb-otg #49** | `static mut EP_MEMORY` creates UB via mutable aliasing; deprecated in Rust 2024 edition | Rust crate | **YES** | **MEDIUM** (soundness) |
| **synopsys-usb-otg #43 / usb-device #166** | USB-IF Chapter 9 compliance failures: Interface Descriptor (9.4), Halt Endpoint (9.9), LPM L1 (9.21) | Rust crate | **YES** | **LOW-MEDIUM** |
| **TinyUSB #2832** | DWC2 OUT buffer overflow on STM32U5 when software buffer < received data — up to 128-byte overwrite | DWC2 driver | Instructive only (different driver) | **Reference** |
| **ES0499 §2.26.4** | Wrong interrupt mask for battery charger mode → spurious interrupt | DWC2 hardware | YES (minor) | LOW |
| **ES0499 §2.26.5** | False CIDSCHG interrupt after reset | DWC2 hardware | YES (minor) | LOW |
| **ES0499 §2.2.15** | OTG_FS shares reset domain with DCMI_PSSI; writing DCMI_PSSIRST partially resets OTG | System | YES if DCMI used | LOW |
| SA0035 | PCD HAL buffer overflow in USB device setup/data transfers | STM32Cube HAL | **NO** — HAL not used | N/A |
| CVE-2021-42553 | USB Host Library endpoint count overflow | STM32Cube Host | **NO** — device mode only | N/A |
| CVE-2021-34259–34264 | Multiple USB Host descriptor parsing overflows | STM32Cube Host | **NO** | N/A |
| CVE-2026-4179 | Zephyr `usb_dc_stm32.c` infinite loop | Zephyr RTOS | **NO** | N/A |

**Key takeaway: zero CVEs apply to PQSigner's custom Rust stack from the STM32Cube ecosystem.** The attack surface is the DWC2 silicon errata (affects everyone) and the EMFI physical attack (affects every USB stack that uses conditional branches for bounds checks).

### The O'Flynn EMFI attack in detail

Colin O'Flynn's "MIN()imum Failure" (USENIX WOOT 2019) uses a ChipSHOUTER or PicoEMP to inject a single electromagnetic pulse timed to the CPU's execution of the `min(wLength, descriptor_length)` comparison during a USB `GET_DESCRIPTOR` control transfer. The PhyWhisperer-USB provides cycle-accurate triggering by hardware-decoding USB traffic and pattern-matching on the SETUP packet. When the branch instruction is skipped, the device uses the attacker-supplied `wLength` (up to 65,535 bytes) as the transfer length, reading past the descriptor buffer into adjacent memory — which on the Trezor One included the BIP-39 seed in flash. **The attack was performed without opening the device enclosure.**

This applies to PQSigner because `core::cmp::min()` compiles to a conditional branch (`CMP` + `BLS`/`BHI` on Cortex-M33). The compiler may also emit `CSEL` (conditional select) on ARMv8-M, which is marginally more resistant but still glitchable with precise timing.

---

## 2. Highest-risk USB descriptor parsing paths

Rust's memory safety eliminates the classical buffer overread/overwrite bugs that plague C stacks — slice bounds checking makes `GET_DESCRIPTOR` with oversized `wLength` return only the buffer contents, never adjacent memory. However, several attack paths remain relevant.

### DWC2 FIFO architecture creates hardware-level risks

The STM32U585 OTG_FS has **320 words (1,280 bytes) of dedicated SPRAM** shared across one RX FIFO and per-endpoint TX FIFOs. The RX FIFO is shared across all OUT endpoints — every received SETUP and DATA OUT packet lands in the same FIFO. The OTG_FS operates exclusively in **slave (FIFO) mode with no DMA**, meaning the CPU must pop each word from `GRXSTSP` and the data FIFO registers. This is actually a security advantage: no peripheral bus master can independently access system SRAM, so TrustZone memory protections cannot be bypassed by the USB peripheral.

The recommended FIFO allocation for PQSigner's HID configuration:

```
OTG_GRXFSIZ   = 0x0080  (128 words = 512 bytes RX FIFO)
OTG_DIEPTXF0  = 0x0010_0080  (EP0 TX: 16 words @ offset 128)
OTG_DIEPTXF1  = 0x0020_0090  (EP1 TX: 32 words @ offset 144)
Total: 176 of 320 words used — 144-word safety margin
```

FIFO sizing must follow the RM0456 formula: `RxFIFO ≥ 13 + (MPS/4 + 1) + (2 × num_OUT_EPs) + 1`. For 64-byte MPS and 2 OUT endpoints, the minimum is 35 words; 128 words provides generous headroom and prevents NAK storms under burst traffic.

### Stale FIFO data leakage via errata 2.26.3

ES0499 §2.26.3 describes a race condition where the DWC2 sends an **unexpected data packet instead of a zero-length packet** when specific timing conditions align between SNAK clearing, CNAK setting, endpoint enable, and IN token reception. The data sent is whatever happens to be in the TX FIFO at that moment — potentially stale data from a previous transfer. **This is a data exfiltration vector.** The workaround is a specific SNAK/CNAK/EPENA sequencing with AHB clock cycle delays as described in the errata. Additionally, all FIFOs should be flushed on every USB reset via `GRSTCTL.RXFFLSH` and `GRSTCTL.TXFFLSH` (with `TXFNUM = 0x10` to flush all TX FIFOs), and the FIFO region should be zeroed if the SPRAM is memory-mapped.

### Control transfer state machine abuse

The `usb-device` crate's `ControlPipe` correctly handles SETUP packet injection during an active data phase — it resets the state machine to `Idle` and processes the new SETUP. The DWC2 hardware stores up to 3 back-to-back SETUP packets (configured via `DOEPTSIZ0.STUPCNT = 3`), setting `DOEPINT.B2BSETUP` on overflow. The interrupt handler must always check `DOEPINT.STUP` and `DOEPINT.STPKTRX` (bit 15, often undocumented in RM0456) before processing `XFRC` on EP0.

A known deficiency in `usb-device`: if `get_configuration_descriptors()` exceeds the 128-byte control buffer (`CONTROL_BUF_LEN`), the `BufferOverflow` error is silently swallowed via `.ok()`, producing a malformed descriptor response instead of a STALL. **Enable the `control-buffer-256` feature** and verify total configuration descriptor size fits the buffer. Better yet, patch the crate to STALL on overflow.

### CSR/TxFIFO interleave corruption (errata 2.26.2)

In slave mode, if the CPU reads or writes a CSR for a *different* endpoint between the last two 32-bit pushes of a packet to a TxFIFO, the transfer size counter (`DIEPTSIZx.XFRSIZ`) is incorrectly decremented to zero, corrupting the packet. **The synopsys-usb-otg crate must ensure FIFO writes are atomic** — no CSR access to other endpoints may occur between successive writes to the same FIFO. In the interrupt handler, this means completing all FIFO writes for one endpoint before touching any other endpoint's registers. The recommended workaround from the errata is to schedule single-packet transfers (`DIEPTSIZ.XFRSIZ = DIEPCTL.MPSIZ`) so only one packet is ever in-flight.

---

## 3. Hardening checklist: USB ISR through APDU handler

The validation pipeline from USB interrupt to NSC gateway must enforce 21 checks across three trust boundaries. Below is the ranked checklist with concrete implementations.

### Priority 1 — EMFI countermeasures (addresses the CRITICAL threat)

Every `min(host_value, device_value)` comparison in the USB control transfer path must be hardened against single-instruction skip:

```rust
// FI-resistant min: double-check with complementary comparison
fn fi_resistant_min(a: usize, b: usize) -> usize {
    let result = core::cmp::min(a, b);
    // Redundant check: if EMFI skipped the first branch,
    // the second comparison catches it
    if result > a || result > b {
        // Fault detected — return the smaller bound
        return if a < b { a } else { b };
    }
    result
}
```

Additionally, **verify the actual bytes written to the TX FIFO after transmission** by checking `DIEPTSIZ.XFRSIZ` post-transfer. If the transmitted size exceeds the expected descriptor length, assert a fault. The `usb-device` crate's `accept_in()` function performs `len = min(len, req.length as usize)` — this is the exact `MIN()` pattern O'Flynn targeted. Wrap this in a double-check.

### Priority 2 — HID transport layer validation

The Ledger-compatible HID framing uses 64-byte reports with a 7-byte header on init packets (channel ID[2] + tag[1] + sequence[2] + length[2]) and 5-byte header on continuations.

**Rate limiting** should use a token-bucket algorithm in the USB OUT callback, *before* any reassembly processing:

```rust
const BUCKET_MAX: u16 = 64;       // burst capacity (one full APDU)
const REFILL_PER_MS: u16 = 1;     // ~200 reports/sec sustained

static mut RATE_TOKENS: u16 = BUCKET_MAX;

fn rate_check() -> bool {
    let elapsed = tick_delta_ms();
    RATE_TOKENS = (RATE_TOKENS + elapsed * REFILL_PER_MS).min(BUCKET_MAX);
    if RATE_TOKENS == 0 { return false; } // NAK the endpoint
    RATE_TOKENS -= 1;
    true
}
```

When the rate limit fires, set `DOEPCTL.SNAK` on the HID OUT endpoint to NAK further packets until the bucket refills.

The full HID-layer check sequence in the OUT interrupt callback:

1. **Rate limit** → NAK if exceeded
2. **Channel ID** must equal `0x0101` → drop silently if wrong
3. **Command tag** must be `0x05` (APDU) or `0x02` (PING) → drop otherwise
4. **Sequence number** must be strictly ascending; seq=0 starts new APDU
5. **On seq=0**: declared APDU length must satisfy `4 ≤ length ≤ 4096` → respond `SW 6700` if violated
6. **Bounded copy**: `copy_len = min(chunk_size, declared_len - bytes_received)` — never exceed `MAX_APDU_RX`
7. **Reassembly timeout**: 5-second timer from first packet; abort and scrub buffer on expiry
8. **If seq=0 arrives during active reassembly**: abort old reassembly, increment anomaly counter, start new

### Priority 3 — APDU validation before NSC gateway crossing

The non-secure world must perform allowlist validation before any NSC call to minimize the secure world's exposure:

```rust
fn validate_apdu(apdu: &[u8]) -> bool {
    if apdu.len() < 4 { return false; }
    let (cla, ins) = (apdu[0], apdu[1]);
    match cla {
        0xF0 => matches!(ins, 
            INS_GET_PUBKEY | INS_SIGN_HASH | INS_GET_VERSION | INS_GET_RESPONSE),
        0x00 => matches!(ins, INS_SELECT | INS_GET_RESPONSE),
        _ => false,
    }
}
```

Verify `Lc` consistency: for short APDUs, `apdu[4]` as Lc must satisfy `apdu.len() >= 5 + Lc`. For P1-based chaining, enforce cumulative payload ≤ `MAX_APDU_RX` and reject a continuation block arriving without a prior chaining-in-progress state.

### Priority 4 — NSC gateway hardening

All 6 NSC gateway functions must:

1. Call `cmse_check_address_range()` on every pointer argument with `CMSE_NONSECURE | CMSE_MPU_READ` (or `READWRITE` for output buffers)
2. **Copy-in** all data to secure SRAM before processing (TOCTOU defense — the non-secure world can modify the buffer between validation and use)
3. **Re-validate** CLA/INS/Lc independently — never trust non-secure validation
4. Clear all registers before `BXNS` return (the compiler-generated veneer should handle this, but verify the SG/BXNS sequence in the linker-generated NSC thunks)
5. Rate-limit NSC calls: no more than ~50/second to prevent secure-world CPU starvation

### Priority 5 — GET_RESPONSE chunking for 17 KB signatures

SLH-DSA SPHINCS+ SHA2-128f signatures are **17,088 bytes**, requiring ~290 HID packets. The response buffer must be protected:

```rust
static mut RESPONSE_BUF: [u8; 17090] = [0u8; 17090]; // +2 for SW
static mut RESPONSE_LOCKED: bool = false;
static mut RESPONSE_OFFSET: usize = 0;
static mut RESPONSE_TOTAL: usize = 0;

// While response_locked, reject all commands except GET_RESPONSE (INS 0xC0)
// Timeout: 30 seconds — if host doesn't complete retrieval, scrub buffer
// Any non-GET_RESPONSE command cancels the pending response and scrubs
```

Use the ISO 7816 `SW 0x61xx` pattern where `xx` indicates remaining chunks (or `0x00` if >255 remain). Each `GET_RESPONSE` returns up to 255 bytes + 2-byte SW.

### Priority 6 — USB bus event handling

On **USB reset** (`GINTSTS.USBRST`):
- Flush all FIFOs via `GRSTCTL.RXFFLSH` and `GRSTCTL.TXFFLSH`
- Zero the reassembly buffer, response buffer, and all protocol state
- Signal secure world to abort any in-flight crypto via a shared `abort_flag`
- Reset rate limiter
- Debounce rapid resets: if >5 resets in 10 seconds, delay re-enumeration by 1 second

On **USB suspend** (`GINTSTS.USBSUSP`):
- Start 10-second timer; if no resume, scrub all buffers and enter low-power
- Do NOT immediately clear reassembly state (host may resume within 7 ms)

On **endpoint stall clear** (`CLEAR_FEATURE(ENDPOINT_HALT)`):
- Rate-limit: max 10 per second per endpoint
- Reset data toggle and reassembly state for that endpoint

---

## 4. Register-level hardening configuration

### OTG_GINTMSK: disable unnecessary interrupts

For a device-only HID configuration, the minimal interrupt mask eliminates host-mode, OTG, and SOF interrupts that expand the attack surface:

```
OTG_GINTMSK = 0x800C_3810

Enabled:  WUIM(31) | OEPINTM(19) | IEPINTM(18) | ENUMDNEM(13) | USBRSTM(12) | USBSUSPM(11) | RXFLVLM(4)
Disabled: SOFM(3) — timing side-channel; MMISM(1) — OTG only; PRTIM(24) — host only;
          HCIM(25) — host only; CIDSCHGM(28) — OTG only; SRQM(30) — OTG only
```

**Force device mode** with `OTG_GUSBCFG.FDMOD = 1` (bit 30) to prevent any host-mode state transitions. Disable SOF interrupt — it provides a precise 1 ms timing oracle that could serve as a side channel.

### GTZC and MPCBB configuration

Assign USB OTG_FS to non-secure world:
```c
HAL_GTZC_TZSC_ConfigPeriphAttributes(GTZC_PERIPH_USB_OTG_FS,
    GTZC_TZSC_PERIPH_NSEC | GTZC_TZSC_PERIPH_NPRIV);
```

Mark USB buffer SRAM pages as non-secure via MPCBB (512-byte granularity on STM32U5). Ensure the APDU reassembly buffer, response buffer, and endpoint memory (`EP_MEMORY`) all reside in non-secure SRAM regions. Secure SRAM (crypto keys, PIN state) must be in separate MPCBB-protected pages.

**Critical architectural advantage: OTG_FS has no DMA engine.** Since all USB data transfer is CPU-mediated in slave/FIFO mode, there is no DMA bus master that could bypass TrustZone memory protections. This is the strongest possible TrustZone-compatible USB configuration. If PQSigner ever migrates to an STM32U5 variant with OTG_HS (which supports DMA), the GPDMA channel security attributes (`SRC_SEC`, `DEST_SEC`) and MPCBB configuration become critical.

### IWDG for USB stack hang detection

```c
IWDG->KR  = 0x5555;   // unlock
IWDG->PR  = 6;        // prescaler /256 → ~125 Hz from 32 kHz LSI
IWDG->RLR = 250;      // ~2-second timeout
IWDG->KR  = 0xCCCC;   // start
// Kick with IWDG->KR = 0xAAAA after each successful USB transaction
```

The USB processing loop must kick the watchdog; if the DWC2 hangs (e.g., errata 2.26.2 corruption or synopsys-usb-otg issue #37 reset hang), the IWDG forces a system reset.

---

## 5. Co-processor USB isolation: architectural recommendation

### What production wallets actually do

The industry splits into three architectural camps:

**Co-processor proxy (Ledger Nano S/X)**: The STM32F042 (Nano S) or STM32WB55 (Nano X) handles USB/BLE as a "dumb router," forwarding APDUs to the ST31/ST33 secure element via UART using the SEPROXYHAL protocol. Crypto keys never exist on the MCU. This is genuine physical USB isolation — a USB stack exploit on the MCU cannot directly access the SE's key material. However, Saleem Rashid (2018) demonstrated that a compromised MCU can exfiltrate the seed during generation by manipulating the display and APDU routing. Ledger's response with Stax/Flex was to move display driving *into* the SE itself (ST33K1M5, CC EAL6+), eliminating the MCU-display trust gap.

**Single MCU, no isolation (Trezor Model T, earlier Trezors)**: The STM32F427 handles USB, display, keys, and signing — all on one chip with no secure element. Ledger Donjon built a **$100 voltage-glitching board that extracts the seed in 5 minutes with 100% reliability**. Kraken Security Labs independently confirmed the attack. Trezor Safe 3/5 added OPTIGA Trust M for seed storage, and Safe 5/7 moved to STM32U5 (Cortex-M33) for improved fault resistance.

**Air-gapped, no USB data (Foundation Passport, Keystone 3 Pro, ColdCard in air-gap mode)**: USB-C connector has data pins physically removed (Passport) or USB data can be permanently disabled by scratching a PCB trace (ColdCard). Communication is exclusively via QR codes and MicroSD. **This eliminates the entire USB attack surface by design.**

### The case against a USB co-processor for PQSigner

Adding a dedicated co-processor (e.g., RP2040 or STM32G0) beside the STM32U585 to handle USB would mirror Ledger's architecture. The security benefit is real but marginal given PQSigner's TrustZone design:

**TrustZone on STM32U585 already provides hardware-enforced isolation** between the USB stack (non-secure) and crypto operations (secure), with the SAU, MPCBB, and GTZC enforcing memory and peripheral access boundaries. The 6 NSC gateway commands create a narrow, auditable interface — functionally equivalent to Ledger's SEPROXYHAL but without the BOM cost, board complexity, or inter-chip latency.

**OTG_FS's lack of DMA is a decisive factor.** Because all USB data moves through CPU load/store instructions (slave mode), TrustZone's memory protections apply to every byte. A separate co-processor communicating over SPI would introduce a *new* attack surface (the SPI channel itself) while providing isolation that TrustZone already delivers.

The **real gap** in PQSigner's architecture compared to Ledger Stax/Flex is not USB isolation but **trusted display**: the non-secure world drives the UI, meaning a compromise of the non-secure world could show the user a false transaction while the secure world signs a different one. A co-processor doesn't solve this — only a secure-world display path or a secondary SE with display control would.

### Known TrustZone bypass attacks to defend against

TrustZone on Cortex-M33 is not impervious to physical attacks. Known bypass techniques include:

- **Voltage glitching**: Thomas Roth broke TrustZone-M on SAM L11 (Cortex-M23) with ~$5 of equipment at 36C3. STM32U5 has enhanced anti-tamper and voltage/frequency glitch detectors, and no public glitching attack has been demonstrated against it — but the principle applies. RDP Level 2 + anti-tamper configuration is essential.
- **ret2ns (Return-to-Non-Secure)**: Academic attack exploiting buffer overflows in NSC functions to escalate from non-secure to secure world. Cortex-M33 lacks PXN (Privileged Execute Never), which is only available on M55/M85. **Mitigation: validate all NSC function inputs rigorously, use stack canaries, keep NSC functions minimal.**
- **BUSted**: Timing side-channel via bus contention between CPU and DMA. Less relevant here since OTG_FS has no DMA.

### Recommendation

**Do not add a USB co-processor.** The cost/benefit ratio is unfavorable:

- **Cost**: $1–3 BOM, additional PCB space, second firmware image, protocol versioning, SPI/UART attack surface, supply chain complexity, 10–100 µs latency per USB transaction
- **Benefit**: Marginally stronger isolation than TrustZone, primarily against physical fault injection — but PQSigner's dual SE (NXP SE050 + OPTIGA Trust M) already protects the seed against physical extraction, and SLH-DSA signing on the Cortex-M33 is protected by TrustZone's secure world

Instead, invest engineering effort in: (1) EMFI countermeasures (FI-resistant code patterns, secure enclosure design), (2) trusted display path (even partial — e.g., showing a transaction hash on a secondary LED/segment display driven from secure world), and (3) rigorous NSC gateway hardening.

---

## 6. Ranked hardening checklist (implementation priority)

| # | Item | Effort | Impact |
|---|---|---|---|
| 1 | **FI-resistant `min()` in USB control path** — double-check all `wLength` clamping; verify post-transfer `DIEPTSIZ.XFRSIZ` | Low | Critical |
| 2 | **Flush + zero FIFOs on USB reset** — `GRSTCTL.RXFFLSH`, `GRSTCTL.TXFFLSH(0x10)`, clear SPRAM if mapped | Low | High |
| 3 | **Enforce declared APDU length ≤ 4096 at seq=0** — reject before any copy; bounded copy with running counter | Low | High |
| 4 | **Atomic TxFIFO writes** — no CSR access to other endpoints between FIFO pushes (errata 2.26.2) | Low | High |
| 5 | **ZLP errata workaround** — correct SNAK/CNAK/EPENA sequencing per ES0499 §2.26.3 | Medium | High |
| 6 | **Force device mode** (`GUSBCFG.FDMOD=1`); set `GINTMSK = 0x800C_3810`; disable SOF | Low | Medium |
| 7 | **NSC gateway: `cmse_check_address_range` + copy-in/copy-out** on all 6 gateways | Medium | High |
| 8 | **Rate limit HID OUT** — token bucket (64 burst, ~200/sec sustained) with SNAK enforcement | Medium | Medium |
| 9 | **CLA/INS allowlist in non-secure before NSC call** | Low | Medium |
| 10 | **5-second reassembly timeout with buffer scrub** | Low | Medium |
| 11 | **Response buffer locking + 30-second GET_RESPONSE timeout** for 17 KB signatures | Medium | Medium |
| 12 | **IWDG at ~2 seconds** — kick after each USB transaction | Low | Medium |
| 13 | **Enable `control-buffer-256` feature** in usb-device; patch STALL-on-overflow | Low | Low |
| 14 | **SecureFault + GTZC_IRQ handlers** — log and reset on TrustZone violations | Medium | Medium |
| 15 | **USB reset debounce** — delay re-enumeration if >5 resets in 10 seconds | Low | Low |
| 16 | **Fix synopsys-usb-otg `static mut` UB** — migrate to `MaybeUninit`/`UnsafeCell` pattern before Rust 2024 edition | Medium | Medium |
| 17 | **Fuzz with FaceDancer/Hydradancer** — test wLength overflow, rapid SETUP injection, reset cycling, ZLP edge cases | High | High |
| 18 | **Abort secure-world crypto on USB disconnect** — shared `abort_flag` checked periodically during SPHINCS+ signing | Low | Low |

---

## Conclusion

PQSigner's architecture — USB in non-secure TrustZone on DWC2 OTG_FS with no DMA — is a strong starting point that avoids the worst design patterns seen in production wallets (Trezor's single-chip-no-SE, Ledger Nano's MCU-controlled-display). The custom Rust stack sidesteps every known STM32Cube CVE, and Rust's memory safety eliminates the buffer overread class of bugs that O'Flynn's EMFI attack exploits in C stacks. However, **Rust does not protect against fault injection on branch instructions** — the `MIN()` pattern compiles to the same conditional branch regardless of language. Hardening the control transfer path with redundant bounds checks, post-transfer length verification, and FIFO scrubbing on reset addresses the highest-severity threats. The three DWC2 errata (§2.26.2, §2.26.3, §2.26.5) require specific workarounds that the synopsys-usb-otg crate may not implement — audit the crate's TxFIFO write sequencing and ZLP handling against the ES0499 errata descriptions. A separate USB co-processor is not justified given TrustZone's hardware isolation on OTG_FS; the engineering budget is better spent on EMFI shielding, NSC gateway hardening, and establishing a trusted display path from the secure world.