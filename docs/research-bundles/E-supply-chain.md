# Research Prompt E — Supply Chain and Provisioning Attestation

## Research question

Map the supply-chain + provisioning threat model for a hardware wallet
using SE050 + OPTIGA on TrustZone STM32U585, shipping through
conventional retail / e-commerce, and recommend a provisioning +
attestation protocol that defeats each attacker class.

Specifically:

1. Counterfeit STM32U5 supply in 2024-2025: are there confirmed
   clones (GD32/CS32/APM32 style) in the U5 family yet, or only
   older F/L-series? What boot-time probes reliably detect clones?
2. NXP's SE050 UID cert chain up to NXP root CA: how reliable for
   anti-clone? Threat model for SE050 extraction + re-implantation
   in a different physical wallet.
3. Same question for OPTIGA Trust M cert chain.
4. What do Ledger, Trezor, Coinkite, Foundation etc. do at
   provisioning to attest "genuine factory-sealed device" to a
   customer opening the box? Known failure modes (historical + 2024-
   2025).
5. Given our dual-SE architecture, is there an additional attestation
   advantage from cross-binding SE050-UID + OPTIGA-UID + STM32-UID
   in a signed manifest that must match at every boot?

Deliverables: ranked attacker list (opportunistic re-seller;
sophisticated interdictor; nation-state with factory access), the
attestation protocol that defeats each, and a specific "box-opening"
user ceremony that demonstrates genuineness without requiring the
customer to run an independent tool.


---

## Project context (condensed — full version in `docs/ai-research-briefing.md`)

**What this is.** PQSigner OS: a post-quantum ERC-4337 smart-wallet
firmware for STM32U585 (Cortex-M33 + ARM TrustZone) on the
B-U585I-IOT02A Discovery board. Only external interface is USB-C. No
Bluetooth, no UART, no debug access in production (RDP Level 2
planned).

**Secure elements.** **Dual**-SE architecture, not single:
- **NXP SE050** (I2C1, addr `0x48`, EAL6+): stores `half_E` of XOR-
  split BIP-39 entropy. Hardware PIN gate via UserID (10 attempts).
- **Infineon OPTIGA Trust M V3** (I2C1, addr `0x30`, EAL6+): stores
  `half_O`. Shielded Connection (AES-128-CCM-8) for bus encryption.

Both chips are mandatory. Neither alone reveals any bit of the seed —
only `half_O XOR half_E = entropy`.

**Why signing must run on the Cortex-M33, not the SE.** Transaction
signatures are **post-quantum SLH-DSA (SPHINCS+ SHA2-128f, migrating
to 192f)**. No commercial secure element currently computes SLH-DSA.
Bootstrap signatures are **ML-DSA-44** (also PQ, also not SE-capable).
The SEs are gated storage, not signing accelerators. The seed
therefore transits STM32 secure-world SRAM during the active signing
window (~120 s idle timeout, then zeroize). TrustZone SAU+GTZC isolates
this from the non-secure world.

**TrustZone partition.** Secure world (flash bank 1, SRAM1) owns all
crypto, PIN, persistent secrets. Non-secure world (flash bank 2,
SRAM2) owns UI, USB, tx parsing. Crossings go through 6 NSC gateway
commands with pointer validation and TOCTOU-safe copy-in.

**Power supervision state.** BOR, PVD, ECC (except SRAM1 which is
always-on), IWDG all at factory defaults. Stage 1 of a 5-stage brownout
roadmap added reset-cause classification + verified flash writes; the
rest is planned. `make stm32-harden-opts` is a one-time option-byte
setup target (sets BOR3 + SRAM2_RST=0) but has not been run yet. See
`docs/brownout-hardening.md` for the full plan.

**VBAT.** B-U585I-IOT02A holder is CR1220 (not CR2032), **unpopulated
by default**. Backup-register state machine for dual-SE wipe (Stage 4)
is planned but depends on a populated cell.

**Accepted trade-offs (research that contradicts these is not useful):**
1. Seed transits STM32 SRAM during signing. Unavoidable until SE can
   do SLH-DSA.
2. SE050's value is hardware PIN gate + XOR storage, not "seed never
   leaves silicon." Don't suggest "do all signing on SE050" — it
   can't.
3. USB-C is the only external interface.
4. Out of scope: EAL6+ invasive decapping attacks.

**Dark Skippy and similar nonce-exfil attacks do NOT apply.** Hash-
based SLH-DSA has no nonce. Don't chase this.

**Current SCP03 state.** The SE050 SCP03 channel is active (every TX
has CLA=0x84). Using NXP default static keys; rotation to per-device
keys + HUK-SAES wrapping is a production-readiness item (work-todo #7).

---

## Style guidance

- Cite specific RM0456 / AN5342 / ES0499 / UM11225 / Infineon doc
  sections where possible. Prefer "per AN5342" over inventing
  revision numbers you aren't sure of.
- Say "I don't know" on things not answerable from public sources,
  rather than guessing.
- Give concrete, implementable code / register values — hand-wave
  recommendations without specifics are not useful.
- Respect the architecture above. Suggestions that require signing
  on the SE are category errors for this project.

---


## Relevant design docs (code footprint small — feature not implemented)


### From `docs/architecture.md`

# SPHINCS+ Post-Quantum Hardware Wallet — TrustZone Architecture

## Overview

This project implements a post-quantum hardware wallet using **SLH-DSA (SPHINCS+)** signatures
with **ARM TrustZone** isolation on a Cortex-M33 microcontroller. Private key material never
leaves the secure world. The non-secure world (USB, display, buttons) can only request
signatures through a narrow gateway.

The firmware targets **STM32U585** (production) and runs on **QEMU mps2-an505** (development).
A desktop CLI (`sphincs-wallet`) demonstrates the full TROPIC01 flow over USB.

Two modes of operation:
- **`mock-se`** (default): Mock secure element in SRAM, no hardware needed
- **`tropic01-se`**: Real TROPIC01 chip connected via USB at `/dev/ttyACM0`, bridged to
  QEMU via semihosting file I/O. All chip communication is e2e encrypted (X25519 + AES-256-GCM).

```
┌─────────────────────────────────────────────────────────────┐
│                    QEMU mps2-an505                          │
│  ┌──────────────────────┐   ┌────────────────────────────┐  │
│  │   SECURE WORLD       │   │   NON-SECURE WORLD         │  │
│  │                      │   │                             │  │
│  │  SPHINCS+ keys       │   │  USB protocol handler      │  │
│  │  AES-GCM wrap/unwrap │   │  OLED display driver       │  │
│  │  PIN verification    │   │  Button input               │  │
│  │  TROPIC01 comms ─────│───│──── /dev/ttyACM0 ──► chip  │  │
│  │  (e2e encrypted SPI) │   │                             │  │
│  │                      │   │  Calls secure world ONLY   │  │
│  │  SysTick handler     │◄──│  through gateway            │  │
│  │  polls gateway       │──►│  Reads results              │  │
│  └──────────────────────┘   └────────────────────────────┘  │
│         0x10000000                  0x00200000               │
│       (secure flash)              (NS flash)                │
└─────────────────────────────────────────────────────────────┘
         │ (semihosting SYS_OPEN / SYS_READ / SYS_WRITE)
         ▼
   ┌─────────────┐      USB serial       ┌────────────────┐
   │ /dev/ttyACM0│◄─────────────────────►│ TROPIC01 chip  │
   │ (host)      │  115200 8N1 raw       │ (TS1302 devkit)│
   └─────────────┘                        └────────────────┘
```

## Workspace Structure

```
sphincs_rust/
├── Cargo.toml              # Workspace root
├── Makefile                # Build orchestration (secure → veneers → nonsecure → QEMU)
├── rust-toolchain.toml     # Nightly 2026-04-06, thumbv8m.main-none-eabi
│
├── desktop/                # Original USB CLI (std, runs on host)
│   ├── Cargo.toml          #   sphincs-wallet — talks to real TROPIC01 over USB
│   └── src/
│       ├── main.rs         #   enroll + sign commands
│       └── usb_dongle.rs   #   SPI-over-USB transport (embedded_hal::SpiDevice)
│
├── shared/                 # #![no_std] types shared between worlds
│   ├── Cargo.toml          #   zero dependencies
│   └── src/lib.rs          #   NscStatus, size constants, memory addresses
│
├── bip39/                  # #![no_std] BIP-39 24-word mnemonic crate
│   ├── Cargo.toml          #   sha2, hmac, zeroize
│   ├── src/lib.rs          #   Mnemonic, PBKDF2-HMAC-SHA512, prefix lookup
│   ├── src/wordlist.rs     #   Canonical 2048-word English wordlist
│   └── tests/vectors.rs    #   Trezor 24-word test vectors (host-tested)
│
├── secure/                 # TrustZone SECURE world firmware
│   ├── Cargo.toml          #   no_std crypto: slh-dsa, aes-gcm, sha2, hmac, bls12_381, bip39
│   ├── memory.x            #   FLASH 0x10000000 + NSC 0x103FF000 + RAM 0x38000000
│   ├── build.rs            #   Patches link.x to place .gnu.sgstubs in NSC region
│   └── src/
│       ├── main.rs         #   Boot: SAU → first-boot wizard → SysTick → boot NS
│       ├── sau.rs          #   SAU region config + MPC block config
│       ├── boot_ns.rs      #   VTOR_NS + MSP_NS + BXNS
│       ├── nsc.rs          #   Shared-memory gateway (5 commands)
│       ├── crypto.rs       #   KDF, AES-GCM, BIP-39→SLH-DSA seed derivation
│       ├── host_rng.rs     #   Host CSPRNG via semihosting /dev/urandom
│       ├── pin.rs          #   PIN verify via MAC-and-Destroy chain
│       ├── secure_element.rs  # trait SecureElement + MockSecureElement
│       ├── semihosting_spi.rs # SpiDevice impl via semihosting (tropic01-se)
│       ├── tropic01_se.rs     # Tropic01SecureElement with e2e encrypted sessions
│       ├── db_roots.rs        # Generated: ERC20_DB_ROOT + VK_DB_ROOT Merkle roots
│       ├── erc20/             # ERC20 dispatcher + bundle Merkle verifier
│       │   ├── mod.rs            # Public surface
│       │   ├── calldata.rs       # Strict ABI decoder (transfer/transferFrom/approve)
│       │   ├── dispatch.rs       # dispatch_tx() → TxKind trust level
│       │   ├── merkle.rs         # sha256 Merkle proof verifier (shared with VK DB)
│       │   └── bundle.rs         # NS → S metadata bundle parser + verifier
│       ├── zk/                # ZK clear-signing verifier (no_std, no alloc)
│       │   ├── mod.rs            # Module entry + size constants
│       │   ├── groth16.rs        # BLS12-381 Groth16 verifier (4 individual pairings)
│       │   ├── poseidon.rs       # Poseidon hash over BLS12-381 scalar field (alpha=5)
│       │   ├── poseidon_constants.rs  # Auto-generated round constants + MDS matrices
│       │   ├── vk_bundle.rs      # NS → S VK bundle parser + Merkle verifier
│       │   └── test_data/        # vk_bytes.bin, vk_hash.bin (Aave V3 reference VK)
│       └── ui/
│           ├── mod.rs         #   Display + Input + global singletons
│           ├── pin_entry.rs   #   2-button 8-digit PIN entry (+ confirm helper)
│           ├── confirm.rs     #   Multi-page tx confirmation navigator
│           └── seed_wizard.rs #   First-boot mnemonic display / verify / restore
│
├── secure/data/              # Curated source data for dbgen
│   ├── erc20.json            # (chain_id, address, name, symbol, decimals) rows
│   ├── vks.json              # Protocol VK manifest
│   ├── vks/*.vk.bin          # Per-protocol 960-byte Groth16 VKs
│   └── vks.review.txt        # Generated: release-review manifest (sha256 per VK)
│
├── dbgen/                    # Host-side DB + Merkle tree builder
│   ├── Cargo.toml
│   └── src/{main,erc20,vks,merkle}.rs
│
├── zk-test/                  # Host-side end-to-end test for the ZK verifier
│   ├── Cargo.toml            #   bls12_381 + sha2 (host std), no QEMU needed
│   └── src/main.rs           #   Mirrors the secure-world Poseidon + Groth16 path,
│                             #   exercises ZKlarity's proof_supply.json on the host
│
├── tools/
│   └── export_zk_constants.js # Exports Poseidon round constants from
│                              # poseidon-bls12381 (npm) into Rust source
│
└── nonsecure/                # TrustZone NON-SECURE world firmware
    ├── Cargo.toml            #   minimal: cortex-m-rt + semihosting
    ├── memory.x              #   FLASH 0x00200000 + RAM 0x28020000
    ├── build.rs              #   memory.x copy + magic-bytes validator for .bin blobs
    └── src/
        ├── main.rs           #   Interactive test harness
        ├── e2e_test.rs       #   Scripted runner for `make e2e` (feature-gated)
        ├── nsc_api.rs        #   Shared-memory gateway client
        ├── erc20_db.bin      #   Full ERC20 DB (generated by dbgen, include_bytes!d)
        ├── erc20_db.rs       #   NS-side lookup → metadata bundle builder
        ├── vk_db.bin         #   Full ZK VK DB (generated by dbgen)
        └── vk_db.rs          #   NS-side lookup → VK bundle builder
```

## Memory Map (QEMU mps2-an505)

The mps2-an505 has two SSRAM banks. The IDAU uses address bit 28 to distinguish
secure (0x1xxx/0x3xxx) and non-secure (0x0xxx/0x2xxx) aliases of the same physical memory.
The MPC (Memory Protection Controller) provides block-level S/NS attribution within each bank.

### SSRAM-0 (Code, 4 MB)

| Address Range       | Alias | MPC    | Usage                        |
|---------------------|-------|--------|------------------------------|
| `0x10000000-0x101FFFFF` | S     | Secure | Secure world code + rodata   |
| `0x103FF000-0x103FFFFF` | S     | NS     | NSC veneers (.gnu.sgstubs)   |
| `0x00200000-0x003FFFFF` | NS    | NS     | Non-secure world code        |

### SSRAM-1 (Data, 2 MB)

| Address Range       | Alias | MPC    | Usage                        |
|---------------------|-------|--------|------------------------------|
| `0x38000000-0x3801FFFF` | S     | Secure | Secure stack (128 KB)        |
| `0x28020000-0x2803FFFF` | NS    | NS     | Non-secure stack + BSS       |
| `0x2802FF00-0x2802FF14` | NS    | NS     | Shared memory gateway        |

### SAU Regions

| Region | Base         | Limit        | Type | Purpose              |
|--------|-------------|-------------|------|----------------------|
| 0      | `0x00200000` | `0x003FFFFF` | NS   | NS code flash        |
| 1      | veneer_base  | veneer_base+0xFF | NSC  | SG veneers (dynamic) |
| 2      | `0x28020000` | `0x29FFFFFF` | NS   | NS data SRAM         |
| 3      | `0x40000000` | `0x4FFFFFFF` | NS   | NS peripherals       |

Everything not covered by an SAU region defaults to Secure.

### MPC Configuration

| Controller | Register    | Blocks 0-63 | Blocks 64+ |
|-----------|-------------|-------------|------------|
| MPC0      | `0x58007000` | Secure      | NS         |
| MPC1      | `0x58008000` | Secure (0-3) | NS (4+)  |

## Secure Gateway

### Design

The gateway provides 6 operations across the TrustZone boundary:

| Command | ID | NS → S Args | S → NS Result |
|---------|-----|-------------|---------------|
| `GET_REMAINING` | 1 | — | Remaining PIN attempts (u32) |
| `REQUEST_UNLOCK` | 2 | — (PIN entered on trusted UI) | NscStatus |
| `GET_PUBKEY` | 3 | ptr to 32-byte output buf, buf_len | NscStatus |
| `SIGN` | 4 | ptr to has_bundle-wrapped EIP-1559 payload, ptr to 17088-byte sig buf, total_len | NscStatus |
| `CLEAR_SIGN` | 5 | ptr to ZK calldata payload (proof ‖ calldata ‖ string ‖ tx_len ‖ tx ‖ vk_bundle), ptr to sig buf, total_len | NscStatus |
| `CLEAR_SIGN_MSG` | 6 | ptr to EIP-712 payload (proof ‖ canonical ‖ string ‖ vk_bundle), ptr to sig buf, total_len | NscStatus |

The same six `cmd_*::run` handlers run under both transports described
below. Only the trigger differs: the QEMU build reads command + args
out of a shared mailbox in SysTick, and the STM32U585 build enters
them via CMSE SG veneers.

### Transport A: STM32U585 — CMSE veneers (production path)

On real STM32U585 silicon the gateway uses proper ARMv8-M Security
Extension veneers. `secure/src/nsc/mod.rs` exports all six entry
points with `extern "cmse-nonsecure-entry"`:

```rust
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_get_remaining_attempts() -> u32;
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_request_unlock() -> u32;
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_get_pubkey(out_ptr: u32, out_len: u32) -> u32;
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_sign(payload_ptr: u32, sig_out_ptr: u32, total_len: u32) -> u32;
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_clear_sign(payload_ptr: u32, sig_out_ptr: u32, total_len: u32) -> u32;
#[no_mangle]
pub extern "cmse-nonsecure-entry" fn nsc_clear_sign_msg(payload_ptr: u32, sig_out_ptr: u32, total_len: u32) -> u32;
```

All six are gated on `#[cfg(feature = "stm32u585")]`. The secure
`build.rs` runs `--cmse-implib` to emit SG stubs for every one of
them into `target/veneers.o`, which the non-secure crate links
against (`-C link-arg=…/veneers.o`). On the NS side
(`nonsecure/src/nsc_api.rs`) the symbols resolve as plain
`extern "C"` functions:

```rust
extern "C" {
    fn nsc_get_remaining_attempts() -> u32;
    fn nsc_request_unlock() -> u32;
    fn nsc_get_pubkey(out_ptr: u32, out_len: u32) -> u32;
    fn nsc_sign(payload_ptr: u32, sig_out_ptr: u32, total_len: u32) -> u32;
    fn nsc_clear_sign(payload_ptr: u32, sig_out_ptr: u32, total_len: u32) -> u32;
    fn nsc_clear_sign_msg(payload_ptr: u32, sig_out_ptr: u32, total_len: u32) -> u32;
}
```

Each call is a synchronous `BLXNS` → SG stub → secure handler →
`BXNS`. No shared memory, no polling, no SysTick involvement — the
secure `SysTick` handler only services `timeout::tick()` and the
idle-wipe check on this transport. End-to-end sign flows pass under
`make e2e-hw` driving a real ST-LINK/STM32U585AI.

### Transport B: QEMU mps2-an505 — shared-memory mailbox (workaround)

On QEMU mps2-an505 the CMSE `SG` check reads through the MPC NS
alias of the stub block and fails with `SFSR.INVEP` (see "QEMU
Limitations" below). The QEMU build therefore uses a shared mailbox
in NS SRAM driven by secure-side SysTick polling:

```
         NON-SECURE                                SECURE
    ┌───────────────────┐                  ┌──────────────────────┐
    │                   │                  │                      │
    │ 1. Write CMD+args │──────────────►   │                      │
    │    to 0x2802FF00  │  shared memory   │                      │
    │                   │                  │ 2. SysTick fires     │
    │ 3. Spin on DONE   │                  │    poll_gateway()    │
    │    flag           │                  │    reads CMD          │
    │                   │                  │    dispatches         │
    │ 4. Read RESULT    │  ◄──────────────│    writes RESULT     │
    │    from 0x2802FF10│  shared memory   │    sets DONE=1       │
    │                   │                  │                      │
    └───────────────────┘                  └──────────────────────┘
```

Shared memory layout at `0x2802FF00`:

| Offset | Name   | Size | Direction | Description     |
|--------|--------|------|-----------|-----------------|
| +0x00  | CMD    | 4    | NS→S     | Command ID      |
| +0x04  | ARG0   | 4    | NS→S     | Pointer to input data |
| +0x08  | ARG1   | 4    | NS→S     | Pointer to output buffer |
| +0x0C  | ARG2   | 4    | NS→S     | Output buffer length |
| +0x10  | RESULT | 4    | S→NS     | Return value (NscStatus) |
| +0x14  | DONE   | 4    | S→NS     | 1 = result ready |

`init_gateway`, `poll_gateway`, and `dispatch` in
`secure/src/nsc/mod.rs` are all gated
`#[cfg(not(feature = "stm32u585"))]` and exist solely for this
transport. When the `stm32u585` feature is enabled they're compiled
out entirely.

## TROPIC01 Integration

### Semihosting SPI Bridge

The real TROPIC01 chip (TS1302 devkit) connects to the host laptop via USB serial
at `/dev/ttyACM0`. The firmware accesses it through QEMU's ARM semihosting:

1. **SYS_OPEN**: Opens `/dev/ttyACM0` on the host (the host must pre-configure with `stty`)
2. **SYS_WRITE**: Sends hex-encoded SPI commands (same protocol as `desktop/src/usb_dongle.rs`)
3. **SYS_READ**: Reads hex-encoded SPI responses byte-by-byte until `\n`
4. **SPI protocol**: `"A0B1C2x\n"` → chip processes → `"D3E4F5\r\n"`
5. **CS deassert**: `"CS=0\n"` → `"OK\r\n"`

The `SemihostingSpi` struct (`secure/src/semihosting_spi.rs`) implements
`embedded_hal::spi::SpiDevice`, so the `tropic01` crate works unmodified.

### E2E Encrypted Session

Every TROPIC01 operation establishes a fresh Noise_KK1 encrypted session:

```
Secure World                          TROPIC01 Chip
────────────                          ─────────────
1. startup_req(Reboot)          ───►  Chip resets
2. Generate ephemeral X25519          
   keypair (random from               
   host /dev/urandom)                  
3. session_start(                ───►  X25519 handshake
     shpub=SH0PUB_PROD0,              3x DH exchanges
     shpriv=SH0PRIV_PROD0,            AES-GCM auth verify
     ehpub, ehpriv, slot=0)    ◄───  Session keys derived
                                       (Noise_KK1 protocol)
                                       
   === All further commands encrypted with AES-256-GCM ===
   
4. mac_and_destroy(slot, data)   ─E2E─►  HMAC + destroy
5. r_mem_data_read(slot)         ─E2E─►  Read encrypted
6. r_mem_data_write(slot, data)  ─E2E─►  Write encrypted
7. session_abort()               ───►  Zeroize keys
```

The pre-shared pairing keys (`SH0PUB_PROD0`, `SH0PRIV_PROD0`) are compiled into
the secure world firmware. The ephemeral keys are fresh for each session, generated
from `/dev/urandom` via semihosting.

### Batch Operations

The `Tropic01SecureElement` provides batch methods that perform multiple operations
in a single e2e encrypted session, avoiding the overhead of re-establishing a session
for each individual command:

| Method | Operations per session |
|--------|----------------------|
| `batch_enroll()` | N x mac_and_destroy + 3 x r_mem_write |
| `batch_verify_pin()` | r_mem_read + mac_and_destroy + N x mac_and_destroy (re-init) + r_mem_write |
| `batch_read_key_material()` | 2 x r_mem_read |
| `batch_read_pin_state()` | r_mem_read |

### Running with Real TROPIC01

```bash
# 1. Connect TROPIC01 TS1302 devkit via USB
# 2. Configure serial port + build + run:
make run-tropic01

# Or manually:
stty -F /dev/ttyACM0 115200 raw -echo cs8 -cstopb -parenb
make FEATURES=tropic01-se all
make run
```

## Cryptographic Design

### Key Hierarchy

The root of trust is a **24-word BIP-39 mnemonic** chosen on first boot
(generated from the host CSPRNG / chip TRNG, or restored from a piece of
paper). The mnemonic is **never persisted on the device** — it lives only on
the user's paper backup.

The on-device secret blob is the **32-byte BIP-39 entropy** that the 24
words encode. The 48-byte SLH-DSA seed and the SigningKey itself are
**recomputed on every unlock** by re-running the full BIP-39 → SLH-DSA
chain. They never touch persistent storage.

Everything is deterministically derived from the entropy, so the same 24
words always produce the same SPHINCS+ keypair on any device running this
firmware.

```
                  ┌────────────────────────────┐
                  │   24-word BIP-39 mnemonic  │  256 bits of entropy
                  │   (paper backup, NOT on    │  + 8-bit checksum
                  │    device after first boot)│
                  └─────────────┬──────────────┘
                                │  Mnemonic::to_entropy()
                                ▼
            ┌──────────────────────────────────────┐
            │   BIP-39 entropy (32 B)              │
            │   STORED encrypted in r-mem slot 0   │
            │   under wrap_key derived from        │
            │   PIN-gated master_secret            │
            └────────────────┬─────────────────────┘
                             │  Mnemonic::from_entropy()
                             │  + PBKDF2-HMAC-SHA512 (2048 iters)
                             ▼  ───── runs on every unlock ─────
                  ┌────────────────────────────┐
                  │      bip39_seed (64 B)     │  ephemeral, stack-only
                  └─────────────┬──────────────┘
                                │  slhdsa_seed_from_bip39():
                                │  3 × SHA256("sphincs-slh-seed" || s || i)[..16]
                                ▼
                  ┌────────────────────────────┐
                  │ SLH-DSA seed (48 B)        │  ephemeral, stack-only
                  │ sk_seed ‖ sk_prf ‖ pk_seed │
                  └─────────────┬──────────────┘
                                │  slh_keygen_internal() (FIPS-205)
                                ▼
                  ┌────────────────────────────┐
                  │  SigningKey<Sha2_128f>     │  ephemeral, stack-only
                  │  (64 B + Merkle root)      │  zeroized after sign call
                  └────────────────────────────┘

  -- Independently --
  master_secret = SHA256("sphincs-master" || entropy || 0x00)   # at provision
                = decrypted from MACD chain via PIN              # at unlock
  wrap_key      = SHA256("sphincs-wrap-key" || master_secret || 0x00)
  → unwraps the 60-byte AES-GCM blob in r-mem slot 0 to recover entropy
```

**On-device storage** (`RMEM_*` slots in the secure element):

| Slot | Name                     | Contents                                  | Size |
|------|--------------------------|-------------------------------------------|------|
| 0    | `RMEM_ENCRYPTED_ENTROPY` | AES-GCM blob of the 32-byte BIP-39 entropy | 60 B |
| 1    | `RMEM_PIN_STATE`         | next-attempt counter + 10 × per-attempt encrypted master_secret blobs | 481 B |
| 2    | `RMEM_VERIFYING_KEY`     | 32-byte SLH-DSA public key (cached so the host can read it without unlocking) | 32 B |

The mnemonic is **not** in any slot. The 48-byte SLH-DSA seed is **not** in
any slot. Only the raw 32-byte BIP-39 entropy is persisted, which means the
on-device secret is bit-for-bit identical to what the user's paper backup
encodes. PBKDF2 + the slhdsa_seed_from_bip39 KDF run fresh on every
unlock — ~tens of milliseconds, dwarfed by SPHINCS+ signing's seconds.

### PIN Protection (MAC-and-Destroy)

Each PIN attempt consumes one MACD slot (10 slots = 10 attempts max). On correct PIN,
all slots are re-initialized. On 10 wrong PINs, the key is permanently erased ("bricked").

```
Enrollment (per slot j = 0..9):
  1. mac_and_destroy(j, init_input_j)     → initialize slot
  2. mac_and_destroy(j, pin_input_j)      → w_j (slot-specific wrap key)
  3. mac_and_destroy(j, init_input_j)     → re-initialize to known state
  4. encrypted_secrets[j] = AES-GCM(w_j, master_secret)

Verification (slot j = next_index):
  1. mac_and_destroy(j, pin_input_j)      → w_j'
  2. Try AES-GCM decrypt of encrypted_secrets[j] with w_j'
  3. If decrypt succeeds → correct PIN, recover master_secret
  4. If decrypt fails → wrong PIN, increment next_index
```

### Recovery from Seed Phrase

If the device is lost, bricked (9 wrong PINs erase all MACD slots), or
otherwise unusable, the user can restore the wallet on any replacement unit
running the same firmware. The procedure:

1. Power on a fresh / wiped device. The first-boot wizard runs.
2. Choose **"Restore"** instead of **"New Wallet"**.
3. Choose a new PIN (the PIN is local to each device — it gates only the
   on-device encrypted state, not the mnemonic itself, so a recovered device
   uses whatever new PIN the user picks).
4. Type the 24 words from the paper backup using the trusted UI's letter-
   scroll widget. The first 4 letters of every BIP-39 English word are
   unique, so each word usually only needs 3 keystrokes before auto-completing.
   Short words (`act`, `add`, `art`, …) drop into a candidate-pick list when
   the prefix matches multiple longer words.
5. The wizard verifies the BIP-39 checksum and rejects bad phrases.
6. The same `slhdsa_seed_from_bip39` KDF runs and reconstructs an identical
   48-byte SLH-DSA seed. The MACD chain is re-initialized, the encrypted seed
   blob is rewritten, and the verifying key matches the original byte-for-byte.

The recovery contract is the stability of two functions:

```rust
Mnemonic::to_seed("")                       // PBKDF2-HMAC-SHA512, 2048 iters
crypto::slhdsa_seed_from_bip39(&bip39_seed) // domain-separated SHA-256 KDF
```

These are tested by host-side unit tests (`cargo test -p sphincs-tz-bip39`)
against the canonical Trezor test vectors and by an end-to-end QEMU test
that runs the Restore flow twice and confirms the verifying keys match
byte-for-byte.

### Backup Verification

After displaying the 24 words on first boot, the wizard prompts for a
spot-check of **3 randomly-selected words** (e.g. "Enter word 7", "Enter
word 14", "Enter word 21") via the same word-entry widget used for
recovery. The device only finalises provisioning if all three match. This
catches transcription errors before they become permanent — same flow as
Ledger / Trezor. The selected indices come from the host CSPRNG so the
prompts differ between runs.

### SLH-DSA Parameters

| Parameter | Value |
|-----------|-------|
| Algorithm | SLH-DSA-SHA2-128f (FIPS 205) |
| Security level | 128-bit (NIST Level 1) |
| Signing key | 64 bytes |
| Verifying key | 32 bytes |
| Signature | 17,088 bytes |
| Stack during signing | ~20-34 KB |

## Secure Element Abstraction

The `SecureElement` trait abstracts the TROPIC01 API subset used by the wallet:

```rust
pub trait SecureElement {
    fn r_mem_write(&mut self, slot: u16, data: &[u8]) -> Result<(), SeError>;
    fn r_mem_read(&mut self, slot: u16, buf: &mut [u8]) -> Result<usize, SeError>;
    fn r_mem_erase(&mut self, slot: u16) -> Result<(), SeError>;
    fn mac_and_destroy(&mut self, slot: u16, data_in: &[u8; 32]) -> Result<[u8; 32], SeError>;
}
```

| Implementation | Feature | Backend |
|---------------|---------|---------|
| `MockSecureElement` | `mock-se` (default) | In-memory arrays, HMAC-SHA256 for MACD |
| `Tropic01SecureElement` | `tropic01-se` | Real TROPIC01 chip via SPI (bare-metal SPI1/SPI2 on STM32U585, semihosting bridge on QEMU), e2e encrypted |

The mock stores up to 8 r-mem slots (512 bytes each) and 16 MACD slots (32 bytes each).
The real implementation establishes a fresh Noise_KK1 encrypted session per operation batch.

## Build System

### Prerequisites

```bash
rustup toolchain install nightly-2026-04-06
rustup target add thumbv8m.main-none-eabi --toolchain nightly
sudo apt install gcc-arm-none-eabi qemu-system-arm
```

### Build Commands

```bash
# Mock secure element (no hardware needed)
make all                          # Build both worlds with mock SE
make run                          # Build + run in QEMU

# Real TROPIC01 chip (TS1302 devkit at /dev/ttyACM0)
make run-tropic01                 # Configure serial + build + run
make FEATURES=tropic01-se all     # Build only (manual serial setup)
make setup-serial                 # Configure /dev/ttyACM0 only

# Other
make secure                       # Build only secure world
make nonsecure                    # Build only non-secure world
make clean                        # Remove build artifacts
```

### Build Pipeline

```
secure/           arm-none-eabi-ld         nonsecure/
  *.rs  ──────►  --cmse-implib  ──────►    *.rs
  memory.x        --out-implib=             memory.x
                   veneers.o                 +veneers.o
                        │                       │
                        ▼                       ▼
              sphincs-tz-secure.elf    sphincs-tz-nonsecure.elf
                        │                       │
                        └───────────┬───────────┘
                                    ▼
                          qemu-system-arm
                          -M mps2-an505
                          -kernel secure.elf
                          -device loader,file=nonsecure.elf
```

The secure world must build first because the non-secure world links against `veneers.o`
(the CMSE import library containing SG stub addresses). The Makefile uses separate
`--target-dir` for each crate to avoid linker flag conflicts.

### Linker Flags

| Crate | Linker Flags |
|-------|-------------|
| secure | `-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=--cmse-implib -C link-arg=--out-implib=veneers.o` |
| nonsecure | `-C linker=arm-none-eabi-ld -C link-arg=-Tlink.x -C link-arg=veneers.o` |

`arm-none-eabi-ld` is required because Rust's default linker (LLD) does not support CMSE.

## Boot Sequence

```
 1. QEMU starts in secure mode
 2. CPU fetches SP from 0x10000000, reset vector from 0x10000004
 3. cortex-m-rt Reset handler: zero BSS, copy .data
 4. main():
    a. Configure MPC0 (SSRAM-0: blocks 0-63 S, 64+ NS)
    b. Configure MPC1 (SSRAM-1: blocks 0-3 S, 4+ NS)
    c. Configure SAU (4 regions: NS code, NSC veneers, NS data, NS periph)
    d. DSB + ISB barriers
    e. Initialize trusted UI (display + buttons)
    f. is_provisioned()? → if no, run first-boot wizard:
       - User picks (and confirms) a PIN via the trusted UI
       - User chooses "New Wallet" or "Restore"
       - New: 32 B host_rng entropy → BIP-39 24-word mnemonic → display
              paginated → spot-check 3 random words against re-entry
       - Restore: word-by-word entry with 4-letter prefix narrowing
       - master_secret = KDF("sphincs-master", entropy, 0)
       - One-shot full chain (PBKDF2 + slhdsa_seed_from_bip39 + KeyGen)
         to compute the verifying key for caching in slot 2
       - MACD chain initialized, encrypted ENTROPY (not seed) and
         verifying key written to r-mem (mock or TROPIC01 e2e session)
    g. Initialize gateway transport:
         - QEMU: clear shared-memory CMD/RESULT/DONE mailbox words
         - STM32U585: no-op (CMSE veneers are statically linked)
    h. Enable secure SysTick (1 ms interval). On QEMU this drives
       poll_gateway() plus the idle-wipe check; on STM32U585 only
       the idle-wipe check runs.
    i. Set VTOR_NS = 0x00200000
    j. Set MSP_NS from NS vector table[0]
    k. BXNS to NS reset handler
 5. Non-secure world boots via cortex-m-rt
 6. NS main() exercises gateway commands
 7. debug::exit(EXIT_SUCCESS) terminates QEMU
```

## Sign Transaction Flow (End-to-End)

The diagram below uses the QEMU mailbox transport for clarity
(`CMD=…, DONE=1` etc.). On STM32U585 the transition arrows labelled
`──►` / `◄──` are CMSE `nsc_*` veneer calls instead: NS executes
`BLXNS` into the SG stub, the secure handler runs synchronously, and
control returns via `BXNS`. Everything between the two arrows is
identical.

```
NS World                          Secure World                        TROPIC01 Chip
────────                          ────────────                        ─────────────
1. Write PIN to NS SRAM
2. CMD=ENTER_PIN, ARG0=&pin  ──►  [QEMU: SysTick poll / HW: SG stub]
                                  Read PIN from NS memory
                                  [tropic01-se: open e2e session] ──► X25519 handshake
                                  mac_and_destroy(slot, pin_in) ─E2E─► HMAC + destroy
                                  AES-GCM decrypt master_secret
                                  Re-init all MACD slots ────────E2E─► Restore slots
                                  [tropic01-se: close session] ──────► Zeroize keys
                                  RESULT=Ok, DONE=1
3. Read RESULT=Ok            ◄──

4. Write tx_hash to NS SRAM
5. CMD=SIGN, ARG0=&hash,     ──►  [QEMU: SysTick poll / HW: SG stub]
   ARG1=&sig_buf, ARG2=17088     Read tx_hash from NS memory
                                  [tropic01-se: open e2e session] ──► X25519 handshake
                                  Read encrypted ENTROPY (60 B) ─E2E─► r_mem_data_read slot 0
                                  [tropic01-se: close session] ──────► Zeroize keys
                                  Derive wrap_key from master_secret
                                  AES-GCM decrypt → 32 B BIP-39 entropy
                                  Mnemonic::from_entropy(entropy)
                                  PBKDF2-HMAC-SHA512(2048) → 64 B bip39_seed
                                  slhdsa_seed_from_bip39 → 48 B SLH-DSA seed
                                  slh_keygen_internal → SigningKey
                                  slh_dsa::SigningKey::try_sign(tx_hash)
                                  Write 17,088-byte signature to NS sig_buf
                                  Wipe entropy + bip39_seed + slh_seed
                                  + signing key from RAM
                                  RESULT=Ok, DONE=1
6. Read RESULT=Ok            ◄──
   Read 17,088-byte signature
   from sig_buf
```

## ZK Clear Signing

For supported DeFi protocols (Aave V3, CowSwap `setPreSignature`, and
CowSwap EIP-712 `GPv2Order` typed-data signing), the secure world
refuses to display a "human-readable" action string on the trusted UI
unless a **Groth16 zero-knowledge proof** cryptographically certifies
that the string is a faithful interpretation of the raw bytes being
signed. This closes a long-standing trust hole in hardware wallets:
today, the companion app on the host is free to render `swap 1 ETH for
3000 USDC` while the chip is asked to sign a calldata blob that
actually drains the caller's balance to an attacker.

The architecture follows the [ZKNOX clear-signing
proposal](https://zknox.org). The Aave V3 circuit is a byte-identical copy
of [ZKNoxHQ/ZKlarity](https://github.com/ZKNoxHQ/ZKlarity) (see
`circuits/UPSTREAM.md` for provenance and the unresolved license note);
the CowSwap `setPreSignature` circuit is written in-tree under
`circuits/cowswap/set_pre_signature/`, and the M4 EIP-712 GPv2Order
circuit lives at `circuits/cowswap/eip712_order/`. Proving runs
off-device, on either a watchtower service or the user's companion;
the wallet only ever runs the **verifier**, which is small enough
(`#![no_std]`, no `alloc`) to fit inside the secure world.

The wallet supports two distinct sign-time payload shapes:

| Command | Payload | Wraps | Signed bytes |
|---|---|---|---|
| `CMD_CLEAR_SIGN` (5) | proof ‖ calldata(164) ‖ readable(64) ‖ tx_len ‖ EIP-1559 envelope ‖ vk_bundle | EIP-1559 transaction | `keccak256(unsigned_envelope)` |
| `CMD_CLEAR_SIGN_MSG` (6) | proof ‖ canonical(164) ‖ readable(64) ‖ vk_bundle | EIP-712 typed data (no on-chain tx) | `keccak256(0x1901 ‖ domain_separator ‖ struct_hash)` |

The **M4 / EIP-712 path** sidesteps keccak-in-circom by hashing the
canonical bytes with Poseidon inside the circuit and recomputing the
EIP-712 keccak digest natively in the secure world from the **same
164-byte buffer** the proof bound. The circuit only needs to certify
the human-readable summary; the firmware does the EIP-712 keccak
work at zero proving cost. The EIP-712 dispatch is generic: each
protocol implements `Eip712Protocol` in a sibling submodule under
`secure/src/tx/eip712/` and registers itself in the static
`PROTOCOLS` table; adding a second EIP-712 protocol is a sibling
file plus a VK row, no edits to `nsc.rs`. See `secure/src/tx/eip712/` and
**[docs/m4-cowswap-eip712-impl.md](./m4-cowswap-eip712-impl.md)** for
implementation notes; **[docs/m4-cowswap-eip712.md](./m4-cowswap-eip712.md)**
captures the original handoff design sketch.

### Verification chain

The full VK pool lives in **non-secure firmware rodata**
(`nonsecure/src/vk_db.bin`, `include_bytes!`d into the NS image).
The secure world only embeds a single 32-byte Merkle root in
`secure/src/db_roots.rs::VK_DB_ROOT`. At sign time the non-secure
world walks its local index by `(chain_id, contract)`, reads the
matching 960-byte VK + the pre-computed Merkle proof for its leaf
position, and forwards the bundle to the secure world.

```
NS World                                Secure World
────────                                ────────────
1. Local lookup on (chain_id, tx.to)    VK_DB_ROOT [u8; 32]
   in `nonsecure/src/vk_db.rs` →        embedded in secure image
   leaf_index, vk_bytes (960 B),
   merkle_proof[depth × 32 B]

2. Build clear-sign payload:
     [  0..384)   Groth16 proof (π.A ‖ π.B ‖ π.C)
     [384..548)   Aave V3 calldata (164 B, right-zero-padded)
     [548..612)   readable string (64 B, null-padded)
     [612..616)   tx_len (u32 LE)
     [616..)      EIP-1559 tx envelope
     then:
     [bundle_len u32 LE]
     [vk_bundle:
        chain_id (8 B) ‖ contract (20 B) ‖ vk_bytes (960 B)
        ‖ leaf_index (4 B) ‖ proof_depth (4 B)
        ‖ merkle_proof (depth × 32 B)
     ]

3. CMD=CLEAR_SIGN, ARG0=&payload  ──►  SysTick fires
   ARG1=&sig_buf, ARG2=total_len
                                       a. Validate payload pointer + length,
                                          reject overlap with shared mailbox
                                       b. Copy entire payload into a secure-stack
                                          buffer (TOCTOU defense)
                                       c. Parse the EIP-1559 envelope FIRST,
                                          extract chain_id, to, value, data
                                       d. Cross-check:
                                            tx.to.is_some()
                                            tx.value.is_zero()
                                            payload.calldata[..tx.data.len()]
                                               == tx.data
                                            payload.calldata[tx.data.len()..]
                                               == [0; ...] (padding)
                                          FAIL any → CryptoError
                                       e. Re-derive canonical leaf bytes from
                                          the bundle: (chain_id ‖ contract
                                          ‖ vk_bytes)
                                       f. leaf_hash = sha256(0x00 ‖ canonical)
                                          walk the Merkle proof, hashing
                                          pairwise with 0x01 || left || right,
                                          using bit i of leaf_index to pick
                                          left/right at each level
                                          final hash != VK_DB_ROOT → reject
                                          also cross-check bundle.chain_id +
                                          bundle.contract match parsed tx
                                       g. Deserialize the VK (now trusted) and
                                          the proof from the payload
                                       h. H_tx  = Poseidon(calldata, 164)
                                          H_str = Poseidon(readable, 64)
                                          (Poseidon over the BLS12-381 scalar
                                          field, alpha=5, Hades — matches
                                          ZKlarity's poseidon-bls12381 npm
                                          package bit-for-bit)
                                       i. vk_x = IC[0] + H_tx·IC[1] + H_str·IC[2]
                                       j. Verify Groth16 equation:
                                            e(π.A, π.B) · e(-α, β)
                                          · e(-vk_x, γ) · e(-π.C, δ) == 1 ∈ GT
                                          (4 individual pairings — no
                                          multi_miller_loop, so no alloc)
                                          FAIL → CryptoError, "ZK INVALID"
                                          OK   → continue
                                       k. Render `readable` on the trusted UI
                                          (3 pages: header, action string,
                                          confirm prompt). User long-presses
                                          R to confirm or L to cancel
                                       l. Parse + sign the EIP-1559 envelope
                                          (same flow as CMD_SIGN steps 5–10)
                                       m. RESULT=Ok, DONE=1
4. Read RESULT=Ok                ◄──
   Read 17 088-byte signature
   from sig_buf
```

### What this gives you

- **The display is cryptographically bound to the calldata.** The
  Poseidon hashes over the calldata and the readable string are the
  Groth16 public inputs. A proof exists *only* if a circuit-defined
  ABI-interpretation function maps that exact calldata to that exact
  string. Substituting either side invalidates the pairing equation.
- **The VK is authenticated against a secure-flash Merkle root.** The
  full VK pool ships in non-secure rodata, but the secure world only
  trusts a VK after re-deriving the leaf hash from the supplied bytes
  and walking the Merkle proof up to `VK_DB_ROOT`. The trust anchor
  is the firmware-signing key itself — the release reviewer compares
  `secure/data/vks.review.txt` (a build-artifact manifest of
  `(chain_id, contract, sha256(vk))` triples) against on-chain
  governance values before signing the release. Adding a new protocol
  requires a firmware update that bumps the root.
- **The NS side cannot forge a VK substitution.** If a hostile
  non-secure world sends a different VK for a pinned contract, the
  Merkle proof over the substituted bytes won't match the embedded
  root and the request is rejected before Groth16 ever runs.
- **The bundle cannot be replayed for the wrong transaction.** The
  bundle's `(chain_id, contract)` fields are cross-checked against the
  parsed envelope's `tx.chain_id` and `tx.to` after Merkle verification,
  so a valid VK for Aave V3 on Mainnet cannot be attached to a tx
  targeting a different chain or a different contract.
- **The signing key never depends on the proof's correctness.** A
  failing proof returns `CryptoError` *before* the entropy is even read
  from the secure element. The seed and SLH-DSA path are unchanged.

### Why classical, when everything else is post-quantum?

Groth16 and Poseidon over BLS12-381 are **classical** — a CRQC that
breaks the discrete log over BLS12-381's pairing-friendly curves could
forge a Groth16 proof for an arbitrary `(calldata, readable)` pair.

We accept this for now because:

1. **The ZK layer cannot leak the seed.** It only gates *what gets
   displayed before signing*. The classical assumptions are the same as
   they would be without the proof — the user is back to "trust the
   companion's display string".
2. **No PQ ZK proof system fits today.** Hash-based STARKs (Plonky3,
   Risc0) produce proofs that are O(100 KB) and verifiers that need
   alloc; lattice-based SNARKs are not yet practical for circuits the
   size of Aave V3 calldata parsing. The migration target is an
   STARK-based verifier once the proof + verifier sizes fit in the
   firmware budget.
3. **The display string is short-lived.** Even a successful forgery is
   only useful in the few seconds between the user reading the OLED and
   pressing confirm. There is no harvest-now-decrypt-later attack on a
   ZK display proof.

### Sizes (today, Aave V3 supply circuit)

| Field | Size | Notes |
|---|---|---|
| Verification key | 960 B | α(96) + β(192) + γ(192) + δ(192) + IC[0..2](288) — ships in NS rodata |
| Groth16 proof | 384 B | π.A(96) ‖ π.B(192) ‖ π.C(96), uncompressed |
| Calldata window | 164 B | matches ZKlarity circuit `MAX_CALLDATA` |
| Readable string | 64 B | matches ZKlarity circuit `STRING_LEN` |
| VK DB Merkle root | 32 B | embedded in secure flash via `db_roots::VK_DB_ROOT` |
| VK Merkle proof | depth × 32 B | ≤ 32 levels; 5 pinned Aave V3 deployments today → proof_depth ≤ 3 |
| Verify time (host) | ~3.3 ms | measured via `cargo run -p zk-test`; the `bls12_381` crate's pairing in pure Rust |
| Verify time (QEMU) | seconds | dominated by software BLS12-381 pairing on Cortex-M33 |

### Host-side parity test (`zk-test` crate)

`zk-test` is a host-only crate (`std`, real `bls12_381` from crates.io)
that imports the **same** `poseidon_constants.rs` and `test_vectors.rs`
files as the secure world, plus its own private copy of the reference
Aave V3 VK (independent of the firmware DB so it's stable across
Merkle-root changes). It runs the entire verifier chain on
`proof_supply.json` (a real Aave V3 supply proof generated by
ZKlarity's prover) and asserts:

1. Our Poseidon output for a known input matches `poseidon-bls12381`'s
   output bit-for-bit.
2. Groth16 verification of `proof_supply.json` returns true.

This catches divergence between the secure world's Poseidon
implementation and the reference circuit *without* the multi-minute
QEMU emulation cost of running BLS12-381 pairings on a soft-Cortex-M33.

```bash
cargo run -p zk-test --release
# → Poseidon: ok (matches poseidon-bls12381 reference)
# → Groth16 : ok in 3.3ms
```

### Automated end-to-end test (`make e2e`)

`make e2e` is a non-interactive test suite that builds both worlds
with a special `e2e-test` cargo feature and runs the full gateway
flow in QEMU with stdin closed. The feature:

- Replaces the first-boot wizard with deterministic provisioning from
  a fixed test mnemonic (`abandon`×23 + `art`) and PIN `00000000`
- Sets `PIN_VERIFIED` + `MASTER_SECRET` directly so the gateway is
  callable on boot
- Short-circuits every `confirm()` dialog to auto-return `Confirmed`
- Logs the chosen `TxKind` variant for every `cmd_sign` / `cmd_clear_sign`
  so the host harness can assert routing

It walks four scenarios back-to-back and greps the QEMU stdout for
both `[S][e2e] dispatch = <variant>` and `[E2E] <name> = PASS` lines
for every one:

| Scenario | Gateway | Expected TxKind |
|---|---|---|
| value_transfer | `CMD_SIGN` | `ValueTransfer` |
| erc20_known (USDC mainnet, bundle attached) | `CMD_SIGN` | `Erc20Known` |
| blind_sign (Uniswap router selector only) | `CMD_SIGN` | `ContractCall` |
| zk_clear_sign (Aave V3 supply, VK bundle attached) | `CMD_CLEAR_SIGN` | `ZkClearSign` |
| cowswap_pre_sign (GPv2Settlement.setPreSignature, in-tree circuit, VK bundle) | `CMD_CLEAR_SIGN` | `ZkClearSign` |
| cowswap_eip712_order (GPv2Order EIP-712 typed data, in-tree M4 circuit, VK bundle) | `CMD_CLEAR_SIGN_MSG` | `ZkClearSignMsg` |

The runner exits 0 only if every assertion holds. Total runtime
~20 seconds including QEMU's software BLS12-381 pairing.

The `e2e-test` feature is **never** enabled in production builds;
`secure/Cargo.toml` documents it as "NEVER ship in production: it
disables every meaningful trust gate."

### Tool: `tools/export_zk_constants.js`

Generates `secure/src/zk/poseidon_constants.rs` from the
`poseidon-bls12381` npm package's round constants and MDS matrices.
Run only when bumping the upstream package — the generated file is
checked in so the secure-world build does not require Node.js.

## Building the ERC20 + VK databases

The two on-device databases (ERC20 metadata, ZK clear-signing VKs)
are built by the `dbgen` workspace crate from JSON source files
checked into `secure/data/`. This section documents the source
schema, the tooling, the generated artifacts, the trust-anchor
workflow, and the sanity guards. For a quick-start "how do I add a
token" guide see the corresponding section in the top-level README.

### Source-data layout

```
secure/data/
├── erc20.json              # curated ERC20 metadata — sorted by (chain_id, address)
├── vks.json                # VK manifest (one block per protocol + its deployments)
├── vks/                    # raw 960-byte Groth16 verification keys
│   ├── aave_v3_pool.vk.bin
│   └── cowswap_set_pre_signature.vk.bin
└── vks.review.txt          # GENERATED — build-traceability manifest (checked in)
```

VKs are produced by the in-tree Circom pipeline under `circuits/`
(see `circuits/README.md` and `circuits/UPSTREAM.md`). The host-side
driver `tools/build_vks.sh` compiles the `.circom` sources, runs the
`snarkjs` trusted setup, and writes the 960-byte files into
`secure/data/vks/`. `cargo run -p dbgen` then folds them into the
Merkle-rooted firmware DB. The two pipelines are decoupled: `dbgen`
is cargo-only and does not shell out to Node or circom, so a clean
clone with only cargo can rebuild the firmware DB from the committed
`.vk.bin` files.

#### `secure/data/erc20.json`

A JSON array of records, one per `(chain_id, contract)` the wallet
should recognise. All fields are required except `flags`.

```json
[
  { "chain_id": 1, "address": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    "name": "USD Coin", "symbol": "USDC", "decimals": 6 },
  { "chain_id": 8453, "address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    "name": "USD Coin", "symbol": "USDC", "decimals": 6 }
]
```

| Field | Type | Constraint |
|---|---|---|
| `chain_id` | u64 | EIP-155 chain id, matches what the EIP-1559 envelope encodes |
| `address` | hex string | 20 bytes, with or without `0x` prefix; case insensitive |
| `name` | UTF-8 string | 1–255 bytes. `dbgen` hard-errors if longer |
| `symbol` | UTF-8 string | 1–255 bytes |
| `decimals` | u8 | Token decimals used by `U256::format_decimal_fixed` |
| `flags` | u8 (optional, default 0) | Reserved per-entry flags |

#### `secure/data/vks.json`

A JSON array where each element describes one protocol (i.e. one
circuit + VK) plus every chain/contract deployment that shares that
VK. Dedup happens at the protocol level: the Aave V3 Pool circuit
covers four actions (supply / borrow / repay / withdraw) via an
internal `action_type` mux and is identical across
Mainnet/Base/Arbitrum/Optimism/Polygon, so all five deployments ride
on a single 960-byte entry in the VK pool. Similarly the CowSwap
`setPreSignature` VK covers every chain where `GPv2Settlement` is
deployed at the canonical CREATE2 address.

```json
[
  {
    "protocol": "aave-v3-pool-v1",
    "vk_file": "aave_v3_pool.vk.bin",
    "deployments": [
      { "chain_id": 1,     "address": "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2",
        "label": "Aave V3 Pool, Mainnet" },
      { "chain_id": 8453,  "address": "0xA238Dd80C259a72e81d7e4664a9801593F98d1c5",
        "label": "Aave V3 Pool, Base" }
    ]
  },
  {
    "protocol": "cowswap-set-pre-signature-v1",
    "vk_file": "cowswap_set_pre_signature.vk.bin",
    "deployments": [
      { "chain_id": 1,   "address": "0x9008D19f58AAbD9eD0D60971565AA8510560ab41",
        "label": "GPv2Settlement, Mainnet" }
    ]
  }
]
```

`vk_file` is a path relative to `secure/data/vks/` pointing at a raw
960-byte Groth16 VK blob. `dbgen` rejects any file that's not exactly
`VK_BLOB_LEN` bytes (960). The `label` is purely cosmetic and only
appears in the release-review manifest.

### Canonical leaf encoding

The Merkle leaf hash for each entry is `sha256(0x00 || canonical)`,
where `canonical` is the exact byte sequence reconstructed at both
ends of the wire. The dbgen writer emits these bytes into the tree;
the secure-world verifier re-emits the same bytes from the bundle
received via the gateway before hashing. Both implementations share
the layout via `sphincs_tz_shared::db_format` constants.

**ERC20 canonical leaf:**

```
chain_id      u64 LE            (8 B)
contract      [u8; 20]          (20 B)
decimals      u8                (1 B)
name_len      u8                (1 B)
name          [u8; name_len]
symbol_len    u8                (1 B)
symbol        [u8; symbol_len]
```

**VK canonical leaf:**

```
chain_id      u64 LE            (8 B)
contract      [u8; 20]          (20 B)
vk_bytes      [u8; 960]         (960 B)
```

Internal Merkle nodes use `sha256(0x01 || left || right)`. The
`0x00`/`0x01` domain separation prefix stops an attacker who controls
the entry encoding from crafting bytes that look like an
internal-node concatenation, which would otherwise break
second-preimage resistance for the tree.

### dbgen pipeline

`cargo run -p dbgen` (a new workspace member) runs a single
host-side pipeline that produces all four generated outputs:

```
secure/data/erc20.json                     ─┐
                                            ├─► erc20::build_db()
                                            │    ├─ parse + validate rows
                                            │    ├─ sort by (chain_id, contract)
                                            │    ├─ intern name + symbol into pool
                                            │    ├─ compute leaf hashes from canonical encoding
                                            │    ├─ build Merkle tree (pad to pow-2 by dup)
                                            │    └─ emit blob + per-entry proofs
                                            ▼
                                  nonsecure/src/erc20_db.bin   (include_bytes! in NS)
                                  ERC20_DB_ROOT: [u8; 32]      (→ secure/src/db_roots.rs)

secure/data/vks.json                       ─┐
secure/data/vks/*.vk.bin                    ├─► vks::build_db()
                                            │    ├─ load each VK, validate 960 B
                                            │    ├─ dedup VKs by sha256(vk_bytes)
                                            │    ├─ flatten (chain_id, contract) → vk_id
                                            │    ├─ same canonical leaf + Merkle build
                                            │    └─ emit blob + per-entry proofs + review text
                                            ▼
                                  nonsecure/src/vk_db.bin      (include_bytes! in NS)
                                  VK_DB_ROOT: [u8; 32]         (→ secure/src/db_roots.rs)
                                  secure/data/vks.review.txt   (human-reviewable manifest)
```

All four outputs are **checked into the repo** so downstream builds
need only `cargo` (no Node.js, no network access). Rerun `dbgen`
whenever the JSON source changes, and commit the regenerated
outputs alongside the source diff.

### Blob format (generated on-disk layout)

Both blobs share a 32-byte header, a sorted entry array, a
secondary pool (strings for ERC20, VK bytes for VK), and a
per-entry proofs section. Constants live in
`shared/src/db_format.rs`.

**`erc20_db.bin` (`b"ERC2"`):**

```
Header (32 B):
  magic        [u8; 4] = b"ERC2"
  version      u32 LE  = 1
  flags        u32 LE
  entry_cnt    u32 LE
  pool_off     u32 LE    // byte offset of string pool from blob start
  pool_size    u32 LE
  proof_depth  u32 LE    // sibling hashes per proof (= log2(padded n))
  proofs_off   u32 LE    // byte offset of per-entry proofs array

Entries (entry_cnt × 40 B, sorted by (chain_id, contract)):
  chain_id     u64 LE
  contract     [u8; 20]
  name_off     u32 LE     // offset into string pool
  symbol_off   u32 LE
  decimals     u8
  flags        u8
  _pad         [u8; 2]

String pool:
  Length-prefixed: [u8 len][bytes]. Strings are interned at build
  time so "USD Coin" appears once even if 10 chains have a USDC.

Proofs:
  entry_cnt × (proof_depth × 32 B). Proof[i] is the list of sibling
  hashes from leaf i up to the root, ordered leaf-up. The direction
  at each level is implicit from the bits of i.
```

**`vk_db.bin` (`b"VKDB"`):**

Same header shape with `VK_BLOB_LEN = 960`. Entries are 32 B each
(`chain_id`, `contract`, `vk_id: u8`, `vk_sha_pfx: [u8; 3]` — a
defense-in-depth SHA-256 prefix the verifier cross-checks against
the pool entry it indexes). The secondary pool holds `vk_count ×
960` bytes of unique VKs. The `vk_sha_pfx` catches any drift
between the entry's `vk_id` and the pool contents that survived
dbgen's internal checks.

### Round-trip self-test

After writing a blob, `dbgen` immediately opens it through its
host-side mirror of the runtime parser, re-derives the canonical
leaf bytes for every source row, walks the appended Merkle proof up
to the just-computed root, and asserts match. Any drift between the
writer and the reader — which would silently break the secure-world
verifier — fails `dbgen` loudly with a precise error pointing at the
specific row.

The parser mirror lives in `dbgen/src/{erc20.rs,vks.rs}` as
`HostErc20Db` and `HostVkDb`. It deliberately mimics the structure
the **non-secure-side** parser (`nonsecure/src/erc20_db.rs`,
`nonsecure/src/vk_db.rs`) uses so the two can't drift.

### Secure-side Merkle verifier

`secure/src/erc20/merkle.rs` exposes one function, shared by both
DBs:

```rust
pub fn verify_proof(
    canonical: &[u8],
    leaf_index: usize,
    proof_bytes: &[u8],
    proof_depth: usize,
    expected_root: &[u8; 32],
) -> bool;
```

It walks the supplied sibling hashes from `sha256(0x00 || canonical)`
to the root, picking left/right at each level by bit `i` of
`leaf_index`. No heap, no allocation, no panics on bad input — a
bad bundle just returns `false` and the gateway surfaces
`CryptoError` to NS.

### Stale-blob protection

`nonsecure/build.rs` panics at compile time if either of its
`include_bytes!`'d blobs doesn't start with the expected magic. The
common failure mode — "edited `erc20.json`, forgot to run `dbgen`"
— fails the build with a clear "run `cargo run -p dbgen`" message
instead of silently shipping stale data.

```rust
// nonsecure/build.rs
check_db_magic("src/erc20_db.bin", b"ERC2");
check_db_magic("src/vk_db.bin", b"VKDB");
```

The secure-side counterpart is implicit: `secure/src/db_roots.rs`
is generated by `dbgen` as regular Rust source, so any format
mismatch would be caught by the compiler rather than by magic-byte
sniffing.

### Release-review workflow (VK DB only)

`dbgen` also writes `secure/data/vks.review.txt`, a
human-readable manifest that lists the VK DB Merkle root plus every
`(protocol, chain_id, contract, sha256(vk))` triple in the DB:

```
=== ZK Clear-Signing VK Manifest (firmware build artifact) ===
...
Merkle root (VK_DB_ROOT) = 89ccb93ed5034a90b48ae07bc10694e2ab7da74b8f8cef3af840d563b943f12a

aave-v3-pool-v1
  sha256(vk) = f36a73b5bb084a9800ceff63e33e061d182af2b09f6bcef20d441c68fd80292e
  chain      1, contract 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2 (Aave V3 Pool, Mainnet)
  chain   8453, contract 0xA238Dd80C259a72e81d7e4664a9801593F98d1c5 (Aave V3 Pool, Base)
  ...
cowswap-set-pre-signature-v1
  sha256(vk) = 5114d50fc022a64aaa199dec0c130a4b27e859714d5f03ba14ef5a8406c1a236
  chain      1, contract 0x9008D19f58AAbD9eD0D60971565AA8510560ab41 (GPv2Settlement, Mainnet)
  ...
```

**This file is a pure build-traceability artifact.** It records
which `(chain_id, contract, sha256(vk))` triples were folded into
`VK_DB_ROOT` for a given release, so the release reviewer can diff
successive releases and notice any unexpected additions. The trust
chain is entirely offline:

```
firmware-signing key
      ↓  signs
firmware release (containing VK_DB_ROOT in secure flash)
      ↓  anchors
VK_DB_ROOT                          [32 bytes in secure/src/db_roots.rs]
      ↓  Merkle-proves
(chain_id, contract, vk_bytes)      [NS-supplied bundle at sign time]
      ↓  Groth16-verifies
proof π binds calldata → readable   [displayed on trusted UI]
```

There is **no** on-chain `clearSigningVKHash` comparison anywhere in
this project. The wallet trusts its own Merkle root, the reviewer
trusts the firmware-signing key, and neither the firmware nor the
tooling ever reads from an RPC. If a future plan wants to add an
optional governance-comparison script as a reviewer convenience, it
will be a strict opt-in on top of this hardware-only baseline.

Release-signing checklist simply becomes:

```
[ ] git diff secure/data/vks.review.txt
    — confirm that every added or modified row corresponds to a
      Circom circuit you actually intended to add in this release,
      authored in circuits/, and that no unexpected rows appeared.
    — no external lookups required.
```

### Putting it all together

```bash
# 1a. Edit ERC20 source data
$EDITOR secure/data/erc20.json

# 1b. OR: author a new ZK clear-signing circuit and produce its VK
$EDITOR circuits/circuits.json                         # add a row
mkdir -p circuits/myproto/myaction
$EDITOR circuits/myproto/myaction/circuit.circom       # write the circuit
head -c 32 /dev/urandom > circuits/myproto/myaction/contribution.seed
tools/build_vks.sh myproto_myaction                    # compile → .vk.bin
$EDITOR secure/data/vks.json                           # add deployment rows

# 2. Regenerate all four outputs
cargo run -p dbgen

# 3. Review the diff (build-traceability only — no external lookups)
git diff secure/data/vks.review.txt

# 4. Sanity-build both worlds (magic-bytes validator runs here)
make all

# 5. Run the scripted e2e suite
make e2e

# 6. Commit source + all regenerated outputs atomically
git add circuits/ secure/data/ nonsecure/src/{erc20,vk}_db.bin \
        secure/src/db_roots.rs secure/src/zk/vk_data.rs
git commit -m "..."
```

See `circuits/README.md` for the full circuit-authoring workflow
and `circuits/UPSTREAM.md` for the provenance of any Circom sources
imported from third-party repositories.

## QEMU Limitations

### MPC S-Alias Bug (QEMU 8.2.2)

**Symptom:** `SFSR.INVEP` (Invalid Entry Point) SecureFault when NS code branches to
an SG veneer, even though SAU correctly marks the region as NSC and the SG instruction
bytes are verified present.

**Root cause:** QEMU's mps2-an505 model does not allow S-alias reads
(`0x1xxx_xxxx`) of SSRAM blocks marked as NS by the MPC. The SG instruction verification
path reads through this broken path, so it cannot read the SG opcode and reports INVEP.
On real hardware, secure code can access both S and NS memory regardless of MPC settings.

**Workaround:** Shared memory gateway with secure SysTick polling (see
"Transport B" under "Secure Gateway" above). The CMSE veneer path
(Transport A) is used on the STM32U585 build and is exercised end-to-end
under `make e2e-hw` on real silicon — it is only absent from the QEMU
build because of the MPC bug described here.

**Note:** Secure code CAN read/write NS memory through the NS alias
(`0x0xxx_xxxx` / `0x2xxx_xxxx`). Only the S-alias of NS-MPC blocks is broken.

## Porting to STM32U585

When the STM32U585 board arrives:

1. **Memory map:** Update `memory.x` files with STM32U585 flash/SRAM addresses.
   The SAU programming model is identical (standard ARMv8-M). The MPC is replaced
   by STM32's GTZC (Global TrustZone Security Controller).

2. **Gateway:** Done. The STM32U585 build uses proper CMSE veneers
   (`extern "cmse-nonsecure-entry"`) for all six gateway commands; NS
   resolves them as `extern "C"` symbols through `veneers.o`. The
   shared-memory mailbox + SysTick poll path is compiled out on this
   target — see "Transport A" under "Secure Gateway" above.
   `make e2e-hw` runs the full sign-dispatch suite over this path on
   real silicon.

3. **SPI transport:** ~~Replace `SemihostingSpi` with a real `embedded_hal::spi::SpiDevice`
   implementation.~~ **DONE.** Bare-metal `Stm32Spi` driver (`hw/spi_hw.rs` + `hw/spi.rs`)
   implements `SpiDevice` for SPI1 (`spi1-arduino` feature, PE12-PE15 Arduino headers)
   or SPI2 (default, PB12-PB15). The `with_session!` macro auto-selects `Stm32Spi`
   on STM32U585, `SemihostingSpi` on QEMU.

4. **RNG:** Replace semihosting `/dev/urandom` reads in `secure/src/host_rng.rs`
   with the STM32U585's hardware RNG (`embassy_stm32::rng`) or the TROPIC01's
   TRNG (`session.get_random_value(32)`). The `host_rng::fill` and
   `host_rng::byte` API can stay the same — only the implementation changes.
   This RNG feeds:
   * BIP-39 mnemonic generation in the first-boot wizard (32 bytes of entropy)
   * Word indices for the 3-word backup spot check
   * Ephemeral X25519 keypairs for each TROPIC01 e2e session

5. **Key generation:** Already mnemonic-driven. The first-boot wizard
   (`secure/src/main.rs::run_first_boot_wizard`) prompts the user for a PIN
   and a 24-word BIP-39 mnemonic (generated fresh or restored from paper).
   The 48-byte SLH-DSA seed is then derived deterministically via
   `crypto::slhdsa_seed_from_bip39`. Nothing else needs to change for
   STM32U585 — the mnemonic flow runs identically on the real hardware,
   only the RNG backend differs.

6. **Embassy:** Add `embassy-stm32` for async HAL (USB, SPI, GPIO, RNG). Embassy supports
   STM32U585 via feature flag `stm32u585zi`.

## no_std Dependencies

All cryptographic crates run without heap allocation:

| Crate | Version | no_std | Notes |
|-------|---------|--------|-------|
| `slh-dsa` | 0.2.0-rc.4 | `default-features = false` | 17 KB signatures on stack |
| `aes-gcm` | 0.10 | `default-features = false, features = ["aes"]` | In-place encrypt/decrypt |
| `sha2` | 0.10 | `default-features = false` | Used for KDF + PBKDF2-HMAC-SHA512 + ZK VK hash |
| `hmac` | 0.12 | `default-features = false` | Used for mock MACD + PBKDF2 |
| `signature` | 3.0.0-rc.10 | `default-features = false` | Signer/Verifier traits |
| `bls12_381` | 0.8 | `default-features = false, features = ["groups", "pairings"]` | Groth16 ZK clear-sign verifier; 4 individual pairings, no `multi_miller_loop` so no alloc |
| `sphincs-tz-bip39` | local crate | `#![no_std]` | 24-word BIP-39 mnemonic + PBKDF2-HMAC-SHA512, host-tested against canonical Trezor vectors |
| `tropic01` | git (libtropic-rs) | `#![no_std]` | TROPIC01 driver (optional, `tropic01-se` feature) |
| `x25519-dalek` | 2.0.1 | `default-features = false` | X25519 for e2e session (optional) |

## Security Considerations

- **Key isolation:** SPHINCS+ signing key exists in secure SRAM only during the signing
  operation. It is wiped (zeroed + compiler fence) immediately after use.

- **E2E encrypted transport:** All communication between TrustZone secure world and the
  TROPIC01 chip is encrypted with AES-256-GCM over a Noise_KK1 session (X25519 key
  exchange with pre-shared pairing keys). The private key is encrypted at rest
  (AES-GCM wrap in r-mem), encrypted in transit (session encryption), and only
  plaintext in secure SRAM during signing.

- **PIN bricking:** After `MAX_ATTEMPTS` (9) wrong PINs, the encrypted signing key and
  all MACD state are erased from the secure element. Recovery is impossible by design.

- **Pointer validation:** In the gateway, NS pointers should be validated against
  `NS_SRAM_BASE..NS_SRAM_END` before dereferencing. On real hardware, use the TT
  (Test Target) instruction for proper CMSE address validation.

- **Stack budget:** SPHINCS+ signing requires ~20-34 KB of stack (17 KB for the
  `Signature` struct + working memory). The secure world linker script allocates
  128 KB of SRAM with stack growing from the top.

- **Shared memory:** The gateway command buffer is in NS SRAM and is thus writable
  by the non-secure world at any time. The secure handler treats all data read from
  shared memory as untrusted input.

- **Session freshness:** Each TROPIC01 operation batch generates a fresh ephemeral
  X25519 keypair (from `/dev/urandom` on QEMU, hardware RNG on STM32U585), preventing
  session replay attacks.



### From `docs/pq-aa-wallet-design.md`

# Post-Quantum ERC-4337 Wallet: Final Design Spec

A hardware-wallet-backed, seed-phrase-recoverable, post-quantum ERC-4337 account abstraction wallet. Built as a fork of Coinbase Smart Wallet, modified for stateful hash-based PQ signers with unlimited rotations and stable cross-chain addresses.

## Design goals

1. **Stable address across all chains**, forever, regardless of rotation history on any individual chain
2. **Unlimited rotations** of the main signer, recoverable deterministically from the BIP-39 seed phrase
3. **Zero cryptographic contamination** between chains — one chain's signing activity never weakens another's
4. **Crash-consistent state management** — losing the hardware device and recovering on a new one is always safe, with no risk of OTS index reuse
5. **Production compatibility with Gnosis Safe and CowSwap today**, without relying on ERC-6492 adoption
6. **Graceful handling of the stateful hash-based signature budget** (~2^20 signatures per keypair)

---

## Core architectural decisions

### 1. Two-tier signer architecture

The wallet has **two classes of signer**, both derived from the same BIP-39 seed:

- **Bootstrap signer**: a single, stateless PQ keypair (ML-DSA-44 recommended, ~2.4 KB signatures). Used only for administrative operations: initial deployment on each chain, and emergency rotation if state is lost. Never rotates. One key for the lifetime of the wallet.
- **Main signer**: the active signing key for day-to-day transactions on a specific chain. Stateful hash-based (XMSS h=20 or SPHINCS+ few-time 128s). Rotates every ~1M signatures. **Per-chain and per-epoch.**

### 2. Per-chain key derivation

Each chain gets its own independent sequence of main signers, derived via BIP-85 from the seed:

```
bootstrap            = BIP85(seed, m/83696968'/PQ_BOOTSTRAP'/0')
<chain>-main-key_i   = BIP85(seed, m/83696968'/PQ_MAIN'/<chainId>'/<i>')
```

For example:
- `base-main-key_0`     = `m/83696968'/PQ_MAIN'/8453'/0'`
- `base-main-key_1`     = `m/83696968'/PQ_MAIN'/8453'/1'`
- `mainnet-main-key_0`  = `m/83696968'/PQ_MAIN'/1'/0'`
- `arbitrum-main-key_0` = `m/83696968'/PQ_MAIN'/42161'/0'`

Keys on different chains are cryptographically independent. OTS indices on Base can never collide with OTS indices on mainnet because the underlying keypairs are different.

### 3. CREATE2 salt is bootstrap-only

The factory computes the CREATE2 address using **only** the bootstrap public key:

```
salt = keccak256(bootstrapPubKey)
address = keccak256(0xff ‖ factory ‖ salt ‖ keccak256(proxyInitCode))
```

The `proxyInitCode` is a constant ERC-1967 proxy pointing at a fixed implementation slot. **Nothing chain-specific or main-signer-specific goes into the initCode or salt**, so the address is identical on every chain.

### 4. On-chain state per chain

Each chain's deployed wallet stores its own state independently:

```solidity
struct PQSignerStorage {
    bytes32 bootstrapPubKeyHash;   // set at init, immutable
    uint32  currentKeyIndex;       // epoch index: 0, 1, 2, ...
    bytes32 currentMainPubKeyHash; // keccak256(current main signer pubkey)
    uint32  currentOTSIndex;       // next unused OTS leaf for current main key
    uint32  maxOTSIndex;           // 2^20 - 1 = 1,048,575
}
```

The blockchain is the **authoritative state**. The hardware wallet's local OTS counter is a convenience optimization; on any ambiguity, the on-chain value wins.

---

## Factory contract

```solidity
contract PQWalletFactory {
    address public immutable implementation;
    bytes32 public immutable proxyInitCodeHash;

    event WalletDeployed(address indexed wallet, bytes32 indexed bootstrapPubKeyHash);

    constructor(address _implementation) {
        implementation = _implementation;
        // proxy bytecode is a constant ERC-1967 minimal proxy
        proxyInitCodeHash = keccak256(_proxyInitCode());
    }

    /// @notice Deploys a wallet at a deterministic address derived from bootstrapPubKey.
    /// @dev The address is the same on every chain for the same bootstrapPubKey.
    function createAccount(
        bytes calldata bootstrapPubKey,
        bytes calldata initialMainSigner,
        bytes calldata bootstrapSig
    ) external returns (address account) {
        // Verify the bootstrap signature authorizes this initial main signer.
        // Note: no chainId in the signed message — it's intentionally replayable
        // across chains, because the user wants the same initial signer everywhere.
        bytes32 authMsg = keccak256(abi.encodePacked("PQWALLET_INIT_V1", initialMainSigner));
        require(
            _verifyBootstrapSig(bootstrapPubKey, authMsg, bootstrapSig),
            "bad bootstrap sig"
        );

        bytes32 salt = keccak256(bootstrapPubKey);
        account = _deployProxy(salt);

        IPQWallet(account).initialize(bootstrapPubKey, initialMainSigner);

        emit WalletDeployed(account, keccak256(bootstrapPubKey));
    }

    /// @notice Computes the CREATE2 address for a given bootstrap key.
    /// @dev Same inputs → same address on every chain.
    function getAddress(bytes calldata bootstrapPubKey) external view returns (address) {
        bytes32 salt = keccak256(bootstrapPubKey);
        return address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff), address(this), salt, proxyInitCodeHash
        )))));
    }

    function _deployProxy(bytes32 salt) internal returns (address) {
        bytes memory initCode = _proxyInitCode();
        address addr;
        assembly {
            addr := create2(0, add(initCode, 0x20), mload(initCode), salt)
        }
        require(addr != address(0), "create2 failed");
        return addr;
    }

    function _proxyInitCode() internal view returns (bytes memory) {
        // Constant ERC-1967 proxy with `implementation` baked in via immutable
        // (not storage), so the initCode depends only on `implementation`.
        // Returned bytes are identical on every chain where this factory is
        // deployed at the same address with the same implementation.
        // ... standard ERC-1967 proxy bytecode ...
    }

    function _verifyBootstrapSig(
        bytes calldata pubKey,
        bytes32 message,
        bytes calldata sig
    ) internal view returns (bool) {
        // Verify ML-DSA-44 signature (or whatever bootstrap scheme is chosen).
        // Likely a call to a verifier library or precompile (EIP-8051 when available).
    }
}
```

### Why the bootstrap signature is required and chain-agnostic

- **Required**: without it, a front-runner who sees your `bootstrapPubKey` (public, in the salt) could deploy your wallet on a chain you haven't touched yet, initialized with *their* chosen main signer. You'd recover via bootstrap-authorized rotation, but it wastes gas and creates an ugly race.
- **Chain-agnostic**: the signed message deliberately omits `chainId`. This lets the user produce *one* bootstrap signature over `initialMainSigner` and use it on every chain they ever deploy to. A replayed signature on a new chain is not a threat — it can only deploy the wallet with the *exact* main signer the user chose, which is what they wanted anyway.

---

## Wallet contract

```solidity
contract PQWallet is IPQWallet, BaseAccount {
    // ERC-7201 namespaced storage
    bytes32 private constant STORAGE_SLOT =
        keccak256(abi.encode(uint256(keccak256("pqwallet.storage.v1")) - 1))
        & ~bytes32(uint256(0xff));

    struct Storage {
        bytes32 bootstrapPubKeyHash;
        uint32  currentKeyIndex;
        bytes32 currentMainPubKeyHash;
        uint32  currentOTSIndex;
        bool    initialized;
    }

    uint32 constant MAX_OTS = (1 << 20) - 1;

    event MainSignerRotated(uint32 indexed newKeyIndex, bytes32 indexed newPubKeyHash);
    event OTSConsumed(uint32 indexed keyIndex, uint32 indexed otsIndex);

    modifier onlySelf() {
        require(msg.sender == address(this), "only self");
        _;
    }

    function initialize(
        bytes calldata bootstrapPubKey,
        bytes calldata initialMainSigner
    ) external {
        Storage storage s = _s();
        require(!s.initialized, "already init");
        s.initialized = true;
        s.bootstrapPubKeyHash = keccak256(bootstrapPubKey);
        s.currentKeyIndex = 0;
        s.currentMainPubKeyHash = keccak256(initialMainSigner);
        s.currentOTSIndex = 0;
    }

    /// @notice Rotate the main signer. Authorized by EITHER the current main
    /// signer (normal rotation) OR the bootstrap signer (recovery rotation).
    function rotateMainSigner(
        uint32 newKeyIndex,
        bytes calldata newMainPubKey
    ) external onlySelf {
        Storage storage s = _s();
        require(newKeyIndex == s.currentKeyIndex + 1, "sequential only");

        s.currentKeyIndex = newKeyIndex;
        s.currentMainPubKeyHash = keccak256(newMainPubKey);
        s.currentOTSIndex = 0;

        emit MainSignerRotated(newKeyIndex, s.currentMainPubKeyHash);
    }

    /// @notice ERC-4337 validation. Accepts signatures from either the current
    /// main signer or the bootstrap signer.
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal override returns (uint256) {
        Storage storage s = _s();
        PQSignatureWrapper memory wrapper = abi.decode(userOp.signature, (PQSignatureWrapper));

        if (wrapper.signerType == SignerType.MAIN) {
            // Normal path: stateful PQ signature from current main signer
            require(wrapper.keyIndex == s.currentKeyIndex, "wrong key epoch");
            require(wrapper.otsIndex == s.currentOTSIndex, "wrong ots index");
            require(wrapper.otsIndex <= MAX_OTS, "key exhausted");
            require(
                keccak256(wrapper.pubKey) == s.currentMainPubKeyHash,
                "pubkey mismatch"
            );

            bool ok = _verifyStatefulPQ(
                wrapper.pubKey,
                userOpHash,
                wrapper.otsIndex,
                wrapper.signature
            );
            if (!ok) return SIG_VALIDATION_FAILED;

            // Consume the OTS index atomically with validation success
            s.currentOTSIndex = wrapper.otsIndex + 1;
            emit OTSConsumed(s.currentKeyIndex, wrapper.otsIndex);

            return 0;
        } else if (wrapper.signerType == SignerType.BOOTSTRAP) {
            // Admin path: stateless PQ signature from bootstrap signer
            require(
                keccak256(wrapper.pubKey) == s.bootstrapPubKeyHash,
                "bootstrap mismatch"
            );
            bool ok = _verifyStatelessPQ(wrapper.pubKey, userOpHash, wrapper.signature);
            return ok ? 0 : SIG_VALIDATION_FAILED;
        }

        return SIG_VALIDATION_FAILED;
    }

    /// @notice EIP-1271 for Safe and CowSwap compatibility (when deployed).
    function isValidSignature(bytes32 hash, bytes calldata signature)
        external view returns (bytes4)
    {
        // Verify against current main signer OR bootstrap.
        // For large PQ signatures, prefer ZK-wrapped proofs here to keep size
        // compatible with Safe/CowSwap calldata limits.
        // ...
        return 0x1626ba7e;
    }

    function _s() private pure returns (Storage storage s) {
        bytes32 slot = STORAGE_SLOT;
        assembly { s.slot := slot }
    }

    function _verifyStatefulPQ(
        bytes memory pubKey,
        bytes32 message,
        uint32 otsIndex,
        bytes memory sig
    ) internal view returns (bool) {
        // XMSS or SPHINCS+ few-time verification.
        // Likely wrapped as a ZK proof of validity to fit in validateUserOp's
        // gas budget — raw verification is 4.4M gas (XMSS) or 11.6M gas (SPHINCS+),
        // both over the practical bundler limit.
    }

    function _verifyStatelessPQ(
        bytes memory pubKey,
        bytes32 message,
        bytes memory sig
    ) internal view returns (bool) {
        // ML-DSA-44 verification. Cheap enough to do inline once EIP-8051
        // precompile lands; until then, use a verifier library or ZK wrapper.
    }
}
```

---

## Key derivation spec

All keys derive from a single BIP-39 seed phrase (24 words recommended for post-quantum security margin) via BIP-85.

```
Application ID: 83696968' (standard BIP-85 prefix)

Bootstrap signer (global, never rotates):
    m/83696968'/PQ_BOOTSTRAP'/0'
    → ML-DSA-44 keygen seed → (bootstrap_sk, bootstrap_pk)

Main signers (per-chain, per-epoch):
    m/83696968'/PQ_MAIN'/<chainId>'/<keyIndex>'
    → XMSS or SPHINCS+ few-time keygen seed → (main_sk_i, main_pk_i)
```

Recommended constants (pick final values before deployment; they become permanent):
- `PQ_BOOTSTRAP` = `0x50510001'` (or similar, any unused BIP-85 app code)
- `PQ_MAIN`      = `0x50510002'`

BIP-85 derivation produces 64 bytes of entropy per path; use as the seed input to the PQ scheme's deterministic KeyGen.

---

## Operational flows

### Flow A: first-time deployment on a new chain

```
User action: "Use my wallet on chain X for the first time"

1. Companion app derives:
     - bootstrap_pk (from seed)
     - chainX-main-key_0 (from seed, using chainId X)
2. Companion app computes wallet address via factory.getAddress(bootstrap_pk)
3. User confirms bootstrap-authorized deployment on hardware wallet
4. Hardware wallet produces bootstrap signature over:
     keccak256("PQWALLET_INIT_V1" ‖ chainX-main-key_0)
   (Same signature is valid on every chain, can be cached.)
5. Companion app submits UserOp on chain X:
     initCode = factory.createAccount(
         bootstrap_pk,
         chainX-main-key_0,
         bootstrapSig
     )
     callData = <optional first action, e.g. setPreSignature for CowSwap>
6. Bundler deploys + optionally executes the first action atomically
7. Wallet state on chain X:
     bootstrapPubKeyHash  = keccak256(bootstrap_pk)
     currentKeyIndex      = 0
     currentMainPubKeyHash = keccak256(chainX-main-key_0)
     currentOTSIndex      = 0
```

### Flow B: normal rotation (main signer exhausted on chain X)

```
Trigger: currentOTSIndex approaches MAX_OTS (e.g., 1,048,000 of 1,048,575)

1. Companion app reads state from chain X
2. Hardware wallet derives chainX-main-key_<i+1> from seed
3. Construct rotation UserOp signed by current main signer at the next OTS index:
     callData = rotateMainSigner(i+1, chainX-main-key_<i+1>)
     signature = stateful PQ sig from chainX-main-key_i at OTS index currentOTSIndex
4. Submit to bundler; wallet state updates to:
     currentKeyIndex      = i+1
     currentMainPubKeyHash = keccak256(chainX-main-key_<i+1>)
     currentOTSIndex      = 0
5. Old chainX-main-key_i is now permanently retired for this chain
```

### Flow C: hardware wallet lost, recover on new device, continue on same chain

```
Scenario: user was at currentKeyIndex=1, currentOTSIndex=432117 on Base

1. User enters seed phrase on new hardware wallet
2. Companion app reads Base state via eth_getStorageAt:
     currentKeyIndex=1, currentOTSIndex=432117, currentMainPubKeyHash=H
3. New device derives base-main-key_1 from seed (deterministic, same as old)
4. Sanity check: keccak256(base-main-key_1) must equal H ✓
5. Set local OTS counter to 432117
6. Resume signing; next signature uses OTS index 432118
7. (Optional paranoia rotation: if old device may be stolen, immediately
    submit a rotation UserOp to base-main-key_2 to invalidate the old device)
```

### Flow D: hardware wallet lost, recover on new device, use on a DIFFERENT chain for the first time

```
Scenario: user had Base wallet (already rotated to key_1), loses device,
           recovers, wants to transact on mainnet (never deployed there)

1. User enters seed phrase on new hardware wallet
2. Companion app checks mainnet: eth_getCode(walletAddress) = 0x → not deployed
3. Derive from seed:
     - bootstrap_pk
     - mainnet-main-key_0  (NEVER been used anywhere — fresh key)
4. Hardware wallet produces bootstrap signature over mainnet-main-key_0
5. Deploy on mainnet via factory.createAccount(
       bootstrap_pk, mainnet-main-key_0, bootstrapSig)
6. Wallet address on mainnet = wallet address on Base ✓
     (both derived from keccak256(bootstrap_pk))
7. Mainnet state initializes to:
     currentKeyIndex=0, currentMainPubKeyHash=keccak256(mainnet-main-key_0),
     currentOTSIndex=0
8. Base remains completely independent: still at key_1, still ticking along
9. Zero cross-contamination: mainnet's key_0 has never signed anything on Base,
    so there's no OTS reuse risk even in principle
```

### Flow E: emergency state recovery (on-chain state suspected corrupt)

```
Scenario: unclear what currentOTSIndex is, or suspect a race condition

1. Companion app reads on-chain state; if state looks suspicious:
2. User authorizes bootstrap-level rotation
3. Hardware wallet derives chainX-main-key_<current+1> from seed
4. Bootstrap-signed UserOp calling rotateMainSigner(current+1, new_pk)
5. Wallet advances to next key epoch, resetting currentOTSIndex to 0
6. Any ambiguity about old state is now moot — old key is retired
```

---

## Bootstrap key security properties

The bootstrap key is powerful: it can rotate the main signer on any chain without the current main signer's cooperation. Treat it accordingly:

- **Never leaves the hardware wallet**. Derived fresh from seed each use.
- **Explicit UX on every use**: "You are authorizing an administrative operation that can move your wallet to a new signer. This should only happen during first deployment on a chain or emergency recovery."
- **Stateless**, so state loss is never a bootstrap security issue — no OTS counter to corrupt.
- **Optional timelock** (recommended for high-value wallets): bootstrap-authorized rotations take effect after N hours, with a cancel-by-main-signer escape hatch. Gives you a window to notice and cancel if the seed is compromised.
- **Different crypto family from main signer** (ML-DSA vs. hash-based): a cryptanalytic break in one family doesn't compromise the other. This is a valuable hedge given the relative youth of PQ schemes.

---

## EIP-1271 / Safe / CowSwap integration

### Deployment detection

```typescript
async function isDeployed(provider: Provider, walletAddress: string): Promise<boolean> {
    const code = await provider.getCode(walletAddress);
    return code !== '0x' && code.length > 2;
}
```

Check per chain. Never rely on EntryPoint queries (deposits can exist without deployment).

### CowSwap: setPreSignature pattern (recommended)

Avoid passing PQ signatures through CowSwap entirely. When the user places a CowSwap order:

1. Ensure wallet is deployed on the chain (deploy via Flow A if not)
2. Submit a UserOp: `wallet.execute(GPv2Settlement, 0, abi.encodeCall(setPreSignature, (orderUid, true)))`
3. The UserOp's signature is a normal PQ signature (main signer), verified inside `validateUserOp` only
4. CowSwap's settlement sees a PreSign flag, not a signature — it checks `preSignature[orderUid] == PRE_SIGNED`
5. CowSwap API receives just the 20-byte wallet address as "signature"

This completely sidesteps large PQ signature compatibility issues with CowSwap.

### Gnosis Safe: signMessage pattern (recommended)

For Safe transactions where the PQ wallet is a signer on a Safe:

1. Ensure PQ wallet is deployed on the chain
2. Submit a UserOp: `wallet.execute(safeAddress, 0, abi.encodeCall(Safe.signMessage, (msgHash)))`
3. Safe marks the hash as signed in its own storage
4. When the Safe transaction executes, Safe's `checkSignatures` sees the pre-approved hash and accepts it
5. The PQ signature is verified only once, inside the PQ wallet's `validateUserOp` — never passed to the Safe

### Direct EIP-1271 (fallback, for off-chain gasless flows)

When a protocol absolutely requires `isValidSignature` to be called and there's no on-chain pre-approval path:

1. The PQ wallet must be deployed on the target chain
2. `isValidSignature` verifies a **ZK proof** of PQ signature validity, not the raw PQ signature
    - Groth16 proof: ~128–200 bytes, cheap verification
    - STARK proof: larger but post-quantum secure
3. The ZK proof fits comfortably in Safe's ~64 KB practical signature limit
4. Raw PQ signatures (7.8–50 KB) would exceed practical Safe/CowSwap signature size limits and should never be passed directly

---

## Cross-chain deployment cost summary

| Chain    | Deployment gas | Cost at typical gas price |
|----------|---------------|---------------------------|
| Mainnet  | ~200,000      | ~$1–3 at 30 gwei          |
| Base     | ~200,000      | <$0.01                    |
| Arbitrum | ~200,000      | <$0.01                    |
| Optimism | ~200,000      | <$0.01                    |

Can be bundled with the first real action (e.g., a CowSwap setPreSignature) to save a transaction.

---

## Signature scheme selection

### Main signer (stateful, rotates)

**Recommended: SPHINCS+ few-time 128s** with parameters (n=16, h=17, d=1, log(t)=20, k=8, w=16)
- Signature size: ~3.4 KB
- Public key: 32 bytes
- Signature budget: ~2^20 per keypair
- Graceful degradation on OTS overuse (safer than XMSS if state is lost)

**Alternative: XMSS with h=20**
- Signature size: ~2.75 KB
- Public key: 68 bytes
- Signature budget: exactly 2^20 per keypair
- Catastrophic failure on OTS reuse — only choose if you have high confidence in state management

On-chain verification cost is prohibitive for both (4.4M/11.6M gas). Wrap verification in a ZK-STARK proof (~200–500K gas) for `validateUserOp` compatibility.

### Bootstrap signer (stateless, global)

**Recommended: ML-DSA-44 (Dilithium2)**
- Signature size: ~2.4 KB
- Public key: ~1.3 KB
- NIST standardized (FIPS 204)
- Lattice-based (different family from main signer — hedge against hash-based breaks)
- Verification fast enough for direct on-chain use when EIP-8051 precompile lands

**Alternative: SPHINCS+-128s (standard, not few-time)**
- Signature size: ~7.8 KB
- Same hash-based family as main signer (less hedging value)
- Larger signatures but simpler crypto review

---

## Implementation checklist

- [ ] Fork Coinbase Smart Wallet (`coinbase/smart-wallet`)
- [ ] Replace `MultiOwnable` with `PQSignerStorage` layout
- [ ] Implement `_validateSignature` with dual-path (main/bootstrap) logic
- [ ] Implement `rotateMainSigner` with `onlySelf` modifier
- [ ] Implement `isValidSignature` for EIP-1271 (ZK-wrapped verification)
- [ ] Write `PQWalletFactory` with bootstrap-signature-gated `createAccount`
- [ ] Use ERC-1967 proxy with immutable implementation to keep initCode constant
- [ ] Verify CREATE2 addresses match across chains in testing (deploy to at least 3 testnets, confirm identical addresses)
- [ ] Build the PQ verifier library (or ZK circuit) for the chosen main signer scheme
- [ ] Build the ML-DSA verifier library (or wait for EIP-8051)
- [ ] Define BIP-85 app codes for `PQ_BOOTSTRAP` and `PQ_MAIN`; document them permanently
- [ ] Hardware wallet firmware: implement BIP-85 derivation, XMSS/SPHINCS+ signing, ML-DSA signing, OTS counter sync from chain
- [ ] Companion app: deployment detection per chain, factory deployment flow, rotation flow, recovery flow
- [ ] Companion app: CowSwap setPreSignature integration
- [ ] Companion app: Safe signMessage integration
- [ ] Test Flow D extensively — cross-chain first-deployment after rotation on another chain is the most subtle path
- [ ] Security audit focused on: OTS reuse scenarios, front-running on new chains, bootstrap key exposure, ZK circuit soundness
- [ ] Consider timelock on bootstrap-authorized rotations for high-value deployments

---

## Open questions to resolve before mainnet

1. **Exact main signer scheme**: final parameter selection for SPHINCS+ few-time vs. XMSS. Pending completion of the C reference implementation.
2. **ZK wrapping strategy**: Groth16 (smaller proofs, trusted setup) vs. STARK (no trusted setup, post-quantum secure, larger proofs). STARK is philosophically better aligned with a PQ wallet.
3. **EIP-8051 timing**: if ML-DSA precompile lands before mainnet, bootstrap verification becomes nearly free and the design simplifies.
4. **Timelock default**: should bootstrap-authorized rotations have a default timelock? What's the right duration? (Suggestion: 24h default, user-configurable, 0h for low-value wallets.)
5. **Chain ID collisions**: the per-chain derivation path uses `chainId` — what happens if a chain forks and creates a duplicate? (Unlikely but worth specifying: the wallet commits to a specific chainId at deploy time via its state, so a fork creates two independent states naturally.)



### From `docs/HARDENING.md`

# Hardware Wallet Hardening Requirements

**Project:** SPHINCS+ hardware wallet on STM32U585 (B-U585I-IOT02A) + NXP EdgeLock SE050, Rust, TrustZone-M.

**Purpose:** Consolidated security requirements and invariants. Every item here is load-bearing. Skipping any of them weakens the whole chain.

---

## 1. Threat Model (Write This Down First)

Before writing code, commit to an explicit threat model. The design below targets:

- **In scope:** remote/software attackers, firmware exploits, stolen powered-off device, bus snooping, casual physical access, skilled physical attacker with bench equipment during or shortly after a legitimate unlock.
- **Out of scope (acknowledge explicitly):** nation-state lab attackers with unlimited FIB/SEM budget, coerced unlock (rubber-hose, shoulder-surf), supply-chain compromise of silicon vendors.
- **Partially mitigated:** fault injection, cold-boot attacks on SRAM, SE050 die-level invasive attacks.

Document your trust boundaries, your list of secrets, and where each secret is allowed to exist (which chip, which memory region, which lifetime). Enforce those invariants in the Rust type system.

---

## 2. Architecture Invariants

### 2.1 Secret Residency Rules

| Secret | Lives in | Never allowed in |
|---|---|---|
| BIP-39 entropy / seed | SE050 at rest; U585 Secure SRAM briefly during signing | U585 flash, NS world, logs, debug output |
| SPHINCS+ `SK.seed`, `SK.prf`, `PK.seed` | U585 Secure SRAM briefly during signing | Anywhere persistent on U585, NS world |
| SCP03 static keys | U585 Secure flash, HUK-wrapped | Plain flash, NS world, any unwrapped form outside SAES operations |
| PIN (raw) | U585 Secure SRAM for microseconds during stretching | Anywhere else, ever |
| Stretched PIN (AESKey credential) | U585 Secure SRAM for one SCP03 handshake | Persistent storage, NS world |
| SE050 attestation root cert | U585 Secure flash (hardcoded in image) | N/A (public) |

### 2.2 World Separation

- **Secure world owns:** I²C driver to SE050, SCP03 state, PIN stretching, SPHINCS+ implementation, all secret handling, the inactivity timer, the wipe routine.
- **Non-Secure world owns:** UI, keypad/touch, display, network (if any), everything else.
- **NSC boundary:** minimal surface. Entry points accept opaque requests (sign this hash, unlock with this PIN) and return only non-secret outputs (signatures, success/failure, public keys).

### 2.3 The Seed Never Crosses to NS

There is no legitimate NSC call that returns the seed, the mnemonic, the SPHINCS+ secret key, or any derivative from which they can be recovered. If you find yourself writing one, stop and redesign.

---

## 3. SE050 Configuration

### 3.1 Authentication Object

- Type: **AESKey** (not UserID — UserID is plaintext on the I²C bus).
- `TAG_MAX_ATTEMPTS = 10`. Must be non-zero; zero means infinite.
- Credential is the *stretched* PIN output, never the raw PIN.
- Counter is pre-decremented in flash before verify — power-pull during verify does not grant a free retry.

### 3.2 Seed Storage Object

- Type: Binary file object containing the 16–32 bytes of BIP-39 entropy.
- Policy: `ALLOW_READ` **only** when authenticated by the specific Auth Object ID above.
- Policy: **no** access for Auth Object ID `0x00000000` (the "any user" pseudo-ID).
- Policy: **no** `ALLOW_WRITE` or `ALLOW_DELETE` except for a distinct admin auth object used only during provisioning.
- Consider storing the precomputed SPHINCS+ `PK.root` in a separate non-secret binary object to avoid recomputing on every boot.

### 3.3 Channel

- **SCP03** via AESKey or ECKey (FastSCP) auth. Prefer ECKey for cleaner at-rest posture (no shared symmetric secret in U585 flash).
- All communication with the SE050 after boot attestation must run inside an SCP03 session. No plaintext APDUs touching secrets, ever.

### 3.4 Boot-Time Attestation

On every boot, before trusting the SE050:

1. Generate a fresh random nonce in Secure world (from U585 TRNG or SE050 RNG — do not reuse).
2. Request an attested signature over the nonce using the SE050's NXP-provisioned attestation key.
3. Verify the signature chains to NXP's root certificate, hardcoded in the Secure image.
4. Verify the SE050's unique ID matches the value pinned at provisioning time. A genuine-but-different SE050 must be rejected.
5. Only then open the SCP03 session.
6. On any failure: refuse to proceed, display a tamper warning, do not accept a PIN.

### 3.5 Provisioning

- Rotate the SE050 factory-default SCP03 platform keys to device-unique keys **before the device leaves your facility**.
- Create the PIN auth object, seed binary object, and all policies in the same authenticated provisioning session.
- Wrap the new SCP03 keys with the U585's HUK-derived key via SAES and write the ciphertext to Secure flash in the same provisioning step.
- Pin the SE050 unique ID to U585 Secure flash.
- Apply SE050 transport lock if applicable to your variant.
- Enable U585 RDP Level 2 as the final production step. **This is irreversible; do it last.**
- Consider NXP EdgeLock 2GO if you need to provision at volume.
- Provisioning must run in a clean-room environment. A compromised provisioning station compromises every device that passes through it.

---

## 4. STM32U585 Configuration

### 4.1 TrustZone & Memory Protection

- Enable TrustZone. Configure SAU and IDAU to partition flash, SRAM, and peripherals.
- **GTZC configuration is the #1 source of TrustZone-M leaks.** Budget real time for it and have it reviewed.
- Mark as Secure: I²C to SE050, TIM used for inactivity timer, TAMP, SAES, PKA, HASH, TRNG, BKPSRAM holding secrets.
- Block **all** DMA controllers from mastering into Secure SRAM unless the DMA instance is itself Secure.
- MPU regions covering Secret SRAM must be enforced in both S and NS worlds.

### 4.2 Debug & Readout Protection

- **RDP Level 2** in production. Final step before shipping. Irreversible.
- Debug ports (SWD, JTAG) disabled by RDP-2.
- Boot from internal flash only. Disable bootloader access in option bytes.
- Verify the RDP level in boot code; refuse to run if debug build flags are set in a production image.

### 4.3 At-Rest Key Protection

- SCP03 keys (or ECKey private key) stored **wrapped** in Secure flash.
- Wrapping key is derived from the U585 HUK via SAES; the wrapping key itself never leaves the SAES peripheral.
- A flash dump transplanted to another U585 must be useless.
- The wrapped blob lives in a Secure flash region governed by GTZC.

### 4.4 Hardware Peripherals to Use

- **TRNG**: for all nonces, challenges, and any randomness. Audit that `rand_core` is wired to this, not to a software PRNG.
- **HASH**: for SHA-256 acceleration inside SPHINCS+ (pick the SHA2 parameter set specifically to benefit from this).
- **SAES**: for HUK-wrapped key operations.
- **TAMP**: wire any tamper inputs (case switch, mesh) into the wipe handler.
- **BOR**: set to a high threshold so brownout detection fires with enough headroom for the wipe ISR.

### 4.5 Inactivity Timer (2-Minute Seed Wipe)

- Timer runs on a **Secure** TIM instance. NS world cannot stop, reprogram, or observe it.
- "Activity" is defined by Secure world (e.g., completed signing operation). NS world opinion is ignored; a compromised NS image cannot keep the seed alive by spamming fake activity.
- On timeout: fire the wipe routine.
- Also fire the wipe on: tamper event, unexpected reset reason, low-power mode entry, integrity check failure, any NSC call returning an error, brownout interrupt.

### 4.6 Power-Loss Wipe

- External supervisor or programmable BOR trips above the minimum operating voltage, with enough margin for the wipe ISR to complete.
- Bulk capacitor sized to hold the U585 through the worst-case ISR runtime under full load. **Measure this on real hardware; don't estimate.**
- Wipe ISR: zeroize Secret SRAM regions, clear caches, clear CPU registers, write a "clean shutdown" flag.
- Wipe ISR is written defensively: loop twice, verify after, use DMA/SAES for bulk clearing if faster than software loop.
- Same ISR handler is invoked by TAMP events.

### 4.7 Temperature Sensing

- Use the internal temperature sensor to refuse operation below (e.g.) 0°C, mitigating cold-boot attacks that freeze SRAM to extend retention.
- Check temperature on boot and periodically during operation.

---

## 5. PIN Handling

### 5.1 Flow

1. NS UI collects PIN digits, passes a byte buffer into a Secure NSC entry point.
2. Secure world copies the PIN into a Secure-only buffer, zeroizes the NS-facing buffer immediately.
3. Secure world computes `PIN_key = KDF(PIN, device_salt)` where:
   - KDF is PBKDF2-HMAC-SHA256 with a high iteration count.
   - `device_salt` is a random per-device value stored on the SE050 as a non-secret binary object.
4. `PIN_key` is used as the AESKey credential to open an SCP03 session against the SE050's PIN auth object.
5. On success: read the seed binary object inside the SCP03 session.
6. Zeroize `PIN_key` and the raw PIN immediately after the SCP03 handshake completes.

### 5.2 Stretching Requirements

- Iteration count / memory parameter sized so that a single PIN guess takes hundreds of milliseconds on the U585. Users will feel it; that's the point.
- Even if the SE050's retry counter is somehow bypassed, per-guess CPU cost makes offline brute force painful.
- The stretched value is a 128-bit AES key, not a short PIN.

### 5.3 Consider

- **Duress PIN:** a second PIN that unlocks a decoy wallet or triggers a wipe. Architectural, not a bug, but worth deciding on.
- **Progressive delay:** increasing delay between attempts in Secure world before the SCP03 handshake is attempted, to make online brute force slower than the 10-strike limit would suggest.

---

## 6. SPHINCS+ Implementation

### 6.1 Parameter Set

- Prefer **`-128f` or `-192f` with SHA2** on this platform. Rationale:
  - `f` variants are dramatically faster than `s` variants on Cortex-M33 (often 10-30×).
  - SHA2 lets you use the U585 HASH peripheral for the inner hash loop.
  - SHAKE and Haraka have no hardware acceleration on this chip.
- Benchmark on real hardware before committing. Paper numbers lie.
- Document the parameter set in your protocol spec with a domain separation tag; changing it later is a migration problem.

### 6.2 Derivation from BIP-39

1. Read 16–32 bytes of entropy from SE050 over SCP03.
2. Compute BIP-39 seed: `PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" + passphrase, 2048)` → 64 bytes.
3. Derive SPHINCS+ key material via HKDF-SHA256 with an explicit domain separation label, e.g. `"SPHINCS+-128f-simple-sha2/v1"`.
4. Extract `SK.seed`, `SK.prf`, `PK.seed` (3 × *n* bytes).
5. Run SPHINCS+ keygen to compute `PK.root`, or load it from the SE050 if precomputed.

**Question to resolve:** do you actually need BIP-39? If human-recoverable word lists aren't a product requirement, store the SPHINCS+ seed material directly on the SE050 and skip the BIP-39 layer. Simpler, less code, smaller attack surface.

### 6.3 Implementation Sourcing

- Candidates: `pqcrypto-sphincsplus` (PQClean via FFI), pure-Rust `sphincs-plus` crates.
- Audit whichever you pick. "Reference implementation" and "pure Rust" both mean "not necessarily constant-time or fault-hardened."
- Pin the version. Vendor the code if you can. Review every line that touches `SK.seed` or `SK.prf`.
- Run against NIST PQC test vectors in CI. Differential test against a second implementation if possible.

### 6.4 Side-Channel Hardening

- Constant-time execution for every secret-dependent operation. `subtle` crate for comparisons and conditional selects.
- No secret-dependent branches, no secret-dependent memory access patterns.
- Disable compiler optimizations that might introduce variable-time code (e.g., table lookups that become branches). Inspect the generated assembly for critical inner loops.
- Power analysis is a real threat on an unshielded board. Full DPA resistance is hard, but at minimum avoid the worst patterns (secret-dependent hash inputs without randomization).

### 6.5 Fault Hardening

- Redundant computation of critical steps (WOTS+ chains, FORS).
- **Verify the signature before releasing it.** If verification fails, zeroize and refuse. This catches fault injections that corrupted the signing process.
- Canary values checked at function boundaries.
- Control-flow integrity where practical.
- None of this is in PQClean or most pure-Rust crates by default. You add it.

### 6.6 Memory Budget

- Secret key material: up to 96 bytes.
- Signing working set: 8–64 KB of stack depending on parameter set.
- Signature buffer: 8–50 KB.
- Ensure Secure-world stack is sized accordingly. Default CubeIDE/CubeMX stacks are too small.
- All of this must be in Secure SRAM, GTZC-protected.

---

## 7. Rust-Specific Requirements

### 7.1 Toolchain & Targets

- Target: `thumbv8m.main-none-eabihf`.
- Stable Rust where possible. Nightly only if required for `cmse_nonsecure_entry` or similar — document the exact reason.
- Separate crates for Secure image and NS image; shared `nsc-interface` crate defining the ABI with `#[repr(C)]` types.
- Reproducible builds. Pin the toolchain version in `rust-toolchain.toml`.

### 7.2 Mandatory Crates

- **`zeroize`**: for every secret. Use `ZeroizeOnDrop` derives. Do not rely on plain `Drop` or manual assignment — the compiler will elide it.
- **`subtle`**: for constant-time operations.
- **`rand_core`** wired to U585 TRNG or SE050 RNG. Never a software PRNG for secrets.
- Audit every other dependency that touches secrets.

### 7.3 Lints & Build

- `#![deny(unsafe_op_in_unsafe_fn)]`
- `#![warn(clippy::pedantic, clippy::nursery)]`
- `#![deny(clippy::indexing_slicing)]` (forces explicit bounds handling)
- Every `unsafe` block has a `// SAFETY:` comment explaining the invariant. Reviewed explicitly in code review.
- `cargo audit` and `cargo deny` in CI. Fail the build on any advisory.
- `cargo-geiger` to track `unsafe` surface across dependencies.

### 7.4 Type System Enforcement

Lean into the type system to make invariants compile-time errors:

- `struct Seed([u8; 64])` with `ZeroizeOnDrop`, constructed only inside the unlock flow, consumed by signing.
- `struct UnlockedSession<'a>` that borrows from a live SCP03 session; signing functions take `&UnlockedSession` so they cannot be called without one.
- `struct NsPtr<T>` wrapping raw pointers from NS with a checked constructor that validates length and alignment. Rest of the Secure code only handles validated types.
- Mark secret-bearing types `!Copy` and `!Clone` so they can't be silently duplicated.

### 7.5 NSC Boundary

- Every NSC entry point validates every parameter. Treat NS as fully hostile.
- Length fields validated before use.
- Pointers validated to point into NS memory, not into Secure memory (prevents NS from tricking Secure into reading its own secrets through a "buffer").
- No panics across the NSC boundary. Set a panic handler that wipes secrets and resets.
- Return types expose only non-secret data.

### 7.6 What Rust Does Not Save You From

Say this out loud to yourself before every commit:

- Side-channel leaks. The borrow checker does not know what timing is.
- Fault injection. Rust compiles to the same machine code C does.
- Zeroization actually happening under optimization — use `zeroize`, not assignment.
- Stack frame ghosts after function return — minimize secret lifetime depth.
- GTZC/MPU/peripheral config bugs.
- Bugs in your dependencies.
- Provisioning and supply-chain problems.

---

## 8. Zeroization Discipline

- Every secret has a clear lifetime and a clear zeroization point.
- Use `zeroize::Zeroize` and `ZeroizeOnDrop` everywhere. Never plain `memset` or assignment.
- Compiler fences around zeroization calls (the `zeroize` crate handles this; verify).
- After sensitive operations, explicitly clear the stack region used. `zeroize` has helpers; if not, write a small assembly routine.
- Clear CPU registers after returning from crypto operations if the ABI allowed secrets into them.
- Cache flushes if secrets may have been cached.
- Verify zeroization in tests — write a test that runs a signing operation and then scans Secure SRAM for any byte pattern matching the test key. Fail loudly if found.

---

## 9. Provisioning Security

- Clean-room facility. No network on provisioning stations.
- HSM-backed generation of per-device SCP03 keys, or EdgeLock 2GO.
- Provisioning logs never contain secret material. Audit every log statement.
- Post-provisioning verification: each device is challenged before shipping to prove it's in the expected state (PIN auth object present, seed object present, RDP-2 set, attestation working).
- Tamper-evident packaging between facility and user.
- A provisioning station compromise compromises every device that passed through it during the compromise window. Have a plan.

---

## 10. Update Mechanism

Firmware update is its own project, outside the scope of this document, but note:

- Updates must be signed with a key held in an HSM, verified by the bootloader before any code runs.
- The verification key is stored in a region covered by RDP-2 and option bytes that prevent modification.
- Downgrade protection via a monotonic counter in Secure flash.
- Rollback plan for broken updates that doesn't involve unlocking RDP-2.
- Update process must not require exposing secrets.
- Test updates on field hardware before every release, not just in the lab.

---

## 11. Testing & Verification

- Unit tests for all cryptographic primitives against published test vectors (NIST PQC for SPHINCS+, BIP-39 spec vectors, etc.).
- Differential tests against a second implementation where available.
- Host-side tests with a mock SE050 for logic.
- On-device integration tests for hardware interaction.
- Fuzz every NSC entry point (`cargo fuzz`) with AFL-style mutation.
- Property-based tests (`proptest`) for anything with nontrivial invariants.
- Zeroization verification tests that scan SRAM after operations.
- Boot-time attestation negative tests: what happens if the SE050 responds with a wrong cert, a replayed nonce, a malformed APDU, no response at all.
- Timing tests on critical paths; flag any data-dependent variation.
- Power-loss tests on real hardware: cut power at many points during a signing operation and verify no secrets survive in any persistent memory.

---

## 12. Operational

### 12.1 Before Touching Real Funds

- **External security audit** from a firm with embedded/TrustZone/secure-element specialization (NCC Group, Trail of Bits, Quarkslab, Kudelski, etc.). Budget $30K–$150K. Yes, really.
- Fault injection testing on real hardware (lab time).
- Public bug bounty with meaningful rewards.
- Gradual rollout: start with small amounts, wait months, scale up only if nothing surfaces.
- Do not store your own significant funds on it until it has been under public scrutiny for an extended period.

### 12.2 Incident Response

- Have a vulnerability disclosure policy before you ship.
- Have a plan for pushing updates fast when (not if) a flaw is found.
- Have a plan for informing users whose devices may be compromised.
- Reserve capacity to triage reports from researchers.

### 12.3 Documentation

- Threat model document, updated as the design evolves.
- Protocol specification covering every APDU, every NSC call, every crypto primitive and its parameters.
- A "known limitations" document listing what you *don't* protect against, so users can make informed decisions.

---

## 13. Honest Caveats

Things that must be acknowledged plainly:

1. **Coerced unlock defeats everything.** No PIN-gated system survives a user being forced to unlock it. Architecturally unfixable without multi-party approval.
2. **Lab attacks on the SE050 die** are rare but not impossible. EAL 6+ is very high resistance, not absolute.
3. **The SRAM exposure window** during signing and during the 2-minute cache is the biggest remaining attack surface for a skilled physical attacker. Fault injection and cold-boot attacks both target this window. The 2-minute cache is a UX concession; consider whether your users need it.
4. **Implementation bugs are the most likely failure mode.** More likely than cryptographic breaks, more likely than hardware exploits. Every shipped wallet vulnerability in history proves this. Spend your paranoia budget on code review, not on exotic attacks.
5. **First-party custom hardware wallets have a poor track record.** Not because the builders were dumb. Because the attack surface is enormous and the economic incentive for attackers scales with the funds stored. Use an audited existing wallet if you can. Build custom only if you have a real reason the existing ones can't serve.
6. **SPHINCS+ is unusual for cryptocurrency.** Verify that your signing scheme actually matches what you need to sign. Don't build the wrong crypto stack.

---

## 14. The One-Line Summary

**Architecture is necessary but not sufficient. Execution is where wallets live or die. Assume every line of code is wrong until proven otherwise, minimize the time secrets exist in any form, and do not trust your own confidence.**

